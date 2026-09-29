//! Blocks of the main database file in memory: the blocks read or written, the blocks modified since the last commit,
//! and the memory limit. Where missing blocks come from is up to a [`Source`]: the server with its cache, or the local
//! store.

use std::collections::{BTreeSet, HashMap};

use crate::Stats;
use crate::database::Broken;

/// Number of blocks loaded on a miss when the database was preloaded and the block has since been evicted. With
/// `Load::OnDemand`, the configured `blocks_per_fetch` is used instead.
const REFILL_BLOCKS: u64 = 64;

/// A block in memory. `used` is the value of the LRU clock at its last access.
struct Block {
    data: Vec<u8>,
    used: u64,
}

/// Loads blocks that are not in memory.
pub(crate) trait Source {
    /// Loads blocks `first` to `first + count - 1`, none of which is in memory, and stores them with [`Pages::keep`].
    /// A block the source does not have may be left out; it then reads as zeros.
    fn fill(&mut self, pages: &mut Pages, first: u64, count: u64, stats: &mut Stats) -> Result<(), Broken>;
}

pub(crate) struct Pages {
    page_size: usize,
    page_count: u64,
    /// Page count after the last commit. The committed state uses this value, because `page_count` may already
    /// include changes of an uncommitted transaction.
    stable_page_count: u64,
    blocks: HashMap<u64, Block>,
    dirty: BTreeSet<u64>,
    size_changed: bool,
    /// `None`: the database was preloaded. `Some(n)`: blocks are loaded on demand, up to `n` per request.
    blocks_per_fetch: Option<u64>,
    /// Memory limit in blocks, if any. Beyond it, the least recently used blocks are evicted and loaded again on
    /// access.
    cap: Option<u64>,
    /// LRU clock. Incremented on every block access.
    clock: u64,
}

impl Pages {
    pub fn new(page_size: usize, page_count: u64, blocks_per_fetch: Option<u64>, cap: Option<u64>) -> Self {
        Pages {
            page_size,
            page_count,
            stable_page_count: page_count,
            blocks: HashMap::new(),
            dirty: BTreeSet::new(),
            size_changed: false,
            blocks_per_fetch,
            cap,
            clock: 0,
        }
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }

    /// Current page count, including an uncommitted transaction.
    pub fn page_count(&self) -> u64 {
        self.page_count
    }

    /// Page count after the last commit.
    pub fn stable_page_count(&self) -> u64 {
        self.stable_page_count
    }

    /// Whether blocks are loaded on demand instead of preloaded.
    pub fn on_demand(&self) -> bool {
        self.blocks_per_fetch.is_some()
    }

    pub fn file_size(&self) -> u64 {
        self.page_count * self.page_size as u64
    }

    /// Number of blocks in memory.
    pub fn held(&self) -> u64 {
        self.blocks.len() as u64
    }

    /// Content of block `index`, if it is in memory.
    pub fn block(&self, index: u64) -> Option<&[u8]> {
        self.blocks.get(&index).map(|block| block.data.as_slice())
    }

    /// Indexes of all blocks in memory.
    pub fn indexes(&self) -> Vec<u64> {
        self.blocks.keys().copied().collect()
    }

    /// Whether nothing changed since the last commit.
    pub fn is_clean(&self) -> bool {
        self.dirty.is_empty() && !self.size_changed
    }

    /// Blocks modified since the last commit, in index order.
    pub fn dirty(&self) -> Vec<(u64, &[u8])> {
        self.dirty
            .iter()
            .map(|&index| (index, self.blocks[&index].data.as_slice()))
            .collect()
    }

    /// Marks the changes as committed and returns the indexes of the blocks written. From now on these blocks can be
    /// evicted by [`Pages::make_room`].
    pub fn committed(&mut self) -> Vec<u64> {
        let written: Vec<u64> = self.dirty.iter().copied().collect();
        self.dirty.clear();
        self.size_changed = false;
        self.stable_page_count = self.page_count;
        written
    }

    /// Advances the LRU clock and returns the new value.
    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    fn touch(&mut self, index: u64) {
        let used = self.tick();
        if let Some(block) = self.blocks.get_mut(&index) {
            block.used = used;
        }
    }

    /// Stores a block in memory unless it is already there. A block already in memory may be newer than `data`,
    /// because it can hold uncommitted changes.
    pub fn keep(&mut self, index: u64, data: Vec<u8>) {
        let used = self.tick();
        self.blocks.entry(index).or_insert(Block { data, used });
    }

    /// Evicts least recently used blocks until the blocks in memory plus `incoming` fit the memory limit.
    ///
    /// Blocks modified since the last commit are never evicted, because they are not stored anywhere else yet.
    /// Evicted blocks are loaded again on access.
    pub fn make_room(&mut self, incoming: u64, stats: &mut Stats) {
        let Some(cap) = self.cap.map(|cap| cap.max(1)) else {
            return;
        };
        let here = self.blocks.len() as u64;
        if here + incoming <= cap {
            return;
        }
        // Evict down to 7/8 of the limit, minus `incoming`, so that the next miss does not evict again.
        let target = (cap - cap / 8).saturating_sub(incoming);
        let mut ages: Vec<(u64, u64)> = self
            .blocks
            .iter()
            .filter(|(index, _)| !self.dirty.contains(index))
            .map(|(index, block)| (block.used, *index))
            .collect();
        let count = (here.saturating_sub(target) as usize).min(ages.len());
        if count == 0 {
            return;
        }
        // Partial sort: moves the `count` least recently used blocks to the front.
        ages.select_nth_unstable(count - 1);
        for (_, index) in &ages[..count] {
            self.blocks.remove(index);
        }
        stats.evicted_blocks += count as u64;
    }

    /// Reads `buf.len()` bytes at `offset`. Returns false if the read extends past the end of the file. The part past
    /// the end is zero-filled, as SQLite expects.
    pub fn read(
        &mut self,
        source: &mut dyn Source,
        buf: &mut [u8],
        offset: u64,
        stats: &mut Stats,
    ) -> Result<bool, Broken> {
        let page_size = self.page_size as u64;
        let mut done = 0usize;
        while done < buf.len() {
            let position = offset + done as u64;
            let index = position / page_size;
            if index >= self.page_count {
                buf[done..].fill(0);
                return Ok(false);
            }
            self.ensure_loaded(source, index, stats)?;
            let within = (position % page_size) as usize;
            let n = (self.page_size - within).min(buf.len() - done);
            match self.blocks.get(&index) {
                Some(block) => buf[done..done + n].copy_from_slice(&block.data[within..within + n]),
                None => buf[done..done + n].fill(0),
            }
            done += n;
        }
        stats.held_blocks = self.held();
        Ok(true)
    }

    pub fn write(
        &mut self,
        source: &mut dyn Source,
        data: &[u8],
        offset: u64,
        stats: &mut Stats,
    ) -> Result<(), Broken> {
        let page_size = self.page_size as u64;
        let mut done = 0usize;
        while done < data.len() {
            let position = offset + done as u64;
            let index = position / page_size;
            let within = (position % page_size) as usize;
            let n = (self.page_size - within).min(data.len() - done);
            if n < self.page_size && index < self.page_count {
                // A partial write needs the existing content of the block.
                self.ensure_loaded(source, index, stats)?;
            }
            let used = self.tick();
            let bytes = self.page_size;
            let block = self.blocks.entry(index).or_insert_with(|| Block {
                data: vec![0; bytes],
                used,
            });
            block.used = used;
            block.data[within..within + n].copy_from_slice(&data[done..done + n]);
            self.dirty.insert(index);
            if index >= self.page_count {
                self.page_count = index + 1;
                self.size_changed = true;
            }
            done += n;
        }
        stats.held_blocks = self.held();
        Ok(())
    }

    pub fn truncate(&mut self, size: u64) {
        let page_count = size.div_ceil(self.page_size as u64);
        if page_count != self.page_count {
            self.blocks.retain(|&index, _| index < page_count);
            self.dirty.retain(|&index| index < page_count);
            self.page_count = page_count;
            self.size_changed = true;
        }
    }

    /// Ensures that block `index` is in memory. Loads the run of missing blocks starting at `index` from `source`.
    fn ensure_loaded(&mut self, source: &mut dyn Source, index: u64, stats: &mut Stats) -> Result<(), Broken> {
        if self.blocks.contains_key(&index) || self.dirty.contains(&index) {
            self.touch(index);
            return Ok(());
        }
        if self.blocks_per_fetch.is_none() && self.cap.is_none() {
            // Preloaded without a memory limit: every block is in memory.
            return Ok(());
        }
        // Load only the run of missing blocks starting at `index`. Blocks in memory may be newer than the stored ones
        // and must not be overwritten.
        let per_fetch = self.blocks_per_fetch.unwrap_or(REFILL_BLOCKS);
        let count = (index..self.page_count)
            .take(per_fetch as usize)
            .take_while(|i| !self.blocks.contains_key(i) && !self.dirty.contains(i))
            .count() as u64;
        if count == 0 {
            return Ok(());
        }
        self.make_room(count, stats);
        source.fill(self, index, count, stats)
    }
}
