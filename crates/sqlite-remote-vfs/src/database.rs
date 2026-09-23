//! State of the main database file: blocks in memory, blocks modified since the last commit, and the lease.

use std::collections::{BTreeSet, HashMap};
use std::thread;
use std::time::Duration;

use sqlite_remote_protocol::v1::{self as pb, client_frame, server_frame};

use crate::Stats;
use crate::client::{Client, ClientError};
use crate::local::{Head, LocalCopy, LocalStore};
use crate::platform::Moment;

const COMMIT_ID_BYTES: usize = 16;
// Bytes reserved in a Commit frame for the fields around the blocks, and per block for its index, tag and length.
const COMMIT_FRAME_OVERHEAD: usize = 256;
const COMMIT_BLOCK_OVERHEAD: usize = 16;
const RECONNECT_PAUSE: Duration = Duration::from_millis(200);
/// Number of blocks fetched on a miss when the database was preloaded and the block has since been evicted. With
/// `Load::OnDemand`, the configured `blocks_per_fetch` is used instead.
const REFILL_BLOCKS: u64 = 64;
/// Maximum number of block ranges in the single fetch request that catches up a local copy. It bounds the size of
/// that request. The server rejects requests with more ranges.
const MAX_CATCH_UP_RANGES: usize = 4096;

/// Reason why a database no longer accepts writes. It has to be closed and opened again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Broken {
    /// Another instance has taken over the lease.
    Fenced,
    /// The state on the server is unknown to this client: the connection could not be restored, or the server is at
    /// an unexpected version after reconnecting.
    Uncertain(String),
    /// The server rejected a commit, or a fetch failed.
    Refused(String),
}

/// A block in memory. `used` is the value of the LRU clock at its last access.
struct Block {
    data: Vec<u8>,
    used: u64,
}

pub(crate) struct Database {
    pub db_id: String,
    subject: String,
    page_size: usize,
    page_count: u64,
    /// Page count after the last commit. The head of the local copy uses this value, because `page_count` may
    /// already include changes of an uncommitted transaction.
    stable_page_count: u64,
    blocks: HashMap<u64, Block>,
    dirty: BTreeSet<u64>,
    size_changed: bool,
    version: u64,
    lease_id: Vec<u8>,
    lease_epoch: u64,
    last_commit_id: Vec<u8>,
    /// `None`: the database was preloaded. `Some(n)`: blocks are fetched on demand, up to `n` per request.
    blocks_per_fetch: Option<u64>,
    /// Memory limit in blocks, if any. Beyond it, the least recently used blocks are evicted and reloaded on access
    /// from the local copy or the server.
    cap: Option<u64>,
    /// LRU clock. Incremented on every block access.
    clock: u64,
    /// Optional local copy. It is disabled for the rest of the session after its first error. Such errors are not
    /// reported to SQLite, because the server has all blocks.
    local: LocalCopy,
    pub broken: Option<Broken>,
}

/// How a database is opened.
pub(crate) struct OpenOptions {
    pub page_size: u32,
    pub create: bool,
    pub takeover: bool,
    pub blocks_per_fetch: Option<u64>,
    pub cap: Option<u64>,
    /// Owner of the database. A local copy that belongs to another subject is not used.
    pub subject: String,
    pub local: Option<Box<dyn LocalStore>>,
}

impl Database {
    /// Opens the database on the server and takes its lease. With `Load::Preload`, also loads all blocks: from the
    /// local copy if it is current and complete, otherwise from the server.
    pub fn open(
        client: &mut Client,
        db_id: &str,
        options: OpenOptions,
        stats: &mut Stats,
    ) -> Result<Self, ClientError> {
        let answer = client.call(client_frame::Body::Open(pb::Open {
            db_id: db_id.into(),
            page_size: options.page_size,
            create_if_missing: options.create,
            takeover: options.takeover,
            resume: None,
        }))?;
        let server_frame::Body::Opened(opened) = answer else {
            return Err(ClientError::Protocol(format!("expected Opened, got {answer:?}")));
        };
        let mut db = Database {
            db_id: db_id.into(),
            subject: options.subject,
            page_size: opened.page_size as usize,
            page_count: opened.page_count,
            stable_page_count: opened.page_count,
            blocks: HashMap::new(),
            dirty: BTreeSet::new(),
            size_changed: false,
            version: opened.version,
            lease_id: opened.lease_id,
            lease_epoch: opened.lease_epoch,
            last_commit_id: opened.last_commit_id,
            blocks_per_fetch: options.blocks_per_fetch,
            cap: options.cap,
            clock: 0,
            local: match options.local {
                Some(store) => LocalCopy::Ready(store),
                None => LocalCopy::None,
            },
            broken: None,
        };

        let from_copy = db.take_copy(client, stats)?;
        if db.blocks_per_fetch.is_none() && db.page_count > 0 && !from_copy {
            db.load(client, 0, db.page_count, stats)?;
            // Write all blocks to the local copy, so that it starts at the same version.
            db.write_copy(&db.blocks.keys().copied().collect::<Vec<_>>(), stats);
        }
        // A preloaded database can exceed the memory limit right away.
        db.make_room(0, stats);
        stats.held_blocks = db.blocks.len() as u64;
        Ok(db)
    }

    /// Checks whether the local copy can be used. A copy that is behind is caught up if possible, otherwise it is
    /// cleared. With `Load::Preload`, loads the database from the copy. Returns true if all blocks were loaded from
    /// it.
    fn take_copy(&mut self, client: &mut Client, stats: &mut Stats) -> Result<bool, ClientError> {
        let LocalCopy::Ready(local) = &mut self.local else {
            return Ok(false);
        };
        let head = match local.head() {
            Ok(head) => head,
            Err(reason) => {
                stats.local_failures += 1;
                let _ = reason;
                self.local = LocalCopy::None;
                return Ok(false);
            }
        };
        let usable = head.filter(|head| {
            head.subject == self.subject && head.db_id == self.db_id && head.page_size as usize == self.page_size
        });
        let Some(head) = usable else {
            // No local copy, or one for another subject, database or page size. Clear it and use the server.
            self.forget_copy(stats);
            return Ok(false);
        };

        if head.version > self.version {
            // The local copy is ahead of the server, so the server has lost commits, e.g. after a restore from a
            // backup. Refuse to open: recovering those commits needs an explicit recovery step.
            return Err(ClientError::Protocol(format!(
                "local copy of {} is at version {}, the server at version {}: the server has lost commits",
                self.db_id, head.version, self.version
            )));
        }
        if head.version < self.version && !self.catch_copy_up(client, &head, stats)? {
            // Catching up is not possible or too expensive. Clear the local copy and load from the server.
            self.forget_copy(stats);
            return Ok(false);
        }

        // The local copy is current. With `Load::OnDemand`, blocks are read from it on first access instead of
        // now.
        if self.blocks_per_fetch.is_some() {
            return Ok(false);
        }
        // Read in chunks: in a browser, blocks are transferred through the fixed-size bridge buffer.
        const AT_ONCE: u64 = 256;
        let mut first = 0;
        while first < self.page_count {
            let count = AT_ONCE.min(self.page_count - first);
            let read = match self.local.read(first, count) {
                Ok(read) => read,
                Err(_) => {
                    stats.local_failures += 1;
                    self.local = LocalCopy::None;
                    return Ok(false);
                }
            };
            if read.len() as u64 != count {
                // The local copy has a gap. Keep it and load the database from the server. The fetched blocks are
                // then written to the copy, which fills the gap.
                stats.local_misses += 1;
                return Ok(false);
            }
            stats.local_blocks_read += count;
            for (offset, data) in read.into_iter().enumerate() {
                self.keep(first + offset as u64, data);
            }
            first += count;
        }
        stats.local_reads += 1;
        Ok(true)
    }

    /// Brings a local copy that is a few commits behind up to the current version.
    ///
    /// Gets the blocks modified since the copy's version from the server's change log and removes them from the
    /// copy. All other blocks are unchanged in the current version and stay. Returns false if catching up is not
    /// possible or not worthwhile. The caller then clears the copy.
    fn catch_copy_up(&mut self, client: &mut Client, behind: &Head, stats: &mut Stats) -> Result<bool, ClientError> {
        let changes = client.changes(&self.db_id, behind.version)?;
        if !changes.complete || changes.to_version != self.version {
            // The change log does not cover the versions from the copy's version to the current one.
            return Ok(false);
        }
        let runs: Vec<(u64, u64)> = runs(&changes.blocks)
            .into_iter()
            .filter_map(|(first, count)| {
                let count = count.min(self.page_count.saturating_sub(first));
                (count > 0).then_some((first, count))
            })
            .collect();
        // If more than a third of the database changed, or there are too many ranges, loading it whole is cheaper.
        if changes.blocks.len() as u64 > self.page_count / 3 || runs.len() > MAX_CATCH_UP_RANGES {
            return Ok(false);
        }

        let head = self.copy_head();
        if self.local.catch_up(&head, &changes.blocks).is_err() {
            stats.local_failures += 1;
            self.local = LocalCopy::None;
            return Ok(false);
        }
        stats.caught_up += 1;
        stats.forgotten_blocks += changes.blocks.len() as u64;

        // With `Load::OnDemand`, the removed blocks are fetched when accessed. With `Load::Preload`, fetch them now,
        // in a single request with one range per run instead of one round trip per run.
        if self.blocks_per_fetch.is_none() && !runs.is_empty() {
            let started = Moment::now();
            let blocks = client.fetch_ranges(&self.db_id, self.version, &runs)?;
            stats.fetches += 1;
            stats.fetched_blocks += blocks.len() as u64;
            stats.fetch_time += started.elapsed();
            let filled: Vec<u64> = blocks.iter().map(|(index, _)| *index).collect();
            for (index, data) in blocks {
                self.keep(index, data);
            }
            self.write_copy(&filled, stats);
        }
        Ok(true)
    }

    /// Head for writes to the local copy. It describes the state after the last commit.
    fn copy_head(&self) -> Head {
        Head {
            subject: self.subject.clone(),
            db_id: self.db_id.clone(),
            page_size: self.page_size as u32,
            page_count: self.stable_page_count,
            version: self.version,
        }
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
    fn keep(&mut self, index: u64, data: Vec<u8>) {
        let used = self.tick();
        self.blocks.entry(index).or_insert(Block { data, used });
    }

    /// Evicts least recently used blocks until the blocks in memory plus `incoming` fit the memory limit.
    ///
    /// Blocks modified since the last commit are never evicted, because the server does not have them yet. Evicted
    /// blocks are reloaded on access from the local copy or the server.
    fn make_room(&mut self, incoming: u64, stats: &mut Stats) {
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

    /// Loads the blocks from `first` on that the local copy holds, at most `count` and up to the first missing block.
    /// Returns true if block `first` was loaded.
    fn take_from_copy(&mut self, first: u64, count: u64, stats: &mut Stats) -> bool {
        if self.local.is_none() {
            return false;
        }
        stats.local_reads += 1;
        let read = match self.local.read(first, count) {
            Ok(read) => read,
            Err(_) => {
                stats.local_failures += 1;
                self.local = LocalCopy::None;
                return false;
            }
        };
        if read.is_empty() || read.iter().any(|block| block.len() != self.page_size) {
            stats.local_misses += 1;
            return false;
        }
        stats.local_blocks_read += read.len() as u64;
        for (offset, data) in read.into_iter().enumerate() {
            self.keep(first + offset as u64, data);
        }
        true
    }

    /// Clears the local copy but keeps the store for later writes. Disables the local copy if clearing fails.
    fn forget_copy(&mut self, stats: &mut Stats) {
        if let LocalCopy::Ready(local) = &mut self.local
            && local.clear().is_err()
        {
            stats.local_failures += 1;
            self.local = LocalCopy::None;
        }
    }

    /// Writes blocks to the local copy under the head of the last commit. Errors disable the local copy and are not
    /// returned, because the server has all blocks.
    fn write_copy(&mut self, indexes: &[u64], stats: &mut Stats) {
        if self.local.is_none() || indexes.is_empty() {
            return;
        }
        // Use the page count of the last commit. `page_count` may include an uncommitted transaction, but these
        // blocks belong to the committed version.
        let head = self.copy_head();
        let blocks: Vec<(u64, Vec<u8>)> = indexes
            .iter()
            .filter_map(|index| self.blocks.get(index).map(|block| (*index, block.data.clone())))
            .collect();
        let count = blocks.len() as u64;

        // Natively, the local copy is written on a background thread from the first write on. The server has
        // acknowledged these blocks, so the commit does not wait for the disk.
        #[cfg(not(target_arch = "wasm32"))]
        {
            if let LocalCopy::Ready(_) = &self.local {
                let LocalCopy::Ready(store) = std::mem::replace(&mut self.local, LocalCopy::None) else {
                    unreachable!("just checked")
                };
                self.local = LocalCopy::Writing(crate::local::Background::start(store));
            }
            if let LocalCopy::Writing(writer) = &mut self.local {
                stats.local_failures = writer.failures.load(std::sync::atomic::Ordering::Relaxed);
                if writer.write(head, blocks) {
                    stats.local_writes += 1;
                    stats.local_blocks_written += count;
                } else {
                    self.local = LocalCopy::None;
                }
            }
        }
        // In a browser, the connection worker takes the blocks and writes them to IndexedDB asynchronously. The call
        // does not block, so no background thread is needed.
        #[cfg(target_arch = "wasm32")]
        if let LocalCopy::Ready(store) = &mut self.local {
            let borrowed: Vec<(u64, &[u8])> = blocks.iter().map(|(index, data)| (*index, data.as_slice())).collect();
            match store.write(&head, &borrowed) {
                Ok(()) => {
                    stats.local_writes += 1;
                    stats.local_blocks_written += count;
                }
                Err(_) => {
                    stats.local_failures += 1;
                    self.local = LocalCopy::None;
                }
            }
        }
    }

    pub fn file_size(&self) -> u64 {
        self.page_count * self.page_size as u64
    }

    /// Reads `buf.len()` bytes at `offset`. Returns false if the read extends past the end of the file. The part past
    /// the end is zero-filled, as SQLite expects.
    pub fn read(
        &mut self,
        client: &mut Client,
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
            self.ensure_loaded(client, index, stats)?;
            let within = (position % page_size) as usize;
            let n = (self.page_size - within).min(buf.len() - done);
            match self.blocks.get(&index) {
                Some(block) => buf[done..done + n].copy_from_slice(&block.data[within..within + n]),
                None => buf[done..done + n].fill(0),
            }
            done += n;
        }
        stats.held_blocks = self.blocks.len() as u64;
        Ok(true)
    }

    pub fn write(&mut self, client: &mut Client, data: &[u8], offset: u64, stats: &mut Stats) -> Result<(), Broken> {
        if let Some(broken) = &self.broken {
            return Err(broken.clone());
        }
        let page_size = self.page_size as u64;
        let mut done = 0usize;
        while done < data.len() {
            let position = offset + done as u64;
            let index = position / page_size;
            let within = (position % page_size) as usize;
            let n = (self.page_size - within).min(data.len() - done);
            if n < self.page_size && index < self.page_count {
                // A partial write needs the existing content of the block.
                self.ensure_loaded(client, index, stats)?;
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
        stats.held_blocks = self.blocks.len() as u64;
        Ok(())
    }

    pub fn truncate(&mut self, size: u64) -> Result<(), Broken> {
        if let Some(broken) = &self.broken {
            return Err(broken.clone());
        }
        let page_count = size.div_ceil(self.page_size as u64);
        if page_count != self.page_count {
            self.blocks.retain(|&index, _| index < page_count);
            self.dirty.retain(|&index| index < page_count);
            self.page_count = page_count;
            self.size_changed = true;
        }
        Ok(())
    }

    /// Sends all changes since the last commit to the server and blocks until the server has acknowledged them. If the
    /// connection breaks, reconnects for up to `reconnect_timeout`. Any error marks the database as broken.
    pub fn commit(
        &mut self,
        client: &mut Client,
        reconnect_timeout: Duration,
        stats: &mut Stats,
    ) -> Result<(), Broken> {
        if let Some(broken) = &self.broken {
            return Err(broken.clone());
        }
        if self.dirty.is_empty() && !self.size_changed {
            return Ok(());
        }
        if client.was_revoked(&self.db_id) {
            return Err(self.break_with(Broken::Fenced));
        }

        let mut commit_id = [0u8; COMMIT_ID_BYTES];
        getrandom::fill(&mut commit_id).expect("OS randomness");
        let parts = self.parts(&commit_id, client.limits().max_frame_bytes as usize);
        let started = Moment::now();
        let deadline = started.plus(reconnect_timeout);

        let version = loop {
            if !client.is_connected() {
                let opened = self.resume_until(client, deadline, stats)?;
                if opened.version != self.version {
                    return Err(self.break_with(Broken::Uncertain(format!(
                        "server is at version {}, this client at {}",
                        opened.version, self.version
                    ))));
                }
            }
            match client.commit(parts.clone()) {
                Ok(version) => break version,
                Err(err) if err.is_fenced() => return Err(self.break_with(Broken::Fenced)),
                Err(ClientError::Server(e)) => {
                    return Err(self.break_with(Broken::Refused(format!("{}: {}", e.code().as_str_name(), e.detail))));
                }
                Err(_) => {
                    // The connection broke, so the commit may or may not have been applied. Reconnect and compare
                    // the server's version and last commit id.
                    let opened = self.resume_until(client, deadline, stats)?;
                    if opened.version == self.version + 1 && opened.last_commit_id == commit_id {
                        stats.recovered_commits += 1;
                        break opened.version;
                    }
                    if opened.version != self.version {
                        return Err(self.break_with(Broken::Uncertain(format!(
                            "server is at version {}, this client at {}",
                            opened.version, self.version
                        ))));
                    }
                    // Not applied: send it again.
                    stats.resent_commits += 1;
                }
            }
        };

        let elapsed = started.elapsed();
        stats.commits += 1;
        stats.commit_frames += parts.len() as u64;
        stats.committed_blocks += self.dirty.len() as u64;
        stats.committed_bytes += (self.dirty.len() * self.page_size) as u64;
        stats.commit_time += elapsed;
        stats.max_commit_time = stats.max_commit_time.max(elapsed);

        self.version = version;
        self.last_commit_id = commit_id.to_vec();
        let written: Vec<u64> = self.dirty.iter().copied().collect();
        self.dirty.clear();
        self.size_changed = false;
        self.stable_page_count = self.page_count;
        // The commit is durable on the server. Now write the blocks to the local copy.
        self.write_copy(&written, stats);
        // The committed blocks are no longer dirty and can be evicted.
        self.make_room(0, stats);
        stats.held_blocks = self.blocks.len() as u64;
        Ok(())
    }

    /// Takes the local copy out of the database, so that the next database opened on this VFS can use it. In a browser
    /// the local copy is a handle to the connection worker, which exists once per VFS.
    #[cfg(target_arch = "wasm32")]
    pub fn take_local(&mut self) -> Option<Box<dyn LocalStore>> {
        match std::mem::replace(&mut self.local, LocalCopy::None) {
            LocalCopy::Ready(store) => Some(store),
            LocalCopy::None => None,
        }
    }

    /// Releases the lease. Best effort: if this fails, the lease expires on the server.
    pub fn close(&self, client: &mut Client) {
        if self.broken.is_some() || !client.is_connected() {
            return;
        }
        let _ = client.call(client_frame::Body::CloseDb(pb::CloseDb {
            db_id: self.db_id.clone(),
            lease_epoch: self.lease_epoch,
        }));
    }

    fn parts(&self, commit_id: &[u8], max_frame_bytes: usize) -> Vec<pb::Commit> {
        let per_part =
            (max_frame_bytes.saturating_sub(COMMIT_FRAME_OVERHEAD) / (self.page_size + COMMIT_BLOCK_OVERHEAD)).max(1);
        let blocks: Vec<pb::Block> = self
            .dirty
            .iter()
            .map(|&index| pb::Block {
                index,
                data: self.blocks[&index].data.clone(),
            })
            .collect();
        let chunks: Vec<Vec<pb::Block>> = if blocks.is_empty() {
            // Only the size changed: one part without blocks.
            vec![Vec::new()]
        } else {
            blocks.chunks(per_part).map(<[pb::Block]>::to_vec).collect()
        };
        let count = chunks.len();
        chunks
            .into_iter()
            .enumerate()
            .map(|(part, blocks)| pb::Commit {
                db_id: self.db_id.clone(),
                commit_id: commit_id.to_vec(),
                lease_epoch: self.lease_epoch,
                base_version: self.version,
                page_count: self.page_count,
                blocks,
                more: part + 1 < count,
                part: part as u32,
            })
            .collect()
    }

    /// Ensures that block `index` is in memory. Loads it from the local copy or, if it is missing there, the server.
    fn ensure_loaded(&mut self, client: &mut Client, index: u64, stats: &mut Stats) -> Result<(), Broken> {
        if self.blocks.contains_key(&index) || self.dirty.contains(&index) {
            self.touch(index);
            return Ok(());
        }
        if self.blocks_per_fetch.is_none() && self.cap.is_none() {
            // Preloaded without a memory limit: every block is in memory.
            return Ok(());
        }
        if let Some(broken) = &self.broken {
            return Err(broken.clone());
        }
        // Fetch only the run of missing blocks starting at `index`. Blocks in memory may be newer than the server's
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

        // Try the local copy first. Its reads are queued behind pending writes, so it returns the state of the last
        // commit.
        if self.take_from_copy(index, count, stats) {
            return Ok(());
        }
        if !client.is_connected() {
            // Reads reconnect once, without a deadline. If that fails, the read fails.
            self.resume(client, stats)
                .map_err(|err| self.break_with(Broken::Uncertain(err.to_string())))?;
        }
        self.load(client, index, count, stats).map_err(|err| match err {
            err if err.is_fenced() => self.break_with(Broken::Fenced),
            err => Broken::Refused(err.to_string()),
        })?;
        // Write the fetched blocks to the local copy.
        let fetched: Vec<u64> = (index..index + count).collect();
        self.write_copy(&fetched, stats);
        Ok(())
    }

    /// Fetches `count` blocks from `first` on and stores those not yet in memory. Blocks in memory may be newer than
    /// the server's.
    fn load(&mut self, client: &mut Client, first: u64, count: u64, stats: &mut Stats) -> Result<(), ClientError> {
        let started = Moment::now();
        let blocks = client.fetch(pb::Fetch {
            db_id: self.db_id.clone(),
            version: self.version,
            first_block: first,
            count,
            ranges: Vec::new(),
        })?;
        stats.fetches += 1;
        stats.fetched_blocks += count;
        stats.fetch_time += started.elapsed();
        for (offset, data) in blocks.into_iter().enumerate() {
            self.keep(first + offset as u64, data);
        }
        Ok(())
    }

    /// Reconnects and resumes the lease, retrying until `deadline`.
    fn resume_until(&mut self, client: &mut Client, deadline: Moment, stats: &mut Stats) -> Result<pb::Opened, Broken> {
        loop {
            match self.resume(client, stats) {
                Ok(opened) => return Ok(opened),
                Err(err) if err.is_fenced() => return Err(self.break_with(Broken::Fenced)),
                Err(err) if Moment::now() >= deadline => {
                    return Err(self.break_with(Broken::Uncertain(format!("no connection to the server: {err}"))));
                }
                Err(_) => thread::sleep(RECONNECT_PAUSE),
            }
        }
    }

    fn resume(&mut self, client: &mut Client, stats: &mut Stats) -> Result<pb::Opened, ClientError> {
        client.reconnect()?;
        stats.reconnects += 1;
        let answer = client.call(client_frame::Body::Open(pb::Open {
            db_id: self.db_id.clone(),
            page_size: self.page_size as u32,
            create_if_missing: false,
            takeover: false,
            resume: Some(pb::Resume {
                lease_id: self.lease_id.clone(),
                lease_epoch: self.lease_epoch,
                known_version: self.version,
                pending_commit_id: Vec::new(),
            }),
        }))?;
        match answer {
            server_frame::Body::Opened(opened) => Ok(opened),
            other => Err(ClientError::Protocol(format!("expected Opened, got {other:?}"))),
        }
    }

    fn break_with(&mut self, broken: Broken) -> Broken {
        self.broken = Some(broken.clone());
        broken
    }
}

/// Groups a sorted list of block indexes into runs of consecutive indexes, as `(first, count)`.
fn runs(blocks: &[u64]) -> Vec<(u64, u64)> {
    let mut runs: Vec<(u64, u64)> = Vec::new();
    for &index in blocks {
        match runs.last_mut() {
            Some((first, count)) if *first + *count == index => *count += 1,
            _ => runs.push((index, 1)),
        }
    }
    runs
}

#[cfg(test)]
mod tests {
    #[test]
    fn block_list_splits_into_runs() {
        assert_eq!(super::runs(&[]), vec![]);
        assert_eq!(super::runs(&[7]), vec![(7, 1)]);
        assert_eq!(super::runs(&[0, 1, 2]), vec![(0, 3)]);
        assert_eq!(super::runs(&[0, 1, 4, 9, 10]), vec![(0, 2), (4, 1), (9, 2)]);
    }
}
