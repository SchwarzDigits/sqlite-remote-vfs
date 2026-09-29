//! A database kept only in this browser ([`Store::Local`](crate::Store::Local)). The connection worker stores its
//! blocks in IndexedDB; this side holds the blocks in memory in [`Pages`], as for a database on a server.
//!
//! Only one instance may write a database. Opening takes a Web Lock named after the database and increments the epoch
//! in the stored head. Every commit checks the epoch in the IndexedDB transaction that writes its blocks. An instance
//! whose lock was taken over therefore cannot commit, even before it learns that it lost the lock.
//!
//! A commit returns when its IndexedDB transaction is complete. A failed commit leaves the stored database unchanged
//! and marks the database as broken until it is opened again, as with a server.

use crate::Stats;
use crate::database::Broken;
use crate::pages::{Pages, Source};
use crate::platform::Moment;
use crate::transport::{LocalBridge, Refusal};

pub(crate) struct LocalDatabase {
    bridge: LocalBridge,
    pages: Pages,
    epoch: u64,
    broken: Option<Broken>,
}

/// How a local database is opened.
pub(crate) struct LocalOptions {
    pub page_size: u32,
    pub create: bool,
    pub takeover: bool,
    pub blocks_per_fetch: Option<u64>,
    pub cap: Option<u64>,
}

/// Loads missing blocks from IndexedDB.
struct Load<'a> {
    bridge: &'a LocalBridge,
    broken: &'a mut Option<Broken>,
}

impl LocalDatabase {
    /// Opens the database and takes its lock. With `Load::Preload`, also loads all blocks.
    pub fn open(bridge: LocalBridge, name: &str, options: LocalOptions, stats: &mut Stats) -> Result<Self, Refusal> {
        let opened = bridge.open(name, options.page_size, options.create, options.takeover)?;
        let mut db = LocalDatabase {
            pages: Pages::new(
                opened.page_size as usize,
                opened.page_count,
                options.blocks_per_fetch,
                options.cap,
            ),
            bridge,
            epoch: opened.epoch,
            broken: None,
        };
        let count = db.pages.page_count();
        if !db.pages.on_demand() && count > 0 {
            let mut load = Load {
                bridge: &db.bridge,
                broken: &mut db.broken,
            };
            if let Err(broken) = load.fill(&mut db.pages, 0, count, stats) {
                db.bridge.close();
                return Err(Refusal::Failed(format!("loading the database failed: {broken:?}")));
            }
        }
        // A preloaded database can exceed the memory limit right away.
        db.pages.make_room(0, stats);
        stats.held_blocks = db.pages.held();
        Ok(db)
    }

    pub fn file_size(&self) -> u64 {
        self.pages.file_size()
    }

    /// Reads `buf.len()` bytes at `offset`. Returns false if the read extends past the end of the file. The part past
    /// the end is zero-filled, as SQLite expects.
    pub fn read(&mut self, buf: &mut [u8], offset: u64, stats: &mut Stats) -> Result<bool, Broken> {
        let mut load = Load {
            bridge: &self.bridge,
            broken: &mut self.broken,
        };
        self.pages.read(&mut load, buf, offset, stats)
    }

    pub fn write(&mut self, data: &[u8], offset: u64, stats: &mut Stats) -> Result<(), Broken> {
        if let Some(broken) = &self.broken {
            return Err(broken.clone());
        }
        let mut load = Load {
            bridge: &self.bridge,
            broken: &mut self.broken,
        };
        self.pages.write(&mut load, data, offset, stats)
    }

    pub fn truncate(&mut self, size: u64) -> Result<(), Broken> {
        if let Some(broken) = &self.broken {
            return Err(broken.clone());
        }
        self.pages.truncate(size);
        Ok(())
    }

    /// Writes all changes since the last commit to IndexedDB and blocks until the transaction is complete. Any error
    /// marks the database as broken.
    pub fn commit(&mut self, stats: &mut Stats) -> Result<(), Broken> {
        if let Some(broken) = &self.broken {
            return Err(broken.clone());
        }
        if self.pages.is_clean() {
            return Ok(());
        }
        let started = Moment::now();
        let (result, count) = {
            let blocks = self.pages.dirty();
            let result = self.bridge.commit(self.epoch, self.pages.page_count(), &blocks);
            (result, blocks.len())
        };
        if let Err(refusal) = result {
            let broken = match refusal {
                Refusal::Busy => Broken::Fenced,
                Refusal::Full(reason) => Broken::Full(reason),
                Refusal::NoAnswer(reason) => Broken::Uncertain(reason),
                other => Broken::Refused(other.to_string()),
            };
            self.broken = Some(broken.clone());
            return Err(broken);
        }

        let elapsed = started.elapsed();
        stats.commits += 1;
        stats.committed_blocks += count as u64;
        stats.committed_bytes += (count * self.pages.page_size()) as u64;
        stats.commit_time += elapsed;
        stats.max_commit_time = stats.max_commit_time.max(elapsed);
        self.pages.committed();
        // The committed blocks are no longer dirty and can be evicted.
        self.pages.make_room(0, stats);
        stats.held_blocks = self.pages.held();
        Ok(())
    }

    /// Closes the database and releases its lock.
    pub fn close(&self) {
        self.bridge.close();
    }
}

impl Source for Load<'_> {
    fn fill(&mut self, pages: &mut Pages, first: u64, count: u64, stats: &mut Stats) -> Result<(), Broken> {
        if let Some(broken) = self.broken {
            return Err(broken.clone());
        }
        let at_once = self.bridge.max_read(pages.page_size());
        let end = first + count;
        let mut next = first;
        while next < end {
            let n = at_once.min(end - next);
            let blocks = self.bridge.read(next, n).map_err(|refusal| match refusal {
                // Another instance has taken over, so the stored blocks may be newer than those in memory.
                Refusal::Busy => {
                    *self.broken = Some(Broken::Fenced);
                    Broken::Fenced
                }
                // A late answer would be taken as the answer to the next request.
                Refusal::NoAnswer(reason) => {
                    let broken = Broken::Uncertain(reason);
                    *self.broken = Some(broken.clone());
                    broken
                }
                other => Broken::Refused(other.to_string()),
            })?;
            stats.local_reads += 1;
            stats.local_blocks_read += n;
            for (offset, data) in blocks.into_iter().enumerate() {
                pages.keep(next + offset as u64, data);
            }
            next += n;
        }
        Ok(())
    }
}
