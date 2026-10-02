//! A database on the server: the lease, the version and the local copy. The blocks in memory are in [`Pages`], which
//! loads missing blocks through [`Fetch`].

use std::time::Duration;

use sqlite_remote_protocol::v1::{self as pb, client_frame, server_frame};

use crate::Stats;
use crate::client::{Client, ClientError};
use crate::local::{Head, LocalCopy, LocalStore};
use crate::pages::{Pages, Source};
use crate::platform::Moment;

const COMMIT_ID_BYTES: usize = 16;
// Bytes reserved in a Commit frame for the fields around the blocks, and per block for its index, tag and length.
const COMMIT_FRAME_OVERHEAD: usize = 256;
const COMMIT_BLOCK_OVERHEAD: usize = 16;
const RECONNECT_PAUSE: Duration = Duration::from_millis(200);
/// Maximum number of block ranges in the single fetch request that catches up a local copy. It bounds the size of
/// that request. The server rejects requests with more ranges.
const MAX_CATCH_UP_RANGES: usize = 4096;

/// Reason why a database can no longer be used. It has to be closed and opened again, except after `Uncertain` on a
/// server, which [`Database::heal`] can undo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Broken {
    /// Another instance has taken over the lease, or locally the lock.
    Fenced,
    /// The connection could not be restored in time, so the state on the server is unknown to this client. Locally:
    /// the connection worker did not answer in time.
    Uncertain(String),
    /// After reconnecting, the server is at a version this client does not expect, e.g. after a restore.
    Diverged(String),
    /// The server rejected a commit, or a fetch failed. Locally: IndexedDB failed.
    Refused(String),
    /// The server rejected the access token when the client reconnected. SQLite gets `SQLITE_AUTH` for a commit.
    Denied(String),
    /// Locally: the browser's storage quota is exhausted. SQLite gets `SQLITE_FULL`.
    #[cfg(target_arch = "wasm32")]
    Full(String),
}

pub(crate) struct Database {
    pages: Pages,
    remote: Remote,
}

/// Server side of an open database.
struct Remote {
    db_id: String,
    subject: String,
    version: u64,
    lease_id: Vec<u8>,
    lease_epoch: u64,
    last_commit_id: Vec<u8>,
    /// commit_id of a commit whose outcome is unknown because the connection broke before it was acknowledged.
    pending_commit: Option<Vec<u8>>,
    /// Optional local copy. It is disabled for the rest of the session after its first error. Such errors are not
    /// reported to SQLite, because the server has all blocks.
    local: LocalCopy,
    broken: Option<Broken>,
    /// The client's login on which the database was opened or last resumed. See `Client::logins`.
    login: u64,
}

/// Loads missing blocks from the local copy or, if they are missing there, from the server.
struct Fetch<'a> {
    remote: &'a mut Remote,
    client: &'a mut Client,
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
        let mut pages = Pages::new(
            opened.page_size as usize,
            opened.page_count,
            options.blocks_per_fetch,
            options.cap,
        );
        let mut remote = Remote {
            db_id: db_id.into(),
            subject: options.subject,
            version: opened.version,
            lease_id: opened.lease_id,
            lease_epoch: opened.lease_epoch,
            last_commit_id: opened.last_commit_id,
            pending_commit: None,
            local: match options.local {
                Some(store) => LocalCopy::Ready(store),
                None => LocalCopy::None,
            },
            broken: None,
            login: client.logins(),
        };

        remote.fill(client, &mut pages, stats)?;
        Ok(Database { pages, remote })
    }

    /// Whether the database broke because the server could not be reached, so that [`Database::heal`] may make it
    /// usable again.
    pub fn is_unreachable(&self) -> bool {
        matches!(self.remote.broken, Some(Broken::Uncertain(_)))
    }

    /// Makes a database usable again that broke because the server could not be reached. Reconnects, resumes the
    /// lease, finds out whether the pending commit was applied, and loads the blocks as of the server's current
    /// version, as when opening. The blocks in memory are discarded, including those of a commit that was not
    /// applied.
    ///
    /// SQLite has rolled back and dropped its page cache after the error that broke the database. With a journal on
    /// this VFS, it finds the journal of a failed commit at its next access and rolls that commit back also if the
    /// server had applied it. Its SQLite call then reports a failed commit consistently.
    ///
    /// Fails, and the database stays broken, if the server is still unreachable, the lease was taken over, the token
    /// is rejected, or the server is at a version that neither includes nor excludes exactly the pending commit.
    pub fn heal(&mut self, client: &mut Client, stats: &mut Stats) -> Result<(), Broken> {
        let remote = &mut self.remote;
        let opened = remote
            .resume(client, self.pages.page_size(), stats)
            .map_err(|err| remote.break_on(err))?;
        let applied = opened.version == remote.version + 1
            && remote.pending_commit.as_deref() == Some(opened.last_commit_id.as_slice());
        if opened.version != remote.version && !applied {
            return Err(remote.break_with(Broken::Diverged(format!(
                "server is at version {}, this client at {}",
                opened.version, remote.version
            ))));
        }
        if applied {
            stats.recovered_commits += 1;
        }
        remote.version = opened.version;
        remote.last_commit_id = opened.last_commit_id;
        remote.pending_commit = None;

        let mut pages = self.pages.emptied(opened.page_count);
        remote
            .fill(client, &mut pages, stats)
            .map_err(|err| remote.break_on(err))?;
        self.pages = pages;
        remote.broken = None;
        stats.healed += 1;
        Ok(())
    }

    pub fn file_size(&self) -> u64 {
        self.pages.file_size()
    }

    /// Reads `buf.len()` bytes at `offset`. Returns false if the read extends past the end of the file. The part past
    /// the end is zero-filled, as SQLite expects.
    ///
    /// Fails if the database is broken: the blocks in memory may hold a commit that failed.
    pub fn read(
        &mut self,
        client: &mut Client,
        buf: &mut [u8],
        offset: u64,
        stats: &mut Stats,
    ) -> Result<bool, Broken> {
        if let Some(broken) = &self.remote.broken {
            return Err(broken.clone());
        }
        let mut fetch = Fetch {
            remote: &mut self.remote,
            client,
        };
        self.pages.read(&mut fetch, buf, offset, stats)
    }

    pub fn write(&mut self, client: &mut Client, data: &[u8], offset: u64, stats: &mut Stats) -> Result<(), Broken> {
        if let Some(broken) = &self.remote.broken {
            return Err(broken.clone());
        }
        let mut fetch = Fetch {
            remote: &mut self.remote,
            client,
        };
        self.pages.write(&mut fetch, data, offset, stats)
    }

    pub fn truncate(&mut self, size: u64) -> Result<(), Broken> {
        if let Some(broken) = &self.remote.broken {
            return Err(broken.clone());
        }
        self.pages.truncate(size);
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
        let remote = &mut self.remote;
        let pages = &mut self.pages;
        if let Some(broken) = &remote.broken {
            return Err(broken.clone());
        }
        if pages.is_clean() {
            return Ok(());
        }
        if client.was_revoked(&remote.db_id, remote.lease_epoch) {
            return Err(remote.break_with(Broken::Fenced));
        }

        let mut commit_id = [0u8; COMMIT_ID_BYTES];
        getrandom::fill(&mut commit_id).expect("OS randomness");
        let parts = remote.parts(pages, &commit_id, client.limits().max_frame_bytes as usize);
        // Stays set if the commit ends with the server unreachable, so that healing can find out whether it was
        // applied.
        remote.pending_commit = Some(commit_id.to_vec());
        let started = Moment::now();
        let deadline = started.plus(reconnect_timeout);

        let version = loop {
            if !remote.on_current_connection(client) {
                let opened = remote.resume_until(client, pages.page_size(), deadline, stats)?;
                if opened.version != remote.version {
                    return Err(remote.break_with(Broken::Diverged(format!(
                        "server is at version {}, this client at {}",
                        opened.version, remote.version
                    ))));
                }
            }
            match client.commit(parts.clone()) {
                Ok(version) => break version,
                Err(err) if err.is_fenced() => return Err(remote.break_with(Broken::Fenced)),
                Err(ClientError::Server(e)) => {
                    return Err(remote.break_with(Broken::Refused(format!(
                        "{}: {}",
                        e.code().as_str_name(),
                        e.detail
                    ))));
                }
                Err(_) => {
                    // The connection broke, so the commit may or may not have been applied. Reconnect and compare
                    // the server's version and last commit id.
                    let opened = remote.resume_until(client, pages.page_size(), deadline, stats)?;
                    if opened.version == remote.version + 1 && opened.last_commit_id == commit_id {
                        stats.recovered_commits += 1;
                        break opened.version;
                    }
                    if opened.version != remote.version {
                        return Err(remote.break_with(Broken::Diverged(format!(
                            "server is at version {}, this client at {}",
                            opened.version, remote.version
                        ))));
                    }
                    // Not applied: send it again.
                    stats.resent_commits += 1;
                }
            }
        };

        let elapsed = started.elapsed();
        let dirty = pages.dirty().len();
        stats.commits += 1;
        stats.commit_frames += parts.len() as u64;
        stats.committed_blocks += dirty as u64;
        stats.committed_bytes += (dirty * pages.page_size()) as u64;
        stats.commit_time += elapsed;
        stats.max_commit_time = stats.max_commit_time.max(elapsed);

        remote.version = version;
        remote.last_commit_id = commit_id.to_vec();
        remote.pending_commit = None;
        // The commit is durable on the server. Now write the blocks to the local copy.
        let written = pages.committed();
        remote.write_copy(pages, &written, stats);
        // The committed blocks are no longer dirty and can be evicted.
        pages.make_room(0, stats);
        stats.held_blocks = pages.held();
        Ok(())
    }

    /// Why the database no longer accepts writes, if it does not.
    pub fn broken(&self) -> Option<&Broken> {
        self.remote.broken.as_ref()
    }

    /// Takes the local copy out of the database, so that the next database opened on this VFS can use it. In a browser
    /// the local copy is a handle to the connection worker, which exists once per VFS.
    #[cfg(target_arch = "wasm32")]
    pub fn take_local(&mut self) -> Option<Box<dyn LocalStore>> {
        match std::mem::replace(&mut self.remote.local, LocalCopy::None) {
            LocalCopy::Ready(store) => Some(store),
            LocalCopy::None => None,
        }
    }

    /// Releases the lease. Best effort: if this fails, the lease expires on the server.
    ///
    /// A broken database cannot release its lease, and the server would keep it open on this connection and refuse to
    /// open it again there. The connection is dropped instead; the next request reconnects.
    pub fn close(&self, client: &mut Client) {
        if self.remote.broken.is_some() {
            client.disconnect();
            return;
        }
        if !self.remote.on_current_connection(client) {
            return;
        }
        let _ = client.call(client_frame::Body::CloseDb(pb::CloseDb {
            db_id: self.remote.db_id.clone(),
            lease_epoch: self.remote.lease_epoch,
        }));
    }
}

impl Source for Fetch<'_> {
    fn fill(&mut self, pages: &mut Pages, first: u64, count: u64, stats: &mut Stats) -> Result<(), Broken> {
        let remote = &mut *self.remote;
        if let Some(broken) = &remote.broken {
            return Err(broken.clone());
        }
        // Try the local copy first. Its reads are queued behind pending writes, so it returns the state of the last
        // commit.
        if remote.take_from_copy(pages, first, count, stats) {
            return Ok(());
        }
        if !remote.on_current_connection(self.client) {
            // Reads reconnect once, without a deadline. If that fails, the read fails.
            remote
                .resume(self.client, pages.page_size(), stats)
                .map_err(|err| match err {
                    err if err.is_access_denied() => remote.break_with(Broken::Denied(err.to_string())),
                    err => remote.break_with(Broken::Uncertain(err.to_string())),
                })?;
        }
        remote
            .load(self.client, pages, first, count, stats)
            .map_err(|err| match err {
                err if err.is_fenced() => remote.break_with(Broken::Fenced),
                err => Broken::Refused(err.to_string()),
            })?;
        // Write the fetched blocks to the local copy.
        let fetched: Vec<u64> = (first..first + count).collect();
        remote.write_copy(pages, &fetched, stats);
        Ok(())
    }
}

impl Remote {
    /// Loads the blocks after opening: with `Load::Preload` all of them, from the local copy if it is current and
    /// complete, otherwise from the server. With `Load::OnDemand`, only checks the local copy.
    fn fill(&mut self, client: &mut Client, pages: &mut Pages, stats: &mut Stats) -> Result<(), ClientError> {
        let from_copy = self.take_copy(client, pages, stats)?;
        if !pages.on_demand() && pages.page_count() > 0 && !from_copy {
            let count = pages.page_count();
            self.load(client, pages, 0, count, stats)?;
            // Write all blocks to the local copy, so that it starts at the same version.
            self.write_copy(pages, &pages.indexes(), stats);
        }
        // A preloaded database can exceed the memory limit right away.
        pages.make_room(0, stats);
        stats.held_blocks = pages.held();
        Ok(())
    }

    /// Checks whether the local copy can be used. A copy that is behind is caught up if possible, otherwise it is
    /// cleared. With `Load::Preload`, loads the database from the copy. Returns true if all blocks were loaded from
    /// it.
    fn take_copy(&mut self, client: &mut Client, pages: &mut Pages, stats: &mut Stats) -> Result<bool, ClientError> {
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
            head.subject == self.subject && head.db_id == self.db_id && head.page_size as usize == pages.page_size()
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
        if head.version < self.version && !self.catch_copy_up(client, pages, &head, stats)? {
            // Catching up is not possible or too expensive. Clear the local copy and load from the server.
            self.forget_copy(stats);
            return Ok(false);
        }

        // The local copy is current. With `Load::OnDemand`, blocks are read from it on first access instead of
        // now.
        if pages.on_demand() {
            return Ok(false);
        }
        // Read in chunks: in a browser, blocks are transferred through the fixed-size bridge buffer.
        let at_once = crate::local::blocks_per_read(pages.page_size());
        let mut first = 0;
        while first < pages.page_count() {
            let count = at_once.min(pages.page_count() - first);
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
                pages.keep(first + offset as u64, data);
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
    fn catch_copy_up(
        &mut self,
        client: &mut Client,
        pages: &mut Pages,
        behind: &Head,
        stats: &mut Stats,
    ) -> Result<bool, ClientError> {
        let changes = client.changes(&self.db_id, behind.version)?;
        if !changes.complete || changes.to_version != self.version {
            // The change log does not cover the versions from the copy's version to the current one.
            return Ok(false);
        }
        let page_count = pages.page_count();
        let runs: Vec<(u64, u64)> = runs(&changes.blocks)
            .into_iter()
            .filter_map(|(first, count)| {
                let count = count.min(page_count.saturating_sub(first));
                (count > 0).then_some((first, count))
            })
            .collect();
        // If more than a third of the database changed, or there are too many ranges, loading it whole is cheaper.
        if changes.blocks.len() as u64 > page_count / 3 || runs.len() > MAX_CATCH_UP_RANGES {
            return Ok(false);
        }

        let head = self.copy_head(pages);
        if self.local.catch_up(&head, &changes.blocks).is_err() {
            stats.local_failures += 1;
            self.local = LocalCopy::None;
            return Ok(false);
        }
        stats.caught_up += 1;
        stats.forgotten_blocks += changes.blocks.len() as u64;

        // With `Load::OnDemand`, the removed blocks are fetched when accessed. With `Load::Preload`, fetch them now,
        // in a single request with one range per run instead of one round trip per run.
        if !pages.on_demand() && !runs.is_empty() {
            let started = Moment::now();
            let blocks = client.fetch_ranges(&self.db_id, self.version, &runs)?;
            stats.fetches += 1;
            stats.fetched_blocks += blocks.len() as u64;
            stats.fetch_time += started.elapsed();
            let filled: Vec<u64> = blocks.iter().map(|(index, _)| *index).collect();
            for (index, data) in blocks {
                pages.keep(index, data);
            }
            self.write_copy(pages, &filled, stats);
        }
        Ok(true)
    }

    /// Head for writes to the local copy. It describes the state after the last commit.
    fn copy_head(&self, pages: &Pages) -> Head {
        Head {
            subject: self.subject.clone(),
            db_id: self.db_id.clone(),
            page_size: pages.page_size() as u32,
            page_count: pages.stable_page_count(),
            version: self.version,
        }
    }

    /// Loads the blocks from `first` on that the local copy holds, at most `count` and up to the first missing block.
    /// Returns true if block `first` was loaded.
    fn take_from_copy(&mut self, pages: &mut Pages, first: u64, count: u64, stats: &mut Stats) -> bool {
        if self.local.is_none() {
            return false;
        }
        stats.local_reads += 1;
        let count = count.min(crate::local::blocks_per_read(pages.page_size()));
        let read = match self.local.read(first, count) {
            Ok(read) => read,
            Err(_) => {
                stats.local_failures += 1;
                self.local = LocalCopy::None;
                return false;
            }
        };
        if read.is_empty() || read.iter().any(|block| block.len() != pages.page_size()) {
            stats.local_misses += 1;
            return false;
        }
        stats.local_blocks_read += read.len() as u64;
        for (offset, data) in read.into_iter().enumerate() {
            pages.keep(first + offset as u64, data);
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
    fn write_copy(&mut self, pages: &Pages, indexes: &[u64], stats: &mut Stats) {
        if self.local.is_none() || indexes.is_empty() {
            return;
        }
        // Use the page count of the last commit. `page_count` may include an uncommitted transaction, but these
        // blocks belong to the committed version.
        let head = self.copy_head(pages);
        let blocks: Vec<(u64, Vec<u8>)> = indexes
            .iter()
            .filter_map(|index| pages.block(*index).map(|data| (*index, data.to_vec())))
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

    fn parts(&self, pages: &Pages, commit_id: &[u8], max_frame_bytes: usize) -> Vec<pb::Commit> {
        let per_part = (max_frame_bytes.saturating_sub(COMMIT_FRAME_OVERHEAD)
            / (pages.page_size() + COMMIT_BLOCK_OVERHEAD))
            .max(1);
        let blocks: Vec<pb::Block> = pages
            .dirty()
            .into_iter()
            .map(|(index, data)| pb::Block {
                index,
                data: data.to_vec(),
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
                page_count: pages.page_count(),
                blocks,
                more: part + 1 < count,
                part: part as u32,
            })
            .collect()
    }

    /// Fetches `count` blocks from `first` on and stores those not yet in memory. Blocks in memory may be newer than
    /// the server's.
    fn load(
        &mut self,
        client: &mut Client,
        pages: &mut Pages,
        first: u64,
        count: u64,
        stats: &mut Stats,
    ) -> Result<(), ClientError> {
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
            pages.keep(first + offset as u64, data);
        }
        Ok(())
    }

    /// Reconnects and resumes the lease, retrying until `deadline`.
    fn resume_until(
        &mut self,
        client: &mut Client,
        page_size: usize,
        deadline: Moment,
        stats: &mut Stats,
    ) -> Result<pb::Opened, Broken> {
        loop {
            match self.resume(client, page_size, stats) {
                Ok(opened) => return Ok(opened),
                Err(err) if err.is_fenced() => return Err(self.break_with(Broken::Fenced)),
                // Not transient: the client has already asked the token source again.
                Err(err) if err.is_access_denied() => return Err(self.break_with(Broken::Denied(err.to_string()))),
                Err(err) if Moment::now() >= deadline => {
                    return Err(self.break_with(Broken::Uncertain(format!("no connection to the server: {err}"))));
                }
                Err(_) => crate::platform::pause(RECONNECT_PAUSE),
            }
        }
    }

    /// Whether the database is open on the client's current connection. After a new login, also one made for
    /// another request, it must be resumed there.
    fn on_current_connection(&self, client: &Client) -> bool {
        client.is_connected() && client.logins() == self.login
    }

    /// Resumes the lease on the current connection, after reconnecting if the connection is broken.
    fn resume(&mut self, client: &mut Client, page_size: usize, stats: &mut Stats) -> Result<pb::Opened, ClientError> {
        if !client.is_connected() {
            client.reconnect()?;
            stats.reconnects += 1;
        }
        let answer = client.call(client_frame::Body::Open(pb::Open {
            db_id: self.db_id.clone(),
            page_size: page_size as u32,
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
            server_frame::Body::Opened(opened) => {
                self.login = client.logins();
                Ok(opened)
            }
            other => Err(ClientError::Protocol(format!("expected Opened, got {other:?}"))),
        }
    }

    /// Breaks the database after a failed attempt to heal it. A lost connection and a transient server error leave
    /// it healable.
    fn break_on(&mut self, err: ClientError) -> Broken {
        let broken = match err {
            err if err.is_fenced() => Broken::Fenced,
            err if err.is_access_denied() => Broken::Denied(err.to_string()),
            ClientError::Server(e) if !matches!(e.code(), pb::ErrorCode::Internal | pb::ErrorCode::RateLimited) => {
                Broken::Refused(format!("{}: {}", e.code().as_str_name(), e.detail))
            }
            err => Broken::Uncertain(format!("no connection to the server: {err}")),
        };
        self.break_with(broken)
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
