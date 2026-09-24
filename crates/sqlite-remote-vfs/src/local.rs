//! Local copy of the database: a file natively, IndexedDB in a browser. It serves reads without a network round trip.
//!
//! The server is authoritative. Blocks are written to the local copy only after the server has acknowledged the
//! commit, so a missing, stale or damaged copy causes extra fetches but never data loss.
//!
//! The local copy may have gaps. Each block it holds has the content of the copy's version. A missing block is
//! fetched from the server and then written to the copy. Two rules keep the copy consistent:
//!
//! - **Reads and writes go through one queue.** A read never overtakes an earlier write. A block evicted from memory
//!   right after a commit is therefore read back with its committed content.
//! - **A failed write clears the copy.** Otherwise a later write could set the head to a newer version while the
//!   blocks of the failed write still have old content. If clearing fails too, the copy is never read again.

use crate::transport::AcrossThreads;

/// Metadata record of a local copy: owner, database, page size, page count and the version of the blocks it holds.
/// It is written atomically together with its blocks, so it always matches them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Head {
    /// Owner and name of the database. A copy whose owner, name or page size differs from the open database is not
    /// used.
    pub subject: String,
    pub db_id: String,
    pub page_size: u32,
    pub page_count: u64,
    pub version: u64,
}

/// Storage backend of a local copy. Errors are not fatal: the caller disables the copy and uses the server.
pub(crate) trait LocalStore: AcrossThreads {
    /// Returns the head, or `None` if there is no copy or it is not trusted, e.g. after an interrupted write.
    fn head(&mut self) -> Result<Option<Head>, String>;

    /// Returns the blocks from `first` on, at most `count`, up to the first missing block. An empty result means that
    /// block `first` is missing.
    fn read(&mut self, first: u64, count: u64) -> Result<Vec<Vec<u8>>, String>;

    /// Writes blocks and the new head. A crash during the write leaves the copy in its previous state or marked as
    /// untrusted. It never leaves a mix of old and new blocks under a head that looks valid.
    fn write(&mut self, head: &Head, blocks: &[(u64, &[u8])]) -> Result<(), String>;

    /// Removes the given blocks and sets the new head. All other blocks stay.
    ///
    /// Used to catch up a stale copy: the server's change log lists the blocks modified since the copy's version, and
    /// all other blocks are unchanged in the new version. A crash behaves as for [`LocalStore::write`].
    fn forget(&mut self, head: &Head, blocks: &[u64]) -> Result<(), String>;

    /// Deletes the local copy.
    fn clear(&mut self) -> Result<(), String>;

    /// Switches to the copy of database `db_id`, for a store that keeps one copy per database. A store with a single
    /// copy ignores it.
    fn select(&mut self, _db_id: &str) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use background::Background;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use file::FileStore;

/// State of the local copy during a session.
pub(crate) enum LocalCopy {
    /// No local copy, or it was disabled after an error.
    None,
    /// Before the first write. While the database is opened, the copy is read directly to decide whether it is
    /// usable.
    Ready(Box<dyn LocalStore>),
    /// After the first write, natively. Writes go to a background thread without blocking. Reads are queued behind
    /// them.
    #[cfg(not(target_arch = "wasm32"))]
    Writing(Background),
}

impl LocalCopy {
    pub fn is_none(&self) -> bool {
        matches!(self, LocalCopy::None)
    }

    /// Catches up the local copy: removes the given blocks and sets the head to the new version. Only possible before
    /// the first write, i.e. while the database is opened.
    pub fn catch_up(&mut self, head: &Head, blocks: &[u64]) -> Result<(), String> {
        match self {
            LocalCopy::Ready(store) => store.forget(head, blocks),
            _ => Err("a local copy can only be caught up before the first write".into()),
        }
    }

    /// Returns the blocks from `first` on, at most `count`, up to the first missing block. Reads are queued behind
    /// pending writes, so the result reflects every block written before.
    pub fn read(&mut self, first: u64, count: u64) -> Result<Vec<Vec<u8>>, String> {
        match self {
            LocalCopy::None => Ok(Vec::new()),
            LocalCopy::Ready(store) => store.read(first, count),
            #[cfg(not(target_arch = "wasm32"))]
            LocalCopy::Writing(writer) => writer.read(first, count),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod background {
    use std::sync::mpsc::{Sender, channel};
    use std::thread::JoinHandle;

    use super::{Head, LocalStore};

    /// A request to the background thread. Reads use the same channel as writes so that they cannot overtake them. A
    /// block read right after a commit must have its committed content.
    enum Job {
        Write(Head, Vec<(u64, Vec<u8>)>),
        Read(u64, u64, Sender<Result<Vec<Vec<u8>>, String>>),
    }

    /// Writes the local copy on a background thread.
    ///
    /// The server has already acknowledged every block written here, so commits do not wait for the disk. A disk
    /// write takes milliseconds, which would otherwise be added to every commit.
    pub(crate) struct Background {
        work: Option<Sender<Job>>,
        thread: Option<JoinHandle<u64>>,
        /// Number of failed writes. Shared with the thread, because it reports failures after the commit that
        /// caused them has returned.
        pub failures: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    impl Background {
        pub fn start(mut store: Box<dyn LocalStore>) -> Background {
            let (work, jobs) = channel::<Job>();
            let failures = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let counter = std::sync::Arc::clone(&failures);
            let thread = std::thread::Builder::new()
                .name("sqlite-remote-vfs-copy".into())
                .spawn(move || {
                    let mut written = 0;
                    // Set if clearing the copy after a failed write also failed. Reads then fail, because the copy
                    // could hold blocks older than its head claims.
                    let mut given_up = false;
                    for job in jobs {
                        match job {
                            Job::Write(head, blocks) => {
                                if given_up {
                                    continue;
                                }
                                let borrowed: Vec<(u64, &[u8])> =
                                    blocks.iter().map(|(index, data)| (*index, data.as_slice())).collect();
                                match store.write(&head, &borrowed) {
                                    Ok(()) => written += 1,
                                    Err(_) => {
                                        // The server has every block, so nothing is lost. Clear the copy; the
                                        // next open loads from the server.
                                        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        given_up = store.clear().is_err();
                                    }
                                }
                            }
                            Job::Read(first, count, reply) => {
                                let answer = if given_up {
                                    Err("local copy disabled after a failed write".to_string())
                                } else {
                                    store.read(first, count)
                                };
                                let _ = reply.send(answer);
                            }
                        }
                    }
                    written
                })
                .ok();
            Background {
                work: Some(work),
                thread,
                failures,
            }
        }

        /// Queues blocks for writing. Returns false if the thread has stopped. The caller then disables the copy.
        pub fn write(&mut self, head: Head, blocks: Vec<(u64, Vec<u8>)>) -> bool {
            match &self.work {
                Some(work) => work.send(Job::Write(head, blocks)).is_ok(),
                None => false,
            }
        }

        /// Reads after all previously queued writes have completed. This ensures that a block evicted right after a
        /// commit is read back with its committed content.
        pub fn read(&mut self, first: u64, count: u64) -> Result<Vec<Vec<u8>>, String> {
            let gone = || "local copy thread has stopped".to_string();
            let work = self.work.as_ref().ok_or_else(gone)?;
            let (reply, answer) = channel();
            work.send(Job::Read(first, count, reply)).map_err(|_| gone())?;
            answer.recv().map_err(|_| gone())?
        }
    }

    impl Drop for Background {
        /// Waits for queued writes to finish, so that the copy is up to date after the database is closed.
        fn drop(&mut self) {
            self.work = None;
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod file {
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::{Path, PathBuf};

    use super::{Head, LocalStore};

    const MAGIC: &[u8; 8] = b"rvfslcl2";
    /// Size of the header at the start of the file. Blocks start at this offset.
    const HEADER_BYTES: u64 = 4096;
    const CLEAN: u8 = 0;
    const WRITING: u8 = 1;

    /// Local copy in a single file: the header, block `i` at offset `HEADER_BYTES + i * page_size`, and after the last
    /// block a bitmap with one bit per block that marks which blocks are present. Without the bitmap, a block that
    /// was never written would read as zeroes and look like valid data.
    pub(crate) struct FileStore {
        path: PathBuf,
        file: Option<File>,
    }

    /// Bitmap of the blocks present in the copy, one bit per block.
    struct Present(Vec<u8>);

    impl Present {
        fn empty(page_count: u64) -> Present {
            Present(vec![0u8; page_count.div_ceil(8) as usize])
        }

        fn has(&self, index: u64) -> bool {
            let byte = (index / 8) as usize;
            byte < self.0.len() && self.0[byte] & (1 << (index % 8)) != 0
        }

        fn set(&mut self, index: u64) {
            let byte = (index / 8) as usize;
            if byte < self.0.len() {
                self.0[byte] |= 1 << (index % 8);
            }
        }

        fn clear(&mut self, index: u64) {
            let byte = (index / 8) as usize;
            if byte < self.0.len() {
                self.0[byte] &= !(1 << (index % 8));
            }
        }

        /// Returns the bitmap for a different page count. Bits for blocks beyond the new end are cleared.
        fn resized(&self, page_count: u64) -> Present {
            let mut next = Present::empty(page_count);
            let keep = next.0.len().min(self.0.len());
            next.0[..keep].copy_from_slice(&self.0[..keep]);
            // The last byte kept may still hold bits for blocks beyond the new end.
            for index in page_count..page_count.next_multiple_of(8) {
                next.clear(index);
            }
            next
        }
    }

    impl FileStore {
        pub fn new(path: impl AsRef<Path>) -> FileStore {
            FileStore {
                path: path.as_ref().to_path_buf(),
                file: None,
            }
        }

        fn open(&mut self) -> Result<&mut File, String> {
            if self.file.is_none() {
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(&self.path)
                    .map_err(|err| format!("{}: {err}", self.path.display()))?;
                self.file = Some(file);
            }
            Ok(self.file.as_mut().expect("just opened"))
        }

        fn read_header(&mut self) -> Result<Option<(Head, u8)>, String> {
            let file = self.open()?;
            let length = file.metadata().map_err(text)?.len();
            if length < HEADER_BYTES {
                return Ok(None);
            }
            let mut bytes = vec![0u8; HEADER_BYTES as usize];
            file.seek(SeekFrom::Start(0)).map_err(text)?;
            file.read_exact(&mut bytes).map_err(text)?;
            Ok(decode(&bytes))
        }

        fn write_header(&mut self, head: &Head, state: u8) -> Result<(), String> {
            let bytes = encode(head, state);
            let file = self.open()?;
            file.seek(SeekFrom::Start(0)).map_err(text)?;
            file.write_all(&bytes).map_err(text)?;
            file.sync_data().map_err(text)
        }

        /// Offset of the bitmap, directly after the last block. When the database grows, the bitmap moves and the
        /// blocks stay in place.
        fn bits_at(head: &Head) -> u64 {
            HEADER_BYTES + head.page_count * head.page_size as u64
        }

        fn read_present(&mut self, head: &Head) -> Result<Present, String> {
            let length = head.page_count.div_ceil(8) as usize;
            let at = Self::bits_at(head);
            let file = self.open()?;
            if file.metadata().map_err(text)?.len() < at + length as u64 {
                return Ok(Present::empty(head.page_count));
            }
            let mut bytes = vec![0u8; length];
            file.seek(SeekFrom::Start(at)).map_err(text)?;
            file.read_exact(&mut bytes).map_err(text)?;
            Ok(Present(bytes))
        }
    }

    impl LocalStore for FileStore {
        fn head(&mut self) -> Result<Option<Head>, String> {
            // A header in the writing state means that a write was interrupted. The blocks may be partly old and
            // partly new, so the copy is not used.
            Ok(self
                .read_header()?
                .filter(|(_, state)| *state == CLEAN)
                .map(|(head, _)| head))
        }

        fn read(&mut self, first: u64, count: u64) -> Result<Vec<Vec<u8>>, String> {
            let Some((head, CLEAN)) = self.read_header()? else {
                return Ok(Vec::new());
            };
            let present = self.read_present(&head)?;
            let run = (first..(first + count).min(head.page_count))
                .take_while(|index| present.has(*index))
                .count();
            if run == 0 {
                return Ok(Vec::new());
            }
            let page_size = head.page_size as usize;
            let mut blocks = Vec::with_capacity(run);
            let file = self.open()?;
            file.seek(SeekFrom::Start(HEADER_BYTES + first * page_size as u64))
                .map_err(text)?;
            for _ in 0..run {
                let mut block = vec![0u8; page_size];
                file.read_exact(&mut block).map_err(text)?;
                blocks.push(block);
            }
            Ok(blocks)
        }

        fn write(&mut self, head: &Head, blocks: &[(u64, &[u8])]) -> Result<(), String> {
            // Mark the header as writing before changing any block. A crash before the final header write leaves
            // the copy marked as untrusted.
            let before = self.read_header()?.map(|(head, _)| head);
            let mut present = match &before {
                Some(before) => self.read_present(before)?.resized(head.page_count),
                None => Present::empty(head.page_count),
            };
            let stale = before.unwrap_or_else(|| Head {
                version: 0,
                ..head.clone()
            });
            self.write_header(&stale, WRITING)?;

            let page_size = head.page_size as u64;
            let file = self.open()?;
            for (index, data) in blocks {
                if *index >= head.page_count {
                    continue; // beyond the end of the database after this commit
                }
                file.seek(SeekFrom::Start(HEADER_BYTES + index * page_size))
                    .map_err(text)?;
                file.write_all(data).map_err(text)?;
                present.set(*index);
            }
            let at = Self::bits_at(head);
            file.seek(SeekFrom::Start(at)).map_err(text)?;
            file.write_all(&present.0).map_err(text)?;
            file.set_len(at + present.0.len() as u64).map_err(text)?;
            file.sync_data().map_err(text)?;

            self.write_header(head, CLEAN)
        }

        fn forget(&mut self, head: &Head, blocks: &[u64]) -> Result<(), String> {
            let Some(before) = self.read_header()?.map(|(head, _)| head) else {
                return Err("no local copy to catch up".into());
            };
            let mut present = self.read_present(&before)?.resized(head.page_count);
            for index in blocks {
                present.clear(*index);
            }
            // Same order as in `write`: mark the header as writing first, so that a crash leaves the copy untrusted.
            self.write_header(&before, WRITING)?;
            let at = Self::bits_at(head);
            let file = self.open()?;
            file.seek(SeekFrom::Start(at)).map_err(text)?;
            file.write_all(&present.0).map_err(text)?;
            file.set_len(at + present.0.len() as u64).map_err(text)?;
            file.sync_data().map_err(text)?;
            self.write_header(head, CLEAN)
        }

        fn clear(&mut self) -> Result<(), String> {
            self.file = None;
            match std::fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(format!("{}: {err}", self.path.display())),
            }
        }
    }

    fn encode(head: &Head, state: u8) -> Vec<u8> {
        let mut bytes = vec![0u8; HEADER_BYTES as usize];
        bytes[0..8].copy_from_slice(MAGIC);
        bytes[8] = state;
        bytes[12..16].copy_from_slice(&head.page_size.to_le_bytes());
        bytes[16..24].copy_from_slice(&head.page_count.to_le_bytes());
        bytes[24..32].copy_from_slice(&head.version.to_le_bytes());
        let subject = head.subject.as_bytes();
        let db_id = head.db_id.as_bytes();
        bytes[32..34].copy_from_slice(&(subject.len() as u16).to_le_bytes());
        bytes[34..36].copy_from_slice(&(db_id.len() as u16).to_le_bytes());
        let start = 36;
        bytes[start..start + subject.len()].copy_from_slice(subject);
        let start = start + subject.len();
        bytes[start..start + db_id.len()].copy_from_slice(db_id);
        bytes
    }

    fn decode(bytes: &[u8]) -> Option<(Head, u8)> {
        if &bytes[0..8] != MAGIC {
            return None;
        }
        let state = bytes[8];
        let page_size = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
        let page_count = u64::from_le_bytes(bytes[16..24].try_into().ok()?);
        let version = u64::from_le_bytes(bytes[24..32].try_into().ok()?);
        let subject_len = u16::from_le_bytes(bytes[32..34].try_into().ok()?) as usize;
        let db_id_len = u16::from_le_bytes(bytes[34..36].try_into().ok()?) as usize;
        let start = 36;
        let subject = String::from_utf8(bytes.get(start..start + subject_len)?.to_vec()).ok()?;
        let start = start + subject_len;
        let db_id = String::from_utf8(bytes.get(start..start + db_id_len)?.to_vec()).ok()?;
        Some((
            Head {
                subject,
                db_id,
                page_size,
                page_count,
                version,
            },
            state,
        ))
    }

    fn text(err: std::io::Error) -> String {
        err.to_string()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn head(version: u64, page_count: u64) -> Head {
        Head {
            subject: "alice".into(),
            db_id: "db".into(),
            page_size: 8,
            page_count,
            version,
        }
    }

    fn store(name: &str) -> (FileStore, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("sqlite-remote-vfs-local-{name}-{}.copy", std::process::id()));
        let _ = std::fs::remove_file(&path);
        (FileStore::new(&path), path)
    }

    #[test]
    fn new_store_is_empty() {
        let (mut store, path) = store("fresh");
        assert_eq!(store.head().unwrap(), None);
        assert!(store.read(0, 1).unwrap().is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn written_blocks_read_back() {
        let (mut store, path) = store("roundtrip");
        let first = vec![1u8; 8];
        let second = vec![2u8; 8];
        store
            .write(&head(1, 2), &[(0, &first), (1, &second)])
            .expect("write the copy");

        assert_eq!(store.head().unwrap(), Some(head(1, 2)));
        assert_eq!(store.read(0, 2).unwrap(), vec![first, second]);
        assert!(store.read(2, 1).unwrap().is_empty(), "beyond the end of the file");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn unwritten_block_is_missing_not_zero() {
        let (mut store, path) = store("gap");
        // Write blocks 0 and 2 of a three-block database. Block 1 is missing.
        store
            .write(&head(1, 3), &[(0, &[1u8; 8]), (2, &[3u8; 8])])
            .expect("write the copy");

        assert_eq!(
            store.read(0, 3).unwrap(),
            vec![vec![1u8; 8]],
            "the read stops at the missing block"
        );
        assert!(
            store.read(1, 1).unwrap().is_empty(),
            "the missing block returns nothing"
        );
        assert_eq!(store.read(2, 1).unwrap(), vec![vec![3u8; 8]], "the block after the gap");

        // After block 1 is written, all three blocks are read.
        store.write(&head(1, 3), &[(1, &[2u8; 8])]).unwrap();
        assert_eq!(
            store.read(0, 3).unwrap(),
            vec![vec![1u8; 8], vec![2u8; 8], vec![3u8; 8]]
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn newer_version_replaces_block() {
        let (mut store, path) = store("replace");
        store.write(&head(1, 1), &[(0, &[1u8; 8])]).unwrap();
        store.write(&head(2, 1), &[(0, &[9u8; 8])]).unwrap();

        assert_eq!(store.head().unwrap().unwrap().version, 2);
        assert_eq!(store.read(0, 1).unwrap(), vec![vec![9u8; 8]]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn shrinking_drops_blocks_past_end() {
        let (mut store, path) = store("truncate");
        store.write(&head(1, 2), &[(0, &[1u8; 8]), (1, &[2u8; 8])]).unwrap();
        store.write(&head(2, 1), &[(0, &[3u8; 8])]).unwrap();

        assert!(store.read(1, 1).unwrap().is_empty());
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            4096 + 8 + 1,
            "the file is the header, one block and one bitmap byte"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn growing_keeps_existing_blocks() {
        let (mut store, path) = store("grow");
        store.write(&head(1, 1), &[(0, &[1u8; 8])]).unwrap();
        // With one block, the bitmap is at the offset where block 1 is written now.
        store.write(&head(2, 2), &[(1, &[2u8; 8])]).unwrap();

        assert_eq!(store.read(0, 2).unwrap(), vec![vec![1u8; 8], vec![2u8; 8]]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn copy_interrupted_mid_write_is_untrusted() {
        let (mut store, path) = store("interrupted");
        store.write(&head(1, 1), &[(0, &[1u8; 8])]).unwrap();

        // Simulate a crash during a write: set the header state to writing.
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[8] = 1; // the writing state, see `encode`
        std::fs::write(&path, &bytes).unwrap();

        let mut store = FileStore::new(&path);
        assert_eq!(
            store.head().unwrap(),
            None,
            "a head in the writing state is not trusted"
        );
        assert!(store.read(0, 1).unwrap().is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn foreign_file_is_not_a_copy() {
        let (mut store, path) = store("foreign");
        std::fs::write(&path, vec![0x5au8; 8192]).unwrap();
        assert_eq!(store.head().unwrap(), None);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn clear_deletes_file() {
        let (mut store, path) = store("clear");
        store.write(&head(1, 1), &[(0, &[1u8; 8])]).unwrap();
        store.clear().unwrap();

        assert!(!path.exists());
        assert_eq!(store.head().unwrap(), None);
        store.clear().expect("clearing an already deleted copy succeeds");
    }

    #[test]
    fn read_waits_for_queued_writes() {
        // A block evicted from memory right after a commit must be read back with its committed content. Writes are
        // not awaited, so only the queue order guarantees this.
        let (store, path) = store("ordered");
        let mut writer = Background::start(Box::new(store));
        for version in 1..20u64 {
            writer.write(head(version, 1), vec![(0, vec![version as u8; 8])]);
        }
        assert_eq!(
            writer.read(0, 1).expect("read the copy"),
            vec![vec![19u8; 8]],
            "the read returns the last queued write"
        );
        drop(writer);
        let _ = std::fs::remove_file(path);
    }
}
