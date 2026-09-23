//! Integration tests against a running server. They need `SQLITE_REMOTE_TEST_URL`, e.g. `ws://localhost:8080/v1/ws`,
//! and are skipped without it. Each test uses a random key and therefore its own subject, so all tests can share one
//! server.

use std::sync::atomic::{AtomicUsize, Ordering};

use std::sync::Arc;

use rusqlite::{Connection, ErrorCode, OpenFlags};
use sqlite_remote_vfs::{Algorithm, Config, Load, Local, Memory, RemoteVfs, Signer};

const KEY: [u8; 32] = [0x11; 32];
const OTHER_KEY: [u8; 32] = [0x22; 32];

fn server_url() -> Option<String> {
    let url = std::env::var("SQLITE_REMOTE_TEST_URL").ok();
    if url.is_none() {
        eprintln!("skipped: SQLITE_REMOTE_TEST_URL is not set");
    }
    url
}

/// Ed25519 signer for the tests. The crate has no key handling of its own: an application creates or loads the key
/// and passes a `Signer`.
struct TestSigner(ed25519_dalek::SigningKey);

impl TestSigner {
    /// Returns a signer with a random key, so a test run does not see data an earlier run left on the server. The
    /// same key always maps to the same subject. Different keys map to different subjects.
    fn fresh() -> Arc<dyn Signer> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        Arc::new(TestSigner(ed25519_dalek::SigningKey::from_bytes(&seed)))
    }
}

impl Signer for TestSigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn public_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer as _;
        self.0.sign(message).to_bytes().to_vec()
    }
}

fn unique(prefix: &str) -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let mut random = [0u8; 4];
    getrandom::fill(&mut random).unwrap();
    let hex: String = random.iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}-{hex}-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

fn register(config: Config) -> RemoteVfs {
    RemoteVfs::register(&unique("vfs"), config).expect("register VFS")
}

fn raw_key(key: &[u8; 32]) -> String {
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    format!("x'{hex}'")
}

fn open(vfs: &RemoteVfs, db: &str, key: &[u8; 32]) -> rusqlite::Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags_and_vfs(db, flags, vfs.encrypted_name().as_str())?;
    conn.pragma_update(None, "key", raw_key(key))?;
    let mode: String = conn.query_row("PRAGMA journal_mode = MEMORY", [], |row| row.get(0))?;
    assert_eq!(mode, "memory");
    Ok(conn)
}

fn insert_rows(conn: &Connection, from: i64, count: i64, payload_bytes: usize) {
    conn.execute_batch("BEGIN").unwrap();
    for id in from..from + count {
        conn.execute(
            "INSERT INTO t (id, payload) VALUES (?1, randomblob(?2))",
            (id, payload_bytes as i64),
        )
        .unwrap();
    }
    conn.execute_batch("COMMIT").unwrap();
}

fn count(conn: &Connection) -> i64 {
    conn.query_row("SELECT count(*) FROM t", [], |row| row.get(0)).unwrap()
}

fn integrity(conn: &Connection) -> String {
    conn.query_row("PRAGMA integrity_check", [], |row| row.get(0)).unwrap()
}

const CREATE: &str = "CREATE TABLE t (id INTEGER PRIMARY KEY, payload BLOB)";

#[test]
fn database_persists_on_server() {
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();

    let writer = register(Config::new(&url, subject.clone()));
    let conn = open(&writer, "db", &KEY).unwrap();
    conn.execute_batch(CREATE).unwrap();
    insert_rows(&conn, 0, 100, 200);
    drop(conn);

    // A second VFS instance in the same process acts as another client. It shares nothing with the first but the
    // server.
    let reader = register(Config::new(&url, subject.clone()));
    let conn = open(&reader, "db", &KEY).unwrap();
    assert_eq!(count(&conn), 100);
    assert_eq!(integrity(&conn), "ok");
}

#[test]
fn takeover_sees_commits_and_fences_holder() {
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();

    let first = register(Config::new(&url, subject.clone()));
    let first_conn = open(&first, "db", &KEY).unwrap();
    first_conn.execute_batch(CREATE).unwrap();
    insert_rows(&first_conn, 0, 50, 200);

    // The first connection is still open, so the data can only come from the server.
    let mut config = Config::new(&url, subject.clone());
    config.takeover = true;
    let second = register(config);
    let second_conn = open(&second, "db", &KEY).unwrap();
    assert_eq!(count(&second_conn), 50);

    // The takeover revoked the first instance's lease, so its next write must fail.
    let err = first_conn
        .execute("INSERT INTO t (id, payload) VALUES (1000, x'00')", [])
        .unwrap_err();
    assert_eq!(err.sqlite_error_code(), Some(ErrorCode::SystemIoFailure), "{err}");
    insert_rows(&second_conn, 50, 10, 200);
    assert_eq!(count(&second_conn), 60);
}

#[test]
fn held_lease_blocks_second_open() {
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();

    let holder = register(Config::new(&url, subject.clone()));
    let _conn = open(&holder, "db", &KEY).unwrap();

    let other = register(Config::new(&url, subject.clone()));
    let err = open(&other, "db", &KEY).unwrap_err();
    println!("open while the lease is held: {err}");
    assert!(
        matches!(
            err.sqlite_error_code(),
            Some(ErrorCode::DatabaseBusy | ErrorCode::CannotOpen)
        ),
        "{err}"
    );
}

#[test]
fn on_demand_fetches_only_needed_blocks() {
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();

    let writer = register(Config::new(&url, subject.clone()));
    let conn = open(&writer, "db", &KEY).unwrap();
    conn.execute_batch(CREATE).unwrap();
    insert_rows(&conn, 0, 2000, 500);
    let pages: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0)).unwrap();
    drop(conn);

    let mut config = Config::new(&url, subject.clone());
    config.load = Load::OnDemand { blocks_per_fetch: 4 };
    let reader = register(config);
    let conn = open(&reader, "db", &KEY).unwrap();
    let length: i64 = conn
        .query_row("SELECT length(payload) FROM t WHERE id = 1234", [], |row| row.get(0))
        .unwrap();
    assert_eq!(length, 500);
    let after_lookup = reader.stats();
    println!(
        "{pages} pages; one lookup fetched {} blocks in {} fetches",
        after_lookup.fetched_blocks, after_lookup.fetches
    );
    assert!(after_lookup.fetched_blocks < pages as u64 / 4, "{after_lookup:?}");

    assert_eq!(count(&conn), 2000);
    assert_eq!(integrity(&conn), "ok");
    println!(
        "after a full scan: {} blocks in {} fetches",
        reader.stats().fetched_blocks,
        reader.stats().fetches
    );
}

#[test]
fn rollback_sends_no_commit() {
    let Some(url) = server_url() else { return };
    let vfs = register(Config::new(&url, TestSigner::fresh()));
    let conn = open(&vfs, "db", &KEY).unwrap();
    conn.execute_batch(CREATE).unwrap();
    let before = vfs.stats();

    conn.execute_batch("BEGIN; INSERT INTO t (id, payload) VALUES (1, x'01'); ROLLBACK;")
        .unwrap();
    assert_eq!(vfs.stats().commits, before.commits);
    assert_eq!(count(&conn), 0);
}

#[test]
fn large_commit_and_rekey_span_frames() {
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();

    let vfs = register(Config::new(&url, subject.clone()));
    let conn = open(&vfs, "db", &KEY).unwrap();
    conn.execute_batch(CREATE).unwrap();
    let before = vfs.stats();
    insert_rows(&conn, 0, 3000, 1000);
    let after = vfs.stats();
    println!(
        "3 MB in one transaction: {} commit(s), {} frames, {} blocks",
        after.commits - before.commits,
        after.commit_frames - before.commit_frames,
        after.committed_blocks - before.committed_blocks
    );
    assert_eq!(after.commits - before.commits, 1);
    assert!(after.commit_frames - before.commit_frames > 1);

    conn.pragma_update(None, "rekey", raw_key(&OTHER_KEY)).unwrap();
    drop(conn);

    let reader = register(Config::new(&url, subject.clone()));
    let conn = open(&reader, "db", &OTHER_KEY).unwrap();
    assert_eq!(count(&conn), 3000);
    assert_eq!(integrity(&conn), "ok");
}

#[test]
fn dropped_connection_is_resumed() {
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();

    let vfs = register(Config::new(&url, subject.clone()));
    let conn = open(&vfs, "db", &KEY).unwrap();
    conn.execute_batch(CREATE).unwrap();
    insert_rows(&conn, 0, 10, 100);

    vfs.drop_connection();
    insert_rows(&conn, 10, 10, 100);
    assert!(vfs.stats().reconnects >= 1, "{:?}", vfs.stats());
    drop(conn);

    let reader = register(Config::new(&url, subject.clone()));
    let conn = open(&reader, "db", &KEY).unwrap();
    assert_eq!(count(&conn), 20);
}

#[test]
fn rollback_after_cache_spill_restores_server_state() {
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();

    let vfs = register(Config::new(&url, subject.clone()));
    let conn = open(&vfs, "db", &KEY).unwrap();
    conn.execute_batch("PRAGMA cache_size = 16").unwrap();
    conn.execute_batch(CREATE).unwrap();
    insert_rows(&conn, 0, 10, 200);
    let before = vfs.stats();

    // Far more data than the 16-page cache holds, so SQLite writes pages to the main file before the commit
    // (cache spill).
    conn.execute_batch("BEGIN").unwrap();
    for id in 100..400 {
        conn.execute("INSERT INTO t (id, payload) VALUES (?1, randomblob(4000))", [id])
            .unwrap();
    }
    conn.execute_batch("ROLLBACK").unwrap();

    // The rollback writes the original pages back and syncs them. That is one commit, and it restores the state from
    // before the transaction.
    assert_eq!(
        vfs.stats().commits,
        before.commits + 1,
        "rollback must restore the pages in one commit"
    );
    assert_eq!(count(&conn), 10);
    assert_eq!(integrity(&conn), "ok");
    drop(conn);

    let reader = register(Config::new(&url, subject.clone()));
    let conn = open(&reader, "db", &KEY).unwrap();
    assert_eq!(
        count(&conn),
        10,
        "server must hold the state from before the transaction"
    );
    assert_eq!(integrity(&conn), "ok");
}

#[test]
fn vacuum_shrinks_database_on_server() {
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();

    let vfs = register(Config::new(&url, subject.clone()));
    let conn = open(&vfs, "db", &KEY).unwrap();
    conn.execute_batch(CREATE).unwrap();
    insert_rows(&conn, 0, 500, 1000);
    conn.execute_batch("DELETE FROM t WHERE id % 2 = 0").unwrap();
    let before: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0)).unwrap();

    conn.execute_batch("VACUUM").unwrap();
    let after: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0)).unwrap();
    println!("vacuum: {before} pages before, {after} after");
    assert!(after < before);
    assert_eq!(count(&conn), 250);
    drop(conn);

    let reader = register(Config::new(&url, subject.clone()));
    let conn = open(&reader, "db", &KEY).unwrap();
    assert_eq!(count(&conn), 250);
    assert_eq!(integrity(&conn), "ok");
}

#[test]
fn empty_database_reopens_without_takeover() {
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();

    let vfs = register(Config::new(&url, subject.clone()));
    let conn = open(&vfs, "db", &KEY).unwrap();
    drop(conn);

    // Closing releases the lease, so the next instance acquires it without a takeover.
    let again = register(Config::new(&url, subject.clone()));
    let conn = open(&again, "db", &KEY).unwrap();
    conn.execute_batch(CREATE).unwrap();
    insert_rows(&conn, 0, 5, 100);
    assert_eq!(count(&conn), 5);
}

// ---------------------------------------------------------------------------------------------------------------
// Local copy
// ---------------------------------------------------------------------------------------------------------------

fn copy_path(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("{}-{}.copy", unique(name), std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

fn with_copy(url: &str, subject: &Arc<dyn Signer>, path: &std::path::Path) -> Config {
    let mut config = Config::new(url, subject.clone());
    config.local = Local::File(path.to_path_buf());
    config
}

/// Creates table `t` with `rows` rows in database `db`. With a local copy configured, the copy holds the result.
fn fill(vfs: &RemoteVfs, rows: i64) {
    let conn = open(vfs, "db", &KEY).expect("open database");
    conn.execute_batch(CREATE).expect("create table");
    insert_rows(&conn, 0, rows, 400);
    assert_eq!(count(&conn), rows);
}

#[test]
fn current_local_copy_avoids_fetches() {
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();
    let path = copy_path("current");

    let vfs = register(with_copy(&url, &subject, &path));
    fill(&vfs, 40);
    let written = vfs.stats();
    assert!(written.local_writes > 0, "local copy must have been written");
    drop(vfs);

    // The local copy has the same version as the server, so nothing is fetched.
    let again = register(with_copy(&url, &subject, &path));
    let conn = open(&again, "db", &KEY).expect("reopen database");
    assert_eq!(count(&conn), 40);
    assert_eq!(integrity(&conn), "ok");
    let stats = again.stats();
    assert_eq!(stats.fetches, 0, "no fetch expected with a current local copy");
    assert!(stats.local_blocks_read > 0, "blocks must be read from the local copy");
    let _ = std::fs::remove_file(path);
}

#[test]
fn without_local_copy_blocks_are_fetched() {
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();

    let vfs = register(Config::new(&url, subject.clone()));
    fill(&vfs, 40);
    drop(vfs);

    let again = register(Config::new(&url, subject.clone()));
    let conn = open(&again, "db", &KEY).expect("reopen database");
    assert_eq!(count(&conn), 40);
    assert!(again.stats().fetches > 0);
}

#[test]
fn stale_local_copy_is_caught_up() {
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();
    let path = copy_path("behind");

    let vfs = register(with_copy(&url, &subject, &path));
    fill(&vfs, 400);
    let pages = vfs.stats().committed_blocks;
    assert!(pages > 0);
    drop(vfs);

    // Another instance without a local copy commits three more rows, so the local copy is now behind the server.
    let other = register(Config::new(&url, subject.clone()));
    let conn = open(&other, "db", &KEY).expect("open from second instance");
    insert_rows(&conn, 1000, 3, 400);
    drop(conn);
    drop(other);

    let again = register(with_copy(&url, &subject, &path));
    let conn = open(&again, "db", &KEY).expect("reopen database");
    assert_eq!(count(&conn), 403, "must see the newer state from the server");
    assert_eq!(integrity(&conn), "ok");

    let stats = again.stats();
    assert_eq!(stats.caught_up, 1, "local copy must be caught up");
    assert!(
        stats.forgotten_blocks > 0,
        "changed blocks must be dropped from the local copy"
    );
    assert_eq!(stats.fetches, 1, "missing blocks must be fetched in one request");
    assert!(
        stats.fetched_blocks < stats.local_blocks_read / 4,
        "only changed blocks may be fetched: {} fetched, {} read locally",
        stats.fetched_blocks,
        stats.local_blocks_read
    );
    drop(conn);
    drop(again);

    // After the catch-up the local copy is complete and current, so the next open fetches nothing.
    let third = register(with_copy(&url, &subject, &path));
    let conn = open(&third, "db", &KEY).expect("reopen database a third time");
    assert_eq!(count(&conn), 403);
    assert_eq!(integrity(&conn), "ok");
    let stats = third.stats();
    assert_eq!(stats.caught_up, 0, "no catch-up expected");
    assert_eq!(stats.fetches, 0, "no fetch expected");
    let _ = std::fs::remove_file(path);
}

#[test]
fn local_copy_too_far_behind_is_replaced() {
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();
    let path = copy_path("far-behind");

    let vfs = register(with_copy(&url, &subject, &path));
    fill(&vfs, 20);
    drop(vfs);

    // 300 more commits change more than a third of the database's blocks. Above that share the VFS does not catch
    // up. It loads the database from the server and replaces the local copy.
    let other = register(Config::new(&url, subject.clone()));
    let conn = open(&other, "db", &KEY).expect("open from second instance");
    for row in 0..300i64 {
        insert_rows(&conn, 1000 + row, 1, 400);
    }
    drop(conn);
    drop(other);

    let again = register(with_copy(&url, &subject, &path));
    let conn = open(&again, "db", &KEY).expect("reopen database");
    assert_eq!(count(&conn), 320);
    assert_eq!(integrity(&conn), "ok");

    let stats = again.stats();
    assert_eq!(stats.caught_up, 0, "no catch-up expected");
    assert!(stats.fetches > 0, "database must be loaded from the server");
    let _ = std::fs::remove_file(path);
}

#[test]
fn on_demand_catch_up_fetches_nothing_extra() {
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();
    let path = copy_path("behind-on-demand");

    let on_demand = |path: &std::path::Path| {
        let mut config = with_copy(&url, &subject, path);
        config.load = Load::OnDemand { blocks_per_fetch: 16 };
        config
    };

    // 2000 rows, so one fetch of 16 blocks is a small part of the database. The comparison below depends on that.
    let vfs = register(on_demand(&path));
    fill(&vfs, 2000);
    drop(vfs);

    let other = register(Config::new(&url, subject.clone()));
    let conn = open(&other, "db", &KEY).expect("open from second instance");
    insert_rows(&conn, 10_000, 3, 400);
    drop(conn);
    drop(other);

    // With on-demand loading, catching up only drops the changed blocks from the local copy. They are fetched when
    // SQLite reads them.
    let again = register(on_demand(&path));
    let conn = open(&again, "db", &KEY).expect("reopen database");
    let opened = again.stats();
    assert_eq!(opened.caught_up, 1);
    // The catch-up itself fetches nothing. The only fetch is the range containing page 1, which every commit changes
    // and SQLite reads on open.
    assert!(
        opened.fetched_blocks <= 16,
        "open must fetch at most one range of 16 blocks, fetched {}",
        opened.fetched_blocks
    );

    assert_eq!(count(&conn), 2003);
    assert_eq!(integrity(&conn), "ok");
    let stats = again.stats();
    assert!(
        stats.fetched_blocks < stats.local_blocks_read / 4,
        "most blocks must come from the local copy: {} fetched, {} read locally",
        stats.fetched_blocks,
        stats.local_blocks_read
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn local_copy_of_other_subject_is_ignored() {
    let Some(url) = server_url() else { return };
    let path = copy_path("foreign");

    let vfs = register(with_copy(&url, &TestSigner::fresh(), &path));
    fill(&vfs, 20);
    drop(vfs);

    // Same local copy file, different subject. The copy belongs to another database and must not be used.
    let elsewhere = register(with_copy(&url, &TestSigner::fresh(), &path));
    let conn = open(&elsewhere, "db", &KEY).expect("open from second instance");
    conn.execute_batch(CREATE).expect("create table");
    assert_eq!(count(&conn), 0, "new database must be empty");
    assert_eq!(integrity(&conn), "ok");
    let _ = std::fs::remove_file(path);
}

#[test]
fn local_copy_ahead_of_server_fails_open() {
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();
    let path = copy_path("ahead");

    let vfs = register(with_copy(&url, &subject, &path));
    fill(&vfs, 20);
    drop(vfs);

    // Simulates a server restored from an older backup: the version of the local copy is set above the server's.
    // The version is at byte offset 24 of the file header (see `local.rs`).
    let mut bytes = std::fs::read(&path).expect("read local copy file");
    let version = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    bytes[24..32].copy_from_slice(&(version + 5).to_le_bytes());
    std::fs::write(&path, &bytes).expect("write local copy file");

    let again = register(with_copy(&url, &subject, &path));
    let refused = open(&again, "db", &KEY);
    assert!(
        refused.is_err(),
        "open must fail when the local copy is ahead of the server"
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn evicted_blocks_reload_from_local_copy() {
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();
    let path = copy_path("capped");

    // Memory limit of 16 blocks. The database is many times larger.
    let mut config = with_copy(&url, &subject, &path);
    config.memory = Memory::Blocks(16);
    config.load = Load::OnDemand { blocks_per_fetch: 8 };
    let vfs = register(config);
    let conn = open(&vfs, "db", &KEY).expect("open database");
    conn.execute_batch(CREATE).expect("create table");
    insert_rows(&conn, 0, 300, 400);
    let written = vfs.stats();

    // A full table scan needs far more blocks than the limit, so evicted blocks have to be reloaded.
    assert_eq!(count(&conn), 300);
    assert_eq!(integrity(&conn), "ok");

    let stats = vfs.stats();
    assert!(stats.evicted_blocks > 0, "blocks must be evicted");
    assert!(
        stats.local_blocks_read > written.local_blocks_read,
        "evicted blocks must be reloaded from the local copy"
    );
    assert_eq!(stats.fetches, written.fetches, "no fetch from the server expected");
    let _ = std::fs::remove_file(path);
}

#[test]
fn evicted_block_reloads_as_committed() {
    // The local copy is written in the background after each commit. A read from the local copy must not overtake
    // that write, or an evicted block would be reloaded with its content from before the commit. The memory limit is
    // small enough that each round reloads the changed block from the local copy.
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();
    let path = copy_path("evicted");

    let mut config = with_copy(&url, &subject, &path);
    config.memory = Memory::Blocks(8);
    config.load = Load::OnDemand { blocks_per_fetch: 4 };
    let vfs = register(config);
    let conn = open(&vfs, "db", &KEY).expect("open database");
    conn.execute_batch(CREATE).expect("create table");
    insert_rows(&conn, 0, 200, 400);

    for round in 1..=5i64 {
        conn.execute("UPDATE t SET payload = randomblob(?1) WHERE id = 0", [round * 100])
            .expect("update row 0");
        // A full scan evicts the block that was just committed.
        assert_eq!(count(&conn), 200);
        let length: i64 = conn
            .query_row("SELECT length(payload) FROM t WHERE id = 0", [], |row| row.get(0))
            .expect("read row 0");
        assert_eq!(length, round * 100, "reloaded block must have the committed content");
    }
    assert_eq!(integrity(&conn), "ok");
    assert!(vfs.stats().evicted_blocks > 0, "blocks must be evicted");
    let _ = std::fs::remove_file(path);
}

#[test]
fn local_copy_fills_during_on_demand_loading() {
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();
    let path = copy_path("on-demand");

    let on_demand = |path: &std::path::Path| {
        let mut config = with_copy(&url, &subject, path);
        config.load = Load::OnDemand { blocks_per_fetch: 8 };
        config
    };

    let vfs = register(on_demand(&path));
    fill(&vfs, 60);
    drop(vfs);

    // The first session loaded on demand. Every committed block was still written to the local copy.
    let again = register(on_demand(&path));
    let conn = open(&again, "db", &KEY).expect("reopen database");
    assert_eq!(count(&conn), 60);
    assert_eq!(integrity(&conn), "ok");
    let stats = again.stats();
    assert_eq!(stats.fetches, 0, "no fetch expected");
    assert!(stats.local_blocks_read > 0, "blocks must be read from the local copy");
    let _ = std::fs::remove_file(path);
}

#[test]
fn gaps_in_local_copy_are_filled_from_server() {
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();
    let path = copy_path("partial");

    // Another instance without a local copy creates the database, so this local copy starts empty.
    let maker = register(Config::new(&url, subject.clone()));
    fill(&maker, 60);
    drop(maker);

    // A session that reads one row leaves a local copy with gaps.
    let mut config = with_copy(&url, &subject, &path);
    config.load = Load::OnDemand { blocks_per_fetch: 2 };
    let partial = register(config);
    let conn = open(&partial, "db", &KEY).expect("open database on demand");
    let seen: i64 = conn
        .query_row("SELECT id FROM t WHERE id = 1", [], |row| row.get(0))
        .expect("read one row");
    assert_eq!(seen, 1);
    drop(conn);
    let fetched = partial.stats().fetched_blocks;
    assert!(
        fetched > 0 && fetched < 60,
        "reading one row must fetch only part of the database: {fetched}"
    );
    drop(partial);

    // A full read fetches the missing blocks from the server. The local copy with gaps is kept and filled.
    let again = register(with_copy(&url, &subject, &path));
    let conn = open(&again, "db", &KEY).expect("reopen database");
    assert_eq!(count(&conn), 60);
    assert_eq!(integrity(&conn), "ok");
    assert!(again.stats().fetches > 0, "missing blocks must be fetched");
    drop(conn);
    drop(again);

    // The local copy is now complete.
    let third = register(with_copy(&url, &subject, &path));
    let conn = open(&third, "db", &KEY).expect("reopen database a third time");
    assert_eq!(count(&conn), 60);
    assert_eq!(third.stats().fetches, 0, "no fetch expected from a complete local copy");
    let _ = std::fs::remove_file(path);
}

#[test]
fn same_key_opens_same_database() {
    let Some(url) = server_url() else { return };
    let mine = TestSigner::fresh();

    let vfs = register(Config::new(&url, mine.clone()));
    let conn = open(&vfs, "db", &KEY).expect("open database");
    conn.execute_batch(CREATE).expect("create table");
    insert_rows(&conn, 0, 20, 400);
    assert_eq!(count(&conn), 20);
    drop(conn);
    drop(vfs);

    // Same key, new connection: the server derives the same subject.
    let again = register(Config::new(&url, mine.clone()));
    let conn = open(&again, "db", &KEY).expect("reopen database");
    assert_eq!(count(&conn), 20);
    assert_eq!(integrity(&conn), "ok");
}

#[test]
fn other_key_cannot_open_database() {
    let Some(url) = server_url() else { return };
    let mine = TestSigner::fresh();
    let theirs = TestSigner::fresh();

    let vfs = register(Config::new(&url, mine.clone()));
    let conn = open(&vfs, "db", &KEY).expect("open database");
    conn.execute_batch(CREATE).expect("create table");
    insert_rows(&conn, 0, 20, 400);
    drop(conn);
    drop(vfs);

    // The same name under another key refers to a different database, which does not exist.
    let other = register(Config::new(&url, theirs.clone()));
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX; // without SQLITE_OPEN_CREATE
    let opened = Connection::open_with_flags_and_vfs("db", flags, other.encrypted_name().as_str());
    assert!(opened.is_err(), "open must fail for another key");
}

fn tables(conn: &Connection) -> i64 {
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn deleted_database_comes_back_empty_with_new_key() {
    let Some(url) = server_url() else { return };
    let vfs = register(Config::new(&url, TestSigner::fresh()));
    fill(&vfs, 30);
    vfs.delete_database("db").expect("delete database");

    // Nothing of the old database remains, so a new key works.
    let conn = open(&vfs, "db", &OTHER_KEY).expect("open recreated database");
    assert_eq!(tables(&conn), 0, "recreated database must be empty");
    conn.execute_batch(CREATE).unwrap();
    insert_rows(&conn, 0, 5, 100);
    assert_eq!(count(&conn), 5);
}

#[test]
fn deleted_database_is_not_found_without_create() {
    let Some(url) = server_url() else { return };
    let vfs = register(Config::new(&url, TestSigner::fresh()));
    fill(&vfs, 10);
    vfs.delete_database("db").expect("delete database");

    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let result = Connection::open_with_flags_and_vfs("db", flags, vfs.encrypted_name().as_str())
        .and_then(|conn| conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get::<_, i64>(0)));
    assert!(result.is_err(), "opening a deleted database without create must fail");
}

#[test]
fn delete_fences_holder_also_after_recreate() {
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();
    let holder = register(Config::new(&url, subject.clone()));
    let holder_conn = open(&holder, "db", &KEY).unwrap();
    holder_conn.execute_batch(CREATE).unwrap();
    insert_rows(&holder_conn, 0, 10, 100);

    let mut config = Config::new(&url, subject);
    config.takeover = true;
    let deleter = register(config);
    deleter.delete_database("db").expect("delete with takeover");
    let recreated = open(&deleter, "db", &OTHER_KEY).unwrap();
    recreated.execute_batch(CREATE).unwrap();
    insert_rows(&recreated, 0, 3, 100);

    // The holder of the deleted database must not commit, also not into the database created under the same name.
    let err = holder_conn
        .execute("INSERT INTO t (id, payload) VALUES (1000, x'00')", [])
        .unwrap_err();
    assert_eq!(err.sqlite_error_code(), Some(ErrorCode::SystemIoFailure), "{err}");
    assert_eq!(count(&recreated), 3);
}

#[test]
fn delete_without_takeover_fails_while_lease_is_held() {
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();
    let holder = register(Config::new(&url, subject.clone()));
    let _holder_conn = open(&holder, "db", &KEY).unwrap();

    let other = register(Config::new(&url, subject));
    let err = other
        .delete_database("db")
        .expect_err("an active lease must block the deletion");
    assert!(err.to_string().contains("LEASE_HELD"), "{err}");
}

#[test]
fn deleting_an_open_database_is_refused() {
    let Some(url) = server_url() else { return };
    let vfs = register(Config::new(&url, TestSigner::fresh()));
    let _conn = open(&vfs, "db", &KEY).unwrap();
    let err = vfs
        .delete_database("db")
        .expect_err("an open database must not be deleted");
    assert!(err.to_string().contains("close it"), "{err}");
}

#[test]
fn delete_removes_local_copy_of_that_database_only() {
    let Some(url) = server_url() else { return };
    let subject = TestSigner::fresh();
    let path = copy_path("delete");

    let vfs = register(with_copy(&url, &subject, &path));
    fill(&vfs, 20);
    drop(vfs);
    assert!(path.exists(), "local copy must have been written");

    let vfs = register(with_copy(&url, &subject, &path));
    vfs.delete_database("other").expect("delete another database");
    assert!(path.exists(), "the local copy of another database must stay");
    vfs.delete_database("db").expect("delete database");
    assert!(!path.exists(), "the local copy of the deleted database must be removed");
}

#[test]
fn deleting_a_missing_database_succeeds() {
    let Some(url) = server_url() else { return };
    let vfs = register(Config::new(&url, TestSigner::fresh()));
    vfs.delete_database("never-created").expect("first delete");
    vfs.delete_database("never-created").expect("second delete");
}
