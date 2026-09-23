//! Deterministic workload modelled on a message store. Transaction k depends only on k, so [`verify`] can compute
//! exactly what the database must contain after transactions 1 to p: none missing, none partially applied, none extra.

use std::collections::BTreeMap;

use rusqlite::{Connection, OpenFlags, OptionalExtension};
use sqlite_remote_vfs::RemoteVfs;

pub const KEY: [u8; 32] = [0x5a; 32];
const CONVERSATIONS: u64 = 5;

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY, txid INTEGER NOT NULL, conv INTEGER NOT NULL, body TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS messages_by_conv ON messages (conv, id);
    CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5 (body);
    CREATE TABLE IF NOT EXISTS counters (conv INTEGER PRIMARY KEY, n INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS receipts (conv INTEGER PRIMARY KEY, last_read INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS progress (txid INTEGER PRIMARY KEY);
";

/// Number of messages transaction k inserts.
fn rows(k: u64) -> u64 {
    1 + k % 7
}

fn conversation(k: u64) -> u64 {
    k % CONVERSATIONS
}

/// Whether transaction k also updates the read receipt of its conversation. True for every third transaction.
fn marks_read(k: u64) -> bool {
    k.is_multiple_of(3)
}

fn body(k: u64, i: u64) -> String {
    let words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"];
    let mut body = format!("message {k}/{i}:");
    for n in 0..(10 + (k * 31 + i * 17) % 40) {
        body.push(' ');
        body.push_str(words[((k + i + n) % words.len() as u64) as usize]);
    }
    body
}

fn raw_key(key: &[u8; 32]) -> String {
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    format!("x'{hex}'")
}

/// Opens the database through SQLite3 Multiple Ciphers on top of the VFS, with the journal in memory.
pub fn open(vfs: &RemoteVfs, db: &str) -> rusqlite::Result<Connection> {
    open_with_page_size(vfs, db, None)
}

/// Like [`open`], with an optional page size. The page size only applies to a new database. It must equal the page
/// size in the VFS configuration, because the server creates the database with that page size and rejects blocks of
/// any other size.
pub fn open_with_page_size(vfs: &RemoteVfs, db: &str, page_size: Option<u32>) -> rusqlite::Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags_and_vfs(db, flags, vfs.encrypted_name().as_str())?;
    conn.pragma_update(None, "key", raw_key(&KEY))?;
    if let Some(size) = page_size {
        conn.pragma_update(None, "page_size", size)?;
    }
    let _: String = conn.query_row("PRAGMA journal_mode = MEMORY", [], |row| row.get(0))?;
    Ok(conn)
}

/// Creates the tables in one transaction, so a crash leaves either all of them or none.
pub fn create_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(&format!("BEGIN; {SCHEMA} COMMIT;"))
}

/// Returns the number of the last committed transaction, or 0 if there is none.
pub fn last_txid(conn: &Connection) -> rusqlite::Result<u64> {
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'progress'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if exists.is_none() {
        return Ok(0);
    }
    let last: Option<i64> = conn.query_row("SELECT max(txid) FROM progress", [], |row| row.get(0))?;
    Ok(last.unwrap_or(0) as u64)
}

/// Runs transaction k as one SQLite transaction.
pub fn transaction(conn: &Connection, k: u64) -> rusqlite::Result<()> {
    let conv = conversation(k) as i64;
    let tx = conn.unchecked_transaction()?;
    for i in 0..rows(k) {
        let body = body(k, i);
        tx.execute(
            "INSERT INTO messages (txid, conv, body) VALUES (?1, ?2, ?3)",
            (k as i64, conv, &body),
        )?;
        tx.execute(
            "INSERT INTO messages_fts (rowid, body) VALUES (last_insert_rowid(), ?1)",
            [&body],
        )?;
    }
    tx.execute(
        "INSERT INTO counters (conv, n) VALUES (?1, ?2) ON CONFLICT (conv) DO UPDATE SET n = n + excluded.n",
        (conv, rows(k) as i64),
    )?;
    if marks_read(k) {
        tx.execute(
            "INSERT INTO receipts (conv, last_read) VALUES (?1, ?2)
             ON CONFLICT (conv) DO UPDATE SET last_read = excluded.last_read",
            (conv, k as i64),
        )?;
    }
    tx.execute("INSERT INTO progress (txid) VALUES (?1)", [k as i64])?;
    tx.commit()
}

/// Checks that the database holds exactly transactions 1 to p for some p, and returns p.
pub fn verify(conn: &Connection) -> Result<u64, String> {
    let q = |err: rusqlite::Error| err.to_string();
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(q)?;
    if integrity != "ok" {
        return Err(format!("integrity_check: {integrity}"));
    }
    let p = last_txid(conn).map_err(q)?;
    if p == 0 {
        return Ok(0);
    }

    let (count, max): (i64, i64) = conn
        .query_row("SELECT count(*), max(txid) FROM progress", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .map_err(q)?;
    if count as u64 != p || max as u64 != p {
        return Err(format!("progress holds {count} transactions up to {max}"));
    }

    let mut per_txid = BTreeMap::new();
    let mut stmt = conn
        .prepare("SELECT txid, count(*) FROM messages GROUP BY txid")
        .map_err(q)?;
    for row in stmt
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64))
        })
        .map_err(q)?
    {
        let (txid, n) = row.map_err(q)?;
        per_txid.insert(txid, n);
    }
    for k in 1..=p {
        if per_txid.remove(&k) != Some(rows(k)) {
            return Err(format!("transaction {k} is not complete"));
        }
    }
    if let Some((txid, _)) = per_txid.into_iter().next() {
        return Err(format!(
            "found messages of transaction {txid}, but the last transaction is {p}"
        ));
    }

    for conv in 0..CONVERSATIONS {
        let expected: u64 = (1..=p).filter(|&k| conversation(k) == conv).map(rows).sum();
        let counter: Option<i64> = conn
            .query_row("SELECT n FROM counters WHERE conv = ?1", [conv as i64], |row| {
                row.get(0)
            })
            .optional()
            .map_err(q)?;
        if counter.unwrap_or(0) as u64 != expected {
            return Err(format!(
                "counter of conversation {conv} is {counter:?}, expected {expected}"
            ));
        }
        let receipt: Option<i64> = conn
            .query_row("SELECT last_read FROM receipts WHERE conv = ?1", [conv as i64], |row| {
                row.get(0)
            })
            .optional()
            .map_err(q)?;
        let expected_receipt = (1..=p).filter(|&k| conversation(k) == conv && marks_read(k)).max();
        if receipt.map(|r| r as u64) != expected_receipt {
            return Err(format!(
                "receipt of conversation {conv} is {receipt:?}, expected {expected_receipt:?}"
            ));
        }
    }

    let (messages, indexed): (i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM messages), (SELECT count(*) FROM messages_fts)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(q)?;
    if messages != indexed {
        return Err(format!("{messages} messages, {indexed} in the full-text index"));
    }
    let hits: i64 = conn
        .query_row(
            "SELECT count(*) FROM messages_fts WHERE messages_fts MATCH 'foxtrot'",
            [],
            |row| row.get(0),
        )
        .map_err(q)?;
    if hits == 0 {
        return Err("full-text search returned no rows".into());
    }
    Ok(p)
}
