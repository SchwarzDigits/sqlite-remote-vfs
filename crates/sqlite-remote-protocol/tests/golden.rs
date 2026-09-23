//! Encodes one sample of every frame and compares the bytes with the golden files in `proto/testdata/v1/`. The
//! server's test suite decodes the same files and checks that it gets the same messages. This keeps both
//! implementations on the same wire format.
//!
//! After an intended protocol change, run `SQLITE_REMOTE_UPDATE_GOLDEN=1 cargo test -p sqlite-remote-protocol` to
//! rewrite the files.

use std::collections::BTreeSet;
use std::path::PathBuf;

use prost::Message;
use sqlite_remote_protocol::v1::{
    Block, Challenge, Changed, Changes, ClientFrame, CloseDb, Commit, CommitAck, Delete, Error, ErrorCode, Fetch,
    Hello, HelloOk, LeaseRevoked, Ok, Open, Opened, Pages, Ping, Pong, Proof, Range, Resume, ServerFrame, SigAlg,
    client_frame, server_frame,
};

const DB_ID: &str = "keystore";
const INSTANCE_ID: [u8; 16] = [0x01; 16];
const LEASE_ID: [u8; 16] = [0xaa; 16];
const PREVIOUS_COMMIT_ID: [u8; 16] = [0xbb; 16];
const PUBLIC_KEY: [u8; 32] = [0x7e; 32];
const NONCE: [u8; 32] = [0x5c; 32];
const SIGNATURE: [u8; 64] = [0x3f; 64];
const COMMIT_ID: [u8; 16] = [0xcc; 16];
const TIME_MS: u64 = 1_758_550_000_000;

enum Frame {
    Client(ClientFrame),
    Server(ServerFrame),
}

impl Frame {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::Client(frame) => frame.encode_to_vec(),
            Self::Server(frame) => frame.encode_to_vec(),
        }
    }

    fn assert_decodes_to_itself(&self, name: &str, bytes: &[u8]) {
        match self {
            Self::Client(frame) => assert_eq!(&ClientFrame::decode(bytes).unwrap(), frame, "{name}"),
            Self::Server(frame) => assert_eq!(&ServerFrame::decode(bytes).unwrap(), frame, "{name}"),
        }
    }
}

fn client(request_id: u64, body: client_frame::Body) -> Frame {
    Frame::Client(ClientFrame {
        request_id,
        body: Some(body),
    })
}

fn server(request_id: u64, body: server_frame::Body) -> Frame {
    Frame::Server(ServerFrame {
        request_id,
        body: Some(body),
    })
}

/// Sample frames with their file names. The server's golden test builds the same messages.
fn samples() -> Vec<(&'static str, Frame)> {
    use client_frame::Body as C;
    use server_frame::Body as S;

    vec![
        (
            "client_hello",
            client(
                1,
                C::Hello(Hello {
                    protocol_version: 1,
                    instance_id: INSTANCE_ID.to_vec(),
                    sig_alg: SigAlg::Ed25519 as i32,
                    public_key: PUBLIC_KEY.to_vec(),
                }),
            ),
        ),
        (
            "server_challenge",
            server(
                1,
                S::Challenge(Challenge {
                    nonce: NONCE.to_vec(),
                    server_id: "wss://vfs.example/v1/ws".into(),
                    expires_at_ms: 1_758_550_030_000,
                }),
            ),
        ),
        (
            "client_proof",
            client(
                2,
                C::Proof(Proof {
                    signature: SIGNATURE.to_vec(),
                }),
            ),
        ),
        (
            "server_hello_ok",
            server(
                1,
                S::HelloOk(HelloOk {
                    protocol_version: 1,
                    max_frame_bytes: 1_048_576,
                    ping_interval_ms: 10_000,
                    lease_ttl_ms: 30_000,
                }),
            ),
        ),
        (
            "client_open",
            client(
                2,
                C::Open(Open {
                    db_id: DB_ID.into(),
                    page_size: 4096,
                    create_if_missing: true,
                    takeover: false,
                    resume: None,
                }),
            ),
        ),
        (
            "client_open_resume",
            client(
                2,
                C::Open(Open {
                    db_id: DB_ID.into(),
                    page_size: 4096,
                    create_if_missing: false,
                    takeover: true,
                    resume: Some(Resume {
                        lease_id: LEASE_ID.to_vec(),
                        lease_epoch: 3,
                        known_version: 41,
                        pending_commit_id: COMMIT_ID.to_vec(),
                    }),
                }),
            ),
        ),
        (
            "server_opened",
            server(
                2,
                S::Opened(Opened {
                    lease_id: LEASE_ID.to_vec(),
                    lease_epoch: 3,
                    version: 41,
                    page_size: 4096,
                    page_count: 12,
                    last_commit_id: PREVIOUS_COMMIT_ID.to_vec(),
                }),
            ),
        ),
        (
            "client_fetch",
            client(
                3,
                C::Fetch(Fetch {
                    db_id: DB_ID.into(),
                    version: 41,
                    first_block: 0,
                    count: 12,
                    ranges: Vec::new(),
                }),
            ),
        ),
        (
            "server_pages",
            server(
                3,
                S::Pages(Pages {
                    first_block: 10,
                    blocks: vec![vec![0x10; 8], vec![0x11; 8]],
                    last: true,
                }),
            ),
        ),
        (
            "client_fetch_ranges",
            client(
                3,
                C::Fetch(Fetch {
                    db_id: DB_ID.into(),
                    version: 41,
                    first_block: 0,
                    count: 0,
                    ranges: vec![
                        Range {
                            first_block: 0,
                            count: 2,
                        },
                        Range {
                            first_block: 9,
                            count: 1,
                        },
                    ],
                }),
            ),
        ),
        (
            "client_changed",
            client(
                3,
                C::Changed(Changed {
                    db_id: DB_ID.into(),
                    from_version: 38,
                }),
            ),
        ),
        (
            "server_changes",
            server(
                3,
                S::Changes(Changes {
                    from_version: 38,
                    to_version: 41,
                    blocks: vec![0, 3, 4, 9],
                    complete: true,
                }),
            ),
        ),
        (
            "client_commit",
            client(
                4,
                C::Commit(Commit {
                    db_id: DB_ID.into(),
                    commit_id: COMMIT_ID.to_vec(),
                    lease_epoch: 3,
                    base_version: 41,
                    page_count: 13,
                    blocks: vec![
                        Block {
                            index: 0,
                            data: vec![0x20; 8],
                        },
                        Block {
                            index: 12,
                            data: vec![0x21; 8],
                        },
                    ],
                    more: true,
                    part: 1,
                }),
            ),
        ),
        (
            "server_commit_ack",
            server(
                4,
                S::CommitAck(CommitAck {
                    commit_id: COMMIT_ID.to_vec(),
                    version: 42,
                }),
            ),
        ),
        (
            "client_ping",
            client(
                5,
                C::Ping(Ping {
                    client_time_ms: TIME_MS,
                }),
            ),
        ),
        (
            "server_pong",
            server(
                5,
                S::Pong(Pong {
                    client_time_ms: TIME_MS,
                }),
            ),
        ),
        (
            "client_close_db",
            client(
                6,
                C::CloseDb(CloseDb {
                    db_id: DB_ID.into(),
                    lease_epoch: 3,
                }),
            ),
        ),
        ("server_ok", server(6, S::Ok(Ok {}))),
        (
            "client_delete",
            client(
                7,
                C::Delete(Delete {
                    db_id: DB_ID.into(),
                    takeover: true,
                }),
            ),
        ),
        (
            "server_lease_revoked",
            server(
                0,
                S::LeaseRevoked(LeaseRevoked {
                    db_id: DB_ID.into(),
                    new_lease_epoch: 4,
                }),
            ),
        ),
        (
            "server_error_fenced",
            server(
                7,
                S::Error(Error {
                    code: ErrorCode::Fenced.into(),
                    detail: "lease epoch 3 is stale".into(),
                    current_version: 42,
                    lease_holder_since_ms: 0,
                }),
            ),
        ),
        (
            "server_error_lease_held",
            server(
                2,
                S::Error(Error {
                    code: ErrorCode::LeaseHeld.into(),
                    detail: "another instance holds the lease".into(),
                    current_version: 0,
                    lease_holder_since_ms: TIME_MS,
                }),
            ),
        ),
    ]
}

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proto/testdata/v1")
}

fn update_requested() -> bool {
    std::env::var_os("SQLITE_REMOTE_UPDATE_GOLDEN").is_some_and(|value| value == "1")
}

#[test]
fn frames_match_golden_files() {
    let dir = golden_dir();
    if update_requested() {
        std::fs::create_dir_all(&dir).unwrap();
    }
    for (name, frame) in samples() {
        let bytes = frame.encode();
        frame.assert_decodes_to_itself(name, &bytes);

        let path = dir.join(format!("{name}.binpb"));
        if update_requested() {
            std::fs::write(&path, &bytes).unwrap();
        }
        let golden = std::fs::read(&path).unwrap_or_else(|err| {
            panic!(
                "{}: {err}. Run with SQLITE_REMOTE_UPDATE_GOLDEN=1 to create it.",
                path.display()
            )
        });
        assert_eq!(bytes, golden, "{name}: encoding differs from the golden file");
    }
}

#[test]
fn golden_directory_has_no_stale_files() {
    if update_requested() {
        // The other test rewrites the directory concurrently. Stale files have to be deleted by hand.
        return;
    }
    let expected: BTreeSet<String> = samples().into_iter().map(|(name, _)| format!("{name}.binpb")).collect();
    let actual: BTreeSet<String> = std::fs::read_dir(golden_dir())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(actual, expected, "files without a sample have to be deleted");
}
