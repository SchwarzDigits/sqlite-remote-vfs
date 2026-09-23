//! Client for the page server protocol: one WebSocket connection, one request at a time, blocking I/O.
//!
//! Blocking I/O matches how SQLite calls the VFS: synchronously, and a commit must be stored on the server before the
//! call returns.

use std::collections::HashSet;
use std::fmt;
use std::time::Duration;

use prost::Message as _;
use sqlite_remote_protocol::v1::{self as pb, client_frame, server_frame};

use crate::platform::Moment;
use crate::transport::{Transport, dial};

pub(crate) const PROTOCOL_VERSION: u32 = 1;

// `url` and `timeout` are only used for dialling. In a browser the connection worker dials, and the client reaches it
// through the bridge.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
#[derive(Clone, Debug)]
pub(crate) struct ClientConfig {
    pub url: String,
    pub signer: std::sync::Arc<dyn crate::Signer>,
    pub instance_id: [u8; 16],
    pub timeout: Duration,
    pub trace_fetches: bool,
    #[cfg(not(target_arch = "wasm32"))]
    pub extra_roots: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub(crate) enum ClientError {
    /// The connection failed or broke. The request may or may not have reached the server.
    Transport(String),
    /// The server rejected the request.
    Server(pb::Error),
    /// The server sent a response that does not match the request.
    Protocol(String),
}

impl ClientError {
    pub fn is_fenced(&self) -> bool {
        matches!(self, Self::Server(e) if e.code() == pb::ErrorCode::Fenced)
    }

    pub fn is_lease_held(&self) -> bool {
        matches!(self, Self::Server(e) if e.code() == pb::ErrorCode::LeaseHeld)
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(reason) => write!(f, "connection: {reason}"),
            Self::Server(e) => write!(f, "server: {}: {}", e.code().as_str_name(), e.detail),
            Self::Protocol(reason) => write!(f, "protocol: {reason}"),
        }
    }
}

fn transport(err: impl fmt::Display) -> ClientError {
    ClientError::Transport(err.to_string())
}

/// Limits the server sent in `HelloOk`.
// `ping_interval` is only used by the native ping thread. In a browser the connection worker sends the pings.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub max_frame_bytes: u32,
    pub ping_interval: Duration,
}

pub(crate) struct Client {
    config: ClientConfig,
    socket: Option<Box<dyn Transport>>,
    /// Whether the connection is usable. After a break the transport is kept, because in a browser it is the
    /// connection worker, which cannot be started again during a call from SQLite.
    connected: bool,
    limits: Limits,
    next_id: u64,
    last_request: Moment,
    /// Databases whose lease the server revoked because another instance took it over.
    revoked: HashSet<String>,
    /// Block ranges of all fetches, if `trace_fetches` is set in the configuration.
    trace: Option<Vec<(u64, u64)>>,
}

impl Client {
    /// Connects to the server and logs in.
    pub fn connect(config: ClientConfig) -> Result<Self, ClientError> {
        let config_trace = config.trace_fetches.then(Vec::new);
        let mut client = Client {
            config,
            socket: None,
            connected: false,
            limits: Limits {
                max_frame_bytes: 0,
                ping_interval: Duration::from_secs(10),
            },
            next_id: 0,
            last_request: Moment::now(),
            revoked: HashSet::new(),
            trace: config_trace,
        };
        client.reconnect()?;
        Ok(client)
    }

    /// Logs in over a transport that was opened elsewhere. In a browser the transport must be created before SQLite
    /// blocks, so the client cannot dial it itself.
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    pub fn with_transport(transport: Box<dyn Transport>, config: ClientConfig) -> Result<Self, ClientError> {
        let trace = config.trace_fetches.then(Vec::new);
        let mut client = Client {
            config,
            socket: Some(transport),
            connected: true,
            limits: Limits {
                max_frame_bytes: 0,
                ping_interval: Duration::from_secs(10),
            },
            next_id: 0,
            last_request: Moment::now(),
            revoked: HashSet::new(),
            trace,
        };
        client.say_hello()?;
        Ok(client)
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    pub fn is_connected(&self) -> bool {
        self.connected && self.socket.is_some()
    }

    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub fn idle_for(&self) -> Duration {
        self.last_request.elapsed()
    }

    pub fn was_revoked(&self, db_id: &str) -> bool {
        self.revoked.contains(db_id)
    }

    /// Block ranges fetched so far. Empty unless `trace_fetches` is set.
    pub fn fetch_trace(&self) -> Vec<(u64, u64)> {
        self.trace.clone().unwrap_or_default()
    }

    /// Marks the connection as broken, as after a network failure. The transport is kept so that it can be reopened.
    pub fn disconnect(&mut self) {
        self.connected = false;
    }

    /// Opens a new connection and logs in. Databases opened on the old connection must be resumed.
    pub fn reconnect(&mut self) -> Result<(), ClientError> {
        match &mut self.socket {
            Some(socket) => socket.reopen().map_err(ClientError::Transport)?,
            None => self.socket = Some(dial(&self.config).map_err(ClientError::Transport)?),
        }
        self.connected = true;
        self.say_hello()
    }

    /// Logs in on a new connection: sends `Hello`, signs the challenge, and stores the limits from `HelloOk`.
    fn say_hello(&mut self) -> Result<(), ClientError> {
        let signer = std::sync::Arc::clone(&self.config.signer);
        let public_key = signer.public_key();
        let hello = client_frame::Body::Hello(pb::Hello {
            protocol_version: PROTOCOL_VERSION,
            instance_id: self.config.instance_id.to_vec(),
            sig_alg: crate::identity::wire_algorithm(signer.algorithm()),
            public_key: public_key.clone(),
        });
        // Refuse a server that does not send a challenge: it would accept any client under any subject.
        let challenge = match self.call(hello)? {
            server_frame::Body::Challenge(challenge) => challenge,
            other => {
                return Err(ClientError::Protocol(format!(
                    "expected Challenge, got {other:?}; refusing a server that does not authenticate clients"
                )));
            }
        };
        // The signer holds the private key. The client only receives the signature.
        let signed = crate::identity::login_transcript(
            &challenge.server_id,
            &challenge.nonce,
            &self.config.instance_id,
            signer.algorithm(),
            &public_key,
        );
        let answer = self.call(client_frame::Body::Proof(pb::Proof {
            signature: signer.sign(&signed),
        }))?;
        match answer {
            server_frame::Body::HelloOk(ok) => {
                self.limits = Limits {
                    max_frame_bytes: ok.max_frame_bytes,
                    ping_interval: Duration::from_millis(ok.ping_interval_ms.into()),
                };
                Ok(())
            }
            other => Err(ClientError::Protocol(format!("expected HelloOk, got {other:?}"))),
        }
    }

    /// Sends one request and returns the response to it.
    pub fn call(&mut self, body: client_frame::Body) -> Result<server_frame::Body, ClientError> {
        let id = self.send(body)?;
        loop {
            let frame = self.receive()?;
            if frame.request_id != id {
                continue;
            }
            return match frame.body {
                Some(server_frame::Body::Error(e)) => Err(ClientError::Server(e)),
                Some(body) => Ok(body),
                None => Err(ClientError::Protocol("empty response".into())),
            };
        }
    }

    /// Deletes a database on the server. Succeeds if it does not exist. It must not be open on this connection.
    pub fn delete(&mut self, db_id: &str, takeover: bool) -> Result<(), ClientError> {
        let answer = self.call(client_frame::Body::Delete(pb::Delete {
            db_id: db_id.into(),
            takeover,
        }))?;
        match answer {
            server_frame::Body::Ok(_) => Ok(()),
            other => Err(ClientError::Protocol(format!("expected Ok, got {other:?}"))),
        }
    }

    /// Returns the blocks changed since `from_version`, from the server's change log. Used to catch up an outdated
    /// local copy.
    pub fn changes(&mut self, db_id: &str, from_version: u64) -> Result<pb::Changes, ClientError> {
        let answer = self.call(client_frame::Body::Changed(pb::Changed {
            db_id: db_id.into(),
            from_version,
        }))?;
        match answer {
            server_frame::Body::Changes(changes) => Ok(changes),
            other => Err(ClientError::Protocol(format!("expected Changes, got {other:?}"))),
        }
    }

    /// Fetches a range of blocks. The server may split the response across several frames.
    pub fn fetch(&mut self, fetch: pb::Fetch) -> Result<Vec<Vec<u8>>, ClientError> {
        let expected = fetch.count;
        if let Some(trace) = &mut self.trace {
            trace.push((fetch.first_block, fetch.count));
        }
        let blocks = self.fetch_frames(fetch, expected)?;
        Ok(blocks.into_iter().map(|(_, data)| data).collect())
    }

    /// Fetches several block ranges in one request and returns each block with its index.
    ///
    /// Used to catch up an outdated local copy. The blocks changed by recent commits are spread across the file, and
    /// one request per range would cost one round trip each.
    pub fn fetch_ranges(
        &mut self,
        db_id: &str,
        version: u64,
        ranges: &[(u64, u64)],
    ) -> Result<Vec<(u64, Vec<u8>)>, ClientError> {
        if let Some(trace) = &mut self.trace {
            trace.extend(ranges.iter().copied());
        }
        let expected: u64 = ranges.iter().map(|(_, count)| count).sum();
        self.fetch_frames(
            pb::Fetch {
                db_id: db_id.into(),
                version,
                first_block: 0,
                count: 0,
                ranges: ranges
                    .iter()
                    .map(|&(first_block, count)| pb::Range { first_block, count })
                    .collect(),
            },
            expected,
        )
    }

    /// Reads the response frames of one fetch and pairs each block with its index. Each frame carries the index of
    /// its first block, and no frame spans two ranges, so every block's index follows from its frame.
    fn fetch_frames(&mut self, fetch: pb::Fetch, expected: u64) -> Result<Vec<(u64, Vec<u8>)>, ClientError> {
        let id = self.send(client_frame::Body::Fetch(fetch))?;
        let mut blocks = Vec::new();
        loop {
            let frame = self.receive()?;
            if frame.request_id != id {
                continue;
            }
            match frame.body {
                Some(server_frame::Body::Pages(pages)) => {
                    for (offset, data) in pages.blocks.into_iter().enumerate() {
                        blocks.push((pages.first_block + offset as u64, data));
                    }
                    if pages.last {
                        if blocks.len() as u64 != expected {
                            return Err(ClientError::Protocol(format!(
                                "requested {expected} blocks, received {}",
                                blocks.len()
                            )));
                        }
                        return Ok(blocks);
                    }
                }
                Some(server_frame::Body::Error(e)) => return Err(ClientError::Server(e)),
                other => return Err(ClientError::Protocol(format!("expected Pages, got {other:?}"))),
            }
        }
    }

    /// Sends all parts of a commit without waiting between them and returns the new version.
    ///
    /// The server responds to every part it rejects, and always to the last part. The first rejection is returned.
    pub fn commit(&mut self, parts: Vec<pb::Commit>) -> Result<u64, ClientError> {
        let mut ids = Vec::with_capacity(parts.len());
        for part in parts {
            ids.push(self.send(client_frame::Body::Commit(part))?);
        }
        let Some(&last) = ids.last() else {
            return Err(ClientError::Protocol("commit without parts".into()));
        };
        let mut refusal = None;
        loop {
            let frame = self.receive()?;
            if !ids.contains(&frame.request_id) {
                continue;
            }
            match frame.body {
                Some(server_frame::Body::Error(e)) => {
                    refusal.get_or_insert(e);
                    if frame.request_id == last {
                        return Err(ClientError::Server(refusal.unwrap_or_default()));
                    }
                }
                Some(server_frame::Body::CommitAck(ack)) if frame.request_id == last => {
                    return match refusal {
                        Some(e) => Err(ClientError::Server(e)),
                        None => Ok(ack.version),
                    };
                }
                other => {
                    return Err(ClientError::Protocol(format!(
                        "unexpected response to a commit: {other:?}"
                    )));
                }
            }
        }
    }

    fn send(&mut self, body: client_frame::Body) -> Result<u64, ClientError> {
        if !self.connected {
            return Err(ClientError::Transport("not connected".into()));
        }
        let socket = self
            .socket
            .as_mut()
            .ok_or_else(|| ClientError::Transport("not connected".into()))?;
        self.next_id += 1;
        let frame = pb::ClientFrame {
            request_id: self.next_id,
            body: Some(body),
        };
        if let Err(err) = socket.send(frame.encode_to_vec()) {
            self.connected = false;
            return Err(transport(err));
        }
        self.last_request = Moment::now();
        Ok(self.next_id)
    }

    /// Returns the next response frame. Frames the server sends unprompted (request id 0, such as `LeaseRevoked`)
    /// are handled here and skipped.
    fn receive(&mut self) -> Result<pb::ServerFrame, ClientError> {
        loop {
            if !self.connected {
                return Err(ClientError::Transport("not connected".into()));
            }
            let socket = self
                .socket
                .as_mut()
                .ok_or_else(|| ClientError::Transport("not connected".into()))?;
            let data = match socket.receive() {
                Ok(data) => data,
                Err(err) => {
                    self.connected = false;
                    return Err(ClientError::Transport(err));
                }
            };
            let frame = pb::ServerFrame::decode(data.as_ref())
                .map_err(|err| ClientError::Protocol(format!("malformed frame: {err}")))?;
            if frame.request_id == 0 {
                if let Some(server_frame::Body::LeaseRevoked(revoked)) = frame.body {
                    self.revoked.insert(revoked.db_id);
                }
                continue;
            }
            return Ok(frame);
        }
    }
}
