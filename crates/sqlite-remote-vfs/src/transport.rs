//! Transport to the page server: a connection that sends and receives whole frames.
//!
//! Every request blocks until its response arrives, because SQLite calls the VFS synchronously. Natively this is a
//! blocking socket. In a browser a WebSocket cannot be used blocking, so the connection worker holds the WebSocket and
//! the SQLite worker waits for its responses on shared memory.

use crate::client::ClientConfig;

/// Thread-safety bound for a transport.
///
/// Natively `Send`, because the client is behind a mutex that the ping thread also locks. No bound in a browser: there
/// are no threads, and the transport holds JavaScript values, which are not `Send`.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) trait AcrossThreads: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send> AcrossThreads for T {}

#[cfg(target_arch = "wasm32")]
pub(crate) trait AcrossThreads {}
#[cfg(target_arch = "wasm32")]
impl<T> AcrossThreads for T {}

/// Connection to the page server that carries whole frames.
pub(crate) trait Transport: AcrossThreads {
    /// Sends one frame.
    fn send(&mut self, frame: Vec<u8>) -> Result<(), String>;

    /// Waits for the next frame. A connection closed by the server is returned as an error. The caller then
    /// reconnects and resumes.
    fn receive(&mut self) -> Result<Vec<u8>, String>;

    /// Replaces a broken connection with a new one. In a browser the connection worker is kept and opens the new
    /// connection itself: a new worker cannot be started during a call from SQLite, because that needs a running
    /// event loop.
    fn reopen(&mut self) -> Result<(), String>;
}

/// Opens a connection. The protocol login (`Hello`, `Proof`) is done by the client.
pub(crate) fn dial(config: &ClientConfig) -> Result<Box<dyn Transport>, String> {
    imp::dial(config)
}

#[cfg(target_arch = "wasm32")]
pub(crate) use imp::start;

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    use std::io::{self, Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::sync::{Arc, OnceLock};

    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConnection, RootCertStore, StreamOwned};
    use tungstenite::client::IntoClientRequest;
    use tungstenite::{Message, WebSocket};

    use super::Transport;
    use crate::client::ClientConfig;

    /// WebSocket over a blocking socket. Reads and writes time out after the configured timeout.
    struct Socket {
        socket: WebSocket<Stream>,
        config: ClientConfig,
    }

    /// Byte stream under the WebSocket: plain TCP for `ws://`, TLS over TCP for `wss://`.
    enum Stream {
        Plain(TcpStream),
        Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
    }

    impl Read for Stream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self {
                Stream::Plain(stream) => stream.read(buf),
                Stream::Tls(stream) => stream.read(buf),
            }
        }
    }

    impl Write for Stream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            match self {
                Stream::Plain(stream) => stream.write(buf),
                Stream::Tls(stream) => stream.write(buf),
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            match self {
                Stream::Plain(stream) => stream.flush(),
                Stream::Tls(stream) => stream.flush(),
            }
        }
    }

    impl Transport for Socket {
        fn send(&mut self, frame: Vec<u8>) -> Result<(), String> {
            self.socket
                .send(Message::Binary(frame.into()))
                .map_err(|err| err.to_string())
        }

        fn receive(&mut self) -> Result<Vec<u8>, String> {
            loop {
                match self.socket.read().map_err(|err| err.to_string())? {
                    Message::Binary(data) => return Ok(data.into()),
                    Message::Close(close) => return Err(format!("closed by the server: {close:?}")),
                    // tungstenite responds to pings itself. Other message types are ignored.
                    _ => {}
                }
            }
        }

        fn reopen(&mut self) -> Result<(), String> {
            self.socket = open(&self.config)?;
            Ok(())
        }
    }

    pub(super) fn dial(config: &ClientConfig) -> Result<Box<dyn Transport>, String> {
        Ok(Box::new(Socket {
            socket: open(config)?,
            config: config.clone(),
        }))
    }

    fn open(config: &ClientConfig) -> Result<WebSocket<Stream>, String> {
        let request = config
            .url
            .as_str()
            .into_client_request()
            .map_err(|err| err.to_string())?;
        let uri = request.uri();
        let secure = match uri.scheme_str() {
            Some("wss") => true,
            Some("ws") => false,
            _ => return Err(format!("{}: the URL must start with wss:// or ws://", config.url)),
        };
        let host = uri
            .host()
            .ok_or_else(|| format!("{}: no host", config.url))?
            .to_string();
        let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });

        let stream = connect(&host, port, config)?;
        stream.set_nodelay(true).map_err(|err| err.to_string())?;
        stream
            .set_read_timeout(Some(config.timeout))
            .map_err(|err| err.to_string())?;
        stream
            .set_write_timeout(Some(config.timeout))
            .map_err(|err| err.to_string())?;
        let stream = if secure {
            // The certificate must be valid for the host name in the URL. The TLS handshake runs when the WebSocket
            // handshake writes its first bytes.
            let name = ServerName::try_from(host.clone()).map_err(|err| format!("{host}: {err}"))?;
            let connection = ClientConnection::new(tls(&config.extra_roots)?, name).map_err(|err| err.to_string())?;
            Stream::Tls(Box::new(StreamOwned::new(connection, stream)))
        } else {
            Stream::Plain(stream)
        };
        let (socket, _response) = tungstenite::client(request, stream).map_err(|err| err.to_string())?;
        Ok(socket)
    }

    /// Tries every address the host name resolves to, in order. A host name often resolves to an IPv6 and an IPv4
    /// address, and the server may listen on only one of them.
    fn connect(host: &str, port: u16, config: &ClientConfig) -> Result<TcpStream, String> {
        let mut last = None;
        for address in (host, port).to_socket_addrs().map_err(|err| format!("{host}: {err}"))? {
            match TcpStream::connect_timeout(&address, config.timeout) {
                Ok(stream) => return Ok(stream),
                Err(err) => last = Some(format!("{address}: {err}")),
            }
        }
        Err(last.unwrap_or_else(|| format!("{host}: no address")))
    }

    /// Builds the TLS configuration. Trusted CAs are those of the operating system plus those in `extra_roots`.
    ///
    /// The operating system's store is used instead of a built-in list because organisations with an internal CA or
    /// with TLS inspection install their CA there. With a built-in list the client would reject every server in such
    /// a network.
    fn tls(extra_roots: &[Vec<u8>]) -> Result<Arc<rustls::ClientConfig>, String> {
        let mut roots = RootCertStore::empty();
        for certificate in system_roots() {
            // System stores contain certificates the verifier cannot use. Those are skipped.
            let _ = roots.add(certificate.clone());
        }
        for der in extra_roots {
            roots
                .add(CertificateDer::from(der.clone()))
                .map_err(|err| format!("invalid certificate in extra_roots: {err}"))?;
        }
        if roots.is_empty() {
            return Err("no trusted CA certificates: the system store and extra_roots are both empty".into());
        }
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|err| err.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Arc::new(config))
    }

    /// CA certificates of the operating system, loaded once. Loading can be slow on some systems, and the client may
    /// reconnect several times.
    fn system_roots() -> &'static [CertificateDer<'static>] {
        static ROOTS: OnceLock<Vec<CertificateDer<'static>>> = OnceLock::new();
        ROOTS.get_or_init(|| rustls_native_certs::load_native_certs().certs)
    }
}

#[cfg(target_arch = "wasm32")]
mod imp {
    //! SQLite worker side of the bridge. It works like the OPFS VFS of SQLite's own WebAssembly build: a
    //! `SharedArrayBuffer` with one region per direction, signalled with `Atomics`. Requests are not sent with
    //! `postMessage`, because Chrome does not deliver a message posted by a worker that then blocks.
    //!
    //! The connection worker can only be started while the event loop runs, so `start` starts it once, before SQLite
    //! blocks. After that, sending, receiving and reconnecting all go through the shared buffer.

    use std::cell::Cell;
    use std::rc::Rc;

    use js_sys::{Array, Atomics, Int32Array, JsString, Object, Reflect, SharedArrayBuffer, Uint8Array};
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::{JsCast, JsValue};
    use web_sys::{Blob, BlobPropertyBag, MessageEvent, Url, Worker};

    use super::Transport;
    use crate::client::ClientConfig;
    use crate::local::{Head, LocalStore};
    use crate::platform::Moment;

    const WORKER: &str = include_str!("connection-worker.js");

    const CONTROL_SLOTS: u32 = 8;
    const STATE: u32 = 0;
    const ANSWER: u32 = 1;
    const KIND: u32 = 2;
    const LENGTH: u32 = 3;
    const REQUEST: u32 = 4;
    const OP: u32 = 5;
    const REQUEST_LENGTH: u32 = 6;

    const STATE_OPEN: i32 = 1;
    const KIND_FRAME: i32 = 1;
    const KIND_DONE: i32 = 3;
    const KIND_NOTHING: i32 = 4;

    const OP_SEND: i32 = 1;
    const OP_RECEIVE: i32 = 2;
    const OP_REOPEN: i32 = 3;
    const OP_CLOSE: i32 = 4;
    const OP_COPY_HEAD: i32 = 5;
    const OP_COPY_READ: i32 = 6;
    const OP_COPY_WRITE: i32 = 7;
    const OP_COPY_CLEAR: i32 = 8;
    const OP_COPY_FORGET: i32 = 9;

    /// Size of the region for each direction. It must hold the largest frame the server allows.
    const CAPACITY: u32 = 2 << 20;

    /// The connection worker and the memory shared with it. The connection and the local copy both use it, one call
    /// at a time.
    struct Shared {
        worker: Worker,
        control: Int32Array,
        /// Written only by the SQLite worker, read only by the connection worker.
        request: Uint8Array,
        /// Written only by the connection worker, read only by the SQLite worker.
        answer: Uint8Array,
        timeout: std::time::Duration,
        /// Last value of the `ANSWER` counter that this side has consumed.
        seen: Cell<i32>,
    }

    /// Transport over the bridge.
    struct Bridge(Rc<Shared>);

    /// Local copy in IndexedDB, kept by the connection worker.
    struct Copy(Rc<Shared>);

    impl Transport for Bridge {
        fn send(&mut self, frame: Vec<u8>) -> Result<(), String> {
            let length = u32::try_from(frame.len()).map_err(|_| "frame too large".to_string())?;
            if length > CAPACITY {
                return Err(format!("frame of {length} bytes exceeds the bridge buffer"));
            }
            self.0.request.subarray(0, length).copy_from(&frame);
            match self.0.ask(OP_SEND, length)? {
                (KIND_DONE, _) => Ok(()),
                _ => Err(self.0.answer_text()),
            }
        }

        fn receive(&mut self) -> Result<Vec<u8>, String> {
            let (kind, length) = self.0.ask(OP_RECEIVE, 0)?;
            if kind != KIND_FRAME {
                return Err(self.0.answer_text());
            }
            Ok(self.0.answer_bytes(length))
        }

        fn reopen(&mut self) -> Result<(), String> {
            self.0.ask(OP_REOPEN, 0)?;
            self.0.wait_until_open()
        }
    }

    impl LocalStore for Copy {
        fn head(&mut self) -> Result<Option<Head>, String> {
            let (kind, length) = self.0.ask(OP_COPY_HEAD, 0)?;
            match kind {
                KIND_NOTHING => Ok(None),
                KIND_FRAME => Ok(head_from(&self.0.answer_bytes(length))),
                _ => Err(self.0.answer_text()),
            }
        }

        fn read(&mut self, first: u64, count: u64) -> Result<Vec<Vec<u8>>, String> {
            let mut bytes = Vec::with_capacity(16);
            bytes.extend_from_slice(&first.to_le_bytes());
            bytes.extend_from_slice(&count.to_le_bytes());
            self.0.request.subarray(0, bytes.len() as u32).copy_from(&bytes);
            let (kind, length) = self.0.ask(OP_COPY_READ, bytes.len() as u32)?;
            match kind {
                KIND_NOTHING => Ok(Vec::new()),
                KIND_FRAME => {
                    // The response may contain fewer blocks than requested, so it starts with the block size instead
                    // of relying on the requested count.
                    let all = self.0.answer_bytes(length);
                    let Some(header) = all.get(0..4) else {
                        return Ok(Vec::new());
                    };
                    let size = u32::from_le_bytes(header.try_into().expect("four bytes")) as usize;
                    let body = &all[4..];
                    if size == 0 || !body.len().is_multiple_of(size) {
                        return Ok(Vec::new());
                    }
                    Ok(body.chunks(size).map(<[u8]>::to_vec).collect())
                }
                _ => Err(self.0.answer_text()),
            }
        }

        fn write(&mut self, head: &Head, blocks: &[(u64, &[u8])]) -> Result<(), String> {
            let head_bytes = head_bytes(head);
            // Data that does not fit the buffer is sent in pieces. The worker collects them and writes them in one
            // IndexedDB transaction.
            let mut at = 0;
            loop {
                let mut chunk = Vec::with_capacity(CAPACITY as usize / 2);
                chunk.extend_from_slice(&0u32.to_le_bytes()); // last-piece flag, set below
                chunk.extend_from_slice(&(head_bytes.len() as u32).to_le_bytes());
                chunk.extend_from_slice(&head_bytes);
                let count_at = chunk.len();
                chunk.extend_from_slice(&0u32.to_le_bytes());
                let mut count = 0u32;
                while at < blocks.len() {
                    let (index, data) = blocks[at];
                    if chunk.len() + 12 + data.len() > CAPACITY as usize && count > 0 {
                        break;
                    }
                    chunk.extend_from_slice(&index.to_le_bytes());
                    chunk.extend_from_slice(&(data.len() as u32).to_le_bytes());
                    chunk.extend_from_slice(data);
                    count += 1;
                    at += 1;
                }
                let last = at >= blocks.len();
                chunk[0..4].copy_from_slice(&u32::from(last).to_le_bytes());
                chunk[count_at..count_at + 4].copy_from_slice(&count.to_le_bytes());

                let length = u32::try_from(chunk.len()).map_err(|_| "piece too large".to_string())?;
                if length > CAPACITY {
                    return Err(format!("piece of {length} bytes exceeds the bridge buffer"));
                }
                self.0.request.subarray(0, length).copy_from(&chunk);
                match self.0.ask(OP_COPY_WRITE, length)? {
                    (KIND_DONE, _) => {}
                    _ => return Err(self.0.answer_text()),
                }
                if last {
                    return Ok(());
                }
            }
        }

        fn forget(&mut self, head: &Head, blocks: &[u64]) -> Result<(), String> {
            let head_bytes = head_bytes(head);
            let mut request = Vec::with_capacity(8 + head_bytes.len() + blocks.len() * 8);
            request.extend_from_slice(&(head_bytes.len() as u32).to_le_bytes());
            request.extend_from_slice(&head_bytes);
            request.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
            for index in blocks {
                request.extend_from_slice(&index.to_le_bytes());
            }
            let length = u32::try_from(request.len()).map_err(|_| "too many blocks".to_string())?;
            if length > CAPACITY {
                // Catching up is not worthwhile for that many blocks. The caller discards the copy instead.
                return Err(format!("list of {} blocks exceeds the bridge buffer", blocks.len()));
            }
            self.0.request.subarray(0, length).copy_from(&request);
            match self.0.ask(OP_COPY_FORGET, length)? {
                (KIND_DONE, _) => Ok(()),
                _ => Err(self.0.answer_text()),
            }
        }

        fn clear(&mut self) -> Result<(), String> {
            match self.0.ask(OP_COPY_CLEAR, 0)? {
                (KIND_DONE, _) => Ok(()),
                _ => Err(self.0.answer_text()),
            }
        }
    }

    /// Encodes the head in the layout the worker reads, little-endian: page size, page count, version, the lengths of
    /// subject and database id, then both strings.
    fn head_bytes(head: &Head) -> Vec<u8> {
        let subject = head.subject.as_bytes();
        let db_id = head.db_id.as_bytes();
        let mut bytes = Vec::with_capacity(24 + subject.len() + db_id.len());
        bytes.extend_from_slice(&head.page_size.to_le_bytes());
        bytes.extend_from_slice(&head.page_count.to_le_bytes());
        bytes.extend_from_slice(&head.version.to_le_bytes());
        bytes.extend_from_slice(&(subject.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(db_id.len() as u16).to_le_bytes());
        bytes.extend_from_slice(subject);
        bytes.extend_from_slice(db_id);
        bytes
    }

    fn head_from(bytes: &[u8]) -> Option<Head> {
        if bytes.len() < 24 {
            return None;
        }
        let page_size = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
        let page_count = u64::from_le_bytes(bytes[4..12].try_into().ok()?);
        let version = u64::from_le_bytes(bytes[12..20].try_into().ok()?);
        let subject_len = u16::from_le_bytes(bytes[20..22].try_into().ok()?) as usize;
        let db_id_len = u16::from_le_bytes(bytes[22..24].try_into().ok()?) as usize;
        let subject = String::from_utf8(bytes.get(24..24 + subject_len)?.to_vec()).ok()?;
        let db_id = String::from_utf8(bytes.get(24 + subject_len..24 + subject_len + db_id_len)?.to_vec()).ok()?;
        Some(Head {
            subject,
            db_id,
            page_size,
            page_count,
            version,
        })
    }

    impl Shared {
        /// Writes a request into the control slots, wakes the connection worker and blocks until it answers or the
        /// timeout expires.
        fn ask(&self, op: i32, request_length: u32) -> Result<(i32, u32), String> {
            store(&self.control, OP, op)?;
            store(&self.control, REQUEST_LENGTH, request_length as i32)?;
            store(&self.control, REQUEST, 1)?;
            Atomics::notify(&self.control, REQUEST).map_err(describe)?;

            let deadline = Moment::now().plus(self.timeout);
            loop {
                let current = load(&self.control, ANSWER)?;
                if current != self.seen.get() {
                    self.seen.set(current);
                    return Ok((load(&self.control, KIND)?, load(&self.control, LENGTH)?.max(0) as u32));
                }
                let left = deadline.since(Moment::now());
                if left.is_zero() {
                    return Err("the connection worker did not respond in time".into());
                }
                // `Atomics.wait` can return without a change (spurious wakeup), so the loop checks the counter again.
                // SQLite's OPFS VFS does the same.
                let _ = Atomics::wait_with_timeout(&self.control, ANSWER, current, left.as_secs_f64() * 1000.0);
            }
        }

        /// Waits until the connection worker reports the connection as open, or reports why it failed.
        fn wait_until_open(&self) -> Result<(), String> {
            let deadline = Moment::now().plus(self.timeout);
            loop {
                match load(&self.control, STATE)? {
                    0 => {}
                    STATE_OPEN => return Ok(()),
                    _ => return Err(self.answer_text()),
                }
                let left = deadline.since(Moment::now());
                if left.is_zero() {
                    return Err("the connection was not established in time".into());
                }
                let _ = Atomics::wait_with_timeout(&self.control, STATE, 0, left.as_secs_f64() * 1000.0);
            }
        }

        /// Copies `length` bytes from the answer region.
        fn answer_bytes(&self, length: u32) -> Vec<u8> {
            let mut bytes = vec![0u8; length as usize];
            self.answer.subarray(0, length).copy_to(&mut bytes);
            bytes
        }

        /// Reads the answer region as text. The connection worker reports failures this way.
        fn answer_text(&self) -> String {
            let length = load(&self.control, LENGTH).unwrap_or(0).max(0) as u32;
            String::from_utf8_lossy(&self.answer_bytes(length)).into_owned()
        }
    }

    impl Drop for Shared {
        /// Closes the connection and terminates the connection worker. Runs when the last of the two handles
        /// (`Bridge`, `Copy`) is dropped.
        fn drop(&mut self) {
            let _ = self.ask(OP_CLOSE, 0);
            self.worker.terminate();
        }
    }

    /// Starts the connection worker and waits until it is ready and the connection is open. Must be awaited before
    /// SQLite blocks, because the worker can only start while the event loop runs.
    pub(crate) async fn start(config: &ClientConfig) -> Result<(Box<dyn Transport>, Box<dyn LocalStore>), String> {
        let buffer = SharedArrayBuffer::new(CONTROL_SLOTS * 4 + 2 * CAPACITY);
        let control = Int32Array::new_with_byte_offset_and_length(&buffer, 0, CONTROL_SLOTS);
        let request = Uint8Array::new_with_byte_offset_and_length(&buffer, CONTROL_SLOTS * 4, CAPACITY);
        let answer = Uint8Array::new_with_byte_offset_and_length(&buffer, CONTROL_SLOTS * 4 + CAPACITY, CAPACITY);
        let worker = start_worker()?;

        let ready = js_sys::Promise::new(&mut |resolve, _reject| {
            let handler = Closure::once_into_js(move |_event: MessageEvent| {
                let _ = resolve.call0(&JsValue::NULL);
            });
            worker.set_onmessage(Some(handler.unchecked_ref()));
        });
        let hand_over = message(&[
            ("op", "start".into()),
            ("url", config.url.as_str().into()),
            (
                "copyName",
                format!("sqlite-remote-vfs-copy-{}", crate::subject(&*config.signer))
                    .as_str()
                    .into(),
            ),
            ("buffer", buffer.into()),
            ("controlSlots", CONTROL_SLOTS.into()),
            ("capacity", CAPACITY.into()),
        ])?;
        worker.post_message(&hand_over).map_err(describe)?;
        wasm_bindgen_futures::JsFuture::from(ready).await.map_err(describe)?;
        worker.set_onmessage(None);

        let shared = Rc::new(Shared {
            worker,
            control,
            request,
            answer,
            timeout: config.timeout,
            seen: Cell::new(0),
        });
        shared.wait_until_open()?;
        Ok((Box::new(Bridge(Rc::clone(&shared))), Box::new(Copy(shared))))
    }

    /// Always fails. In a browser the connection worker must be started with `start` before SQLite blocks.
    pub(super) fn dial(_config: &ClientConfig) -> Result<Box<dyn Transport>, String> {
        Err("in a browser, register with RemoteVfs::register_async: the connection worker must be started first".into())
    }

    /// Starts the connection worker from the script embedded in this crate, so the application does not have to
    /// serve a separate file.
    fn start_worker() -> Result<Worker, String> {
        let parts = Array::new();
        parts.push(&JsString::from(WORKER).into());
        let options = BlobPropertyBag::new();
        options.set_type("text/javascript");
        let blob = Blob::new_with_str_sequence_and_options(&parts, &options).map_err(describe)?;
        let url = Url::create_object_url_with_blob(&blob).map_err(describe)?;
        let worker = Worker::new(&url).map_err(describe);
        // The object URL is no longer needed once the worker is created.
        let _ = Url::revoke_object_url(&url);
        worker
    }

    fn message(pairs: &[(&str, JsValue)]) -> Result<Object, String> {
        let message = Object::new();
        for (key, value) in pairs {
            Reflect::set(&message, &(*key).into(), value).map_err(describe)?;
        }
        Ok(message)
    }

    fn load(control: &Int32Array, slot: u32) -> Result<i32, String> {
        Atomics::load(control, slot).map_err(describe)
    }

    fn store(control: &Int32Array, slot: u32, value: i32) -> Result<(), String> {
        Atomics::store(control, slot, value).map(|_| ()).map_err(describe)
    }

    fn describe(error: JsValue) -> String {
        error
            .as_string()
            .or_else(|| js_sys::JSON::stringify(&error).ok().map(String::from))
            .unwrap_or_else(|| format!("{error:?}"))
    }
}
