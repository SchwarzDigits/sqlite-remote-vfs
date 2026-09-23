//! TCP proxy between the VFS and the server that injects faults and simulates a network link.
//!
//! It cuts each connection after a random number of bytes from the client, often in the middle of a frame. On some
//! connections it delays the server's answers for longer than the client's timeout. It can also add a fixed delay and
//! a bandwidth limit.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use crate::rng::Rng;

/// What the proxy does to each connection.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// Every connection is cut after a number of bytes from the client. With this probability the number is drawn
    /// from `early_cut`, otherwise from `late_cut`. The late range lets large commits get through sometimes.
    pub early_cut_probability: f64,
    pub early_cut: (u64, u64),
    pub late_cut: (u64, u64),
    /// Probability that the proxy delays the server's answers on a connection once, by `stall`, after a number of
    /// bytes from the server drawn from `stall_after`.
    pub stall_probability: f64,
    pub stall_after: (u64, u64),
    pub stall: Duration,
    /// Delay added to every byte, in both directions. A request and its answer take twice this long. The proxy keeps
    /// reading while bytes wait, so the delay does not add up over the chunks of a large message.
    pub delay: Duration,
    /// Bandwidth in bytes per second, in each direction. `None` means no limit. Set it to measure transfer times,
    /// because without a limit a large transfer on the local machine takes almost no time.
    pub rate: Option<u64>,
}

impl Policy {
    /// A policy that only adds `delay`. It cuts and stalls nothing and sets no bandwidth limit.
    pub fn delay_only(delay: Duration) -> Policy {
        Policy {
            early_cut_probability: 0.0,
            early_cut: (u64::MAX, u64::MAX),
            late_cut: (u64::MAX, u64::MAX),
            stall_probability: 0.0,
            stall_after: (1, 1),
            stall: Duration::ZERO,
            delay,
            rate: None,
        }
    }
}

/// Counters of a proxy.
#[derive(Default)]
pub struct ProxyStats {
    /// Accepted connections.
    pub connections: AtomicU64,
    /// Connections the proxy cut.
    pub cuts: AtomicU64,
    /// Connections on which the proxy delayed the server's answers.
    pub stalls: AtomicU64,
}

/// A running proxy. It runs until the process exits.
pub struct Proxy {
    pub address: SocketAddr,
    pub stats: Arc<ProxyStats>,
}

impl Proxy {
    /// Starts a proxy to `target` (`host:port`) on a free local port.
    pub fn start(target: &str, policy: Policy, seed: u64) -> io::Result<Proxy> {
        Proxy::start_on(target, 0, policy, seed)
    }

    /// Starts a proxy to `target` on the given local port. Port 0 picks a free port.
    pub fn start_on(target: &str, port: u16, policy: Policy, seed: u64) -> io::Result<Proxy> {
        let target = target
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::other(format!("{target}: no address")))?;
        let listener = TcpListener::bind(("127.0.0.1", port))?;
        let address = listener.local_addr()?;
        let stats = Arc::new(ProxyStats::default());
        let rng = Arc::new(Mutex::new(Rng::new(seed)));

        let accept_stats = Arc::clone(&stats);
        thread::spawn(move || {
            for client in listener.incoming().flatten() {
                let Ok(server) = TcpStream::connect(target) else {
                    continue;
                };
                // Disable Nagle's algorithm, which would otherwise add its own delay to latency measurements.
                let _ = client.set_nodelay(true);
                let _ = server.set_nodelay(true);
                accept_stats.connections.fetch_add(1, Ordering::Relaxed);
                let (cut_after, stall) = {
                    let mut rng = rng.lock().unwrap();
                    let (low, high) = if rng.chance(policy.early_cut_probability) {
                        policy.early_cut
                    } else {
                        policy.late_cut
                    };
                    let cut_after = rng.between(low, high);
                    let stall = rng
                        .chance(policy.stall_probability)
                        .then(|| rng.between(policy.stall_after.0, policy.stall_after.1));
                    (cut_after, stall)
                };
                connect(
                    client,
                    server,
                    Fate {
                        cut_after,
                        stall_after: stall,
                        stall: policy.stall,
                        delay: policy.delay,
                        rate: policy.rate,
                    },
                    Arc::clone(&accept_stats),
                );
            }
        });
        Ok(Proxy { address, stats })
    }

    /// WebSocket URL of the proxy.
    pub fn url(&self) -> String {
        format!("ws://{}/v1/ws", self.address)
    }
}

/// Faults and link properties of one connection, drawn when it is accepted.
#[derive(Clone, Copy)]
struct Fate {
    cut_after: u64,
    stall_after: Option<u64>,
    stall: Duration,
    delay: Duration,
    rate: Option<u64>,
}

fn connect(client: TcpStream, server: TcpStream, fate: Fate, stats: Arc<ProxyStats>) {
    let Fate {
        cut_after,
        stall_after,
        stall,
        delay,
        rate,
    } = fate;
    let (Ok(client_reader), Ok(server_reader)) = (client.try_clone(), server.try_clone()) else {
        return;
    };
    // Client to server: cut the connection after `cut_after` bytes.
    {
        let (client_side, server_side, stats) = (client.try_clone(), server.try_clone(), Arc::clone(&stats));
        thread::spawn(move || {
            let (Ok(client_side), Ok(server_side)) = (client_side, server_side) else {
                return;
            };
            let Ok(mut line) = Line::new(&server_side, delay, rate) else {
                return;
            };
            let mut reader = client_reader;
            let mut forwarded = 0u64;
            let mut buf = [0u8; 8192];
            loop {
                let n = match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let allowed = (cut_after - forwarded).min(n as u64) as usize;
                if !line.send(&buf[..allowed]) {
                    break;
                }
                forwarded += allowed as u64;
                if forwarded >= cut_after {
                    stats.cuts.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
            let _ = client_side.shutdown(Shutdown::Both);
            let _ = server_side.shutdown(Shutdown::Both);
        });
    }
    // Server to client: on some connections, delay the answers once by `stall`.
    thread::spawn(move || {
        let mut reader = server_reader;
        let Ok(mut line) = Line::new(&client, delay, rate) else {
            return;
        };
        let mut forwarded = 0u64;
        let mut stalled = false;
        let mut buf = [0u8; 8192];
        loop {
            let n = match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if let Some(after) = stall_after
                && !stalled
                && forwarded + n as u64 >= after
            {
                stalled = true;
                stats.stalls.fetch_add(1, Ordering::Relaxed);
                thread::sleep(stall);
            }
            if !line.send(&buf[..n]) {
                break;
            }
            forwarded += n as u64;
        }
        let _ = client.shutdown(Shutdown::Both);
        let _ = server.shutdown(Shutdown::Both);
    });
}

/// Forwards the bytes of one direction. Without delay and bandwidth limit, it writes them directly. Otherwise a
/// separate thread writes each chunk after the delay and at the configured rate, while the caller keeps reading.
struct Line {
    direct: Option<TcpStream>,
    delayed: Option<mpsc::Sender<(Instant, Vec<u8>)>>,
}

impl Line {
    fn new(target: &TcpStream, delay: Duration, rate: Option<u64>) -> io::Result<Line> {
        let mut target = target.try_clone()?;
        if delay.is_zero() && rate.is_none() {
            return Ok(Line {
                direct: Some(target),
                delayed: None,
            });
        }
        let (sender, chunks) = mpsc::channel::<(Instant, Vec<u8>)>();
        thread::spawn(move || {
            // With a bandwidth limit, a chunk starts only after the previous chunk has been transmitted.
            let mut free_at = Instant::now();
            for (arrived, chunk) in chunks {
                let start = arrived.max(free_at);
                wait_until(start + delay);
                if let Some(rate) = rate {
                    let takes = Duration::from_secs_f64(chunk.len() as f64 / rate as f64);
                    free_at = start + takes;
                    wait_until(free_at + delay);
                }
                if target.write_all(&chunk).is_err() {
                    break;
                }
            }
        });
        Ok(Line {
            direct: None,
            delayed: Some(sender),
        })
    }

    /// Forwards the bytes. Returns false if the receiving side is closed.
    fn send(&mut self, bytes: &[u8]) -> bool {
        match (&mut self.direct, &self.delayed) {
            (Some(target), _) => target.write_all(bytes).is_ok(),
            (_, Some(sender)) => sender.send((Instant::now(), bytes.to_vec())).is_ok(),
            _ => false,
        }
    }
}

/// Waits until `deadline`.
///
/// `thread::sleep` overshoots by several milliseconds on macOS, which would add latency to measurements. This function
/// sleeps until 15 ms before the deadline and busy-waits for the rest.
fn wait_until(deadline: Instant) {
    const SPIN: Duration = Duration::from_millis(15);
    let now = Instant::now();
    if deadline > now + SPIN {
        thread::sleep(deadline - now - SPIN);
    }
    while Instant::now() < deadline {
        std::hint::spin_loop();
    }
}
