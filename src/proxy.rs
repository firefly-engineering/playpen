//! The broker's proxy ([spec §6.2]): **the proxy is the supervisor's, and the two confinements are
//! independent** ([ADR 0013]).
//!
//! It exists **iff at least one credential route resolves**. It binds `127.0.0.1:0` *before the
//! fork*, so the port the child is pointed at is a port that already exists, and serves in the
//! supervisor's own process — never a sibling to be orphaned, never a port on a wider interface.
//!
//! One thread per connection, blocking. Nothing here holds ten thousand sockets, so an async
//! runtime would buy complexity and no throughput.
//!
//! **Every client is pointed at it**, because `HTTPS_PROXY` is global and `NO_PROXY` can only
//! exclude hosts: there is no standard way to route only credentialed hosts through a proxy. So a
//! host with no route gets an **opaque `CONNECT`, with no check** — playpen confines no network
//! traffic ([spec §6.1]), and a tunnel it cannot read is a tunnel it does not look at.
//!
//! **A dead proxy tears the run down.** Every client points at it, so a proxy that stopped serving
//! would leave the agent making requests that fail in ways it cannot interpret; a loud end beats
//! credentials lapsing silently. A panic in any proxy thread is caught here and routed into
//! teardown the same way ([spec §4.2]).
//!
//! [spec §6.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#62-the-broker
//! [spec §6.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#61-what-is-not-confined
//! [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
//! [ADR 0013]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0013-the-proxy-is-the-supervisors-and-the-two-confinements-are-independent.md

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::code::Code;
use crate::refusal::Refusal;

/// The one interface the proxy ever binds. Loopback is open because nothing is closed
/// ([spec §6.1]), and a proxy on a wider interface would be a credential oracle for the host's
/// whole network.
///
/// [spec §6.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#61-what-is-not-confined
const INTERFACE: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// How long a connection waits on a peer that has said nothing. A client that opens a socket and
/// never speaks must not hold a thread for the run's whole life.
const IDLE: std::time::Duration = std::time::Duration::from_secs(120);

/// The most of a request head the proxy will read before giving up on it: a `CONNECT` line and its
/// headers, with room to spare. A peer that sends more than this is not speaking HTTP.
const MAX_HEAD: usize = 64 * 1024;

/// The provenance of everything the broker authors in the child's environment.
pub const FROM: &str = "broker";

/// What hosts are never proxied: the agent's own loopback, so a language server, a dev server or
/// an MCP server it started for itself is reached directly. Both spellings of the name are written
/// because clients disagree about which they read ([spec §9.2]).
///
/// It cannot do the thing one would want of it — route only credentialed hosts through the proxy —
/// because `NO_PROXY` can only *exclude*, and that is why `HTTPS_PROXY` is global.
///
/// [spec §9.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#92-set-entries
pub const NO_PROXY: &str = "localhost,127.0.0.1,::1";

/// What the broker contributes to the child's environment ([spec §9.2]). There is no such value
/// where no credential route resolved, and then none of these names exists at all.
///
/// [spec §9.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#92-set-entries
pub struct Set {
    /// Where the proxy is listening, which `HTTPS_PROXY` is rendered from.
    pub addr: SocketAddr,
}

impl Set {
    /// The proxy entries, by name and value: rendered from the bound address, never formatted from
    /// a string the policy supplied.
    pub fn entries(&self) -> Vec<(&'static str, String)> {
        vec![
            ("HTTPS_PROXY", format!("http://{}", self.addr)),
            ("NO_PROXY", NO_PROXY.to_owned()),
            ("no_proxy", NO_PROXY.to_owned()),
            // Bun and Node honour a proxy from the environment only when asked to
            // ([ADR 0012]), and both flagship agents are Bun.
            //
            // [ADR 0012]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0012-the-environment-is-constructed-and-exactly-one-author-writes-each-name.md
            ("NODE_USE_ENV_PROXY", "1".to_owned()),
        ]
    }
}

/// A listener bound before the fork, not yet serving ([spec §4.2] step 11).
///
/// Bound first and served later because the child's environment must name the port, and the
/// environment is constructed before the fork: a proxy that bound after it would be pointed at
/// from a variable written before it existed.
///
/// [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
pub struct Bound {
    listener: TcpListener,
    addr: SocketAddr,
}

/// Bind the proxy's listener on loopback, at a port the kernel picks ([spec §6.2]). A failure is
/// `refusal.proxy.bind`: a route resolved, so there is a credential to serve and nothing to serve
/// it from.
///
/// [spec §6.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#62-the-broker
pub fn bind() -> Result<Bound, Refusal> {
    let bind_failed = |what: &str, e: std::io::Error| {
        Refusal::new(
            Code::ProxyBind,
            format!("the broker cannot {what} on {INTERFACE}: {e}"),
        )
    };
    let listener = TcpListener::bind((INTERFACE, 0)).map_err(|e| bind_failed("bind", e))?;
    let addr = listener
        .local_addr()
        .map_err(|e| bind_failed("read back the address it bound", e))?;
    Ok(Bound { listener, addr })
}

impl Bound {
    /// Where the child is pointed, which the proxy set entries are rendered from.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Serve until [`Serving`] is dropped, which is teardown.
    ///
    /// `child` is the confined child, killed if the proxy ever stops before teardown does: that is
    /// what "a dead proxy tears the run down" means in one process, where the proxy cannot exit on
    /// its own without taking the run with it.
    pub fn serve(self, child: libc::pid_t) -> Serving {
        let stopping = Arc::new(AtomicBool::new(false));
        let accepting = Arc::clone(&stopping);
        // A second descriptor on the same socket, kept here so teardown can shut the socket down
        // from another thread and wake the accept loop out of `accept`.
        //
        // A *copy*, not the loop's own descriptor number: a number is only a name, and the moment
        // the loop returns and drops its descriptor the kernel is free to hand that number to the
        // next socket anyone opens. Shutting one down by number after the fact would reach into
        // whatever had since taken it.
        let (listener, served) = match self.listener.try_clone() {
            Ok(held) => {
                let served = std::thread::Builder::new()
                    .name("playpen-broker".into())
                    .spawn(move || accept_loop(self.listener, &accepting, child))
                    .ok();
                (Some(held), served)
            }
            // Nothing is serving, which is a dead proxy, which tears the run down.
            Err(_) => {
                tear_down(child);
                (None, None)
            }
        };
        Serving {
            stopping,
            listener,
            served,
        }
    }
}

/// The proxy, for as long as the run lasts.
pub struct Serving {
    stopping: Arc<AtomicBool>,
    /// A descriptor on the listening socket, held for this value's whole life so that stopping
    /// names a socket that still exists.
    listener: Option<TcpListener>,
    /// `None` where the thread could not be spawned, which has already torn the run down.
    served: Option<std::thread::JoinHandle<()>>,
}

impl Serving {
    /// Stop serving, in teardown's own order: after the revokers, which need the proxy up, and
    /// before the scratch goes ([spec §4.2] step 18).
    ///
    /// [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
    pub fn stop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        // Wakes the accept loop, which then sees the flag and returns. No teardown failure changes
        // the exit status, so a shutdown that fails is dropped.
        if let Some(listener) = &self.listener {
            // SAFETY: the descriptor belongs to a `TcpListener` this value owns, so it is open for
            // the duration of the call.
            unsafe { libc::shutdown(listener.as_raw_fd(), libc::SHUT_RDWR) };
        }
        if let Some(served) = self.served.take() {
            let _ = served.join();
        }
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Accept until told to stop. Anything that ends this loop early tears the run down, because every
/// client is pointed here and a silent end is the one failure the agent cannot interpret.
fn accept_loop(listener: TcpListener, stopping: &AtomicBool, child: libc::pid_t) {
    loop {
        match listener.accept() {
            Ok((client, _)) => {
                if stopping.load(Ordering::SeqCst) {
                    return;
                }
                // One thread per connection, detached: a connection that outlives its usefulness
                // is bounded by `IDLE` rather than by anything this loop does.
                let _ = std::thread::Builder::new()
                    .name("playpen-broker-connection".into())
                    .spawn(move || {
                        // A panic in a connection is a panic in the proxy, which tears the run
                        // down ([spec §4.2]): it means the credential path is broken, and the
                        // agent must not run on against a broker that half works.
                        let served = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            serve_connection(client);
                        }));
                        if served.is_err() {
                            tear_down(child);
                        }
                    });
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            // Shut down by teardown, or broken. Either way, stop; only the second tears down.
            Err(_) => {
                if !stopping.load(Ordering::SeqCst) {
                    tear_down(child);
                }
                return;
            }
        }
        if stopping.load(Ordering::SeqCst) {
            return;
        }
    }
}

/// End the run, loudly. `SIGTERM` first, so the agent can exit as it would for any caller; the
/// supervisor reaps it and exits with its status, and the caller sees a death rather than a run
/// that quietly stopped authenticating.
fn tear_down(child: libc::pid_t) {
    // SAFETY: kill has no memory preconditions. A pid that has already been reaped simply fails.
    unsafe { libc::kill(child, libc::SIGTERM) };
}

/// Serve one client connection ([spec §6.2]).
fn serve_connection(mut client: TcpStream) {
    let _ = client.set_read_timeout(Some(IDLE));
    let _ = client.set_write_timeout(Some(IDLE));
    let Some(head) = read_head(&mut client) else {
        return;
    };
    match connect_target(&head) {
        // Every host gets an opaque tunnel: playpen confines no network traffic, and a host with
        // no credential route has nothing for the broker to do.
        Some(target) => tunnel(client, &target),
        // Only `HTTPS_PROXY` points here, so everything that arrives is a `CONNECT`. Anything else
        // is answered rather than dropped, and carries no `broker.*` code: the one denial the
        // broker makes is an endpoint rule's, and this is not one.
        None => {
            let _ = client.write_all(
                b"HTTP/1.1 501 Not Implemented\r\n\
                  Content-Type: text/plain\r\n\
                  Connection: close\r\n\
                  Content-Length: 78\r\n\
                  \r\n\
                  playpen's broker proxies CONNECT only; this request was not a CONNECT.\r\n",
            );
        }
    }
}

/// Read a request head — everything up to the blank line — or `None` if the peer sent no head
/// worth parsing. Bounded by [`MAX_HEAD`] and by [`IDLE`].
fn read_head(client: &mut TcpStream) -> Option<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while head.len() < MAX_HEAD {
        match client.read(&mut byte) {
            Ok(0) => return None,
            Ok(_) => head.push(byte[0]),
            Err(_) => return None,
        }
        if head.ends_with(b"\r\n\r\n") {
            return Some(head);
        }
    }
    None
}

/// The `host:port` a `CONNECT` request names, or `None` where `head` is not a `CONNECT`.
///
/// Parsed by `httparse`, never by a pattern over the bytes: a request line is a grammar, and a
/// pattern that matched most of one would differ from it exactly where an attacker looked.
fn connect_target(head: &[u8]) -> Option<String> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    // A head that does not parse names nothing, and a partial one cannot happen: `read_head`
    // returns only on the blank line that ends it.
    request.parse(head).ok()?;
    if !request.method.is_some_and(|method| method == "CONNECT") {
        return None;
    }
    // In a `CONNECT`, the target *is* the authority: `CONNECT host:port HTTP/1.1`.
    let authority = request.path?;
    // A target with no port is not one a tunnel can be opened to, and a `CONNECT` is required to
    // carry one.
    authority.rsplit_once(':').map(|_| authority.to_owned())
}

/// Open a tunnel to `target` and copy bytes both ways until either end closes ([spec §6.2]):
/// opaque, with no check, and nothing of it read.
fn tunnel(mut client: TcpStream, target: &str) {
    let upstream = TcpStream::connect(target);
    let Ok(upstream) = upstream else {
        // A destination playpen could not reach is an upstream failure, which is `502` and carries
        // no code ([spec §6.4]).
        let _ = client.write_all(
            b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        );
        return;
    };
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }
    // No timeouts on a tunnel: a long-lived stream — an SSE subscription, a held connection — is
    // exactly what an agent's client does, and `IDLE` is about a peer that never spoke.
    let _ = client.set_read_timeout(None);
    let _ = client.set_write_timeout(None);
    splice(client, upstream);
}

/// Copy between two streams in both directions until either closes.
fn splice(client: TcpStream, upstream: TcpStream) {
    let Ok(client_back) = client.try_clone() else {
        return;
    };
    let Ok(upstream_back) = upstream.try_clone() else {
        return;
    };
    let outbound = std::thread::Builder::new()
        .name("playpen-broker-tunnel".into())
        .spawn(move || {
            let mut from = client;
            let mut to = upstream;
            let _ = std::io::copy(&mut from, &mut to);
            // Half-close, so the far end learns the near end is done rather than waiting on a
            // stream that will never speak again.
            let _ = to.shutdown(std::net::Shutdown::Write);
        });
    let mut from = upstream_back;
    let mut to = client_back;
    let _ = std::io::copy(&mut from, &mut to);
    let _ = to.shutdown(std::net::Shutdown::Write);
    if let Ok(outbound) = outbound {
        let _ = outbound.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_binds_loopback_at_a_port_the_kernel_picks() {
        let bound = bind().expect("bound");
        assert_eq!(bound.addr().ip(), INTERFACE);
        assert_ne!(bound.addr().port(), 0, "the kernel picked no port");
        // Two proxies never collide: each gets its own.
        let other = bind().expect("bound");
        assert_ne!(bound.addr(), other.addr());
    }

    /// A `CONNECT` names its authority, and nothing else here is one.
    #[test]
    fn a_connect_names_its_authority() {
        assert_eq!(
            connect_target(b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com\r\n\r\n"),
            Some("api.github.com:443".to_owned())
        );
        for other in [
            &b"GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n"[..],
            // No port: not a tunnel target.
            &b"CONNECT api.github.com HTTP/1.1\r\n\r\n"[..],
            &b"not a request at all\r\n\r\n"[..],
            &b"\r\n\r\n"[..],
        ] {
            assert_eq!(
                connect_target(other),
                None,
                "{:?}",
                String::from_utf8_lossy(other)
            );
        }
    }

    /// A head ends at the blank line, and a peer that never sends one gets nowhere.
    #[test]
    fn a_head_ends_at_the_blank_line() {
        let bound = bind().expect("bound");
        let addr = bound.addr();
        let serving = std::thread::spawn(move || {
            let (mut client, _) = bound.listener.accept().expect("accepted");
            read_head(&mut client)
        });
        let mut client = TcpStream::connect(addr).expect("connected");
        client
            .write_all(b"CONNECT h:1 HTTP/1.1\r\nHost: h\r\n\r\nand the body")
            .expect("wrote");
        let head = serving.join().expect("served").expect("a head");
        assert_eq!(head, b"CONNECT h:1 HTTP/1.1\r\nHost: h\r\n\r\n");
    }

    /// Every host gets an opaque tunnel, and nothing of it is read: what goes in one end comes out
    /// the other, byte for byte.
    #[test]
    fn a_tunnel_is_opaque_in_both_directions() {
        // An upstream that echoes what it is sent, with a greeting first.
        let upstream = TcpListener::bind((INTERFACE, 0)).expect("upstream");
        let upstream_addr = upstream.local_addr().expect("addr");
        std::thread::spawn(move || {
            let (mut peer, _) = upstream.accept().expect("accepted");
            peer.write_all(b"hello from upstream\n").expect("greeted");
            let mut echoed = Vec::new();
            let _ = peer.read_to_end(&mut echoed);
            let _ = peer.write_all(&echoed);
            let _ = peer.shutdown(std::net::Shutdown::Write);
        });
        let bound = bind().expect("bound");
        let addr = bound.addr();
        // Served with no child to kill: the pid 0 group is never signalled here, because the
        // tunnel closes in good order.
        let mut serving = bound.serve(0);

        let mut client = TcpStream::connect(addr).expect("connected");
        client
            .write_all(format!("CONNECT {upstream_addr} HTTP/1.1\r\n\r\n").as_bytes())
            .expect("wrote the CONNECT");
        // The tunnel is established, then the bytes are the peers' own.
        let mut answer = [0u8; 39];
        client.read_exact(&mut answer).expect("read the answer");
        assert_eq!(&answer[..], b"HTTP/1.1 200 Connection Established\r\n\r\n");
        client.write_all(b"opaque bytes").expect("wrote");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("half-closed");
        let mut seen = Vec::new();
        client.read_to_end(&mut seen).expect("read");
        assert_eq!(seen, b"hello from upstream\nopaque bytes");
        serving.stop();
    }

    /// Only `HTTPS_PROXY` points at the broker, so anything that is not a `CONNECT` is answered
    /// rather than dropped — and never with a `broker.*` code, which is the endpoint rule's alone.
    #[test]
    fn a_request_that_is_not_a_connect_is_answered() {
        let bound = bind().expect("bound");
        let addr = bound.addr();
        let mut serving = bound.serve(0);
        let mut client = TcpStream::connect(addr).expect("connected");
        client
            .write_all(b"GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
            .expect("wrote");
        let mut answer = String::new();
        client.read_to_string(&mut answer).expect("read");
        assert!(answer.starts_with("HTTP/1.1 501 "), "{answer}");
        assert!(!answer.contains("broker."), "{answer}");
        serving.stop();
    }

    /// A destination the proxy cannot reach is an upstream failure: `502`, and no code
    /// ([spec §6.4]).
    ///
    /// [spec §6.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#64-broker-denial
    #[test]
    fn an_unreachable_destination_is_a_bare_502() {
        // A port nothing listens on: bound and dropped, so the kernel has not reassigned it yet.
        let closed = TcpListener::bind((INTERFACE, 0)).expect("a port");
        let closed_addr = closed.local_addr().expect("addr");
        drop(closed);
        let bound = bind().expect("bound");
        let addr = bound.addr();
        let mut serving = bound.serve(0);
        let mut client = TcpStream::connect(addr).expect("connected");
        client
            .write_all(format!("CONNECT {closed_addr} HTTP/1.1\r\n\r\n").as_bytes())
            .expect("wrote");
        let mut answer = String::new();
        client.read_to_string(&mut answer).expect("read");
        assert!(answer.starts_with("HTTP/1.1 502 "), "{answer}");
        assert!(!answer.contains("broker."), "{answer}");
        serving.stop();
    }

    /// A sleeping child of this process, to be torn down.
    fn sleeper() -> std::process::Child {
        let sleep = crate::floor::binary("sleep").unwrap_or_else(|searched| {
            panic!("the floor holds no `sleep`; looked at {searched:?}")
        });
        std::process::Command::new(sleep)
            .arg("30")
            .spawn()
            .expect("a child to tear down")
    }

    /// A dead proxy tears the run down: every client points at it, and a loud end beats
    /// credentials lapsing silently ([spec §6.2]).
    ///
    /// [spec §6.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#62-the-broker
    #[test]
    fn a_proxy_that_stops_serving_tears_the_run_down() {
        let mut child = sleeper();
        let pid = child.id() as libc::pid_t;
        // A listener broken under the accept loop, with nobody having asked it to stop: exactly
        // what "the proxy stopped serving" looks like from inside the loop.
        let listener = TcpListener::bind((INTERFACE, 0)).expect("bound");
        let fd = listener.as_raw_fd();
        let broken = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            // SAFETY: `fd` is the listener's, which outlives this call — the accept loop below
            // owns it until it returns, and this thread is joined before that.
            unsafe { libc::shutdown(fd, libc::SHUT_RDWR) };
        });
        accept_loop(listener, &AtomicBool::new(false), pid);
        broken.join().expect("the breaker");
        let status = child.wait().expect("reaped");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGTERM),
            "the run was not torn down: {status:?}"
        );
    }

    /// Teardown stopping the proxy is not the proxy dying, so it kills nothing.
    #[test]
    fn stopping_at_teardown_tears_nothing_down() {
        let mut child = sleeper();
        let pid = child.id() as libc::pid_t;
        let bound = bind().expect("bound");
        let mut serving = bound.serve(pid);
        serving.stop();
        // Still running: it was teardown that stopped the proxy, not the proxy that stopped.
        assert_eq!(
            child.try_wait().expect("try_wait").map(|s| s.success()),
            None,
            "stopping the proxy killed the child"
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    /// Stopping is what teardown does, and it is idempotent: the accept loop is woken out of
    /// `accept`, sees the flag, and ends.
    #[test]
    fn stopping_ends_the_accept_loop() {
        let bound = bind().expect("bound");
        let addr = bound.addr();
        let mut serving = bound.serve(0);
        serving.stop();
        serving.stop();
        drop(serving);
        // Nothing is served once it has stopped.
        if let Ok(mut client) = TcpStream::connect(addr) {
            let mut answer = String::new();
            let _ = client.write_all(b"CONNECT h:1 HTTP/1.1\r\n\r\n");
            let _ = client.read_to_string(&mut answer);
            assert!(answer.is_empty(), "{answer}");
        }
    }
}
