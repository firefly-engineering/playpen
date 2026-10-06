//! The broker end to end ([spec §6.2]): whether a proxy exists at all, what the child is pointed
//! at, and that what it is pointed at serves.
//!
//! [spec §6.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#62-the-broker

mod common;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Stdio};

use serde_json::json;

use common::{Fixture, os_bin};

/// Every name the broker writes ([spec §9.2]).
///
/// [spec §9.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#92-set-entries
const PROXY_NAMES: [&str; 4] = ["HTTPS_PROXY", "NO_PROXY", "no_proxy", "NODE_USE_ENV_PROXY"];

/// A policy whose profile `p` has `credentials`, minted by a minter that answers at once.
fn with_routes(fx: &Fixture, credentials: serde_json::Value) -> PathBuf {
    fx.policy_named(
        "broker.json",
        &json!({
            "version": 1,
            "minters": {"m": {"command": [
                os_bin("sh"), "-c",
                r#"cat >/dev/null; printf '{"token":"s3cret","expires_at":"2027-01-01T00:00:00Z"}'"#,
            ]}},
            "workspaces": {"w": {"roots": [{"path": fx.root(), "mode": "readwrite"}]}},
            "profiles": {"p": {
                "workspaces": ["w"],
                "toolchain": [],
                "credentials": credentials,
            }},
        }),
    )
}

/// The confined child's environment, as `env` prints it.
fn environ(fx: &Fixture, policy: &std::path::Path) -> BTreeMap<String, String> {
    let output = fx
        .run_under(policy, &[&os_bin("env")])
        .output()
        .expect("playpen");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("utf-8")
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

/// With no credential route there is no proxy, and so no proxy variable: the names do not exist
/// rather than existing empty.
#[test]
fn no_route_means_no_proxy_and_no_proxy_variable() {
    let fx = Fixture::new();
    let policy = with_routes(&fx, json!([]));
    let env = environ(&fx, &policy);
    for name in PROXY_NAMES {
        assert!(!env.contains_key(name), "{name} is set: {env:?}");
    }
}

/// With a route, every client is pointed at the proxy — `HTTPS_PROXY` is global, because
/// `NO_PROXY` can only exclude hosts — and the address is rendered from the one it bound.
#[test]
fn a_route_points_every_client_at_the_proxy() {
    let fx = Fixture::new();
    let policy = with_routes(
        &fx,
        json!([{
            "host": "api.anthropic.com",
            "path_prefix": "/",
            "minter": "m",
            "delivery": {"env": "CLAUDE_CODE_OAUTH_TOKEN"},
        }]),
    );
    let env = environ(&fx, &policy);
    for name in PROXY_NAMES {
        assert!(env.contains_key(name), "{name} is not set: {env:?}");
    }
    assert_eq!(env["NODE_USE_ENV_PROXY"], "1");
    // Loopback, at a port the kernel picked, and the agent's own loopback excluded.
    let proxy = env["HTTPS_PROXY"]
        .strip_prefix("http://127.0.0.1:")
        .unwrap_or_else(|| panic!("HTTPS_PROXY is {}", env["HTTPS_PROXY"]));
    assert!(proxy.parse::<u16>().is_ok_and(|port| port != 0), "{proxy}");
    assert_eq!(env["NO_PROXY"], env["no_proxy"]);
    assert!(env["NO_PROXY"].contains("127.0.0.1"), "{}", env["NO_PROXY"]);
}

/// A live run, its child printing one line and then waiting, so a test can use what that line
/// named while the run is still going.
struct Live {
    child: Child,
    line: String,
}

impl Live {
    /// Launch `argv` under `policy`, with the child's stdout piped, and read its first line.
    fn start(fx: &Fixture, policy: &std::path::Path, script: &str) -> Self {
        let mut child = fx
            .run_under(policy, &[&os_bin("sh"), "-c", script])
            .stdout(Stdio::piped())
            .spawn()
            .expect("playpen");
        let mut line = String::new();
        BufReader::new(child.stdout.as_mut().expect("piped"))
            .read_line(&mut line)
            .expect("the child's first line");
        Self {
            child,
            line: line.trim_end().to_owned(),
        }
    }
}

impl Drop for Live {
    /// Ended by `SIGTERM`, which playpen forwards, not `SIGKILL`, which it cannot: macOS has no
    /// parent-death signal (named asymmetry #6), so a killed playpen leaves its agent running there.
    /// The scripts `exec` their wait for the same reason — the forwarded signal reaches the shell
    /// alone, and a shell that forks its last command would leave that behind.
    fn drop(&mut self) {
        let pid = libc::pid_t::try_from(self.child.id()).expect("a pid fits pid_t");
        // SAFETY: a plain syscall to a child of this process that has not been reaped yet, so the
        // pid is still its.
        unsafe { libc::kill(pid, libc::SIGTERM) };
        let _ = self.child.wait();
    }
}

/// The address the child is pointed at serves, and what it serves a non-routed host is an opaque
/// `CONNECT` with no check: what goes in one end comes out the other.
#[test]
fn a_non_routed_host_gets_an_opaque_tunnel() {
    // An upstream that echoes, standing for any host the policy has no route for.
    let upstream = TcpListener::bind(("127.0.0.1", 0)).expect("upstream");
    let upstream_addr = upstream.local_addr().expect("addr");
    std::thread::spawn(move || {
        let (mut peer, _) = upstream.accept().expect("accepted");
        let mut sent = Vec::new();
        let _ = peer.read_to_end(&mut sent);
        let _ = peer.write_all(&sent);
        let _ = peer.shutdown(std::net::Shutdown::Write);
    });

    let fx = Fixture::new();
    let policy = with_routes(
        &fx,
        json!([{
            "host": "api.anthropic.com",
            "path_prefix": "/",
            "minter": "m",
            "delivery": {"env": "CLAUDE_CODE_OAUTH_TOKEN"},
        }]),
    );
    // The child prints where it was pointed, then waits, so the proxy is up while this runs.
    let live = Live::start(&fx, &policy, r#"echo "$HTTPS_PROXY"; exec sleep 30"#);
    let proxy = live
        .line
        .strip_prefix("http://")
        .unwrap_or_else(|| panic!("HTTPS_PROXY is {:?}", live.line))
        .to_owned();

    let mut client = TcpStream::connect(&proxy).expect("the proxy is listening");
    client
        .write_all(format!("CONNECT {upstream_addr} HTTP/1.1\r\n\r\n").as_bytes())
        .expect("wrote the CONNECT");
    let mut established = [0u8; 39];
    client.read_exact(&mut established).expect("established");
    assert_eq!(
        &established[..],
        b"HTTP/1.1 200 Connection Established\r\n\r\n"
    );
    client.write_all(b"opaque bytes").expect("wrote");
    client
        .shutdown(std::net::Shutdown::Write)
        .expect("half-closed");
    let mut seen = Vec::new();
    client.read_to_end(&mut seen).expect("read");
    assert_eq!(seen, b"opaque bytes", "the tunnel was not opaque");
}

/// The proxy is the supervisor's: it stops when the run ends, so nothing of it is left listening
/// for the next caller to find ([ADR 0013]).
///
/// [ADR 0013]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0013-the-proxy-is-the-supervisors-and-the-two-confinements-are-independent.md
#[test]
fn the_proxy_stops_with_the_run() {
    let fx = Fixture::new();
    let policy = with_routes(
        &fx,
        json!([{
            "host": "api.anthropic.com",
            "path_prefix": "/",
            "minter": "m",
            "delivery": {"env": "CLAUDE_CODE_OAUTH_TOKEN"},
        }]),
    );
    let proxy = {
        let live = Live::start(&fx, &policy, r#"echo "$HTTPS_PROXY"; exec sleep 30"#);
        let proxy = live
            .line
            .strip_prefix("http://")
            .expect("an address")
            .to_owned();
        // Up while the run is.
        TcpStream::connect(&proxy).expect("the proxy is listening");
        proxy
        // The run ends here, with `live`.
    };
    // Nothing serves on it afterwards: either the port is closed, or it accepts and answers
    // nothing, which is what a listener the kernel has not yet reclaimed does.
    if let Ok(mut client) = TcpStream::connect(&proxy) {
        let _ = client.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let _ = client.write_all(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\n\r\n");
        let mut answer = String::new();
        let _ = client.read_to_string(&mut answer);
        assert!(answer.is_empty(), "the proxy outlived its run: {answer}");
    }
}
