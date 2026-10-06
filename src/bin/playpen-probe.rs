//! `playpen-probe`: the shipped actor for boundary assertions. It performs the actions on its
//! command line in order and writes one verdict per action, as one JSON object per line on stdout,
//! so that one confined launch serves every row of a policy fixture ([spec §17.1]). Its exit
//! status carries one bit: the probe ran (0) or the probe broke (non-zero), never "an assertion
//! failed".
//!
//! [spec §17.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#171-form

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

/// The closed set of actions. A new kind of check is a new variant.
enum Action {
    /// Open the path and read it to the end.
    Read(String),
    /// Create or truncate the path and write a byte to it.
    Write(String),
    /// List the directory at the path.
    List(String),
    /// Run the path with no arguments and wait for it: ok only if it was `exec`ed and exited 0.
    Exec(String),
    /// Send signal 0 to the pid: the permission check alone, delivering nothing.
    Signal(libc::pid_t),
    /// Connect to the abstract unix socket of this name (Linux).
    #[cfg(target_os = "linux")]
    ConnectAbstract(String),
    /// Connect to the pathname unix socket at this path: what a **credential oracle** is reached
    /// by ([spec §6.3]).
    ///
    /// [spec §6.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#63-credential-oracles
    ConnectUnix(String),
    /// Resolve the host name through the system resolver, as any client does before it connects.
    Resolve(String),
    /// Read an inherited descriptor to the end, without opening anything.
    ReadFd(libc::c_int),
    /// Look the Mach service up by name in the bootstrap namespace.
    #[cfg(target_os = "macos")]
    LookUp(String),
    /// List the descriptors above stderr held by this process.
    Fds,
    /// Report the identity (device, inode) of descriptors 0, 1 and 2.
    Stdio,
    /// Report this process's id, its group and its terminal's foreground group, then wait for
    /// one of [`waited`] and report it with how many arrived. Two verdicts, one per line.
    WaitSignal,
    /// Issue one HTTPS request to a destination the harness stands up outside the launch, and
    /// report the answer head it came back with.
    Request(Box<Request>),
}

/// One HTTPS request, as JSON on the command line. A request takes more than one operand, and a
/// row's fixture is the only thing that writes these, so the shape is a document rather than a
/// positional list nothing could read back.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    via: Via,
    method: String,
    /// `host:port`: the `CONNECT` target, the name TLS is verified against, and the `Host` header.
    authority: String,
    path: String,
    /// The header the phantom is presented in, so a row can assert the secret arrived **in the
    /// header the phantom came in**.
    header: String,
    /// The environment variable the phantom was delivered in. **Named rather than carried**: no
    /// token belongs on a command line, where the host's process table can read it.
    delivery: String,
}

/// Which leg a request takes. **A probe argument, never a host fact.** `NO_PROXY` holds
/// `localhost`, so a probe that let its client infer the leg would take the bypassing one twice,
/// and a row phrased on that would pass on a build where the proxy injected into everything.
#[derive(serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Via {
    /// Dial what `HTTPS_PROXY` names and open a `CONNECT` to the authority.
    Proxy,
    /// Connect to the authority itself, around the proxy.
    Direct,
}

/// How long a request waits on a peer before the probe gives up on it, so a destination that has
/// stopped answering ends the row rather than the suite.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The signals `wait-signal` waits for: ones whose default action would terminate the probe.
///
/// On Linux the first realtime signal is waited for too. It is the only one whose deliveries are
/// **queued** rather than coalesced, so it is the only one that can count a double delivery
/// exactly — a standard signal delivered twice while still pending arrives once, which would make
/// the doubling of a group-directed signal unobservable rather than absent
/// ([ADR 0026](https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0026-signal-origin-is-readable-on-linux-and-the-kill-target-is-readable-nowhere.md)).
fn waited() -> Vec<libc::c_int> {
    #[allow(unused_mut)] // extended per platform
    let mut signals = vec![
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGTERM,
        libc::SIGUSR1,
        libc::SIGUSR2,
    ];
    #[cfg(target_os = "linux")]
    signals.push(libc::SIGRTMIN());
    signals
}

fn main() -> ExitCode {
    let Some(actions) = parse(std::env::args().skip(1)) else {
        eprintln!(
            "usage: playpen-probe (read <path> | write <path> | list <path> | read-fd <fd> | look-up <service> (macOS) | request <json> | fds | stdio)... | playpen-probe wait-signal"
        );
        return ExitCode::from(2);
    };
    if let [Action::WaitSignal] = actions.as_slice() {
        return wait_signal();
    }
    for action in &actions {
        println!("{}", verdict(action));
    }
    ExitCode::SUCCESS
}

/// One or more actions, each a verb followed by its operand if it takes one. `wait-signal` writes
/// its own verdicts and does not return until signalled, so it stands alone.
fn parse(args: impl IntoIterator<Item = String>) -> Option<Vec<Action>> {
    let mut args = args.into_iter();
    let mut actions = Vec::new();
    while let Some(verb) = args.next() {
        actions.push(match verb.as_str() {
            "read" => Action::Read(args.next()?),
            "write" => Action::Write(args.next()?),
            "list" => Action::List(args.next()?),
            "exec" => Action::Exec(args.next()?),
            "signal" => Action::Signal(args.next()?.parse().ok()?),
            #[cfg(target_os = "linux")]
            "connect-abstract" => Action::ConnectAbstract(args.next()?),
            "connect-unix" => Action::ConnectUnix(args.next()?),
            "resolve" => Action::Resolve(args.next()?),
            "read-fd" => Action::ReadFd(args.next()?.parse().ok()?),
            #[cfg(target_os = "macos")]
            "look-up" => Action::LookUp(args.next()?),
            "fds" => Action::Fds,
            "stdio" => Action::Stdio,
            "wait-signal" => Action::WaitSignal,
            "request" => Action::Request(Box::new(serde_json::from_str(&args.next()?).ok()?)),
            _ => return None,
        });
    }
    match actions.as_slice() {
        [] => None,
        [Action::WaitSignal] => Some(actions),
        _ if actions.iter().any(|a| matches!(a, Action::WaitSignal)) => None,
        _ => Some(actions),
    }
}

fn verdict(action: &Action) -> String {
    match action {
        Action::Read(path) => {
            io_verdict(File::open(path).and_then(|mut f| f.read_to_end(&mut Vec::new())))
        }
        Action::Write(path) => io_verdict(
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)
                .and_then(|mut f| f.write_all(b"x")),
        ),
        Action::List(path) => io_verdict(
            std::fs::read_dir(path).and_then(|entries| entries.collect::<Result<Vec<_>, _>>()),
        ),
        Action::Exec(path) => io_verdict(exec(path)),
        // SAFETY: kill has no memory preconditions, and signal 0 delivers nothing.
        Action::Signal(pid) => io_verdict(match unsafe { libc::kill(*pid, 0) } {
            0 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        }),
        #[cfg(target_os = "linux")]
        Action::ConnectAbstract(name) => io_verdict({
            use std::os::linux::net::SocketAddrExt;
            use std::os::unix::net::{SocketAddr, UnixStream};
            SocketAddr::from_abstract_name(name.as_bytes())
                .and_then(|addr| UnixStream::connect_addr(&addr))
        }),
        Action::ConnectUnix(path) => io_verdict(std::os::unix::net::UnixStream::connect(path)),
        Action::Resolve(host) => io_verdict(std::net::ToSocketAddrs::to_socket_addrs(&(
            host.as_str(),
            443,
        ))),
        Action::ReadFd(fd) => io_verdict(read_fd(*fd)),
        #[cfg(target_os = "macos")]
        Action::LookUp(service) => look_up(service),
        Action::Fds => {
            let fds: Vec<String> = held_fds().iter().map(|fd| fd.to_string()).collect();
            format!(r#"{{"fds":[{}]}}"#, fds.join(","))
        }
        Action::Stdio => {
            let ids: Vec<String> = (0..3)
                .map(|fd| match identity(fd) {
                    Some((dev, ino)) => format!("[{dev},{ino}]"),
                    None => "null".to_string(),
                })
                .collect();
            format!(r#"{{"stdio":[{}]}}"#, ids.join(","))
        }
        Action::WaitSignal => unreachable!("wait-signal writes its own verdicts"),
        Action::Request(request) => issue(request),
    }
}

/// Issue `request` and report the answer head it came back with, as the verdict's `answer`.
///
/// The roots are **the ones this process's environment names**, loaded the way
/// `rustls-native-certs` loads them: `SSL_CERT_FILE` replaces the platform store outright, so this
/// is the client that could verify nothing but a routed host while that variable named the bare
/// session CA ([#140](https://github.com/firefly-engineering/playpen/issues/140)). Its succeeding
/// on both legs is that fix asserted from inside a live launch.
fn issue(request: &Request) -> String {
    match issued(request) {
        Ok(answer) => {
            let answer = serde_json::Value::String(answer);
            format!(r#"{{"ok":true,"answer":{answer}}}"#)
        }
        Err(why) => {
            let detail = serde_json::Value::String(why);
            format!(r#"{{"ok":false,"detail":{detail}}}"#)
        }
    }
}

fn issued(request: &Request) -> Result<String, String> {
    use std::net::TcpStream;
    use std::sync::Arc;

    let host = request
        .authority
        .rsplit_once(':')
        .map_or(request.authority.as_str(), |(host, _)| host)
        .to_owned();
    let token = std::env::var(&request.delivery)
        .map_err(|_| format!("{} names no delivered token", request.delivery))?;

    // Named rather than taken from process-global state, so the probe and the broker cannot
    // disagree about which provider is in play.
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for certificate in native.certs {
        let _ = roots.add(certificate);
    }
    if roots.is_empty() {
        return Err(format!(
            "this process's environment names no trusted roots ({} errors loading them)",
            native.errors.len()
        ));
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("protocol versions: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    // The one protocol the broker speaks, offered so a client that would have chosen HTTP/2 does
    // not.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let socket = match request.via {
        Via::Direct => TcpStream::connect(&request.authority)
            .map_err(|e| format!("connect {}: {e}", request.authority))?,
        Via::Proxy => {
            let proxy = std::env::var("HTTPS_PROXY")
                .map_err(|_| "HTTPS_PROXY names no proxy".to_owned())?;
            let at = proxy.strip_prefix("http://").unwrap_or(&proxy).to_owned();
            let mut socket =
                TcpStream::connect(&at).map_err(|e| format!("connect the proxy {at}: {e}"))?;
            socket
                .set_read_timeout(Some(REQUEST_TIMEOUT))
                .and_then(|()| socket.set_write_timeout(Some(REQUEST_TIMEOUT)))
                .map_err(|e| format!("the proxy's timeouts: {e}"))?;
            socket
                .write_all(format!("CONNECT {} HTTP/1.1\r\n\r\n", request.authority).as_bytes())
                .map_err(|e| format!("the CONNECT: {e}"))?;
            let established = head(&mut socket)?;
            if !established.starts_with("HTTP/1.1 200 ") {
                return Err(format!(
                    "the proxy did not establish a tunnel: {established:?}"
                ));
            }
            socket
        }
    };
    socket
        .set_read_timeout(Some(REQUEST_TIMEOUT))
        .and_then(|()| socket.set_write_timeout(Some(REQUEST_TIMEOUT)))
        .map_err(|e| format!("the request's timeouts: {e}"))?;
    let name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|e| format!("{host} is not a server name: {e}"))?;
    let session = rustls::ClientConnection::new(Arc::new(config), name)
        .map_err(|e| format!("a TLS session: {e}"))?;
    let mut tls = rustls::StreamOwned::new(session, socket);
    tls.write_all(
        format!(
            "{} {} HTTP/1.1\r\nHost: {host}\r\n{}: {token}\r\nAccept: application/json\r\n\r\n",
            request.method, request.path, request.header
        )
        .as_bytes(),
    )
    .map_err(|e| format!("the request: {e}"))?;
    tls.flush().map_err(|e| format!("flush: {e}"))?;
    let mut answer = Vec::new();
    // To the end: every answer here is framed by `Connection: close`, so end of stream is end of
    // response. A read that fails mid-answer is taken for what it delivered, and the row judges
    // that.
    let _ = tls.read_to_end(&mut answer);
    Ok(String::from_utf8_lossy(&answer).into_owned())
}

/// One head — everything up to the blank line — read a byte at a time so nothing of what follows
/// is consumed with it.
fn head(from: &mut impl Read) -> Result<String, String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while head.len() < 64 * 1024 {
        match from.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => head.push(byte[0]),
            Err(e) => return Err(format!("reading a head: {e}")),
        }
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

/// Run `path` with no arguments and wait for it. Forked and `execve`d rather than spawned: the
/// macOS 15 `posix_spawn` reports an image the sandbox denies as `ENOENT` where `execve` reports
/// `EPERM`, and a denial must never read as absence.
fn exec(path: &str) -> std::io::Result<()> {
    let mut command = Command::new(path);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: the closure does nothing; its presence alone makes std fork and `execve`.
    unsafe { command.pre_exec(|| Ok(())) };
    let status = command.status()?;
    match status.success() {
        true => Ok(()),
        // It ran, so whatever failed was not the `exec`: no errno to report.
        false => Err(std::io::Error::other(format!("{path}: {status}"))),
    }
}

/// Read `fd` to the end with `read(2)` itself: wrapping a descriptor that may be closed in a
/// `File` would assert an ownership the probe cannot know it has.
fn read_fd(fd: libc::c_int) -> std::io::Result<()> {
    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: `buf` is valid for writes of its length; `read` fails cleanly with EBADF on a
        // descriptor that is not open.
        match unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) } {
            0 => return Ok(()),
            -1 => {
                let err = std::io::Error::last_os_error();
                if err.kind() != ErrorKind::Interrupted {
                    return Err(err);
                }
            }
            _ => {}
        }
    }
}

/// A bootstrap lookup reports through its `kern_return_t`, never `errno`: a sandbox denial is
/// `BOOTSTRAP_NOT_PRIVILEGED`, which stays distinct from `BOOTSTRAP_UNKNOWN_SERVICE`.
#[cfg(target_os = "macos")]
fn look_up(service: &str) -> String {
    use mach2::bootstrap::{bootstrap_look_up, bootstrap_port};
    use mach2::kern_return::KERN_SUCCESS;
    use mach2::mach_port::mach_port_deallocate;
    use mach2::traps::mach_task_self;

    let Ok(name) = std::ffi::CString::new(service) else {
        return r#"{"ok":false}"#.to_string();
    };
    let mut port = 0;
    // SAFETY: `bootstrap_port` is libSystem's, initialised before `main`; `name` is a C string
    // and `port` a valid out-pointer for the duration of the call.
    let kr = unsafe { bootstrap_look_up(bootstrap_port, name.as_ptr(), &mut port) };
    if kr != KERN_SUCCESS {
        return format!(r#"{{"ok":false,"kr":{kr}}}"#);
    }
    // SAFETY: the lookup gave this task a send right to `port`, which nothing else uses.
    unsafe { mach_port_deallocate(mach_task_self(), port) };
    r#"{"ok":true}"#.to_string()
}

/// The (device, inode) of an open descriptor, which names the object behind it.
fn identity(fd: libc::c_int) -> Option<(u64, u64)> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `stat` is a valid out-pointer; fstat fails cleanly on a closed descriptor.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: fstat succeeded, so it initialised `stat`.
    let stat = unsafe { stat.assume_init() };
    #[allow(clippy::unnecessary_cast)] // the field widths differ by platform
    Some((stat.st_dev as u64, stat.st_ino as u64))
}

/// The first signal `wait-signal` took, or 0 while it waits.
static FIRST: AtomicI32 = AtomicI32::new(0);
/// How many waited signals arrived in all.
static COUNT: AtomicI32 = AtomicI32::new(0);

/// How long `wait-signal` keeps counting after the first signal, to catch a second delivery.
const GRACE: Duration = Duration::from_millis(300);

extern "C" fn record(sig: libc::c_int) {
    let _ = FIRST.compare_exchange(0, sig, Ordering::SeqCst, Ordering::SeqCst);
    COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Waits in `sigsuspend` rather than `sigwait`: on macOS a thread inside `sigwait` is not stopped
/// by `SIGTSTP`, and the probe must stop like any job.
fn wait_signal() -> ExitCode {
    // SAFETY: a zeroed sigset_t is valid storage, initialised by sigemptyset.
    let (mut set, mut unblocked): (libc::sigset_t, libc::sigset_t) =
        unsafe { (std::mem::zeroed(), std::mem::zeroed()) };
    // SAFETY: `set` is valid storage.
    unsafe { libc::sigemptyset(&mut set) };
    // SAFETY: a zeroed sigaction is valid; the handler only touches atomics.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = record as extern "C" fn(libc::c_int) as libc::sighandler_t;
    for sig in waited() {
        // SAFETY: `set` and `action` are initialised; `sig` is a valid signal number.
        if unsafe { libc::sigaddset(&mut set, sig) } != 0
            || unsafe { libc::sigaction(sig, &action, std::ptr::null_mut()) } != 0
        {
            return ExitCode::from(1);
        }
    }
    // Blocking before reporting ready leaves no window in which a waited signal could be missed.
    // SAFETY: both sets are valid for the call.
    if unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut unblocked) } != 0 {
        return ExitCode::from(1);
    }
    // SAFETY: none of these has preconditions; tcgetpgrp is -1 without a terminal.
    let (pid, pgrp, foreground) = unsafe { (libc::getpid(), libc::getpgrp(), libc::tcgetpgrp(0)) };
    println!(r#"{{"pid":{pid},"pgrp":{pgrp},"foreground":{foreground}}}"#);
    while FIRST.load(Ordering::SeqCst) == 0 {
        // SAFETY: `unblocked` is the initialised mask from before blocking.
        unsafe { libc::sigsuspend(&unblocked) };
    }
    // SAFETY: as above; the waited signals stay handled, so further ones are only counted.
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &unblocked, std::ptr::null_mut()) };
    std::thread::sleep(GRACE);
    println!(
        r#"{{"signal":{},"count":{}}}"#,
        FIRST.load(Ordering::SeqCst),
        COUNT.load(Ordering::SeqCst)
    );
    ExitCode::SUCCESS
}

fn io_verdict<T>(result: std::io::Result<T>) -> String {
    match result {
        Ok(_) => r#"{"ok":true}"#.to_string(),
        Err(err) => {
            let errno = err.raw_os_error().unwrap_or(-1);
            let enoent = err.kind() == ErrorKind::NotFound;
            format!(r#"{{"ok":false,"errno":{errno},"enoent":{enoent}}}"#)
        }
    }
}

/// Descriptors above 2, found by asking the kernel about each one rather than by listing a
/// directory, which would itself open a descriptor and need a grant.
fn held_fds() -> Vec<i32> {
    // SAFETY: getdtablesize has no preconditions.
    let limit = unsafe { libc::getdtablesize() };
    // SAFETY: F_GETFD on any integer is harmless; it fails with EBADF when the fd is not open.
    (3..limit)
        .filter(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } != -1)
        .collect()
}
