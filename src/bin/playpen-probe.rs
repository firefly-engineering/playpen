//! `playpen-probe`: the shipped actor for boundary assertions. It performs the actions on its
//! command line in order and writes one verdict per action, as one JSON object per line on stdout,
//! so that one confined launch serves every row of a policy fixture ([spec §17.1]). Its exit
//! status carries one bit: the probe ran (0) or the probe broke (non-zero), never "an assertion
//! failed".
//!
//! [spec §17.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#171-form

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::process::ExitCode;
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
}

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
            "usage: playpen-probe (read <path> | write <path> | list <path> | read-fd <fd> | look-up <service> (macOS) | fds | stdio)... | playpen-probe wait-signal"
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
            "read-fd" => Action::ReadFd(args.next()?.parse().ok()?),
            #[cfg(target_os = "macos")]
            "look-up" => Action::LookUp(args.next()?),
            "fds" => Action::Fds,
            "stdio" => Action::Stdio,
            "wait-signal" => Action::WaitSignal,
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
