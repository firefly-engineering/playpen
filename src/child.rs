//! The confined child ([spec §4.1]): closes every descriptor above 2, applies the capability set
//! to itself, and `exec`s the target. The supervisor stays the child's direct parent, forwards
//! signals to it, and exits with its status ([`crate::supervisor`]).
//!
//! [spec §4.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#41-processes

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::backend;
use crate::capability::CapabilitySet;
use crate::code::Code;
use crate::refusal::{EXIT_REFUSED, Refusal};
use crate::supervisor::HeldSignals;

/// Fork, confine the child under `caps`, `exec` `argv` in the inherited CWD, and wait for it.
/// Returns the status the supervisor exits with.
///
/// The supervisor must still be single-threaded here: the child allocates between `fork` and
/// `exec`, which is sound only when no other thread can hold the allocator's lock.
pub fn run_confined(caps: &CapabilitySet, argv: &[OsString]) -> Result<i32, Refusal> {
    let (target, args) = argv
        .split_first()
        .ok_or_else(|| Refusal::new(Code::InvocationUsage, "no target after `--`"))?;
    let mut command = Command::new(target);
    command.args(args);

    let held = HeldSignals::block()?;
    let pid = spawn_confined(caps, &mut command, || {
        held.release_in_child();
        Ok(())
    })?;
    held.supervise(pid)
}

/// Fork a child that runs `prepare`, closes every descriptor above 2, applies `caps` to itself
/// and `exec`s `command`. Returns the child's pid; the caller reaps it.
///
/// If any step fails, the child writes one refusal line to its own stderr and exits `125`.
/// `prepare` runs between `fork` and `exec`, so it is bound by the same single-threaded rule.
pub(crate) fn spawn_confined(
    caps: &CapabilitySet,
    command: &mut Command,
    prepare: impl FnOnce() -> Result<(), Refusal>,
) -> Result<libc::pid_t, Refusal> {
    // SAFETY: plain fork; the child only runs `prepare` and `confine_and_exec`, never returning.
    match unsafe { libc::fork() } {
        -1 => Err(Refusal::new(
            Code::ProcessFork,
            format!("fork failed: {}", std::io::Error::last_os_error()),
        )),
        0 => confine_and_exec(caps, command, prepare),
        pid => Ok(pid),
    }
}

fn confine_and_exec(
    caps: &CapabilitySet,
    command: &mut Command,
    prepare: impl FnOnce() -> Result<(), Refusal>,
) -> ! {
    let confined = prepare()
        .and_then(|()| close_inherited_fds())
        .and_then(|()| backend::apply(caps));
    let refusal = match confined {
        Ok(()) => {
            let err = command.exec();
            Refusal::new(
                Code::TargetExec,
                format!("cannot exec {}: {err}", command.get_program().display()),
            )
        }
        Err(refusal) => refusal,
    };
    refusal.emit();
    // SAFETY: `_exit` skips the parent's atexit handlers, which must not run twice.
    unsafe { libc::_exit(EXIT_REFUSED) }
}

/// The sandbox gates acquiring a descriptor, not using one already open, so nothing inherited
/// above stderr may survive into the target ([spec §8.7]).
///
/// [spec §8.7]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#87-file-descriptors
fn close_inherited_fds() -> Result<(), Refusal> {
    for fd in open_fds()? {
        if fd > 2 {
            // SAFETY: closing a descriptor this process holds; none is in use by Rust code here.
            unsafe { libc::close(fd) };
        }
    }
    Ok(())
}

fn fd_refusal(err: std::io::Error) -> Refusal {
    Refusal::new(
        Code::MechanismUnavailable,
        format!("cannot enumerate inherited descriptors: {err}"),
    )
}

#[cfg(target_os = "macos")]
fn open_fds() -> Result<Vec<libc::c_int>, Refusal> {
    use std::mem::size_of;

    // SAFETY: getpid has no preconditions.
    let pid = unsafe { libc::getpid() };
    let entry = size_of::<libc::proc_fdinfo>() as libc::c_int;
    // SAFETY: a null buffer asks proc_pidinfo for the size it needs.
    let needed =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if needed <= 0 {
        return Err(fd_refusal(std::io::Error::last_os_error()));
    }
    // Room for descriptors opened between the two calls; none are, but the call must not truncate.
    let capacity = needed as usize / entry as usize + 16;
    let mut buf: Vec<libc::proc_fdinfo> = Vec::with_capacity(capacity);
    // SAFETY: the buffer holds `capacity` entries and its byte size is passed alongside it.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            buf.as_mut_ptr().cast(),
            capacity as libc::c_int * entry,
        )
    };
    if written <= 0 {
        return Err(fd_refusal(std::io::Error::last_os_error()));
    }
    // SAFETY: proc_pidinfo initialised `written` bytes of whole entries.
    unsafe { buf.set_len(written as usize / entry as usize) };
    Ok(buf.iter().map(|info| info.proc_fd).collect())
}

#[cfg(target_os = "linux")]
fn open_fds() -> Result<Vec<libc::c_int>, Refusal> {
    // Collect first, then close: closing while iterating would close the directory's own fd.
    let mut fds = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd").map_err(fd_refusal)? {
        let name = entry.map_err(fd_refusal)?.file_name();
        if let Some(fd) = name.to_str().and_then(|s| s.parse().ok()) {
            fds.push(fd);
        }
    }
    Ok(fds)
}
