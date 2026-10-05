//! The floor self-test ([spec §8.6]): before every launch, playpen applies the bare floor to a
//! throwaway child and asserts that a dynamically linked OS binary exits 0. A floor that no longer
//! lets `exec` return is caught here, as one refusal line, rather than as an agent that dies with
//! `rc=134` and empty stderr.
//!
//! The verdict is **never cached**: a cache key is a proxy for "the floor still works", and every
//! proxy fails open and silently. The suite's `P-canary` row calls this same implementation
//! ([spec §17.2]), so the runtime check and the enforcement row cannot disagree.
//!
//! [spec §8.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#86-the-floor-self-test
//! [spec §17.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#172-rows

use std::fs::File;
use std::io::Read;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::Command;

use crate::capability::CapabilitySet;
use crate::child::{self, Started};
use crate::code::Code;
use crate::refusal::Refusal;

/// The canary: an OS-owned binary, dynamically linked against the platform's C library, that needs
/// no grant beyond the floor. The suite's bare-floor row admits OS-owned binaries only.
const CANARY: &str = "true";

/// The canary this host's floor can run, found by name the way the floor finds any OS binary
/// ([`floor::binary`]). A dedicated floor carries its own, because on such a host no path outside
/// that floor is both OS-owned and runnable. Resolved per call rather than once, for the same
/// reason the self-test's verdict is never cached: the answer is a property of the host as it is
/// now.
///
/// Where no floor directory holds one, this is the first place looked, so the self-test's refusal
/// names where the canary belongs.
///
/// [`floor::binary`]: crate::floor::binary
pub fn canary_path() -> PathBuf {
    crate::floor::binary(CANARY).unwrap_or_else(|searched| searched[0].clone())
}

/// Run [`CANARY`] under the bare floor. A failure is `refusal.floor.self-test`.
///
/// The caller must be single-threaded, as for [`child::run_confined`]: the throwaway child
/// allocates between `fork` and `exec`.
pub fn floor() -> Result<(), Refusal> {
    canary(&crate::floor::floor()?)
}

/// Run [`CANARY`] confined under `caps`, with its stdin and stdout on the null device, and assert
/// that it exits 0. Its stderr is captured into the refusal, so a failure names what went wrong
/// as far as the child could tell; nothing it writes reaches playpen's own stdio. The caller must
/// be single-threaded, as for [`floor`].
pub fn canary(caps: &CapabilitySet) -> Result<(), Refusal> {
    let null = File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|e| prepare_refusal("open /dev/null", e))?;
    let (mut stderr, writer) = std::io::pipe().map_err(|e| prepare_refusal("pipe", e))?;
    let _reapable = Reapable::new()?;
    let path = canary_path();
    let named = path.display();
    // A host with no canary has no floor to test. Said here rather than left to surface as an
    // `exec` that found nothing, because the remedy is a floor, not anything about this run.
    if !path.exists() {
        return Err(Refusal::new(
            Code::FloorUnavailable,
            format!(
                "this host has no floor canary at {named}: its OS is not an FHS tree, so the \
                 floor must be a dedicated one (build it with `nix build .#floor` and name it \
                 in {})",
                crate::floor::FLOOR_ENV
            ),
        ));
    }
    let mut command = Command::new(&path);
    // The canary's refusal is carried inside the self-test's own line, which names the run.
    let started = child::spawn_confined(caps, &mut command, None, || {
        redirect(&null, 0)?;
        redirect(&null, 1)?;
        redirect(&writer, 2)
    })?;
    let pid = match started {
        Started::Exec(pid) => pid,
        Started::Refused(refusal) => {
            return Err(Refusal::new(
                Code::FloorSelfTest,
                format!(
                    "the floor canary {named} could not start when confined: {}: {}",
                    refusal.code,
                    refusal.message()
                ),
            ));
        }
    };
    // The child holds the only other write end; once it exits, the read below ends.
    drop(writer);
    let mut said = Vec::new();
    // The canary's stderr is a diagnostic only: failing to read it changes no verdict.
    let _ = stderr.read_to_end(&mut said);
    let status = wait(pid)?;
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        return Ok(());
    }
    let how = if libc::WIFSIGNALED(status) {
        format!("died by signal {}", libc::WTERMSIG(status))
    } else {
        format!("exited {}", libc::WEXITSTATUS(status))
    };
    let said = String::from_utf8_lossy(&said);
    let said = match said.trim_end() {
        "" => "with empty stderr".to_string(),
        said => format!("saying {said:?}"),
    };
    Err(Refusal::new(
        Code::FloorSelfTest,
        format!("the floor canary {named} {how} when confined, {said}"),
    ))
}

/// In the throwaway child: make `fd` a copy of `file`.
fn redirect(file: &impl AsRawFd, fd: libc::c_int) -> Result<(), Refusal> {
    // SAFETY: dup2 is async-signal-safe; both descriptors are open in this process.
    if unsafe { libc::dup2(file.as_raw_fd(), fd) } == -1 {
        return Err(prepare_refusal(
            &format!("dup2 onto {fd}"),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn prepare_refusal(call: &str, err: std::io::Error) -> Refusal {
    Refusal::new(
        Code::ProcessFork,
        format!("cannot prepare the floor self-test: {call}: {err}"),
    )
}

/// `SIGCHLD` at its default action for as long as this lives. A caller may hand playpen an
/// ignored `SIGCHLD`, which Linux keeps across `exec`, and under it the kernel reaps the child
/// itself, so the wait below would fail. The caller's disposition is restored on drop.
struct Reapable(libc::sigaction);

impl Reapable {
    fn new() -> Result<Self, Refusal> {
        let mut previous = MaybeUninit::<libc::sigaction>::uninit();
        // SAFETY: a zeroed sigaction with `SIG_DFL` is valid; `previous` is a valid out-pointer,
        // read only once sigaction has filled it.
        unsafe {
            let mut default: libc::sigaction = std::mem::zeroed();
            default.sa_sigaction = libc::SIG_DFL;
            if libc::sigaction(libc::SIGCHLD, &default, previous.as_mut_ptr()) != 0 {
                return Err(prepare_refusal(
                    "sigaction(SIGCHLD)",
                    std::io::Error::last_os_error(),
                ));
            }
            Ok(Self(previous.assume_init()))
        }
    }
}

impl Drop for Reapable {
    fn drop(&mut self) {
        // SAFETY: restoring the action sigaction itself returned.
        unsafe { libc::sigaction(libc::SIGCHLD, &self.0, std::ptr::null_mut()) };
    }
}

/// Wait for the throwaway child and return its raw wait status.
fn wait(pid: libc::pid_t) -> Result<libc::c_int, Refusal> {
    loop {
        let mut status = 0;
        // SAFETY: `status` is a valid out-pointer for the duration of the call.
        if unsafe { libc::waitpid(pid, &mut status, 0) } != -1 {
            return Ok(status);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(Refusal::new(
                Code::ProcessWait,
                format!("waitpid on the floor self-test failed: {err}"),
            ));
        }
    }
}
