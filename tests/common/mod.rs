//! The fixture shared by the end-to-end suites: a policy with one read-write root holding a copy
//! of the probe, a state directory of its own, and helpers to run playpen and the probe against
//! them.

#![allow(dead_code)] // each suite uses its own subset

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};
use tempfile::TempDir;

pub const PLAYPEN: &str = env!("CARGO_BIN_EXE_playpen");
pub const PROBE: &str = env!("CARGO_BIN_EXE_playpen-probe");

/// An OS-owned command binary by name, resolved by the floor itself ([`playpen::floor::binary`]).
/// A test names the binary it needs and never a path, so a non-FHS host needs no special case of
/// its own.
///
/// Every binary this returns is inside the floor, so a target that uses one is confined by the
/// floor alone and needs no root of its own. A name the floor does not hold is a broken fixture,
/// and panics naming where it looked rather than surfacing later as `refusal.target.exec`.
pub fn os_bin(name: &str) -> String {
    let path = playpen::floor::binary(name).unwrap_or_else(|searched| {
        panic!("test setup: the floor holds no `{name}`; looked at {searched:?}")
    });
    path.to_str().expect("utf-8 path").to_owned()
}

/// The denial errnos of this platform ([spec §15.2]); `ENOENT` is never one.
///
/// [spec §15.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#152-capability-matrix
#[cfg(target_os = "macos")]
pub const DENIAL_ERRNOS: &[i32] = &[libc::EPERM];
#[cfg(target_os = "linux")]
pub const DENIAL_ERRNOS: &[i32] = &[libc::EACCES, libc::EXDEV, libc::EPERM];

/// One workspace with one brought root, holding a copy of the probe.
pub struct Fixture {
    root: TempDir,
    pub policy: PathBuf,
    /// Kept apart from the root so the policy is never inside the boundary.
    pub policy_dir: TempDir,
    /// `XDG_STATE_HOME` for every playpen this fixture runs, so no test touches the real one.
    state_home: TempDir,
}

impl Fixture {
    /// The root is read-write.
    pub fn new() -> Self {
        Self::with_mode("readwrite")
    }

    /// The root is granted at `mode` (`read` or `readwrite`).
    pub fn with_mode(mode: &str) -> Self {
        let root = TempDir::new().expect("root");
        std::fs::copy(PROBE, root.path().join("probe")).expect("copy probe");
        let policy_dir = TempDir::new().expect("policy dir");
        let policy = policy_dir.path().join("policy.json");
        let document = json!({
            "version": 1,
            "workspaces": {"w": {"roots": [{"path": root.path(), "mode": mode}]}},
            "profiles": {"p": {"workspaces": ["w"], "toolchain": []}},
        });
        std::fs::write(&policy, document.to_string()).expect("write policy");
        Self {
            root,
            policy,
            policy_dir,
            state_home: TempDir::new().expect("state home"),
        }
    }

    pub fn state_home(&self) -> &Path {
        self.state_home.path()
    }

    /// Where playpen keeps this fixture's run records.
    pub fn runs(&self) -> PathBuf {
        self.state_home().join("playpen/runs")
    }

    /// The stored record of run `id`.
    pub fn record(&self, id: &str) -> Value {
        let path = self.runs().join(format!("{id}.json"));
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        serde_json::from_slice(&bytes).expect("a record is JSON")
    }

    /// The ids of every run this fixture has recorded.
    pub fn run_ids(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(self.runs()) else {
            return Vec::new();
        };
        let mut ids: Vec<_> = entries
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .into_string()
                    .expect("utf-8")
            })
            .filter_map(|name| name.strip_suffix(".json").map(str::to_owned))
            .collect();
        ids.sort();
        ids
    }

    /// `playpen` with `args`, from inside the root, under this fixture's state directory.
    pub fn playpen(&self, args: &[&str]) -> Command {
        let mut command = Command::new(PLAYPEN);
        command
            .args(args)
            .current_dir(self.root())
            .env("XDG_STATE_HOME", self.state_home());
        command
    }

    pub fn root(&self) -> &Path {
        self.root.path()
    }

    pub fn probe(&self) -> PathBuf {
        self.root().join("probe")
    }

    /// `playpen run` from inside the root.
    pub fn run(&self, argv: &[&str]) -> Command {
        self.run_from(self.root(), argv)
    }

    pub fn run_from(&self, cwd: &Path, argv: &[&str]) -> Command {
        let mut command = self.playpen(&["run", "--profile", "p", "--agent", "claude", "--policy"]);
        command
            .arg(&self.policy)
            .arg("--")
            .args(argv)
            .current_dir(cwd);
        command
    }

    /// Run the probe confined and return its verdict.
    pub fn probe_inside(&self, args: &[&str]) -> Value {
        let probe = self.probe();
        let mut argv = vec![probe.to_str().expect("utf-8 path")];
        argv.extend(args);
        verdict(self.run(&argv).output().expect("run playpen"))
    }
}

/// Exactly one stderr line `playpen: <code>: … — run <id>`, exit 125, and nothing on stdout.
/// Returns the run id.
pub fn assert_refused(output: &Output, code: &str) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(125), "stderr={stderr}");
    assert!(
        output.stdout.is_empty(),
        "stdout is sacred: {:?}",
        output.stdout
    );
    let lines: Vec<_> = stderr.lines().collect();
    assert_eq!(lines.len(), 1, "a refusal is one line: {stderr:?}");
    assert!(stderr.ends_with('\n'));
    let prefix = format!("playpen: {code}: ");
    assert!(
        lines[0].starts_with(&prefix),
        "expected {prefix:?}, got {:?}",
        lines[0]
    );
    let (_, run) = lines[0]
        .rsplit_once(" — run ")
        .unwrap_or_else(|| panic!("no run id on {:?}", lines[0]));
    assert_eq!(run.len(), 26, "a run id is a ULID: {run:?}");
    run.to_owned()
}

pub fn verdict(output: Output) -> Value {
    assert!(
        output.status.success(),
        "the probe broke: {output:?} stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("probe verdict is JSON")
}

pub fn probe_outside(args: &[&str]) -> Value {
    verdict(Command::new(PROBE).args(args).output().expect("run probe"))
}

/// A new pseudo-terminal: the master, and the slave as a file.
pub fn pty() -> (OwnedFd, File) {
    // SAFETY: posix_openpt has no memory preconditions.
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    assert!(master >= 0, "posix_openpt");
    // SAFETY: `master` is a fresh descriptor nothing else owns.
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    // SAFETY: grantpt and unlockpt act on the master descriptor only.
    unsafe {
        assert_eq!(libc::grantpt(master.as_raw_fd()), 0, "grantpt");
        assert_eq!(libc::unlockpt(master.as_raw_fd()), 0, "unlockpt");
    }
    // SAFETY: ptsname returns null or a NUL-terminated string, read before any other pty call.
    let name = unsafe {
        let name = libc::ptsname(master.as_raw_fd());
        assert!(!name.is_null(), "ptsname");
        std::ffi::CStr::from_ptr(name)
            .to_str()
            .expect("utf-8")
            .to_owned()
    };
    let slave = File::options()
        .read(true)
        .write(true)
        .open(name)
        .expect("open slave");
    (master, slave)
}
