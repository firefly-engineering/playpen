//! The fixture shared by the end-to-end suites: a policy with one read-write root holding a copy
//! of the probe, and helpers to run playpen and the probe against it.

#![allow(dead_code)] // each suite uses its own subset

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};
use tempfile::TempDir;

pub const PLAYPEN: &str = env!("CARGO_BIN_EXE_playpen");
pub const PROBE: &str = env!("CARGO_BIN_EXE_playpen-probe");

/// One workspace with one read-write brought root, holding a copy of the probe.
pub struct Fixture {
    root: TempDir,
    pub policy: PathBuf,
    /// Kept apart from the root so the policy is never inside the boundary.
    pub policy_dir: TempDir,
}

impl Fixture {
    pub fn new() -> Self {
        let root = TempDir::new().expect("root");
        std::fs::copy(PROBE, root.path().join("probe")).expect("copy probe");
        let policy_dir = TempDir::new().expect("policy dir");
        let policy = policy_dir.path().join("policy.json");
        let document = json!({
            "version": 1,
            "workspaces": {"w": {"roots": [{"path": root.path(), "mode": "readwrite"}]}},
            "profiles": {"p": {"workspaces": ["w"]}},
        });
        std::fs::write(&policy, document.to_string()).expect("write policy");
        Self {
            root,
            policy,
            policy_dir,
        }
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
        let mut command = Command::new(PLAYPEN);
        command
            .args(["run", "--profile", "p", "--agent", "claude", "--policy"])
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
