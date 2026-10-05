//! The agent state directory end to end ([spec §5.6]): where the kind's redirect points, who
//! shares it, and what stays out of reach.
//!
//! [spec §5.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#56-agent-state-directory

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use tempfile::TempDir;

use common::{DENIAL_ERRNOS, Fixture, os_bin, probe_outside};

fn assert_denied(v: &Value) {
    assert_eq!(v["ok"], false, "{v}");
    assert_eq!(v["enoent"], false, "a denial never reads as absence: {v}");
    let errno = v["errno"].as_i64().expect("errno") as i32;
    assert!(DENIAL_ERRNOS.contains(&errno), "errno {errno}: {v}");
}

/// A policy with two profiles over the one workspace: they share the work, and not the agent's
/// history ([ADR 0021]).
///
/// [ADR 0021]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0021-agent-state-belongs-to-the-profile.md
fn two_profiles(fx: &Fixture) -> PathBuf {
    let profile = json!({"workspaces": ["w"], "toolchain": []});
    fx.policy_named(
        "agent-state.json",
        &json!({
            "version": 1,
            "workspaces": {"w": {"roots": [{"path": fx.root(), "mode": "readwrite"}]}},
            "profiles": {"p": profile, "q": profile},
        }),
    )
}

/// `playpen run` of `profile` as `kind` under `policy`.
fn run(fx: &Fixture, policy: &Path, profile: &str, kind: &str, argv: &[&str]) -> Command {
    let mut command = fx.playpen(&["run", "--profile", profile, "--agent", kind, "--policy"]);
    command.arg(policy).arg("--").args(argv);
    command
}

/// What the kind's redirect variable holds inside a run of `profile` as `kind`.
fn redirect(fx: &Fixture, policy: &Path, profile: &str, kind: &str) -> PathBuf {
    let name = playpen::kind::require(kind).expect("a known kind").redirect;
    let output = run(fx, policy, profile, kind, &[&os_bin("env")])
        .output()
        .expect("playpen");
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout)
        .expect("utf-8")
        .lines()
        .filter_map(|line| line.split_once('='))
        .find(|(var, _)| *var == name)
        .map(|(_, value)| PathBuf::from(value))
        .unwrap_or_else(|| panic!("{name} is not in the child's environment"))
}

/// The redirect names a directory the agent can write, keyed by profile and kind.
#[test]
fn the_redirect_names_a_writable_directory_keyed_by_profile_and_kind() {
    let fx = Fixture::new();
    let policy = two_profiles(&fx);
    let dir = redirect(&fx, &policy, "p", "claude");
    assert!(dir.is_dir(), "{dir:?} was not created");
    assert!(
        dir.starts_with(fx.state_home().join("playpen")),
        "the agent state directory is playpen's own: {dir:?}"
    );
    let written = dir.join("history.jsonl");
    assert_eq!(
        fx.probe_under(&policy, &["write", written.to_str().unwrap()])["ok"],
        true,
        "the agent cannot write its own state directory"
    );
}

/// Two profiles sharing a workspace get different directories, and one profile's two kinds do
/// too: the directory holds whatever the writing run could read.
#[test]
fn two_profiles_sharing_a_workspace_get_different_directories() {
    let fx = Fixture::new();
    let policy = two_profiles(&fx);
    let p = redirect(&fx, &policy, "p", "claude");
    let q = redirect(&fx, &policy, "q", "claude");
    let omp = redirect(&fx, &policy, "p", "omp");
    assert_ne!(p, q);
    assert_ne!(p, omp);
}

/// Shared by every run of the profile, concurrently: there is no lock and no `concurrency` field,
/// because the agent handles its own.
#[test]
fn concurrent_runs_of_one_profile_share_the_directory() {
    let fx = Fixture::new();
    let policy = two_profiles(&fx);
    let first = redirect(&fx, &policy, "p", "claude");
    // A run that holds the directory open while a second one starts.
    let mut held = run(&fx, &policy, "p", "claude", &[&os_bin("sleep"), "5"])
        .spawn()
        .expect("spawn");
    let second = redirect(&fx, &policy, "p", "claude");
    assert_eq!(first, second);
    let _ = held.kill();
    let _ = held.wait();
}

/// The real `~/.claude` is never granted: the redirect is what the agent gets, and the host's own
/// agent home is outside every grant.
#[test]
fn the_real_agent_home_stays_unreadable() {
    let fx = Fixture::new();
    let policy = two_profiles(&fx);
    let home = TempDir::new().expect("home");
    let real = home.path().join(".claude");
    std::fs::create_dir(&real).expect("mkdir");
    let credentials = real.join(".credentials.json");
    std::fs::write(&credentials, "{\"token\":\"decoy\"}").expect("seed");
    let credentials = credentials.to_str().expect("a UTF-8 path");
    assert_eq!(
        probe_outside(&["read", credentials])["ok"],
        true,
        "readable outside"
    );
    assert_denied(&fx.probe_under(&policy, &["read", credentials]));
}

/// A real `~/.claude` holding `settings.json`, which the policy shares, and `.credentials.json`,
/// which it does not. Returns the home and the policy.
fn with_share(fx: &Fixture, share: Value) -> (TempDir, PathBuf) {
    let home = TempDir::new().expect("home");
    let agent_home = home.path().join(".claude");
    std::fs::create_dir(&agent_home).expect("mkdir");
    std::fs::write(agent_home.join("settings.json"), "{\"theme\":\"dark\"}").expect("seed");
    std::fs::write(
        agent_home.join(".credentials.json"),
        "{\"token\":\"decoy\"}",
    )
    .expect("seed");
    let policy = fx.policy_named(
        "share.json",
        &json!({
            "version": 1,
            "workspaces": {"w": {"roots": [{"path": fx.root(), "mode": "readwrite"}]}},
            "profiles": {"p": {
                "workspaces": ["w"],
                "toolchain": [],
                "agent_state": {"claude": {"share": share}},
            }},
        }),
    );
    (home, policy)
}

/// A run of profile `p` as `claude` under `policy`, with `home` as the caller's home.
fn run_at_home(fx: &Fixture, policy: &Path, home: &Path, argv: &[&str]) -> Command {
    let mut command = run(fx, policy, "p", "claude", argv);
    command.env("HOME", home);
    command
}

/// The agent state directory of profile `p` as `claude`, with `home` as the caller's home.
fn redirect_at_home(fx: &Fixture, policy: &Path, home: &Path) -> PathBuf {
    let name = playpen::kind::require("claude")
        .expect("a known kind")
        .redirect;
    let output = run_at_home(fx, policy, home, &[&os_bin("env")])
        .output()
        .expect("playpen");
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout)
        .expect("utf-8")
        .lines()
        .filter_map(|line| line.split_once('='))
        .find(|(var, _)| *var == name)
        .map(|(_, value)| PathBuf::from(value))
        .unwrap_or_else(|| panic!("{name} is not in the child's environment"))
}

/// A named entry is readable inside the state directory and not writable; the list is
/// default-deny, so an unnamed one from the same agent home is not visible at all ([spec §5.6]).
///
/// [spec §5.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#56-agent-state-directory
#[test]
fn a_named_share_entry_is_readable_inside_and_an_unnamed_one_is_not() {
    let fx = Fixture::new();
    let (home, policy) = with_share(&fx, json!(["settings.json"]));
    let dir = redirect_at_home(&fx, &policy, home.path());
    let shared = dir.join("settings.json");
    let unnamed = dir.join(".credentials.json");
    // Outside first: the entry is there, and it is where playpen says it is.
    assert!(shared.symlink_metadata().expect("the link").is_symlink());
    assert_eq!(
        std::fs::read_link(&shared).expect("the link"),
        home.path()
            .canonicalize()
            .expect("canonical")
            .join(".claude/settings.json")
    );
    let probe = fx.probe();
    let inside = |argv: &[&str]| {
        let mut full = vec![probe.to_str().expect("a UTF-8 path")];
        full.extend(argv);
        let output = run_at_home(&fx, &policy, home.path(), &full)
            .output()
            .expect("playpen");
        common::verdict(output)
    };
    assert_eq!(inside(&["read", shared.to_str().unwrap()])["ok"], true);
    assert_denied(&inside(&["write", shared.to_str().unwrap()]));
    // Not visible: no link was made, and the real file is outside every grant.
    assert!(!unnamed.exists(), "{unnamed:?} is visible");
    let real = home.path().join(".claude/.credentials.json");
    assert_denied(&inside(&["read", real.to_str().unwrap()]));
}

/// A share list that silently shared nothing would read as a working policy, so a missing source
/// refuses.
#[test]
fn a_missing_share_source_refuses() {
    let fx = Fixture::new();
    let (home, policy) = with_share(&fx, json!(["settings.json", "gone.json"]));
    let output = run_at_home(&fx, &policy, home.path(), &[&os_bin("true")])
        .output()
        .expect("playpen");
    let run = common::assert_refused(&output, "refusal.root.missing");
    let message = fx.record(&run)["refusal"]["message"]
        .as_str()
        .expect("a message")
        .to_owned();
    assert!(
        message.contains("profile:p.agent_state.claude.share[1]"),
        "{message}"
    );
    assert!(message.contains("gone.json"), "{message}");
}

/// A share entry is one name in the kind's agent home: a nested path or `..` names nothing
/// playpen can share, and refuses rather than reaching out of the agent home.
#[test]
fn a_share_entry_that_is_not_one_name_refuses() {
    let fx = Fixture::new();
    for entry in ["../.ssh", "a/b", "/etc/passwd", "."] {
        let (home, policy) = with_share(&fx, json!([entry]));
        let output = run_at_home(&fx, &policy, home.path(), &[&os_bin("true")])
            .output()
            .expect("playpen");
        common::assert_refused(&output, "refusal.root.missing");
    }
}
