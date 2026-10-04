//! `playpen run` end to end: the walking skeleton's acceptance criteria, each asserted in two
//! parts — the condition is first shown to hold outside, then the boundary's behaviour inside.

mod common;

use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;

use serde_json::{Value, json};
use tempfile::TempDir;

use common::{DENIAL_ERRNOS, Fixture, PLAYPEN, PROBE, assert_refused, probe_outside, verdict};

fn assert_denied(v: &Value) {
    assert_eq!(v["ok"], false, "{v}");
    assert_eq!(
        v["enoent"], false,
        "a denial must never read as absence: {v}"
    );
    let errno = v["errno"].as_i64().expect("errno") as i32;
    assert!(
        DENIAL_ERRNOS.contains(&errno),
        "errno {errno} is not a denial errno: {v}"
    );
}

#[test]
fn a_dynamically_linked_binary_reads_and_writes_inside_the_granted_root() {
    let fx = Fixture::new();
    let existing = fx.root().join("existing");
    std::fs::write(&existing, "content").expect("seed");
    let created = fx.root().join("created");

    assert_eq!(
        fx.probe_inside(&["read", existing.to_str().unwrap()])["ok"],
        true
    );
    assert_eq!(
        fx.probe_inside(&["write", created.to_str().unwrap()])["ok"],
        true
    );
    assert_eq!(std::fs::read(&created).expect("written"), b"x");
}

#[test]
fn reading_outside_the_root_and_the_floor_is_a_denial_never_enoent() {
    let fx = Fixture::new();
    let elsewhere = TempDir::new().expect("decoy dir");
    let decoy = elsewhere.path().join("id_ed25519");
    std::fs::write(&decoy, "decoy").expect("decoy");
    let decoy = decoy.to_str().unwrap();

    assert_eq!(
        probe_outside(&["read", decoy])["ok"],
        true,
        "decoy readable outside"
    );
    assert_denied(&fx.probe_inside(&["read", decoy]));
}

#[test]
fn writing_outside_the_root_is_a_denial() {
    let fx = Fixture::new();
    let elsewhere = TempDir::new().expect("decoy dir");
    let target = elsewhere.path().join("planted");
    let target_str = target.to_str().unwrap();

    assert_denied(&fx.probe_inside(&["write", target_str]));
    assert!(!target.exists(), "nothing was written outside the root");
    assert_eq!(
        probe_outside(&["write", target_str])["ok"],
        true,
        "writable outside"
    );
}

/// Hand `file` to the spawned process as descriptor `fd`, without close-on-exec.
fn inherit_as(command: &mut Command, file: &File, fd: i32) {
    let source = file.as_raw_fd();
    // SAFETY: dup2 is async-signal-safe; both descriptors are valid in the forked child.
    unsafe {
        command.pre_exec(move || match libc::dup2(source, fd) {
            -1 => Err(std::io::Error::last_os_error()),
            _ => Ok(()),
        });
    }
}

#[test]
fn the_child_holds_no_descriptor_above_stderr_at_exec() {
    const INHERITED: i32 = 7;
    let fx = Fixture::new();
    let credential = File::open(PLAYPEN).expect("an open file to inherit");

    let mut outside = Command::new(PROBE);
    outside.arg("fds");
    inherit_as(&mut outside, &credential, INHERITED);
    let seen = verdict(outside.output().expect("probe"));
    assert!(
        seen["fds"].as_array().unwrap().contains(&json!(INHERITED)),
        "the fd is inherited outside: {seen}"
    );

    let probe = fx.probe();
    let mut inside = fx.run(&[probe.to_str().unwrap(), "fds"]);
    inherit_as(&mut inside, &credential, INHERITED);
    let seen = verdict(inside.output().expect("playpen"));
    assert_eq!(
        seen["fds"],
        json!([]),
        "descriptors leaked into the child: {seen}"
    );
}

#[test]
fn a_cwd_outside_every_granted_root_refuses() {
    let fx = Fixture::new();
    let elsewhere = TempDir::new().expect("cwd");
    let output = fx
        .run_from(elsewhere.path(), &["/usr/bin/true"])
        .output()
        .expect("playpen");
    let run = assert_refused(&output, "refusal.cwd.ungranted");
    assert_eq!(fx.record(&run)["refusal"]["code"], "refusal.cwd.ungranted");
}

#[test]
fn success_writes_nothing_and_passes_the_status_through() {
    let fx = Fixture::new();
    let output = fx
        .run(&["/bin/sh", "-c", "exit 3"])
        .output()
        .expect("playpen");
    assert_eq!(output.status.code(), Some(3));
    assert!(
        output.stdout.is_empty() && output.stderr.is_empty(),
        "{output:?}"
    );
}

#[test]
fn a_caller_that_ignores_sigchld_still_gets_a_launch() {
    let fx = Fixture::new();
    let mut command = fx.run(&["/bin/sh", "-c", "exit 3"]);
    // SAFETY: signal is async-signal-safe. Linux keeps an ignored SIGCHLD across `exec`, and with
    // it the kernel reaps children before playpen can wait for them.
    unsafe {
        command.pre_exec(|| {
            libc::signal(libc::SIGCHLD, libc::SIG_IGN);
            Ok(())
        });
    }
    let output = command.output().expect("playpen");
    assert_eq!(
        output.status.code(),
        Some(3),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_target_that_cannot_be_executed_refuses() {
    let fx = Fixture::new();
    let missing = fx.root().join("missing");
    let output = fx
        .run(&[missing.to_str().unwrap()])
        .output()
        .expect("playpen");
    // Refused in the child, after the fork, and still recorded by the supervisor.
    let run = assert_refused(&output, "refusal.target.exec");
    assert_eq!(fx.record(&run)["refusal"]["code"], "refusal.target.exec");
}

/// `playpen run` of `true` under `policy`, with the given profile and kind.
fn run_args<'a>(profile: &'a str, kind: &'a str, policy: &'a str) -> Vec<&'a str> {
    let mut args = vec!["run", "--profile", profile, "--agent", kind];
    if !policy.is_empty() {
        args.extend(["--policy", policy]);
    }
    args.extend(["--", "true"]);
    args
}

#[test]
fn every_refusal_is_one_line_and_exit_125() {
    let fx = Fixture::new();
    let root = fx.root();
    let run = |args: &[&str]| fx.playpen(args).output().expect("playpen");
    let policy = fx.policy.to_str().unwrap();
    let write_policy = |name: &str, document: Value| {
        let path = fx.policy_dir.path().join(name);
        std::fs::write(&path, document.to_string()).expect("policy");
        path.to_str().unwrap().to_owned()
    };
    let with_root = |name: &str, path: Value| {
        write_policy(
            name,
            json!({
                "version": 1,
                "workspaces": {"w": {"roots": [{"path": path, "mode": "read"}]}},
                "profiles": {"p": {"workspaces": ["w"]}},
            }),
        )
    };
    let unknown_workspace = write_policy(
        "unknown-ws.json",
        json!({"version": 1, "profiles": {"p": {"workspaces": ["nope"]}}}),
    );
    let missing_root = with_root("missing-root.json", json!(root.join("gone")));
    let relative_root = with_root("relative-root.json", json!("src/playpen"));
    let unknown_field = write_policy("unknown-field.json", json!({"version": 1, "profils": {}}));
    let absent = root.join("absent.yaml");
    // A directory where the policy file should be: present, and unreadable as a document.
    let unreadable = fx.policy_dir.path().to_str().unwrap();

    let cases: &[(Vec<&str>, &str)] = &[
        (
            vec!["run", "--agent", "claude", "--", "true"],
            "refusal.invocation.usage",
        ),
        (
            vec!["run", "--profile", "p", "--agent", "claude", "true"],
            "refusal.invocation.usage",
        ),
        (vec!["frobnicate"], "refusal.invocation.usage"),
        (vec!["--version"], "refusal.invocation.usage"),
        (run_args("p", "nope", policy), "refusal.kind.unknown"),
        (run_args("p", "claude", ""), "refusal.policy.not-found"),
        (
            run_args("p", "claude", absent.to_str().unwrap()),
            "refusal.policy.not-found",
        ),
        (
            run_args("p", "claude", unreadable),
            "refusal.policy.unreadable",
        ),
        (
            run_args("p", "claude", &unknown_field),
            "refusal.policy.unknown-field",
        ),
        (
            run_args("q", "claude", policy),
            "refusal.selection.unknown-profile",
        ),
        (
            run_args("p", "claude", &unknown_workspace),
            "refusal.workspace.unknown",
        ),
        (
            run_args("p", "claude", &relative_root),
            "refusal.root.relative",
        ),
        (
            run_args("p", "claude", &missing_root),
            "refusal.root.missing",
        ),
    ];
    for (args, code) in cases {
        let id = assert_refused(&run(args), code);
        // Every refusal, including one before the command line parsed, leaves its record.
        assert_eq!(fx.record(&id)["refusal"]["code"], *code, "{args:?}");
    }
    assert_eq!(fx.run_ids().len(), cases.len(), "one record per run");
}
