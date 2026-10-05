//! `playpen explain --run` and `--list` ([spec §14.2]) end to end, and the bounded ring they read
//! ([spec §14.1]).
//!
//! [spec §14.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#142-playpen-explain
//! [spec §14.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#141-the-run-record

mod common;

use std::process::Output;

use serde_json::Value;

use common::{Fixture, assert_refused, os_bin};

/// `explain` with `args` succeeded, wrote nothing to stderr, and opened no record of its own.
/// Returns its stdout.
fn explain(fx: &Fixture, args: &[&str]) -> String {
    let before = fx.run_ids();
    let mut command = fx.playpen(&["explain"]);
    let output = command.args(args).output().expect("playpen explain");
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(fx.run_ids(), before, "explain launches nothing");
    String::from_utf8(output.stdout).expect("utf-8")
}

/// Exactly one stderr line `playpen: <code>: …`, with no run id, since `explain` has no run of
/// its own; exit 125, and nothing on stdout.
fn assert_explain_refused(output: &Output, code: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(125), "stderr={stderr}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let lines: Vec<_> = stderr.lines().collect();
    assert_eq!(lines.len(), 1, "a refusal is one line: {stderr:?}");
    assert!(
        lines[0].starts_with(&format!("playpen: {code}: ")),
        "{:?}",
        lines[0]
    );
    assert!(!lines[0].contains(" — run "), "{:?}", lines[0]);
}

#[test]
fn explain_run_replays_a_stored_record_in_both_forms() {
    let fx = Fixture::new();
    let output = fx
        .run(&[&os_bin("sh"), "-c", "echo $$; exit 3"])
        .output()
        .expect("playpen");
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let pid = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let id = fx.run_ids().pop().expect("a record");

    let mut json: Value =
        serde_json::from_str(&explain(&fx, &["--run", &id, "--json"])).expect("JSON");
    let denials = json
        .as_object_mut()
        .and_then(|fields| fields.remove("denials"))
        .expect("the denials command, or null");
    assert_eq!(
        json,
        fx.record(&id),
        "the JSON form is the stored record, beside the command"
    );

    let human = explain(&fx, &["--run", &id]);
    let field = |name: &str| {
        human
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(' ')?;
                (key == name).then(|| value.trim().to_owned())
            })
            .unwrap_or_else(|| panic!("no {name} in {human}"))
    };
    assert_eq!(field("run"), id);
    assert_eq!(field("pid"), pid);
    assert_eq!(field("profile"), "p");
    assert_eq!(field("kind"), "claude");
    assert_eq!(field("status"), "3");
    assert_eq!(field("refusal"), "-");
    // The command is the same in both forms. On macOS it names the child's pid; on Linux it waits
    // on the trace work, so it is absent.
    match denials.as_str() {
        Some(command) => {
            assert_eq!(field("denials"), command);
            assert!(command.starts_with("/usr/bin/log show "), "{command}");
            assert!(command.contains(&format!("({pid})")), "{command}");
        }
        None => assert_eq!(field("denials"), "-"),
    }
    assert_eq!(denials.is_string(), cfg!(target_os = "macos"), "{denials}");
    let root = fx.root().canonicalize().expect("root");
    assert!(
        human
            .lines()
            .any(|line| line.contains(root.to_str().unwrap())
                && line.contains("readwrite")
                && line.contains("(from workspace:w.roots[0])")),
        "the brought root, with its provenance: {human}"
    );
}

#[test]
fn explain_run_shows_a_refused_runs_code() {
    let fx = Fixture::new();
    let id = assert_refused(
        &fx.playpen(&["run", "--profile", "p", "--agent", "nobody", "--", "x"])
            .output()
            .expect("playpen"),
        "refusal.kind.unknown",
    );
    let human = explain(&fx, &["--run", &id]);
    assert!(
        human
            .lines()
            .any(|line| line.starts_with("refusal") && line.contains("refusal.kind.unknown")),
        "{human}"
    );
    assert!(
        human.lines().any(|line| line == "capabilities -"),
        "{human}"
    );
}

#[test]
fn explain_list_lists_recent_runs_most_recent_first() {
    let fx = Fixture::new();
    assert_eq!(explain(&fx, &["--list"]), "", "no runs yet");
    assert!(
        fx.run(&[&os_bin("true")])
            .status()
            .expect("playpen")
            .success()
    );
    let refused = fx
        .playpen(&["run", "--profile", "p", "--agent", "nobody", "--", "x"])
        .output()
        .expect("playpen");
    let refused = assert_refused(&refused, "refusal.kind.unknown");
    let ids = fx.run_ids();
    assert_eq!(ids.len(), 2);

    let json: Value = serde_json::from_str(&explain(&fx, &["--list", "--json"])).expect("JSON");
    assert_eq!(
        json,
        Value::Array(vec![fx.record(&ids[1]), fx.record(&ids[0])])
    );

    let human = explain(&fx, &["--list"]);
    let lines: Vec<_> = human.lines().collect();
    assert_eq!(lines.len(), 2, "{human}");
    assert!(lines[0].starts_with(&refused), "{human}");
    assert!(lines[0].ends_with("refusal.kind.unknown"), "{human}");
    assert!(lines[1].starts_with(&ids[0]), "{human}");
    assert!(lines[1].ends_with("claude  p  status 0"), "{human}");
}

#[test]
fn an_unknown_run_is_refused_without_a_record() {
    let fx = Fixture::new();
    for id in ["01ARZ3NDEKTSV4RRFFQ69G5FAV", "../../../etc/passwd"] {
        let output = fx
            .playpen(&["explain", "--run", id])
            .output()
            .expect("playpen");
        assert_explain_refused(&output, "refusal.run.unknown");
    }
    assert_eq!(fx.run_ids(), Vec::<String>::new());
}

#[test]
fn explain_with_no_state_directory_is_state_io() {
    let fx = Fixture::new();
    let output = fx
        .playpen(&["explain", "--list"])
        .env_remove("XDG_STATE_HOME")
        .env_remove("HOME")
        .output()
        .expect("playpen");
    assert_explain_refused(&output, "refusal.state.io");
}

#[test]
fn explain_asks_one_question() {
    let fx = Fixture::new();
    for args in [&["explain"][..], &["explain", "--list", "--run", "x"]] {
        let output = fx.playpen(args).output().expect("playpen");
        assert_refused(&output, "refusal.invocation.usage");
    }
}

#[test]
fn the_ring_keeps_the_most_recent_ended_runs() {
    let fx = Fixture::new();
    // One more than the bound, all of them history: ids in the ULID alphabet, below any id
    // allocated today, and none with a sidecar, so none reads as live.
    std::fs::create_dir_all(fx.runs()).expect("runs");
    let planted: Vec<_> = (0..=playpen::record::RETAINED)
        .map(|i| format!("0000000000000000000000{i:04}"))
        .collect();
    for id in &planted {
        std::fs::write(fx.runs().join(format!("{id}.json")), "{}").expect("plant");
    }
    assert!(
        fx.run(&[&os_bin("true")])
            .status()
            .expect("playpen")
            .success()
    );

    let ids = fx.run_ids();
    assert_eq!(ids[0], planted[1], "only the oldest piece of history went");
    assert!(
        ids[ids.len() - 1] > planted[planted.len() - 1],
        "the new run stays"
    );
    // The bound is on history; the run that was live while the ring was swept took no place in
    // it, which is what keeps a long session's own record (ADR 0028).
    assert_eq!(ids.len(), playpen::record::RETAINED + 1);
}

#[test]
fn a_request_for_help_opens_no_record() {
    let fx = Fixture::new();
    for args in [&["--help"][..], &["explain", "--help"], &["run", "--help"]] {
        let output = fx.playpen(args).output().expect("playpen");
        assert!(output.status.success(), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        assert!(!output.stderr.is_empty(), "help goes to stderr");
    }
    assert_eq!(fx.run_ids(), Vec::<String>::new());
}
