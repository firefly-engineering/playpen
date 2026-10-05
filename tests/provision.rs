//! What playpen provisions for a run, end to end: the run scratch ([spec §5.7]).
//!
//! [spec §5.7]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#57-run-scratch

mod common;

use std::path::PathBuf;

use serde_json::Value;

use common::{Fixture, os_bin};

/// Run `script` under `sh` confined, and return its stdout lines; it must exit 0.
fn sh(fx: &Fixture, script: &str) -> Vec<String> {
    let output = fx
        .run(&[&os_bin("sh"), "-c", script])
        .output()
        .expect("playpen");
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout)
        .expect("utf-8")
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn each_run_gets_a_fresh_writable_scratch_as_tmpdir_removed_at_teardown() {
    let fx = Fixture::new();
    let script = r#"echo "$TMPDIR"; ls -A "$TMPDIR"; echo x > "$TMPDIR/f" && echo written"#;
    let first = sh(&fx, script);
    assert_eq!(
        first[1..],
        ["written"],
        "the scratch starts empty: {first:?}"
    );
    let scratch = PathBuf::from(&first[0]);
    assert!(
        scratch.starts_with(fx.state_home().canonicalize().expect("state")),
        "the scratch is playpen's state: {scratch:?}"
    );
    assert!(!scratch.exists(), "the scratch outlived its run");
    let second = sh(&fx, script);
    assert_ne!(second[0], first[0], "a scratch belongs to one run");
}

#[test]
fn playpen_active_carries_the_profile_name() {
    let fx = Fixture::new();
    assert_eq!(sh(&fx, r#"echo "$PLAYPEN_ACTIVE""#), ["p"]);
}

#[test]
fn explain_states_the_run_scratch() {
    let fx = Fixture::new();
    let output = fx
        .playpen(&["explain", "p", "--json", "--policy"])
        .arg(&fx.policy)
        .output()
        .expect("playpen explain");
    assert!(output.status.success(), "{output:?}");
    let resolved: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let scratch = resolved["paths"]
        .as_array()
        .expect("paths")
        .iter()
        .find(|path| path["from"] == "run-scratch")
        .unwrap_or_else(|| panic!("no run scratch in {resolved}"));
    assert_eq!(scratch["access"], "readwrite");
    let tmpdir = resolved["env"]
        .as_array()
        .expect("env")
        .iter()
        .find(|var| var["name"] == "TMPDIR")
        .unwrap_or_else(|| panic!("no TMPDIR in {resolved}"));
    assert_eq!(tmpdir["value"], scratch["path"]);
    assert_eq!(tmpdir["from"], "run-scratch");
}
