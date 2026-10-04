//! The run record ([spec §14.1]) end to end: opened before anything else, completed on a
//! successful launch, holding the code of a refusal, and out of reach from inside the boundary.
//!
//! [spec §14.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#141-the-run-record

mod common;

use serde_json::Value;
use tempfile::TempDir;

use common::{Fixture, assert_refused, probe_outside};

fn the_only_record(fx: &Fixture) -> Value {
    let ids = fx.run_ids();
    assert_eq!(ids.len(), 1, "{ids:?}");
    fx.record(&ids[0])
}

#[test]
fn a_successful_run_records_policy_profile_capabilities_pid_and_timestamps() {
    let fx = Fixture::new();
    // `exec` keeps the pid, so the shell's `$$` is the confined child's pid.
    let output = fx
        .run(&["/bin/sh", "-c", "echo $$; exit 3"])
        .output()
        .expect("playpen");
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let pid: i64 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("the child's pid");

    let record = the_only_record(&fx);
    assert_eq!(record["format"], 1);
    assert_eq!(record["policy"], fx.policy.to_str().unwrap());
    assert_eq!(record["profile"], "p");
    assert_eq!(record["kind"], "claude");
    assert_eq!(record["pid"], pid);
    assert_eq!(record["status"], 3);
    assert_eq!(record["refusal"], Value::Null);
    let root = fx.root().canonicalize().expect("root");
    let grants = record["capabilities"]["paths"].as_array().expect("paths");
    assert!(
        grants
            .iter()
            .any(|grant| grant["path"] == root.to_str().unwrap()
                && grant["access"] == "readwrite"
                && grant["from"] == "workspace:w.roots[0]"),
        "the brought root is recorded with its provenance: {grants:?}"
    );
    let at = |name: &str| record[name].as_u64().unwrap_or_else(|| panic!("{name}"));
    assert!(at("started_at_unix_ms") <= at("launched_at_unix_ms"));
    assert!(at("launched_at_unix_ms") <= at("ended_at_unix_ms"));
}

#[test]
fn the_record_directory_is_denied_from_inside_the_boundary() {
    let fx = Fixture::new();
    let status = fx.run(&["/usr/bin/true"]).status().expect("playpen");
    assert!(status.success());
    let ids = fx.run_ids();
    let earlier = fx.runs().join(format!("{}.json", ids[0]));
    let earlier = earlier.to_str().unwrap();
    let planted = fx.runs().join("planted.json");
    let planted = planted.to_str().unwrap();

    assert_eq!(
        probe_outside(&["read", earlier])["ok"],
        true,
        "readable outside"
    );
    let read = fx.probe_inside(&["read", earlier]);
    assert_eq!(read["ok"], false, "{read}");
    assert_eq!(read["enoent"], false, "a denial, not absence: {read}");
    let write = fx.probe_inside(&["write", planted]);
    assert_eq!(write["ok"], false, "{write}");
    assert!(!fx.runs().join("planted.json").exists());
}

#[test]
fn a_state_directory_that_cannot_be_created_refuses_with_state_io() {
    let fx = Fixture::new();
    let blocker = TempDir::new().expect("blocker");
    let file = blocker.path().join("a-file");
    std::fs::write(&file, "").expect("a file where the state directory goes");
    let output = fx
        .run(&["/usr/bin/true"])
        .env("XDG_STATE_HOME", &file)
        .output()
        .expect("playpen");
    assert_refused(&output, "refusal.state.io");
}

#[test]
fn no_state_directory_at_all_refuses_with_state_io() {
    let fx = Fixture::new();
    let output = fx
        .run(&["/usr/bin/true"])
        .env_remove("XDG_STATE_HOME")
        .env_remove("HOME")
        .output()
        .expect("playpen");
    assert_refused(&output, "refusal.state.io");
}

#[test]
fn a_relative_policy_path_is_recorded_absolute() {
    let fx = Fixture::new();
    // Both temporary directories share a parent, so the policy is one step up and across.
    assert_eq!(fx.root().parent(), fx.policy_dir.path().parent());
    let relative = std::path::Path::new("..")
        .join(fx.policy_dir.path().file_name().expect("name"))
        .join("policy.json");
    let output = fx
        .playpen(&["run", "--profile", "p", "--agent", "claude", "--policy"])
        .arg(&relative)
        .args(["--", "/usr/bin/true"])
        .output()
        .expect("playpen");
    assert!(output.status.success(), "{output:?}");
    let recorded = the_only_record(&fx)["policy"].clone();
    let recorded = std::path::Path::new(recorded.as_str().expect("a path"));
    assert!(recorded.is_absolute(), "{recorded:?}");
    assert_eq!(
        recorded.canonicalize().expect("names the file"),
        fx.policy.canonicalize().expect("policy")
    );
}
