//! The run record ([spec §14.1]) end to end: opened before anything else, completed on a
//! successful launch, holding the code of a refusal, and out of reach from inside the boundary.
//!
//! [spec §14.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#141-the-run-record

mod common;

use serde_json::Value;
use tempfile::TempDir;

use common::{Fixture, assert_refused, os_bin, probe_outside};

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
        .run(&[&os_bin("sh"), "-c", "echo $$; exit 3"])
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
    // `run` names its profile, so the chain is its explicit step alone.
    assert_eq!(
        record["selection"],
        serde_json::json!([{"step": "explicit", "outcome": "selected", "profile": "p"}])
    );
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
    let status = fx.run(&[&os_bin("true")]).status().expect("playpen");
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
        .run(&[&os_bin("true")])
        .env("XDG_STATE_HOME", &file)
        .output()
        .expect("playpen");
    assert_refused(&output, "refusal.state.io");
}

#[test]
fn no_state_directory_at_all_refuses_with_state_io() {
    let fx = Fixture::new();
    let output = fx
        .run(&[&os_bin("true")])
        .env_remove("XDG_STATE_HOME")
        .env_remove("HOME")
        .output()
        .expect("playpen");
    assert_refused(&output, "refusal.state.io");
}

/// A brought root that is an ancestor of playpen's state directory refuses, naming both paths
/// ([ADR 0027]). Before this, the launch went ahead silently and every run record was readable
/// from inside the boundary — and forgeable, since this fixture's root is `readwrite`.
///
/// The state directory is synthetic, as every row's is: the check compares resolved paths and does
/// not care whose home it is, so pointing it at the real `$HOME` would buy no realism and risk
/// what [#118](https://github.com/firefly-engineering/playpen/issues/118) reports.
///
/// The enforcement suite's `R-state-reachable` row asserts the same refusal against the suite's
/// own contract — exit `125`, the code, and a record. This one is here for the half that row does
/// not cover: that the line **names both paths**, which is the acceptance criterion the operator
/// actually depends on to find the offending grant.
///
/// [ADR 0027]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0027-the-state-directory-is-unreachable-by-refusal-because-a-carve-out-is-not-portable.md
#[test]
fn a_root_above_the_state_directory_refuses_naming_both_paths() {
    let fx = Fixture::new();
    // Inside the brought root, which is the breach: an `XDG_STATE_HOME` under a granted path.
    let inside = fx.root().join("state");
    let output = fx
        .run(&[&os_bin("true")])
        .env("XDG_STATE_HOME", &inside)
        .output()
        .expect("playpen");

    assert_refused(&output, "refusal.state.reachable");
    let said = String::from_utf8_lossy(&output.stderr).to_string();
    let root = fx.root().canonicalize().expect("root");
    assert!(
        said.contains(&root.display().to_string()),
        "the line names the offending grant: {said}"
    );
    assert!(
        said.contains(&inside.join("playpen").display().to_string()),
        "and the state directory it reaches: {said}"
    );
    // The refusal still leaves a record, like every other refusal class ([spec §14.1]): the
    // record opens before the check, which needs the resolved profile's grants, and no agent is
    // ever forked on this path so the window has no reader. Its sidecar went with the run.
    let left: Vec<_> = std::fs::read_dir(inside.join("playpen/runs"))
        .expect("the state directory the run was refused about")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert_eq!(
        left.len(),
        1,
        "the refusing run left its own record, and its sidecar went with it: {left:?}"
    );
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
        .args(["--", &os_bin("true")])
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

/// The run that refuses is the one whose record is most wanted, so its trace is kept too.
#[test]
fn a_refused_selection_records_its_trace() {
    let fx = Fixture::new();
    let output = fx
        .playpen(&["run", "--profile", "nope", "--agent", "claude", "--policy"])
        .arg(&fx.policy)
        .args(["--", "true"])
        .output()
        .expect("playpen");
    assert_refused(&output, "refusal.selection.unknown-profile");
    let record = the_only_record(&fx);
    assert_eq!(record["profile"], Value::Null);
    assert_eq!(
        record["selection"],
        serde_json::json!([{
            "step": "explicit",
            "outcome": "refused",
            "code": "refusal.selection.unknown-profile",
        }])
    );
}
