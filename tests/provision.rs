//! What playpen provisions for a run, end to end: the run scratch ([spec §5.7]) and the provisioned
//! areas ([spec §5.4]).
//!
//! [spec §5.7]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#57-run-scratch
//! [spec §5.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#54-provisioned-areas

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

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
    // The scratch holds the run's manifest, which every run is written ([spec §13.1]), and
    // nothing else of anyone's.
    //
    // [spec §13.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#131-form
    assert_eq!(
        first[1..],
        ["manifest.json", "written"],
        "the scratch starts with the manifest alone: {first:?}"
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

/// A policy whose profile `p` has the fixture's root, in workspace `w` with areas `areas`.
fn with_areas(fx: &Fixture, areas: Value) -> PathBuf {
    fx.policy_named(
        "areas.json",
        &json!({
            "version": 1,
            "workspaces": {"w": {"roots": [{"path": fx.root(), "mode": "readwrite"}], "areas": areas}},
            "profiles": {"p": {"workspaces": ["w"], "toolchain": []}},
        }),
    )
}

/// Launch `script` under `sh`, confined by `policy`, with its stdin a pipe.
fn spawn(fx: &Fixture, policy: &Path, script: &str) -> Child {
    fx.run_under(policy, &[&os_bin("sh"), "-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("playpen")
}

/// The record of the one run `fx` has that is not in `before`, once it holds its capability set:
/// the run is about to fork, or has.
fn launched(fx: &Fixture, before: &[String]) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let new: Vec<_> = fx
            .run_ids()
            .into_iter()
            .filter(|id| !before.contains(id))
            .collect();
        if let [id] = new.as_slice()
            && let Ok(bytes) = std::fs::read(fx.runs().join(format!("{id}.json")))
            && let Ok(record) = serde_json::from_slice::<Value>(&bytes)
            && !record["capabilities"].is_null()
        {
            return record;
        }
        assert!(Instant::now() < deadline, "the run never launched");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The path of the grant from `from` in a run's `record`.
fn granted(record: &Value, from: &str) -> PathBuf {
    let grant = record["capabilities"]["paths"]
        .as_array()
        .expect("paths")
        .iter()
        .find(|grant| grant["from"] == from)
        .unwrap_or_else(|| panic!("no grant from {from} in {record}"));
    PathBuf::from(grant["path"].as_str().expect("a path"))
}

/// Run `script`, which reads one line, confined by `policy`; once the run has launched, write it
/// the path of the area granted from `from`. Returns that path and the run's output.
fn with_area_on_stdin(fx: &Fixture, policy: &Path, from: &str, script: &str) -> (PathBuf, Output) {
    let before = fx.run_ids();
    let mut child = spawn(fx, policy, script);
    let area = granted(&launched(fx, &before), from);
    let mut stdin = child.stdin.take().expect("stdin");
    writeln!(stdin, "{}", area.display()).expect("hand the child its area");
    drop(stdin);
    (area, child.wait_with_output().expect("playpen"))
}

/// The script that writes into the area named on its stdin, and says so.
const WRITE_AREA: &str = r#"read area; echo x > "$area/f" && echo written"#;

#[test]
fn an_ephemeral_area_is_writable_for_the_run_at_a_real_path_and_removed_at_teardown() {
    let fx = Fixture::new();
    let policy = with_areas(&fx, json!({"target": {"lifetime": "ephemeral"}}));
    let (area, output) = with_area_on_stdin(&fx, &policy, "workspace:w.areas.target", WRITE_AREA);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "written\n");
    assert!(
        area.starts_with(fx.state_home().canonicalize().expect("state")),
        "the area is a real path under playpen's state: {area:?}"
    );
    assert!(!area.exists(), "the area outlived its run");
}

#[test]
fn a_persistent_area_survives_across_runs() {
    let fx = Fixture::new();
    let policy = with_areas(&fx, json!({"landing": {"lifetime": "persistent"}}));
    let from = "workspace:w.areas.landing";
    let (area, output) = with_area_on_stdin(&fx, &policy, from, WRITE_AREA);
    assert!(output.status.success(), "{output:?}");
    assert!(area.join("f").exists(), "the area did not survive its run");
    let (again, output) = with_area_on_stdin(&fx, &policy, from, r#"read area; cat "$area/f""#);
    assert_eq!(again, area);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "x\n", "{output:?}");
}

/// Hold an `exclusive` area in a run that waits on its stdin; returns the run and its id.
fn hold(fx: &Fixture, policy: &Path) -> (Child, String) {
    let before = fx.run_ids();
    // `read` fails at end of file, which is how the test lets it go.
    let child = spawn(fx, policy, "read _ || :");
    let record = launched(fx, &before);
    (child, record["run"].as_str().expect("a run id").to_owned())
}

#[test]
fn a_held_exclusive_area_refuses_naming_the_holder_and_releases_when_the_supervisor_dies() {
    let fx = Fixture::new();
    // `exclusive` is the default.
    let policy = with_areas(&fx, json!({"landing": {"lifetime": "persistent"}}));
    let (mut holder, id) = hold(&fx, &policy);
    let output = fx
        .run_under(&policy, &[&os_bin("true")])
        .output()
        .expect("playpen");
    common::assert_refused(&output, "refusal.area.busy");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(&format!("held by run {id}")), "{stderr}");

    // The supervisor dies with no chance to clean up; the kernel releases its lock.
    holder.kill().expect("SIGKILL the supervisor");
    holder.wait().expect("reap it");
    // Closing its stdin ends the agent, which on macOS outlives its supervisor (ADR 0025).
    drop(holder.stdin.take());
    let output = fx
        .run_under(&policy, &[&os_bin("true")])
        .output()
        .expect("playpen");
    assert!(
        output.status.success(),
        "the lock outlived its supervisor: {output:?}"
    );
}

#[test]
fn two_runs_share_a_shared_area_concurrently() {
    let fx = Fixture::new();
    let policy = with_areas(
        &fx,
        json!({"cache": {"lifetime": "persistent", "concurrency": "shared"}}),
    );
    let (mut first, _) = hold(&fx, &policy);
    let (area, output) = with_area_on_stdin(&fx, &policy, "workspace:w.areas.cache", WRITE_AREA);
    assert!(output.status.success(), "{output:?}");
    assert!(area.join("f").exists());
    drop(first.stdin.take());
    assert!(first.wait().expect("first run").success());
}

/// A policy whose profile `p` has workspace `w` with areas `areas`, and the `set:` table `set`.
fn with_areas_and_set(fx: &Fixture, areas: Value, set: Value) -> PathBuf {
    fx.policy_named(
        "set.json",
        &json!({
            "version": 1,
            "workspaces": {"w": {"roots": [{"path": fx.root(), "mode": "readwrite"}], "areas": areas}},
            "profiles": {"p": {"workspaces": ["w"], "toolchain": [], "env": {"set": set}}},
        }),
    )
}

#[test]
fn an_area_reference_gives_the_child_the_areas_path() {
    let fx = Fixture::new();
    // JSON has no tags, so the reference is the one-key mapping `!area` stands for.
    let policy = with_areas_and_set(
        &fx,
        json!({"target": {"lifetime": "ephemeral"}}),
        json!({"CARGO_TARGET_DIR": {"area": "w/target"}}),
    );
    let before = fx.run_ids();
    let output = fx
        .run_under(
            &policy,
            &[
                &os_bin("sh"),
                "-c",
                r#"echo "$CARGO_TARGET_DIR"; echo x > "$CARGO_TARGET_DIR/f" && echo written"#,
            ],
        )
        .output()
        .expect("playpen");
    assert!(output.status.success(), "{output:?}");
    let record = launched(&fx, &before);
    let area = granted(&record, "workspace:w.areas.target");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("{}\nwritten\n", area.display())
    );
}

#[test]
fn a_dangling_area_reference_is_refused() {
    let fx = Fixture::new();
    let policy = with_areas_and_set(
        &fx,
        json!({"target": {"lifetime": "ephemeral"}}),
        json!({"X": {"area": "w/nope"}}),
    );
    let output = fx
        .run_under(&policy, &[&os_bin("true")])
        .output()
        .expect("playpen");
    common::assert_refused(&output, "refusal.area.unknown");
}
