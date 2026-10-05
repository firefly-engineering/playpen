//! The filesystem enforcement surface end to end ([spec §8]): brought roots, each asserted in two
//! parts — the condition holds outside, then the boundary's behaviour inside.
//!
//! [spec §8]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#8-enforcement-surface-filesystem

mod common;

use serde_json::{Value, json};
use tempfile::TempDir;

use common::{DENIAL_ERRNOS, Fixture, assert_refused, os_bin, probe_outside};

fn assert_denied(v: &Value) {
    assert_eq!(v["ok"], false, "{v}");
    assert_eq!(v["enoent"], false, "a denial never reads as absence: {v}");
    let errno = v["errno"].as_i64().expect("errno") as i32;
    assert!(DENIAL_ERRNOS.contains(&errno), "errno {errno}: {v}");
}

/// A copy of `true` in `dir`, runnable outside.
fn runnable(dir: &std::path::Path) -> String {
    let copy = dir.join("true");
    std::fs::copy(os_bin("true"), &copy).expect("copy true");
    let copy = copy.to_str().expect("a UTF-8 path").to_owned();
    assert_eq!(
        probe_outside(&["exec", &copy])["ok"],
        true,
        "runnable outside"
    );
    copy
}

/// `read` grants read and execute, never write ([spec §5.2]).
///
/// [spec §5.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#52-brought-roots
#[test]
fn a_read_root_is_readable_and_executable_but_not_writable() {
    let fx = Fixture::with_mode("read");
    let file = fx.root().join("existing");
    std::fs::write(&file, "content").expect("seed");
    let binary = runnable(fx.root());
    let created = fx.root().join("created");
    let created = created.to_str().unwrap();
    assert_eq!(
        probe_outside(&["write", created])["ok"],
        true,
        "writable outside"
    );
    std::fs::remove_file(created).expect("reset");

    assert_eq!(
        fx.probe_inside(&["read", file.to_str().unwrap()])["ok"],
        true
    );
    assert_eq!(fx.probe_inside(&["exec", &binary])["ok"], true);
    assert_denied(&fx.probe_inside(&["write", created]));
}

#[test]
fn a_readwrite_root_is_writable() {
    let fx = Fixture::with_mode("readwrite");
    let created = fx.root().join("created");
    assert_eq!(
        fx.probe_inside(&["write", created.to_str().unwrap()])["ok"],
        true
    );
}

/// Brought roots union across a profile's workspaces ([spec §5.5]).
///
/// [spec §5.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#55-profile
#[test]
fn roots_from_every_workspace_of_a_profile_are_unioned() {
    let fx = Fixture::new();
    let second = TempDir::new().expect("second root");
    let file = second.path().join("notes");
    std::fs::write(&file, "content").expect("seed");
    let file = file.to_str().unwrap();
    let alone = fx.policy_named(
        "alone.json",
        &json!({
            "version": 1,
            "workspaces": {"code": {"roots": [{"path": fx.root(), "mode": "readwrite"}]}},
            "profiles": {"p": {"workspaces": ["code"], "toolchain": []}},
        }),
    );
    // The file is outside the first workspace: the second's grant is what reaches it.
    assert_denied(&fx.probe_under(&alone, &["read", file]));

    let both = fx.policy_named(
        "both.json",
        &json!({
            "version": 1,
            "workspaces": {
                "code": {"roots": [{"path": fx.root(), "mode": "readwrite"}]},
                "notes": {"roots": [{"path": second.path(), "mode": "read"}]},
            },
            "profiles": {"p": {"workspaces": ["code", "notes"], "toolchain": []}},
        }),
    );
    assert_eq!(fx.probe_under(&both, &["read", file])["ok"], true);
}

#[test]
fn a_missing_root_is_refused() {
    let fx = Fixture::new();
    let policy = fx.policy_named(
        "missing.json",
        &json!({
            "version": 1,
            "workspaces": {"w": {"roots": [{"path": fx.root().join("gone"), "mode": "read"}]}},
            "profiles": {"p": {"workspaces": ["w"], "toolchain": []}},
        }),
    );
    let output = fx
        .run_under(&policy, &[&os_bin("true")])
        .output()
        .expect("playpen");
    assert_refused(&output, "refusal.root.missing");
}
