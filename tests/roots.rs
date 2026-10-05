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

/// A policy names a stable link; the mechanism enforces on the resolved path, so playpen grants
/// both ([spec §8.5]).
///
/// [spec §8.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#85-symlinks
#[test]
fn a_root_named_through_a_symlink_is_usable_from_inside() {
    let fx = Fixture::new();
    let target = TempDir::new().expect("target");
    let file = target.path().join("notes");
    std::fs::write(&file, "content").expect("seed");
    let links = TempDir::new().expect("links");
    let link = links.path().join("current");
    std::os::unix::fs::symlink(target.path(), &link).expect("symlink");
    let policy = fx.policy_named(
        "linked.json",
        &json!({
            "version": 1,
            "workspaces": {
                "code": {"roots": [{"path": fx.root(), "mode": "readwrite"}]},
                "notes": {"roots": [{"path": link, "mode": "read"}]},
            },
            "profiles": {"p": {"workspaces": ["code", "notes"], "toolchain": []}},
        }),
    );
    let through_link = link.join("notes");
    for path in [through_link.as_path(), file.as_path()] {
        let path = path.to_str().unwrap();
        assert_eq!(probe_outside(&["read", path])["ok"], true);
        assert_eq!(
            fx.probe_under(&policy, &["read", path])["ok"],
            true,
            "{path}"
        );
    }
}

#[test]
fn a_dangling_link_is_refused_naming_the_path() {
    let fx = Fixture::new();
    let links = TempDir::new().expect("links");
    let link = links.path().join("stale");
    std::os::unix::fs::symlink(links.path().join("gone"), &link).expect("symlink");
    let policy = fx.policy_named(
        "stale.json",
        &json!({
            "version": 1,
            "workspaces": {
                "code": {"roots": [{"path": fx.root(), "mode": "readwrite"}]},
                "stale": {"roots": [{"path": link, "mode": "read"}]},
            },
            "profiles": {"p": {"workspaces": ["code", "stale"], "toolchain": []}},
        }),
    );
    let output = fx
        .run_under(&policy, &[&os_bin("true")])
        .output()
        .expect("playpen");
    assert_refused(&output, "refusal.root.missing");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(link.to_str().unwrap()), "{stderr}");
}

/// A binary runs only where a grant covers it: the agent's own included ([spec §8.1], Appendix C
/// item C9).
///
/// [spec §8.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#81-shape
#[test]
fn a_binary_covered_by_a_toolchain_root_runs_and_an_uncovered_one_is_denied() {
    let fx = Fixture::new();
    let covered = TempDir::new().expect("toolchain");
    let uncovered = TempDir::new().expect("elsewhere");
    let (covered_bin, uncovered_bin) = (runnable(covered.path()), runnable(uncovered.path()));
    let policy = fx.policy_named(
        "toolchain.json",
        &json!({
            "version": 1,
            "workspaces": {"w": {"roots": [{"path": fx.root(), "mode": "readwrite"}]}},
            "profiles": {"p": {"workspaces": ["w"], "toolchain": [{"path": covered.path()}]}},
        }),
    );
    assert_eq!(fx.probe_under(&policy, &["exec", &covered_bin])["ok"], true);
    assert_denied(&fx.probe_under(&policy, &["exec", &uncovered_bin]));
    // Read and execute only.
    let planted = covered.path().join("planted");
    assert_denied(&fx.probe_under(&policy, &["write", planted.to_str().unwrap()]));
}

/// A policy granting the fixture's root read-write with `exclude` on it.
fn excluding(fx: &Fixture, exclude: Value) -> std::path::PathBuf {
    fx.policy_named(
        "excluding.json",
        &json!({
            "version": 1,
            "workspaces": {"w": {"roots": [
                {"path": fx.root(), "mode": "readwrite", "exclude": exclude},
            ]}},
            "profiles": {"p": {"workspaces": ["w"], "toolchain": []}},
        }),
    )
}

/// An excluded subpath is denied for its classes and still allowed for the others; omitting
/// `classes` subtracts all three ([spec §8.4]).
///
/// [spec §8.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#84-exclusions
#[test]
#[cfg(target_os = "macos")]
fn an_excluded_subpath_is_denied_for_its_classes_only() {
    let fx = Fixture::new();
    let (hooks, secrets) = (fx.root().join("hooks"), fx.root().join("secrets"));
    for dir in [&hooks, &secrets] {
        std::fs::create_dir(dir).expect("mkdir");
        std::fs::write(dir.join("file"), "content").expect("seed");
    }
    let binary = runnable(&secrets);
    let policy = excluding(
        &fx,
        json!([
            {"path": hooks, "classes": ["write"]},
            {"path": secrets},
        ]),
    );
    let path = |p: std::path::PathBuf| p.to_str().unwrap().to_owned();
    let (hooks_file, hooks_new) = (path(hooks.join("file")), path(hooks.join("new")));
    let (secrets_file, secrets_new) = (path(secrets.join("file")), path(secrets.join("new")));
    // Write alone is subtracted from `hooks`.
    assert_eq!(fx.probe_under(&policy, &["read", &hooks_file])["ok"], true);
    assert_denied(&fx.probe_under(&policy, &["write", &hooks_new]));
    // Everything is subtracted from `secrets`.
    assert_denied(&fx.probe_under(&policy, &["read", &secrets_file]));
    assert_denied(&fx.probe_under(&policy, &["write", &secrets_new]));
    assert_denied(&fx.probe_under(&policy, &["exec", &binary]));
    // The rest of the root is untouched.
    let beside = path(fx.root().join("beside"));
    assert_eq!(fx.probe_under(&policy, &["write", &beside])["ok"], true);
}

/// Landlock cannot subtract a subpath, so the launch refuses rather than grant it (#127).
#[test]
#[cfg(target_os = "linux")]
fn an_exclusion_refuses_on_linux() {
    let fx = Fixture::new();
    let secrets = fx.root().join("secrets");
    std::fs::create_dir(&secrets).expect("mkdir");
    let policy = excluding(&fx, json!([{"path": secrets}]));
    let output = fx
        .run_under(&policy, &[&os_bin("true")])
        .output()
        .expect("playpen");
    assert_refused(&output, "refusal.mechanism.unavailable");
}

#[test]
fn a_missing_exclusion_is_refused() {
    let fx = Fixture::new();
    let policy = excluding(&fx, json!([{"path": fx.root().join("gone")}]));
    let output = fx
        .run_under(&policy, &[&os_bin("true")])
        .output()
        .expect("playpen");
    assert_refused(&output, "refusal.exclusion.missing");
}

/// The playpen executable runs unconfined on the next launch, so a profile that can write it is
/// refused ([spec §11.7]).
///
/// [spec §11.7]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#117-self-integrity
#[test]
fn a_profile_that_can_write_the_playpen_executable_is_refused() {
    let fx = Fixture::new();
    let bin = std::path::Path::new(common::PLAYPEN)
        .parent()
        .expect("a directory");
    let policy = fx.policy_named(
        "writable-exe.json",
        &json!({
            "version": 1,
            "workspaces": {
                "w": {"roots": [{"path": fx.root(), "mode": "readwrite"}]},
                "bin": {"roots": [{"path": bin, "mode": "readwrite"}]},
            },
            "profiles": {"p": {"workspaces": ["w", "bin"], "toolchain": []}},
        }),
    );
    let output = fx
        .run_under(&policy, &[&os_bin("true")])
        .output()
        .expect("playpen");
    assert_refused(&output, "refusal.integrity.writable");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("playpen executable"), "{stderr}");
}

#[test]
fn a_profile_that_can_write_its_policy_is_refused_and_explain_says_so() {
    let fx = Fixture::new();
    let policy = fx.root().join("policy.json");
    std::fs::write(
        &policy,
        json!({
            "version": 1,
            "workspaces": {"w": {"roots": [{"path": fx.root(), "mode": "readwrite"}]}},
            "profiles": {"p": {"workspaces": ["w"], "toolchain": []}},
        })
        .to_string(),
    )
    .expect("policy");
    let output = fx
        .run_under(&policy, &[&os_bin("true")])
        .output()
        .expect("playpen");
    assert_refused(&output, "refusal.integrity.writable");
    let explained = fx
        .playpen(&["explain", "p", "--policy", policy.to_str().unwrap()])
        .output()
        .expect("playpen explain");
    assert_eq!(explained.status.code(), Some(125), "{explained:?}");
    assert!(
        String::from_utf8_lossy(&explained.stderr)
            .starts_with("playpen: refusal.integrity.writable: "),
        "{explained:?}"
    );
}

/// The agent binary is not checked: tampering with it lands inside the boundary on the next run.
#[test]
fn a_writable_agent_binary_is_not_refused() {
    let fx = Fixture::new();
    let agent = runnable(fx.root());
    let output = fx.run(&[&agent]).output().expect("playpen");
    assert!(output.status.success(), "{output:?}");
}
