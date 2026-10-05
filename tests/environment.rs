//! The constructed environment end to end ([spec §9]): what the confined child's `environ` holds,
//! and what `explain` says it holds.
//!
//! [spec §9]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#9-the-environment

mod common;

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Value, json};

use common::{Fixture, assert_refused, os_bin};

/// A policy whose profile `p` has the fixture's root and the env table `env`.
fn with_env(fx: &Fixture, env: Value) -> std::path::PathBuf {
    fx.policy_named(
        "env.json",
        &json!({
            "version": 1,
            "fragments": {"env": {"rust": ["CARGO_HOME", "RUSTUP_HOME"]}},
            "workspaces": {"w": {"roots": [{"path": fx.root(), "mode": "readwrite"}]}},
            "profiles": {"p": {"workspaces": ["w"], "toolchain": [], "env": env}},
        }),
    )
}

/// The confined child's environment, as `env` prints it.
fn environ(fx: &Fixture, policy: &Path, host: &[(&str, &str)]) -> BTreeMap<String, String> {
    let mut command = fx.run_under(policy, &[&os_bin("env")]);
    command.envs(host.iter().copied());
    let output = command.output().expect("playpen");
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout)
        .expect("utf-8")
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

#[test]
fn nothing_reaches_the_child_that_playpen_did_not_put_there() {
    let fx = Fixture::new();
    let policy = with_env(&fx, json!({}));
    let env = environ(
        &fx,
        &policy,
        &[("PLAYPEN_TEST_SECRET", "decoy"), ("TERM", "xterm")],
    );
    // The test process carries cargo's variables and the decoy; the child carries the floor.
    assert!(std::env::var_os("CARGO_PKG_NAME").is_some(), "cargo set it");
    assert!(!env.contains_key("CARGO_PKG_NAME"), "{env:?}");
    assert!(!env.contains_key("PLAYPEN_TEST_SECRET"), "{env:?}");
    assert_eq!(env.get("TERM").map(String::as_str), Some("xterm"));
    let allowed: Vec<_> = env
        .keys()
        .filter(|name| !playpen::environment::FLOOR.contains(&name.as_str()))
        .filter(|name| !name.starts_with("PLAYPEN_") && *name != "TMPDIR")
        .collect();
    assert!(allowed.is_empty(), "beyond the floor: {allowed:?}");
}

#[test]
fn home_and_path_pass_through_unrewritten() {
    let fx = Fixture::new();
    let policy = with_env(&fx, json!({}));
    let env = environ(
        &fx,
        &policy,
        &[("HOME", "/nonexistent/home"), ("PATH", "/a:/b")],
    );
    assert_eq!(env["HOME"], "/nonexistent/home");
    assert_eq!(env["PATH"], "/a:/b");
}

#[test]
fn allowed_and_fragment_names_pass_through_and_set_values_win_over_the_floor() {
    let fx = Fixture::new();
    let policy = with_env(
        &fx,
        json!({
            "allow": ["COLORTERM"],
            "fragments": ["rust"],
            "set": {"TERM": "dumb", "GIT_AUTHOR_NAME": "playpen agent"},
        }),
    );
    let env = environ(
        &fx,
        &policy,
        &[
            ("COLORTERM", "truecolor"),
            ("CARGO_HOME", "/c"),
            ("TERM", "xterm"),
        ],
    );
    assert_eq!(env["COLORTERM"], "truecolor");
    assert_eq!(env["CARGO_HOME"], "/c");
    assert!(!env.contains_key("RUSTUP_HOME"), "absent on the host");
    assert_eq!(env["TERM"], "dumb");
    assert_eq!(env["GIT_AUTHOR_NAME"], "playpen agent");
}

#[test]
fn an_unknown_env_fragment_is_refused() {
    let fx = Fixture::new();
    let policy = with_env(&fx, json!({"fragments": ["nope"]}));
    let output = fx
        .run_under(&policy, &[&os_bin("true")])
        .output()
        .expect("playpen");
    assert_refused(&output, "refusal.fragment.unknown");
    let output = fx
        .playpen(&[
            "check",
            "--no-filesystem",
            "--policy",
            policy.to_str().unwrap(),
        ])
        .output()
        .expect("playpen check");
    assert_eq!(output.status.code(), Some(125), "{output:?}");
}

#[test]
fn explain_shows_the_constructed_environment_with_its_provenance() {
    let fx = Fixture::new();
    let policy = with_env(
        &fx,
        json!({"fragments": ["rust"], "set": {"GIT_AUTHOR_NAME": "agent"}}),
    );
    let output = fx
        .playpen(&[
            "explain",
            "p",
            "--json",
            "--policy",
            policy.to_str().unwrap(),
        ])
        .env("CARGO_HOME", "/c")
        .env("HOME", "/home/u")
        .output()
        .expect("playpen explain");
    assert!(output.status.success(), "{output:?}");
    let resolved: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let var = |name: &str| {
        resolved["env"]
            .as_array()
            .expect("env")
            .iter()
            .find(|var| var["name"] == name)
            .unwrap_or_else(|| panic!("{name} is not in {resolved}"))
            .clone()
    };
    assert_eq!(
        var("CARGO_HOME"),
        json!({"name": "CARGO_HOME", "value": null, "from": "fragment:rust"})
    );
    assert_eq!(var("HOME")["from"], "floor");
    assert_eq!(
        var("GIT_AUTHOR_NAME"),
        json!({"name": "GIT_AUTHOR_NAME", "value": "agent", "from": "profile:p.env.set.GIT_AUTHOR_NAME"})
    );
}
