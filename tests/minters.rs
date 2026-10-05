//! Minters end to end ([spec §7.2]): what a declared minter is handed, what a launch does with
//! what it returns, and what the run record holds afterwards.
//!
//! [spec §7.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#72-minters

mod common;

use std::path::PathBuf;

use serde_json::{Value, json};

use common::{Fixture, assert_refused, os_bin};

/// A policy with one profile route through a minter that is `script`.
fn with_minter(fx: &Fixture, name: &str, script: &str, timeout: Option<u64>) -> PathBuf {
    let mut minter = json!({"command": [os_bin("sh"), "-c", script]});
    if let Some(timeout) = timeout {
        minter["timeout"] = timeout.into();
    }
    fx.policy_named(
        "minters.json",
        &json!({
            "version": 1,
            "minters": {name: minter},
            "workspaces": {"w": {"roots": [{"path": fx.root(), "mode": "readwrite"}]}},
            "profiles": {"p": {
                "workspaces": ["w"],
                "toolchain": [],
                "credentials": [{
                    "host": "api.anthropic.com",
                    "path_prefix": "/",
                    "minter": name,
                    "delivery": {"env": "CLAUDE_CODE_OAUTH_TOKEN"},
                }],
            }},
        }),
    )
}

/// A minter that answers with a fixed token and expiry, and copies its stdin into the fixture's
/// root so the test can read what the contract put there.
fn echoes_stdin(fx: &Fixture) -> String {
    format!(
        r#"cat > {}/minter-stdin.json; printf '{{"token":"s3cret-not-in-the-record","expires_at":"2027-01-01T00:00:00Z"}}'"#,
        fx.root().display()
    )
}

/// The minter is handed the versioned request on stdin, with `scope: null` for a profile route;
/// the run record holds `expires_at` and never the token.
#[test]
fn a_profile_route_is_minted_before_the_launch_and_recorded_without_its_token() {
    let fx = Fixture::new();
    let policy = with_minter(&fx, "anthropic", &echoes_stdin(&fx), None);
    let output = fx
        .run_under(&policy, &[&os_bin("true")])
        .output()
        .expect("playpen");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // What the contract put on stdin.
    let request: Value =
        serde_json::from_slice(&std::fs::read(fx.root().join("minter-stdin.json")).expect("stdin"))
            .expect("the request is JSON");
    assert_eq!(
        request,
        json!({
            "version": 1,
            "route": {"host": "api.anthropic.com", "path_prefix": "/"},
            "scope": null,
        })
    );
    // What the record holds, and what it does not.
    let ids = fx.run_ids();
    assert_eq!(ids.len(), 1, "{ids:?}");
    let record = fx.record(&ids[0]);
    assert_eq!(
        record["credentials"],
        json!([{
            "host": "api.anthropic.com",
            "path_prefix": "/",
            "minter": "anthropic",
            "expires_at": "2027-01-01T00:00:00Z",
            "from": "profile:p.credentials[0]",
        }])
    );
    assert!(
        !record.to_string().contains("s3cret-not-in-the-record"),
        "the record holds the token: {record}"
    );
}

/// A route naming a minter the policy does not declare is a coherence refusal, so `check` makes
/// it without looking at this host.
#[test]
fn a_route_naming_an_undeclared_minter_refuses() {
    let fx = Fixture::new();
    let policy = fx.policy_named(
        "undeclared.json",
        &json!({
            "version": 1,
            "workspaces": {"w": {"roots": [{"path": fx.root(), "mode": "readwrite"}]}},
            "profiles": {"p": {
                "workspaces": ["w"],
                "toolchain": [],
                "credentials": [{
                    "host": "api.anthropic.com",
                    "path_prefix": "/",
                    "minter": "nope",
                    "delivery": {"env": "CLAUDE_CODE_OAUTH_TOKEN"},
                }],
            }},
        }),
    );
    let output = fx
        .run_under(&policy, &[&os_bin("true")])
        .output()
        .expect("playpen");
    let run = assert_refused(&output, "refusal.minter.unknown");
    let message = fx.record(&run)["refusal"]["message"]
        .as_str()
        .expect("a message")
        .to_owned();
    assert!(
        message.contains("profile:p.credentials[0].minter"),
        "{message}"
    );
    assert!(message.contains("declared minters: none"), "{message}");
    let output = fx
        .playpen(&[
            "check",
            "--no-filesystem",
            "--policy",
            policy.to_str().expect("a UTF-8 path"),
        ])
        .output()
        .expect("playpen check");
    assert_eq!(output.status.code(), Some(125), "{output:?}");
}

/// Each way a minter can fail has its own code, and the agent never runs: launching without the
/// credential would produce a run that works for ten minutes and then fails at the first push.
#[test]
fn a_minter_that_fails_refuses_the_whole_run() {
    for (script, timeout, code) in [
        ("cat >/dev/null; exit 7", None, "refusal.minter.failed"),
        (
            "cat >/dev/null; echo nonsense",
            None,
            "refusal.minter.malformed",
        ),
        (
            "cat >/dev/null; sleep 60",
            Some(1),
            "refusal.minter.timeout",
        ),
    ] {
        let fx = Fixture::new();
        let policy = with_minter(&fx, "anthropic", script, timeout);
        // A target that would leave a trace if it ran at all.
        let witness = fx.root().join("the-agent-ran");
        let output = fx
            .run_under(
                &policy,
                &[
                    &os_bin("sh"),
                    "-c",
                    &format!("echo ran > {}", witness.display()),
                ],
            )
            .output()
            .expect("playpen");
        let run = assert_refused(&output, code);
        assert!(!witness.exists(), "{script}: the agent ran anyway");
        let message = fx.record(&run)["refusal"]["message"]
            .as_str()
            .expect("a message")
            .to_owned();
        assert!(message.contains("\"anthropic\""), "{script}: {message}");
    }
}

/// No credential route means no minter runs at all, and the record holds none.
#[test]
fn a_profile_with_no_route_mints_nothing() {
    let fx = Fixture::new();
    let output = fx.run(&[&os_bin("true")]).output().expect("playpen");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let ids = fx.run_ids();
    assert_eq!(fx.record(&ids[0])["credentials"], json!([]));
}
