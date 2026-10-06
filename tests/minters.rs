//! Minters end to end ([spec §7.2]): what a declared minter is handed, what a launch does with
//! what it returns, and what the run record holds afterwards.
//!
//! [spec §7.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#72-minters

mod common;

use std::path::PathBuf;

use serde_json::{Value, json};

use common::{Fixture, assert_refused, os_bin};

/// Two seconds from now as an RFC 3339 timestamp, in whichever `date` the runner has: GNU takes
/// `-d`, BSD — which is macOS's — takes `-v`. A near expiry has to be computed rather than
/// written, because renewal is due after a fraction of the credential's **own** life, so a
/// literal timestamp years away would never come due inside a test.
const SOON: &str = "TZ=UTC date -u -d '+2 seconds' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
                    || date -u -v+2S '+%Y-%m-%dT%H:%M:%SZ'";

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

/// Two routes a run would resolve on one host, whose prefixes are not ordered by strict extension,
/// are a coherence refusal: `path_prefix` selects the credential, and an unordered pair is a tie
/// the proxy would break silently ([spec §7.1]). Like every coherence rule, `check` makes it without
/// looking at this host, and no minter runs.
#[test]
fn two_routes_on_one_host_that_are_not_ordered_by_prefix_refuse() {
    let fx = Fixture::new();
    // A minter that would leave a trace if it ran at all.
    let witness = fx.root().join("minted");
    let policy = fx.policy_named(
        "ambiguous.json",
        &json!({
            "version": 1,
            "minters": {"m": {"command": [
                os_bin("sh"), "-c",
                format!("cat >/dev/null; echo ran > {}", witness.display()),
            ]}},
            "workspaces": {
                "a": {
                    "roots": [],
                    "credentials": [{
                        "host": "api.example",
                        "path_prefix": "/repos/a/",
                        "minter": "m",
                        "delivery": {"env": "A_TOKEN"},
                    }],
                },
                "b": {
                    "roots": [],
                    "credentials": [{
                        "host": "api.example",
                        "path_prefix": "/repos/b/",
                        "minter": "m",
                        "delivery": {"env": "B_TOKEN"},
                    }],
                },
            },
            "profiles": {"p": {
                "workspaces": ["a", "b"],
                "toolchain": [],
            }},
        }),
    );
    let output = fx
        .run_under(&policy, &[&os_bin("true")])
        .output()
        .expect("playpen");
    let run = assert_refused(&output, "refusal.route.ambiguous");
    let message = fx.record(&run)["refusal"]["message"]
        .as_str()
        .expect("a message")
        .to_owned();
    assert!(message.contains("\"api.example\""), "{message}");
    assert!(message.contains("workspace:a.credentials[0]"), "{message}");
    assert!(message.contains("workspace:b.credentials[0]"), "{message}");
    assert!(!witness.exists(), "a minter ran for a refused policy");
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

/// A workspace route's minter receives that workspace's own forge scope, and a profile with two
/// workspaces mints each of them with its own: forge scope is never unioned across a profile's
/// workspaces ([spec §7.4]). Both kinds of route resolve into one table.
///
/// [spec §7.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#74-attachment
#[test]
fn each_workspace_route_is_minted_with_its_own_forge_scope() {
    let fx = Fixture::new();
    // One minter for every route, appending what it was handed to one file: the request already
    // ends in a newline, and minting is sequential, so the file is one request per line.
    let script = format!(
        r#"cat >> {}/requests.jsonl; printf '{{"token":"t","expires_at":"2027-01-01T00:00:00Z"}}'"#,
        fx.root().display()
    );
    let policy = fx.policy_named(
        "attached.json",
        &json!({
            "version": 1,
            "minters": {"m": {"command": [os_bin("sh"), "-c", script]}},
            "workspaces": {
                "work": {
                    "roots": [{"path": fx.root(), "mode": "readwrite"}],
                    "forge": {"org": "firefly-engineering"},
                    "credentials": [{
                        "host": "work.example",
                        "path_prefix": "/firefly-engineering/",
                        "minter": "m",
                        "delivery": {"env": "WORK_TOKEN"},
                    }],
                },
                "notes": {
                    "roots": [],
                    "forge": {"repos": ["op/notes"]},
                    "credentials": [{
                        "host": "notes.example",
                        "path_prefix": "/op/",
                        "minter": "m",
                        "delivery": {"env": "NOTES_TOKEN"},
                    }],
                },
            },
            "profiles": {"p": {
                "workspaces": ["work", "notes"],
                "toolchain": [],
                "credentials": [{
                    "host": "model.example",
                    "path_prefix": "/",
                    "minter": "m",
                    "delivery": {"env": "MODEL_TOKEN"},
                }],
            }},
        }),
    );
    let output = fx
        .run_under(&policy, &[&os_bin("true")])
        .output()
        .expect("playpen");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let requests: Vec<Value> = std::fs::read_to_string(fx.root().join("requests.jsonl"))
        .expect("the requests")
        .lines()
        .map(|line| serde_json::from_str(line).expect("each request is JSON"))
        .collect();
    let request = |host: &str| -> Value {
        requests
            .iter()
            .find(|request| request["route"]["host"] == host)
            .unwrap_or_else(|| panic!("no request for {host} in {requests:?}"))
            .clone()
    };
    // Each workspace route carries its own workspace's scope, in its own shape.
    assert_eq!(
        request("work.example")["scope"],
        json!({"org": "firefly-engineering"})
    );
    assert_eq!(
        request("notes.example")["scope"],
        json!({"repos": ["op/notes"]})
    );
    // The profile route carries none: it does not minimize to one workspace.
    assert_eq!(request("model.example")["scope"], Value::Null);
    assert_eq!(requests.len(), 3, "{requests:?}");

    // One route table, in the profile's own order — its workspaces as it listed them, then its
    // own routes — with both kinds of attachment named by their provenance.
    let ids = fx.run_ids();
    let credentials = fx.record(&ids[0])["credentials"].clone();
    let table: Vec<_> = credentials
        .as_array()
        .expect("a route table")
        .iter()
        .map(|route| {
            (
                route["host"].as_str().expect("a host").to_owned(),
                route["from"].as_str().expect("provenance").to_owned(),
            )
        })
        .collect();
    assert_eq!(
        table,
        [
            (
                "work.example".to_owned(),
                "workspace:work.credentials[0]".to_owned()
            ),
            (
                "notes.example".to_owned(),
                "workspace:notes.credentials[0]".to_owned()
            ),
            (
                "model.example".to_owned(),
                "profile:p.credentials[0]".to_owned()
            ),
        ]
    );
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

/// A policy with one profile route whose minter answers at once and whose revoker is `revoke`.
fn with_revoker(fx: &Fixture, revoke: &Value) -> PathBuf {
    fx.policy_named(
        "revoke.json",
        &json!({
            "version": 1,
            "minters": {"gh-app": {
                "command": [os_bin("sh"), "-c",
                    r#"cat >/dev/null; printf '{"token":"s3cret","expires_at":"2027-01-01T00:00:00Z"}'"#],
                "revoke": revoke,
                "timeout": 2,
            }},
            "workspaces": {"w": {
                "roots": [{"path": fx.root(), "mode": "readwrite"}],
                "forge": {"org": "firefly-engineering"},
                "credentials": [{
                    "host": "api.github.com",
                    "path_prefix": "/repos/firefly-engineering/",
                    "minter": "gh-app",
                    "delivery": {"env": "GH_TOKEN"},
                }],
            }},
            "profiles": {"p": {"workspaces": ["w"], "toolchain": []}},
        }),
    )
}

/// **Each declared `revoke` runs with the minter's stdin** ([spec §4.2] step 18) — the same
/// request, scope included, so a revoker can address the credential it is retiring.
///
/// That it runs *before the proxy stops* is the call site's order and is not asserted here: a
/// revoker is an ordinary host process, so the only way a row could observe the listener is a
/// TCP client, and neither runner is guaranteed one.
///
/// [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
#[test]
fn each_declared_revoker_runs_with_the_minters_own_stdin() {
    let fx = Fixture::new();
    let seen = fx.root().join("revoker-stdin.json");
    let policy = with_revoker(
        &fx,
        &json!([os_bin("sh"), "-c", format!("cat > {}", seen.display())]),
    );
    let output = fx
        .run_under(&policy, &[&os_bin("true")])
        .output()
        .expect("playpen");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdin = std::fs::read_to_string(&seen).expect("the revoker's stdin");
    let request: Value = serde_json::from_str(&stdin).expect("JSON");
    assert_eq!(request["version"], 1);
    assert_eq!(request["route"]["host"], "api.github.com");
    assert_eq!(
        request["route"]["path_prefix"],
        "/repos/firefly-engineering/"
    );
    // The same stdin the minter got: a workspace route carries that workspace's forge scope.
    assert_eq!(request["scope"], json!({"org": "firefly-engineering"}));
    // Nothing of the run's own teardown went wrong.
    let id = fx.run_ids().pop().expect("a record");
    assert_eq!(fx.record(&id)["teardown"], json!([]));
}

/// **A failing revoker is written to the run record and does not change the exit status**
/// ([spec §4.2] step 18): the caller asked what the agent did, and a stumbled cleanup must not
/// overwrite the answer.
#[test]
fn a_failing_revoker_goes_to_the_record_and_leaves_the_exit_status_alone() {
    let fx = Fixture::new();
    let policy = with_revoker(&fx, &json!([os_bin("sh"), "-c", "cat >/dev/null; exit 9"]));
    let output = fx
        .run_under(&policy, &[&os_bin("sh"), "-c", "exit 3"])
        .output()
        .expect("playpen");
    // The child's status, not the revoker's, and not a refusal.
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let id = fx.run_ids().pop().expect("a record");
    let record = fx.record(&id);
    assert_eq!(record["status"], 3);
    assert_eq!(record["refusal"], Value::Null);
    let teardown = record["teardown"].as_array().expect("a teardown list");
    assert_eq!(teardown.len(), 1, "{teardown:?}");
    let said = teardown[0].as_str().expect("a sentence");
    assert!(said.contains("\"gh-app\""), "{said}");
    assert!(said.contains("api.github.com"), "{said}");
    assert!(said.contains("exited with"), "{said}");
    // And `explain --run` replays it, which is the only place it is ever reported.
    let human = fx
        .playpen(&["explain", "--run", &id])
        .output()
        .expect("playpen explain");
    let human = String::from_utf8(human.stdout).expect("utf-8");
    assert!(
        human
            .lines()
            .any(|line| line.starts_with("teardown ") && line.contains("exited with")),
        "{human}"
    );
}

/// A revoker that hangs does not hold teardown open for longer than the minter's own `timeout`,
/// and the run still exits with the child's status.
#[test]
fn a_hanging_revoker_is_bounded_and_the_run_still_ends() {
    let fx = Fixture::new();
    let policy = with_revoker(
        &fx,
        &json!([os_bin("sh"), "-c", "cat >/dev/null; sleep 120"]),
    );
    let started = std::time::Instant::now();
    let output = fx
        .run_under(&policy, &[&os_bin("true")])
        .output()
        .expect("playpen");
    assert!(output.status.success(), "{output:?}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(60),
        "teardown waited on the revoker for {:?}",
        started.elapsed()
    );
    let id = fx.run_ids().pop().expect("a record");
    let teardown = fx.record(&id)["teardown"]
        .as_array()
        .expect("a teardown list")
        .clone();
    assert_eq!(teardown.len(), 1, "{teardown:?}");
    assert!(
        teardown[0]
            .as_str()
            .expect("a sentence")
            .contains("did not exit within 2s"),
        "{teardown:?}"
    );
}

/// **Ephemeral areas and the run scratch are gone after exit** ([spec §4.2] step 18), and a
/// persistent area is not: that is the whole difference between the two lifetimes.
#[test]
fn the_run_scratch_and_every_ephemeral_area_are_gone_after_exit() {
    let fx = Fixture::new();
    let policy = fx.policy_named(
        "lifetimes.json",
        &json!({
            "version": 1,
            "workspaces": {"w": {
                "roots": [{"path": fx.root(), "mode": "readwrite"}],
                "areas": {"target": {"lifetime": "ephemeral"},
                          "landing": {"lifetime": "persistent"}},
            }},
            "profiles": {"p": {
                "workspaces": ["w"],
                "toolchain": [],
                "env": {"set": {"TARGET": {"area": "w/target"},
                                "LANDING": {"area": "w/landing"}}},
            }},
        }),
    );
    // The child prints the three paths and writes a file into each, so nothing is removed merely
    // for having been empty.
    let output = fx
        .run_under(
            &policy,
            &[
                &os_bin("sh"),
                "-c",
                r#"for d in "$TMPDIR" "$TARGET" "$LANDING"; do echo "$d"; echo x > "$d/file"; done"#,
            ],
        )
        .output()
        .expect("playpen");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).expect("utf-8");
    let paths: Vec<&str> = text.lines().collect();
    let [scratch, ephemeral, persistent] = paths.as_slice() else {
        panic!("three paths: {paths:?}");
    };
    assert!(
        !std::path::Path::new(scratch).exists(),
        "the run scratch outlived the run: {scratch}"
    );
    assert!(
        !std::path::Path::new(ephemeral).exists(),
        "an ephemeral area outlived the run: {ephemeral}"
    );
    assert!(
        std::path::Path::new(persistent).join("file").exists(),
        "a persistent area did not survive its run: {persistent}"
    );
}

/// **A short-lived credential is re-minted before expiry, and the run record holds each new
/// `expires_at`** ([spec §7.2]). The minter answers with a fresh expiry every time, so the one
/// the record ends with is a renewal's and not the launch's.
///
/// [spec §7.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#72-minters
#[test]
fn a_short_lived_credential_is_re_minted_and_each_new_expiry_is_recorded() {
    let fx = Fixture::new();
    let mints = fx.root().join("mints");
    // A two-second credential, so the first renewal is due one and a half seconds in. Every
    // expiry it answers with is appended, so the last line is the one still in force.
    let policy = with_minter(
        &fx,
        "short",
        &format!(
            r#"cat >/dev/null
               expiry=$({soon})
               echo "$expiry" >> {mints}
               printf '{{"token":"s3cret","expires_at":"%s"}}' "$expiry""#,
            soon = SOON,
            mints = mints.display(),
        ),
        None,
    );
    // The child waits long enough for a renewal to land, then exits of its own accord.
    let output = fx
        .run_under(&policy, &[&os_bin("sh"), "-c", "exec sleep 3"])
        .output()
        .expect("playpen");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let answered = std::fs::read_to_string(&mints).expect("the expiries the minter answered with");
    let answered: Vec<&str> = answered.lines().collect();
    assert!(
        answered.len() >= 2,
        "the credential was never re-minted: {answered:?}"
    );
    let id = fx.run_ids().pop().expect("a record");
    let record = fx.record(&id);
    // The record holds the latest expiry, which is a renewal's and not the launch's.
    let credentials = record["credentials"].as_array().expect("credentials");
    assert_eq!(credentials.len(), 1, "{credentials:?}");
    assert_eq!(
        credentials[0]["expires_at"],
        *answered.last().expect("an expiry"),
        "the record kept an expiry a renewal had replaced"
    );
    assert_ne!(
        credentials[0]["expires_at"], answered[0],
        "the record kept the expiry the launch minted"
    );
    // A renewal that worked is not a lapse, and renewal is never a refusal.
    assert_eq!(record["lapsed"], json!([]));
    assert_eq!(record["refusal"], Value::Null);
    // Never a token, in any of it.
    assert!(!record.to_string().contains("s3cret"), "{record}");
}

/// **A failed re-mint leaves the run alive and the credential lapses** ([spec §7.2]): it is not a
/// refusal, the child exits with its own status, and the record says why its requests stopped
/// authenticating.
///
/// [spec §7.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#72-minters
#[test]
fn a_failed_re_mint_leaves_the_run_alive_and_records_the_lapse() {
    let fx = Fixture::new();
    let expiry = fx.root().join("expiry");
    // The first mint answers with a two-second credential and every later one fails, so the
    // launch succeeds and the renewal that comes due one and a half seconds in does not.
    let policy = with_minter(
        &fx,
        "flaky",
        &format!(
            r#"cat >/dev/null
               if [ -f {expiry} ]; then exit 4; fi
               answered=$({soon})
               echo "$answered" > {expiry}
               printf '{{"token":"s3cret","expires_at":"%s"}}' "$answered""#,
            soon = SOON,
            expiry = expiry.display(),
        ),
        None,
    );
    let output = fx
        .run_under(&policy, &[&os_bin("sh"), "-c", "exec sleep 3"])
        .output()
        .expect("playpen");
    // The child's own status, and no refusal: a re-mint failure mid-run cannot be one.
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let id = fx.run_ids().pop().expect("a record");
    let record = fx.record(&id);
    assert_eq!(record["refusal"], Value::Null, "{record}");
    assert_eq!(record["status"], 0);
    let lapsed = record["lapsed"].as_array().expect("a lapse list");
    assert_eq!(lapsed.len(), 1, "{lapsed:?}");
    let said = lapsed[0].as_str().expect("a sentence");
    assert!(said.contains("api.anthropic.com"), "{said}");
    assert!(said.contains("lapses"), "{said}");
    assert!(said.contains("401"), "{said}");
    // The expiry stays the one that is still in force: nothing replaced it.
    let minted = std::fs::read_to_string(&expiry).expect("the launch's expiry");
    assert_eq!(record["credentials"][0]["expires_at"], minted.trim());
}
