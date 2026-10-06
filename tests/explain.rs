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
    // The command is the same in both forms. On macOS it names the run's tag, which the record
    // holds; on Linux it waits on the trace work, so it is absent.
    match denials.as_str() {
        Some(command) => {
            assert_eq!(field("denials"), command);
            assert!(command.starts_with("/usr/bin/log show "), "{command}");
            let tag = json["denial_tag"].as_str().expect("the run's tag");
            // Spelled out rather than taken from the backend: this is the shape §14.2 states.
            assert_eq!(tag, format!("playpen-run-{id}"));
            assert!(command.contains(&format!("\"{tag}\"")), "{command}");
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

/// A profile's boundary, one run's record, or the ring: never two at once. A bare `explain` is the
/// first, with the selection chain naming the profile.
#[test]
fn explain_asks_one_question() {
    let fx = Fixture::new();
    for args in [
        &["explain", "--list", "--run", "x"][..],
        &["explain", "p", "--list"],
        &["explain", "--cwd", "/", "--run", "x"],
    ] {
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

/// `explain <profile>` with `args`, with no `PLAYPEN_PROFILE` of the caller's own unless `env`
/// gives one.
fn explain_profile(fx: &Fixture, args: &[&str], env: Option<&str>) -> std::process::Command {
    let mut command = fx.playpen(&["explain"]);
    command
        .args(args)
        .arg("--policy")
        .arg(&fx.policy)
        .env_remove("PLAYPEN_PROFILE");
    if let Some(profile) = env {
        command.env("PLAYPEN_PROFILE", profile);
    }
    command
}

fn resolved(fx: &Fixture, args: &[&str], env: Option<&str>) -> Value {
    let before = fx.run_ids();
    let output = explain_profile(fx, args, env)
        .arg("--json")
        .output()
        .expect("playpen explain");
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(fx.run_ids(), before, "explain launches nothing");
    serde_json::from_slice(&output.stdout).expect("JSON")
}

#[test]
fn explain_resolves_a_profile_with_provenance_on_every_entry() {
    let fx = Fixture::new();
    let form = resolved(&fx, &["p"], None);
    assert_eq!(form["profile"], "p");
    assert_eq!(form["policy"], fx.policy.to_str().unwrap());
    assert_eq!(
        form["selection"],
        serde_json::json!([{"step": "explicit", "outcome": "selected", "profile": "p"}])
    );
    let paths = form["paths"].as_array().expect("paths");
    let root = fx.root().canonicalize().expect("root");
    assert!(
        paths.iter().any(|p| p["path"] == root.to_str().unwrap()
            && p["access"] == "readwrite"
            && p["from"] == "workspace:w.roots[0]"),
        "{form}"
    );
    assert!(paths.iter().any(|p| p["from"] == "floor"), "{form}");
    let entries = paths
        .iter()
        .chain(form["mach_services"].as_array().expect("services"))
        .chain([&form["network"]]);
    for entry in entries {
        assert!(
            entry["from"].as_str().is_some_and(|from| !from.is_empty()),
            "an entry without provenance: {entry}"
        );
    }
    assert_eq!(
        form["network"],
        serde_json::json!({"mode": "allow-all", "from": "built-in"})
    );
}

/// The human form is rendered from the JSON one: every path and its provenance appear in it.
#[test]
fn the_human_form_shows_what_the_json_form_holds() {
    let fx = Fixture::new();
    let form = resolved(&fx, &["p"], None);
    let output = explain_profile(&fx, &["p"], None)
        .output()
        .expect("playpen explain");
    assert!(output.status.success(), "{output:?}");
    let human = String::from_utf8(output.stdout).expect("utf-8");
    assert!(human.contains("selected  p"), "{human}");
    assert!(
        human.contains("network   allow-all  (from built-in)"),
        "{human}"
    );
    for path in form["paths"].as_array().expect("paths") {
        let line = format!(
            "{}  (from {})",
            path["path"].as_str().unwrap(),
            path["from"].as_str().unwrap()
        );
        assert!(human.contains(&line), "{line} missing from {human}");
    }
}

#[test]
fn explain_selects_from_the_environment_then_the_working_directory() {
    let fx = Fixture::new();
    let form = resolved(&fx, &[], Some("p"));
    assert_eq!(form["selection"][1]["step"], "environment");
    assert_eq!(form["selection"][1]["outcome"], "selected");

    // A policy whose one profile is selected by a prefix: the fixture's root.
    let root = fx.root().canonicalize().expect("root");
    let policy = fx.policy_dir.path().join("prefixed.json");
    let document = serde_json::json!({
        "version": 1,
        "workspaces": {"w": {"roots": [{"path": root, "mode": "read"}]}},
        "profiles": {"p": {"prefixes": [root], "workspaces": ["w"], "toolchain": []}},
    });
    std::fs::write(&policy, document.to_string()).expect("policy");
    let output = fx
        .playpen(&[
            "explain",
            "--json",
            "--policy",
            policy.to_str().unwrap(),
            "--cwd",
        ])
        .arg(root.join("sub"))
        .env_remove("PLAYPEN_PROFILE")
        .output()
        .expect("playpen explain");
    assert!(output.status.success(), "{output:?}");
    let form: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(
        form["selection"][2],
        serde_json::json!({
            "step": "cwd", "outcome": "selected", "profile": "p", "prefix": root,
        })
    );

    let output = fx
        .playpen(&[
            "explain",
            "--policy",
            policy.to_str().unwrap(),
            "--cwd",
            "/",
        ])
        .env_remove("PLAYPEN_PROFILE")
        .output()
        .expect("playpen explain");
    assert_explain_refused(&output, "refusal.selection.no-match");
}

#[test]
fn explain_refuses_where_run_would() {
    let fx = Fixture::new();
    let output = explain_profile(&fx, &["nope"], None)
        .output()
        .expect("playpen explain");
    assert_explain_refused(&output, "refusal.selection.unknown-profile");
    let output = explain_profile(&fx, &[], Some("nope"))
        .output()
        .expect("playpen explain");
    assert_explain_refused(&output, "refusal.selection.unknown-profile");
}

/// `explain --json` lists **every route with its provenance and never a token** ([spec §14.2]),
/// and the human form renders the same table. Nothing is minted to answer: the only secret a
/// route has is the one a launch's minter makes, and `explain` launches nothing.
///
/// [spec §14.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#142-playpen-explain
#[test]
fn explain_states_the_resolved_route_table_with_provenance_and_no_token() {
    let fx = Fixture::new();
    // A minter that would hand back a token if anything ran it, so a route table that held one
    // could only have got it by running one.
    let policy = fx.policy_named(
        "routes.json",
        &serde_json::json!({
            "version": 1,
            "minters": {"gh-app": {"command": [
                os_bin("sh"), "-c",
                r#"cat >/dev/null; printf '{"token":"s3cret","expires_at":"2027-01-01T00:00:00Z"}'"#,
            ]}},
            "fragments": {"endpoints": {
                "github-read-only": [{"method": "GET", "path": "/repos/*/*/**"}],
            }},
            "workspaces": {"w": {
                "roots": [{"path": fx.root(), "mode": "readwrite"}],
                "forge": {"org": "firefly-engineering"},
                "credentials": [{
                    "host": "api.github.com",
                    "path_prefix": "/repos/firefly-engineering/",
                    "minter": "gh-app",
                    "delivery": {"env": "GH_TOKEN"},
                    "endpoints": ["github-read-only"],
                }],
            }},
            "profiles": {"p": {
                "workspaces": ["w"],
                "toolchain": [],
                "credentials": [{
                    "host": "api.anthropic.com",
                    "path_prefix": "/",
                    "minter": "gh-app",
                    "delivery": {"env": "CLAUDE_CODE_OAUTH_TOKEN"},
                }],
            }},
        }),
    );
    let text = explain(
        &fx,
        &["p", "--policy", policy.to_str().expect("utf-8"), "--json"],
    );
    let json: Value = serde_json::from_str(&text).expect("JSON");
    let routes = json["routes"].as_array().expect("a route table").clone();
    assert_eq!(routes.len(), 2, "{routes:?}");
    // The workspace's own route first, then the profile's, as a launch resolves them.
    assert_eq!(routes[0]["host"], "api.github.com");
    assert_eq!(routes[0]["path_prefix"], "/repos/firefly-engineering/");
    assert_eq!(routes[0]["delivery_env"], "GH_TOKEN");
    // §14.2 asks for the route table with fragment provenance, not for the minter: which keystore
    // the operator reaches is the run record's business, and it holds it.
    assert_eq!(routes[0]["minter"], Value::Null);
    assert_eq!(routes[0]["from"], "workspace:w.credentials[0]");
    let set = &routes[0]["endpoints"][0];
    assert_eq!(set["name"], "github-read-only");
    assert_eq!(set["from"], "fragment:endpoints.github-read-only");
    assert_eq!(set["rules"][0]["method"], "GET");
    assert_eq!(set["rules"][0]["path"], "/repos/*/*/**");
    assert_eq!(routes[1]["host"], "api.anthropic.com");
    assert_eq!(routes[1]["from"], "profile:p.credentials[0]");
    // Absent `endpoints:` means unrestricted, which is the empty list and not a rule set.
    assert_eq!(routes[1]["endpoints"], serde_json::json!([]));
    // Never a token, in either form.
    assert!(!text.contains("s3cret"), "{text}");

    let human = explain(&fx, &["p", "--policy", policy.to_str().expect("utf-8")]);
    assert!(!human.contains("s3cret"), "{human}");
    let routes = human.split_once("\nroutes\n").expect("a routes section").1;
    assert!(
        routes.contains(
            "  api.github.com/repos/firefly-engineering/  deliver GH_TOKEN  \
             (from workspace:w.credentials[0])\n"
        ),
        "{routes}"
    );
    assert!(
        routes.contains(
            "    endpoints github-read-only  (from fragment:endpoints.github-read-only)\n      \
             allow GET /repos/*/*/**\n"
        ),
        "{routes}"
    );
    assert!(routes.contains("    unrestricted\n"), "{routes}");
}

/// A profile with no credential route states so, because "no route resolves, and so no proxy
/// runs" is the answer to a question an operator asks.
#[test]
fn explain_states_that_a_profile_with_no_route_runs_no_proxy() {
    let fx = Fixture::new();
    let policy = fx.policy_named(
        "no-routes.json",
        &serde_json::json!({
            "version": 1,
            "workspaces": {"w": {"roots": [{"path": fx.root(), "mode": "readwrite"}]}},
            "profiles": {"p": {"workspaces": ["w"], "toolchain": []}},
        }),
    );
    let args = ["p", "--policy", policy.to_str().expect("utf-8")];
    let json: Value =
        serde_json::from_str(&explain(&fx, &[&args[..], &["--json"]].concat())).expect("JSON");
    assert_eq!(json["routes"], serde_json::json!([]));
    assert!(
        explain(&fx, &args).contains("routes\n  none, so no proxy runs\n"),
        "no route was stated"
    );
}
