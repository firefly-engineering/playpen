//! `playpen check` end to end: it validates a policy, launches nothing, and so leaves no run
//! record.

mod common;

use common::Fixture;

#[test]
fn a_valid_policy_checks_silently() {
    let fx = Fixture::new();
    let policy = fx.policy.to_str().unwrap();
    for args in [
        vec!["check", "--policy", policy],
        vec!["check", "--policy", policy, "--no-filesystem"],
    ] {
        let output = fx.playpen(&args).output().expect("playpen check");
        assert!(output.status.success(), "{args:?}: {output:?}");
        assert!(
            output.stdout.is_empty() && output.stderr.is_empty(),
            "{output:?}"
        );
    }
    assert_eq!(
        fx.run_ids(),
        Vec::<String>::new(),
        "check opens no run record"
    );
}

#[test]
fn a_refusal_is_one_line_with_no_run() {
    let fx = Fixture::new();
    let policy = fx.policy_dir.path().join("bad.yaml");
    std::fs::write(&policy, "version: 1\nprofils: {}\n").expect("policy");
    let output = fx
        .playpen(&[
            "check",
            "--no-filesystem",
            "--policy",
            policy.to_str().unwrap(),
        ])
        .output()
        .expect("playpen check");
    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr,
        format!(
            "playpen: refusal.policy.unknown-field: {}:2:1: unknown field `profils`, expected one \
             of version, definitions, minters, fragments, workspaces, profiles, shims\n",
            policy.display()
        )
    );
    assert_eq!(
        fx.run_ids(),
        Vec::<String>::new(),
        "check opens no run record"
    );
}

/// Coherence is decidable from the document, so `--no-filesystem` runs it too.
#[test]
fn the_coherence_tier_runs_without_the_filesystem() {
    let fx = Fixture::new();
    let policy = fx.policy_dir.path().join("incoherent.json");
    let document = serde_json::json!({
        "version": 1,
        "profiles": {"p": {"workspaces": ["nope"], "toolchain": []}},
    });
    std::fs::write(&policy, document.to_string()).expect("policy");
    let output = fx
        .playpen(&[
            "check",
            "--no-filesystem",
            "--policy",
            policy.to_str().unwrap(),
        ])
        .output()
        .expect("playpen check");
    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("playpen: refusal.workspace.unknown: "),
        "{stderr}"
    );
}

/// A config home and a home of the test's own, holding `document` as `playpen/policy.json` in the
/// config home, so no search reaches the caller's own locations before `/etc/playpen`.
fn configured(document: &serde_json::Value) -> (tempfile::TempDir, tempfile::TempDir) {
    let config = tempfile::TempDir::new().expect("config home");
    let home = tempfile::TempDir::new().expect("home");
    std::fs::create_dir(config.path().join("playpen")).expect("mkdir");
    std::fs::write(
        config.path().join("playpen/policy.json"),
        document.to_string(),
    )
    .expect("policy");
    (config, home)
}

/// Without `--policy`, the search path is read, and `PLAYPEN_POLICY` is not a way to name one.
#[test]
fn the_policy_is_found_on_the_search_path_and_never_through_the_environment() {
    let fx = Fixture::new();
    let incoherent = serde_json::json!({
        "version": 1,
        "profiles": {"p": {"workspaces": ["nope"], "toolchain": []}},
    });
    let (config, home) = configured(&incoherent);
    let output = fx
        .playpen(&["check", "--no-filesystem"])
        .env("XDG_CONFIG_HOME", config.path())
        .env("HOME", home.path())
        // A valid policy: were it read, the check would pass.
        .env("PLAYPEN_POLICY", &fx.policy)
        .output()
        .expect("playpen check");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(125), "{stderr}");
    assert!(
        stderr.starts_with("playpen: refusal.workspace.unknown: "),
        "{stderr}"
    );
    assert!(stderr.contains(config.path().to_str().unwrap()), "{stderr}");
}

#[test]
fn run_reads_the_policy_the_search_path_finds() {
    let fx = Fixture::new();
    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fx.policy).expect("policy")).expect("json");
    let (config, home) = configured(&document);
    let probe = fx.probe();
    let output = fx
        .playpen(&["run", "--profile", "p", "--agent", "claude", "--"])
        .arg(&probe)
        .arg("fds")
        .env("XDG_CONFIG_HOME", config.path())
        .env("HOME", home.path())
        .output()
        .expect("playpen run");
    assert!(output.status.success(), "{output:?}");
    let id = fx.run_ids().pop().expect("a record");
    assert_eq!(
        fx.record(&id)["policy"],
        config.path().join("playpen/policy.json").to_str().unwrap()
    );
}
