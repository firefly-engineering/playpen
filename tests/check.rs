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
