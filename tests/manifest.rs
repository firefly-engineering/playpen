//! The manifest end to end ([spec §13]): that every run gets one, where it is, and that the agent
//! can read it. Whether what it says is *true* is `P-manifest`, in the enforcement suite.
//!
//! [spec §13]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#13-the-manifest

mod common;

use serde_json::json;

use common::{Fixture, os_bin};

/// Always written, even when nothing is provisioned: an absent manifest and an empty one say
/// different things, and only one of them is true.
#[test]
fn every_run_writes_the_manifest_where_playpen_manifest_names_it() {
    let fx = Fixture::new();
    // A profile with nothing provisioned beyond what every run gets.
    let policy = fx.policy_named(
        "bare.json",
        &json!({
            "version": 1,
            "workspaces": {"w": {"roots": [{"path": fx.root(), "mode": "readwrite"}]}},
            "profiles": {"p": {"workspaces": ["w"], "toolchain": []}},
        }),
    );
    // One run, so the scratch it names and the scratch it has are the same run's.
    let output = fx
        .run_under(
            &policy,
            &[
                &os_bin("sh"),
                "-c",
                r#"echo "$TMPDIR"; cat "$PLAYPEN_MANIFEST""#,
            ],
        )
        .output()
        .expect("playpen");
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).expect("utf-8");
    let (tmpdir, json) = text
        .split_once('\n')
        .expect("the scratch, then the manifest");
    let manifest: playpen::manifest::Manifest =
        serde_json::from_str(json).expect("the manifest the agent read is JSON");
    assert_eq!(
        manifest.manifest_version,
        playpen::manifest::VERSION,
        "{manifest:?}"
    );
    assert_eq!(manifest.workspaces.len(), 1);
    assert!(manifest.workspaces[0].areas.is_empty());
    assert_eq!(manifest.workspaces[0].forge, None);
    // It sits in the run's own scratch, which the run is granted read-write: the manifest
    // describes the boundary and never constitutes it.
    assert_eq!(manifest.run_scratch, std::path::Path::new(tmpdir));
}

/// The agent already holds its own environment, and the provenance that would name the policy is
/// the operator's business, not the agent's ([spec §13.2]). What an exclusion subtracts is omitted
/// too, which the unit tests show on both platforms; Landlock cannot subtract a subpath
/// ([#127](https://github.com/firefly-engineering/playpen/issues/127)), so no launch here can
/// carry one.
///
/// [spec §13.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#132-content
#[test]
fn the_manifest_omits_the_environment_and_provenance() {
    let fx = Fixture::new();
    let policy = fx.policy_named(
        "omits.json",
        &json!({
            "version": 1,
            "workspaces": {"w": {"roots": [{"path": fx.root(), "mode": "readwrite"}]}},
            "profiles": {"p": {
                "workspaces": ["w"],
                "toolchain": [],
                "env": {"set": {"GIT_AUTHOR_NAME": "playpen agent"}},
            }},
        }),
    );
    let output = fx
        .run_under(
            &policy,
            &[&os_bin("sh"), "-c", r#"cat "$PLAYPEN_MANIFEST""#],
        )
        .output()
        .expect("playpen");
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).expect("utf-8");
    for absent in ["exclude", "GIT_AUTHOR_NAME", "\"from\"", "selection"] {
        assert!(
            !text.contains(absent),
            "{absent} is in the manifest:\n{text}"
        );
    }
}
