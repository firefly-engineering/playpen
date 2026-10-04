//! The backend is the maintained fork, pinned by exact `rev` and never a branch, tag or range
//! (ADR 0022). A rev that moves only through a reviewed edit is what makes a version bump a PR
//! the enforcement suite can hold red.

use toml::Table;

const FORK: &str = "https://github.com/firefly-engineering/nono";

#[test]
fn nono_is_pinned_to_an_exact_rev_of_the_fork() {
    let manifest: Table = toml::from_str(include_str!("../Cargo.toml")).expect("Cargo.toml parses");
    let nono = &manifest["dependencies"]["nono"];
    assert_eq!(nono["git"].as_str(), Some(FORK));
    let rev = nono["rev"].as_str().expect("nono is pinned by `rev`");
    assert!(
        rev.len() == 40 && rev.bytes().all(|b| b.is_ascii_hexdigit()),
        "`rev` must be a full commit id, got {rev:?}"
    );
    for floating in ["branch", "tag", "version"] {
        assert!(
            nono.get(floating).is_none(),
            "nono must not carry `{floating}`"
        );
    }
}

/// What each Landlock ABI offers is read from the `landlock` crate (`src/mechanism.rs`), so it
/// must be the very version nono enforces with: pinned exactly, and the only one in the lock.
#[test]
fn landlock_is_pinned_to_the_version_nono_resolves() {
    let manifest: Table = toml::from_str(include_str!("../Cargo.toml")).expect("Cargo.toml parses");
    let pinned = manifest["target"]["cfg(target_os = \"linux\")"]["dependencies"]["landlock"]
        .as_str()
        .and_then(|requirement| requirement.strip_prefix('='))
        .expect("landlock is pinned with `=`");
    let lock: Table = toml::from_str(include_str!("../Cargo.lock")).expect("Cargo.lock parses");
    let packages = lock["package"].as_array().expect("the lock lists packages");
    let named = |name: &'static str| {
        packages
            .iter()
            .filter(move |package| package["name"].as_str() == Some(name))
    };
    let versions: Vec<_> = named("landlock")
        .map(|package| package["version"].as_str().expect("a version"))
        .collect();
    assert_eq!(versions, [pinned], "one landlock, at the pinned version");
    let nono = named("nono").next().expect("nono is locked");
    let depends = nono["dependencies"]
        .as_array()
        .expect("nono has dependencies");
    assert!(
        depends.iter().any(|d| d.as_str() == Some("landlock")),
        "nono depends on that landlock: {depends:?}"
    );
}
