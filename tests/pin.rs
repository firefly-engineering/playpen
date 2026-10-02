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
