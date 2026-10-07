//! The endpoint rule sets playpen ships ([spec §7.6]): each file under `endpoints/` is the value
//! of one `fragments.endpoints` entry, read by the real parser and held coherent against the route
//! it was written for, and none of them applies to a policy that does not name it.
//!
//! [spec §7.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#76-endpoint-rule-sets

use std::path::{Path, PathBuf};

use playpen::code::Code;
use playpen::policy::{Loaded, Policy, coherence};
use serde_json::json;

/// Each shipped set's intended route: the host and the `path_prefix` its rules are written for.
/// A file with no row here fails, so a new set cannot ship without saying where it belongs.
const INTENDED: [(&str, &str, &str); 3] = [
    (
        "github-git-read-only",
        "github.com",
        "/firefly-engineering/",
    ),
    (
        "github-api-read-only",
        "api.github.com",
        "/repos/firefly-engineering/",
    ),
    ("anthropic-inference-only", "api.anthropic.com", "/"),
];

/// Every shipped set, as its name and its file.
fn shipped() -> Vec<(String, PathBuf)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("endpoints");
    let mut sets: Vec<_> = std::fs::read_dir(&dir)
        .expect("endpoints/")
        .map(|entry| {
            let path = entry.expect("entry").path();
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_suffix(".json"))
                .unwrap_or_else(|| panic!("{} is not a .json rule set", path.display()))
                .to_owned();
            (name, path)
        })
        .collect();
    sets.sort();
    sets
}

/// A policy whose one route on `host` under `prefix` carries `endpoints`, with `declared` as its
/// `fragments.endpoints`, parsed by playpen's own parser.
fn policy(
    host: &str,
    prefix: &str,
    endpoints: &[&str],
    declared: serde_json::Value,
) -> Result<Loaded, playpen::refusal::Refusal> {
    let path = PathBuf::from("policy.json");
    let mut route = json!({
        "host": host,
        "path_prefix": prefix,
        "minter": "m",
        "delivery": {"env": "T"},
    });
    if !endpoints.is_empty() {
        route["endpoints"] = json!(endpoints);
    }
    let text = json!({
        "version": 1,
        "minters": {"m": {"command": ["/bin/true"]}},
        "fragments": {"endpoints": declared},
        "workspaces": {"w": {"roots": [], "credentials": [route]}},
        "profiles": {"p": {"workspaces": ["w"], "toolchain": []}},
    })
    .to_string();
    Ok(Loaded {
        policy: Policy::parse(&text, &path)?,
        path,
    })
}

/// Each shipped file parses as a `fragments.endpoints` entry and is coherent on its intended
/// route: no `refusal.endpoint.unsatisfiable`, so none is a set that 403s every request it meets.
#[test]
fn every_shipped_rule_set_is_coherent_on_its_intended_route() {
    let sets = shipped();
    assert!(!sets.is_empty(), "endpoints/ ships no rule set");
    for (name, path) in &sets {
        let (_, host, prefix) = INTENDED
            .iter()
            .find(|(intended, _, _)| intended == name)
            .unwrap_or_else(|| panic!("{name} ships with no intended route in INTENDED"));
        let rules: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("readable"))
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let loaded = policy(host, prefix, &[name], json!({ name: rules }))
            .unwrap_or_else(|refusal| panic!("{name}: {refusal}"));
        coherence::check(&loaded).unwrap_or_else(|refusal| panic!("{name}: {refusal}"));
    }
    // And no row names a set that does not ship.
    for (intended, _, _) in INTENDED {
        assert!(
            sets.iter().any(|(name, _)| name == intended),
            "{intended} is in INTENDED but endpoints/ ships no such file"
        );
    }
}

/// Nothing applies unless the policy names it ([spec §7.6]): the files ship beside the binary,
/// not inside it. A route naming no set resolves unrestricted, and naming a shipped set the
/// policy does not declare is `refusal.endpoint.unknown` rather than the shipped rules.
#[test]
fn no_shipped_rule_set_applies_unless_the_policy_names_it() {
    let loaded = policy("github.com", "/", &[], json!({})).expect("parsed");
    coherence::check(&loaded).expect("coherent");
    let routes = playpen::resolve::routes(&loaded.policy, "p", &loaded.policy.profiles["p"]);
    assert_eq!(routes.len(), 1, "{routes:?}");
    assert!(routes[0].endpoints.is_empty(), "{routes:?}");

    for (name, _) in shipped() {
        let loaded = policy("github.com", "/", &[&name], json!({})).expect("parsed");
        let refusal = coherence::check(&loaded).expect_err("refused");
        assert_eq!(refusal.code, Code::EndpointUnknown, "{name}: {refusal}");
    }
}
