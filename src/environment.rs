//! The child's environment ([spec §9]): **constructed, never filtered**, and exactly one author
//! writes each name ([ADR 0012]). Nothing reaches the child that playpen did not put there, so
//! there is no deny list and nothing to strip.
//!
//! Four layers, each one a set of names, later layers writing over earlier ones:
//!
//! 1. the floor, passed through from the host ([`FLOOR`]);
//! 2. playpen's own set entries, which the caller hands in already rendered;
//! 3. the profile's allow-list — `env.allow` and the names of each listed env fragment — passed
//!    through from the host;
//! 4. the profile's `set:` table, whose values win over floor pass-through.
//!
//! Only names are matched, exactly; an inherited value is never inspected. An allow-listed name
//! the host does not have is simply absent, which fails closed.
//!
//! [spec §9]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#9-the-environment
//! [ADR 0012]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0012-the-environment-is-constructed-and-exactly-one-author-writes-each-name.md

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use crate::policy::{AreaRef, Policy, Profile, SetValue};

/// The floor ([spec §9.1]): facts about a *process*, never about what it may reach, so a built-in
/// default rather than policy. `LC_*` is the closed family the C library defines, enumerated,
/// because a name is never a pattern.
///
/// [spec §9.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#91-layers
pub const FLOOR: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_COLLATE",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NUMERIC",
    "LC_TIME",
    "LC_ADDRESS",
    "LC_IDENTIFICATION",
    "LC_MEASUREMENT",
    "LC_NAME",
    "LC_PAPER",
    "LC_TELEPHONE",
    "TZ",
];

/// playpen's own set entries ([spec §9.2]), reserved in every run whether or not this one writes
/// them. The kind table's entries ([`written_by_playpen`]) and every route's delivery name
/// ([`deliveries`]) are reserved beside these.
///
/// [spec §9.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#92-set-entries
pub const SET_ENTRIES: &[&str] = &[
    "TMPDIR",
    "PLAYPEN_MANIFEST",
    "PLAYPEN_ACTIVE",
    "HTTPS_PROXY",
    "NO_PROXY",
    "no_proxy",
    "NODE_USE_ENV_PROXY",
    "SSL_CERT_FILE",
    "NODE_EXTRA_CA_CERTS",
];

/// Names no policy may pass through or set ([spec §9.1]). `SSH_AUTH_SOCK` names a credential
/// oracle the proxy cannot see. Path-shaped names are deliberately absent: they can only name a
/// path, and the mechanism enforces every path.
///
/// [spec §9.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#91-layers
pub const FORBIDDEN: &[&str] = &["SSH_AUTH_SOCK"];

/// Every name playpen itself writes in some run, with which entry writes it: the set entries, and
/// every kind's state-dir redirect and suppression entries ([spec Appendix B], B7). A route's
/// delivery name is reserved too ([`deliveries`]), but the policy authors that one.
///
/// [spec Appendix B]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#appendix-b--reconciliations-made-in-assembly
pub fn written_by_playpen() -> Vec<(&'static str, String)> {
    let mut names: Vec<_> = SET_ENTRIES
        .iter()
        .map(|&name| (name, "playpen's set entry".to_string()))
        .collect();
    for kind in crate::kind::KINDS {
        names.push((
            kind.redirect,
            format!("kind:{}'s state-dir redirect", kind.name),
        ));
        for &(name, _) in kind.suppression {
            names.push((name, format!("kind:{}'s suppression entry", kind.name)));
        }
    }
    names
}

/// Every route's delivery name, with where the route was written.
pub fn deliveries(policy: &Policy) -> impl Iterator<Item = (String, String)> + '_ {
    let workspaces = policy.workspaces.iter().flat_map(|(name, workspace)| {
        workspace
            .credentials
            .iter()
            .enumerate()
            .map(move |(i, route)| {
                (
                    route.delivery.env.clone(),
                    format!("workspace:{name}.credentials[{i}].delivery.env"),
                )
            })
    });
    let profiles = policy.profiles.iter().flat_map(|(name, profile)| {
        profile
            .credentials
            .iter()
            .enumerate()
            .map(move |(i, route)| {
                (
                    route.delivery.env.clone(),
                    format!("profile:{name}.credentials[{i}].delivery.env"),
                )
            })
    });
    workspaces.chain(profiles)
}

/// Every name the policy itself asks to pass through or set, with where it asked: each profile's
/// `env.allow` and `set:`, and every env fragment.
pub fn authored(policy: &Policy) -> impl Iterator<Item = (&str, String)> + '_ {
    let profiles = policy.profiles.iter().flat_map(|(name, profile)| {
        let allow = profile
            .env
            .allow
            .iter()
            .enumerate()
            .map(move |(i, var)| (var.as_str(), format!("profile:{name}.env.allow[{i}]")));
        let set = profile
            .env
            .set
            .keys()
            .map(move |var| (var.as_str(), format!("profile:{name}.env.set.{var}")));
        allow.chain(set)
    });
    let fragments = policy.fragments.env.iter().flat_map(|(fragment, names)| {
        names
            .iter()
            .map(move |var| (var.as_str(), format!("fragment:{fragment}")))
    });
    profiles.chain(fragments)
}

/// The provenance of a floor name.
pub const FROM_FLOOR: &str = "floor";

/// One variable of the constructed environment, with the authored source that put it there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Var {
    pub name: String,
    pub value: Value,
    pub from: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Passed through from the host, and never inspected.
    Inherited(OsString),
    /// Written by playpen or by the policy's `set:`.
    Written(OsString),
}

impl Value {
    pub fn as_os_str(&self) -> &OsStr {
        match self {
            Value::Inherited(value) | Value::Written(value) => value,
        }
    }
}

/// The environment of a launch of profile `name`, `selected` from `policy`, on a host whose own
/// environment is `host`, with playpen's own set entries `written`. Ordered by name.
///
/// `area` resolves an `!area` reference to the area's real path, which is the value: rendered from
/// the path, never formatted. The coherence tier has already refused a reference that dangles, so
/// one it cannot resolve is left out.
pub fn construct(
    policy: &Policy,
    name: &str,
    selected: &Profile,
    host: &[(OsString, OsString)],
    written: Vec<Var>,
    area: impl Fn(&AreaRef) -> Option<PathBuf>,
) -> Vec<Var> {
    let inherited = |var: &str| {
        host.iter()
            .rev()
            .find(|(name, _)| name == var)
            .map(|(_, value)| Value::Inherited(value.clone()))
    };
    let mut env = BTreeMap::new();
    let mut pass = |var: &str, from: String| {
        if let Some(value) = inherited(var) {
            env.insert(
                var.to_owned(),
                Var {
                    name: var.to_owned(),
                    value,
                    from,
                },
            );
        }
    };
    for var in FLOOR {
        pass(var, FROM_FLOOR.into());
    }
    for (i, var) in selected.env.allow.iter().enumerate() {
        pass(var, format!("profile:{name}.env.allow[{i}]"));
    }
    for fragment in &selected.env.fragments {
        for var in policy.fragments.env.get(fragment).into_iter().flatten() {
            pass(var, format!("fragment:{fragment}"));
        }
    }
    for var in written {
        env.insert(var.name.clone(), var);
    }
    for (var, value) in &selected.env.set {
        let value = match value {
            SetValue::Literal(literal) => Some(OsString::from(literal)),
            SetValue::Area(reference) => area(reference).map(PathBuf::into_os_string),
        };
        if let Some(value) = value {
            env.insert(
                var.clone(),
                Var {
                    name: var.clone(),
                    value: Value::Written(value),
                    from: format!("profile:{name}.env.set.{var}"),
                },
            );
        }
    }
    env.into_values().collect()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn policy(profile: serde_json::Value) -> Policy {
        let text = serde_json::json!({
            "version": 1,
            "fragments": {"env": {"rust": ["CARGO_HOME", "RUSTUP_HOME"]}},
            "profiles": {"p": profile},
        });
        Policy::parse(&text.to_string(), Path::new("/p.json")).expect("parses")
    }

    fn host(vars: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        vars.iter()
            .map(|(name, value)| (name.into(), value.into()))
            .collect()
    }

    fn construct_for(profile: serde_json::Value, vars: &[(&str, &str)]) -> Vec<Var> {
        let policy = policy(profile);
        construct(
            &policy,
            "p",
            &policy.profiles["p"],
            &host(vars),
            Vec::new(),
            |_| None,
        )
    }

    fn names(env: &[Var]) -> Vec<&str> {
        env.iter().map(|var| var.name.as_str()).collect()
    }

    fn get<'a>(env: &'a [Var], name: &str) -> &'a Var {
        env.iter()
            .find(|var| var.name == name)
            .unwrap_or_else(|| panic!("{name} is not in {env:?}"))
    }

    /// The host's own environment is not where the child's comes from: only the floor's names
    /// cross, unasked.
    #[test]
    fn nothing_reaches_the_child_that_playpen_did_not_put_there() {
        let env = construct_for(
            serde_json::json!({"workspaces": [], "toolchain": []}),
            &[
                ("HOME", "/home/u"),
                ("AWS_SECRET_ACCESS_KEY", "s"),
                ("GH_TOKEN", "t"),
                ("TERM", "xterm"),
            ],
        );
        assert_eq!(names(&env), ["HOME", "TERM"]);
        assert!(env.iter().all(|var| var.from == FROM_FLOOR));
    }

    #[test]
    fn home_and_path_pass_through_unrewritten() {
        let env = construct_for(
            serde_json::json!({"workspaces": [], "toolchain": []}),
            &[("HOME", "/home/u"), ("PATH", "/a:/b")],
        );
        assert_eq!(get(&env, "HOME").value, Value::Inherited("/home/u".into()));
        assert_eq!(get(&env, "PATH").value, Value::Inherited("/a:/b".into()));
    }

    #[test]
    fn allowed_names_and_fragment_names_pass_through_with_their_provenance() {
        let env = construct_for(
            serde_json::json!({
                "workspaces": [], "toolchain": [],
                "env": {"allow": ["COLORTERM"], "fragments": ["rust"]},
            }),
            &[
                ("COLORTERM", "truecolor"),
                ("CARGO_HOME", "/c"),
                ("OTHER", "x"),
            ],
        );
        assert_eq!(names(&env), ["CARGO_HOME", "COLORTERM"]);
        assert_eq!(get(&env, "COLORTERM").from, "profile:p.env.allow[0]");
        assert_eq!(get(&env, "CARGO_HOME").from, "fragment:rust");
        assert_eq!(get(&env, "CARGO_HOME").value, Value::Inherited("/c".into()));
    }

    /// The one stated exception to refusal-never-silent-downgrade: it fails closed.
    #[test]
    fn an_allowed_name_absent_from_the_host_is_absent() {
        let env = construct_for(
            serde_json::json!({
                "workspaces": [], "toolchain": [],
                "env": {"allow": ["COLORTERM"], "fragments": ["rust"]},
            }),
            &[],
        );
        assert_eq!(names(&env), Vec::<&str>::new());
    }

    /// Names are exact, never patterns: `LC_*` is the enumerated family, nothing else.
    #[test]
    fn a_name_is_never_a_pattern() {
        let env = construct_for(
            serde_json::json!({"workspaces": [], "toolchain": [], "env": {"allow": ["GH_*"]}}),
            &[("LC_ALL", "C"), ("LC_FOO", "x"), ("GH_TOKEN", "t")],
        );
        assert_eq!(names(&env), ["LC_ALL"]);
    }

    #[test]
    fn set_values_win_over_floor_pass_through() {
        let env = construct_for(
            serde_json::json!({
                "workspaces": [], "toolchain": [],
                "env": {"set": {"PATH": "/curated/bin", "GIT_AUTHOR_NAME": "agent"}},
            }),
            &[("PATH", "/host/bin")],
        );
        assert_eq!(
            get(&env, "PATH").value,
            Value::Written("/curated/bin".into())
        );
        assert_eq!(get(&env, "PATH").from, "profile:p.env.set.PATH");
        assert_eq!(
            get(&env, "GIT_AUTHOR_NAME").value,
            Value::Written("agent".into())
        );
    }

    #[test]
    fn an_area_reference_is_the_areas_path() {
        let policy = policy(serde_json::json!({
            "workspaces": [], "toolchain": [],
            "env": {"set": {"CARGO_HOME": {"area": "w/cache"}}},
        }));
        let path = PathBuf::from("/state/areas/persistent/w/cache");
        let env = construct(&policy, "p", &policy.profiles["p"], &[], Vec::new(), |r| {
            (r.target() == Some(("w", "cache"))).then(|| path.clone())
        });
        assert_eq!(
            get(&env, "CARGO_HOME").value,
            Value::Written(path.into_os_string())
        );
    }

    #[test]
    fn playpen_writes_its_own_entries() {
        let policy = policy(serde_json::json!({"workspaces": [], "toolchain": []}));
        let written = vec![Var {
            name: "PLAYPEN_ACTIVE".into(),
            value: Value::Written("p".into()),
            from: "built-in".into(),
        }];
        let env = construct(&policy, "p", &policy.profiles["p"], &[], written, |_| None);
        assert_eq!(
            get(&env, "PLAYPEN_ACTIVE").value,
            Value::Written("p".into())
        );
    }
}
