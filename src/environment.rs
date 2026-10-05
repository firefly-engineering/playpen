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

use crate::policy::{Policy, Profile, SetValue};

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
/// `area` renders an `!area` reference to the area's real path; the coherence tier has already
/// refused one that dangles, so a reference it cannot render is left out.
pub fn construct(
    policy: &Policy,
    name: &str,
    selected: &Profile,
    host: &[(OsString, OsString)],
    written: Vec<Var>,
    area: impl Fn(&str) -> Option<OsString>,
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
            SetValue::Area(crate::policy::AreaRef::Area(reference)) => area(reference),
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
