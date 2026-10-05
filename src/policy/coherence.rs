//! The coherence tier ([spec §10.5]): everything decidable from the policy alone, run at build
//! time by `playpen check` and at launch step 5. Each check is one function over the whole
//! document, so a profile no launch selects is held to the same rules as one that is, and a policy
//! that passes `check` in a build never refuses for coherence at launch.
//!
//! The checks run in a fixed order and the first refusal wins. Each names the policy file, and
//! where the offending value is spanned, its line and column.
//!
//! [spec §10.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#105-validation-tiers

use super::syntax::written_at;
use super::{AreaRef, Loaded, SetValue};
use crate::code::Code;
use crate::environment;
use crate::refusal::Refusal;

/// One coherence check of the document read from the policy file.
type Check = fn(&Loaded) -> Result<(), Refusal>;

/// Every check, in the order they run. A new coherence code is one more entry here.
const CHECKS: &[Check] = &[
    workspaces_are_declared,
    roots_are_absolute,
    fragments_are_declared,
    env_is_not_forbidden,
    env_is_not_reserved,
    areas_are_declared,
];

/// Run the coherence tier over `loaded`.
pub fn check(loaded: &Loaded) -> Result<(), Refusal> {
    CHECKS.iter().try_for_each(|check| check(loaded))
}

/// A profile names only declared workspaces (`refusal.workspace.unknown`).
fn workspaces_are_declared(loaded: &Loaded) -> Result<(), Refusal> {
    let Loaded { path, policy } = loaded;
    for (profile, selected) in &policy.profiles {
        for name in &selected.workspaces {
            if !policy.workspaces.contains_key(&name.value) {
                return Err(Refusal::new(
                    Code::WorkspaceUnknown,
                    format!(
                        "{}: profile {profile:?} names workspace {:?}, which is not declared; \
                         declared workspaces: {}",
                        written_at(path, name),
                        name.value,
                        known(policy.workspaces.keys()),
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// A brought or toolchain root is an absolute path (`refusal.root.relative`): a relative one would
/// be resolved against whatever directory playpen happened to start in.
fn roots_are_absolute(loaded: &Loaded) -> Result<(), Refusal> {
    let Loaded { path, policy } = loaded;
    let brought = policy.workspaces.iter().flat_map(|(name, workspace)| {
        workspace
            .roots
            .iter()
            .enumerate()
            .map(move |(i, root)| (format!("workspace:{name}.roots[{i}]"), &root.path))
    });
    let toolchain = policy.profiles.iter().flat_map(|(name, profile)| {
        profile
            .toolchain
            .iter()
            .enumerate()
            .map(move |(i, root)| (format!("profile:{name}.toolchain[{i}]"), &root.path))
    });
    match brought
        .chain(toolchain)
        .find(|(_, root)| !root.is_absolute())
    {
        Some((from, root)) => Err(Refusal::new(
            Code::RootRelative,
            format!(
                "{}: {from} is {}, which is not an absolute path",
                path.display(),
                root.display()
            ),
        )),
        None => Ok(()),
    }
}

/// A profile lists only declared env fragments (`refusal.fragment.unknown`).
fn fragments_are_declared(loaded: &Loaded) -> Result<(), Refusal> {
    let Loaded { path, policy } = loaded;
    for (profile, selected) in &policy.profiles {
        for (i, fragment) in selected.env.fragments.iter().enumerate() {
            if !policy.fragments.env.contains_key(fragment) {
                return Err(Refusal::new(
                    Code::FragmentUnknown,
                    format!(
                        "{}: profile:{profile}.env.fragments[{i}] is {fragment:?}, which is not \
                         declared; declared env fragments: {}",
                        path.display(),
                        known(policy.fragments.env.keys()),
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// No policy entry passes through or sets a forbidden name (`refusal.env.forbidden`).
fn env_is_not_forbidden(loaded: &Loaded) -> Result<(), Refusal> {
    let Loaded { path, policy } = loaded;
    match environment::authored(policy).find(|(var, _)| environment::FORBIDDEN.contains(var)) {
        Some((var, from)) => Err(Refusal::new(
            Code::EnvForbidden,
            format!(
                "{}: {from} names {var:?}, which no policy may pass through or set: it names a \
                 credential oracle the proxy cannot see",
                path.display()
            ),
        )),
        None => Ok(()),
    }
}

/// No policy entry writes a name playpen writes (`refusal.env.reserved`): two authors of one
/// variable is "which rule won" in miniature. The reserved names are playpen's own and every
/// route's delivery name. A delivery name is itself a policy entry, so it is held against
/// playpen's own names, and two routes delivering one name are one author.
fn env_is_not_reserved(loaded: &Loaded) -> Result<(), Refusal> {
    let Loaded { path, policy } = loaded;
    let collision = |var: &str, from: &str, author: &str| {
        Err(Refusal::new(
            Code::EnvReserved,
            format!(
                "{}: {from} names {var:?}, which is reserved for {author}: one name has one author",
                path.display()
            ),
        ))
    };
    let by_playpen = environment::written_by_playpen();
    let by_playpen_of = |var: &str| {
        by_playpen
            .iter()
            .find(|(name, _)| *name == var)
            .map(|(_, author)| author.clone())
    };
    // A delivery name against playpen's own.
    for (var, from) in environment::deliveries(policy) {
        if let Some(author) = by_playpen_of(&var) {
            return collision(&var, &from, &author);
        }
    }
    // An allowed or set name against playpen's own, then against every delivery name.
    for (var, from) in environment::authored(policy) {
        let delivered = || {
            environment::deliveries(policy)
                .find(|(name, _)| name == var)
                .map(|(_, route)| route)
        };
        if let Some(author) = by_playpen_of(var).or_else(delivered) {
            return collision(var, &from, &author);
        }
    }
    Ok(())
}

/// An `!area` reference names an area of one of its profile's own workspaces
/// (`refusal.area.unknown`): any other has no path in that profile's runs.
fn areas_are_declared(loaded: &Loaded) -> Result<(), Refusal> {
    let Loaded { path, policy } = loaded;
    for (profile, selected) in &policy.profiles {
        for (var, value) in &selected.env.set {
            let SetValue::Area(reference) = value else {
                continue;
            };
            let declared = reference.target().is_some_and(|(workspace, area)| {
                selected.workspaces.iter().any(|w| w.value == workspace)
                    && policy
                        .workspaces
                        .get(workspace)
                        .is_some_and(|w| w.areas.contains_key(area))
            });
            if !declared {
                let AreaRef::Area(reference) = reference;
                return Err(Refusal::new(
                    Code::AreaUnknown,
                    format!(
                        "{}: profile:{profile}.env.set.{var} is !area {reference}, which names no \
                         area of profile {profile:?}'s workspaces: an area is named \
                         <workspace>/<area>",
                        path.display(),
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// `names`, comma-separated, or `none`.
fn known<'a>(names: impl Iterator<Item = &'a String>) -> String {
    let names: Vec<_> = names.map(String::as_str).collect();
    if names.is_empty() {
        "none".into()
    } else {
        names.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::policy::Policy;

    const ORIGIN: &str = "/etc/playpen/policy.yaml";

    fn checked(text: &str) -> Result<(), Refusal> {
        let path = Path::new(ORIGIN);
        let policy = Policy::parse(text, path).expect("the document parses");
        check(&Loaded {
            path: path.into(),
            policy,
        })
    }

    #[test]
    fn a_coherent_policy_passes() {
        let text = "\
version: 1
workspaces:
  w: { roots: [{ path: /src/w, mode: read }] }
profiles:
  p: { workspaces: [w], toolchain: [] }
";
        assert_eq!(checked(text), Ok(()));
    }

    #[test]
    fn an_undeclared_workspace_is_refused_where_it_is_named() {
        let text = "\
version: 1
workspaces:
  w: { roots: [{ path: /src/w, mode: read }] }
profiles:
  p:
    workspaces: [w, nope]
    toolchain: []
";
        let refusal = checked(text).expect_err("refused");
        assert_eq!(refusal.code, Code::WorkspaceUnknown);
        assert!(
            refusal.message().starts_with(&format!("{ORIGIN}:6:21: ")),
            "{refusal}"
        );
        assert!(refusal.message().contains("\"nope\""), "{refusal}");
        assert!(
            refusal.message().ends_with("declared workspaces: w"),
            "{refusal}"
        );
    }

    /// Coherence is a property of the document, not of the profile a launch selects.
    #[test]
    fn every_profile_is_held_to_it() {
        let text = "\
version: 1
profiles:
  used: { workspaces: [], toolchain: [] }
  unused: { workspaces: [nope], toolchain: [] }
";
        let refusal = checked(text).expect_err("refused");
        assert_eq!(refusal.code, Code::WorkspaceUnknown);
        assert!(
            refusal.message().ends_with("declared workspaces: none"),
            "{refusal}"
        );
    }

    #[test]
    fn a_workspace_named_through_an_alias_names_both_sites() {
        let text = "\
version: 1
definitions:
  name: &name nope
profiles:
  p: { workspaces: [*name], toolchain: [] }
";
        let refusal = checked(text).expect_err("refused");
        assert_eq!(refusal.code, Code::WorkspaceUnknown);
        assert!(
            refusal
                .message()
                .starts_with(&format!("{ORIGIN}:5:21 (defined at {ORIGIN}:3:15): ")),
            "{refusal}"
        );
    }

    #[test]
    fn a_relative_toolchain_root_is_refused() {
        let text = "\
version: 1
profiles:
  p: { workspaces: [], toolchain: [{ path: nix/store/x }] }
";
        let refusal = checked(text).expect_err("refused");
        assert_eq!(refusal.code, Code::RootRelative);
        assert!(
            refusal.message().contains("profile:p.toolchain[0]"),
            "{refusal}"
        );
    }

    #[test]
    fn an_undeclared_env_fragment_is_refused() {
        let text = "\
version: 1
fragments:
  env: { rust: [CARGO_HOME] }
profiles:
  p: { workspaces: [], toolchain: [], env: { fragments: [rust, nope] } }
";
        let refusal = checked(text).expect_err("refused");
        assert_eq!(refusal.code, Code::FragmentUnknown);
        assert!(
            refusal.message().contains("profile:p.env.fragments[1]"),
            "{refusal}"
        );
        assert!(
            refusal.message().ends_with("declared env fragments: rust"),
            "{refusal}"
        );
    }

    /// `SSH_AUTH_SOCK` names a credential oracle the proxy cannot see, wherever it is allowed.
    #[test]
    fn ssh_auth_sock_is_forbidden_in_every_place_a_name_is_allowed() {
        for (env, fragments, from) in [
            ("{ allow: [SSH_AUTH_SOCK] }", "{}", "profile:p.env.allow[0]"),
            (
                "{ set: { SSH_AUTH_SOCK: /tmp/s } }",
                "{}",
                "profile:p.env.set.SSH_AUTH_SOCK",
            ),
            ("{}", "{ ssh: [SSH_AUTH_SOCK] }", "fragment:ssh"),
        ] {
            let text = format!(
                "version: 1\nfragments: {{ env: {fragments} }}\nprofiles:\n  p: {{ workspaces: [], \
                 toolchain: [], env: {env} }}\n"
            );
            let refusal = checked(&text).expect_err("refused");
            assert_eq!(refusal.code, Code::EnvForbidden, "{text}");
            assert!(refusal.message().contains(from), "{refusal}");
        }
    }

    /// Path-shaped names can only name a path, which the mechanism enforces, so they are not banned.
    #[test]
    fn path_shaped_names_are_not_banned() {
        let text = "\
version: 1
profiles:
  p:
    workspaces: []
    toolchain: []
    env: { allow: [LD_PRELOAD, DYLD_INSERT_LIBRARIES], set: { NODE_OPTIONS: --require /x } }
";
        assert_eq!(checked(text), Ok(()));
    }

    /// Every name playpen writes in some run has one author: playpen.
    #[test]
    fn a_policy_entry_colliding_with_a_reserved_name_is_refused() {
        for (env, fragments, reserved) in [
            ("{ set: { TMPDIR: /tmp } }", "{}", "TMPDIR"),
            ("{ allow: [PLAYPEN_ACTIVE] }", "{}", "PLAYPEN_ACTIVE"),
            ("{ allow: [no_proxy] }", "{}", "no_proxy"),
            (
                "{ set: { NODE_USE_ENV_PROXY: \"0\" } }",
                "{}",
                "NODE_USE_ENV_PROXY",
            ),
            (
                "{ set: { CLAUDE_CONFIG_DIR: /c } }",
                "{}",
                "CLAUDE_CONFIG_DIR",
            ),
            (
                "{ allow: [PI_CODING_AGENT_DIR] }",
                "{}",
                "PI_CODING_AGENT_DIR",
            ),
            (
                "{ set: { CLAUDE_CODE_SANDBOXED: \"0\" } }",
                "{}",
                "CLAUDE_CODE_SANDBOXED",
            ),
            ("{}", "{ certs: [SSL_CERT_FILE] }", "SSL_CERT_FILE"),
            ("{ set: { GH_TOKEN: x } }", "{}", "GH_TOKEN"),
        ] {
            let text = format!(
                "version: 1\nfragments: {{ env: {fragments} }}\nminters: {{ m: {{ command: [/m] }} }}\n\
                 workspaces:\n  w:\n    roots: []\n    credentials:\n      - {{ host: github.com, \
                 path_prefix: /, minter: m, delivery: {{ env: GH_TOKEN }} }}\n\
                 profiles:\n  p: {{ workspaces: [w], toolchain: [], env: {env} }}\n"
            );
            let refusal = checked(&text).expect_err("refused");
            assert_eq!(refusal.code, Code::EnvReserved, "{text}");
            assert!(
                refusal.message().contains(&format!("{reserved:?}")),
                "{refusal}"
            );
        }
    }

    #[test]
    fn a_delivery_name_colliding_with_a_set_entry_is_refused() {
        let text = "\
version: 1
minters: { m: { command: [/m] } }
profiles:
  p:
    workspaces: []
    toolchain: []
    credentials:
      - { host: h, path_prefix: /, minter: m, delivery: { env: HTTPS_PROXY } }
";
        let refusal = checked(text).expect_err("refused");
        assert_eq!(refusal.code, Code::EnvReserved);
        assert!(
            refusal
                .message()
                .contains("profile:p.credentials[0].delivery.env"),
            "{refusal}"
        );
    }

    /// An `!area` reference names an area of one of the profile's own workspaces: any other has
    /// no path in that profile's runs.
    #[test]
    fn a_dangling_area_reference_is_refused() {
        for reference in ["w/nope", "other/a", "nope/a", "w", "w/a/b"] {
            let text = format!(
                "version: 1\nworkspaces:\n  w: {{ roots: [], areas: {{ a: {{ lifetime: ephemeral }} }} }}\n  \
                 other: {{ roots: [], areas: {{ a: {{ lifetime: ephemeral }} }} }}\n\
                 profiles:\n  p: {{ workspaces: [w], toolchain: [], env: {{ set: {{ X: !area {reference} }} }} }}\n"
            );
            let refusal = checked(&text).expect_err(reference);
            assert_eq!(refusal.code, Code::AreaUnknown, "{reference}");
            assert!(
                refusal.message().contains("profile:p.env.set.X"),
                "{refusal}"
            );
            assert!(refusal.message().contains(reference), "{refusal}");
        }
        let text = "\
version: 1
workspaces:
  w: { roots: [], areas: { a: { lifetime: ephemeral } } }
profiles:
  p: { workspaces: [w], toolchain: [], env: { set: { X: !area w/a } } }
";
        assert_eq!(checked(text), Ok(()));
    }

    #[test]
    fn a_relative_root_is_refused() {
        let text = "\
version: 1
workspaces:
  w: { roots: [{ path: src/w, mode: read }] }
";
        let refusal = checked(text).expect_err("refused");
        assert_eq!(refusal.code, Code::RootRelative);
        assert!(
            refusal.message().contains("workspace:w.roots[0]"),
            "{refusal}"
        );
    }
}
