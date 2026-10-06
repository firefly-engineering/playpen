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
    minters_are_declared,
    routes_are_unambiguous,
    endpoint_sets_are_declared,
    endpoint_sets_are_satisfiable,
    shared_entry_points_can_be_imported,
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

/// A share entry naming a kind's instruction entry point is composed by reference, so the kind
/// must have an import mechanism (`refusal.state.collision`): the presentation adapter owns that
/// file, and playpen will not drop the rendered file to make room for a copy of someone else's
/// ([spec §5.6]).
///
/// Decidable from the policy alone — the share list is keyed by kind name, and the kind table is
/// compiled in — so it belongs here, and holds every profile to the rule rather than only the one
/// a launch selects.
///
/// [spec §5.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#56-agent-state-directory
fn shared_entry_points_can_be_imported(loaded: &Loaded) -> Result<(), Refusal> {
    let Loaded { path, policy } = loaded;
    for (profile, selected) in &policy.profiles {
        for (name, state) in &selected.agent_state {
            // A kind this playpen does not know has no entry point to collide with; the
            // invocation that states it refuses as `refusal.kind.unknown` of its own accord.
            let Some(presentation) = crate::kind::get(name).and_then(|k| k.presentation.as_ref())
            else {
                continue;
            };
            let Some(i) = state
                .share
                .iter()
                .position(|entry| presentation.collides_with(entry))
            else {
                continue;
            };
            return Err(Refusal::new(
                Code::StateCollision,
                format!(
                    "{}: profile:{profile}.agent_state.{name}.share[{i}] is {:?}, the instruction \
                     entry point of kind {name:?}, which has no import mechanism, so it cannot be \
                     composed by reference",
                    path.display(),
                    presentation.entry_point,
                ),
            ));
        }
    }
    Ok(())
}

/// Every credential route names a declared minter (`refusal.minter.unknown`): a route whose minter
/// does not exist would authenticate nothing, and would do it silently.
fn minters_are_declared(loaded: &Loaded) -> Result<(), Refusal> {
    let Loaded { path, policy } = loaded;
    match routes(policy).find(|(_, route)| !policy.minters.contains_key(&route.minter)) {
        Some((from, route)) => Err(Refusal::new(
            Code::MinterUnknown,
            format!(
                "{}: {from}.minter is {:?}, which is not declared; declared minters: {}",
                path.display(),
                route.minter,
                known(policy.minters.keys()),
            ),
        )),
        None => Ok(()),
    }
}

/// Every profile's routes on one host are ordered by strict prefix extension
/// (`refusal.route.ambiguous`): `path_prefix` is the proxy's **selector**, so for the selection to
/// be determinate one of any two prefixes on a host must strictly extend the other, and the longer
/// wins ([spec §7.1]). Longest-prefix-wins over an unordered pair is a tie broken silently, which
/// would authenticate a request with the wrong workspace's credential.
///
/// Held per profile over the set a launch would resolve — its workspaces' routes and its own
/// ([`crate::minter::attached`]) — because two routes collide only where one run sees both.
///
/// [spec §7.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#71-credential-route
fn routes_are_unambiguous(loaded: &Loaded) -> Result<(), Refusal> {
    let Loaded { path, policy } = loaded;
    for (profile, selected) in &policy.profiles {
        let routes = crate::minter::attached(policy, profile, selected);
        for (i, (from, route, _)) in routes.iter().enumerate() {
            for (other, against, _) in &routes[i + 1..] {
                if against.host != route.host || extends(&route.path_prefix, &against.path_prefix) {
                    continue;
                }
                return Err(Refusal::new(
                    Code::RouteAmbiguous,
                    format!(
                        "{}: profile {profile:?} has two routes on host {:?} where neither path \
                         prefix extends the other: {from}.path_prefix is {:?} and \
                         {other}.path_prefix is {:?}; which credential a request gets would be a \
                         silent tie",
                        path.display(),
                        route.host,
                        route.path_prefix,
                        against.path_prefix,
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Every route names only declared endpoint rule sets (`refusal.endpoint.unknown`). A reference
/// to a set that does not exist cannot be read as "unrestricted": an absent `endpoints:` means
/// that, and a name that resolves to nothing would mean the operator's restriction silently did
/// not apply ([spec §7.6]).
///
/// [spec §7.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#76-endpoint-rule-sets
fn endpoint_sets_are_declared(loaded: &Loaded) -> Result<(), Refusal> {
    let Loaded { path, policy } = loaded;
    for (from, route) in routes(policy) {
        for (i, set) in route.endpoints.iter().enumerate() {
            if !policy.fragments.endpoints.contains_key(set) {
                return Err(Refusal::new(
                    Code::EndpointUnknown,
                    format!(
                        "{}: {from}.endpoints[{i}] is {set:?}, which is not declared; declared \
                         endpoint rule sets: {}",
                        path.display(),
                        known(policy.fragments.endpoints.keys()),
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Every rule set a route carries can allow something on that route
/// (`refusal.endpoint.unsatisfiable`): some path beginning with the route's `path_prefix` matches
/// at least one of its rules ([spec §7.6]).
///
/// A set that can match nothing under the prefix it is attached to allows nothing, so the route is
/// a credential that can never be spent. That is almost always a set written for a different
/// route, and a restriction that silently denies everything is the hardest kind of policy bug to
/// see from inside the boundary.
///
/// Held per route rather than per set membership, because the same set is satisfiable on one route
/// and not on another, and only the pairing is wrong.
///
/// [spec §7.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#76-endpoint-rule-sets
fn endpoint_sets_are_satisfiable(loaded: &Loaded) -> Result<(), Refusal> {
    let Loaded { path, policy } = loaded;
    for (from, route) in routes(policy) {
        for (i, name) in route.endpoints.iter().enumerate() {
            // Declared, because the check before this one refused a route that names one that is
            // not.
            let Some(rules) = policy.fragments.endpoints.get(name) else {
                continue;
            };
            if rules
                .iter()
                .any(|rule| rule.path.satisfiable_under(&route.path_prefix))
            {
                continue;
            }
            return Err(Refusal::new(
                Code::EndpointUnsatisfiable,
                format!(
                    "{}: {from}.endpoints[{i}] is {name:?}, and no path under that route's prefix \
                     {:?} matches any of its {} rule(s), so the rule set allows nothing and the \
                     credential can never be spent",
                    path.display(),
                    route.path_prefix,
                    rules.len(),
                ),
            ));
        }
    }
    Ok(())
}

/// Every credential route in the document, with the provenance of where it was written. Both
/// endpoint checks are about a route and its prefix alone, so they hold over every route the
/// document declares rather than over the set one profile resolves.
fn routes(policy: &super::Policy) -> impl Iterator<Item = (String, &super::Route)> {
    let workspaces = policy.workspaces.iter().flat_map(|(name, workspace)| {
        workspace
            .credentials
            .iter()
            .enumerate()
            .map(move |(i, route)| (format!("workspace:{name}.credentials[{i}]"), route))
    });
    let profiles = policy.profiles.iter().flat_map(|(name, profile)| {
        profile
            .credentials
            .iter()
            .enumerate()
            .map(move |(i, route)| (format!("profile:{name}.credentials[{i}]"), route))
    });
    workspaces.chain(profiles)
}

/// Whether one of `a` and `b` **strictly** extends the other: equal prefixes are not ordered, so
/// they are as ambiguous as disjoint ones.
fn extends(a: &str, b: &str) -> bool {
    a != b && (a.starts_with(b) || b.starts_with(a))
}

/// `names`, comma-separated, or `none`. Every refusal that says "and here is what *is* declared"
/// renders its list through this, so the launch front-end shares it ([`crate::policy::known`]).
pub use crate::policy::known;

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

    /// `claude` imports, so sharing its entry point is composed by reference rather than refused;
    /// a kind this playpen does not know has no entry point to collide with, and the invocation
    /// that states it refuses as `refusal.kind.unknown` of its own accord. Which shape *does*
    /// collide is [`crate::kind::Presentation::collides_with`]'s own test.
    #[test]
    fn sharing_an_importable_entry_point_passes() {
        for kind in ["claude", "omp", "not-a-kind"] {
            let text = format!(
                "version: 1\nprofiles:\n  p:\n    workspaces: []\n    toolchain: []\n    \
                 agent_state: {{ {kind}: {{ share: [CLAUDE.md] }} }}\n"
            );
            assert_eq!(checked(&text), Ok(()), "{kind}");
        }
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

    /// Routes, as `host`/`path_prefix` pairs, written where `site` says: `workspace:<name>` puts
    /// them on that workspace and `profile:p` on the profile. The profile selects every workspace.
    ///
    /// Every route gets a delivery name of its own, so what these tests show is the ambiguity rule
    /// and never [`env_is_not_reserved`] firing first on a shared name.
    fn routed(sites: &[(&str, &[(&str, &str)])]) -> String {
        let mut text = String::from("version: 1\nminters:\n  m: { command: [/bin/true] }\n");
        let mut delivered = 0;
        let mut route = |(host, prefix): &(&str, &str)| {
            delivered += 1;
            format!(
                "      - {{ host: {host}, path_prefix: {prefix}, minter: m, \
                 delivery: {{ env: T{delivered} }} }}\n"
            )
        };
        let mut workspaces = String::new();
        let mut profile = String::new();
        for (site, routes) in sites {
            match site.strip_prefix("workspace:") {
                Some(name) => {
                    workspaces.push_str(&format!("  {name}:\n    roots: []\n    credentials:\n"));
                    for r in *routes {
                        workspaces.push_str(&route(r));
                    }
                }
                None => {
                    profile.push_str("    credentials:\n");
                    for r in *routes {
                        profile.push_str(&route(r));
                    }
                }
            }
        }
        let selected: Vec<&str> = sites
            .iter()
            .filter_map(|(site, _)| site.strip_prefix("workspace:"))
            .collect();
        if !workspaces.is_empty() {
            text.push_str(&format!("workspaces:\n{workspaces}"));
        }
        text.push_str(&format!(
            "profiles:\n  p:\n    workspaces: [{}]\n    toolchain: []\n{profile}",
            selected.join(", ")
        ));
        text
    }

    #[test]
    fn routes_on_one_host_must_be_ordered_by_strict_prefix_extension() {
        // The longer strictly extends the shorter: the proxy's selection is determinate.
        assert_eq!(
            checked(&routed(&[(
                "workspace:w",
                &[("api.example", "/"), ("api.example", "/repos/op/")],
            )])),
            Ok(())
        );
        // One host each: nothing to order.
        assert_eq!(
            checked(&routed(&[(
                "workspace:w",
                &[("a.example", "/one/"), ("b.example", "/two/")],
            )])),
            Ok(())
        );
    }

    #[test]
    fn two_disjoint_prefixes_on_one_host_are_ambiguous() {
        let refusal = checked(&routed(&[(
            "workspace:w",
            &[("api.example", "/repos/a/"), ("api.example", "/repos/b/")],
        )]))
        .expect_err("refused");
        assert_eq!(refusal.code, Code::RouteAmbiguous);
        assert!(refusal.message().contains("\"api.example\""), "{refusal}");
        assert!(
            refusal.message().contains("workspace:w.credentials[0]")
                && refusal.message().contains("workspace:w.credentials[1]"),
            "{refusal}"
        );
        assert!(
            refusal.message().contains("\"/repos/a/\"")
                && refusal.message().contains("\"/repos/b/\""),
            "{refusal}"
        );
    }

    /// A policy with one route carrying `endpoints`, with `fragments.endpoints` as written.
    fn with_endpoints(prefix: &str, endpoints: &str, declared: &str) -> String {
        format!(
            "\
version: 1
minters:
  m: {{ command: [/bin/true] }}
fragments:
  endpoints:
{declared}
workspaces:
  w:
    roots: []
    credentials:
      - host: api.example
        path_prefix: {prefix}
        minter: m
        delivery: {{ env: T }}
        endpoints: {endpoints}
profiles:
  p: {{ workspaces: [w], toolchain: [] }}
"
        )
    }

    /// An absent `endpoints:` means unrestricted, so a policy declaring no rule set at all is
    /// coherent ([spec §7.6]).
    #[test]
    fn a_route_with_no_rule_set_is_coherent() {
        let text = "\
version: 1
minters:
  m: { command: [/bin/true] }
workspaces:
  w:
    roots: []
    credentials:
      - { host: api.example, path_prefix: /, minter: m, delivery: { env: T } }
profiles:
  p: { workspaces: [w], toolchain: [] }
";
        assert_eq!(checked(text), Ok(()));
    }

    /// A rule set a route names must exist: a name that resolved to nothing would mean the
    /// operator's restriction silently did not apply.
    #[test]
    fn an_undeclared_rule_set_is_refused() {
        let refusal = checked(&with_endpoints(
            "/",
            "[read-only, nope]",
            "    read-only:\n      - { method: GET, path: /** }\n",
        ))
        .expect_err("refused");
        assert_eq!(refusal.code, Code::EndpointUnknown);
        assert!(
            refusal
                .message()
                .contains("workspace:w.credentials[0].endpoints[1]"),
            "{refusal}"
        );
        assert!(refusal.message().contains("\"nope\""), "{refusal}");
        assert!(
            refusal
                .message()
                .ends_with("declared endpoint rule sets: read-only"),
            "{refusal}"
        );
    }

    /// A rule set that can allow nothing on the route it is attached to is refused rather than
    /// left to deny every request: it is a set written for a different route.
    #[test]
    fn a_rule_set_that_can_match_nothing_under_the_prefix_is_refused() {
        let refusal = checked(&with_endpoints(
            "/repos/firefly/",
            "[inference]",
            "    inference:\n      - { method: POST, path: /v1/messages }\n",
        ))
        .expect_err("refused");
        assert_eq!(refusal.code, Code::EndpointUnsatisfiable);
        assert!(
            refusal
                .message()
                .contains("workspace:w.credentials[0].endpoints[0]"),
            "{refusal}"
        );
        assert!(refusal.message().contains("\"inference\""), "{refusal}");
        assert!(
            refusal.message().contains("\"/repos/firefly/\""),
            "{refusal}"
        );
        // An empty set allows nothing by construction, so it is unsatisfiable under any prefix.
        let empty = checked(&with_endpoints("/", "[none]", "    none: []\n")).expect_err("refused");
        assert_eq!(empty.code, Code::EndpointUnsatisfiable);
    }

    /// The same set is satisfiable on the route it was written for. One rule reaching under the
    /// prefix is enough: a set is allow-only, so any rule of it can be the one that allows.
    #[test]
    fn a_rule_set_one_of_whose_rules_reaches_under_the_prefix_is_coherent() {
        assert_eq!(
            checked(&with_endpoints(
                "/repos/firefly/",
                "[github-read-only]",
                "    github-read-only:\n      - { method: POST, path: /v1/messages }\n      \
                 - { method: GET, path: /repos/*/*/** }\n",
            )),
            Ok(())
        );
    }

    /// Equal prefixes are the case longest-prefix-wins would break by arbitrary tie.
    #[test]
    fn two_equal_prefixes_on_one_host_are_ambiguous() {
        let refusal = checked(&routed(&[(
            "workspace:w",
            &[("api.example", "/repos/"), ("api.example", "/repos/")],
        )]))
        .expect_err("refused");
        assert_eq!(refusal.code, Code::RouteAmbiguous);
    }

    /// The pair that collides is the one a *run* sees: a workspace route and the profile's own.
    #[test]
    fn a_workspace_route_and_its_profiles_own_are_one_set() {
        let refusal = checked(&routed(&[
            ("workspace:w", &[("api.example", "/a/")]),
            ("profile:p", &[("api.example", "/b/")]),
        ]))
        .expect_err("refused");
        assert_eq!(refusal.code, Code::RouteAmbiguous);
        assert!(
            refusal.message().contains("workspace:w.credentials[0]")
                && refusal.message().contains("profile:p.credentials[0]"),
            "{refusal}"
        );
    }

    /// Two workspaces no one profile selects together never meet, so neither pair is a tie anything
    /// has to break.
    #[test]
    fn routes_of_workspaces_no_profile_shares_do_not_collide() {
        let text = "\
version: 1
minters:
  m: { command: [/bin/true] }
workspaces:
  a:
    roots: []
    credentials:
      - { host: api.example, path_prefix: /a/, minter: m, delivery: { env: A } }
  b:
    roots: []
    credentials:
      - { host: api.example, path_prefix: /b/, minter: m, delivery: { env: B } }
profiles:
  only-a: { workspaces: [a], toolchain: [] }
  only-b: { workspaces: [b], toolchain: [] }
";
        assert_eq!(checked(text), Ok(()));
    }
}
