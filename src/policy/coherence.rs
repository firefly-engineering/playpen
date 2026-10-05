//! The coherence tier ([spec §10.5]): everything decidable from the policy alone, run at build
//! time by `playpen check` and at launch step 5. Each check is one function over the whole
//! document, so a profile no launch selects is held to the same rules as one that is, and a policy
//! that passes `check` in a build never refuses for coherence at launch.
//!
//! The checks run in a fixed order and the first refusal wins. Each names the policy file, and
//! where the offending value is spanned, its line and column.
//!
//! [spec §10.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#105-validation-tiers

use super::Loaded;
use super::syntax::written_at;
use crate::code::Code;
use crate::refusal::Refusal;

/// One coherence check of the document read from the policy file.
type Check = fn(&Loaded) -> Result<(), Refusal>;

/// Every check, in the order they run. A new coherence code is one more entry here.
const CHECKS: &[Check] = &[workspaces_are_declared, roots_are_absolute];

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
