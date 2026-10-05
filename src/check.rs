//! `playpen check` ([spec §10.5]): validate a policy without launching anything.
//!
//! The parser-contract tier always runs. The existence tier runs unless `--no-filesystem` is given,
//! which is how a build validates a policy in a sandbox that has none of this host's paths: an
//! existence check is a fact about this host at this moment, never about the document.
//!
//! `check` launches nothing, so like `explain` it opens no run record and its refusal line ends at
//! the offending value. On success it writes nothing.
//!
//! [spec §10.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#105-validation-tiers

use std::path::{Path, PathBuf};

use crate::code::Code;
use crate::policy::Policy;
use crate::refusal::Refusal;

#[derive(Debug, clap::Args)]
pub struct Args {
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Run only the tiers decidable from the document: look at nothing on this host.
    #[arg(long)]
    no_filesystem: bool,
}

/// Validate the policy `args` names.
pub fn check(args: &Args) -> Result<(), Refusal> {
    let path = args.policy.as_deref().ok_or_else(|| {
        Refusal::new(
            Code::PolicyNotFound,
            "no policy given; pass --policy <path>",
        )
    })?;
    let loaded = Policy::load(path)?;
    if args.no_filesystem {
        return Ok(());
    }
    existence(&loaded.policy)
}

/// The existence tier over the whole document: every path a launch of any profile would need to
/// find. A relative path is the coherence tier's to refuse, so it is not looked up here.
fn existence(policy: &Policy) -> Result<(), Refusal> {
    let exists = |path: &Path, code: Code, from: &str| {
        if !path.is_absolute() {
            return Ok(());
        }
        path.canonicalize().map(drop).map_err(|e| {
            Refusal::new(
                code,
                format!("{from}: {} is unavailable: {e}", path.display()),
            )
        })
    };
    let exclusions = |exclusions: &[crate::policy::Exclusion], from: &str| {
        exclusions
            .iter()
            .enumerate()
            .try_for_each(|(i, exclusion)| {
                exists(
                    &exclusion.path,
                    Code::ExclusionMissing,
                    &format!("{from}.exclude[{i}]"),
                )
            })
    };
    for (name, workspace) in &policy.workspaces {
        for (i, root) in workspace.roots.iter().enumerate() {
            let from = format!("workspace:{name}.roots[{i}]");
            exists(&root.path, Code::RootMissing, &from)?;
            exclusions(&root.exclude, &from)?;
        }
    }
    for (name, profile) in &policy.profiles {
        for (i, root) in profile.toolchain.iter().enumerate() {
            let from = format!("profile:{name}.toolchain[{i}]");
            exists(&root.path, Code::RootMissing, &from)?;
            exclusions(&root.exclude, &from)?;
        }
    }
    for (name, shim) in &policy.shims {
        exists(
            &shim.target,
            Code::RootMissing,
            &format!("shim:{name}.target"),
        )?;
    }
    Ok(())
}
