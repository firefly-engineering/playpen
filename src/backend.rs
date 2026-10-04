//! The seam to the mechanism backend ([spec §15.1]): nono, linked in-process. The backend
//! receives only playpen's [`CapabilitySet`], and every error it returns is translated into a
//! registry code here, never leaked.
//!
//! [spec §15.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#151-the-backend

use std::path::Path;

use nono::{AccessMode, FsCapability, IpcMode, NetworkMode, NonoError, Sandbox, SignalMode};

use crate::capability::{Access, CapabilitySet, PathGrant, Scope};
use crate::code::Code;
use crate::mechanism::{self, Capability};
use crate::refusal::Refusal;

/// Apply `caps` to the calling process, irrevocably.
pub fn apply(caps: &CapabilitySet) -> Result<(), Refusal> {
    let set = compile(caps)?;
    #[cfg(target_os = "macos")]
    Sandbox::apply_auto(&set).map_err(translate)?;
    #[cfg(target_os = "linux")]
    Sandbox::apply_auto(&set).map(drop).map_err(translate)?;
    Ok(())
}

/// Translate playpen's capability set into nono's.
fn compile(caps: &CapabilitySet) -> Result<nono::CapabilitySet, Refusal> {
    // playpen claims credential confinement only; the network is not a confined surface (ADR 0020).
    let mut set = nono::CapabilitySet::new().set_network_mode(NetworkMode::AllowAll);
    for &capability in mechanism::REQUIRED {
        request(&mut set, capability);
    }
    for grant in &caps.paths {
        add_path(&mut set, grant)?;
    }
    add_mach_services(&mut set, &caps.mach_services)?;
    Ok(set)
}

/// Request a required capability explicitly, never through a backend default: an explicit request
/// is what fails closed should the probe ([`mechanism`]) ever pass a mechanism that lacks it.
fn request(set: &mut nono::CapabilitySet, capability: Capability) {
    match capability {
        Capability::ProcessScoping => {
            // Not the default `Isolated`, which nono drops quietly below Landlock ABI 6: on a
            // kernel that offers the scope the two are the same, and on one that does not this
            // one refuses.
            set.set_signal_mode_mut(SignalMode::AllowSameSandbox);
            // The default, stated. nono drops it quietly below ABI 6 and has no explicit mode that
            // refuses instead, so for abstract sockets playpen's own probe is the only refusal.
            set.set_ipc_mode_mut(IpcMode::SharedMemoryOnly);
        }
    }
}

fn add_path(set: &mut nono::CapabilitySet, grant: &PathGrant) -> Result<(), Refusal> {
    let mode = match grant.access {
        Access::Read => AccessMode::Read,
        Access::ReadWrite => AccessMode::ReadWrite,
    };
    let is_dir = grant
        .path
        .metadata()
        .map_err(|e| missing(&grant.path, &grant.from, e))?
        .is_dir();
    match (grant.scope, is_dir) {
        (Scope::Subtree, true) => {
            set.add_fs(FsCapability::new_dir(&grant.path, mode).map_err(translate)?)
        }
        (_, false) => set.add_fs(FsCapability::new_file(&grant.path, mode).map_err(translate)?),
        (Scope::Literal, true) => add_literal_dir(set, &grant.path, mode)?,
    }
    Ok(())
}

fn missing(path: &Path, from: &str, err: std::io::Error) -> Refusal {
    Refusal::new(
        Code::RootMissing,
        format!("{} ({from}) cannot be granted: {err}", path.display()),
    )
}

#[cfg(target_os = "macos")]
fn add_literal_dir(
    set: &mut nono::CapabilitySet,
    path: &Path,
    mode: AccessMode,
) -> Result<(), Refusal> {
    let unsupported = || {
        Refusal::new(
            Code::MechanismUnavailable,
            format!("a literal grant on {} cannot be expressed", path.display()),
        )
    };
    let text = path.to_str().ok_or_else(unsupported)?;
    if mode != AccessMode::Read
        || text
            .chars()
            .any(|c| c == '"' || c == '\\' || c.is_control())
    {
        return Err(unsupported());
    }
    set.add_platform_rule(format!("(allow file-read* (literal \"{text}\"))"))
        .map_err(translate)
}

#[cfg(target_os = "linux")]
fn add_literal_dir(_: &mut nono::CapabilitySet, path: &Path, _: AccessMode) -> Result<(), Refusal> {
    Err(Refusal::new(
        Code::MechanismUnavailable,
        format!(
            "Landlock cannot grant the directory {} without its contents",
            path.display()
        ),
    ))
}

/// Deny every Mach service, by global and by per-user lookup, then allow the enumerated ones.
/// nono emits platform rules last, and Seatbelt's last matching rule wins, so this replaces nono's
/// blanket `mach-lookup` and `mach-per-user-lookup` allowances.
#[cfg(target_os = "macos")]
fn add_mach_services(set: &mut nono::CapabilitySet, services: &[String]) -> Result<(), Refusal> {
    set.add_platform_rule("(deny mach-lookup)")
        .map_err(translate)?;
    set.add_platform_rule("(deny mach-per-user-lookup)")
        .map_err(translate)?;
    for service in services {
        if !service
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            return Err(Refusal::new(
                Code::MechanismUnavailable,
                format!("Mach service name {service:?} cannot be expressed"),
            ));
        }
        set.add_platform_rule(format!("(allow mach-lookup (global-name \"{service}\"))"))
            .map_err(translate)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn add_mach_services(_: &mut nono::CapabilitySet, services: &[String]) -> Result<(), Refusal> {
    match services {
        [] => Ok(()),
        _ => Err(Refusal::new(
            Code::MechanismUnavailable,
            "Mach services do not exist on Linux",
        )),
    }
}

/// Translate a backend error into a registry code. The backend's own words travel as the value;
/// its error type never reaches a consumer.
fn translate(err: NonoError) -> Refusal {
    let code = match &err {
        NonoError::PathNotFound(_)
        | NonoError::ExpectedDirectory(_)
        | NonoError::ExpectedFile(_)
        | NonoError::PathCanonicalization { .. } => Code::RootMissing,
        NonoError::SandboxInit(_)
        | NonoError::UnsupportedPlatform(_)
        | NonoError::NetworkFilterUnsupported { .. } => Code::MechanismUnavailable,
        #[cfg(target_os = "linux")]
        NonoError::Landlock(_) | NonoError::LandlockPath(_) => Code::MechanismUnavailable,
        // Nothing else is reachable from compiling or applying a capability set. Should the
        // backend grow a new failure, it still surfaces under a registry code, named as a bug.
        _ => {
            return Refusal::new(
                Code::MechanismUnavailable,
                format!("untranslated backend error (a playpen bug): {err}"),
            );
        }
    };
    Refusal::new(code, format!("backend: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_init_failure_is_mechanism_unavailable() {
        let r = translate(NonoError::SandboxInit("profile rejected".into()));
        assert_eq!(r.code, Code::MechanismUnavailable);
        assert!(r.to_string().contains("profile rejected"));
    }

    #[test]
    fn a_vanished_path_is_root_missing() {
        let r = translate(NonoError::PathNotFound("/gone".into()));
        assert_eq!(r.code, Code::RootMissing);
    }

    #[test]
    fn an_unexpected_error_still_carries_a_registry_code() {
        let r = translate(NonoError::HomeNotFound);
        assert_eq!(r.code, Code::MechanismUnavailable);
    }

    #[test]
    fn process_scoping_is_requested_explicitly() {
        let set = compile(&CapabilitySet::default()).expect("compiles");
        assert_eq!(set.signal_mode(), SignalMode::AllowSameSandbox);
        assert_eq!(set.ipc_mode(), IpcMode::SharedMemoryOnly);
    }

    #[test]
    fn a_missing_grant_refuses_before_reaching_the_backend() {
        let caps = CapabilitySet {
            paths: vec![PathGrant {
                path: "/nonexistent/playpen-test-root".into(),
                access: Access::Read,
                scope: Scope::Subtree,
                from: "workspace:w.roots[0]".into(),
            }],
            mach_services: vec![],
        };
        let r = compile(&caps).unwrap_err();
        assert_eq!(r.code, Code::RootMissing);
        assert!(r.to_string().contains("workspace:w.roots[0]"));
    }
}
