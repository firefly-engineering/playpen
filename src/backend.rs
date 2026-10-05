//! The seam to the mechanism backend ([spec §15.1]): nono, linked in-process. The backend
//! receives only playpen's [`CapabilitySet`], and every error it returns is translated into a
//! registry code here, never leaked.
//!
//! [spec §15.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#151-the-backend

use std::path::Path;

use nono::{AccessMode, FsCapability, IpcMode, NetworkMode, NonoError, Sandbox, SignalMode};

use crate::capability::{Access, CapabilitySet, PathDenial, PathGrant, Scope};
use crate::code::Code;
use crate::mechanism::{self, Capability};
use crate::record::RunId;
use crate::refusal::Refusal;

/// The tag run `run`'s denials are logged with, so that every process in its tree can be found
/// by it ([spec §14.2]). On macOS the backend attaches it to the profile's default deny, and the
/// kernel logs it with each denial that produces, whatever the denied process's pid
/// ([#124](https://github.com/firefly-engineering/playpen/issues/124)).
///
/// [spec §14.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#142-playpen-explain
#[cfg(target_os = "macos")]
pub fn denial_tag(run: &RunId) -> Option<String> {
    Some(format!("playpen-run-{run}"))
}

/// Landlock has no message to attach to a denial. Linux finds a run's denials by the Landlock
/// domain id instead ([#98](https://github.com/firefly-engineering/playpen/issues/98)).
#[cfg(target_os = "linux")]
pub fn denial_tag(_run: &RunId) -> Option<String> {
    None
}

/// Apply `caps` to the calling process, irrevocably, tagging its denials with `tag` where the
/// platform logs one ([`denial_tag`]).
pub fn apply(caps: &CapabilitySet, tag: Option<&str>) -> Result<(), Refusal> {
    let mut set = compile(caps)?;
    set.set_seatbelt_deny_message(tag.map(str::to_owned));
    #[cfg(target_os = "macos")]
    without_stderr(|| Sandbox::apply_auto(&set)).map_err(|err| applied(caps, err))?;
    #[cfg(target_os = "linux")]
    Sandbox::apply_auto(&set).map(drop).map_err(translate)?;
    Ok(())
}

/// Whether `caps` can be expressed on this platform's mechanism, decided without applying it: what
/// `run` checks before it forks and `explain` before it reports, so both refuse alike.
pub fn check(caps: &CapabilitySet) -> Result<(), Refusal> {
    compile(caps).map(drop)
}

/// Run `apply` with stderr pointed at `/dev/null`, then restore it. libsandbox writes its own
/// account of a failed `sandbox_init` to stderr, beside the `errorbuf` nono hands back; the
/// refusal carries that, and a refusal is one line.
#[cfg(target_os = "macos")]
fn without_stderr<T>(apply: impl FnOnce() -> T) -> T {
    // SAFETY: dup, open, dup2 and close act on descriptors this function owns or on stderr, which
    // it restores before returning; the path is a NUL-terminated literal.
    unsafe {
        let saved = libc::dup(libc::STDERR_FILENO);
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if saved < 0 || null < 0 {
            // Nothing to restore to, or nowhere to point it: apply with stderr as it is.
            for fd in [saved, null].into_iter().filter(|&fd| fd >= 0) {
                libc::close(fd);
            }
            return apply();
        }
        libc::dup2(null, libc::STDERR_FILENO);
        libc::close(null);
        let result = apply();
        libc::dup2(saved, libc::STDERR_FILENO);
        libc::close(saved);
        result
    }
}

/// The compiled-profile ceiling, as `errorbuf` reports a profile over it ([spec §15.3]).
///
/// [spec §15.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#153-the-compiled-profile-ceiling
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ceiling {
    size: u64,
    ceiling: u64,
}

/// Read `errorbuf` as the ceiling's sentence, `data object length <size> exceeds maximum
/// (<ceiling>)`, word for word as macOS 26.6 writes it. `errno` is untouched on this failure, so
/// the sentence is the only account there is. Anything else is not this failure, and keeps its
/// own code.
#[cfg(target_os = "macos")]
fn over_ceiling(errorbuf: &str) -> Option<Ceiling> {
    let words: Vec<&str> = errorbuf.split_whitespace().collect();
    let [
        "data",
        "object",
        "length",
        size,
        "exceeds",
        "maximum",
        ceiling,
    ] = words.as_slice()
    else {
        return None;
    };
    Some(Ceiling {
        size: size.parse().ok()?,
        ceiling: ceiling.strip_prefix('(')?.strip_suffix(')')?.parse().ok()?,
    })
}

/// The refusal for `err`, raised applying `caps`. Over the ceiling, it names the ceiling, the
/// compiled size and the source contributing the most grants, which is where to cut.
#[cfg(target_os = "macos")]
fn applied(caps: &CapabilitySet, err: NonoError) -> Refusal {
    let NonoError::SandboxInit(errorbuf) = &err else {
        return translate(err);
    };
    let Some(Ceiling { size, ceiling }) = over_ceiling(errorbuf) else {
        return translate(err);
    };
    // A grant's source is its provenance up to its index: every root of one toolchain, or of one
    // workspace's roots, is one source.
    let source = |from: &str| from.split('[').next().unwrap_or(from).to_owned();
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for grant in &caps.paths {
        *counts.entry(source(&grant.from)).or_default() += 1;
    }
    let largest = counts
        .iter()
        .max_by_key(|&(_, count)| *count)
        .map(|(source, count)| {
            format!("{source}, with {count} of {} path grants", caps.paths.len())
        })
        .unwrap_or_else(|| "nothing".into());
    Refusal::new(
        Code::BudgetExceeded,
        format!(
            "the compiled profile is {size} bytes, over macOS's ceiling of {ceiling}; the largest \
             contributor is {largest}"
        ),
    )
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
    add_exclusions(&mut set, &caps.exclusions)?;
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
    // A literal grant on a link is a grant on the link itself, never on what it points at: that
    // is granted on its own, at its resolved path ([`crate::resolve`]).
    let meta = grant
        .path
        .symlink_metadata()
        .map_err(|e| missing(&grant.path, &grant.from, e))?;
    if grant.scope == Scope::Literal && meta.file_type().is_symlink() {
        return add_link(set, &grant.path, mode);
    }
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
    if mode != AccessMode::Read {
        return Err(Refusal::new(
            Code::MechanismUnavailable,
            format!("a literal grant on {} cannot be expressed", path.display()),
        ));
    }
    let text = profile_string(path)?;
    set.add_platform_rule(format!("(allow file-read* (literal \"{text}\"))"))
        .map_err(translate)
}

/// `path` as a string a Seatbelt rule can hold: UTF-8, with nothing that would end the string or
/// the line.
#[cfg(target_os = "macos")]
fn profile_string(path: &Path) -> Result<&str, Refusal> {
    path.to_str()
        .filter(|text| {
            !text
                .chars()
                .any(|c| c == '"' || c == '\\' || c.is_control())
        })
        .ok_or_else(|| {
            Refusal::new(
                Code::MechanismUnavailable,
                format!(
                    "the path {} cannot be expressed in a profile",
                    path.display()
                ),
            )
        })
}

/// One deny rule per class an exclusion subtracts. nono emits platform rules after its own allows,
/// and Seatbelt's last matching rule wins, so each overrides whatever grant covers the path.
/// Execute is both halves of running a binary from there: `exec` and mapping it executable.
#[cfg(target_os = "macos")]
fn add_exclusions(set: &mut nono::CapabilitySet, exclusions: &[PathDenial]) -> Result<(), Refusal> {
    for exclusion in exclusions {
        let path = profile_string(&exclusion.path)?;
        for class in &exclusion.classes {
            use crate::capability::Class;
            let operations = match class {
                Class::Read => "file-read*",
                Class::Write => "file-write*",
                Class::Execute => "process-exec* file-map-executable",
            };
            set.add_platform_rule(format!("(deny {operations} (subpath \"{path}\"))"))
                .map_err(translate)?;
        }
    }
    Ok(())
}

/// Landlock is allow-only, and a grant on a directory covers everything beneath it, so it cannot
/// subtract a subpath ([#127]). An exclusion refuses rather than being dropped, which would grant
/// what the policy took away.
///
/// [#127]: https://github.com/firefly-engineering/playpen/issues/127
#[cfg(target_os = "linux")]
fn add_exclusions(_: &mut nono::CapabilitySet, exclusions: &[PathDenial]) -> Result<(), Refusal> {
    match exclusions.first() {
        None => Ok(()),
        Some(exclusion) => Err(Refusal::new(
            Code::MechanismUnavailable,
            format!(
                "{}: Landlock cannot subtract {} from a grant, so exclusions are macOS-only \
                 (https://github.com/firefly-engineering/playpen/issues/127)",
                exclusion.from,
                exclusion.path.display()
            ),
        )),
    }
}

/// Seatbelt checks a path through a link against the link as well as its target, so the link
/// itself is granted, alone.
#[cfg(target_os = "macos")]
fn add_link(set: &mut nono::CapabilitySet, path: &Path, mode: AccessMode) -> Result<(), Refusal> {
    add_literal_dir(set, path, mode)
}

/// Landlock gates what a path resolves to and never the walk to it, so a link needs no grant of
/// its own.
#[cfg(target_os = "linux")]
fn add_link(_: &mut nono::CapabilitySet, _: &Path, _: AccessMode) -> Result<(), Refusal> {
    Ok(())
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

    /// The tag a run's denials are logged with: one shape, read by `explain` and applied here.
    #[test]
    #[cfg(target_os = "macos")]
    fn a_runs_denials_are_tagged_with_its_run_id() {
        let run = RunId::parse("01M45GQTY3RF111ZQ8WPJ5SKTY").expect("a run id");
        assert_eq!(
            denial_tag(&run).as_deref(),
            Some("playpen-run-01M45GQTY3RF111ZQ8WPJ5SKTY")
        );
    }

    /// Landlock has no message to attach; Linux finds a run's denials by its domain id (#98).
    #[test]
    #[cfg(target_os = "linux")]
    fn linux_tags_no_denials() {
        let run = RunId::parse("01M45GQTY3RF111ZQ8WPJ5SKTY").expect("a run id");
        assert_eq!(denial_tag(&run), None);
    }

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
                state_derived: false,
            }],
            mach_services: vec![],
            exclusions: vec![],
        };
        let r = compile(&caps).unwrap_err();
        assert_eq!(r.code, Code::RootMissing);
        assert!(r.to_string().contains("workspace:w.roots[0]"));
    }

    fn excluding(classes: Vec<crate::capability::Class>) -> CapabilitySet {
        let dir = std::env::temp_dir();
        CapabilitySet {
            paths: vec![PathGrant {
                path: dir.clone(),
                access: Access::ReadWrite,
                scope: Scope::Subtree,
                from: "workspace:w.roots[0]".into(),
                state_derived: false,
            }],
            exclusions: vec![crate::capability::PathDenial {
                path: dir.join("secrets"),
                classes,
                from: "workspace:w.roots[0].exclude[0]".into(),
            }],
            mach_services: vec![],
        }
    }

    /// Seatbelt's last matching rule wins, and nono emits platform rules after its allows, so a
    /// deny rule per class subtracts the exclusion from whatever grant covers it.
    #[test]
    #[cfg(target_os = "macos")]
    fn an_exclusion_is_a_deny_rule_per_class() {
        use crate::capability::Class;
        let set = compile(&excluding(Class::ALL.to_vec())).expect("compiles");
        let secrets = std::env::temp_dir().join("secrets");
        let secrets = secrets.display();
        for rule in [
            format!("(deny file-read* (subpath \"{secrets}\"))"),
            format!("(deny file-write* (subpath \"{secrets}\"))"),
            format!("(deny process-exec* file-map-executable (subpath \"{secrets}\"))"),
        ] {
            assert!(
                set.platform_rules().contains(&rule),
                "{rule} in {:?}",
                set.platform_rules()
            );
        }
        let set = compile(&excluding(vec![Class::Write])).expect("compiles");
        let denies: Vec<_> = set
            .platform_rules()
            .iter()
            .filter(|rule| rule.contains("secrets"))
            .collect();
        assert_eq!(
            denies,
            [&format!("(deny file-write* (subpath \"{secrets}\"))")]
        );
    }

    /// Landlock cannot subtract a subpath (#127), so an exclusion refuses rather than being
    /// granted silently.
    #[test]
    #[cfg(target_os = "linux")]
    fn an_exclusion_refuses_on_linux() {
        let refusal =
            compile(&excluding(crate::capability::Class::ALL.to_vec())).expect_err("refused");
        assert_eq!(refusal.code, Code::MechanismUnavailable);
        assert!(
            refusal
                .message()
                .contains("workspace:w.roots[0].exclude[0]"),
            "{refusal}"
        );
        assert!(refusal.message().contains("issues/127"), "{refusal}");
    }

    /// `errorbuf`'s sentence for a profile over the ceiling, as macOS 26.6 writes it.
    #[test]
    #[cfg(target_os = "macos")]
    fn the_ceilings_sentence_is_read_for_size_and_ceiling() {
        assert_eq!(
            over_ceiling("data object length 72815 exceeds maximum (65535)"),
            Some(Ceiling {
                size: 72815,
                ceiling: 65535
            })
        );
        for other in [
            "profile rejected",
            "data object length lots exceeds maximum (65535)",
            "data object length 72815 exceeds maximum 65535",
            "data object length 72815 exceeds maximum (65535) and more",
        ] {
            assert_eq!(over_ceiling(other), None, "{other}");
        }
    }

    /// Over the ceiling is `refusal.budget.exceeded`, naming the ceiling, the size and the source
    /// that contributed the most grants; any other failure keeps its own code.
    #[test]
    #[cfg(target_os = "macos")]
    fn a_profile_over_the_ceiling_is_a_budget_refusal() {
        let grant = |from: &str| PathGrant {
            path: "/x".into(),
            access: Access::Read,
            scope: Scope::Subtree,
            from: from.into(),
            state_derived: false,
        };
        let caps = CapabilitySet {
            paths: vec![
                grant("floor"),
                grant("profile:p.toolchain[0]"),
                grant("profile:p.toolchain[1]"),
                grant("workspace:w.roots[0]"),
            ],
            ..CapabilitySet::default()
        };
        let refusal = applied(
            &caps,
            NonoError::SandboxInit("data object length 72815 exceeds maximum (65535)".into()),
        );
        assert_eq!(refusal.code, Code::BudgetExceeded);
        for named in ["65535", "72815", "profile:p.toolchain", "2 of 4"] {
            assert!(refusal.message().contains(named), "{named}: {refusal}");
        }
        let other = applied(&caps, NonoError::SandboxInit("profile rejected".into()));
        assert_eq!(other.code, Code::MechanismUnavailable);
    }
}
