//! Probing the mechanism ([spec §4.2], step 7): before anything is applied, playpen asks the
//! host's mechanism itself which capabilities it offers, and refuses when one the profile requires
//! is missing. The probe is playpen's own and never the backend's, so the refusal survives a
//! change in the backend's defaults ([spec §15.1], [ADR 0003]).
//!
//! [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
//! [spec §15.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#151-the-backend
//! [ADR 0003]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0003-nono-is-the-mechanism-backend.md

use crate::code::Code;
use crate::refusal::Refusal;

/// A capability of the mechanism that a profile can require. The set is closed: a new capability
/// is a variant here, its probe on each platform, and its explicit request in the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Nothing in the confined tree can signal a process outside the sandbox, or connect to an
    /// abstract unix socket created outside it. On Linux, Landlock's signal and abstract-socket
    /// scopes; on macOS, Seatbelt's `same-sandbox` signal target, where abstract sockets do not
    /// exist.
    ProcessScoping,
}

impl Capability {
    /// The name a refusal gives it.
    pub fn name(self) -> &'static str {
        match self {
            Capability::ProcessScoping => {
                "process scoping (signals and abstract unix sockets confined to the sandbox)"
            }
        }
    }
}

/// What every profile requires. The policy has no way yet to require anything further, so this
/// is the resolved profile's requirement whatever the profile.
pub const REQUIRED: &[Capability] = &[Capability::ProcessScoping];

/// Which regime denied a unix-socket **credential oracle** on this host ([spec §6.3]). Stated
/// outward only — in the run record and `playpen explain`, never in the manifest — because it
/// maps what is worth attacking.
///
/// [spec §6.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#63-credential-oracles
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Regime(String);

impl Regime {
    /// The sentence a record and `explain` carry.
    pub fn stated(&self) -> &str {
        &self.0
    }

    /// Seatbelt treats a unix-socket `connect()` as a network operation, and the pinned fork
    /// sends unix sockets through its explicit-grant path rather than granting them all under
    /// `AllowAll`. There are no versions, so there is nothing to probe.
    #[cfg(target_os = "macos")]
    pub fn probe() -> Self {
        Regime("enforced by Seatbelt's explicit unix-socket grant path".to_string())
    }

    /// Landlock enforces a pathname-socket `connect()` from ABI 9, through the `FS_RESOLVE_UNIX`
    /// right the fork's probe negotiates. Below it the surface is unenforceable, so it is a
    /// **named residual** ([spec §18]) rather than a refusal: refusing every launch on a kernel
    /// older than 6.17 would be refusing the host rather than the boundary.
    ///
    /// [spec §18]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#18-named-residuals
    #[cfg(target_os = "linux")]
    pub fn probe() -> Self {
        Regime(landlock_regime(landlock_abi()))
    }
}

impl std::fmt::Display for Regime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The sentence a Landlock version query describes. The ABI that first offers `FS_RESOLVE_UNIX`
/// is read from the `landlock` crate's own table rather than spelled, so it moves with the crate
/// nono is built against.
#[cfg(target_os = "linux")]
fn landlock_regime(abi: std::io::Result<libc::c_long>) -> String {
    use landlock::{ABI, Access, AccessFs};

    let resolve_unix_from = (1..=i32::from(ABI::V9 as u8))
        .find(|&abi| AccessFs::from_all(ABI::from(abi)).contains(AccessFs::ResolveUnix));
    let Ok(abi) = abi else {
        return "unenforced: this kernel offers no Landlock, a named residual".to_string();
    };
    match resolve_unix_from {
        Some(first) if abi >= libc::c_long::from(first) => {
            format!("enforced by Landlock's FS_RESOLVE_UNIX right, on ABI {abi}")
        }
        Some(first) => format!(
            "unenforced: a named residual below Landlock ABI {first}, and this kernel offers ABI \
             {abi}"
        ),
        // The crate nono is built against knows no `FS_RESOLVE_UNIX` at all, so no ABI could be
        // negotiated for it whatever the kernel offers.
        None => format!(
            "unenforced: a named residual, because the pinned Landlock crate knows no \
             FS_RESOLVE_UNIX right; this kernel offers ABI {abi}"
        ),
    }
}

/// The host's mechanism as probed: what it is, for a refusal to name, and what it offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mechanism {
    name: String,
    offers: Vec<Capability>,
}

impl Mechanism {
    pub fn new(name: impl Into<String>, offers: &[Capability]) -> Self {
        Self {
            name: name.into(),
            offers: offers.to_vec(),
        }
    }

    /// Seatbelt has no versions: what it can express is fixed, and `sandbox_init` is linked
    /// rather than looked up, so a macOS that lacked it would not have started playpen at all.
    #[cfg(target_os = "macos")]
    pub fn probe() -> Self {
        Self::new("Seatbelt", &[Capability::ProcessScoping])
    }

    /// Ask the kernel for its Landlock ABI. Never cached, so every launch probes afresh.
    #[cfg(target_os = "linux")]
    pub fn probe() -> Self {
        landlock(landlock_abi())
    }

    /// Refuse with `refusal.mechanism.unavailable`, naming the first of `required` this
    /// mechanism does not offer.
    pub fn require(&self, required: &[Capability]) -> Result<(), Refusal> {
        match required.iter().find(|c| !self.offers.contains(c)) {
            None => Ok(()),
            Some(missing) => Err(Refusal::new(
                Code::MechanismUnavailable,
                format!(
                    "the profile requires {}, which {} does not offer",
                    missing.name(),
                    self.name
                ),
            )),
        }
    }
}

/// `LANDLOCK_CREATE_RULESET_VERSION` from `include/uapi/linux/landlock.h`: with no attribute and
/// a size of 0, `landlock_create_ruleset` returns the highest ABI the kernel offers rather than a
/// ruleset. Neither `libc` nor the `landlock` crate exports it, so it is spelled here.
#[cfg(target_os = "linux")]
const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1 << 0;

/// The kernel's Landlock ABI, straight from the kernel: the backend's own probe stops at an ABI
/// it knows, and its defaults are what this probe must not depend on.
///
/// Public because the denial trace asks the same question with a different answer in mind: it
/// needs the errno, since `ENOSYS` and `EOPNOTSUPP` are two different refusals of the flag
/// ([`crate::trace`]).
#[cfg(target_os = "linux")]
pub fn landlock_abi() -> std::io::Result<libc::c_long> {
    // SAFETY: the version query reads no attribute and writes nothing; it only returns a number.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(abi)
    }
}

/// The mechanism a Landlock version query describes. What each ABI offers is the `landlock`
/// crate's table, from the version nono itself is built against.
#[cfg(target_os = "linux")]
fn landlock(abi: std::io::Result<libc::c_long>) -> Mechanism {
    use landlock::{ABI, Access, Scope, make_bitflags};

    let abi = match abi {
        Ok(abi) => abi,
        Err(err) if err.raw_os_error() == Some(libc::EOPNOTSUPP) => {
            return Mechanism::new("this kernel (Landlock disabled at boot)", &[]);
        }
        Err(err) => {
            return Mechanism::new(format!("this kernel (no Landlock: {err})"), &[]);
        }
    };
    // An ABI above the crate's newest offers at least what that newest one does.
    let known = ABI::from(i32::try_from(abi).unwrap_or(i32::MAX));
    let mut offers = Vec::new();
    if Scope::from_all(known).contains(make_bitflags!(Scope::{Signal | AbstractUnixSocket})) {
        offers.push(Capability::ProcessScoping);
    }
    Mechanism::new(format!("Landlock ABI {abi}"), &offers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mechanism_offering_every_required_capability_is_accepted() {
        let mechanism = Mechanism::new("m", &[Capability::ProcessScoping]);
        assert_eq!(mechanism.require(REQUIRED), Ok(()));
    }

    #[test]
    fn a_missing_capability_refuses_naming_it() {
        let refusal = Mechanism::new("a mechanism offering nothing", &[])
            .require(&[Capability::ProcessScoping])
            .expect_err("refuses");
        assert_eq!(refusal.code, Code::MechanismUnavailable);
        assert!(
            refusal.message().contains("process scoping")
                && refusal.message().contains("a mechanism offering nothing"),
            "{refusal}"
        );
    }

    #[test]
    fn this_host_offers_what_every_profile_requires() {
        assert_eq!(Mechanism::probe().require(REQUIRED), Ok(()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_scopes_processes_from_abi_6() {
        for abi in 1..6 {
            let refusal = landlock(Ok(abi)).require(REQUIRED).expect_err("below 6");
            assert!(
                refusal.message().contains(&format!("Landlock ABI {abi}")),
                "{refusal}"
            );
        }
        for abi in [6, 7, 9, 1000] {
            assert_eq!(landlock(Ok(abi)).require(REQUIRED), Ok(()), "ABI {abi}");
        }
    }

    /// The regime is the one thing playpen says about this surface, so it must say which of the
    /// two it is rather than a sentence that reads the same either way ([spec §6.3]).
    #[cfg(target_os = "linux")]
    #[test]
    fn the_unix_socket_regime_names_enforcement_from_abi_9_and_a_residual_below_it() {
        for abi in 1..9 {
            let stated = landlock_regime(Ok(abi));
            assert!(stated.starts_with("unenforced:"), "ABI {abi}: {stated}");
            assert!(stated.contains("residual"), "ABI {abi}: {stated}");
            assert!(
                stated.contains(&format!("ABI {abi}")),
                "ABI {abi}: {stated}"
            );
        }
        for abi in [9, 10, 1000] {
            let stated = landlock_regime(Ok(abi));
            assert!(stated.starts_with("enforced by"), "ABI {abi}: {stated}");
            assert!(stated.contains("FS_RESOLVE_UNIX"), "ABI {abi}: {stated}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_kernel_with_no_landlock_at_all_enforces_no_unix_socket_regime() {
        let stated = landlock_regime(Err(std::io::Error::from_raw_os_error(libc::ENOSYS)));
        assert!(stated.contains("residual"), "{stated}");
    }

    /// Whatever this host is, the regime is one sentence that says which way it went: a record
    /// carrying an empty one would state nothing.
    #[test]
    fn this_host_states_a_regime() {
        let regime = Regime::probe();
        assert!(!regime.stated().is_empty());
        assert!(
            regime.stated().starts_with("enforced by")
                || regime.stated().starts_with("unenforced:"),
            "{regime}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_kernel_without_landlock_offers_nothing() {
        for errno in [libc::ENOSYS, libc::EOPNOTSUPP] {
            let mechanism = landlock(Err(std::io::Error::from_raw_os_error(errno)));
            assert_eq!(mechanism.offers, []);
        }
    }
}
