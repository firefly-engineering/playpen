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
#[cfg(target_os = "linux")]
fn landlock_abi() -> std::io::Result<libc::c_long> {
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

    #[cfg(target_os = "linux")]
    #[test]
    fn a_kernel_without_landlock_offers_nothing() {
        for errno in [libc::ENOSYS, libc::EOPNOTSUPP] {
            let mechanism = landlock(Err(std::io::Error::from_raw_os_error(errno)));
            assert_eq!(mechanism.offers, []);
        }
    }
}
