//! The floor ([spec §8.2]): built in, always applied, neither widenable nor narrowable by policy.
//! It decides whether `exec` returns, never what is reachable: read and execute only, only under
//! OS-owned paths, never anything under `$HOME`, never a coarse package store.
//!
//! On a host whose OS *is* a package store the literal path list below is empty of libraries: a
//! NixOS binary names its interpreter and every library it needs by store path, so no list of
//! FHS directories can let one `exec`. Such a host supplies a **dedicated floor** instead — a
//! generated directory carrying the canary and the declared closure it needs, one store path per
//! line ([`dedicated`]). The floor is then one root per line, never a coarse `/nix/store` root,
//! which would be the leak [spec §8.3] describes.
//!
//! A dedicated floor describes *where this host keeps its OS*; it is not policy. No policy
//! document can name or reach it, so the floor stays neither widenable nor narrowable by policy
//! ([ADR 0014]).
//!
//! How the floor is spelled never appears in a test; its behaviour is tested instead.
//!
//! [spec §8.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#82-the-floor
//! [spec §8.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#83-toolchain
//! [ADR 0014]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0014-the-toolchain-is-a-declared-closure.md

use std::path::{Path, PathBuf};

use crate::capability::{Access, CapabilitySet, PathGrant, Scope};
use crate::code::Code;
use crate::refusal::Refusal;

const FROM: &str = "floor";

#[cfg(target_os = "macos")]
const PATHS: &[(&str, Scope)] = &[
    // Without the root's own entry every dynamically linked binary aborts with rc=134.
    ("/", Scope::Literal),
    // libSystem stats the data volume's mount point at startup; denied, it reports the denial
    // over the syslog socket, which the process then holds for its lifetime.
    ("/System/Volumes/Data", Scope::Literal),
    ("/bin", Scope::Subtree),
    ("/sbin", Scope::Subtree),
    ("/usr/bin", Scope::Subtree),
    ("/usr/sbin", Scope::Subtree),
    ("/usr/lib", Scope::Subtree),
    ("/usr/libexec", Scope::Subtree),
    ("/usr/share", Scope::Subtree),
    ("/System/Library", Scope::Subtree),
    ("/System/Cryptexes", Scope::Subtree),
    ("/System/Volumes/Preboot/Cryptexes", Scope::Subtree),
    ("/private/var/db/dyld", Scope::Subtree),
    ("/private/var/db/timezone", Scope::Subtree),
    // `/bin/sh` reads its implementation choice here.
    ("/private/var/select", Scope::Subtree),
    ("/private/etc/localtime", Scope::Subtree),
    ("/dev", Scope::Subtree),
];

#[cfg(target_os = "linux")]
const PATHS: &[(&str, Scope)] = &[
    ("/bin", Scope::Subtree),
    ("/sbin", Scope::Subtree),
    ("/usr/bin", Scope::Subtree),
    ("/usr/sbin", Scope::Subtree),
    ("/lib", Scope::Subtree),
    ("/lib32", Scope::Subtree),
    ("/lib64", Scope::Subtree),
    ("/usr/lib", Scope::Subtree),
    ("/usr/lib32", Scope::Subtree),
    ("/usr/lib64", Scope::Subtree),
    ("/usr/libexec", Scope::Subtree),
    ("/etc/ld.so.cache", Scope::Subtree),
    ("/etc/ld.so.conf", Scope::Subtree),
    ("/etc/ld.so.conf.d", Scope::Subtree),
    ("/proc", Scope::Subtree),
    ("/dev", Scope::Subtree),
];

/// The null device is a sink, not storage: writing to it reveals and keeps nothing, and a
/// program that cannot open it for writing breaks in ways unrelated to its boundary.
const SINKS: &[&str] = &["/dev/null"];

/// Names a dedicated floor, for an operator whose OS is not an FHS tree. It describes the host,
/// never a boundary: it selects *which* OS the floor is drawn from, and cannot add a path to it,
/// because every grant still comes from that floor's own generated closure.
pub const FLOOR_ENV: &str = "PLAYPEN_FLOOR";

/// Where the Nix module installs the floor it generates ([spec §16.1]). This is the default on a
/// NixOS host: the floor comes from the running system generation, which is OS-owned, read-only
/// and root-owned, and excludes every per-user profile, so no `home-manager-files` generation and
/// none of the stale dotfiles [spec §8.3] warns about are inside it.
///
/// The closure is read from a file the generator wrote, never computed here: enumerating the
/// system closure costs a `nix-store` query and some 3300 roots on the reference host, and the
/// self-test's verdict is never cached, so that price would be paid at every launch.
///
/// [spec §16.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#161-nix
#[cfg(target_os = "linux")]
const SYSTEM_FLOOR: &str = "/run/current-system/sw/share/playpen/floor";

/// The dedicated floor in effect: [`FLOOR_ENV`] if set, else the one the Nix module installed in
/// the system closure, else none. An FHS host needs none and gets none.
pub fn dedicated() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os(FLOOR_ENV) {
        return Some(PathBuf::from(dir));
    }
    #[cfg(target_os = "linux")]
    {
        let system = Path::new(SYSTEM_FLOOR);
        if system.is_dir() {
            return Some(system.to_path_buf());
        }
    }
    None
}

/// Where an FHS host keeps its OS binaries, searched in order. `/bin` comes first because it holds
/// them with and without a merged `/usr`; `/usr/bin` covers what `/bin` lacks, such as `true` on
/// macOS. Both are floor paths on every platform, so whatever is found here runs under the floor.
const FHS_BIN_DIRS: &[&str] = &["/bin", "/usr/bin"];

/// The OS binary `name` as this host's floor holds it: inside the dedicated floor where there is
/// one, else the first of the FHS binary directories that has it. Resolved per call, like
/// [`dedicated`], since the answer is a property of the host as it is now.
///
/// When no directory holds it, the error lists every path looked at, in search order.
pub fn binary(name: &str) -> Result<PathBuf, Vec<PathBuf>> {
    let candidates: Vec<PathBuf> = match dedicated() {
        Some(dir) => vec![dir.join("bin").join(name)],
        None => FHS_BIN_DIRS
            .iter()
            .map(|dir| Path::new(dir).join(name))
            .collect(),
    };
    match candidates.iter().find(|path| path.exists()) {
        Some(found) => Ok(found.clone()),
        None => Err(candidates),
    }
}

/// One read-and-execute root per store path in `dir`'s declared closure, plus `dir` itself so the
/// canary's own symlink is readable. The closure file is the generator's output and this is its
/// only reader; a floor without one cannot let anything `exec`, so that is a refusal, not an
/// empty grant list that would fail later as a confusing canary failure.
fn dedicated_grants(dir: &Path) -> Result<Vec<PathGrant>, Refusal> {
    let list = dir.join("closure");
    let text = std::fs::read_to_string(&list).map_err(|err| {
        Refusal::new(
            Code::FloorUnavailable,
            format!(
                "the dedicated floor {} has no readable closure at {}: {err} \
                 (build one with `nix build .#floor` and name it in {FLOOR_ENV})",
                dir.display(),
                list.display()
            ),
        )
    })?;
    let from = format!("floor:{}", dir.display());
    let mut grants: Vec<PathGrant> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|path| PathGrant {
            path: path.into(),
            access: Access::Read,
            scope: Scope::Subtree,
            from: from.clone(),
            // A declared closure is read from a PLAYPEN_FLOOR-selected directory, not computed
            // from the state directory, so it is checked like any other grant (ADR 0027).
            state_derived: false,
        })
        .collect();
    if grants.is_empty() {
        return Err(Refusal::new(
            Code::FloorUnavailable,
            format!(
                "the dedicated floor {} declares an empty closure at {}",
                dir.display(),
                list.display()
            ),
        ));
    }
    grants.push(PathGrant {
        path: dir.into(),
        access: Access::Read,
        scope: Scope::Subtree,
        from,
        state_derived: false,
    });
    Ok(grants)
}

/// Mach services: trust evaluation, and the notify and directory-lookup essentials that libSystem
/// reaches during ordinary startup. The Keychain's services (`com.apple.SecurityServer` and the
/// `com.apple.securityd.*` family, as `N-keychain` enumerates them) are absent and so denied, with
/// no knob to re-add them ([spec §8.2]).
///
/// [spec §8.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#82-the-floor
#[cfg(target_os = "macos")]
const MACH_SERVICES: &[&str] = &[
    "com.apple.trustd",
    "com.apple.trustd.agent",
    "com.apple.system.notification_center",
    // getpwuid and friends: without it a user resolves to a bare uid.
    "com.apple.system.opendirectoryd.libinfo",
];

#[cfg(target_os = "linux")]
const MACH_SERVICES: &[&str] = &[];

/// The floor for this platform, as a capability set. Entries a host lacks (a `/lib32` on a
/// 64-bit-only distribution, a cryptex volume on an older macOS) are omitted: the floor grants
/// what exists, and grants nothing in place of what does not.
///
/// A dedicated floor contributes its declared closure on top of whatever OS-owned paths exist,
/// because `/proc` and `/dev` are still the kernel's and still required.
pub fn floor() -> Result<CapabilitySet, Refusal> {
    let read = PATHS
        .iter()
        .map(|&(path, scope)| (path, Access::Read, scope));
    let sinks = SINKS
        .iter()
        .map(|&path| (path, Access::ReadWrite, Scope::Subtree));
    let mut paths: Vec<PathGrant> = read
        .chain(sinks)
        .filter(|(path, _, _)| Path::new(path).exists())
        .map(|(path, access, scope)| PathGrant {
            path: path.into(),
            access,
            scope,
            from: FROM.into(),
            // The compiled-in FHS floor never reaches under $HOME, so this can never trigger
            // the state-reachability check — but it is checked, not exempted (ADR 0027).
            state_derived: false,
        })
        .collect();
    if let Some(dir) = dedicated() {
        paths.extend(dedicated_grants(&dir)?);
    }
    Ok(CapabilitySet {
        paths,
        mach_services: MACH_SERVICES.iter().map(|s| s.to_string()).collect(),
    })
}
