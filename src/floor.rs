//! The floor ([spec §8.2]): built in, always applied, neither widenable nor narrowable by policy.
//! It decides whether `exec` returns, never what is reachable: read and execute only, only under
//! OS-owned paths, never anything under `$HOME`, never a package store.
//!
//! How the floor is spelled never appears in a test; its behaviour is tested instead.
//!
//! [spec §8.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#82-the-floor

use std::path::Path;

use crate::capability::{Access, CapabilitySet, PathGrant, Scope};

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

/// Mach services: trust evaluation, and the notify and directory-lookup essentials that libSystem
/// reaches during ordinary startup. The Keychain's services (`com.apple.SecurityServer`,
/// `securityd`, the XPC variant) are absent and so denied, with no knob to re-add them.
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
pub fn floor() -> CapabilitySet {
    let read = PATHS
        .iter()
        .map(|&(path, scope)| (path, Access::Read, scope));
    let sinks = SINKS
        .iter()
        .map(|&path| (path, Access::ReadWrite, Scope::Subtree));
    CapabilitySet {
        paths: read
            .chain(sinks)
            .filter(|(path, _, _)| Path::new(path).exists())
            .map(|(path, access, scope)| PathGrant {
                path: path.into(),
                access,
                scope,
                from: FROM.into(),
            })
            .collect(),
        mach_services: MACH_SERVICES.iter().map(|s| s.to_string()).collect(),
    }
}
