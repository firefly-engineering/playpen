//! Self-integrity ([spec §11.7]): nothing that runs unconfined on the next launch may be writable
//! by the selected profile. A profile that could write the policy, or the playpen executable, could
//! widen its own boundary from inside, and the widening would take effect the next time playpen
//! ran.
//!
//! The agent binary is deliberately not checked: tampering with it lands inside the boundary on
//! the next run.
//!
//! [spec §11.7]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#117-self-integrity

use std::path::{Path, PathBuf};

use crate::capability::{Access, CapabilitySet, Class, Scope};
use crate::code::Code;
use crate::refusal::Refusal;

/// Refuse if `caps` lets the confined tree write the policy file at `policy` or the playpen
/// executable at `executable`.
pub fn check(caps: &CapabilitySet, policy: &Path, executable: &Path) -> Result<(), Refusal> {
    for (what, path) in [
        ("the policy file", policy),
        ("the playpen executable", executable),
    ] {
        for entry in entries(what, path)? {
            if let Some(from) = writable_by(caps, &entry) {
                return Err(Refusal::new(
                    Code::IntegrityWritable,
                    format!(
                        "{what} {} is writable from inside the boundary through {} ({from}), \
                         and runs unconfined on the next launch",
                        path.display(),
                        entry.path.display(),
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// The running executable, read once by `main`, or the refusal that its integrity cannot be shown.
pub fn executable(executable: &std::io::Result<PathBuf>) -> Result<PathBuf, Refusal> {
    executable.as_ref().cloned().map_err(|e| {
        Refusal::new(
            Code::IntegrityWritable,
            format!(
                "the playpen executable cannot be found, so it cannot be shown unwritable: {e}"
            ),
        )
    })
}

/// One directory entry the next launch passes through to reach the file, as the mechanism sees it:
/// the entry itself, located through its resolved parent, so a link is the link and not where it
/// leads.
struct Entry {
    path: PathBuf,
    /// The file itself, rather than a directory on the way to it.
    is_file: bool,
}

/// Every entry on the way to `path`, both as it was found and as it finally resolves: the file,
/// each directory above it, and each link among them. Replacing any of them replaces the file.
fn entries(what: &str, path: &Path) -> Result<Vec<Entry>, Refusal> {
    // Integrity that cannot be shown is refused, never assumed.
    let unresolvable = |e: std::io::Error| {
        Refusal::new(
            Code::IntegrityWritable,
            format!(
                "{what} {} cannot be resolved, so it cannot be shown unwritable: {e}",
                path.display()
            ),
        )
    };
    let resolved = path.canonicalize().map_err(unresolvable)?;
    let mut entries = Vec::new();
    for (form, is_resolved) in [(path, false), (resolved.as_path(), true)] {
        for (depth, prefix) in form.ancestors().enumerate() {
            let (Some(parent), Some(name)) = (prefix.parent(), prefix.file_name()) else {
                continue;
            };
            let parent = if is_resolved {
                parent.to_owned()
            } else {
                parent.canonicalize().map_err(unresolvable)?
            };
            entries.push(Entry {
                path: parent.join(name),
                is_file: depth == 0,
            });
        }
    }
    Ok(entries)
}

/// The provenance of the grant that lets the confined tree replace `entry`, unless an exclusion
/// takes that write away again. The file is replaceable wherever a read-write grant covers it; a
/// directory on the way only where the grant holds the directory's own parent, since a grant on
/// the directory itself cannot move it.
fn writable_by<'a>(caps: &'a CapabilitySet, entry: &Entry) -> Option<&'a str> {
    let path = entry.path.as_path();
    let excluded = caps.exclusions.iter().any(|exclusion| {
        exclusion.classes.contains(&Class::Write) && path.starts_with(&exclusion.path)
    });
    if excluded {
        return None;
    }
    caps.paths
        .iter()
        .filter(|grant| grant.access == Access::ReadWrite)
        .find(|grant| match grant.scope {
            Scope::Subtree => {
                path.starts_with(&grant.path) && (entry.is_file || path != grant.path)
            }
            Scope::Literal => entry.is_file && path == grant.path,
        })
        .map(|grant| grant.from.as_str())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::*;
    use crate::capability::{PathDenial, PathGrant};

    fn grant(path: &Path, access: Access) -> PathGrant {
        PathGrant {
            path: path.canonicalize().expect("canonical"),
            access,
            scope: Scope::Subtree,
            from: "workspace:w.roots[0]".into(),
            state_derived: false,
        }
    }

    fn caps(grants: Vec<PathGrant>) -> CapabilitySet {
        CapabilitySet {
            paths: grants,
            ..CapabilitySet::default()
        }
    }

    /// A policy file and an executable, each in a directory of its own.
    struct Files {
        policy_dir: TempDir,
        exe_dir: TempDir,
    }

    impl Files {
        fn new() -> Self {
            let files = Self {
                policy_dir: TempDir::new().expect("policy dir"),
                exe_dir: TempDir::new().expect("exe dir"),
            };
            std::fs::write(files.policy(), "version: 1\n").expect("policy");
            std::fs::write(files.executable(), "").expect("executable");
            files
        }

        fn policy(&self) -> PathBuf {
            self.policy_dir.path().join("policy.yaml")
        }

        fn executable(&self) -> PathBuf {
            self.exe_dir.path().join("playpen")
        }

        fn check(&self, caps: &CapabilitySet) -> Result<(), Refusal> {
            check(caps, &self.policy(), &self.executable())
        }
    }

    #[test]
    fn nothing_writable_passes() {
        let files = Files::new();
        let read = caps(vec![
            grant(files.policy_dir.path(), Access::Read),
            grant(files.exe_dir.path(), Access::Read),
        ]);
        assert_eq!(files.check(&read), Ok(()));
    }

    /// A writable directory containing the policy can replace it as surely as a writable file.
    #[test]
    fn a_writable_directory_containing_the_policy_refuses() {
        let files = Files::new();
        let refusal = files
            .check(&caps(vec![grant(
                files.policy_dir.path(),
                Access::ReadWrite,
            )]))
            .expect_err("refused");
        assert_eq!(refusal.code, Code::IntegrityWritable);
        let named = files.policy().canonicalize().expect("canonical");
        assert!(
            refusal.message().contains(named.to_str().unwrap()),
            "{refusal}"
        );
        assert!(
            refusal.message().contains("workspace:w.roots[0]"),
            "{refusal}"
        );
    }

    #[test]
    fn a_writable_ancestor_refuses() {
        let files = Files::new();
        let ancestor = files.policy_dir.path().parent().expect("a parent");
        let refusal = files
            .check(&caps(vec![grant(ancestor, Access::ReadWrite)]))
            .expect_err("refused");
        assert_eq!(refusal.code, Code::IntegrityWritable);
    }

    #[test]
    fn a_writable_executable_refuses() {
        let files = Files::new();
        let refusal = files
            .check(&caps(vec![grant(files.exe_dir.path(), Access::ReadWrite)]))
            .expect_err("refused");
        assert_eq!(refusal.code, Code::IntegrityWritable);
        let named = files.executable().canonicalize().expect("canonical");
        assert!(
            refusal.message().contains(named.to_str().unwrap()),
            "{refusal}"
        );
    }

    /// The policy is checked where it was found as well as where it resolves: a writable link in
    /// front of it can be repointed.
    #[test]
    fn a_writable_link_to_the_policy_refuses() {
        let files = Files::new();
        let links = TempDir::new().expect("links");
        let link = links.path().join("policy.yaml");
        std::os::unix::fs::symlink(files.policy(), &link).expect("symlink");
        let writable = caps(vec![grant(links.path(), Access::ReadWrite)]);
        let refusal = check(&writable, &link, &files.executable()).expect_err("refused");
        assert_eq!(refusal.code, Code::IntegrityWritable);
    }

    /// An exclusion that takes write away leaves nothing to tamper with.
    #[test]
    fn a_write_exclusion_covering_the_policy_passes() {
        let files = Files::new();
        let mut excluded = caps(vec![grant(files.policy_dir.path(), Access::ReadWrite)]);
        excluded.exclusions.push(PathDenial {
            path: files.policy().canonicalize().expect("canonical"),
            classes: vec![Class::Write],
            from: "workspace:w.roots[0].exclude[0]".into(),
        });
        assert_eq!(files.check(&excluded), Ok(()));
        // Read alone taken away still leaves the file writable.
        excluded.exclusions[0].classes = vec![Class::Read];
        assert!(files.check(&excluded).is_err());
    }

    /// Taking write away from the file alone is not enough: a writable directory between it and
    /// the grant can be renamed away and replaced, file and all.
    #[test]
    fn a_writable_directory_between_the_grant_and_an_excluded_policy_refuses() {
        let base = TempDir::new().expect("base");
        let dir = base.path().join("playpen");
        std::fs::create_dir(&dir).expect("mkdir");
        let policy = dir.join("policy.yaml");
        std::fs::write(&policy, "version: 1\n").expect("policy");
        let files = Files::new();
        let mut excluded = caps(vec![grant(base.path(), Access::ReadWrite)]);
        excluded.exclusions.push(PathDenial {
            path: policy.canonicalize().expect("canonical"),
            classes: vec![Class::Write],
            from: "workspace:w.roots[0].exclude[0]".into(),
        });
        let refusal = check(&excluded, &policy, &files.executable()).expect_err("refused");
        assert_eq!(refusal.code, Code::IntegrityWritable);
        // Excluding the directory instead closes it.
        excluded.exclusions[0].path = dir.canonicalize().expect("canonical");
        assert_eq!(check(&excluded, &policy, &files.executable()), Ok(()));
    }

    /// A symlinked directory on the way to the policy, sitting in a writable root, can be repointed
    /// at another policy: the link's own entry is checked, not only where it leads.
    #[test]
    fn a_writable_symlinked_ancestor_refuses() {
        let files = Files::new();
        let writable = TempDir::new().expect("writable");
        let link = writable.path().join("cfg");
        std::os::unix::fs::symlink(files.policy_dir.path(), &link).expect("symlink");
        let caps = caps(vec![grant(writable.path(), Access::ReadWrite)]);
        let refusal =
            check(&caps, &link.join("policy.yaml"), &files.executable()).expect_err("refused");
        assert_eq!(refusal.code, Code::IntegrityWritable);
    }
}
