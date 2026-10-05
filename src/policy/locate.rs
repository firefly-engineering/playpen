//! Where the policy is ([spec §10.1]): a fixed search path, first hit wins, never merged.
//!
//! The locations come from the caller's environment, which `main` reads once and hands in. Nothing
//! here reads it, and there is no `PLAYPEN_POLICY`: the one way to name a policy is `--policy`.
//!
//! [spec §10.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#101-location

use std::ffi::OsString;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::code::Code;
use crate::refusal::Refusal;

/// The file names looked for at each location, in order. The extension selects nothing but the
/// name: JSON is YAML 1.2, so one parser reads both.
const NAMES: [&str; 2] = ["policy.yaml", "policy.json"];

/// The system location, the last on the path. A system document is not a base layer: it is dead
/// whenever a user document exists.
const SYSTEM: &str = "/etc/playpen";

/// The directories searched when no `--policy` is given, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchPath {
    dirs: Vec<PathBuf>,
}

impl SearchPath {
    /// `$XDG_CONFIG_HOME/playpen`, `~/.config/playpen`, `/etc/playpen`. A value that is unset or
    /// relative contributes no location, as the XDG base directory specification requires.
    pub fn new(xdg_config_home: Option<OsString>, home: Option<OsString>) -> Self {
        let absolute =
            |value: Option<OsString>| value.map(PathBuf::from).filter(|p| p.is_absolute());
        let dirs = absolute(xdg_config_home)
            .into_iter()
            .chain(absolute(home).map(|home| home.join(".config")))
            .map(|base| base.join("playpen"))
            .chain([PathBuf::from(SYSTEM)])
            .collect();
        Self { dirs }
    }

    /// Exactly `dirs`, in order: for a caller that must not reach the host's own locations.
    pub fn of(dirs: Vec<PathBuf>) -> Self {
        Self { dirs }
    }

    /// The policy to read: `explicit` if given, else the first location holding one.
    pub fn locate(&self, explicit: Option<&Path>) -> Result<PathBuf, Refusal> {
        if let Some(path) = explicit {
            return Ok(path.to_owned());
        }
        for dir in &self.dirs {
            let mut present = Vec::new();
            for name in NAMES {
                let path = dir.join(name);
                if is_present(&path)? {
                    present.push(path);
                }
            }
            match present.as_slice() {
                [] => continue,
                [path] => return Ok(path.clone()),
                [yaml, json, ..] => {
                    return Err(Refusal::new(
                        Code::PolicyAmbiguousLocation,
                        format!(
                            "both {} and {} are present; keep one",
                            yaml.display(),
                            json.display()
                        ),
                    ));
                }
            }
        }
        let tried: Vec<_> = self.dirs.iter().map(|d| d.display().to_string()).collect();
        Err(Refusal::new(
            Code::PolicyNotFound,
            format!(
                "no policy.yaml or policy.json in {}, and no --policy given",
                tried.join(", ")
            ),
        ))
    }
}

/// Whether anything is at `path`. A dangling link counts, so it is refused when read rather than
/// skipped for a later location; so does a directory, which reads as unreadable. A location that
/// cannot be looked at is refused, never passed over.
fn is_present(path: &Path) -> Result<bool, Refusal> {
    match path.symlink_metadata() {
        Ok(_) => Ok(true),
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => Ok(false),
        Err(e) => Err(Refusal::new(
            Code::PolicyUnreadable,
            format!("cannot look for a policy at {}: {e}", path.display()),
        )),
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    /// Three locations of a temp directory's own, so no test reads the host's.
    struct Locations {
        _base: TempDir,
        dirs: Vec<PathBuf>,
    }

    impl Locations {
        fn new() -> Self {
            let base = TempDir::new().expect("temp dir");
            let dirs = ["xdg", "home", "etc"]
                .iter()
                .map(|name| {
                    let dir = base.path().join(name);
                    std::fs::create_dir(&dir).expect("mkdir");
                    dir
                })
                .collect();
            Self { _base: base, dirs }
        }

        fn put(&self, location: usize, name: &str) -> PathBuf {
            let path = self.dirs[location].join(name);
            std::fs::write(&path, "version: 1\n").expect("write");
            path
        }

        fn locate(&self) -> Result<PathBuf, Refusal> {
            SearchPath::of(self.dirs.clone()).locate(None)
        }
    }

    #[test]
    fn the_search_path_is_the_specs() {
        let path = SearchPath::new(Some("/xdg".into()), Some("/home/op".into()));
        assert_eq!(
            path.dirs,
            [
                Path::new("/xdg/playpen"),
                Path::new("/home/op/.config/playpen"),
                Path::new("/etc/playpen")
            ]
        );
    }

    #[test]
    fn an_unset_or_relative_location_contributes_nothing() {
        let path = SearchPath::new(Some("relative".into()), None);
        assert_eq!(path.dirs, [Path::new("/etc/playpen")]);
    }

    #[test]
    fn explicit_wins_without_looking() {
        let locations = Locations::new();
        locations.put(0, "policy.yaml");
        let explicit = Path::new("/nowhere/policy.yaml");
        let found = SearchPath::of(locations.dirs.clone()).locate(Some(explicit));
        assert_eq!(found, Ok(explicit.to_owned()));
    }

    #[test]
    fn each_location_is_found_when_it_is_the_first_to_hold_one() {
        for location in 0..3 {
            let locations = Locations::new();
            let path = locations.put(location, "policy.json");
            assert_eq!(locations.locate(), Ok(path), "location {location}");
        }
    }

    /// Later locations are never read: an ambiguous one behind the first hit is not refused.
    #[test]
    fn the_first_hit_wins() {
        let locations = Locations::new();
        let first = locations.put(1, "policy.yaml");
        locations.put(2, "policy.yaml");
        locations.put(2, "policy.json");
        assert_eq!(locations.locate(), Ok(first));
    }

    #[test]
    fn yaml_and_json_at_one_location_is_ambiguous() {
        let locations = Locations::new();
        locations.put(1, "policy.yaml");
        locations.put(1, "policy.json");
        let refusal = locations.locate().expect_err("refused");
        assert_eq!(refusal.code, Code::PolicyAmbiguousLocation);
    }

    #[test]
    fn nothing_found_is_refused_naming_where_it_looked() {
        let locations = Locations::new();
        let refusal = locations.locate().expect_err("refused");
        assert_eq!(refusal.code, Code::PolicyNotFound);
        for dir in &locations.dirs {
            assert!(
                refusal.message().contains(dir.to_str().unwrap()),
                "{refusal}"
            );
        }
    }

    #[test]
    fn a_dangling_link_is_a_hit_not_a_miss() {
        let locations = Locations::new();
        let link = locations.dirs[0].join("policy.yaml");
        std::os::unix::fs::symlink("/nowhere/policy.yaml", &link).expect("symlink");
        locations.put(1, "policy.yaml");
        assert_eq!(locations.locate(), Ok(link));
    }
}
