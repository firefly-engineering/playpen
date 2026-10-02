//! The policy document ([spec §10]), as far as the walking skeleton reads it: one strict
//! document holding workspaces of brought roots, and profiles that name workspaces.
//!
//! [spec §10]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#10-the-policy-document

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_saphyr::Error as YamlError;

use crate::capability::Access;
use crate::code::Code;
use crate::refusal::Refusal;

/// The only `version` this playpen understands.
pub const VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    #[serde(default)]
    pub workspaces: BTreeMap<String, Workspace>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workspace {
    pub roots: Vec<Root>,
}

/// A brought root: a path the workspace grants in place, at one mode.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Root {
    pub path: PathBuf,
    pub mode: Mode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Read,
    Readwrite,
}

impl From<Mode> for Access {
    fn from(mode: Mode) -> Self {
        match mode {
            Mode::Read => Access::Read,
            Mode::Readwrite => Access::ReadWrite,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub workspaces: Vec<String>,
}

impl Policy {
    /// Read and parse the policy at `path`.
    pub fn load(path: &Path) -> Result<Self, Refusal> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            let code = match e.kind() {
                std::io::ErrorKind::NotFound => Code::PolicyNotFound,
                _ => Code::PolicyUnreadable,
            };
            Refusal::new(code, format!("cannot read policy {}: {e}", path.display()))
        })?;
        Self::parse(&text, path)
    }

    /// Parse `text`, naming `origin` in any refusal.
    pub fn parse(text: &str, origin: &Path) -> Result<Self, Refusal> {
        let policy: Policy =
            serde_saphyr::from_str(text).map_err(|e| policy_refusal(&e, origin))?;
        if policy.version != VERSION {
            return Err(Refusal::new(
                Code::PolicyVersion,
                format!(
                    "policy {} declares version {}, this playpen reads version {VERSION}",
                    origin.display(),
                    policy.version
                ),
            ));
        }
        Ok(policy)
    }
}

fn policy_refusal(err: &YamlError, origin: &Path) -> Refusal {
    let code = match err.without_snippet() {
        YamlError::SerdeUnknownField { .. } => Code::PolicyUnknownField,
        YamlError::SerdeInvalidType { .. }
        | YamlError::SerdeInvalidValue { .. }
        | YamlError::SerdeUnknownVariant { .. }
        | YamlError::SerdeMissingField { .. }
        | YamlError::InvalidCharNull { .. } => Code::PolicyType,
        _ => Code::PolicySyntax,
    };
    let at = match err.location() {
        Some(loc) if loc.line() > 0 => {
            format!("{}:{}:{}", origin.display(), loc.line(), loc.column())
        }
        _ => origin.display().to_string(),
    };
    // The parser's own rendering can span lines (it may carry a snippet); keep its headline.
    let rendered = err.to_string();
    let headline = rendered.lines().next().unwrap_or("invalid policy");
    Refusal::new(code, format!("{at}: {headline}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Policy, Refusal> {
        Policy::parse(text, Path::new("/etc/playpen/policy.yaml"))
    }

    const MINIMAL: &str = "\
version: 1
workspaces:
  playpen:
    roots:
      - { path: /src/playpen, mode: readwrite }
profiles:
  dev:
    workspaces: [playpen]
";

    #[test]
    fn reads_a_minimal_policy() {
        let policy = parse(MINIMAL).expect("minimal policy parses");
        let root = &policy.workspaces["playpen"].roots[0];
        assert_eq!(root.path, Path::new("/src/playpen"));
        assert_eq!(root.mode, Mode::Readwrite);
        assert_eq!(policy.profiles["dev"].workspaces, ["playpen"]);
    }

    #[test]
    fn json_is_valid_input() {
        let text = r#"{"version": 1, "profiles": {"dev": {"workspaces": []}}}"#;
        assert!(parse(text).is_ok());
    }

    #[test]
    fn unknown_field_is_refused() {
        let err = parse("version: 1\nprofils: {}\n").unwrap_err();
        assert_eq!(err.code, Code::PolicyUnknownField);
    }

    #[test]
    fn unknown_nested_field_is_refused() {
        let text = MINIMAL.replace("mode: readwrite", "mode: readwrite, exlude: []");
        assert_eq!(parse(&text).unwrap_err().code, Code::PolicyUnknownField);
    }

    #[test]
    fn invalid_variant_is_a_type_refusal() {
        let text = MINIMAL.replace("mode: readwrite", "mode: no");
        assert_eq!(parse(&text).unwrap_err().code, Code::PolicyType);
    }

    #[test]
    fn unrecognised_version_is_refused() {
        let err = parse("version: 2\n").unwrap_err();
        assert_eq!(err.code, Code::PolicyVersion);
    }

    #[test]
    fn malformed_yaml_is_a_syntax_refusal() {
        let err = parse("version: [1\n").unwrap_err();
        assert_eq!(err.code, Code::PolicySyntax);
    }

    #[test]
    fn multi_document_stream_is_refused() {
        let err = parse("version: 1\n---\nversion: 1\n").unwrap_err();
        assert_eq!(err.code, Code::PolicySyntax);
    }

    #[test]
    fn refusal_names_file_line_and_column() {
        let err = parse("version: 1\nprofils: {}\n").unwrap_err();
        let line = err.to_string();
        assert!(line.contains("/etc/playpen/policy.yaml:2:"), "{line}");
    }
}
