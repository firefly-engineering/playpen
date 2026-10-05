//! The kind table ([spec §12]): playpen-owned, compiled in, and the **only** place per-agent
//! knowledge lives. A kind is always stated, never inferred ([spec §11.2]).
//!
//! [spec §12]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#12-the-kind-table
//! [spec §11.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#112-kind

use crate::code::Code;
use crate::refusal::Refusal;

/// One agent kind.
#[derive(Debug)]
pub struct Kind {
    pub name: &'static str,
    /// The private variable that points the agent at its state directory.
    pub redirect: &'static str,
    /// Entries set so a guest's own sandbox stands down; set only, never stripped.
    pub suppression: &'static [(&'static str, &'static str)],
    /// The agent's own home on the host, relative to `$HOME`. It is never granted ([spec §5.6]);
    /// it is where a **share** entry is resolved, which is the only way anything in it is reached
    /// from inside.
    ///
    /// [spec §5.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#56-agent-state-directory
    pub home: &'static str,
}

/// Every kind this playpen knows.
pub const KINDS: &[Kind] = &[
    Kind {
        name: "claude",
        redirect: "CLAUDE_CONFIG_DIR",
        suppression: &[("CLAUDE_CODE_SANDBOXED", "1")],
        home: ".claude",
    },
    Kind {
        name: "omp",
        redirect: "PI_CODING_AGENT_DIR",
        suppression: &[],
        home: ".omp",
    },
];

impl Kind {
    /// The provenance of everything this kind authors ([spec §10.4]), which is the only bridge
    /// from a constructed entry back to the table that wrote it.
    ///
    /// [spec §10.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#104-the-resolved-form
    pub fn from(&self) -> String {
        format!("kind:{}", self.name)
    }
}

/// The kind named `name`, if this playpen knows it.
pub fn get(name: &str) -> Option<&'static Kind> {
    KINDS.iter().find(|kind| kind.name == name)
}

/// The kind named `name`, or the refusal that this playpen knows no such kind: there is nowhere to
/// put what playpen would need to know about it ([spec §11.2]).
///
/// [spec §11.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#112-kind
pub fn require(name: &str) -> Result<&'static Kind, Refusal> {
    get(name).ok_or_else(|| {
        Refusal::new(
            Code::KindUnknown,
            format!(
                "unknown agent kind {name:?}; known kinds: {}",
                KINDS
                    .iter()
                    .map(|kind| kind.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A kind is always stated, never inferred, so an unrecognised one is a refusal that names
    /// what this playpen does know.
    #[test]
    fn an_unrecognised_kind_refuses_naming_the_known_ones() {
        let refusal = require("codex").expect_err("refused");
        assert_eq!(refusal.code, Code::KindUnknown);
        assert!(refusal.message().contains("\"codex\""), "{refusal}");
        assert!(refusal.message().contains("claude, omp"), "{refusal}");
    }

    /// Every kind has a private state-dir redirect: a kind whose binary has none never gets an
    /// `XDG_CONFIG_HOME` exception, so the table cannot hold one ([spec §12]).
    ///
    /// [spec §12]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#12-the-kind-table
    #[test]
    fn every_kind_redirects_its_own_state_directory() {
        for kind in KINDS {
            assert!(!kind.redirect.is_empty(), "{}", kind.name);
            assert_ne!(kind.redirect, "XDG_CONFIG_HOME", "{}", kind.name);
            assert_eq!(kind.from(), format!("kind:{}", kind.name));
        }
    }
}
