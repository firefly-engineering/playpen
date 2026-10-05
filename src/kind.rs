//! The kind table ([spec §12]): playpen-owned, compiled in, and the **only** place per-agent
//! knowledge lives. A kind is always stated, never inferred ([spec §11.2]).
//!
//! [spec §12]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#12-the-kind-table
//! [spec §11.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#112-kind

/// One agent kind.
pub struct Kind {
    pub name: &'static str,
    /// The private variable that points the agent at its state directory.
    pub redirect: &'static str,
    /// Entries set so a guest's own sandbox stands down; set only, never stripped.
    pub suppression: &'static [(&'static str, &'static str)],
}

/// Every kind this playpen knows.
pub const KINDS: &[Kind] = &[
    Kind {
        name: "claude",
        redirect: "CLAUDE_CONFIG_DIR",
        suppression: &[("CLAUDE_CODE_SANDBOXED", "1")],
    },
    Kind {
        name: "omp",
        redirect: "PI_CODING_AGENT_DIR",
        suppression: &[],
    },
];

/// The kind named `name`, if this playpen knows it.
pub fn get(name: &str) -> Option<&'static Kind> {
    KINDS.iter().find(|kind| kind.name == name)
}
