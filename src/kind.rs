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
    /// The agent's own variables naming its temporary directory, where it reads one of those in
    /// place of `TMPDIR`. Each is written with the run scratch, as `TMPDIR` is ([spec §5.7]).
    ///
    /// [spec §5.7]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#57-run-scratch
    pub scratch: &'static [&'static str],
    /// The agent's own variables naming an HTTPS proxy, where its model traffic reads one of
    /// those in place of `HTTPS_PROXY`. Each is written with the broker's address wherever
    /// `HTTPS_PROXY` is, and nowhere else ([spec §6.2]).
    ///
    /// [spec §6.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#62-the-broker
    pub proxy: &'static [&'static str],
    /// The agent's own home on the host, relative to `$HOME`. It is never granted ([spec §5.6]);
    /// it is where a **share** entry is resolved, which is the only way anything in it is reached
    /// from inside.
    ///
    /// [spec §5.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#56-agent-state-directory
    pub home: &'static str,
    /// How this kind reads instruction, where playpen knows ([spec §13.3]). `None` where it does
    /// not, and then nothing is rendered: a guess would be a file the agent never opens, stating
    /// facts about a boundary to nobody.
    ///
    /// [spec §13.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#133-presentation
    pub presentation: Option<Presentation>,
}

/// What the presentation adapter needs of a kind ([spec §13.3]).
///
/// [spec §13.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#133-presentation
#[derive(Debug)]
pub struct Presentation {
    /// The file inside the agent state directory this kind reads for instruction, which the
    /// adapter owns.
    pub entry_point: &'static str,
    /// What this kind reads as "also read this file", as the prefix an absolute path follows. A
    /// share entry naming the entry point is composed by reference through it ([spec §5.6]).
    /// Every kind in the table has one: a kind without one would need a refusal for sharing its
    /// entry point, which was retired while no kind could produce it
    /// ([#158](https://github.com/firefly-engineering/playpen/issues/158)).
    ///
    /// [spec §5.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#56-agent-state-directory
    pub import: &'static str,
}

/// Every kind this playpen knows.
pub const KINDS: &[Kind] = &[
    Kind {
        name: "claude",
        redirect: "CLAUDE_CONFIG_DIR",
        suppression: &[("CLAUDE_CODE_SANDBOXED", "1")],
        // Claude Code 2.1.288 makes its own `claude-<uid>` directory under `CLAUDE_CODE_TMPDIR`,
        // else `/tmp`, and never under `TMPDIR`: without this the first `claude -p` confined dies
        // on `EPERM: mkdir '/tmp/claude-502'`
        // ([#106](https://github.com/firefly-engineering/playpen/issues/106)).
        scratch: &["CLAUDE_CODE_TMPDIR"],
        proxy: &[],
        home: ".claude",
        presentation: Some(Presentation {
            entry_point: "CLAUDE.md",
            import: "@",
        }),
    },
    Kind {
        name: "omp",
        redirect: "PI_CODING_AGENT_DIR",
        suppression: &[],
        scratch: &[],
        // omp 18.8.2 on Bun 1.4 sends Anthropic inference over `node:https`, whose Bun shim drops a
        // tunnel, so `HTTPS_PROXY` leaves that traffic on the default route; it leaves it only for
        // a proxy named by `PI_PROXY` (`pi-ai/src/providers/cowork-fetch.ts`). Confined without
        // it, a request on a route that denies everything came back as Anthropic's own `401`
        // rather than the broker's `403`: it never reached the proxy
        // ([#107](https://github.com/firefly-engineering/playpen/issues/107)).
        proxy: &["PI_PROXY"],
        // `PI_CODING_AGENT_DIR` redirects omp's *agent* directory, which is `~/.omp/agent` by
        // default (`pi-utils/src/dirs.ts`), so that is the home a share entry is resolved in.
        home: ".omp/agent",
        // omp 18.8.2 reads `<PI_CODING_AGENT_DIR>/AGENTS.md` for instruction
        // (`discovery/builtin.ts`), and follows an `@<path>` at the start of a line or after
        // whitespace, absolute paths included (`discovery/at-imports.ts`). Confirmed by `L-omp`
        // ([#107](https://github.com/firefly-engineering/playpen/issues/107)).
        presentation: Some(Presentation {
            entry_point: "AGENTS.md",
            import: "@",
        }),
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
