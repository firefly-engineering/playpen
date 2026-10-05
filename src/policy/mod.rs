//! The policy document ([spec §10]): one strict YAML 1.2 document, JSON accepted as the subset it
//! is, whose tables are the serde types below. The types are canonical: the schema is generated
//! from them, never written beside them.
//!
//! Parsing is two passes over one text. [`syntax`] walks the YAML event stream for what serde
//! cannot see — a second document, a foreign tag, a NUL, and where each anchor was merged — and
//! then serde-saphyr deserialises the types, every refusal naming file, line and column.
//!
//! [spec §10]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#10-the-policy-document

pub mod coherence;
mod locate;
mod syntax;

pub use locate::SearchPath;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::Deserialize;
use serde_saphyr::Spanned;

use crate::capability::Access;
use crate::code::Code;
use crate::refusal::Refusal;

/// The only `version` this playpen understands.
pub const VERSION: u32 = 1;

/// The authored policy. Every table is optional except `version`, so the smallest policy is
/// `version: 1`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[schemars(extend("const" = VERSION))]
    pub version: u32,
    /// Free-form, for holding anchors. Nothing reads it: what it holds counts only where an alias
    /// or merge key uses it, and is checked there.
    #[serde(default)]
    #[schemars(with = "Option<serde_json::Value>")]
    pub definitions: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    pub minters: BTreeMap<String, Minter>,
    #[serde(default)]
    pub fragments: Fragments,
    #[serde(default)]
    pub workspaces: BTreeMap<String, Workspace>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
    #[serde(default)]
    pub shims: BTreeMap<String, Shim>,
}

/// A command that produces one secret ([spec §7.2]). Argv, never a shell string.
///
/// [spec §7.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#72-minters
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Minter {
    pub command: Vec<String>,
    #[serde(default)]
    pub revoke: Option<Vec<String>>,
    /// Seconds.
    #[serde(default)]
    pub timeout: Option<u64>,
}

/// Named lists a profile or route refers to by name.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Fragments {
    /// Environment fragments: lists of variable names a profile allows together.
    #[serde(default)]
    pub env: BTreeMap<String, Vec<String>>,
    /// Endpoint rule sets ([spec §7.6]).
    ///
    /// [spec §7.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#76-endpoint-rule-sets
    #[serde(default)]
    pub endpoints: BTreeMap<String, Vec<EndpointRule>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EndpointRule {
    pub method: String,
    pub path: String,
}

/// Everything a run may reach for one body of work ([spec §5.1]).
///
/// [spec §5.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#51-workspace
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Workspace {
    pub roots: Vec<Root>,
    #[serde(default)]
    pub areas: BTreeMap<String, Area>,
    #[serde(default)]
    pub forge: Option<Forge>,
    #[serde(default)]
    pub credentials: Vec<Route>,
}

/// A brought root: a path the workspace grants in place, at one mode.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Root {
    #[serde(deserialize_with = "literal")]
    #[schemars(extend("pattern" = LITERAL_PATTERN))]
    pub path: PathBuf,
    pub mode: Mode,
    #[serde(default)]
    pub exclude: Vec<Exclusion>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
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

/// A literal subpath subtracted from a root ([spec §8.4]). Omitted `classes` subtract all three.
///
/// [spec §8.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#84-exclusions
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Exclusion {
    #[serde(deserialize_with = "literal")]
    #[schemars(extend("pattern" = LITERAL_PATTERN))]
    pub path: PathBuf,
    #[serde(default)]
    pub classes: Option<Vec<Class>>,
}

/// An access class an exclusion subtracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    Read,
    Execute,
    Write,
}

impl From<Class> for crate::capability::Class {
    fn from(class: Class) -> Self {
        match class {
            Class::Read => Self::Read,
            Class::Execute => Self::Execute,
            Class::Write => Self::Write,
        }
    }
}

/// A provisioned area ([spec §5.4]). `lifetime` is the tag, so `concurrency` exists only where it
/// means something.
///
/// [spec §5.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#54-provisioned-areas
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(tag = "lifetime", rename_all = "lowercase", deny_unknown_fields)]
pub enum Area {
    // A struct variant, not a unit one: serde lets a unit variant of an internally tagged enum
    // swallow any key beside the tag, and `concurrency` here must be refused.
    Ephemeral {},
    Persistent {
        #[serde(default)]
        concurrency: Concurrency,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Concurrency {
    /// The default: a wrongly shared working area corrupts silently, a wrongly exclusive cache
    /// merely refuses.
    #[default]
    Exclusive,
    Shared,
}

/// Which remote repositories the work may reach: exactly one of `org` or `repos` ([spec §5.3]).
///
/// [spec §5.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#53-forge-scope
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum Forge {
    Org(String),
    Repos(Vec<String>),
}

/// A credential route ([spec §7.1]).
///
/// [spec §7.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#71-credential-route
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub host: String,
    pub path_prefix: String,
    pub minter: String,
    pub delivery: Delivery,
    #[serde(default)]
    pub endpoints: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub env: String,
}

/// The unit an invocation selects ([spec §5.5]).
///
/// [spec §5.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#55-profile
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    #[serde(default)]
    pub prefixes: Vec<PathBuf>,
    /// Spanned, so a name that matches no workspace is refused where it was written.
    #[schemars(with = "Vec<String>")]
    pub workspaces: Vec<Spanned<String>>,
    pub toolchain: Vec<ToolchainRoot>,
    #[serde(default)]
    pub env: Env,
    #[serde(default)]
    pub credentials: Vec<Route>,
    /// Keyed by agent kind.
    #[serde(default)]
    pub agent_state: BTreeMap<String, AgentState>,
}

/// A read-only root for what the agent works *with* ([spec §8.3]). Always read, so no `mode`.
///
/// [spec §8.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#83-toolchain
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolchainRoot {
    #[serde(deserialize_with = "literal")]
    #[schemars(extend("pattern" = LITERAL_PATTERN))]
    pub path: PathBuf,
    #[serde(default)]
    pub exclude: Vec<Exclusion>,
}

/// A profile's environment ([spec §9]).
///
/// [spec §9]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#9-the-environment
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Env {
    #[serde(default)]
    pub fragments: Vec<String>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub set: BTreeMap<String, SetValue>,
}

/// A literal `set:` value, or a provisioned area's path written `!area <workspace>/<area>` — in
/// JSON, which has no tags, `{"area": "<workspace>/<area>"}`.
#[derive(Debug, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum SetValue {
    Area(AreaRef),
    Literal(String),
}

#[derive(Debug, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum AreaRef {
    Area(String),
}

/// One kind's share list ([spec §5.6]). Default-deny: empty unless entries are named.
///
/// [spec §5.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#56-agent-state-directory
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentState {
    #[serde(default)]
    pub share: Vec<String>,
}

/// A symlink to playpen, named for its key ([spec §11.3]).
///
/// [spec §11.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#113-shims
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Shim {
    pub target: PathBuf,
    pub kind: String,
    #[serde(default)]
    pub profile: Option<String>,
    /// Literal argv tokens, prepended to the caller's. Never a shell string.
    #[serde(default)]
    pub flags: Vec<String>,
}

/// The characters that make a path a glob. A grant is a literal path, never a pattern
/// ([spec §5.2]), so a path holding one is refused at parse rather than taken for a name.
///
/// [spec §5.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#52-brought-roots
const GLOB: [char; 3] = ['*', '?', '['];

/// [`GLOB`] as the schema states it, for editors that validate against it.
const LITERAL_PATTERN: &str = r"^[^*?\[]*$";

/// A path that is a grant: any path except one holding a glob character.
fn literal<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<PathBuf, D::Error> {
    let path = PathBuf::deserialize(deserializer)?;
    if path.to_string_lossy().contains(GLOB) {
        return Err(serde::de::Error::custom(format!(
            "{} is a glob; a grant is a literal path",
            path.display()
        )));
    }
    Ok(path)
}

/// A policy as read from one file: the document, and the file it came from, which every later
/// refusal about it names.
#[derive(Debug)]
pub struct Loaded {
    pub path: PathBuf,
    pub policy: Policy,
}

impl Policy {
    /// Read and parse the policy at `path`.
    pub fn load(path: &Path) -> Result<Loaded, Refusal> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            let code = match e.kind() {
                std::io::ErrorKind::NotFound => Code::PolicyNotFound,
                _ => Code::PolicyUnreadable,
            };
            Refusal::new(code, format!("cannot read policy {}: {e}", path.display()))
        })?;
        Ok(Loaded {
            path: path.to_owned(),
            policy: Self::parse(&text, path)?,
        })
    }

    /// Parse `text` — the parser-contract tier ([spec §10.5]) — naming `origin` in any refusal.
    ///
    /// [spec §10.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#105-validation-tiers
    pub fn parse(text: &str, origin: &Path) -> Result<Self, Refusal> {
        syntax::parse(text, origin)
    }
}

#[cfg(test)]
mod tests;
