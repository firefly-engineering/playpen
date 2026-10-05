//! The JSON Schemas playpen publishes ([spec §10.3]), each generated from the Rust serde types
//! that are canonical for it, never written beside them.
//!
//! [`SCHEMAS`] is every published schema with the file it is committed as, under `schema/` at the
//! repository root. `just schema` writes them; a test fails whenever a committed file differs from
//! a fresh generation, so a change to a type cannot land without its schema. The resolved form and
//! the manifest join the table when their types exist.
//!
//! [spec §10.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#103-schema

use schemars::JsonSchema;

use crate::policy::Policy;

/// One published schema: the file it is committed as, and how to generate it.
pub struct Schema {
    pub file: &'static str,
    pub generate: fn() -> String,
}

/// Every schema playpen publishes.
pub const SCHEMAS: &[Schema] = &[Schema {
    file: "policy.schema.json",
    generate: generate::<Policy>,
}];

/// The schema of `T`, as committed: pretty-printed JSON ending in a newline.
pub fn generate<T: JsonSchema>() -> String {
    let schema = schemars::schema_for!(T);
    let mut text = serde_json::to_string_pretty(&schema).unwrap_or_else(|e| {
        // A schema is a tree of JSON values built in memory; serialising it cannot fail.
        unreachable!("a generated schema serialises: {e}")
    });
    text.push('\n');
    text
}
