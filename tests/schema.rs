//! The committed schemas are what the types generate ([spec §10.3]). CI runs this, so a change to
//! a canonical type cannot land without its schema.
//!
//! [spec §10.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#103-schema

use std::path::Path;

use playpen::schema::SCHEMAS;

#[test]
fn every_committed_schema_is_a_fresh_generation() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("schema");
    for schema in SCHEMAS {
        let path = dir.join(schema.file);
        let committed = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            committed == (schema.generate)(),
            "{} differs from a fresh generation; run `just schema` and commit the result",
            path.display()
        );
    }
}

/// Nothing in `schema/` that the table does not generate: a schema whose type went would
/// otherwise stay committed, describing nothing.
#[test]
fn every_committed_schema_is_generated() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("schema");
    for entry in std::fs::read_dir(&dir).expect("schema/") {
        let name = entry.expect("entry").file_name();
        assert!(
            SCHEMAS.iter().any(|schema| name == schema.file),
            "{name:?} is in schema/ but nothing generates it"
        );
    }
}
