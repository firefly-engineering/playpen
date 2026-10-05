//! Write every published schema to `schema/` at the repository root (`just schema`).

use std::path::Path;

fn main() -> std::io::Result<()> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("schema");
    for schema in playpen::schema::SCHEMAS {
        std::fs::write(dir.join(schema.file), (schema.generate)())?;
    }
    Ok(())
}
