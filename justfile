# Build every target, as CI does.
build:
    cargo build --all-targets --locked

# Run the whole test suite, enforcement rows included, as CI does.
test:
    cargo test --locked

# Regenerate the committed JSON Schemas from their serde types.
schema:
    cargo run --locked --example schema

# Remove everything cargo built.
clean:
    cargo clean
