# Build every target, as CI does.
build:
    cargo build --all-targets --locked

# Run the whole test suite, enforcement rows included, as CI does.
test:
    cargo test --locked
