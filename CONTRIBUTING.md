# Contributing to PortWatch

Thank you for contributing to PortWatch!

## Development & Testing
```bash
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo run
```

Please add unit tests for any new hygiene rules, parser logic, or socket exposure heuristics.
