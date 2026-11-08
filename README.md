```rust
use redactant::Secret;

let token = Secret::new(String::from("s3cr3t-token"));
assert_eq!(token.to_string(), "<redacted>");
assert_eq!(token.expose(), "s3cr3t-token");
```

# redactant

Secret values that cannot leak through formatting: blank `Display` and `Debug`, one explicit `expose()`, zeroize on drop.
Design: `docs/DESIGN.md`. Status: pre-release, `publish = false`; the scrubber, fingerprints and `serde` feature are
later ROADMAP rows.

Licensed under either of the Apache License, Version 2.0 (`LICENSE-APACHE`) or the MIT licence (`LICENSE-MIT`), at your
option.
