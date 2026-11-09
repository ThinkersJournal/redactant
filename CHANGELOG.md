# Changelog

## Unreleased (version allocated by the PM at gate; **Breaking**, pre-1.0 so the second number)

- PM ruling 2026-11-09 after the s8 fresh-reader trial. **Breaking:** `Scrubber::with` (a consuming builder that lost the scrubber on a refusal) is replaced by `Scrubber::register(&mut self, &Secret<T>) -> Result<(), RegisterError>`. A refusal changes nothing, so the scrubber keeps what it had. `register` takes any `Secret<T>` where `T: Zeroize + AsRef<[u8]>` (`String`, `Vec<u8>`, ...); non-UTF-8 bytes are refused with the new `RegisterError::NotUtf8` (the scrubber cleans text; such a secret could never match as written).
- **Breaking** (`serde`): `Deserialize for Secret<T>` now needs `T: AsRef<[u8]>` and refuses the exact text `<redacted>` with an error that says a serialize step already destroyed the secret, instead of silently storing the literal placeholder as the secret (a config write-then-read round trip). Why `AsRef<[u8]>`: only byte-like values can be mistaken for the placeholder. Tests: `tests/serde.rs` +3 (round trip errors with the message; near-misses stay ordinary values; control shows a plain `String` would have read it silently); removing the guard fails 2. `tests/scrubber.rs` +2 (a refusal keeps earlier secrets; byte secrets accepted, non-UTF-8 refused by name).

## 0.0.4

- ROADMAP row 4: cargo feature `serde`. `Secret<T>` implements `Serialize` writing the placeholder `"<redacted>"` (never the value; call `expose()` to serialize the real one) and `Deserialize` reading a value straight into a `Secret`. Tests: `tests/serde.rs` (6, byte-exact; R2 nested in struct/Option/Vec/map, R3 `unwrap`/`expect`/`unwrap_err` panic bytes, 2 negative controls). The CI test job now passes `--features serde` so they run.

## 0.0.3

- CI fix: the test job ran only `--lib --test canary`, which would have skipped `tests/scrubber.rs`. It now runs every test target (`cargo test --no-fail-fast`); `compile_fail` has `required-features = ["ui-tests"]` and runs only in the pinned compile-fail job (`--features ui-tests`). New cargo feature `ui-tests` (test-only, empty).
- ROADMAP row 2: `Scrubber` (R4). `Scrubber::new().with(&Secret<String>)?` registers a secret, refusing an empty or under-4-byte one with `RegisterError::{Empty, TooShort}` (names the length, never the value; DESIGN Q3). `clean` replaces every occurrence with `<redacted>`, longest secret first; `clean_or_drop` is ConfigurAnt's whole-message mode (same bytes); `clean_error` cleans an error and its whole `source()` chain; `clean_debug` cleans a `Debug` rendering. Plain bytes only: encoded or transformed secrets pass through (a test pins this). Tests: `tests/scrubber.rs` (11, byte-exact, 3 controls); reversing the longest-first sort fails 2.

## 0.0.2

- ROADMAP row 1: `Secret<T: Zeroize>` with blank `Display` (`<redacted>`) and `Debug` (`Secret(<redacted>)`), `expose()`, no `Clone`/`Deref`/`AsRef`/`Into`, zeroize on drop. Tests: `tests/canary.rs` (R1, byte-exact, nested in struct/Option/Vec/HashMap, 3 negative controls; a leaking `Display` mutation fails `display_and_debug_bytes_are_exact`), `tests/compile_fail.rs` (R6: clone, deref, into, as_ref, private field; one pass control). README example compiled as a doctest. The compile-fail (trybuild) tests run in their own CI job pinned to rustc 1.99.1, and the normal test job skips them, so a stable rustc bump cannot redden CI by changing error text.

## 0.0.1

- Docs only: `docs/DESIGN.md` and `ROADMAP.md`; open questions Q1-Q5 answered by the PM (one crate with a `serde` feature; encoding-aware scrubbing later; refuse short secrets with a named error; AuditAnt derive deferred, ROADMAP row 6; fixed `<redacted>` placeholder). No API yet; `publish = false`.
