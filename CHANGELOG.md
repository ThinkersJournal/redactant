# Changelog

## Unreleased (version allocated by the PM at gate)

- ROADMAP row 2: `Scrubber` (R4). `Scrubber::new().with(&Secret<String>)?` registers a secret, refusing an empty or under-4-byte one with `RegisterError::{Empty, TooShort}` (names the length, never the value; DESIGN Q3). `clean` replaces every occurrence with `<redacted>`, longest secret first; `clean_or_drop` is ConfigurAnt's whole-message mode (same bytes); `clean_error` cleans an error and its whole `source()` chain; `clean_debug` cleans a `Debug` rendering. Plain bytes only: encoded or transformed secrets pass through (a test pins this). Tests: `tests/scrubber.rs` (11, byte-exact, 3 controls); reversing the longest-first sort fails 2.

## 0.0.2

- ROADMAP row 1: `Secret<T: Zeroize>` with blank `Display` (`<redacted>`) and `Debug` (`Secret(<redacted>)`), `expose()`, no `Clone`/`Deref`/`AsRef`/`Into`, zeroize on drop. Tests: `tests/canary.rs` (R1, byte-exact, nested in struct/Option/Vec/HashMap, 3 negative controls; a leaking `Display` mutation fails `display_and_debug_bytes_are_exact`), `tests/compile_fail.rs` (R6: clone, deref, into, as_ref, private field; one pass control). README example compiled as a doctest. The compile-fail (trybuild) tests run in their own CI job pinned to rustc 1.99.1, and the normal test job skips them, so a stable rustc bump cannot redden CI by changing error text.

## 0.0.1

- Docs only: `docs/DESIGN.md` and `ROADMAP.md`; open questions Q1-Q5 answered by the PM (one crate with a `serde` feature; encoding-aware scrubbing later; refuse short secrets with a named error; AuditAnt derive deferred, ROADMAP row 6; fixed `<redacted>` placeholder). No API yet; `publish = false`.
