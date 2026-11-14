# Changelog

## 0.1.8 — docs: detector design (ROADMAP row 7)

Docs only: `docs/DETECT.md` designs shape-based screening of text for secrets nobody registered (match classes, results that never carry matched text, regex and entropy dependency options, false-positive policy, test plan with negative controls and run-time-assembled fixtures, patent re-sweep plan, questions for the PM and SageAnt); `docs/DESIGN.md` section 3 is amended per the PM (2026-11-14): shape-based screening behind a feature, never on by default, never a claim of completeness, no code until the re-sweep gate is cleared; ROADMAP row 7 points at it. No code and no public API change.

## 0.1.7 — ci: repin the portfolio caller to coderipper 42dd497; declare api_budget, owns_data, adapter role

CI and declaration only: the advisory `portfolio` job called coderipper `portfolio.yml@30e012b7` (CodeRipper 0.9.6), which cannot parse the `[architecture]` table declared in 0.1.6. It now calls the merge commit of coderipper#313 (`42dd497d`, CodeRipper 0.43.49). `.coderipper.toml` also declares what is true of the crate: an `api_budget` of 4 for `secret` (counted by hand), `owns_data` for the placeholder text, and `fingerprint` as an adapter over hmac and sha2; no composition root is declared because the library wires nothing, so ARC-012 does not run. No code change.

## 0.1.6 — chore: [architecture] declaration; Secret moves to its own module (ARC/MOD programme)

Declares `[architecture]` in `.coderipper.toml` (components secret, fingerprint, scrubber, api; layers core, services, facade; ARC/MOD programme, CireSnave 2026-11-12). The crate root held `Secret` and also re-exported the other modules, which coderipper read as a cycle (ARC-001/ARC-002); `Secret` and `PLACEHOLDER` now live in `src/secret.rs` and `lib.rs` only declares and re-exports. Public paths are unchanged (`redactant::Secret`, `redactant::PLACEHOLDER`); no behaviour change.

## 0.1.5 — docs: field-level derive design (ROADMAP row 6)

Docs only: `docs/DERIVE.md` writes the redactant-side design for structured redaction (attribute syntax, enums and nesting, sink-based consumption, additive-only check against row 1, canary and compile-fail test plan with negative controls, questions for the AuditAnt author); ROADMAP row 6 points at it. No code change.

## 0.1.4 — adopt the fragment+stamp kit (chore)

Chore: adopt the PM changelog-fragment kit (tools/stamp-version.py, tools/check-fragment.py, .github/workflows/changelog-fragment.yml, changelog.d/README.md). From here a PR carries one changelog.d fragment and no version edit; the PM stamps at merge. Dry run with a throwaway fragment listed Cargo.toml, Cargo.lock and CHANGELOG.md. No code change.

## 0.1.3

- Docs: ROADMAP row 5 no longer says "held; rows 1-3 published (PM)". redactant 0.1.2 is published and tagged, so the row reads unblocked and waits on the consumer lanes. No code change. (Version allocated by the PM 2026-11-10; this repo has no `tools/stamp-version.py`, so the lane carries its own version.)

## 0.1.2

- Publish readiness (PM task 2026-11-09): `PATENT-SWEEP.md` (first pass at 0.1.1 @ b502904, 17 patents read, no `needs-review`, design constraints recorded); `publish = false` removed; `keywords` and `categories` added so `releaseant plan --require-metadata readme,keywords,rust-version,categories,repository` passes; README install snippet now `version = "0.1"` and drops the "not on crates.io" line. No code change.

## 0.1.1

- Docs: README rewritten after the s8 fresh-reader trial: a quick start for every shipped feature (use the value, scrub an error, fingerprint, serde), the limits stated where the user will look (scrubber matches plain bytes only and refuses short, empty or non-UTF-8 secrets; fingerprint key must be 16+ bytes and stable, the 4-byte tag can collide; a serde round trip cannot carry the secret). After trial 2 it also has the install snippet (with the `serde` feature) before the first example, a binary-secret note (register the hex/base64 form), a startup pattern that keeps going when a secret is refused, fingerprint key guidance (generate, hold, rotate), and a persist-a-config recipe with `serialize_with`; the format of `clean_error` and the return of `clean_or_drop` are stated. All eight Rust examples are doctests, run in CI. `redactant` lists itself as a dev-dependency with the `serde` feature so they run under plain `cargo test`.

## 0.1.0 (**Breaking**, pre-1.0 so the second number)

- PM ruling 2026-11-09 after the s8 fresh-reader trial. **Breaking:** `Scrubber::with` (a consuming builder that lost the scrubber on a refusal) is replaced by `Scrubber::register(&mut self, &Secret<T>) -> Result<(), RegisterError>`. A refusal changes nothing, so the scrubber keeps what it had. `register` takes any `Secret<T>` where `T: Zeroize + AsRef<[u8]>` (`String`, `Vec<u8>`, ...); non-UTF-8 bytes are refused with the new `RegisterError::NotUtf8` (the scrubber cleans text; such a secret could never match as written).
- **Breaking** (`serde`): `Deserialize for Secret<T>` now needs `T: AsRef<[u8]>` and refuses the exact text `<redacted>` with an error that says a serialize step already destroyed the secret, instead of silently storing the literal placeholder as the secret (a config write-then-read round trip). Why `AsRef<[u8]>`: only byte-like values can be mistaken for the placeholder. Tests: `tests/serde.rs` +3 (round trip errors with the message; near-misses stay ordinary values; control shows a plain `String` would have read it silently); removing the guard fails 2. `tests/scrubber.rs` +2 (a refusal keeps earlier secrets; byte secrets accepted, non-UTF-8 refused by name).

## 0.0.5

- ROADMAP row 3: keyed fingerprints (R5). `secret.fingerprint(&key)` returns a `Fingerprint` printed as `fp:` plus 8 lowercase hex characters (first 4 bytes of HMAC-SHA-256). `FingerprintKey::new(bytes)` refuses a key under 16 bytes with `KeyError { len }` (names the length, never the key); the key has blank `Debug` and zeroizes on drop; RedactAnt never stores keys. New dependencies `hmac` 0.13.0 and `sha2` 0.11.1 (PM-approved 2026-11-09; pure Rust, RustCrypto). Tests: `tests/fingerprint.rs` (10, byte-exact, 3 controls) and an RFC 4231 case 2 vector pinning the primitive; ignoring the key fails 3 (2 integration + the vector).

## 0.0.4

- ROADMAP row 4: cargo feature `serde`. `Secret<T>` implements `Serialize` writing the placeholder `"<redacted>"` (never the value; call `expose()` to serialize the real one) and `Deserialize` reading a value straight into a `Secret`. Tests: `tests/serde.rs` (6, byte-exact; R2 nested in struct/Option/Vec/map, R3 `unwrap`/`expect`/`unwrap_err` panic bytes, 2 negative controls). The CI test job now passes `--features serde` so they run.

## 0.0.3

- CI fix: the test job ran only `--lib --test canary`, which would have skipped `tests/scrubber.rs`. It now runs every test target (`cargo test --no-fail-fast`); `compile_fail` has `required-features = ["ui-tests"]` and runs only in the pinned compile-fail job (`--features ui-tests`). New cargo feature `ui-tests` (test-only, empty).
- ROADMAP row 2: `Scrubber` (R4). `Scrubber::new().with(&Secret<String>)?` registers a secret, refusing an empty or under-4-byte one with `RegisterError::{Empty, TooShort}` (names the length, never the value; DESIGN Q3). `clean` replaces every occurrence with `<redacted>`, longest secret first; `clean_or_drop` is ConfigurAnt's whole-message mode (same bytes); `clean_error` cleans an error and its whole `source()` chain; `clean_debug` cleans a `Debug` rendering. Plain bytes only: encoded or transformed secrets pass through (a test pins this). Tests: `tests/scrubber.rs` (11, byte-exact, 3 controls); reversing the longest-first sort fails 2.

## 0.0.2

- ROADMAP row 1: `Secret<T: Zeroize>` with blank `Display` (`<redacted>`) and `Debug` (`Secret(<redacted>)`), `expose()`, no `Clone`/`Deref`/`AsRef`/`Into`, zeroize on drop. Tests: `tests/canary.rs` (R1, byte-exact, nested in struct/Option/Vec/HashMap, 3 negative controls; a leaking `Display` mutation fails `display_and_debug_bytes_are_exact`), `tests/compile_fail.rs` (R6: clone, deref, into, as_ref, private field; one pass control). README example compiled as a doctest. The compile-fail (trybuild) tests run in their own CI job pinned to rustc 1.99.1, and the normal test job skips them, so a stable rustc bump cannot redden CI by changing error text.

## 0.0.1

- Docs only: `docs/DESIGN.md` and `ROADMAP.md`; open questions Q1-Q5 answered by the PM (one crate with a `serde` feature; encoding-aware scrubbing later; refuse short secrets with a named error; AuditAnt derive deferred, ROADMAP row 6; fixed `<redacted>` placeholder). No API yet; `publish = false`.
