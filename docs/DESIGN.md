# RedactAnt design note

Status: **draft for PM review, nothing built.** Written 2026-11-08 by the `redactant` lane. Claims about other projects
cite the file and the date read (`origin/main`, 2026-11-08); re-check them before relying on them.

## 1. What it is, in one paragraph

A small library that keeps secret values out of text. You wrap a value once, and from then on every way of printing it
(`Display`, `Debug`, `{:?}` inside a bigger struct, a serde dump, an error message) shows a fixed placeholder instead of the
value. When two logs need to say "same secret" without saying what it is, you ask for a *fingerprint*. When some other
library's error might have quoted a secret, you pass it through a *scrubber*. **Easy is the product**: the common case is
one wrapper type and zero configuration.

## 2. Customers (what they need, read 2026-11-08)

| Customer | Need | Source |
|---|---|---|
| SecretAnt | blank-format secret type; keyed-hash-prefix fingerprint; scrubber for adapter errors; every rule has a canary test with a negative control | `secretant` `docs/DESIGN.md` section 3.5 |
| ConfigurAnt | its `REDACTED` constant (`src/config.rs`, several call sites) and substring redaction (`Value::appears_in`, `src/value.rs`; used in the serde-error path of `Config`) move here and are deleted there | `configurant` `ROADMAP.md` row 27 |
| AuditAnt | uses it (the PM's word; its needs are not yet written down, so **open question Q4**) | PM task, 2026-11-08 |

## 3. Scope

In v1:

1. **`Secret<T>`**: owns a value; formatting is blank; no `Clone` unless asked for; zeroizes on drop where `T` allows.
2. **Placeholder**: one agreed text, `<redacted>` (ConfigurAnt's existing string, so adopting it changes no output).
3. **Fingerprint**: a short, keyed, non-reversible tag of a value.
4. **Scrubber**: given a set of secrets, removes every occurrence from a string or an error's message chain.
5. **Canary test kit**: a helper that pushes a known canary through every formatting path and fails if it appears, plus the
   rule that each rule's test has a *negative control* (a deliberately leaking mutation that must make the test fail).

Not in v1 (stated so nobody assumes them): encryption or storage of secrets (that is SecretAnt); locking memory
(`mlock`); detecting secrets by guessing (entropy or regex scanners); redacting values we were never told about; a log
framework integration (a feature flag later if a customer asks).

## 4. API sketch (illustrative; names are not final)

```rust
use redactant::{Secret, Scrubber};

let token = Secret::new(String::from("s3cr3t-token"));
println!("{token}");            // <redacted>
println!("{token:?}");          // Secret(<redacted>)
let t: &str = token.expose();   // the only way to the value; greppable on purpose

let tag = token.fingerprint(&key);   // e.g. "fp:3f9a1c7e" (see 6)

let mut scrub = Scrubber::new();
scrub.register(&token)?;
let msg = scrub.clean(&err.to_string());   // "connect failed for <redacted>"
```

Design rules that fall out of "easy":

- **One way in, one way out.** `Secret::new` and `expose()`. No builder, no trait to implement for the common case.
- **`expose()` is the audit point.** A reviewer greps for it. No `Deref`, no `AsRef`, no `Into<T>`: each would let the value
  out without the word `expose` appearing.
- **Safe by default, opt in to risk.** No `Clone`, no `Serialize` of the real value. `Serialize` writes the placeholder; a
  caller who truly needs the value serialized calls `expose()` themselves.
- **Fails closed.** A formatting trait we cannot make blank is not implemented, so using it is a compile error rather than a
  leak.

## 5. Scrubber semantics

A substring scrubber is the existing ConfigurAnt behaviour and is simple; it is also easy to defeat, so the limits are part
of the contract:

- It replaces every occurrence of each registered secret, longest first (so a secret that contains another is removed whole).
- It cannot catch a secret that was **transformed** before it reached the text (base64, URL-encoded, truncated, split
  across lines). It states this. It *may* additionally match a small, named set of common encodings (percent-encoding,
  base64) behind explicit opt-in, each with its own canary test. **Q2.**
- Very short secrets (say under 4 bytes) would blank ordinary words. Policy: refuse to register them with a clear error
  rather than silently scrub or silently skip. **Q3.**
- Empty secret: refused, never matches everything.
- ConfigurAnt today replaces the *whole message* with `<redacted>: the message quoted a secret value` when a secret appears.
  Replacing only the occurrences keeps the useful part of the message. The whole-message mode stays available
  (`clean_or_drop`) so ConfigurAnt's output need not change on adoption.

## 6. Fingerprints

Goal: two logs can say "same secret" without revealing it, and a leaked log does not let anyone test guesses cheaply.

- **Keyed**, not a bare hash: a bare hash of a low-entropy secret can be brute-forced from the log. The key is supplied by the
  caller (SecretAnt holds one per store); RedactAnt does not store keys.
- Output is a short prefix (default 8 hex chars, 32 bits). A short prefix is deliberate: it identifies within a handful of
  secrets and is useless for confirming a guess. It is **not** a security boundary and the docs say so.
- Different keys give different fingerprints for the same secret, so fingerprints do not link across systems.
- Primitive: a keyed hash from a reviewed crate (BLAKE3 keyed mode or HMAC-SHA-256 are the candidates). **UNVERIFIED**: I have
  not read either crate's current version, MSRV or audit status; choosing is the first task of slice 1, on crates.io
  versions only, newest (CireSnave's standing rules on dependencies).

## 7. Tests (the quality bar, per SecretAnt 3.5)

For each rule R below there is a test that pushes a canary string through the path, and a **negative control**: a mutated
version of the path that leaks, which must make the same assertion fail. A mutation that never applied would look like a
pass, so each control first asserts the mutation changed the output.

| Rule | Statement |
|---|---|
| R1 | `Display` and `Debug` of a `Secret`, alone and nested inside a struct, an `Option`, a `Vec` and a `HashMap`, never contain the value. |
| R2 | `Serialize` (serde, when enabled) never contains the value. |
| R3 | A panic message from `unwrap`/`expect` on a `Secret`-holding `Result` never contains it (the `Debug` of the error path). |
| R4 | The scrubber removes the value from a message, an error `source()` chain and a `Debug` of a wrapped error. |
| R5 | A fingerprint never contains the value and is stable for one key, different for two. |
| R6 | There is no safe-Rust way to reach the value without `expose()` (compile-fail tests, `trybuild`-style: `Deref`, `Clone`, `Into`). |
| R7 | Drop wipes the buffer (not tested here beyond `zeroize`'s own contract; stated as a limit). |

## 8. Ease of use (a release gate)

- README opens with the four-line example from section 4 and nothing before it.
- The example is compiled and run in CI (ConfigurAnt's row 30 pattern).
- Fresh-eyes trial of the published crate before the first release.
- Errors name what to do ("this secret is 2 bytes; the scrubber needs at least 4").
- Zero required features for the common path; `serde` is an opt-in feature.

## 9. Migration plan for the customers

1. RedactAnt publishes (PM publishes; the lane never does).
2. ConfigurAnt row 27: replace `REDACTED` and `appears_in` use with RedactAnt; delete the copies; its S3 canary test stays and
   must still fail against its own negative control.
3. SecretAnt drops its private copy (its section 3.5 stub) behind the same trait.
4. AuditAnt adopts when its needs are known.

Output compatibility goal: after step 2 ConfigurAnt prints the same text it prints today.

## 10. Decisions (PM answers, 2026-11-08)

- **Q1.** One crate, one `serde` feature.
- **Q2.** Encoding-aware scrubbing (percent, base64) later; the plain scrubber ships first.
- **Q3.** Refuse: registering a short secret fails with a named error at registration. Never scrub silently.
- **Q4.** Deferred: AuditAnt is not designed. Build the types so a field-level derive can be added later without breaking them
  (ROADMAP row 6; CireSnave's standing rule: push checks to compile time where applicable).
- **Q5.** Placeholder fixed at `<redacted>`. ConfigurAnt already emits exactly that, so migration changes no bytes. Tests assert
  the BYTES, never displayed text (a harness redaction layer can show `<redacted>` for real bytes; learned 2026-10-21).

## 11. Slice 1 (proposed ROADMAP row)

`Secret<T>` with blank `Display`/`Debug`, `expose()`, no `Clone`, zeroize on drop, R1 and R6 with negative controls, README
hello-world compiled in CI. Then slice 2 the scrubber (R4), slice 3 fingerprints (R5), slice 4 `serde` (R2, R3). Version
numbers are allocated by the PM at gate time.
