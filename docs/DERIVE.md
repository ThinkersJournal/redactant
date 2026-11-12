# Field-level derive: what RedactAnt needs and offers (ROADMAP row 6)

Status: **design, nothing built.** Written 2026-11-12 by the `redactant` lane on the PM's [TASK]. Independent of AuditAnt:
AuditAnt is only a claimed name with no lane and no design (PM, 2026-11-12), so this note says what RedactAnt can offer
any consumer that wants *structured* redaction (a whole struct or enum, field by field) and lists in section 9 what only
that consumer's author can decide. Code below is illustrative; names are not final. Facts about the shipped types were
read from `src/lib.rs`, `src/fingerprint.rs`, `src/scrubber.rs` at `bc0db57` (2026-11-12).

## 1. The problem

`Secret<T>` protects one value you remembered to wrap. A structured record (an audit event, a request log, a config dump)
has many fields of which some are secret, some identifying, some safe. Today the author hand-writes the choice per field
and nothing fails when a new field is added and the choice is forgotten. The derive makes the choice **mandatory and
visible** per field, and makes forgetting a compile error.

## 2. Shape: one trait, one derive, one sink

```rust
// in redactant (always present; the derive macro itself is behind feature `derive`)
pub trait Redact {
    /// Describe `self` field by field to `sink`. Never hands the sink a value the field's disposition forbids.
    fn describe(&self, cx: &Context<'_>, sink: &mut dyn Sink);
}

pub struct Context<'k> { key: Option<&'k FingerprintKey> }   // the caller's fingerprint key, if any

#[non_exhaustive]
pub enum Disposition<'a> {
    Redacted,                          // value withheld; prints as PLACEHOLDER
    Fingerprint(Fingerprint),          // keyed tag; Redacted if the Context has no key (fails closed)
    Kept(&'a dyn core::fmt::Debug),    // explicitly safe to show
}

pub trait Sink {
    fn field(&mut self, path: &[Segment<'_>], d: Disposition<'_>);   // Segment: Field(&str) | Variant(&str) | Index(usize) | Key(&dyn Debug-as-key)
}
```

Why a sink and not "return a string or a map": the consumer (an audit writer, a JSON logger, a test) decides the output
format and RedactAnt stays free of any event model. Two helpers ship so the common case is zero code: `x.redacted()`
returns a view whose `Display`/`Debug` print the tree with dispositions applied (`User { name: <redacted>, id: fp:3f9a1c7e,
role: "admin" }`), and a `serde` adapter implements `Sink` into any `Serializer` (feature `serde`, already an opt-in).

The derive lives in a separate proc-macro crate (`redactant-derive`), re-exported as `redactant::Redact` under
`feature = "derive"` (the standard split; a proc-macro crate cannot also export a trait). Both crates carry **one version
number** (CireSnave's one-version rule); the PM publishes both, derive first.

## 3. Attribute syntax

```rust
#[derive(Redact)]
struct Login {
    #[redact(keep)]            user: String,          // safe to show
    #[redact(fingerprint)]     email: String,         // "same email" without the email
    #[redact]                  note: String,          // withheld (bare `redact` = withhold)
    password: Secret<String>,                         // a Secret<T> field needs no attribute: it is withheld
    #[redact(nested)]          session: Session,      // Session: Redact; recurse
}
```

Rules, each enforced at compile time:

1. **Every field must state a disposition.** An unannotated field is an error naming the field and the three choices.
   Adding a field later breaks the build until someone decides. This is the point of the derive. `Secret<T>` fields are the
   one exception (their type already says "withhold"), and annotating one `keep` is an error (rule 3).
2. Struct-level `#[redact(default = "redact")]` (or `"fingerprint"`) may supply the disposition for unannotated fields,
   for authors who want fail-closed-by-default instead of forced-decision. `default = "keep"` is **not accepted**: the
   safe direction must be the cheap one.
3. **`keep` requires a marker trait `Keep`**, implemented by RedactAnt for primitives, `str`/`String`, `bool`, `char`, and
   `Option`/`Vec`/arrays/tuples of `Keep`; **not** for `Secret<T>` or any type that has not opted in.
   A user type opts in by `impl Keep for Id {}` (a visible, greppable act, like `expose()`). This closes the
   hole "marked `keep`, but the field is a `Secret` or a struct holding one".
4. `fingerprint` requires the field type to be `AsRef<[u8]>` (so `String`, `Vec<u8>`, `&str`, `[u8; N]`).
5. `nested` requires the field type to be `Redact`. `Option<T>`, `Vec<T>`, `Box<T>`, `[T; N]` and maps with `Redact`
   values are `Redact` when `T` is (blanket impls); the path gets `Index`/`Key` segments.
6. A disposition on a collection applies to every element (`#[redact(keep)] tags: Vec<String>`); mixing per element is
   `nested` over a type that has its own derive.
7. Unknown or conflicting attributes (`keep` with `fingerprint`), `union`, and a `#[redact]` on a unit field are errors.
8. Generic types: `impl<T: Redact> Redact for Wrapper<T>` is generated with the bounds the attributes imply
   (`nested` adds `T: Redact`, `keep` adds `T: Keep`).

**Enums.** The variant name is always kept (it is a code identifier, not data) and appears as a `Variant` path segment.
Each variant's fields follow the same rules; a variant may carry `#[redact(default = ...)]`. Tuple fields are annotated
positionally the same way. `#[redact(skip)]` is **not offered**: a field the sink never sees is a field no reviewer can
see was dropped on purpose; `redact` shows its existence with the value withheld.

## 4. How an audit event consumes it

```rust
#[derive(Redact)] struct Event { #[redact(keep)] action: &'static str, #[redact(nested)] actor: Login, ... }

let mut w = MyAuditWriter::new();            // implements redactant::Sink
event.describe(&Context::with_key(&fp_key), &mut w);
```

The writer receives `(path, Disposition)` pairs and never a raw value except through `Kept`, which the author declared
safe. It chooses the output format and decides what a `Redacted` field is called on disk (the shipped answer is
`PLACEHOLDER`; the *presence* of the field is itself information an audit trail wants). The fingerprint key comes from the
`Context`, so RedactAnt still stores no keys (design section 6); with no key, `fingerprint` degrades to `Redacted`,
never to a bare hash.

## 5. No-breaking-change check against row 1 (and rows 2-4)

The derive must not change any item published in 0.1.x. What it adds, and why each is additive:

| Change | Why it breaks nothing |
|---|---|
| new trait `Redact`, `Sink`, `Context`, `Segment`, `Disposition` (`#[non_exhaustive]`), marker `Keep` | new names; a downstream crate cannot already have impls of a trait that did not exist |
| `impl Redact for Secret<T>` (disposition `Redacted`) | `Secret`'s fields, bounds (`T: Zeroize`) and existing impls (`Display`, `Debug`, `Drop`, `Serialize`) are untouched; one new impl of a new trait |
| `impl Redact for Fingerprint` (kept: it is already public-safe text) | same |
| `FingerprintKey::tag(&self, &[u8]) -> Fingerprint` (needed because `fingerprint` fields are not `Secret`) | new inherent method; shares `tag()` with `Secret::fingerprint`, so the two cannot diverge |
| `feature = "derive"` | new feature, off by default; existing feature list unchanged |

Things that would break and are therefore **forbidden** by this design: adding `Clone`, `Deref`, `AsRef` or `Into` to
`Secret` (R6); changing the `Secret<T: Zeroize>` bound; making `Secret` generic over a policy parameter; changing
`PLACEHOLDER`; adding variants to a public enum without `#[non_exhaustive]` (hence the attribute on `Disposition` from the
first release). The blanket `Keep` impls must be written before 1.0 and then only grow. A mechanical check ships with the
implementation: `cargo semver-checks` (or `cargo public-api` diff) against the published 0.1.2 must report additions only.
**Row 1 needs no code change to allow the derive**: that part of the PM's condition holds today; the risk is only in
what the implementation PRs touch, which the semver check guards.

## 6. Test plan

Same bar as design section 7: each rule has a canary test **and a negative control that must fail the same assertion**, and
every control first asserts its mutation changed the output (a mutation that never applied looks like a pass). All
assertions are on BYTES.

**Canary tests (`tests/derive_canary.rs`).** One fixture type with a distinct canary string in *every* disposition-bearing
position: a `Secret` field, a `redact` field, a `fingerprint` field, a nested struct's `redact` field, an enum variant's
field, an `Option`, a `Vec` element, a `HashMap` value. Push it through (a) the `redacted()` view `Display`/`Debug`/`{:#?}`
and padded forms, (b) a recording `Sink`, (c) the serde adapter into `serde_json`, (d) a panic message from `unwrap` on a
`Result` carrying the type. Assertions:

| Id | Assertion | Negative control (must make the assertion fail) |
|---|---|---|
| D1 | no `redact`/`Secret`/`fingerprint` canary appears in any output | a hand-written `Redact` impl for the same type that passes `Kept(&self.field)` for the secret field |
| D2 | the `keep` field's value **does** appear (so D1 cannot pass by printing nothing) | a fixture variant that withholds it |
| D3 | fingerprint output is `fp:` + 8 hex, equal for equal input and key, different for a different key, never contains the input | a variant that emits the input in place of the tag |
| D4 | no key in `Context` means `Redacted`, not a bare hash and not the value | a variant that falls back to `Kept` |
| D5 | every path is reported: the sink's path set equals the expected list (variant and index segments included) | a variant that drops a nested field (set differs) |
| D6 | a field added to a *passing* fixture type with no attribute stops compiling (below) | n/a (it is a compile-fail case) |

**Compile-fail tests (`tests/ui/derive_*.rs`, trybuild, in the existing `ui-tests` job).** Each has a **pass twin** in
`tests/ui-pass/` that differs only by the fix, so the harness cannot fail for an unrelated reason:

| Case | Fails because | Pass twin |
|---|---|---|
| unannotated field | rule 1 | same struct with `#[redact]` added |
| `#[redact(keep)]` on a `Secret<T>` field | rule 3 | field with no attribute |
| `keep` on a user type without `impl Keep` | rule 3 | same type after `impl Keep` |
| `fingerprint` on a type that is not `AsRef<[u8]>` | rule 4 | a `String` field |
| `nested` on a type without `Redact` | rule 5 | the type with `#[derive(Redact)]` |
| `default = "keep"` | rule 2 | `default = "redact"` |
| `keep` + `fingerprint` together; unknown key; `union` | rule 7 | single valid attribute |
| enum variant field unannotated | rule 1 for enums | annotated |

**Also:** `cargo semver-checks` against 0.1.2 in CI (section 5); the existing R1-R6 suites must pass unchanged (they are
the regression proof that row 1 did not move); a macro-hygiene test (derive inside a module that shadows `Option`,
`Result`, `Some`; generic struct; lifetime parameter; `where` clause); `trybuild` stderr pinned on the CI rustc only
(existing practice).

## 7. Limits stated up front (so nobody assumes them)

- The derive controls what *this type's* `describe` reveals. It cannot stop a `Kept` value that the author wrongly
  declared safe (`impl Keep` is the audit point), nor a secret that was copied into an un-derived type earlier.
- It does not scrub text. Free-form strings that *might* quote a secret still go through `Scrubber`; a `keep` on a
  `String` that holds an error message is the author's claim, and the docs say to prefer `redact` for free text.
- A fingerprint is the existing 4-byte keyed tag: it identifies within a few values and is not a security boundary.
- Not offered: reversible/encrypted fields (that is SecretAnt), a per-field custom redactor closure (it would be a second,
  unchecked way to leak; revisit only on a named customer need), runtime-configured policies.

## 8. Slices (proposed; each a PR with its own fragment, numbers allocated by the PM)

1. Core traits and blanket impls, `Secret`/`Fingerprint` impls, `FingerprintKey::tag`, the `redacted()` view, D1-D5 with
   hand-written impls (no macro yet), semver check in CI. 2. `redactant-derive` for structs, compile-fail cases for rules
   1-5, 7. 3. Enums, generics, collections, hygiene tests. 4. serde sink adapter. Re-run `PATENT-SWEEP.md` at slice 1
   (a new capability family: structured redaction), per its own rule.

## 9. Questions only AuditAnt's author can answer

1. **Event shape.** Are events typed Rust structs known at compile time (the derive fits), or built dynamically from maps
   (a derive does not; a `Sink`-fed builder would be needed instead)?
2. **Output format and typing.** Is `Kept(&dyn Debug)` enough, or must kept values arrive typed (number vs string, via
   `Serialize`) so the audit store keeps types? If typed, `Keep` implies `serde::Serialize` under the `serde` feature.
3. **Fingerprint key ownership.** One key per process, per store, per tenant? Rotation: must old and new fingerprints stay
   comparable (a key id in the output)?
4. **Is the field's *existence* sensitive?** `Redacted` prints a placeholder for the field. If even a field name may not
   appear in some trails, a fourth disposition (`Omit`) is needed, which conflicts with the "no skip" stance in section 3.
5. **Integrity.** Does the audit trail hash-chain or sign records? If so, is the chain over the redacted form (then
   redaction must be deterministic, which it is) or must a redaction marker be inside the signed bytes?
6. **Schema evolution.** Does a changed disposition (`keep` to `redact`) count as a schema change for stored events, and
   should the derive emit a per-type schema fingerprint to detect it?
7. **Default policy.** Forced-decision per field (section 3 rule 1) or struct-level default `redact` (rule 2): which does the
   author want as the recommended style? Both are cheap; one needs to be the documented default.
8. **Ownership and async.** Does `describe` need to hand data to a writer on another thread (then `Disposition::Kept`
   would have to own its value, which changes the sketch to an owned `enum`)?
9. **Who consumes `Redact` besides AuditAnt?** If nobody, the serde adapter could be the only public sink and the trait
   stay narrow.

Until these are answered, nothing above is built; slice 1 is safe to start without them (it adds no macro and no
AuditAnt-specific choice), so the PM can release it independently if a second consumer appears first.
