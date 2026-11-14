# Detector design: screening text for secrets we were not told about

Status: **design only. No code and no public API until the patent re-sweep gate (section 10) is cleared and the PM has read the result** (PM [TASK] 2026-11-14, restated 2026-11-14). Written 2026-11-14 by the
`redactant` lane. Facts about redactant were read at `origin/main` `6f3a653` (0.1.6; 0.1.2 is the published head). Facts about
other tools and crates are marked **UNVERIFIED** unless a version is quoted from `cargo search` on 2026-11-14.

## 1. Why this exists, and what it is not

SageAnt (Knowledge Store) must refuse to store a secret on every `put`. It asked for a trait that screens arbitrary text and
returns a *match class*, never the matched text. PM ruling 2026-11-14: **v1 is the registered route**, with no new redactant
API: SageAnt builds a `Scrubber`, `register`s the secrets it holds and calls `appears_in(put_text)`. That route catches "a secret
we hold", exactly, and nothing else.

This note designs the other half: text that **looks like** a secret although nobody registered it (a pasted API token, a PEM
private key, `postgres://user:pass@host`). `DESIGN.md` section 3 listed this as **out of scope for v1** ("detecting secrets by
guessing"). A consumer now exists. **PM ruling 2026-11-14 (Q1, yes, narrowly):** section 3 is amended to *shape-based screening
behind a feature, never on by default, never a claim of completeness*, with no code and no public API until the re-sweep gate
is cleared and the PM has read the result.

It is **not** a way to know that text is safe. A negative result means "none of the shapes below matched", never "no secret".

## 2. Contract (what every design below must keep)

1. **A result never contains matched text.** The result type has no `String`, `&str` or byte-slice field holding input; the
   only data is a class, a byte range and a count. A secret found in a put can therefore be logged, returned in an error, or
   put in an audit event without leaking it.
2. **The class is stable, coarse and named for the shape**, not for a vendor's product, so a refusal message says what to look
   for ("a PEM private key block") without echoing it.
3. **Linear time in the input.** The input is untrusted put text. No backtracking engine, no pattern whose cost can be driven
   up by the input, and a stated input cap the caller is told about.
4. **Nothing on by default that guesses.** High-precision shapes only unless the caller opts into noisier ones (section 6).
5. **Fails visible, not closed-silent.** A pattern set that cannot compile is an error at construction, never an empty detector
   that passes everything.
6. **No new trait in redactant.** SageAnt owns its thin screening trait (PM ruling); redactant offers a concrete type that can
   sit behind it. A trait here would be a second definition of one idea.

## 3. Sketch (illustrative; names are not final)

```rust
// feature = "detect" (off by default)
pub struct Detector { /* compiled rule set */ }
impl Detector {
    pub fn new() -> Self;                         // the default high-precision classes
    pub fn with(classes: &[Class]) -> Result<Self, DetectError>;
    pub fn screen(&self, text: &str) -> Screening;
}
pub struct Screening { /* findings, in input order, capped */ }
impl Screening { pub fn is_clean(&self) -> bool; pub fn findings(&self) -> &[Finding]; }
#[non_exhaustive] pub enum Class { PrivateKeyBlock, UrlCredentials, Jwt, ProviderToken, KeyValueSecret, HighEntropy }
pub struct Finding { pub class: Class, pub start: usize, pub len: usize }   // Debug prints class and range only
```

A `Finding` holds a byte range into the caller's own text. The caller already has that text, so the range adds no secret, but
the **length** of a secret is visible to anyone who sees the finding (log readers). Open question Q3 asks whether ranges are
returned by default or on request. `Class` and `DetectError` are `#[non_exhaustive]` from the first release so adding a class
is not a breaking change (row 1 types are untouched; this adds names only, as `DERIVE.md` section 5 argues).

## 4. Match classes

| Class | Shape (anchored, not a guess) | Precision stance |
|---|---|---|
| `PrivateKeyBlock` | a PEM header line `-----BEGIN ... PRIVATE KEY-----` (RSA, EC, OPENSSH, plain, ENCRYPTED) | very high; the header alone is enough to refuse |
| `UrlCredentials` | `scheme://user:password@host` with a non-empty password | high; a URL with a username and no password does not match |
| `Jwt` | three base64url segments, the first beginning `eyJ` and decoding to a JSON object with an `alg` field | high with the decode check, medium without; decode check is part of the design |
| `ProviderToken` | a fixed prefix plus a length and character set: the vendors publish these (AWS access key id `AKIA` + 16, GitHub `ghp_` + 36, Slack `xox` forms, Stripe `sk_live_`). **UNVERIFIED**: the table is filled from each vendor's current documentation at build time and each row carries its source and the date read | high per row; each row is its own test |
| `KeyValueSecret` | a key whose name is `password`, `passwd`, `secret`, `token`, `api_key`, `apikey`, `authorization` (case-insensitive) followed by `=` or `:` and a value of at least 8 non-space characters | **medium; opt-in**: prose such as "token: bucket" must not match, so the value must also look random (not a dictionary word) |
| `HighEntropy` | a token of 20 or more `[A-Za-z0-9+/_-]` characters whose Shannon entropy per character is at or above a threshold (starting point 4.0 bits for base64-like text, to be fitted on a corpus) | **low; opt-in**: hashes, UUIDs, git SHAs and base64 images all match; included only because some consumers want it, and named so |

## 5. Dependency options (the cost of "scan text for shapes")

SageAnt wants **zero required dependencies in core**, so the whole detector is behind a feature (`detect`), off by default, and
adds nothing for a consumer that does not enable it.

| Option | Crates (version from `cargo search`, 2026-11-14) | For | Against |
|---|---|---|---|
| A. `regex` | `regex` 1.13.1 | one pattern language for every class; **guaranteed linear time** (no backtracking), which section 2.3 needs; most reviewed | large compile time and binary size for a handful of patterns |
| B. `regex-lite` | `regex-lite` 0.1.9 | same pattern language, much smaller, also linear time | fewer features (no Unicode classes), which these ASCII shapes do not need; less widely deployed. **UNVERIFIED**: its worst-case guarantee must be read before choosing |
| C. `aho-corasick` + hand scanners | `aho-corasick` 1.1.5 | smallest dependency for the prefix classes | every non-prefix class (`Jwt`, `UrlCredentials`, entropy) becomes hand-written scanning code that has to be reviewed and fuzzed; more of our own bug surface |
| D. no dependency | none | nothing to track | all of C's cost, plus a prefix matcher of our own |

**Recommendation: B** if its linear-time guarantee reads true against its docs, else **A**. Both are one line in the feature
and compile the rule set once at `Detector::new`. Per CireSnave's rule, the newest crates.io version is used and the choice
is made on versions read on the day, not on this table.

## 6. False-positive policy

For a *refuse-the-write* consumer such as SageAnt, a false positive is a legitimate put that gets refused, so each class has a
written precision stance (section 4) and these rules:

1. **Default set = the classes marked high.** `KeyValueSecret` and `HighEntropy` need an explicit `with(...)`.
2. **The caller can drop a class**, never a single pattern at runtime from outside: suppression is by class, in code, visible in
   review.
3. **Each class ships with a measured precision claim**: a positive set and a near-miss set per class (a too-short `AKIA` id, a
   `PRIVATE KEY` in prose without dashes, a JWT-shaped string that fails the decode check). The claim is stated with the corpus
   and the date; "no known false positives" is not a claim.
4. **A shape that matches a documented example key** (the vendor's own `...EXAMPLE` value) is still a match; the detector does
   not know it is an example.
5. A class whose measured precision falls below the stated stance is demoted to opt-in or removed in the next release, noted in
   the changelog as the version rule requires.

## 7. Test plan (same bar as `DESIGN.md` section 7)

Each rule has a test **and a negative control** that must fail the same assertion, after asserting its mutation changed the
output.

| Id | Assertion | Negative control |
|---|---|---|
| X1 | each class matches its positive fixtures and reports that class | a build of the rule set with the class removed (the positives then go unreported) |
| X2 | each near-miss fixture is **not** reported | a loosened pattern that does match it |
| X3 | **no output form of a `Screening` or `Finding` (`Debug`, `Display`, `{:#?}`, serde) contains any byte of the input canary** | a hand-written finding type that carries the matched slice |
| X4 | input of the maximum size is screened in bounded time, and a pathological input (a long run of one character; deeply repeated prefix) does not blow up | a backtracking engine on the same input, which is slow |
| X5 | a rule set that fails to compile is an `Err`, not an empty detector | a constructor that swallows the error |
| X6 | the default set excludes `KeyValueSecret` and `HighEntropy` | a default that includes them |

**Fixtures never hold a real credential and never a string a secret scanner takes for one.** CodeRipper's SEC-002 reads git
history (gitleaks), so a literal `AKIA...` or a PEM header in a test file would be reported for as long as the commit exists.
Fixtures are **assembled at run time from fragments** (`concat!("AK", "IA", ...)`), and a test asserts the assembled form
matches while no tracked file contains it whole (a `git grep` positive control: the fragment is found, the assembled string is
not).

## 8. Limits stated up front

- It finds **shapes**. A secret that looks like ordinary text (a human-chosen password in prose) is never found; that is what
  the registered route is for.
- It does not decode: a token base64-encoded, URL-encoded, split across lines or interleaved with markup is not seen. The
  scrubber's encoding-aware mode (PM Q2) is a separate, later item.
- Vendor token formats change. The rule set is **volatile** (the ARC-003 sense): each change is a release, and the table's
  dates say how old each row is.
- `&str` only in v1; non-UTF-8 bytes are the caller's problem, as for the scrubber.
- It is not a security boundary and not a data-loss-prevention product.

## 9. Relation to the existing pieces

| Piece | Role |
|---|---|
| `Scrubber::appears_in` | exact bytes of a secret the caller holds: certain, no false positives; the v1 route for SageAnt |
| `Detector` (this note) | shapes of secrets nobody registered: probabilistic, class only |
| `Secret<T>` | unchanged; nothing here touches row 1 |
| a consumer's own trait | owned by the consumer (SageAnt); a `Detector` slots in behind it, as does any other implementation |

A natural later step, **not proposed here**: `Scrubber` could redact findings as well as registered secrets. That would put a
detector's false positives into message rewriting, which is a different risk and needs its own ruling.

## 10. Patent re-sweep plan (before any code)

`PATENT-SWEEP.md` covers 0.1.1 and says to re-sweep when a new capability family is added. This is one: **screening arbitrary
text for secrets by pattern or entropy and reporting only a class**. The gate is: *no code until a sweep of this family has a
verdict the PM accepts.*

- **Ideas to sweep:** (1) text screened against secret-shaped patterns (prefixes, PEM headers, URL credentials, JWT structure)
  with a refuse decision; (2) an entropy threshold applied to candidate tokens to classify a string as a credential;
  (3) a result type that deliberately omits the matched text so the finding can be logged; (4) key-name plus value-shape
  classification (`password=...`).
- **Known watch items from the first sweep:** IBM US11341270B2 claim 1 turns on an **entropy** threshold applied to a secret
  to choose what to register; Amazon US10073980B1 and US9910994B1 turn on tag-driven discovery plus log search. An entropy
  class in section 4 sits nearest to the IBM claim and must be read against it specifically, not assumed clear.
- **Routes:** the first sweep ran US-only Google Patents. For this family add **USPTO full-text** and **Espacenet** (named as
  not run last time), and **assignee searches** on the vendors that sell secret scanning (not read for this note; the search
  targets are named, no claim about them is made here). Independent claims of the closest hits are read whole.
- **Scope ruling (PM, 2026-11-14, Q2: yes):** the wider routes above are approved. A `needs-review` is read by the PM and CireSnave.
- **Output:** an update to `PATENT-SWEEP.md` (new ideas, queries, hits, verdicts), `needs-review` if any independent claim reads
  on a design element, and a design change to avoid it before code starts. Not legal advice; **there is no attorney, so a verdict
  is "outside as read" with the claim text quoted, never "clear"**. The IBM US11341270B2 entropy claim stays the watch item.

## 11. Slices (proposed, each its own PR, version numbers allocated by the PM)

1. Patent sweep verdict (docs). 2. `detect` feature with `PrivateKeyBlock`, `UrlCredentials`, X1-X6 and the run-time fixture
method. 3. `Jwt` and the provider table with sources and dates. 4. Opt-in `KeyValueSecret` and `HighEntropy` with a fitted,
published threshold and corpus. Each slice is stoppable: slice 2 alone already serves a refuse-the-write consumer.

## 12. Questions and answers

For the PM / CireSnave, **answered 2026-11-14 (PM [TASK] redactant-detect-answers):**

1. Does this amend `DESIGN.md` section 3? **YES, narrowly:** shape-based screening behind a feature, never on by default, never a
   claim of completeness; no code and no public API until the patent re-sweep gate is cleared and the PM has read the result.
   (`DESIGN.md` section 3 now says so.)
2. Is the wider re-sweep scope acceptable, and who reads a `needs-review`? **YES to USPTO full text, Espacenet and assignee
   searches; the PM and CireSnave read a `needs-review`; verdicts are "outside as read" with the claim text.**

For SageAnt's author, **sent 2026-11-14 as one numbered message (numbered 1-5 there); answers are recorded here when they
arrive:** SageAnt answered 2026-11-14 (its `docs/CONTRACT.md` D9; **a lane proposal, not a PM ruling**):

3. (SageAnt 1) Class only, or also the range? **Class only, never the range** (its audit log keeps the class, never content).
   Consequence for section 3: `Finding` drops `start` and `len` for this consumer; ranges would be an opt-in for a consumer that wants
   to redact, and no consumer has asked.
4. (SageAnt 2) Which classes? **Default on: PEM private key, URL credentials, JWT, provider tokens. Opt-in: `password=` lines,
   high-entropy.** This matches the default set in sections 4 and 6.
5. (SageAnt 3) False positive: **refuse by default; a per-put override must exist**, needing an explicit caller-held allow value
   (not a bool default), audit-logged with class and no content. The override lives in SageAnt, not in redactant: the detector
   has no allow switch per put, only the class set chosen at construction.
6. (SageAnt 4) Size and latency: **no fixed size; a per-collection byte cap set by the caller; budget unmeasured, proposed a few
   ms for 64 KiB, single pass.** Consistent with section 2.3; redactant measures this at slice 2 (X4) and states the number it
   actually reaches rather than adopting the proposal.
7. (SageAnt 5) Text only? **Text only (`&str`; its chunks are UTF-8 NFC); bytes not needed.** Matches section 8.

