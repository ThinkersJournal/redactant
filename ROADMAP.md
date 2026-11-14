# redactant ROADMAP

| # | Row | Source | Status | Waits on |
|---|---|---|---|---|
| 1 | `Secret<T>`: blank `Display`/`Debug`, `expose()`, no `Clone`, zeroize; canary tests R1, R6 with negative controls; README hello-world compiled in CI | `docs/DESIGN.md` sections 4, 7, 11 | done (PR #2, 0.0.2) | - |
| 2 | Scrubber (R4) | `docs/DESIGN.md` section 5 | done (PR #3, 0.0.3) | - |
| 3 | Keyed fingerprints (R5) | `docs/DESIGN.md` section 6 | done (PR #6, 0.0.5); hmac 0.13.0 + sha2 0.11.1 | - |
| 4 | `serde` feature (R2, R3) | `docs/DESIGN.md` section 7 | done (PR #4, 0.0.4) | - |
| 5 | ConfigurAnt row 27 adoption; SecretAnt stub removal | `docs/DESIGN.md` section 9 | unblocked: 0.1.2 published and tagged v0.1.2 (2026-11-09); consumer lanes adopt (ConfigurAnt row 27 adopted 0.1.2; SecretAnt consuming it) | consumer lanes; redactant answers API questions |
| 6 | Field-level derive for structured redaction (AuditAnt); the row 1 types must allow it without breaking changes | `docs/DESIGN.md` Q4 | redactant-side design written (`docs/DERIVE.md`, 2026-11-12); build deferred | AuditAnt author's answers (DERIVE.md section 9); slice 1 needs none |
| 7 | Detector: screen text for secret shapes, class only (SageAnt asked 2026-11-14) | `docs/DETECT.md` | design written; no code and no API until the PM reads it and a patent re-sweep of the family has a verdict; v1 for SageAnt is the registered route (`Scrubber::appears_in`) | PM; patent re-sweep |
