# redactant ROADMAP

| # | Row | Source | Status | Waits on |
|---|---|---|---|---|
| 1 | `Secret<T>`: blank `Display`/`Debug`, `expose()`, no `Clone`, zeroize; canary tests R1, R6 with negative controls; README hello-world compiled in CI | `docs/DESIGN.md` sections 4, 7, 11 | done (PR #2, 0.0.2) | - |
| 2 | Scrubber (R4) | `docs/DESIGN.md` section 5 | in review (branch scrubber) | PR merge |
| 3 | Keyed fingerprints (R5) | `docs/DESIGN.md` section 6 | in review (branch fingerprint); primitive: hmac 0.13.0 + sha2 0.11.1 (PM-approved) | PR merge |
| 4 | `serde` feature (R2, R3) | `docs/DESIGN.md` section 7 | open, needs 1 | row 1 |
| 5 | ConfigurAnt row 27 adoption; SecretAnt stub removal | `docs/DESIGN.md` section 9 | held | rows 1-3 published (PM) |
| 6 | Field-level derive for structured redaction (AuditAnt); the row 1 types must allow it without breaking changes | `docs/DESIGN.md` Q4 | deferred | AuditAnt design |
