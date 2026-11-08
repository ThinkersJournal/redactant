# redactant ROADMAP

| # | Row | Source | Status | Waits on |
|---|---|---|---|---|
| 1 | `Secret<T>`: blank `Display`/`Debug`, `expose()`, no `Clone`, zeroize; canary tests R1, R6 with negative controls; README hello-world compiled in CI | `docs/DESIGN.md` sections 4, 7, 11 | in review (branch secret-type, stacked on PR #1) | PR #1 merge |
| 2 | Scrubber (R4) | `docs/DESIGN.md` section 5 | open, needs 1 | row 1 |
| 3 | Keyed fingerprints (R5) | `docs/DESIGN.md` section 6 | open, needs 1 | row 1; primitive choice (UNVERIFIED) |
| 4 | `serde` feature (R2, R3) | `docs/DESIGN.md` section 7 | open, needs 1 | row 1 |
| 5 | ConfigurAnt row 27 adoption; SecretAnt stub removal | `docs/DESIGN.md` section 9 | held | rows 1-3 published (PM) |
| 6 | Field-level derive for structured redaction (AuditAnt); the row 1 types must allow it without breaking changes | `docs/DESIGN.md` Q4 | deferred | AuditAnt design |
