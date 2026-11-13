kind: chore: [architecture] declaration; Secret moves to its own module (ARC/MOD programme)
---
Declares `[architecture]` in `.coderipper.toml` (components secret, fingerprint, scrubber, api; layers core, services, facade; ARC/MOD programme, CireSnave 2026-11-12). The crate root held `Secret` and also re-exported the other modules, which coderipper read as a cycle (ARC-001/ARC-002); `Secret` and `PLACEHOLDER` now live in `src/secret.rs` and `lib.rs` only declares and re-exports. Public paths are unchanged (`redactant::Secret`, `redactant::PLACEHOLDER`); no behaviour change.
