kind: coderipper 0.43.77 repin; declare no composition root
---
Repins the portfolio caller in `ci.yml` to coderipper 58e2f7a (workflow installs 0.43.77) and adds `none = ["composition"]` to `[architecture]` in `.coderipper.toml`: the crate only re-exports and wires nothing, so ARC-012 now runs with 0 sites by declaration instead of reading "not run". The other optional inputs (volatile, api_budget, owns_data) stay declared. No code change; verified by reading the whole portfolio job log on this PR.
