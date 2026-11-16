kind: repin portfolio to coderipper 0.47.5
---
Moves the portfolio caller in `ci.yml` to coderipper c72a6e0 (the workflow that installs 0.47.5). `migrate-rule-ids.py` reports nothing to migrate: `.coderipper.toml` names no check or blocking rule and no file calls `coderipper check <old>`. No code change; verified by reading the whole Portfolio job on this PR.
