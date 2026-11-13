kind: ci: repin the portfolio caller to coderipper 42dd497
---
CI only: the advisory `portfolio` job called coderipper `portfolio.yml@30e012b7` (CodeRipper 0.9.6), which cannot parse the `[architecture]` table declared in 0.1.6 and so failed to run the allowlist and version-consistency rules. It now calls the merge commit of coderipper#313 (`42dd497d`, CodeRipper 0.43.49, one-fragment version rule). No code change.
