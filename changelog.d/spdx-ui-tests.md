kind: SPDX headers on the trybuild test sources
---
Adds the `SPDX-License-Identifier: MIT OR Apache-2.0` header to `tests/ui-pass/expose.rs` and `tests/ui/{as_ref,clone,deref,field,into}.rs` (closes #18). The header shifts every line by one, so the five `tests/ui/*.stderr` snapshots were regenerated with `TRYBUILD=overwrite cargo +1.99.1 test --features ui-tests --test compile_fail`; the diff is the line number in each snapshot and nothing else. Verified: compile_fail passes on rustc 1.99.1 without the overwrite flag.
