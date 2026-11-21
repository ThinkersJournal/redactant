kind: serde sink adapter (DERIVE slice 4)
---
New `redactant::serde_sink::serialize` and `Redact::serde_view` (feature `serde`): write a record's field dispositions into any `serde::Serializer` as a flat map keyed by path (`role`, `login.email`, `items[0]`). `Redacted` is written as the placeholder, `Fingerprint` as its `fp:` text (placeholder without a key), only `Keep` fields as themselves. It is an output of `describe`, not a tree masker (PATENT-SWEEP Re-sweep 4). Verified by byte-level canary tests with a negative control.
