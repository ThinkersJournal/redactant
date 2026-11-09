```rust
use redactant::Secret;

let token = Secret::new(String::from("s3cr3t-token"));
assert_eq!(token.to_string(), "<redacted>");
assert_eq!(format!("{token:?}"), "Secret(<redacted>)");
assert_eq!(token.expose(), "s3cr3t-token"); // the only way to the value
```

# redactant

Keep secrets out of logs, errors and config dumps. A `Secret<T>` prints as `<redacted>`, has one explicit way to get the
value out (`expose()`, easy to grep for), and wipes its memory when dropped. Around it: a scrubber that removes known
secrets from error messages, a keyed fingerprint to tell "same secret" apart without revealing it, and an opt-in `serde`
feature. Pre-release (`publish = false`); design in `docs/DESIGN.md`.

There is deliberately no `Clone`, `Deref`, `AsRef` or `Into<T>` on `Secret`: each would let the value out without the word
`expose` appearing.

## Use the value

`expose()` returns a reference to what you stored:

```rust
use redactant::Secret;

let token = Secret::new(String::from("s3cr3t-token"));
let header = format!("Bearer {}", token.expose()); // goes to the wire, not to a log
assert_eq!(header, "Bearer s3cr3t-token");
```

## Scrub an error message

A library error often quotes the very value that was wrong. Register your secrets once, then clean anything you are about to
log:

```rust
use redactant::{Scrubber, Secret};

let token = Secret::new(String::from("s3cr3t-token"));
let mut scrubber = Scrubber::new();
scrubber.register(&token).expect("a usable secret");

let err = std::io::Error::other("401 for Bearer s3cr3t-token");
assert_eq!(scrubber.clean_error(&err), "401 for Bearer <redacted>");
assert_eq!(scrubber.clean("token=s3cr3t-token"), "token=<redacted>");
```

- `clean_error` cleans the error and every `source()` below it; `clean_debug` cleans a `Debug` rendering.
- `register` takes a `Secret<String>`, a `Secret<Vec<u8>>`, or any `Secret<T>` whose bytes are valid UTF-8.
- **It refuses what it cannot do safely, by name, and keeps what you registered before:** an empty secret, one under 4 bytes
  (it would blank ordinary words), or non-UTF-8 bytes. Decide whether a refusal should fail startup or just be logged:

```rust
use redactant::{RegisterError, Scrubber, Secret};

let mut scrubber = Scrubber::new();
let short = Secret::new(String::from("abc"));
assert_eq!(scrubber.register(&short), Err(RegisterError::TooShort { len: 3 }));
assert!(scrubber.is_empty()); // nothing was registered, and the scrubber is still usable
```

- **Limit:** it finds the plain bytes of a secret you registered. A secret that was base64- or URL-encoded, truncated or split
  across lines before it reached the text is not found. It cannot redact a value it was never told about.
- If you would rather drop a whole message than edit it, `clean_or_drop` does that.

## Tell two log lines apart without showing the secret

A fingerprint is a short, keyed tag: the same secret under the same key always gives the same tag.

```rust
use redactant::{FingerprintKey, Secret};

// Keep this key somewhere stable (your config or a secret store); it is never stored here.
let key = FingerprintKey::new(b"a-key-of-at-least-16-bytes").expect("key long enough");
let a = Secret::new(String::from("s3cr3t-token"));
let b = Secret::new(String::from("s3cr3t-token"));
assert_eq!(a.fingerprint(&key), b.fingerprint(&key));
assert_eq!(a.fingerprint(&key).to_string().len(), 11); // "fp:" and 8 hex characters
```

- The key must be at least 16 bytes and must stay the same across restarts if you want tags to match across time. Different
  keys give different tags, so tags do not link across systems.
- The tag is 4 bytes on purpose, so **two different secrets can share a tag**: "same tag" is a hint, not proof, and the tag
  is not a security boundary. Keyed, so a leaked log cannot be tested against guesses without the key.

## serde (opt in)

Enable the feature: `redactant = { version = "...", features = ["serde"] }`.

- `Serialize` writes `"<redacted>"`, never the value, so a config struct holding secrets can be logged as JSON safely.
- `Deserialize` reads the real value into a `Secret`.
- **A serialize-then-deserialize round trip cannot carry the secret.** Reading the written `"<redacted>"` back is an error (not
  a silent secret whose value is the word `<redacted>`), because the real value was dropped when it was written. Serialize the
  real value yourself with `expose()` if you really need to persist it.

```rust
use redactant::Secret;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Config {
    host: String,
    token: Secret<String>,
}

let cfg: Config = serde_json::from_str(r#"{"host":"h","token":"s3cr3t-token"}"#).unwrap();
let written = serde_json::to_string(&cfg).unwrap();
assert_eq!(written, r#"{"host":"h","token":"<redacted>"}"#);
assert!(serde_json::from_str::<Config>(&written).is_err()); // the round trip fails loudly
```

## What it does not do

Encrypt or store secrets (that is SecretAnt's job), lock memory, guess which strings are secrets, or redact values it was
never told about. Zeroizing on drop wipes the buffer the `Secret` owns; copies you made with `expose()` are yours to manage.

Licensed under either of the Apache License, Version 2.0 (`LICENSE-APACHE`) or the MIT licence (`LICENSE-MIT`), at your
option.
