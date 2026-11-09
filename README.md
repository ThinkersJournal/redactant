# redactant

Keep secrets out of logs, errors and config dumps. A `Secret<T>` prints as `<redacted>`, has one explicit way to get the
value out (`expose()`, easy to grep for), and wipes its memory when dropped. Around it: a scrubber that removes known
secrets from error messages, a keyed fingerprint to tell "same secret" apart without revealing it, and an opt-in `serde`
feature. Early releases (0.1.x): the API may still change in a minor version, and each change is in the CHANGELOG.

```toml
[dependencies]
redactant = { version = "0.1", features = ["serde"] } # drop `features` if you do not use serde
```

The `serde` feature is what makes `Secret<T>` implement `Serialize` and `Deserialize`; without it, a struct holding a
`Secret` that derives them will not compile.

The whole idea in four lines:

```rust
use redactant::Secret;

let token = Secret::new(String::from("s3cr3t-token"));
assert_eq!(token.to_string(), "<redacted>");
assert_eq!(format!("{token:?}"), "Secret(<redacted>)");
assert_eq!(token.expose(), "s3cr3t-token"); // the only way to the value
```

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

- `clean_error` renders the error and every `source()` below it joined with `": "` (`connect failed: bad token <redacted>`)
  and cleans the result; `clean_debug` cleans a `Debug` rendering.
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
- If you would rather drop a whole message than edit it, `clean_or_drop` returns the message unchanged when no secret is in it,
  and `<redacted>: the message quoted a secret value` when one is.
- **Binary secrets** (bytes that are not valid UTF-8) are refused with `RegisterError::NotUtf8`: the scrubber cleans text, so it
  could never find them as written. If such a secret reaches your logs as hex or base64, register that encoded form as its own
  `Secret<String>`.

A startup pattern that registers several secrets and keeps going when one is refused:

```rust
use redactant::{Scrubber, Secret};

let secrets = [
    Secret::new(String::from("s3cr3t-token")),
    Secret::new(String::from("abc")), // too short
    Secret::new(String::from("another-long-secret")),
];
let mut scrubber = Scrubber::new();
let mut problems = Vec::new();
for (i, secret) in secrets.iter().enumerate() {
    if let Err(e) = scrubber.register(secret) {
        problems.push(format!("secret #{i}: {e}")); // `RegisterError` implements Display and Debug
    }
}
assert_eq!(scrubber.len(), 2);
assert_eq!(problems.len(), 1);
```

## Tell two log lines apart without showing the secret

A fingerprint is a short, keyed tag: the same secret under the same key always gives the same tag.

```rust
use redactant::{FingerprintKey, Secret};

// EXAMPLE ONLY: do not copy this literal. Load your real key at startup (see below).
let key = FingerprintKey::new(b"a-key-of-at-least-16-bytes").expect("key long enough");
let a = Secret::new(String::from("s3cr3t-token"));
let b = Secret::new(String::from("s3cr3t-token"));
assert_eq!(a.fingerprint(&key), b.fingerprint(&key));
assert_eq!(a.fingerprint(&key).to_string().len(), 11); // "fp:" and 8 hex characters
```

- The key must be at least 16 bytes and must stay the same across restarts if you want tags to match across time. Different
  keys give different tags, so tags do not link across systems.
- **Where the key comes from:** generate it once from a cryptographic random source (for example `openssl rand -hex 32`; any
  bytes work, this crate does not interpret them), keep it in an environment variable or your secret store, and never commit
  it. Read it into a `Secret` first, so it is blank in your own logs too, and pass its bytes to `FingerprintKey::new`.
- **Rotation:** changing the key changes every tag, so lines logged before and after a rotation will not match. Rotate on a
  schedule you can live with, or not at all.
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

### Persisting a config that holds a secret

Best: do not. Keep the real secret in an environment variable or secret store, load it at startup, and write the config
without it. If you must write the real value to a file, say so explicitly with `serialize_with` and `expose()`, and protect
that file as you would the secret itself:

```rust
use redactant::Secret;
use serde::{Deserialize, Serialize};

fn write_real_value<S: serde::Serializer>(secret: &Secret<String>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(secret.expose()) // the one place this config writes the plaintext
}

#[derive(Serialize, Deserialize)]
struct Stored {
    #[serde(serialize_with = "write_real_value")]
    token: Secret<String>,
}

let stored = Stored { token: Secret::new(String::from("s3cr3t-token")) };
let json = serde_json::to_string(&stored).unwrap();
assert_eq!(json, r#"{"token":"s3cr3t-token"}"#);
let back: Stored = serde_json::from_str(&json).unwrap();
assert_eq!(back.token.expose(), "s3cr3t-token");
```

## What it does not do

Encrypt or store secrets (that is SecretAnt's job), lock memory, guess which strings are secrets, or redact values it was
never told about. Zeroizing on drop wipes the buffer the `Secret` owns; copies you made with `expose()` are yours to manage.

Licensed under either of the Apache License, Version 2.0 (`LICENSE-APACHE`) or the MIT licence (`LICENSE-MIT`), at your
option.
