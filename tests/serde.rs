// SPDX-License-Identifier: MIT OR Apache-2.0
//! R2: `Serialize` never contains the value. R3: a panic message from `unwrap`/`expect` on a `Secret`-holding
//! `Result` never contains it. Assertions are on BYTES. Each rule has a negative control that must trip the same check.
#![cfg(feature = "serde")]

use redactant::Secret;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

const CANARY: &str = "CANARY-9f3a7c1e-do-not-print";

fn contains(h: &[u8], n: &str) -> bool {
    h.windows(n.len()).any(|w| w == n.as_bytes())
}

#[derive(Serialize)]
struct Holder {
    token: Secret<String>,
    maybe: Option<Secret<String>>,
    many: Vec<Secret<String>>,
    map: BTreeMap<&'static str, Secret<String>>,
}

fn holder() -> Holder {
    Holder {
        token: Secret::new(CANARY.into()),
        maybe: Some(Secret::new(CANARY.into())),
        many: vec![Secret::new(CANARY.into())],
        map: BTreeMap::from([("k", Secret::new(CANARY.into()))]),
    }
}

#[test]
fn serialize_writes_the_placeholder_bytes() {
    let s = Secret::new(CANARY.to_string());
    assert_eq!(serde_json::to_vec(&s).unwrap(), b"\"<redacted>\"");
}

#[test]
fn serialize_nested_never_leaks() {
    let h = holder();
    // Read every field so the structure is real, not dead code.
    assert_eq!(h.token.expose(), CANARY);
    assert_eq!(
        h.maybe.as_ref().map(|s| s.expose().len()),
        Some(CANARY.len())
    );
    assert_eq!(h.many.len() + h.map.len(), 2);
    let out = serde_json::to_vec(&h).unwrap();
    assert!(!contains(&out, CANARY));
    assert_eq!(
        out,
        br#"{"token":"<redacted>","maybe":"<redacted>","many":["<redacted>"],"map":{"k":"<redacted>"}}"#
    );
}

#[test]
fn deserialize_reads_the_value_into_a_secret() {
    #[derive(Deserialize)]
    struct Cfg {
        token: Secret<String>,
    }
    let c: Cfg = serde_json::from_str(&format!("{{\"token\":\"{CANARY}\"}}")).unwrap();
    assert_eq!(c.token.expose(), CANARY);
    assert_eq!(format!("{}", c.token).as_bytes(), b"<redacted>");
}

/// Built through a function so clippy does not flag the deliberate unwrap of a known `Err`.
fn fail<E>(e: E) -> Result<(), E> {
    std::hint::black_box(Err(e))
}

fn succeed<T>(v: T) -> Result<T, ()> {
    std::hint::black_box(Ok(v))
}

/// The panic message of `f`, as bytes.
fn panic_bytes(f: impl FnOnce()) -> Vec<u8> {
    // The panic hook is process-wide: serialise the swap so parallel tests cannot restore each other's hook.
    static HOOK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = HOOK.lock().unwrap_or_else(|e| e.into_inner());
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = catch_unwind(AssertUnwindSafe(f));
    std::panic::set_hook(prev);
    let payload = r.expect_err("the closure was supposed to panic");
    match payload.downcast::<String>() {
        Ok(s) => s.into_bytes(),
        Err(p) => p
            .downcast::<&str>()
            .expect("string payload")
            .as_bytes()
            .to_vec(),
    }
}

#[test]
fn unwrap_and_expect_panics_never_leak() {
    let unwrap = panic_bytes(|| {
        let r: Result<(), Secret<String>> = fail(Secret::new(CANARY.into()));
        r.unwrap();
    });
    let expect = panic_bytes(|| {
        let r: Result<(), Secret<String>> = fail(Secret::new(CANARY.into()));
        r.expect("loading config");
    });
    let unwrap_err = panic_bytes(|| {
        let r: Result<Secret<String>, ()> = succeed(Secret::new(CANARY.into()));
        r.unwrap_err();
    });
    for out in [&unwrap, &expect, &unwrap_err] {
        assert!(!contains(out, CANARY));
    }
    assert_eq!(
        unwrap,
        b"called `Result::unwrap()` on an `Err` value: Secret(<redacted>)"
    );
}

// ---- negative controls ----

#[derive(Serialize)]
struct LeakyHolder {
    token: String,
}

struct LeakyErr(String);

impl std::fmt::Debug for LeakyErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LeakyErr({})", self.0)
    }
}

#[test]
fn control_leaky_serialize_is_caught() {
    let out = serde_json::to_vec(&LeakyHolder {
        token: CANARY.into(),
    })
    .unwrap();
    assert!(contains(&out, CANARY));
    // The real check passes on the real type, so the difference is the mutation.
    assert!(!contains(&serde_json::to_vec(&holder()).unwrap(), CANARY));
}

#[test]
fn control_leaky_panic_is_caught() {
    let out = panic_bytes(|| {
        let r: Result<(), LeakyErr> = fail(LeakyErr(CANARY.into()));
        r.unwrap();
    });
    assert!(contains(&out, CANARY));
}
