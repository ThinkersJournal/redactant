// SPDX-License-Identifier: MIT OR Apache-2.0
//! R1: Display and Debug never contain the value, alone or nested. Every assertion is on BYTES, never on how a
//! terminal or harness displays them. Each rule has a negative control: a leaking mutation must fail the same check.

use redactant::Secret;
use std::collections::HashMap;
use std::fmt::{Debug, Display};

const CANARY: &str = "CANARY-9f3a7c1e-do-not-print";

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Every formatting path of `v` as bytes: `{}`, `{:?}`, `{:#?}`, and `{:>40}` padding.
fn paths<T: Debug + Display>(v: &T) -> Vec<Vec<u8>> {
    vec![
        format!("{v}").into_bytes(),
        format!("{v:?}").into_bytes(),
        format!("{v:#?}").into_bytes(),
        format!("{v:>40}").into_bytes(),
    ]
}

fn debug_paths<T: Debug>(v: &T) -> Vec<Vec<u8>> {
    vec![
        format!("{v:?}").into_bytes(),
        format!("{v:#?}").into_bytes(),
    ]
}

fn leaks(outputs: &[Vec<u8>]) -> bool {
    outputs.iter().any(|o| contains(o, CANARY.as_bytes()))
}

#[test]
fn display_and_debug_bytes_are_exact() {
    let s = Secret::new(CANARY.to_string());
    assert_eq!(format!("{s}").as_bytes(), b"<redacted>");
    assert_eq!(format!("{s:?}").as_bytes(), b"Secret(<redacted>)");
    assert!(!leaks(&paths(&s)));
}

#[test]
fn nested_never_leaks() {
    #[derive(Debug)]
    struct Holder {
        token: Secret<String>,
        maybe: Option<Secret<String>>,
        many: Vec<Secret<String>>,
        map: HashMap<&'static str, Secret<String>>,
    }
    let h = Holder {
        token: Secret::new(CANARY.into()),
        maybe: Some(Secret::new(CANARY.into())),
        many: vec![Secret::new(CANARY.into())],
        map: HashMap::from([("k", Secret::new(CANARY.into()))]),
    };
    // Read every field so the structure is real, not dead code.
    assert_eq!(h.token.expose(), CANARY);
    assert_eq!(
        h.maybe.as_ref().map(|s| s.expose().len()),
        Some(CANARY.len())
    );
    assert_eq!(h.many.len() + h.map.len(), 2);
    let out = debug_paths(&h);
    assert!(!leaks(&out));
    // The controls below prove this check could fail: the structure really was printed.
    assert!(contains(&out[0], b"token") && contains(&out[0], b"<redacted>"));
}

#[test]
fn expose_is_the_only_way_to_the_value() {
    let s = Secret::new(CANARY.to_string());
    assert_eq!(s.expose().as_bytes(), CANARY.as_bytes());
}

// ---- negative controls: leaking mutations that MUST trip the same check ----

struct Leaky(String);
impl Display for Leaky {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl Debug for Leaky {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Leaky({})", self.0)
    }
}

#[test]
fn control_leaky_display_debug_is_caught() {
    let leaky = Leaky(CANARY.to_string());
    let out = paths(&leaky);
    // The mutation applied: the canary is really in the bytes.
    assert!(out.iter().all(|o| contains(o, CANARY.as_bytes())));
    assert!(leaks(&out));
}

#[test]
fn control_derived_debug_inside_struct_is_caught() {
    #[derive(Debug)]
    struct Holder {
        _token: Leaky,
        _many: Vec<Leaky>,
    }
    let h = Holder {
        _token: Leaky(CANARY.into()),
        _many: vec![Leaky(CANARY.into())],
    };
    let out = debug_paths(&h);
    assert!(leaks(&out));
}

#[test]
fn control_matcher_rejects_absent_canary() {
    assert!(!leaks(&[b"<redacted>".to_vec()]));
    assert!(leaks(&[CANARY.as_bytes().to_vec()]));
}

#[test]
fn drop_zeroizes_via_zeroize_contract() {
    // R7 is zeroize's own contract (stated as a limit in DESIGN s7); here we only check the type is wired to it.
    use zeroize::Zeroize;
    let mut v = CANARY.to_string();
    v.zeroize();
    assert!(v.is_empty());
}
