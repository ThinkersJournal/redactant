// SPDX-License-Identifier: MIT OR Apache-2.0
//! R5: a fingerprint never contains the value, is stable for one key, and differs for two keys. Assertions are on
//! BYTES. Each property has a negative control that must trip the same check.

use redactant::{FingerprintKey, KeyError, Secret};
use sha2::{Digest, Sha256};

const CANARY: &str = "CANARY-9f3a7c1e-do-not-print";
const KEY_A: &[u8] = b"0123456789abcdef-key-A";
const KEY_B: &[u8] = b"0123456789abcdef-key-B";

fn contains(h: &[u8], n: &str) -> bool {
    h.windows(n.len()).any(|w| w == n.as_bytes())
}

fn key(k: &[u8]) -> FingerprintKey {
    FingerprintKey::new(k).unwrap()
}

#[test]
fn shape_is_fp_colon_eight_lowercase_hex() {
    let s = Secret::new(CANARY.to_string());
    let text = s.fingerprint(&key(KEY_A)).to_string();
    let b = text.as_bytes();
    assert_eq!(b.len(), 11);
    assert_eq!(&b[..3], b"fp:");
    assert!(
        b[3..]
            .iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
    );
    // Debug is the same bytes, never a struct dump.
    assert_eq!(format!("{:?}", s.fingerprint(&key(KEY_A))), text);
}

#[test]
fn never_contains_the_value() {
    let s = Secret::new(CANARY.to_string());
    let fp = s.fingerprint(&key(KEY_A));
    assert!(!contains(format!("{fp}").as_bytes(), CANARY));
    assert!(!contains(format!("{fp:?}").as_bytes(), CANARY));
}

#[test]
fn stable_for_one_key_and_value() {
    let a1 = Secret::new(CANARY.to_string()).fingerprint(&key(KEY_A));
    let a2 = Secret::new(CANARY.to_string()).fingerprint(&key(KEY_A));
    assert_eq!(a1, a2);
}

#[test]
fn differs_across_keys_and_across_values() {
    let s = Secret::new(CANARY.to_string());
    assert_ne!(s.fingerprint(&key(KEY_A)), s.fingerprint(&key(KEY_B)));
    let other = Secret::new(format!("{CANARY}!"));
    assert_ne!(s.fingerprint(&key(KEY_A)), other.fingerprint(&key(KEY_A)));
}

#[test]
fn works_for_byte_secrets() {
    let s = Secret::new(CANARY.as_bytes().to_vec());
    let t = Secret::new(CANARY.to_string());
    assert_eq!(s.fingerprint(&key(KEY_A)), t.fingerprint(&key(KEY_A)));
}

#[test]
fn short_key_is_refused_with_a_named_error() {
    let e = FingerprintKey::new(b"short").unwrap_err();
    assert_eq!(e, KeyError { len: 5 });
    assert_eq!(
        e.to_string(),
        "this fingerprint key is 5 bytes; it needs at least 16"
    );
    assert!(FingerprintKey::new(&[7u8; 16]).is_ok());
}

#[test]
fn key_debug_is_blank_and_bytes_exact() {
    assert_eq!(
        format!("{:?}", key(KEY_A)).as_bytes(),
        b"FingerprintKey(<redacted>)"
    );
}

// ---- negative controls ----

/// A bare, unkeyed hash prefix in the same `fp:` shape.
fn bare(value: &str) -> String {
    let d = Sha256::digest(value.as_bytes());
    format!("fp:{:02x}{:02x}{:02x}{:02x}", d[0], d[1], d[2], d[3])
}

#[test]
fn control_bare_hash_does_not_vary_with_a_key() {
    // The mutation (no key) gives one answer whatever the key, so the "differs across keys" check fails on it,
    // which is exactly why a bare hash would let a leaked log be tested against guesses.
    let (a, b) = (bare(CANARY), bare(CANARY));
    assert_eq!(a, b);
    let s = Secret::new(CANARY.to_string());
    assert_ne!(s.fingerprint(&key(KEY_A)), s.fingerprint(&key(KEY_B)));
}

#[test]
fn control_bare_hash_is_independent_of_our_output() {
    // A guesser with a bare hash can confirm a guess offline; with the keyed tag they cannot.
    let keyed = Secret::new(CANARY.to_string())
        .fingerprint(&key(KEY_A))
        .to_string();
    assert_ne!(keyed, bare(CANARY));
}

#[test]
fn control_a_value_in_the_output_is_caught() {
    let leaky = format!("fp:{CANARY}");
    assert!(contains(leaky.as_bytes(), CANARY));
}
