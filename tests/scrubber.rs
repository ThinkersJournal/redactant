// SPDX-License-Identifier: MIT OR Apache-2.0
//! R4: the scrubber removes the value from a message, an error `source()` chain and a `Debug` of a wrapped error.
//! Assertions are on BYTES. Each rule has negative controls (naive scrubbers that miss) that must trip the same check.

use redactant::{RegisterError, Scrubber, Secret};
use std::error::Error;
use std::fmt;

const CANARY: &str = "CANARY-9f3a7c1e-do-not-print";

fn contains(h: &str, n: &str) -> bool {
    h.as_bytes().windows(n.len()).any(|w| w == n.as_bytes())
}

fn scrubber() -> Scrubber {
    Scrubber::new()
        .with(&Secret::new(CANARY.to_string()))
        .unwrap()
}

#[derive(Debug)]
struct Inner(String);
impl fmt::Display for Inner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bad token {}", self.0)
    }
}
impl Error for Inner {}

#[derive(Debug)]
struct Outer(Inner);
impl fmt::Display for Outer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("connect failed")
    }
}
impl Error for Outer {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

#[test]
fn message_is_cleaned_bytewise() {
    let out = scrubber().clean(&format!("connect failed for {CANARY} (twice: {CANARY})"));
    assert_eq!(
        out.as_bytes(),
        b"connect failed for <redacted> (twice: <redacted>)"
    );
}

#[test]
fn source_chain_is_cleaned() {
    let e = Outer(Inner(CANARY.into()));
    let out = scrubber().clean_error(&e);
    assert!(!contains(&out, CANARY));
    assert_eq!(out.as_bytes(), b"connect failed: bad token <redacted>");
}

#[test]
fn debug_of_wrapped_error_is_cleaned() {
    let e = Outer(Inner(CANARY.into()));
    let out = scrubber().clean_debug(&e);
    assert!(!contains(&out, CANARY));
    assert!(contains(&out, "<redacted>"));
}

#[test]
fn longest_secret_wins_when_one_contains_another() {
    let s = Scrubber::new()
        .with(&Secret::new("hunter2".to_string()))
        .unwrap()
        .with(&Secret::new("hunter2-extended".to_string()))
        .unwrap();
    assert_eq!(
        s.clean("x hunter2-extended y").as_bytes(),
        b"x <redacted> y"
    );
}

#[test]
fn multibyte_text_survives() {
    let s = scrubber();
    assert_eq!(s.clean("héllo ✓ ").as_bytes(), "héllo ✓ ".as_bytes());
}

#[test]
fn clean_or_drop_matches_configurant_bytes() {
    let s = scrubber();
    assert_eq!(
        s.clean_or_drop(&format!("x {CANARY}")).as_bytes(),
        b"<redacted>: the message quoted a secret value"
    );
    assert_eq!(s.clean_or_drop("fine").as_bytes(), b"fine");
}

#[test]
fn short_and_empty_secrets_are_refused_with_a_named_error() {
    let e = Scrubber::new()
        .with(&Secret::new("abc".to_string()))
        .unwrap_err();
    assert_eq!(e, RegisterError::TooShort { len: 3 });
    assert_eq!(
        e.to_string(),
        "this secret is 3 bytes; the scrubber needs at least 4 so it does not blank ordinary words"
    );
    assert_eq!(
        Scrubber::new()
            .with(&Secret::new(String::new()))
            .unwrap_err(),
        RegisterError::Empty
    );
    assert!(
        Scrubber::new()
            .with(&Secret::new("abcd".to_string()))
            .is_ok()
    );
}

#[test]
fn scrubber_debug_does_not_leak() {
    assert_eq!(
        format!("{:?}", scrubber()).as_bytes(),
        b"Scrubber(1 secrets)"
    );
}

// ---- negative controls ----

#[test]
fn control_ignoring_source_chain_leaks() {
    // Mutation: clean only the top-level message and ignore `source()`.
    let e = Outer(Inner(CANARY.into()));
    let naive = scrubber().clean(&e.to_string());
    // The mutation applied: it differs from the real output.
    assert_ne!(naive, scrubber().clean_error(&e));
    // The chain really holds the canary, so a scrubber that skipped it would leak.
    let full = format!("{}: {}", e, e.source().unwrap());
    assert!(contains(&full, CANARY));
    assert!(!contains(&scrubber().clean_error(&e), CANARY));
}

#[test]
fn control_shortest_first_leaks_a_tail() {
    // Mutation: replace the shorter secret first. The longer one is then split and its tail leaks.
    let text = "x hunter2-extended y";
    let mutated = text
        .replace("hunter2", "<redacted>")
        .replace("hunter2-extended", "<redacted>");
    assert!(contains(&mutated, "-extended"));
    let real = Scrubber::new()
        .with(&Secret::new("hunter2".to_string()))
        .unwrap()
        .with(&Secret::new("hunter2-extended".to_string()))
        .unwrap()
        .clean(text);
    assert!(!contains(&real, "-extended"));
}

#[test]
fn control_transformed_secret_is_not_found_and_says_so() {
    // The documented limit: a transformed secret passes through. This pins the limit so it cannot change silently.
    let encoded = CANARY.replace('-', "%2D");
    assert_eq!(scrubber().clean(&encoded), encoded);
}
