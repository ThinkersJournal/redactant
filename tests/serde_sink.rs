// SPDX-License-Identifier: MIT OR Apache-2.0
//! DERIVE slice 4: the serde sink adapter writes dispositions, never withheld values. Assertions are on BYTES, with a
//! negative control (a hand-written sink that DOES leak must trip the same check).
#![cfg(all(feature = "serde", feature = "derive"))]

use redactant::{Context, FingerprintKey, Keep, Redact, Secret};

const SECRET: &str = "CANARY-SINK-SECRET-5501";
const WITHHELD: &str = "CANARY-SINK-WITHHELD-6602";
const EMAIL: &str = "CANARY-SINK-EMAIL-7703";

#[derive(serde::Serialize)]
struct Role(&'static str);
impl Keep for Role {}
impl std::fmt::Debug for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

#[derive(Redact)]
struct Login {
    #[redact(keep)]
    role: Role,
    #[redact(fingerprint)]
    email: String,
    #[redact]
    note: String,
    password: Secret<String>,
}

fn login() -> Login {
    Login {
        role: Role("admin"),
        email: EMAIL.into(),
        note: WITHHELD.into(),
        password: Secret::new(SECRET.into()),
    }
}

fn contains(h: &[u8], n: &str) -> bool {
    h.windows(n.len()).any(|w| w == n.as_bytes())
}

#[test]
fn keyed_view_writes_dispositions_only() {
    let key = FingerprintKey::new(&[7u8; 32]).unwrap();
    let cx = Context::with_key(&key);
    let bytes = serde_json::to_vec(&login().serde_view(cx)).unwrap();
    for c in [SECRET, WITHHELD, EMAIL] {
        assert!(!contains(&bytes, c), "leaked {c}");
    }
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["role"], "admin");
    assert_eq!(v["note"], "<redacted>");
    assert_eq!(v["password"], "<redacted>");
    assert!(v["email"].as_str().unwrap().starts_with("fp:"), "{v}");
}

#[test]
fn keyless_view_fails_closed() {
    let bytes = serde_json::to_vec(&login().serde_view(Context::without_key())).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["email"], "<redacted>");
    assert!(!contains(&bytes, EMAIL));
}

#[test]
fn negative_control_the_check_trips_on_a_leak() {
    let leaky = serde_json::to_vec(&serde_json::json!({ "note": WITHHELD })).unwrap();
    assert!(contains(&leaky, WITHHELD));
}
