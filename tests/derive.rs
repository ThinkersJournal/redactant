// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(feature = "derive")]
//! DERIVE slice 2: the derive produces the same dispositions the hand-written slice-1 fixtures did (D1-D5 again, now
//! through the macro), plus rule behaviour, generics, defaults and the schema string.

use redactant::{Context, Disposition, FingerprintKey, Keep, Redact, Secret, Segment, Sink};

const SECRET: &str = "CANARY-SECRET-1101";
const WITHHELD: &str = "CANARY-WITHHELD-2202";
const FP: &str = "CANARY-FP-3303";
const NESTED: &str = "CANARY-NESTED-4404";
const SHOWN: &str = "shown-role";

#[derive(Redact)]
struct Session {
    #[redact]
    token_note: String,
}

#[derive(Redact)]
struct Login {
    #[redact(keep)]
    role: String,
    #[redact(fingerprint)]
    email: String,
    #[redact]
    note: String,
    password: Secret<String>,
    #[redact(nested)]
    session: Session,
    #[redact(nested)]
    history: Vec<Session>,
}

fn login() -> Login {
    Login {
        role: SHOWN.into(),
        email: FP.into(),
        note: WITHHELD.into(),
        password: Secret::new(SECRET.into()),
        session: Session {
            token_note: NESTED.into(),
        },
        history: vec![Session {
            token_note: NESTED.into(),
        }],
    }
}

#[derive(Default)]
struct Rec(Vec<String>);
impl Sink for Rec {
    fn field(&mut self, path: &[Segment<'_>], d: Disposition<'_>) {
        let p: Vec<String> = path.iter().map(|s| format!("{s:?}")).collect();
        let v = match d {
            Disposition::Redacted => "REDACTED".to_string(),
            Disposition::Fingerprint(f) => f.to_string(),
            Disposition::Kept(k) => format!("KEPT {k:?}"),
            _ => unreachable!(),
        };
        self.0.push(format!("{} {v}", p.join("/")));
    }
}

fn record(cx: &Context<'_>) -> Vec<String> {
    let mut r = Rec::default();
    login().describe(cx, &mut r);
    r.0
}

#[test]
fn d1_d2_d5_paths_and_dispositions_through_the_derive() {
    let k = FingerprintKey::new(&[7u8; 32]).unwrap();
    let rec = record(&Context::with_key(&k));
    let paths: Vec<&str> = rec.iter().map(|l| l.split(' ').next().unwrap()).collect();
    assert_eq!(
        paths,
        [
            "role",
            "email",
            "note",
            "password",
            "session/token_note",
            "history/[0]/token_note"
        ]
    );
    let all = rec.join("\n") + &format!("{}", login().redacted_with(Context::with_key(&k)));
    for c in [SECRET, WITHHELD, FP, NESTED] {
        assert!(!all.contains(c), "{c} leaked");
    }
    assert!(all.contains(SHOWN), "D2: the kept field must appear");
}

#[test]
fn d3_d4_fingerprint_with_and_without_a_key() {
    let k1 = FingerprintKey::new(&[1u8; 32]).unwrap();
    let k2 = FingerprintKey::new(&[2u8; 32]).unwrap();
    let email = |cx: &Context<'_>| {
        record(cx)
            .into_iter()
            .find(|l| l.starts_with("email "))
            .unwrap()
    };
    let a = email(&Context::with_key(&k1));
    assert!(a.strip_prefix("email fp:").is_some_and(|t| t.len() == 8));
    assert_eq!(a, email(&Context::with_key(&k1)));
    assert_ne!(a, email(&Context::with_key(&k2)));
    assert_eq!(email(&Context::without_key()), "email REDACTED");
}

#[test]
fn schema_names_every_field_and_disposition_and_changes_with_one() {
    let s = Login::schema();
    assert_eq!(
        s,
        "Login{role:keep,email:fingerprint,note:redact,password:secret,session:nested(Session{token_note:redact,}),history:nested([Session{token_note:redact,}]),}"
    );
    // control: the same type with one disposition changed has a different schema
    #[derive(Redact)]
    struct A {
        #[redact(keep)]
        x: u8,
    }
    #[derive(Redact)]
    #[allow(dead_code)]
    struct B {
        #[redact]
        x: u8,
    }
    assert_ne!(A::schema(), B::schema());
}

#[test]
fn struct_default_redact_covers_unannotated_fields_and_explicit_wins() {
    #[derive(Redact)]
    #[redact(default = "redact")]
    struct D {
        a: String,
        #[redact(keep)]
        b: u8,
    }
    let mut r = Rec::default();
    D {
        a: "CANARY-DEF".into(),
        b: 5,
    }
    .describe(&Context::without_key(), &mut r);
    assert_eq!(r.0, ["a REDACTED", "b KEPT 5"]);
}

#[test]
fn tuple_and_unit_structs_and_generics_and_user_keep() {
    #[derive(Debug, serde::Serialize)]
    struct Id(u32);
    impl Keep for Id {}

    #[derive(Redact)]
    struct T2(#[redact(keep)] Id, #[redact] String);
    #[derive(Redact)]
    struct U;
    #[derive(Redact)]
    struct W<X: Redact, Y: Keep + 'static> {
        #[redact(nested)]
        inner: X,
        #[redact(keep)]
        shown: Y,
    }
    let mut r = Rec::default();
    T2(Id(9), "s".into()).describe(&Context::without_key(), &mut r);
    U.describe(&Context::without_key(), &mut r);
    W {
        inner: Session {
            token_note: "n".into(),
        },
        shown: 3u8,
    }
    .describe(&Context::without_key(), &mut r);
    assert_eq!(
        r.0,
        [
            "0 KEPT Id(9)",
            "1 REDACTED",
            "inner/token_note REDACTED",
            "shown KEPT 3"
        ]
    );
}

#[test]
fn macro_hygiene_survives_shadowed_prelude_names() {
    #[allow(dead_code, non_snake_case, unused)]
    mod shadow {
        pub struct Option;
        pub struct Some;
        pub struct Vec;
        pub struct String;
        use redactant::Redact;
        #[derive(Redact)]
        pub struct H {
            #[redact]
            pub x: u8,
        }
    }
    let mut r = Rec::default();
    shadow::H { x: 1 }.describe(&Context::without_key(), &mut r);
    assert_eq!(r.0, ["x REDACTED"]);
}
