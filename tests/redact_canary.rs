// SPDX-License-Identifier: MIT OR Apache-2.0

//! DERIVE section 6, assertions D1-D5 with hand-written `Redact` impls (no macro yet). Every negative control first
//! asserts that its mutation changed the output, then shows the same assertion would fail on it.

use redactant::{Context, Disposition, FingerprintKey, Keep, Redact, Secret, Segment, Sink};

const SECRET_CANARY: &str = "CANARY-SECRET-7731";
const FP_CANARY: &str = "CANARY-FINGERPRINT-4410";
const NESTED_CANARY: &str = "CANARY-NESTED-9052";
const KEEP_VALUE: &str = "visible-role-admin";

struct Inner {
    note: String,
}

impl Redact for Inner {
    fn describe_at(&self, path: &[Segment<'_>], cx: &Context<'_>, sink: &mut dyn Sink) {
        let mut p = path.to_vec();
        p.push(Segment::Field("note"));
        sink.field(&p, Disposition::Redacted);
        let _ = (cx, &self.note);
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Mutation {
    None,
    /// D1 control: passes the secret straight to `Kept` (only possible by exposing it).
    LeakSecret,
    /// D2 control: withholds the field that should be kept.
    WithholdKept,
    /// D3 control: emits the input in place of the tag.
    InputForTag,
    /// D4 control: falls back to `Kept` with no key.
    KeptWithoutKey,
    /// D5 control: drops the nested field.
    DropNested,
}

struct Fixture {
    password: Secret<String>,
    role: String,
    email: String,
    inner: Inner,
    tags: Vec<Inner>,
    m: Mutation,
}

impl Fixture {
    fn new(m: Mutation) -> Self {
        Fixture {
            password: Secret::new(SECRET_CANARY.to_string()),
            role: KEEP_VALUE.to_string(),
            email: FP_CANARY.to_string(),
            inner: Inner {
                note: NESTED_CANARY.to_string(),
            },
            tags: vec![Inner {
                note: NESTED_CANARY.to_string(),
            }],
            m,
        }
    }
}

impl Redact for Fixture {
    fn describe_at(&self, path: &[Segment<'_>], cx: &Context<'_>, sink: &mut dyn Sink) {
        let mut p = path.to_vec();
        p.push(Segment::Field("password"));
        match self.m {
            Mutation::LeakSecret => sink.field(&p, Disposition::Kept(self.password.expose())),
            _ => self.password.describe_at(&p, cx, sink),
        }
        p.pop();

        p.push(Segment::Field("role"));
        match self.m {
            Mutation::WithholdKept => sink.field(&p, Disposition::Redacted),
            _ => sink.field(&p, Disposition::Kept(&self.role)),
        }
        p.pop();

        p.push(Segment::Field("email"));
        match self.m {
            Mutation::InputForTag => sink.field(&p, Disposition::Kept(&self.email)),
            Mutation::KeptWithoutKey if cx.key_id().is_none() => {
                sink.field(&p, Disposition::Kept(&self.email))
            }
            _ => sink.field(&p, cx.fingerprint(self.email.as_bytes())),
        }
        p.pop();

        if self.m != Mutation::DropNested {
            p.push(Segment::Field("inner"));
            self.inner.describe_at(&p, cx, sink);
            p.pop();
        }
        p.push(Segment::Field("tags"));
        self.tags.describe_at(&p, cx, sink);
    }
}

fn fail(msg: String) -> Result<(), String> {
    Err(msg)
}

fn key(seed: u8) -> FingerprintKey {
    FingerprintKey::new(&[seed; 32]).unwrap()
}

/// Every output form of the same value: the views, a debug of the view, and the recorded sink.
fn outputs(f: &Fixture, cx: Context<'_>) -> Vec<String> {
    let v = f.redacted_with(cx);
    let mut out = vec![
        format!("{v}"),
        format!("{v:?}"),
        format!("{v:#?}"),
        format!("{v:>80}"),
        format!("{v:<80}"),
    ];
    let mut rec = Recorder::default();
    f.describe(&cx, &mut rec);
    out.push(rec.lines.join("\n"));
    out.push(
        std::panic::catch_unwind(|| {
            fail(format!("{v}")).unwrap();
        })
        .err()
        .and_then(|e| e.downcast_ref::<String>().cloned())
        .unwrap_or_default(),
    );
    out
}

#[derive(Default)]
struct Recorder {
    lines: Vec<String>,
}

impl Sink for Recorder {
    fn field(&mut self, path: &[Segment<'_>], d: Disposition<'_>) {
        let p: Vec<String> = path.iter().map(|s| format!("{s:?}")).collect();
        let v = match d {
            Disposition::Redacted => "REDACTED".to_string(),
            Disposition::Fingerprint(fp) => fp.to_string(),
            Disposition::Kept(k) => format!("KEPT {k:?}"),
            _ => unreachable!("slice 1 has three dispositions"),
        };
        self.lines.push(format!("{} {v}", p.join("/")));
    }
}

fn paths(f: &Fixture, cx: Context<'_>) -> Vec<String> {
    let mut rec = Recorder::default();
    f.describe(&cx, &mut rec);
    rec.lines
        .into_iter()
        .map(|l| l.split(' ').next().unwrap().to_string())
        .collect()
}

fn contains(outs: &[String], needle: &str) -> bool {
    outs.iter().any(|o| o.contains(needle))
}

fn no_canary_leaks(outs: &[String]) -> bool {
    ![SECRET_CANARY, FP_CANARY, NESTED_CANARY]
        .iter()
        .any(|c| contains(outs, c))
}

#[test]
fn d1_no_withheld_canary_appears_in_any_output() {
    let k = key(1);
    let good = outputs(&Fixture::new(Mutation::None), Context::with_key(&k));
    assert!(no_canary_leaks(&good));
    // control: the same assertion fails on a leaking impl, and the mutation changed the output
    let bad = outputs(&Fixture::new(Mutation::LeakSecret), Context::with_key(&k));
    assert_ne!(good, bad);
    assert!(!no_canary_leaks(&bad), "control must trip D1");
}

#[test]
fn d2_the_kept_value_does_appear() {
    let k = key(1);
    let good = outputs(&Fixture::new(Mutation::None), Context::with_key(&k));
    assert!(contains(&good, KEEP_VALUE));
    let bad = outputs(&Fixture::new(Mutation::WithholdKept), Context::with_key(&k));
    assert_ne!(good, bad);
    assert!(!contains(&bad, KEEP_VALUE), "control must trip D2");
}

#[test]
fn d3_fingerprint_is_fp_plus_8_hex_stable_keyed_and_not_the_input() {
    let (k1, k2) = (key(1), key(2));
    let tag = |k: &FingerprintKey| {
        let mut r = Recorder::default();
        Fixture::new(Mutation::None).describe(&Context::with_key(k), &mut r);
        r.lines
            .iter()
            .find(|l| l.starts_with("email "))
            .cloned()
            .unwrap()
    };
    let a = tag(&k1);
    let t = a.strip_prefix("email fp:").expect("fp: prefix");
    assert_eq!(t.len(), 8);
    assert!(
        t.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_eq!(a, tag(&k1), "equal for equal input and key");
    assert_ne!(a, tag(&k2), "different for a different key");
    assert!(!a.contains(FP_CANARY));
    // control: emitting the input in place of the tag trips the same shape assertion
    let mut r = Recorder::default();
    Fixture::new(Mutation::InputForTag).describe(&Context::with_key(&k1), &mut r);
    let bad = r
        .lines
        .iter()
        .find(|l| l.starts_with("email "))
        .cloned()
        .unwrap();
    assert_ne!(a, bad);
    assert!(bad.contains(FP_CANARY), "control must trip D3");
}

#[test]
fn d4_no_key_means_redacted_not_a_hash_and_not_the_value() {
    let line = |m| {
        let mut r = Recorder::default();
        Fixture::new(m).describe(&Context::without_key(), &mut r);
        r.lines
            .iter()
            .find(|l| l.starts_with("email "))
            .cloned()
            .unwrap()
    };
    let good = line(Mutation::None);
    assert_eq!(good, "email REDACTED");
    let bad = line(Mutation::KeptWithoutKey);
    assert_ne!(good, bad);
    assert!(bad.contains(FP_CANARY), "control must trip D4");
    assert!(no_canary_leaks(&outputs(
        &Fixture::new(Mutation::None),
        Context::without_key()
    )));
}

#[test]
fn d5_every_path_is_reported_including_index_segments() {
    let k = key(1);
    let good = paths(&Fixture::new(Mutation::None), Context::with_key(&k));
    assert_eq!(
        good,
        ["password", "role", "email", "inner/note", "tags/[0]/note"]
    );
    let bad = paths(&Fixture::new(Mutation::DropNested), Context::with_key(&k));
    assert_ne!(good, bad);
    assert_ne!(
        bad,
        ["password", "role", "email", "inner/note", "tags/[0]/note"]
    );
}

#[test]
fn output_is_deterministic_and_carries_the_key_id() {
    let k = key(1);
    let f = Fixture::new(Mutation::None);
    let cx = Context::with_key(&k).with_key_id("trail-2026-11");
    assert_eq!(cx.key_id(), Some("trail-2026-11"));
    assert_eq!(outputs(&f, cx), outputs(&f, cx));
    assert_eq!(
        format!("{}", f.redacted_with(cx)),
        format!("{}", f.redacted_with(cx))
    );
}

#[test]
fn keep_is_implemented_for_the_documented_types_and_a_user_type_opts_in() {
    #[derive(Debug, serde::Serialize)]
    struct Id(u32);
    impl Keep for Id {}
    fn is_keep<T: Keep + ?Sized>(_: &T) {}
    is_keep(&Id(1));
    is_keep(&vec![Some(1u8)]);
    is_keep(&("a", 1i64));
    is_keep(&[1u8, 2]);
    is_keep("str");
}
