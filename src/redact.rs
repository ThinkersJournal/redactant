// SPDX-License-Identifier: MIT OR Apache-2.0

//! Structured redaction (DERIVE section 2, slice 1): describe a record field by field to a [`Sink`], each field with
//! a stated [`Disposition`]. No macro yet: a type implements [`Redact`] by hand.
//!
//! The sink never receives a raw value except through [`Disposition::Kept`], and `Kept` only takes a value whose type
//! implements the marker trait [`Keep`], which `Secret<T>` does not. A field is therefore withheld, fingerprinted
//! under the caller's key, or shown because its type said it is safe.

use crate::fingerprint::{Fingerprint, FingerprintKey};
use crate::secret::{PLACEHOLDER, Secret};
use core::fmt;
use zeroize::Zeroize;

/// Marker: a value of this type is safe to show and may be handed to a sink as [`Disposition::Kept`].
///
/// RedactAnt implements it for primitives, `str`, `String`, `Option`/`Vec`/arrays/tuples of `Keep`, and references to
/// `Keep`; **never** for `Secret<T>`. A type of yours opts in with `impl Keep for Id {}`: a visible, greppable act, like
/// `expose()`. Under feature `serde` a `Keep` type must also be `serde::Serialize`, so a sink can keep the value's type.
#[cfg(not(feature = "serde"))]
pub trait Keep: fmt::Debug {}

/// Marker: a value of this type is safe to show and may be handed to a sink as [`Disposition::Kept`].
///
/// RedactAnt implements it for primitives, `str`, `String`, `Option`/`Vec`/arrays/tuples of `Keep`, and references to
/// `Keep`; **never** for `Secret<T>`. A type of yours opts in with `impl Keep for Id {}`: a visible, greppable act, like
/// `expose()`. Under feature `serde` a `Keep` type must also be `serde::Serialize`, so a sink can keep the value's type.
#[cfg(feature = "serde")]
pub trait Keep: fmt::Debug + erased_serde::Serialize {}

macro_rules! keep_impls {
    ($($t:ty),* $(,)?) => { $(impl Keep for $t {})* };
}
keep_impls!(
    bool,
    char,
    str,
    String,
    u8,
    u16,
    u32,
    u64,
    u128,
    usize,
    i8,
    i16,
    i32,
    i64,
    i128,
    isize,
    f32,
    f64,
    ()
);

/// Implementation detail of the blanket [`Keep`] impls: under feature `serde` it says "is `serde::Serialize`", and
/// without it says nothing. Not part of the API.
#[doc(hidden)]
#[cfg(feature = "serde")]
pub trait KeepBound: serde::Serialize {}
#[doc(hidden)]
#[cfg(feature = "serde")]
impl<T: serde::Serialize + ?Sized> KeepBound for T {}
#[doc(hidden)]
#[cfg(not(feature = "serde"))]
pub trait KeepBound {}
#[doc(hidden)]
#[cfg(not(feature = "serde"))]
impl<T: ?Sized> KeepBound for T {}

impl<T: Keep + KeepBound + ?Sized> Keep for &T {}
impl<T: Keep + KeepBound> Keep for Option<T> {}
impl<T: Keep + KeepBound> Keep for Vec<T> {}
impl<T: Keep + KeepBound, const N: usize> Keep for [T; N] where [T; N]: KeepBound {}
impl<A: Keep + KeepBound> Keep for (A,) {}
impl<A: Keep + KeepBound, B: Keep + KeepBound> Keep for (A, B) {}
impl<A: Keep + KeepBound, B: Keep + KeepBound, C: Keep + KeepBound> Keep for (A, B, C) {}
impl<A: Keep + KeepBound, B: Keep + KeepBound, C: Keep + KeepBound, D: Keep + KeepBound> Keep
    for (A, B, C, D)
{
}

/// One step of the path from a record's root to a field.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum Segment<'a> {
    /// A struct or variant field name.
    Field(&'a str),
    /// An enum variant name (a code identifier, always kept).
    Variant(&'a str),
    /// A position in a sequence or tuple.
    Index(usize),
    /// A map key, shown through `Debug`.
    Key(&'a dyn fmt::Debug),
}

impl fmt::Debug for Segment<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Segment::Field(n) | Segment::Variant(n) => f.write_str(n),
            Segment::Index(i) => write!(f, "[{i}]"),
            Segment::Key(k) => write!(f, "[{k:?}]"),
        }
    }
}

/// What a field is allowed to reveal.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum Disposition<'a> {
    /// The value is withheld; it prints as [`PLACEHOLDER`].
    Redacted,
    /// A keyed tag of the value ("same value" without the value).
    Fingerprint(Fingerprint),
    /// The value, explicitly declared safe by its type.
    Kept(&'a dyn Keep),
}

/// Receives a record's fields one at a time. The consumer decides the output format.
pub trait Sink {
    /// One field, at `path` from the root, with its disposition.
    fn field(&mut self, path: &[Segment<'_>], d: Disposition<'_>);
}

/// What a record needs from its caller while being described: the fingerprint key (RedactAnt stores none) and an
/// optional key id a sink can record next to a fingerprint (DERIVE 9b answer 3).
#[derive(Clone, Copy, Default)]
pub struct Context<'k> {
    key: Option<&'k FingerprintKey>,
    key_id: Option<&'k str>,
}

impl<'k> Context<'k> {
    /// No key: a field that asks for a fingerprint is [`Disposition::Redacted`] instead (fails closed).
    pub fn without_key() -> Self {
        Context::default()
    }

    /// Fingerprints are computed under `key`.
    pub fn with_key(key: &'k FingerprintKey) -> Self {
        Context {
            key: Some(key),
            key_id: None,
        }
    }

    /// Names the key, for a sink that records it. RedactAnt does not interpret it.
    pub fn with_key_id(mut self, key_id: &'k str) -> Self {
        self.key_id = Some(key_id);
        self
    }

    /// The key id the caller supplied, if any.
    pub fn key_id(&self) -> Option<&'k str> {
        self.key_id
    }

    /// The disposition for a field whose author chose "fingerprint": the keyed tag of `data`, or
    /// [`Disposition::Redacted`] when there is no key. Never a bare hash and never the value.
    pub fn fingerprint(&self, data: &[u8]) -> Disposition<'static> {
        match self.key {
            Some(k) => Disposition::Fingerprint(k.tag(data)),
            None => Disposition::Redacted,
        }
    }
}

/// A type that can describe itself, field by field, to a [`Sink`].
pub trait Redact {
    /// Describes `self` at `path` (the path of this value from the root; empty at the root).
    fn describe_at(&self, path: &[Segment<'_>], cx: &Context<'_>, sink: &mut dyn Sink);

    /// Describes `self` as a root value.
    fn describe(&self, cx: &Context<'_>, sink: &mut dyn Sink) {
        self.describe_at(&[], cx, sink);
    }

    /// A canonical description of this type's field dispositions (`Name{field:keep,other:nested(..),}`), for a
    /// consumer that hashes it to notice a changed disposition (DERIVE 9b answer 6). `#[derive(Redact)]` writes it; a
    /// hand-written impl may leave the default, the empty string, meaning "no schema stated".
    fn schema() -> String
    where
        Self: Sized,
    {
        String::new()
    }

    /// A view whose `Display` and `Debug` print each field with its disposition applied, no key.
    fn redacted(&self) -> RedactedView<'_, 'static, Self>
    where
        Self: Sized,
    {
        RedactedView {
            value: self,
            cx: Context::without_key(),
        }
    }

    /// Like [`Redact::redacted`], under `cx`.
    fn redacted_with<'k>(&self, cx: Context<'k>) -> RedactedView<'_, 'k, Self>
    where
        Self: Sized,
    {
        RedactedView { value: self, cx }
    }
}

impl<T: Zeroize> Redact for Secret<T> {
    fn describe_at(&self, path: &[Segment<'_>], _cx: &Context<'_>, sink: &mut dyn Sink) {
        sink.field(path, Disposition::Redacted);
    }
}

impl Redact for Fingerprint {
    fn describe_at(&self, path: &[Segment<'_>], _cx: &Context<'_>, sink: &mut dyn Sink) {
        sink.field(path, Disposition::Fingerprint(*self));
    }
}

impl<T: Redact + ?Sized> Redact for &T {
    fn describe_at(&self, path: &[Segment<'_>], cx: &Context<'_>, sink: &mut dyn Sink) {
        (**self).describe_at(path, cx, sink);
    }
}

impl<T: Redact + ?Sized> Redact for Box<T> {
    fn describe_at(&self, path: &[Segment<'_>], cx: &Context<'_>, sink: &mut dyn Sink) {
        (**self).describe_at(path, cx, sink);
    }
}

/// `None` reports nothing: there is no value whose disposition could be stated.
impl<T: Redact> Redact for Option<T> {
    fn schema() -> String {
        format!("?{}", T::schema())
    }

    fn describe_at(&self, path: &[Segment<'_>], cx: &Context<'_>, sink: &mut dyn Sink) {
        if let Some(v) = self {
            v.describe_at(path, cx, sink);
        }
    }
}

fn describe_seq<'a, T: Redact + 'a>(
    items: impl Iterator<Item = &'a T>,
    path: &[Segment<'_>],
    cx: &Context<'_>,
    sink: &mut dyn Sink,
) {
    let mut p: Vec<Segment<'_>> = path.to_vec();
    p.push(Segment::Index(0));
    let last = p.len() - 1;
    for (i, item) in items.enumerate() {
        p[last] = Segment::Index(i);
        item.describe_at(&p, cx, sink);
    }
}

impl<T: Redact> Redact for [T] {
    fn describe_at(&self, path: &[Segment<'_>], cx: &Context<'_>, sink: &mut dyn Sink) {
        describe_seq(self.iter(), path, cx, sink);
    }
}

impl<T: Redact> Redact for Vec<T> {
    fn schema() -> String {
        format!("[{}]", T::schema())
    }

    fn describe_at(&self, path: &[Segment<'_>], cx: &Context<'_>, sink: &mut dyn Sink) {
        describe_seq(self.iter(), path, cx, sink);
    }
}

impl<T: Redact, const N: usize> Redact for [T; N] {
    fn schema() -> String {
        format!("[{}]", T::schema())
    }

    fn describe_at(&self, path: &[Segment<'_>], cx: &Context<'_>, sink: &mut dyn Sink) {
        describe_seq(self.iter(), path, cx, sink);
    }
}

/// The view returned by [`Redact::redacted`]. Output is deterministic: the same value and context print the same
/// bytes. `{}` and `{:?}` print `path=value` pairs on one line; `{:#?}` prints one pair per line. Width and padding
/// flags are ignored.
pub struct RedactedView<'v, 'k, T: Redact> {
    value: &'v T,
    cx: Context<'k>,
}

struct Printer<'f, 'g> {
    f: &'f mut fmt::Formatter<'g>,
    pretty: bool,
    first: bool,
    result: fmt::Result,
}

impl Sink for Printer<'_, '_> {
    fn field(&mut self, path: &[Segment<'_>], d: Disposition<'_>) {
        if self.result.is_err() {
            return;
        }
        let sep = if self.first {
            ""
        } else if self.pretty {
            "\n"
        } else {
            ", "
        };
        self.first = false;
        let f = &mut *self.f;
        let mut r = f.write_str(sep);
        for (i, s) in path.iter().enumerate() {
            if r.is_err() {
                break;
            }
            if i > 0 && !matches!(s, Segment::Index(_) | Segment::Key(_)) {
                r = f.write_str(".");
            }
            r = r.and_then(|()| write!(f, "{s:?}"));
        }
        self.result = r.and_then(|()| match d {
            Disposition::Redacted => write!(f, "={PLACEHOLDER}"),
            Disposition::Fingerprint(fp) => write!(f, "={fp}"),
            Disposition::Kept(v) => write!(f, "={v:?}"),
        });
    }
}

impl<T: Redact> fmt::Display for RedactedView<'_, '_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut p = Printer {
            pretty: f.alternate(),
            f,
            first: true,
            result: Ok(()),
        };
        self.value.describe(&self.cx, &mut p);
        p.result
    }
}

impl<T: Redact> fmt::Debug for RedactedView<'_, '_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
