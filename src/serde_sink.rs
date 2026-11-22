// SPDX-License-Identifier: MIT OR Apache-2.0

//! DERIVE slice 4: a [`Sink`] that writes each reported field straight into a caller's `serde::Serializer`, as one flat
//! map from the field's path to what its disposition allows (`"login.email": "fp:3f9a1c7e"`).
//!
//! It is an output of [`Redact::describe`], never a transform of an already-serialized tree: no document is parsed, no
//! path rules are applied, no value is inspected. A `Redacted` field is written as [`PLACEHOLDER`], a `Fingerprint` as
//! its `Display` text, and only a `Kept` field is serialized as itself.

use crate::redact::{Context, Disposition, Redact, Segment, Sink};
use crate::secret::PLACEHOLDER;
use serde::ser::{Error as _, Serialize, SerializeMap, Serializer};
use std::fmt::Write as _;

/// Serializes `value`'s field dispositions into `serializer` as a flat map keyed by path.
///
/// Paths read `field.sub[0]["key"]`; an enum variant adds its name as a segment. Fields arrive in `describe` order.
pub fn serialize<T, S>(value: &T, cx: &Context<'_>, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Redact + ?Sized,
    S: Serializer,
{
    let map = serializer.serialize_map(None)?;
    let mut sink = MapSink {
        map: Some(map),
        err: None,
    };
    value.describe(cx, &mut sink);
    let map = sink.map.take().expect("map present until end");
    match sink.err {
        Some(e) => Err(e),
        None => map.end(),
    }
}

/// A `Serialize` view of a record's dispositions, see [`serialize`]. Made by [`Redact::serde_view`].
pub struct SerdeView<'v, 'k, T: Redact + ?Sized> {
    pub(crate) value: &'v T,
    pub(crate) cx: Context<'k>,
}

impl<T: Redact + ?Sized> Serialize for SerdeView<'_, '_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize(self.value, &self.cx, serializer)
    }
}

struct MapSink<M: SerializeMap> {
    map: Option<M>,
    err: Option<M::Error>,
}

fn path_text(path: &[Segment<'_>]) -> String {
    let mut out = String::new();
    for seg in path {
        match seg {
            Segment::Field(n) | Segment::Variant(n) => {
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(n);
            }
            Segment::Index(i) => {
                let _ = write!(out, "[{i}]");
            }
            Segment::Key(k) => {
                let _ = write!(out, "[{k:?}]");
            }
        }
    }
    out
}

impl<M: SerializeMap> Sink for MapSink<M> {
    fn field(&mut self, path: &[Segment<'_>], d: Disposition<'_>) {
        if self.err.is_some() {
            return;
        }
        let Some(map) = self.map.as_mut() else { return };
        let key = path_text(path);
        let res = match d {
            Disposition::Fingerprint(fp) => map.serialize_entry(&key, &fp.to_string()),
            Disposition::Kept(v) => {
                let v: &dyn erased_serde::Serialize = v;
                map.serialize_entry(&key, v)
            }
            // Redacted, and any disposition a later version adds: withheld (fails closed).
            _ => map.serialize_entry(&key, PLACEHOLDER),
        };
        if let Err(e) = res {
            self.err = Some(M::Error::custom(e));
        }
    }
}
