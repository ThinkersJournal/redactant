// SPDX-License-Identifier: MIT OR Apache-2.0

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod scrubber;

pub use scrubber::{MIN_SECRET_LEN, RegisterError, Scrubber};

use core::fmt;
use zeroize::Zeroize;

/// The one placeholder every redacted value prints as. Fixed on purpose: one string everywhere
/// (ConfigurAnt already emits exactly this text).
pub const PLACEHOLDER: &str = "<redacted>";

/// A value that must not reach logs, errors or output.
///
/// Formatting is blank (`Display` is [`PLACEHOLDER`], `Debug` is `Secret(<redacted>)`). The only way to the
/// value is [`Secret::expose`], which a reviewer can grep for. There is deliberately no `Clone`, `Deref`,
/// `AsRef` or `Into<T>`: each would let the value out without the word `expose` appearing.
/// The value is zeroized when the `Secret` is dropped.
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    /// Wraps a value.
    pub fn new(value: T) -> Self {
        Secret(value)
    }

    /// The audit point: the only way to read the value.
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(PLACEHOLDER)
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(")?;
        f.write_str(PLACEHOLDER)?;
        f.write_str(")")
    }
}

#[cfg(feature = "serde")]
impl<T: Zeroize> serde::Serialize for Secret<T> {
    /// Writes [`PLACEHOLDER`], never the value. A caller who truly needs the value serialized calls `expose()`.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(PLACEHOLDER)
    }
}

#[cfg(feature = "serde")]
impl<'de, T: Zeroize + AsRef<[u8]> + serde::Deserialize<'de>> serde::Deserialize<'de>
    for Secret<T>
{
    /// Reads a value straight into a `Secret`, so a config struct holds it blank from the start.
    ///
    /// Refuses the exact text [`PLACEHOLDER`] with an error: that is what `Serialize` writes, so seeing it means a
    /// serialize-then-deserialize round trip already destroyed the real secret, and accepting it would silently turn
    /// the secret into the literal string `<redacted>`. (This is why `T` must expose bytes: only byte-like values can
    /// be mistaken for the placeholder.)
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = T::deserialize(deserializer)?;
        if value.as_ref() == PLACEHOLDER.as_bytes() {
            return Err(serde::de::Error::custom(
                "the value is the redaction placeholder `<redacted>`, which is what a serialized Secret writes; \
                 the real secret was lost in an earlier serialize step. Supply the real value",
            ));
        }
        Ok(Secret::new(value))
    }
}
