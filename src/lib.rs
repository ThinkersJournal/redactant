// SPDX-License-Identifier: MIT OR Apache-2.0

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod fingerprint;
mod scrubber;

pub use fingerprint::{Fingerprint, FingerprintKey, KeyError, MIN_KEY_LEN};
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
