// SPDX-License-Identifier: MIT OR Apache-2.0

//! Keyed fingerprints (DESIGN section 6): two logs can say "same secret" without revealing it.
//!
//! A fingerprint is the first 4 bytes (8 hex characters) of HMAC-SHA-256 under a caller-supplied key. It is keyed, so a
//! leaked log does not let anyone test guesses without the key; it is short on purpose, so it identifies within a
//! handful of secrets and is useless for confirming a guess. It is **not** a security boundary. RedactAnt never stores
//! keys: the caller holds the [`FingerprintKey`].

use crate::secret::Secret;
use core::fmt;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::error::Error;
use zeroize::Zeroize;

/// The fewest bytes a [`FingerprintKey`] may have.
pub const MIN_KEY_LEN: usize = 16;

/// How many bytes of the MAC a fingerprint keeps (4 bytes, 8 hex characters).
const TAG_LEN: usize = 4;

/// Why a key was refused. Carries a length only, never the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyError {
    /// Length of the refused key, in bytes.
    pub len: usize,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "this fingerprint key is {} bytes; it needs at least {MIN_KEY_LEN}",
            self.len
        )
    }
}

impl Error for KeyError {}

/// The key a fingerprint is computed under. Blank `Debug`, zeroized on drop, no `Clone`.
pub struct FingerprintKey(Secret<Vec<u8>>);

impl FingerprintKey {
    /// Wraps key bytes, refusing one shorter than [`MIN_KEY_LEN`] with a named error.
    pub fn new(key: &[u8]) -> Result<Self, KeyError> {
        if key.len() < MIN_KEY_LEN {
            return Err(KeyError { len: key.len() });
        }
        Ok(FingerprintKey(Secret::new(key.to_vec())))
    }
}

impl fmt::Debug for FingerprintKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FingerprintKey(")?;
        f.write_str(crate::secret::PLACEHOLDER)?;
        f.write_str(")")
    }
}

/// A short keyed tag of a secret, printed as `fp:` plus 8 lowercase hex characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; TAG_LEN]);

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("fp:")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

fn tag(key: &[u8], data: &[u8]) -> Fingerprint {
    // HMAC accepts a key of any length, so this cannot fail.
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(data);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(&full[..TAG_LEN]);
    Fingerprint(out)
}

impl<T: Zeroize + AsRef<[u8]>> Secret<T> {
    /// The keyed fingerprint of this secret under `key`.
    pub fn fingerprint(&self, key: &FingerprintKey) -> Fingerprint {
        tag(key.0.expose().as_slice(), self.expose().as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 test case 2 pins the primitive: HMAC-SHA-256, key "Jefe", data "what do ya want for nothing?" is
    /// 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843; we keep the first 4 bytes.
    #[test]
    fn matches_rfc_4231_case_2() {
        let t = tag(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(t.to_string().as_bytes(), b"fp:5bdcc146");
    }
}
