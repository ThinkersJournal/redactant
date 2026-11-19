// SPDX-License-Identifier: MIT OR Apache-2.0

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod fingerprint;
mod redact;
mod scrubber;
mod secret;

pub use fingerprint::{Fingerprint, FingerprintKey, KeyError, MIN_KEY_LEN};
pub use redact::{Context, Disposition, Keep, Redact, RedactedView, Segment, Sink};
pub use scrubber::{MIN_SECRET_LEN, RegisterError, Scrubber};
pub use secret::{PLACEHOLDER, Secret};
