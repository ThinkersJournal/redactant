// SPDX-License-Identifier: MIT OR Apache-2.0

//! Removing known secrets from text and error chains (DESIGN section 5).
//!
//! Limits, stated as part of the contract: the scrubber only finds the plain bytes of a secret it was told about. A
//! secret that was transformed first (base64, percent-encoded, truncated, split across lines) is not found.

use crate::{PLACEHOLDER, Secret};
use core::fmt;
use std::error::Error;

/// The fewest bytes a registered secret may have. Shorter ones would blank ordinary words.
pub const MIN_SECRET_LEN: usize = 4;

/// Why a secret could not be registered. Carries lengths only, never the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterError {
    /// The secret is empty; it would match everywhere.
    Empty,
    /// The secret is shorter than [`MIN_SECRET_LEN`].
    TooShort {
        /// Length of the refused secret, in bytes.
        len: usize,
    },
}

impl fmt::Display for RegisterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegisterError::Empty => f.write_str(
                "this secret is empty; the scrubber would match everywhere, so it was not registered",
            ),
            RegisterError::TooShort { len } => write!(
                f,
                "this secret is {len} bytes; the scrubber needs at least {MIN_SECRET_LEN} so it does not blank ordinary words"
            ),
        }
    }
}

impl Error for RegisterError {}

/// Removes registered secrets from strings and error chains.
#[derive(Default)]
pub struct Scrubber {
    /// Longest first, so a secret that contains another is removed whole.
    secrets: Vec<Secret<String>>,
}

impl Scrubber {
    /// An empty scrubber (it removes nothing until secrets are registered).
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a secret. Refuses an empty or too-short one with a named error; never skips it silently.
    pub fn with(mut self, secret: &Secret<String>) -> Result<Self, RegisterError> {
        let value = secret.expose();
        if value.is_empty() {
            return Err(RegisterError::Empty);
        }
        if value.len() < MIN_SECRET_LEN {
            return Err(RegisterError::TooShort { len: value.len() });
        }
        self.secrets.push(Secret::new(value.clone()));
        self.secrets
            .sort_by_key(|s| core::cmp::Reverse(s.expose().len()));
        Ok(self)
    }

    /// How many secrets are registered.
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// True when nothing is registered.
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// True when `text` contains any registered secret.
    pub fn appears_in(&self, text: &str) -> bool {
        self.secrets
            .iter()
            .any(|s| text.contains(s.expose().as_str()))
    }

    /// Replaces every occurrence of every registered secret with [`PLACEHOLDER`]. At each position the longest
    /// secret wins, and replaced text is not rescanned.
    pub fn clean(&self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut i = 0;
        while i < text.len() {
            let rest = &text[i..];
            if let Some(s) = self
                .secrets
                .iter()
                .find(|s| rest.starts_with(s.expose().as_str()))
            {
                out.push_str(PLACEHOLDER);
                i += s.expose().len();
            } else {
                let c = rest.chars().next().expect("i < len on a char boundary");
                out.push(c);
                i += c.len_utf8();
            }
        }
        out
    }

    /// ConfigurAnt's whole-message mode: if any secret appears, the entire message is dropped.
    pub fn clean_or_drop(&self, text: &str) -> String {
        if self.appears_in(text) {
            format!("{PLACEHOLDER}: the message quoted a secret value")
        } else {
            text.to_owned()
        }
    }

    /// The error's message and every `source()` below it, joined with `": "`, cleaned.
    pub fn clean_error(&self, err: &(dyn Error + 'static)) -> String {
        let mut text = err.to_string();
        let mut cur = err.source();
        while let Some(e) = cur {
            text.push_str(": ");
            text.push_str(&e.to_string());
            cur = e.source();
        }
        self.clean(&text)
    }

    /// The `Debug` rendering of any value, cleaned (for a wrapped error whose `Debug` quotes its input).
    pub fn clean_debug<T: fmt::Debug + ?Sized>(&self, value: &T) -> String {
        self.clean(&format!("{value:?}"))
    }
}

impl fmt::Debug for Scrubber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Scrubber({} secrets)", self.secrets.len())
    }
}
