// SPDX-License-Identifier: MIT OR Apache-2.0
use redactant::Redact;
#[derive(Redact)]
struct Plain { #[redact] x: u8 }
#[derive(Redact)]
struct S { #[redact(nested)] a: Plain }
fn main() {}
