// SPDX-License-Identifier: MIT OR Apache-2.0
use redactant::Redact;
#[derive(Redact)]
enum E { A { #[redact] x: String } }
fn main() {}
