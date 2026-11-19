// SPDX-License-Identifier: MIT OR Apache-2.0
use redactant::Redact;
#[derive(Redact)]
struct S { #[redact] a: String }
fn main() {}
