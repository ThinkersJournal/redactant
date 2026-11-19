// SPDX-License-Identifier: MIT OR Apache-2.0
use redactant::Redact;
#[derive(Redact)]
struct S { #[redact(skip)] a: String }
fn main() {}
