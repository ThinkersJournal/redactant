// SPDX-License-Identifier: MIT OR Apache-2.0
use redactant::Redact;
struct Plain;
#[derive(Redact)]
struct S { #[redact(nested)] a: Plain }
fn main() {}
