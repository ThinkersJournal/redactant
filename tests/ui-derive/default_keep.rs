// SPDX-License-Identifier: MIT OR Apache-2.0
use redactant::Redact;
#[derive(Redact)]
#[redact(default = "keep")]
struct S { a: String }
fn main() {}
