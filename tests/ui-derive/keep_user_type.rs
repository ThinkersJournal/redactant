// SPDX-License-Identifier: MIT OR Apache-2.0
use redactant::Redact;
struct Id(u32);
#[derive(Redact)]
struct S { #[redact(keep)] a: Id }
fn main() {}
