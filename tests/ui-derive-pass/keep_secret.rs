// SPDX-License-Identifier: MIT OR Apache-2.0
use redactant::{Redact, Secret};
#[derive(Redact)]
struct S { a: Secret<String> }
fn main() {}
