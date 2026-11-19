// SPDX-License-Identifier: MIT OR Apache-2.0
use redactant::{Keep, Redact};
#[derive(Debug, serde::Serialize)]
struct Id(u32);
impl Keep for Id {}
#[derive(Redact)]
struct S { #[redact(keep)] a: Id }
fn main() {}
