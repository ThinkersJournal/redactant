// SPDX-License-Identifier: MIT OR Apache-2.0
use redactant::Redact;
use std::collections::BTreeMap;
#[derive(Redact)]
struct V { #[redact] x: u8 }
#[derive(Redact)]
struct S { #[redact(nested)] m: BTreeMap<String, V> }
fn main() {}
