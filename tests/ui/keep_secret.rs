// SPDX-License-Identifier: MIT OR Apache-2.0
// A Secret is not `Keep`, so it cannot be handed to a sink as a kept value.
use redactant::{Disposition, Secret};
fn main() {
    let s = Secret::new(String::from("x"));
    let _d = Disposition::Kept(&s);
}
