// SPDX-License-Identifier: MIT OR Apache-2.0
use redactant::Secret;
fn main() {
    let s = Secret::new(String::from("x"));
    let _v: &String = s.as_ref();
}
