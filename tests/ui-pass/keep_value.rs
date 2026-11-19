// SPDX-License-Identifier: MIT OR Apache-2.0
// Control for tests/ui/keep_secret.rs: a plain `String` is `Keep`, so the same call compiles.
use redactant::Disposition;
fn main() {
    let s = String::from("x");
    let _d = Disposition::Kept(&s);
}
