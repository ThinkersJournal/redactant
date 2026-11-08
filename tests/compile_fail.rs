// SPDX-License-Identifier: MIT OR Apache-2.0
//! R6: no safe way to the value without `expose()`. Each case in tests/ui must fail to compile, and the control
//! (tests/ui-pass) must compile, so a broken harness cannot pass vacuously.

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui-pass/*.rs");
    t.compile_fail("tests/ui/*.rs");
}
