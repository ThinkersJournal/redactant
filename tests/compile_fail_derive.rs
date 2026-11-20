// SPDX-License-Identifier: MIT OR Apache-2.0
//! DERIVE section 6 compile-fail cases for the derive: each tests/ui-derive case must fail, and each has a twin in
//! tests/ui-derive-pass that differs only by the fix, so the harness cannot fail for an unrelated reason.

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui-derive-pass/*.rs");
    t.compile_fail("tests/ui-derive/*.rs");
}
