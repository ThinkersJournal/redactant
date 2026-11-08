use redactant::Secret;
fn main() {
    let s = Secret::new(String::from("x"));
    let _v = s.0;
}
