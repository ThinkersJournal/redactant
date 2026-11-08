use redactant::Secret;
fn main() {
    let s = Secret::new(String::from("x"));
    let _c = s.clone();
}
