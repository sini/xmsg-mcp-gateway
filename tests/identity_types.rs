#[test]
fn verified_token_path_compiles() {
    trybuild::TestCases::new().pass("tests/ui/verified_token.rs");
}
#[test]
fn identity_cannot_be_deserialized() {
    trybuild::TestCases::new().compile_fail("tests/ui/deserialize.rs");
}
#[test]
fn identity_cannot_be_converted_from_binding() {
    trybuild::TestCases::new().compile_fail("tests/ui/from_binding.rs");
}
#[test]
fn identity_has_no_default() {
    trybuild::TestCases::new().compile_fail("tests/ui/default.rs");
}
#[test]
fn identity_fields_are_private() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/struct_literal.rs");
    cases.compile_fail("tests/ui/handler_mint.rs");
}
#[test]
fn enrollment_binding_cannot_authorize() {
    trybuild::TestCases::new().compile_fail("tests/ui/authorize_binding.rs");
}
