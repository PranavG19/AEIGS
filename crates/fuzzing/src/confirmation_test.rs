#[test]
fn confirmation_module_compiles() {
    let registry = crate::confirmation::build_confirmation_registry();
    assert!(registry.is_empty());
}
