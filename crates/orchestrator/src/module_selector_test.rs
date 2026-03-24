use crate::module_selector::*;

#[test]
fn parse_php_stack() {
    let techs = vec!["PHP/8.1".to_string(), "Apache".to_string()];
    let parsed = parse_tech_stack(&techs);
    assert!(parsed.contains(&TechStack::Php));
    assert!(!parsed.contains(&TechStack::Node));
}

#[test]
fn parse_node_stack() {
    let techs = vec!["Express".to_string(), "Node.js".to_string()];
    let parsed = parse_tech_stack(&techs);
    assert!(parsed.contains(&TechStack::Express));
    assert!(parsed.contains(&TechStack::Node));
}

#[test]
fn parse_empty_gives_unknown() {
    let parsed = parse_tech_stack(&[]);
    assert_eq!(parsed, vec![TechStack::Unknown]);
}

#[test]
fn universal_modules_always_selected() {
    let selection = select_modules(&[TechStack::Php]);
    let names: Vec<&str> = selection
        .selected_modules
        .iter()
        .map(|m| m.name.as_str())
        .collect();
    assert!(names.contains(&"sql_injection"));
    assert!(names.contains(&"xss"));
    assert!(names.contains(&"broken_auth"));
}

#[test]
fn php_selects_php_modules() {
    let selection = select_modules(&[TechStack::Php]);
    let names: Vec<&str> = selection
        .selected_modules
        .iter()
        .map(|m| m.name.as_str())
        .collect();
    assert!(names.contains(&"php_ssti_twig"));
    assert!(names.contains(&"php_deserialization"));
    assert!(names.contains(&"php_lfi"));
    assert!(!names.contains(&"node_prototype_pollution"));
}

#[test]
fn node_selects_node_modules() {
    let selection = select_modules(&[TechStack::Node]);
    let names: Vec<&str> = selection
        .selected_modules
        .iter()
        .map(|m| m.name.as_str())
        .collect();
    assert!(names.contains(&"node_prototype_pollution"));
    assert!(names.contains(&"node_ssti_handlebars"));
    assert!(!names.contains(&"php_ssti_twig"));
}

#[test]
fn unknown_tech_selects_all() {
    let selection = select_modules(&[TechStack::Unknown]);
    assert!(selection.skipped_modules.is_empty());
}

#[test]
fn modules_sorted_by_priority() {
    let selection = select_modules(&[TechStack::Php]);
    let priorities: Vec<ModulePriority> = selection
        .selected_modules
        .iter()
        .map(|m| m.priority)
        .collect();
    for window in priorities.windows(2) {
        assert!(window[0] <= window[1]);
    }
}

#[test]
fn auto_select_end_to_end() {
    let techs = vec!["Spring Boot".to_string(), "Java".to_string()];
    let selection = auto_select_modules(&techs);
    let names: Vec<&str> = selection
        .selected_modules
        .iter()
        .map(|m| m.name.as_str())
        .collect();
    assert!(names.contains(&"java_deserialization"));
    assert!(names.contains(&"java_xxe"));
    assert!(selection.tech_detected.contains(&TechStack::Java));
    assert!(selection.tech_detected.contains(&TechStack::Spring));
}

#[test]
fn java_not_confused_with_javascript() {
    let techs = vec!["JavaScript".to_string()];
    let parsed = parse_tech_stack(&techs);
    assert!(!parsed.contains(&TechStack::Java));
}

#[test]
fn graphql_modules_selected() {
    let selection = select_modules(&[TechStack::GraphQL]);
    let names: Vec<&str> = selection
        .selected_modules
        .iter()
        .map(|m| m.name.as_str())
        .collect();
    assert!(names.contains(&"graphql_introspection"));
    assert!(names.contains(&"graphql_injection"));
}

#[test]
fn multiple_tech_stacks_merge() {
    let selection = select_modules(&[TechStack::Node, TechStack::GraphQL]);
    let names: Vec<&str> = selection
        .selected_modules
        .iter()
        .map(|m| m.name.as_str())
        .collect();
    assert!(names.contains(&"node_prototype_pollution"));
    assert!(names.contains(&"graphql_injection"));
}
