use crate::mass_assign_audit::*;

#[test]
fn admin_field_reflected() {
    let body = r#"{"id":1,"name":"user","is_admin":true}"#;
    let issues = analyze_mass_assignment("/api/users/1", &["is_admin"], body);
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::ReflectedAdminField { field, .. } if field == "is_admin")
    ));
}

#[test]
fn role_field_reflected() {
    let body = r#"{"id":1,"role":"admin"}"#;
    let issues = analyze_mass_assignment("/api/users/1", &["role"], body);
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::ReflectedRoleField { field, .. } if field == "role")
    ));
}

#[test]
fn unknown_fields_accepted() {
    let body = r#"{"id":1,"__test_field_aegis":"injected"}"#;
    let issues = analyze_mass_assignment("/api/users/1", &["__test_field_aegis"], body);
    assert!(
        issues.iter().any(
            |i| matches!(i, MassAssignIssue::AcceptsUnknownFields { count, .. } if *count == 1)
        )
    );
}

#[test]
fn no_reflection_clean() {
    let body = r#"{"id":1,"name":"user"}"#;
    let issues = analyze_mass_assignment("/api/users/1", &["is_admin", "role"], body);
    assert!(issues.is_empty());
}

#[test]
fn multiple_admin_fields() {
    let body = r#"{"admin":true,"superuser":false}"#;
    let issues = analyze_mass_assignment("/api/users/1", &["admin", "superuser"], body);
    let admin_count = issues
        .iter()
        .filter(|i| matches!(i, MassAssignIssue::ReflectedAdminField { .. }))
        .count();
    assert_eq!(admin_count, 2);
}

#[test]
fn case_insensitive_matching() {
    let body = r#"{"ID":1,"ISADMIN":true}"#;
    let issues = analyze_mass_assignment("/api/users/1", &["isAdmin"], body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MassAssignIssue::ReflectedAdminField { .. }))
    );
}

#[test]
fn permission_field_is_role_category() {
    let body = r#"{"permission":"write"}"#;
    let issues = analyze_mass_assignment("/api/users/1", &["permission"], body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MassAssignIssue::ReflectedRoleField { .. }))
    );
}

#[test]
fn empty_response_clean() {
    let issues = analyze_mass_assignment("/api/users/1", &["is_admin", "role"], "");
    assert!(issues.is_empty());
}

#[test]
fn empty_fields_clean() {
    let body = r#"{"id":1,"is_admin":true}"#;
    let issues = analyze_mass_assignment("/api/users/1", &[], body);
    assert!(issues.is_empty());
}

#[test]
fn severity_ordering() {
    assert!(
        mass_assign_severity(&MassAssignIssue::ReflectedAdminField {
            field: "x".to_string(),
            endpoint: "y".to_string()
        }) > mass_assign_severity(&MassAssignIssue::ReflectedRoleField {
            field: "x".to_string(),
            endpoint: "y".to_string()
        })
    );
    assert!(
        mass_assign_severity(&MassAssignIssue::ReflectedRoleField {
            field: "x".to_string(),
            endpoint: "y".to_string()
        }) > mass_assign_severity(&MassAssignIssue::AcceptsUnknownFields {
            endpoint: "y".to_string(),
            count: 1
        })
    );
}

#[test]
fn operations_generated() {
    let issues = vec![MassAssignIssue::ReflectedAdminField {
        field: "is_admin".to_string(),
        endpoint: "/api/users/1".to_string(),
    }];
    let mut seq = 0;
    let ops = mass_assign_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn operations_empty_for_no_issues() {
    let mut seq = 0;
    let ops = mass_assign_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn display_variants() {
    assert_eq!(
        MassAssignIssue::ReflectedAdminField {
            field: "admin".to_string(),
            endpoint: "/api/u".to_string()
        }
        .to_string(),
        "reflected_admin_field:admin@/api/u"
    );
    assert_eq!(
        MassAssignIssue::ReflectedRoleField {
            field: "role".to_string(),
            endpoint: "/api/u".to_string()
        }
        .to_string(),
        "reflected_role_field:role@/api/u"
    );
    assert_eq!(
        MassAssignIssue::AcceptsUnknownFields {
            endpoint: "/api/u".to_string(),
            count: 2
        }
        .to_string(),
        "accepts_unknown_fields:2@/api/u"
    );
}

#[test]
fn both_canaries_reflected() {
    let body = r#"{"__test_field_aegis":"a","__canary_param":"b"}"#;
    let issues = analyze_mass_assignment(
        "/api/users",
        &["__test_field_aegis", "__canary_param"],
        body,
    );
    assert!(
        issues.iter().any(
            |i| matches!(i, MassAssignIssue::AcceptsUnknownFields { count, .. } if *count == 2)
        )
    );
}
