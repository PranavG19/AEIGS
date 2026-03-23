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

// Tests for analyze_mass_assignment_advanced

#[test]
fn password_field_reflected_positive() {
    let body = r#"{"id":1,"password":"updated"}"#;
    let issues = analyze_mass_assignment_advanced("/api/users/1", &["password"], body);
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::PasswordFieldReflected { field, .. } if field == "password")
    ));
}

#[test]
fn password_field_api_key_variant() {
    let body = r#"{"api_key":"secret123"}"#;
    let issues = analyze_mass_assignment_advanced("/api/keys", &["api_key"], body);
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::PasswordFieldReflected { field, .. } if field == "api_key")
    ));
}

#[test]
fn password_field_negative() {
    let body = r#"{"id":1,"name":"user"}"#;
    let issues = analyze_mass_assignment_advanced("/api/users/1", &["password"], body);
    assert!(issues.is_empty());
}

#[test]
fn internal_id_exposed_positive() {
    let body = r#"{"_id":"507f1f77bcf86cd799439011"}"#;
    let issues = analyze_mass_assignment_advanced("/api/users/1", &["_id"], body);
    assert!(
        issues.iter().any(
            |i| matches!(i, MassAssignIssue::InternalIdExposed { field, .. } if field == "_id")
        )
    );
}

#[test]
fn internal_id_uuid_variant() {
    let body = r#"{"uuid":"550e8400-e29b-41d4-a716-446655440000"}"#;
    let issues = analyze_mass_assignment_advanced("/api/resources", &["uuid"], body);
    assert!(
        issues.iter().any(
            |i| matches!(i, MassAssignIssue::InternalIdExposed { field, .. } if field == "uuid")
        )
    );
}

#[test]
fn internal_id_negative() {
    let body = r#"{"id":1}"#;
    let issues = analyze_mass_assignment_advanced("/api/users/1", &["_id"], body);
    assert!(issues.is_empty());
}

#[test]
fn nested_object_injection_dot_notation() {
    let body = r#"{"profile.admin":true}"#;
    let issues = analyze_mass_assignment_advanced("/api/users/1", &["profile.admin"], body);
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::NestedObjectInjection { path, .. } if path == "profile.admin")
    ));
}

#[test]
fn nested_object_injection_bracket_notation() {
    let body = r#"{"settings[role]":"admin"}"#;
    let issues = analyze_mass_assignment_advanced("/api/users/1", &["settings[role]"], body);
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::NestedObjectInjection { path, .. } if path == "settings[role]")
    ));
}

#[test]
fn nested_object_injection_negative() {
    let body = r#"{"name":"user"}"#;
    let issues = analyze_mass_assignment_advanced("/api/users/1", &["profile.admin"], body);
    assert!(issues.is_empty());
}

#[test]
fn array_field_manipulation_bracket_suffix() {
    let body = r#"{"permissions[]":[1,2,3]}"#;
    let issues = analyze_mass_assignment_advanced("/api/cart", &["permissions[]"], body);
    // Fields with [] are categorized as NestedObjectInjection, not ArrayFieldManipulation
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::NestedObjectInjection { path, .. } if path == "permissions[]")
    ));
}

#[test]
fn array_field_manipulation_tags_variant() {
    let body = r#"{"tags":["admin","user"]}"#;
    let issues = analyze_mass_assignment_advanced("/api/posts", &["tags"], body);
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::ArrayFieldManipulation { field, .. } if field == "tags")
    ));
}

#[test]
fn array_field_manipulation_negative() {
    let body = r#"{"name":"item"}"#;
    let issues = analyze_mass_assignment_advanced("/api/cart", &["items"], body);
    assert!(issues.is_empty());
}

#[test]
fn metadata_field_reflected_created_at() {
    let body = r#"{"created_at":"2026-03-23T00:00:00Z"}"#;
    let issues = analyze_mass_assignment_advanced("/api/posts", &["created_at"], body);
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::MetadataFieldReflected { field, .. } if field == "created_at")
    ));
}

#[test]
fn metadata_field_reflected_version() {
    let body = r#"{"version":2}"#;
    let issues = analyze_mass_assignment_advanced("/api/docs", &["version"], body);
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::MetadataFieldReflected { field, .. } if field == "version")
    ));
}

#[test]
fn metadata_field_negative() {
    let body = r#"{"id":1}"#;
    let issues = analyze_mass_assignment_advanced("/api/posts", &["created_at"], body);
    assert!(issues.is_empty());
}

#[test]
fn timestamp_field_overwrite_positive() {
    let body = r#"{"timestamp":1711152000}"#;
    let issues = analyze_mass_assignment_advanced("/api/events", &["timestamp"], body);
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::TimestampFieldOverwrite { field, .. } if field == "timestamp")
    ));
}

#[test]
fn timestamp_field_expires_at_variant() {
    let body = r#"{"expires_at":"2026-12-31T23:59:59Z"}"#;
    let issues = analyze_mass_assignment_advanced("/api/tokens", &["expires_at"], body);
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::TimestampFieldOverwrite { field, .. } if field == "expires_at")
    ));
}

#[test]
fn timestamp_field_negative() {
    let body = r#"{"id":1}"#;
    let issues = analyze_mass_assignment_advanced("/api/events", &["timestamp"], body);
    assert!(issues.is_empty());
}

#[test]
fn status_field_manipulation_positive() {
    let body = r#"{"status":"active"}"#;
    let issues = analyze_mass_assignment_advanced("/api/users/1", &["status"], body);
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::StatusFieldManipulation { field, .. } if field == "status")
    ));
}

#[test]
fn status_field_verified_variant() {
    let body = r#"{"verified":true}"#;
    let issues = analyze_mass_assignment_advanced("/api/accounts", &["verified"], body);
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::StatusFieldManipulation { field, .. } if field == "verified")
    ));
}

#[test]
fn status_field_negative() {
    let body = r#"{"id":1}"#;
    let issues = analyze_mass_assignment_advanced("/api/users/1", &["status"], body);
    assert!(issues.is_empty());
}

#[test]
fn price_field_reflected_positive() {
    let body = r#"{"price":99.99}"#;
    let issues = analyze_mass_assignment_advanced("/api/products/1", &["price"], body);
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::PriceFieldReflected { field, .. } if field == "price")
    ));
}

#[test]
fn price_field_balance_variant() {
    let body = r#"{"balance":1000.00}"#;
    let issues = analyze_mass_assignment_advanced("/api/accounts", &["balance"], body);
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::PriceFieldReflected { field, .. } if field == "balance")
    ));
}

#[test]
fn price_field_negative() {
    let body = r#"{"id":1}"#;
    let issues = analyze_mass_assignment_advanced("/api/products/1", &["price"], body);
    assert!(issues.is_empty());
}

#[test]
fn type_field_confusion_positive() {
    let body = r#"{"type":"admin"}"#;
    let issues = analyze_mass_assignment_advanced("/api/users/1", &["type"], body);
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::TypeFieldConfusion { field, .. } if field == "type")
    ));
}

#[test]
fn type_field_kind_variant() {
    let body = r#"{"kind":"privileged"}"#;
    let issues = analyze_mass_assignment_advanced("/api/resources", &["kind"], body);
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::TypeFieldConfusion { field, .. } if field == "kind")
    ));
}

#[test]
fn type_field_negative() {
    let body = r#"{"id":1}"#;
    let issues = analyze_mass_assignment_advanced("/api/users/1", &["type"], body);
    assert!(issues.is_empty());
}

#[test]
fn hidden_field_accepted_single_underscore() {
    let body = r#"{"_private":"data"}"#;
    let issues = analyze_mass_assignment_advanced("/api/users/1", &["_private"], body);
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::HiddenFieldAccepted { field, .. } if field == "_private")
    ));
}

#[test]
fn hidden_field_accepted_double_underscore() {
    let body = r#"{"__internal":"secret"}"#;
    let issues = analyze_mass_assignment_advanced("/api/config", &["__internal"], body);
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::HiddenFieldAccepted { field, .. } if field == "__internal")
    ));
}

#[test]
fn hidden_field_negative() {
    let body = r#"{"name":"user"}"#;
    let issues = analyze_mass_assignment_advanced("/api/users/1", &["_private"], body);
    assert!(issues.is_empty());
}

#[test]
fn hidden_field_excludes_admin_fields() {
    let body = r#"{"is_admin":true}"#;
    let issues = analyze_mass_assignment_advanced("/api/users/1", &["is_admin"], body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MassAssignIssue::HiddenFieldAccepted { .. }))
    );
}

#[test]
fn hidden_field_excludes_canary_fields() {
    let body = r#"{"__test_field_aegis":"injected"}"#;
    let issues = analyze_mass_assignment_advanced("/api/users/1", &["__test_field_aegis"], body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MassAssignIssue::HiddenFieldAccepted { .. }))
    );
}

#[test]
fn advanced_empty_response_clean() {
    let issues = analyze_mass_assignment_advanced("/api/users/1", &["password", "price"], "");
    assert!(issues.is_empty());
}

#[test]
fn advanced_empty_fields_clean() {
    let body = r#"{"password":"secret","price":99.99}"#;
    let issues = analyze_mass_assignment_advanced("/api/users/1", &[], body);
    assert!(issues.is_empty());
}

#[test]
fn advanced_case_insensitive_matching() {
    let body = r#"{"PASSWORD":"secret","PRICE":99.99}"#;
    let issues = analyze_mass_assignment_advanced("/api/users/1", &["password", "price"], body);
    assert_eq!(issues.len(), 2);
}

#[test]
fn advanced_multiple_issues_same_response() {
    let body = r#"{"password":"secret","price":99.99,"status":"active","_id":"123"}"#;
    let issues = analyze_mass_assignment_advanced(
        "/api/users/1",
        &["password", "price", "status", "_id"],
        body,
    );
    assert_eq!(issues.len(), 4);
}

#[test]
fn advanced_priority_password_over_hidden() {
    let body = r#"{"_internal_data":"value"}"#;
    let issues = analyze_mass_assignment_advanced("/api/users/1", &["_internal_data"], body);
    // Should be categorized as hidden field (starts with underscore)
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::HiddenFieldAccepted { field, .. } if field == "_internal_data")
    ));
}

#[test]
fn severity_new_variants_ordering() {
    let password = MassAssignIssue::PasswordFieldReflected {
        field: "x".to_string(),
        endpoint: "y".to_string(),
    };
    let internal_id = MassAssignIssue::InternalIdExposed {
        field: "x".to_string(),
        endpoint: "y".to_string(),
    };
    let hidden = MassAssignIssue::HiddenFieldAccepted {
        field: "x".to_string(),
        endpoint: "y".to_string(),
    };

    assert!(mass_assign_severity(&password) > mass_assign_severity(&internal_id));
    assert!(mass_assign_severity(&internal_id) > mass_assign_severity(&hidden));
}

#[test]
fn severity_password_highest() {
    let password = MassAssignIssue::PasswordFieldReflected {
        field: "x".to_string(),
        endpoint: "y".to_string(),
    };
    assert_eq!(mass_assign_severity(&password), 9.5);
}

#[test]
fn operations_advanced_generated() {
    let issues = vec![
        MassAssignIssue::PasswordFieldReflected {
            field: "password".to_string(),
            endpoint: "/api/users/1".to_string(),
        },
        MassAssignIssue::PriceFieldReflected {
            field: "price".to_string(),
            endpoint: "/api/products/1".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = mass_assign_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_new_variants() {
    assert_eq!(
        MassAssignIssue::PasswordFieldReflected {
            field: "password".to_string(),
            endpoint: "/api/u".to_string()
        }
        .to_string(),
        "password_reflected:password@/api/u"
    );
    assert_eq!(
        MassAssignIssue::InternalIdExposed {
            field: "_id".to_string(),
            endpoint: "/api/u".to_string()
        }
        .to_string(),
        "internal_id_exposed:_id@/api/u"
    );
    assert_eq!(
        MassAssignIssue::NestedObjectInjection {
            path: "profile.admin".to_string(),
            endpoint: "/api/u".to_string()
        }
        .to_string(),
        "nested_object_injection:profile.admin@/api/u"
    );
    assert_eq!(
        MassAssignIssue::ArrayFieldManipulation {
            field: "tags".to_string(),
            endpoint: "/api/u".to_string()
        }
        .to_string(),
        "array_field_manipulation:tags@/api/u"
    );
    assert_eq!(
        MassAssignIssue::MetadataFieldReflected {
            field: "created_at".to_string(),
            endpoint: "/api/u".to_string()
        }
        .to_string(),
        "metadata_field_reflected:created_at@/api/u"
    );
    assert_eq!(
        MassAssignIssue::TimestampFieldOverwrite {
            field: "timestamp".to_string(),
            endpoint: "/api/u".to_string()
        }
        .to_string(),
        "timestamp_field_overwrite:timestamp@/api/u"
    );
    assert_eq!(
        MassAssignIssue::StatusFieldManipulation {
            field: "status".to_string(),
            endpoint: "/api/u".to_string()
        }
        .to_string(),
        "status_field_manipulation:status@/api/u"
    );
    assert_eq!(
        MassAssignIssue::PriceFieldReflected {
            field: "price".to_string(),
            endpoint: "/api/u".to_string()
        }
        .to_string(),
        "price_reflected:price@/api/u"
    );
    assert_eq!(
        MassAssignIssue::TypeFieldConfusion {
            field: "type".to_string(),
            endpoint: "/api/u".to_string()
        }
        .to_string(),
        "type_field_confusion:type@/api/u"
    );
    assert_eq!(
        MassAssignIssue::HiddenFieldAccepted {
            field: "_private".to_string(),
            endpoint: "/api/u".to_string()
        }
        .to_string(),
        "hidden_field_accepted:_private@/api/u"
    );
}

#[test]
fn advanced_combined_scenario_full_coverage() {
    let body = r#"{
        "password":"secret123",
        "uuid":"550e8400-e29b-41d4-a716-446655440000",
        "profile.admin":true,
        "roles":["admin","user"],
        "created_at":"2026-03-23",
        "expires_at":"2027-03-23",
        "status":"verified",
        "balance":1000.00,
        "type":"superuser",
        "__internal":"hidden"
    }"#;
    let issues = analyze_mass_assignment_advanced(
        "/api/users/1",
        &[
            "password",
            "uuid",
            "profile.admin",
            "roles",
            "created_at",
            "expires_at",
            "status",
            "balance",
            "type",
            "__internal",
        ],
        body,
    );
    assert_eq!(issues.len(), 10);
}

#[test]
fn advanced_partial_reflection() {
    let body = r#"{"password":"secret","uuid":"123"}"#;
    let issues = analyze_mass_assignment_advanced(
        "/api/users/1",
        &["password", "uuid", "nonexistent"],
        body,
    );
    assert_eq!(issues.len(), 2);
}

#[test]
fn nested_injection_multiple_dots() {
    let body = r#"{"user.profile.settings.admin":true}"#;
    let issues =
        analyze_mass_assignment_advanced("/api/users/1", &["user.profile.settings.admin"], body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MassAssignIssue::NestedObjectInjection { .. }))
    );
}

#[test]
fn array_field_roles_explicit() {
    let body = r#"{"roles":["admin"]}"#;
    let issues = analyze_mass_assignment_advanced("/api/users/1", &["roles"], body);
    assert!(issues.iter().any(
        |i| matches!(i, MassAssignIssue::ArrayFieldManipulation { field, .. } if field == "roles")
    ));
}

#[test]
fn camel_case_variants() {
    let body = r#"{"apiKey":"key123","internalId":"id456","createdAt":"2026-03-23"}"#;
    let issues = analyze_mass_assignment_advanced(
        "/api/config",
        &["apiKey", "internalId", "createdAt"],
        body,
    );
    assert_eq!(issues.len(), 3);
}
