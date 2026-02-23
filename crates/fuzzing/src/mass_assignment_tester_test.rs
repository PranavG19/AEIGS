use crate::mass_assignment_tester::{
    MassAssignmentTester, generate_mass_assignment_payloads, is_mass_assignment_candidate,
};

#[test]
fn candidate_post_is_candidate() {
    assert!(is_mass_assignment_candidate("POST"));
}

#[test]
fn candidate_put_is_candidate() {
    assert!(is_mass_assignment_candidate("PUT"));
}

#[test]
fn candidate_patch_is_candidate() {
    assert!(is_mass_assignment_candidate("PATCH"));
}

#[test]
fn candidate_get_is_not_candidate() {
    assert!(!is_mass_assignment_candidate("GET"));
}

#[test]
fn candidate_delete_is_not_candidate() {
    assert!(!is_mass_assignment_candidate("DELETE"));
}

#[test]
fn candidate_head_is_not_candidate() {
    assert!(!is_mass_assignment_candidate("HEAD"));
}

#[test]
fn candidate_options_is_not_candidate() {
    assert!(!is_mass_assignment_candidate("OPTIONS"));
}

#[test]
fn candidate_case_insensitive_post() {
    assert!(is_mass_assignment_candidate("post"));
}

#[test]
fn candidate_case_insensitive_put() {
    assert!(is_mass_assignment_candidate("put"));
}

#[test]
fn candidate_case_insensitive_patch() {
    assert!(is_mass_assignment_candidate("patch"));
}

#[test]
fn candidate_mixed_case() {
    assert!(is_mass_assignment_candidate("Post"));
    assert!(is_mass_assignment_candidate("pAtCh"));
}

#[test]
fn payloads_without_base_body_generates_all_fields() {
    let payloads = generate_mass_assignment_payloads(None);
    assert!(!payloads.is_empty());

    let fields: Vec<&str> = payloads.iter().map(|p| p.injected_field.as_str()).collect();
    assert!(fields.contains(&"role"));
    assert!(fields.contains(&"isAdmin"));
    assert!(fields.contains(&"is_admin"));
    assert!(fields.contains(&"admin"));
    assert!(fields.contains(&"permissions"));
    assert!(fields.contains(&"is_superuser"));
    assert!(fields.contains(&"level"));
    assert!(fields.contains(&"access_level"));
    assert!(fields.contains(&"plan"));
    assert!(fields.contains(&"subscription"));
    assert!(fields.contains(&"privilege"));
}

#[test]
fn payloads_without_base_body_produces_valid_json() {
    let payloads = generate_mass_assignment_payloads(None);
    for p in &payloads {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&p.body);
        assert!(parsed.is_ok(), "Invalid JSON: {}", p.body);
    }
}

#[test]
fn payloads_with_base_body_preserves_existing_fields() {
    let base = r#"{"username":"alice","email":"alice@test.com"}"#;
    let payloads = generate_mass_assignment_payloads(Some(base));

    for p in &payloads {
        let parsed: serde_json::Value = serde_json::from_str(&p.body).unwrap();
        let obj = parsed.as_object().unwrap();
        assert_eq!(obj.get("username").unwrap().as_str().unwrap(), "alice");
        assert_eq!(
            obj.get("email").unwrap().as_str().unwrap(),
            "alice@test.com"
        );
        assert!(
            obj.contains_key(&p.injected_field),
            "Missing injected field: {}",
            p.injected_field
        );
    }
}

#[test]
fn payloads_with_invalid_base_body_uses_empty_object() {
    let payloads = generate_mass_assignment_payloads(Some("not valid json"));
    assert!(!payloads.is_empty());

    for p in &payloads {
        let parsed: serde_json::Value = serde_json::from_str(&p.body).unwrap();
        let obj = parsed.as_object().unwrap();
        assert_eq!(obj.len(), 1);
        assert!(obj.contains_key(&p.injected_field));
    }
}

#[test]
fn payloads_boolean_fields_get_true_and_one() {
    let payloads = generate_mass_assignment_payloads(None);
    let admin_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| p.injected_field == "isAdmin")
        .collect();

    assert_eq!(admin_payloads.len(), 2);
    let values: Vec<&str> = admin_payloads
        .iter()
        .map(|p| p.injected_value.as_str())
        .collect();
    assert!(values.contains(&"true"));
    assert!(values.contains(&"1"));
}

#[test]
fn payloads_string_fields_get_admin_and_superuser() {
    let payloads = generate_mass_assignment_payloads(None);
    let role_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| p.injected_field == "role")
        .collect();

    assert_eq!(role_payloads.len(), 2);
    let values: Vec<&str> = role_payloads
        .iter()
        .map(|p| p.injected_value.as_str())
        .collect();
    assert!(values.contains(&"\"admin\""));
    assert!(values.contains(&"\"superuser\""));
}

#[test]
fn payloads_numeric_fields_get_999_and_zero() {
    let payloads = generate_mass_assignment_payloads(None);
    let level_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| p.injected_field == "level")
        .collect();

    assert_eq!(level_payloads.len(), 2);
    let values: Vec<&str> = level_payloads
        .iter()
        .map(|p| p.injected_value.as_str())
        .collect();
    assert!(values.contains(&"999"));
    assert!(values.contains(&"0"));
}

#[test]
fn payloads_access_level_gets_numeric_values() {
    let payloads = generate_mass_assignment_payloads(None);
    let al_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| p.injected_field == "access_level")
        .collect();

    assert_eq!(al_payloads.len(), 2);
    let parsed: serde_json::Value = serde_json::from_str(&al_payloads[0].body).unwrap();
    let val = parsed.get("access_level").unwrap();
    assert!(val.is_number());
}

#[test]
fn test_mass_assignment_rejects_get() {
    let findings =
        MassAssignmentTester::test_mass_assignment("http://127.0.0.1:3000/api/users", "GET", None);
    assert!(findings.is_empty());
}

#[test]
fn test_mass_assignment_rejects_delete() {
    let findings = MassAssignmentTester::test_mass_assignment(
        "http://127.0.0.1:3000/api/users",
        "DELETE",
        None,
    );
    assert!(findings.is_empty());
}

#[test]
fn test_mass_assignment_accepts_post() {
    let findings =
        MassAssignmentTester::test_mass_assignment("http://127.0.0.1:3000/api/users", "POST", None);
    assert!(!findings.is_empty());
}

#[test]
fn test_mass_assignment_accepts_put() {
    let findings =
        MassAssignmentTester::test_mass_assignment("http://127.0.0.1:3000/api/users", "PUT", None);
    assert!(!findings.is_empty());
}

#[test]
fn test_mass_assignment_accepts_patch() {
    let findings = MassAssignmentTester::test_mass_assignment(
        "http://127.0.0.1:3000/api/users",
        "PATCH",
        None,
    );
    assert!(!findings.is_empty());
}

#[test]
fn test_mass_assignment_case_insensitive_method() {
    let findings =
        MassAssignmentTester::test_mass_assignment("http://127.0.0.1:3000/api/users", "post", None);
    assert!(!findings.is_empty());
    assert_eq!(findings[0].method, "POST");
}

#[test]
fn test_mass_assignment_populates_endpoint() {
    let findings =
        MassAssignmentTester::test_mass_assignment("http://127.0.0.1:3000/api/users", "POST", None);
    for f in &findings {
        assert_eq!(f.endpoint, "http://127.0.0.1:3000/api/users");
    }
}

#[test]
fn test_mass_assignment_populates_method() {
    let findings = MassAssignmentTester::test_mass_assignment(
        "http://127.0.0.1:3000/api/users",
        "PATCH",
        None,
    );
    for f in &findings {
        assert_eq!(f.method, "PATCH");
    }
}

#[test]
fn severity_critical_for_admin_fields() {
    let findings =
        MassAssignmentTester::test_mass_assignment("http://127.0.0.1:3000/api/users", "POST", None);

    let critical_fields = [
        "isAdmin",
        "is_admin",
        "admin",
        "is_staff",
        "is_superuser",
        "role",
        "permissions",
        "privilege",
    ];

    for field in &critical_fields {
        let matching: Vec<_> = findings.iter().filter(|f| f.field == *field).collect();
        assert!(!matching.is_empty(), "Expected findings for field: {field}");
        for f in matching {
            assert!(
                (f.severity - 9.0).abs() < f64::EPSILON,
                "Expected severity 9.0 for {field}, got {}",
                f.severity
            );
        }
    }
}

#[test]
fn severity_high_for_non_admin_privilege_fields() {
    let findings =
        MassAssignmentTester::test_mass_assignment("http://127.0.0.1:3000/api/users", "POST", None);

    let high_fields = [
        "type",
        "user_type",
        "verified",
        "active",
        "email_verified",
        "plan",
        "subscription",
        "level",
        "access_level",
        "group",
    ];

    for field in &high_fields {
        let matching: Vec<_> = findings.iter().filter(|f| f.field == *field).collect();
        assert!(!matching.is_empty(), "Expected findings for field: {field}");
        for f in matching {
            assert!(
                (f.severity - 7.0).abs() < f64::EPSILON,
                "Expected severity 7.0 for {field}, got {}",
                f.severity
            );
        }
    }
}

#[test]
fn evidence_contains_field_and_endpoint() {
    let findings =
        MassAssignmentTester::test_mass_assignment("http://127.0.0.1:3000/api/users", "POST", None);
    for f in &findings {
        assert!(f.evidence.contains(&f.field));
        assert!(f.evidence.contains("http://127.0.0.1:3000/api/users"));
        assert!(f.evidence.contains("POST"));
    }
}

#[test]
fn all_eighteen_privilege_fields_covered() {
    let payloads = generate_mass_assignment_payloads(None);
    let mut unique_fields: Vec<String> =
        payloads.iter().map(|p| p.injected_field.clone()).collect();
    unique_fields.sort();
    unique_fields.dedup();

    assert_eq!(unique_fields.len(), 18);
}

#[test]
fn payloads_with_empty_base_string_uses_empty_object() {
    let payloads = generate_mass_assignment_payloads(Some(""));
    assert!(!payloads.is_empty());
    for p in &payloads {
        let parsed: serde_json::Value = serde_json::from_str(&p.body).unwrap();
        assert!(parsed.is_object());
    }
}

#[test]
fn payloads_each_has_exactly_one_injected_field_when_no_base() {
    let payloads = generate_mass_assignment_payloads(None);
    for p in &payloads {
        let parsed: serde_json::Value = serde_json::from_str(&p.body).unwrap();
        let obj = parsed.as_object().unwrap();
        assert_eq!(obj.len(), 1);
    }
}

#[test]
fn payloads_with_base_body_adds_one_field() {
    let base = r#"{"name":"bob"}"#;
    let payloads = generate_mass_assignment_payloads(Some(base));
    for p in &payloads {
        let parsed: serde_json::Value = serde_json::from_str(&p.body).unwrap();
        let obj = parsed.as_object().unwrap();
        assert_eq!(obj.len(), 2);
    }
}

#[test]
fn payloads_is_superuser_gets_boolean_values() {
    let payloads = generate_mass_assignment_payloads(None);
    let su_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| p.injected_field == "is_superuser")
        .collect();

    assert_eq!(su_payloads.len(), 2);

    let first: serde_json::Value = serde_json::from_str(&su_payloads[0].body).unwrap();
    assert_eq!(
        first.get("is_superuser").unwrap(),
        &serde_json::Value::Bool(true)
    );

    let second: serde_json::Value = serde_json::from_str(&su_payloads[1].body).unwrap();
    assert_eq!(second.get("is_superuser").unwrap(), &serde_json::json!(1));
}

#[test]
fn payloads_plan_gets_string_values() {
    let payloads = generate_mass_assignment_payloads(None);
    let plan_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| p.injected_field == "plan")
        .collect();

    assert_eq!(plan_payloads.len(), 2);

    let first: serde_json::Value = serde_json::from_str(&plan_payloads[0].body).unwrap();
    assert_eq!(first.get("plan").unwrap().as_str().unwrap(), "admin");

    let second: serde_json::Value = serde_json::from_str(&plan_payloads[1].body).unwrap();
    assert_eq!(second.get("plan").unwrap().as_str().unwrap(), "superuser");
}

#[test]
fn test_mass_assignment_with_base_body() {
    let base = r#"{"username":"alice"}"#;
    let findings = MassAssignmentTester::test_mass_assignment(
        "http://127.0.0.1:3000/api/users",
        "POST",
        Some(base),
    );

    assert!(!findings.is_empty());
    for f in &findings {
        assert_eq!(f.endpoint, "http://127.0.0.1:3000/api/users");
        assert_eq!(f.method, "POST");
    }
}

#[test]
fn payloads_verified_gets_boolean_values() {
    let payloads = generate_mass_assignment_payloads(None);
    let verified_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| p.injected_field == "verified")
        .collect();

    assert_eq!(verified_payloads.len(), 2);
    let values: Vec<&str> = verified_payloads
        .iter()
        .map(|p| p.injected_value.as_str())
        .collect();
    assert!(values.contains(&"true"));
    assert!(values.contains(&"1"));
}

#[test]
fn payloads_group_gets_string_values() {
    let payloads = generate_mass_assignment_payloads(None);
    let group_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| p.injected_field == "group")
        .collect();

    assert_eq!(group_payloads.len(), 2);
    let values: Vec<&str> = group_payloads
        .iter()
        .map(|p| p.injected_value.as_str())
        .collect();
    assert!(values.contains(&"\"admin\""));
    assert!(values.contains(&"\"superuser\""));
}
