use super::ldap_enumeration::*;

#[test]
fn injection_payloads_has_at_least_twelve_entries() {
    assert!(LDAP_INJECTION_PAYLOADS.len() >= 12);
}

#[test]
fn all_injection_payloads_have_non_empty_fields() {
    for p in LDAP_INJECTION_PAYLOADS {
        assert!(!p.name.is_empty(), "payload name must not be empty");
        assert!(!p.payload.is_empty(), "payload value must not be empty");
        assert!(!p.description.is_empty(), "description must not be empty");
    }
}

#[test]
fn injection_payload_names_are_unique() {
    let mut seen = std::collections::HashSet::new();
    for p in LDAP_INJECTION_PAYLOADS {
        assert!(seen.insert(p.name), "duplicate payload name: {}", p.name);
    }
}

#[test]
fn filter_manipulation_payloads_exist() {
    let results = payloads_for_category(InjectionCategory::FilterManipulation);
    assert!(
        results.len() >= 3,
        "expected >=3 filter manipulation payloads, got {}",
        results.len()
    );
    for p in &results {
        assert_eq!(p.category, InjectionCategory::FilterManipulation);
    }
}

#[test]
fn blind_boolean_payloads_include_true_and_false() {
    let results = payloads_for_category(InjectionCategory::BlindBoolean);
    assert_eq!(
        results.len(),
        2,
        "need exactly one true and one false blind payload"
    );
    let names: Vec<&str> = results.iter().map(|p| p.name).collect();
    assert!(names.contains(&"blind_true_condition"));
    assert!(names.contains(&"blind_false_condition"));
}

#[test]
fn user_enumeration_payloads_exist() {
    let results = payloads_for_category(InjectionCategory::UserEnumeration);
    assert!(!results.is_empty());
}

#[test]
fn auth_bypass_payloads_exist() {
    let results = payloads_for_category(InjectionCategory::AuthBypass);
    assert!(!results.is_empty());
}

#[test]
fn null_byte_payloads_contain_null() {
    let results = payloads_for_category(InjectionCategory::NullByte);
    assert!(!results.is_empty());
    for p in &results {
        assert!(
            p.payload.contains('\x00'),
            "null byte payload '{}' missing \\x00",
            p.name
        );
    }
}

#[test]
fn ad_queries_cover_all_target_types() {
    let targets: std::collections::HashSet<AdTarget> =
        AD_ENUMERATION_QUERIES.iter().map(|q| q.target).collect();
    assert!(targets.contains(&AdTarget::PrivilegedGroup));
    assert!(targets.contains(&AdTarget::ServiceAccount));
    assert!(targets.contains(&AdTarget::DisabledAccount));
    assert!(targets.contains(&AdTarget::PasswordPolicy));
    assert!(targets.contains(&AdTarget::TrustRelationship));
    assert!(targets.contains(&AdTarget::ComputerAccount));
    assert!(targets.contains(&AdTarget::GroupPolicy));
}

#[test]
fn ad_queries_for_service_accounts() {
    let results = ad_queries_for_target(AdTarget::ServiceAccount);
    assert!(results.len() >= 2, "expected >=2 service account queries");
    for q in &results {
        assert_eq!(q.target, AdTarget::ServiceAccount);
    }
}

#[test]
fn ad_queries_for_privileged_groups() {
    let results = ad_queries_for_target(AdTarget::PrivilegedGroup);
    assert!(
        results.len() >= 3,
        "expected Domain/Enterprise/Schema Admins"
    );
}

#[test]
fn ad_query_names_are_unique() {
    let mut seen = std::collections::HashSet::new();
    for q in AD_ENUMERATION_QUERIES {
        assert!(seen.insert(q.name), "duplicate AD query name: {}", q.name);
    }
}

#[test]
fn build_user_enum_filter_empty_attributes() {
    let filter = build_user_enum_filter(&[]);
    assert_eq!(filter, "(objectClass=person)");
}

#[test]
fn build_user_enum_filter_single_attribute() {
    let filter = build_user_enum_filter(&["uid"]);
    assert_eq!(filter, "(&(objectClass=person)(uid=*))");
}

#[test]
fn build_user_enum_filter_multiple_attributes() {
    let filter = build_user_enum_filter(&["uid", "cn", "mail"]);
    assert!(filter.starts_with("(&(objectClass=person)(|"));
    assert!(filter.contains("(uid=*)"));
    assert!(filter.contains("(cn=*)"));
    assert!(filter.contains("(mail=*)"));
    assert!(filter.ends_with("))"));
}

#[test]
fn build_group_enum_filter_contains_all_group_classes() {
    let filter = build_group_enum_filter();
    assert!(filter.contains("groupOfNames"));
    assert!(filter.contains("groupOfUniqueNames"));
    assert!(filter.contains("posixGroup"));
    assert!(filter.contains("(objectClass=group)"));
}

#[test]
fn build_blind_payload_structure() {
    let payload = build_blind_payload("cn", "adm", 'i');
    assert_eq!(payload, "*)(cn=admi*");
}

#[test]
fn build_blind_payload_empty_prefix() {
    let payload = build_blind_payload("uid", "", 'a');
    assert_eq!(payload, "*)(uid=a*");
}

#[test]
fn blind_response_differs_within_tolerance() {
    assert!(!blind_response_differs(100, 110, 20));
    assert!(!blind_response_differs(100, 100, 0));
}

#[test]
fn blind_response_differs_exceeds_tolerance() {
    assert!(blind_response_differs(100, 200, 50));
    assert!(blind_response_differs(200, 100, 50));
}

#[test]
fn blind_extraction_state_lifecycle() {
    let mut state = BlindExtractionState::new("cn");
    assert_eq!(state.attribute, "cn");
    assert!(state.extracted.is_empty());
    assert_eq!(state.total_queries, 0);
    assert!(!state.is_complete());

    state.record_miss();
    assert_eq!(state.total_queries, 1);
    assert!(state.extracted.is_empty());

    state.advance('a');
    assert_eq!(state.extracted, "a");
    assert_eq!(state.total_queries, 2);

    state.advance('d');
    state.advance('m');
    assert_eq!(state.extracted, "adm");

    state.confirmed_length = Some(3);
    assert!(state.is_complete());
}

#[test]
fn blind_extraction_charset_covers_alphanumeric_and_special() {
    assert!(BLIND_EXTRACTION_CHARSET.contains('a'));
    assert!(BLIND_EXTRACTION_CHARSET.contains('Z'));
    assert!(BLIND_EXTRACTION_CHARSET.contains('0'));
    assert!(BLIND_EXTRACTION_CHARSET.contains('_'));
    assert!(BLIND_EXTRACTION_CHARSET.contains('-'));
    assert!(BLIND_EXTRACTION_CHARSET.contains('.'));
    assert!(BLIND_EXTRACTION_CHARSET.contains('@'));
}

#[test]
fn evaluate_injection_error_based_detection() {
    assert!(evaluate_injection_result(
        None,
        None,
        Some("LDAP syntax error in filter"),
        50
    ));
    assert!(evaluate_injection_result(
        None,
        None,
        Some("javax.naming.NamingException"),
        50
    ));
    assert!(evaluate_injection_result(
        None,
        None,
        Some("bad search filter"),
        50
    ));
    assert!(evaluate_injection_result(
        None,
        None,
        Some("LDAPException occurred"),
        50
    ));
}

#[test]
fn evaluate_injection_no_error_no_size() {
    assert!(!evaluate_injection_result(None, None, None, 50));
}

#[test]
fn evaluate_injection_size_based_detection() {
    assert!(evaluate_injection_result(Some(100), Some(500), None, 50));
    assert!(!evaluate_injection_result(Some(100), Some(120), None, 50));
}

#[test]
fn report_new_initializes_empty() {
    let report = LdapEnumerationReport::new("ldap://localhost", 389);
    assert_eq!(report.target, "ldap://localhost");
    assert_eq!(report.port, 389);
    assert!(report.anonymous_bind.is_none());
    assert!(report.null_bind.is_none());
    assert!(report.users.is_empty());
    assert!(report.groups.is_empty());
    assert_eq!(report.total_findings(), 0);
}

#[test]
fn report_record_anonymous_bind_success_creates_finding() {
    let mut report = LdapEnumerationReport::new("ldap://localhost", 389);
    report.record_anonymous_bind(LdapBindResult {
        bind_type: LdapBindType::Anonymous,
        success: true,
        server_message: None,
        naming_contexts: vec!["dc=example,dc=com".to_string()],
    });
    assert_eq!(report.total_findings(), 1);
    assert_eq!(
        report.findings[0].finding_type,
        LdapFindingType::AnonymousBindAllowed
    );
    assert_eq!(report.findings[0].severity, FindingSeverity::High);
}

#[test]
fn report_record_anonymous_bind_failure_no_finding() {
    let mut report = LdapEnumerationReport::new("ldap://localhost", 389);
    report.record_anonymous_bind(LdapBindResult {
        bind_type: LdapBindType::Anonymous,
        success: false,
        server_message: Some("Bind failed".to_string()),
        naming_contexts: Vec::new(),
    });
    assert_eq!(report.total_findings(), 0);
    assert!(report.anonymous_bind.is_some());
}

#[test]
fn report_record_null_bind_success() {
    let mut report = LdapEnumerationReport::new("ldap://localhost", 389);
    report.record_null_bind(LdapBindResult {
        bind_type: LdapBindType::NullCredentials,
        success: true,
        server_message: Some("OK".to_string()),
        naming_contexts: Vec::new(),
    });
    assert_eq!(report.total_findings(), 1);
    assert_eq!(
        report.findings[0].finding_type,
        LdapFindingType::NullBindAccepted
    );
}

#[test]
fn report_record_schema_creates_finding_when_populated() {
    let mut report = LdapEnumerationReport::new("ldap://localhost", 389);
    report.record_schema(SchemaEnumerationResult {
        object_classes: vec!["person".to_string(), "inetOrgPerson".to_string()],
        attributes: vec!["cn".to_string()],
        naming_contexts: vec!["dc=test,dc=com".to_string()],
        supported_controls: Vec::new(),
        ldap_versions: vec![3],
    });
    assert_eq!(report.total_findings(), 1);
    assert_eq!(
        report.findings[0].finding_type,
        LdapFindingType::SchemaExposed
    );
    assert_eq!(report.findings[0].severity, FindingSeverity::Medium);
}

#[test]
fn report_record_users_creates_finding() {
    let mut report = LdapEnumerationReport::new("ldap://localhost", 389);
    report.record_users(vec![LdapUserEntry {
        dn: "uid=admin,ou=People,dc=example,dc=com".to_string(),
        uid: Some("admin".to_string()),
        cn: Some("Administrator".to_string()),
        mail: Some("admin@example.com".to_string()),
        groups: vec!["cn=admins,ou=Groups,dc=example,dc=com".to_string()],
        extra_attributes: Vec::new(),
    }]);
    assert_eq!(report.total_findings(), 1);
    assert_eq!(
        report.findings[0].finding_type,
        LdapFindingType::UserEnumerationSucceeded
    );
}

#[test]
fn report_record_groups_creates_finding() {
    let mut report = LdapEnumerationReport::new("ldap://localhost", 389);
    report.record_groups(vec![LdapGroupEntry {
        dn: "cn=admins,ou=Groups,dc=example,dc=com".to_string(),
        cn: "admins".to_string(),
        members: vec!["uid=admin,ou=People,dc=example,dc=com".to_string()],
        nested_groups: Vec::new(),
    }]);
    assert_eq!(report.total_findings(), 1);
    assert_eq!(
        report.findings[0].finding_type,
        LdapFindingType::GroupEnumerationSucceeded
    );
}

#[test]
fn report_record_injection_vulnerable() {
    let mut report = LdapEnumerationReport::new("ldap://localhost", 389);
    report.record_injection_result(InjectionTestResult {
        payload: LDAP_INJECTION_PAYLOADS[0].clone(),
        original_response_size: Some(100),
        injected_response_size: Some(5000),
        response_differs: true,
        error_message: None,
        likely_vulnerable: true,
    });
    assert_eq!(report.total_findings(), 1);
    assert_eq!(report.findings[0].severity, FindingSeverity::Critical);
    assert_eq!(
        report.findings[0].finding_type,
        LdapFindingType::InjectionVulnerable
    );
}

#[test]
fn report_record_injection_not_vulnerable_no_finding() {
    let mut report = LdapEnumerationReport::new("ldap://localhost", 389);
    report.record_injection_result(InjectionTestResult {
        payload: LDAP_INJECTION_PAYLOADS[0].clone(),
        original_response_size: Some(100),
        injected_response_size: Some(105),
        response_differs: false,
        error_message: None,
        likely_vulnerable: false,
    });
    assert_eq!(report.total_findings(), 0);
    assert_eq!(report.injection_results.len(), 1);
}

#[test]
fn report_record_blind_extraction_creates_finding() {
    let mut report = LdapEnumerationReport::new("ldap://localhost", 389);
    let mut state = BlindExtractionState::new("uid");
    state.advance('a');
    state.advance('d');
    state.advance('m');
    report.record_blind_state(state);
    assert_eq!(report.total_findings(), 1);
    assert_eq!(
        report.findings[0].finding_type,
        LdapFindingType::BlindExtractionSucceeded
    );
    assert_eq!(report.findings[0].severity, FindingSeverity::Critical);
}

#[test]
fn report_record_blind_extraction_empty_no_finding() {
    let mut report = LdapEnumerationReport::new("ldap://localhost", 389);
    let state = BlindExtractionState::new("uid");
    report.record_blind_state(state);
    assert_eq!(report.total_findings(), 0);
}

#[test]
fn report_critical_findings_filter() {
    let mut report = LdapEnumerationReport::new("ldap://localhost", 389);
    report.record_anonymous_bind(LdapBindResult {
        bind_type: LdapBindType::Anonymous,
        success: true,
        server_message: None,
        naming_contexts: vec!["dc=test,dc=com".to_string()],
    });
    report.record_injection_result(InjectionTestResult {
        payload: LDAP_INJECTION_PAYLOADS[1].clone(),
        original_response_size: Some(50),
        injected_response_size: Some(5000),
        response_differs: true,
        error_message: None,
        likely_vulnerable: true,
    });
    let crits = report.critical_findings();
    assert_eq!(crits.len(), 1);
    assert_eq!(crits[0].finding_type, LdapFindingType::InjectionVulnerable);
}

#[test]
fn report_service_account_findings() {
    let mut report = LdapEnumerationReport::new("ldap://localhost", 389);
    for q in AD_ENUMERATION_QUERIES {
        report.record_ad_query(q.clone());
    }
    let svc = report.service_account_findings();
    assert!(svc.len() >= 2);
}

#[test]
fn compute_risk_score_empty_report() {
    let report = LdapEnumerationReport::new("ldap://localhost", 389);
    assert_eq!(compute_risk_score(&report), 0);
}

#[test]
fn compute_risk_score_mixed_findings() {
    let mut report = LdapEnumerationReport::new("ldap://localhost", 389);
    report.record_anonymous_bind(LdapBindResult {
        bind_type: LdapBindType::Anonymous,
        success: true,
        server_message: None,
        naming_contexts: vec!["dc=x,dc=y".to_string()],
    });
    report.record_schema(SchemaEnumerationResult {
        object_classes: vec!["top".to_string()],
        attributes: Vec::new(),
        naming_contexts: vec!["dc=x,dc=y".to_string()],
        supported_controls: Vec::new(),
        ldap_versions: vec![3],
    });
    let score = compute_risk_score(&report);
    assert_eq!(score, 30); // High(20) + Medium(10)
}

#[test]
fn rootdse_filter_is_valid() {
    let filter = rootdse_filter();
    assert_eq!(filter, "(objectClass=*)");
}

#[test]
fn rootdse_attributes_includes_naming_contexts() {
    let attrs = rootdse_requested_attributes();
    assert!(attrs.contains(&"namingContexts"));
    assert!(attrs.contains(&"defaultNamingContext"));
    assert!(attrs.contains(&"supportedLDAPVersion"));
}

#[test]
fn build_nested_group_filter_structure() {
    let filter = build_nested_group_filter("cn=Domain Admins,cn=Users,dc=corp,dc=local");
    assert!(filter.contains("1.2.840.113556.1.4.1941"));
    assert!(filter.contains("cn=Domain Admins"));
}

#[test]
fn build_service_account_filter_contains_uac_bit() {
    let filter = build_service_account_filter();
    assert!(filter.contains("65536"));
    assert!(filter.contains("userAccountControl"));
}

#[test]
fn build_kerberoastable_filter_excludes_krbtgt() {
    let filter = build_kerberoastable_filter();
    assert!(filter.contains("servicePrincipalName=*"));
    assert!(filter.contains("!(cn=krbtgt)"));
}

#[test]
fn password_policy_attributes_complete() {
    let attrs = password_policy_attributes();
    assert!(attrs.contains(&"minPwdLength"));
    assert!(attrs.contains(&"maxPwdAge"));
    assert!(attrs.contains(&"lockoutThreshold"));
    assert!(attrs.contains(&"lockoutDuration"));
    assert!(attrs.contains(&"pwdHistoryLength"));
}

#[test]
fn schema_object_classes_includes_ad_and_posix() {
    assert!(SCHEMA_OBJECT_CLASSES.contains(&"person"));
    assert!(SCHEMA_OBJECT_CLASSES.contains(&"inetOrgPerson"));
    assert!(SCHEMA_OBJECT_CLASSES.contains(&"posixAccount"));
    assert!(SCHEMA_OBJECT_CLASSES.contains(&"user"));
    assert!(SCHEMA_OBJECT_CLASSES.contains(&"group"));
    assert!(SCHEMA_OBJECT_CLASSES.contains(&"computer"));
}

#[test]
fn user_enumeration_attributes_includes_core_attrs() {
    assert!(USER_ENUMERATION_ATTRIBUTES.contains(&"uid"));
    assert!(USER_ENUMERATION_ATTRIBUTES.contains(&"cn"));
    assert!(USER_ENUMERATION_ATTRIBUTES.contains(&"sAMAccountName"));
    assert!(USER_ENUMERATION_ATTRIBUTES.contains(&"mail"));
    assert!(USER_ENUMERATION_ATTRIBUTES.contains(&"userPrincipalName"));
}

#[test]
fn group_enumeration_filters_has_entries() {
    assert!(GROUP_ENUMERATION_FILTERS.len() >= 4);
}

#[test]
fn common_base_dns_has_entries() {
    assert!(COMMON_BASE_DNS.len() >= 5);
    for dn in COMMON_BASE_DNS {
        assert!(dn.contains('='), "base DN '{}' must contain '='", dn);
    }
}

#[test]
fn ldap_bind_type_display() {
    assert_eq!(format!("{}", LdapBindType::Anonymous), "Anonymous Bind");
    assert_eq!(
        format!("{}", LdapBindType::NullCredentials),
        "Null Credentials Bind"
    );
    assert_eq!(
        format!(
            "{}",
            LdapBindType::SimpleAuth {
                dn: "cn=admin".to_string(),
                password: "secret".to_string(),
            }
        ),
        "Simple Auth (cn=admin)"
    );
}

#[test]
fn injection_category_display() {
    assert_eq!(
        format!("{}", InjectionCategory::FilterManipulation),
        "Filter Manipulation"
    );
    assert_eq!(
        format!("{}", InjectionCategory::BlindBoolean),
        "Blind Boolean"
    );
    assert_eq!(format!("{}", InjectionCategory::AuthBypass), "Auth Bypass");
    assert_eq!(format!("{}", InjectionCategory::NullByte), "Null Byte");
    assert_eq!(
        format!("{}", InjectionCategory::GroupEnumeration),
        "Group Enumeration"
    );
}

#[test]
fn ad_target_display() {
    assert_eq!(format!("{}", AdTarget::PrivilegedGroup), "Privileged Group");
    assert_eq!(format!("{}", AdTarget::ServiceAccount), "Service Account");
    assert_eq!(format!("{}", AdTarget::GroupPolicy), "Group Policy");
}

#[test]
fn finding_severity_display() {
    assert_eq!(format!("{}", FindingSeverity::Critical), "Critical");
    assert_eq!(format!("{}", FindingSeverity::High), "High");
    assert_eq!(format!("{}", FindingSeverity::Medium), "Medium");
    assert_eq!(format!("{}", FindingSeverity::Low), "Low");
    assert_eq!(format!("{}", FindingSeverity::Info), "Info");
}

#[test]
fn finding_type_display() {
    assert_eq!(
        format!("{}", LdapFindingType::AnonymousBindAllowed),
        "Anonymous Bind Allowed"
    );
    assert_eq!(
        format!("{}", LdapFindingType::InjectionVulnerable),
        "LDAP Injection Vulnerable"
    );
    assert_eq!(
        format!("{}", LdapFindingType::BlindExtractionSucceeded),
        "Blind Extraction Succeeded"
    );
    assert_eq!(
        format!("{}", LdapFindingType::ServiceAccountDetected),
        "Service Account Detected"
    );
    assert_eq!(
        format!("{}", LdapFindingType::PrivilegedGroupExposed),
        "Privileged Group Exposed"
    );
}

#[test]
fn evaluate_injection_case_insensitive_error_match() {
    assert!(evaluate_injection_result(
        None,
        None,
        Some("LDAP SYNTAX ERROR"),
        50
    ));
    assert!(evaluate_injection_result(
        None,
        None,
        Some("Filter Error happened"),
        50
    ));
}

#[test]
fn evaluate_injection_unrelated_error_not_flagged() {
    assert!(!evaluate_injection_result(
        None,
        None,
        Some("connection timeout"),
        50
    ));
    assert!(!evaluate_injection_result(
        None,
        None,
        Some("404 not found"),
        50
    ));
}

#[test]
fn full_report_lifecycle() {
    let mut report = LdapEnumerationReport::new("ldap://127.0.0.1", 636);
    assert_eq!(report.port, 636);

    report.record_anonymous_bind(LdapBindResult {
        bind_type: LdapBindType::Anonymous,
        success: true,
        server_message: None,
        naming_contexts: vec!["dc=corp,dc=local".to_string()],
    });

    report.record_null_bind(LdapBindResult {
        bind_type: LdapBindType::NullCredentials,
        success: true,
        server_message: Some("Accepted".to_string()),
        naming_contexts: Vec::new(),
    });

    report.record_schema(SchemaEnumerationResult {
        object_classes: vec!["person".to_string(), "user".to_string()],
        attributes: vec!["cn".to_string(), "uid".to_string()],
        naming_contexts: vec!["dc=corp,dc=local".to_string()],
        supported_controls: vec!["1.2.840.113556.1.4.319".to_string()],
        ldap_versions: vec![2, 3],
    });

    report.record_users(vec![LdapUserEntry {
        dn: "cn=jdoe,ou=Users,dc=corp,dc=local".to_string(),
        uid: Some("jdoe".to_string()),
        cn: Some("John Doe".to_string()),
        mail: Some("jdoe@corp.local".to_string()),
        groups: Vec::new(),
        extra_attributes: Vec::new(),
    }]);

    report.record_groups(vec![LdapGroupEntry {
        dn: "cn=IT,ou=Groups,dc=corp,dc=local".to_string(),
        cn: "IT".to_string(),
        members: vec!["cn=jdoe,ou=Users,dc=corp,dc=local".to_string()],
        nested_groups: Vec::new(),
    }]);

    report.record_injection_result(InjectionTestResult {
        payload: LDAP_INJECTION_PAYLOADS[1].clone(),
        original_response_size: Some(200),
        injected_response_size: Some(8000),
        response_differs: true,
        error_message: None,
        likely_vulnerable: true,
    });

    let mut blind = BlindExtractionState::new("sAMAccountName");
    blind.advance('s');
    blind.advance('v');
    blind.advance('c');
    report.record_blind_state(blind);

    for q in AD_ENUMERATION_QUERIES {
        report.record_ad_query(q.clone());
    }

    assert_eq!(report.total_findings(), 7);
    assert_eq!(report.critical_findings().len(), 2);
    assert!(compute_risk_score(&report) > 0);
    assert!(!report.service_account_findings().is_empty());
}
