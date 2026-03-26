#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use crate::api_schema_drift_v2::{
        ApiSchemaDriftDetector, DriftFinding, DriftSeverity, DriftType, FieldSpec,
        SchemaDriftConfig, SchemaVersion,
    };

    fn sample_fields() -> Vec<FieldSpec> {
        vec![
            FieldSpec {
                name: "username".to_string(),
                field_type: "string".to_string(),
                required: true,
                validation_regex: Some(r"^[a-zA-Z0-9_]{3,32}$".to_string()),
            },
            FieldSpec {
                name: "email".to_string(),
                field_type: "string".to_string(),
                required: true,
                validation_regex: Some(r"^.+@.+\..+$".to_string()),
            },
            FieldSpec {
                name: "age".to_string(),
                field_type: "integer".to_string(),
                required: false,
                validation_regex: None,
            },
        ]
    }

    fn v1_schema() -> SchemaVersion {
        let mut fields = HashMap::new();
        fields.insert("/api/users".to_string(), sample_fields());

        let mut auth = HashMap::new();
        auth.insert("/api/users".to_string(), vec!["bearer_token".to_string()]);
        auth.insert(
            "/api/admin".to_string(),
            vec!["bearer_token".to_string(), "api_key".to_string()],
        );

        let mut rate_limited = HashSet::new();
        rate_limited.insert("/api/users".to_string());
        rate_limited.insert("/api/login".to_string());

        SchemaVersion {
            version: "v1".to_string(),
            endpoints: vec![
                "/api/users".to_string(),
                "/api/admin".to_string(),
                "/api/login".to_string(),
            ],
            fields_per_endpoint: fields,
            auth_requirements: auth,
            rate_limited_endpoints: rate_limited,
        }
    }

    fn v2_schema_with_regressions() -> SchemaVersion {
        let mut fields = HashMap::new();
        fields.insert(
            "/api/users".to_string(),
            vec![
                FieldSpec {
                    name: "username".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    validation_regex: None,
                },
                FieldSpec {
                    name: "email".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    validation_regex: Some(r"^.+@.+\..+$".to_string()),
                },
            ],
        );

        let mut auth = HashMap::new();
        auth.insert("/api/users".to_string(), vec![]);
        auth.insert("/api/admin".to_string(), vec!["bearer_token".to_string()]);

        let rate_limited = HashSet::new();

        SchemaVersion {
            version: "v2".to_string(),
            endpoints: vec![
                "/api/users".to_string(),
                "/api/admin".to_string(),
                "/api/login".to_string(),
                "/api/export".to_string(),
            ],
            fields_per_endpoint: fields,
            auth_requirements: auth,
            rate_limited_endpoints: rate_limited,
        }
    }

    fn v2_schema_improved() -> SchemaVersion {
        let mut fields = HashMap::new();
        fields.insert(
            "/api/users".to_string(),
            vec![
                FieldSpec {
                    name: "username".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    validation_regex: Some(r"^[a-zA-Z0-9_]{3,64}$".to_string()),
                },
                FieldSpec {
                    name: "email".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    validation_regex: Some(r"^.+@.+\..+$".to_string()),
                },
                FieldSpec {
                    name: "age".to_string(),
                    field_type: "integer".to_string(),
                    required: false,
                    validation_regex: Some(r"^[0-9]{1,3}$".to_string()),
                },
            ],
        );

        let mut auth = HashMap::new();
        auth.insert(
            "/api/users".to_string(),
            vec!["bearer_token".to_string(), "mfa".to_string()],
        );
        auth.insert(
            "/api/admin".to_string(),
            vec!["bearer_token".to_string(), "api_key".to_string()],
        );

        let mut rate_limited = HashSet::new();
        rate_limited.insert("/api/users".to_string());
        rate_limited.insert("/api/login".to_string());
        rate_limited.insert("/api/admin".to_string());

        SchemaVersion {
            version: "v2".to_string(),
            endpoints: vec![
                "/api/users".to_string(),
                "/api/admin".to_string(),
                "/api/login".to_string(),
            ],
            fields_per_endpoint: fields,
            auth_requirements: auth,
            rate_limited_endpoints: rate_limited,
        }
    }

    #[test]
    fn extra_fields_detects_mass_assignment_candidates() {
        let config = SchemaDriftConfig::default();
        let mut detector = ApiSchemaDriftDetector::new(config);
        let fields = sample_fields();

        let findings = detector.test_extra_fields("/api/users", &fields);

        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .all(|f| f.drift_type == DriftType::ExtraFieldAccepted));

        let admin_finding = findings
            .iter()
            .find(|f| f.field_name.as_deref() == Some("isAdmin"));
        assert!(admin_finding.is_some());
        assert_eq!(admin_finding.unwrap().severity, DriftSeverity::Critical);
        assert!(admin_finding.unwrap().is_exploitable);
    }

    #[test]
    fn extra_fields_skips_known_fields() {
        let config = SchemaDriftConfig::default();
        let mut detector = ApiSchemaDriftDetector::new(config);
        let fields = sample_fields();

        let findings = detector.test_extra_fields("/api/users", &fields);

        assert!(!findings
            .iter()
            .any(|f| f.field_name.as_deref() == Some("username")));
        assert!(!findings
            .iter()
            .any(|f| f.field_name.as_deref() == Some("email")));
    }

    #[test]
    fn extra_fields_respects_max_fields_limit() {
        let config = SchemaDriftConfig {
            max_fields_per_test: 5,
            ..SchemaDriftConfig::default()
        };
        let mut detector = ApiSchemaDriftDetector::new(config);

        let findings = detector.test_extra_fields("/api/users", &[]);
        assert_eq!(findings.len(), 5);
    }

    #[test]
    fn missing_required_detects_omitted_fields() {
        let config = SchemaDriftConfig::default();
        let mut detector = ApiSchemaDriftDetector::new(config);
        let fields = sample_fields();

        let findings = detector.test_missing_required("/api/users", &fields);

        let required_count = fields.iter().filter(|f| f.required).count();
        assert_eq!(findings.len(), required_count);
        assert!(findings
            .iter()
            .all(|f| f.drift_type == DriftType::MissingFieldAccepted));
        assert!(findings
            .iter()
            .any(|f| f.field_name.as_deref() == Some("username")));
        assert!(findings
            .iter()
            .any(|f| f.field_name.as_deref() == Some("email")));
        assert!(!findings
            .iter()
            .any(|f| f.field_name.as_deref() == Some("age")));
    }

    #[test]
    fn wrong_types_generates_coercion_findings() {
        let config = SchemaDriftConfig::default();
        let mut detector = ApiSchemaDriftDetector::new(config);

        let string_field = vec![FieldSpec {
            name: "name".to_string(),
            field_type: "string".to_string(),
            required: true,
            validation_regex: None,
        }];

        let findings = detector.test_wrong_types("/api/users", &string_field);

        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .all(|f| f.drift_type == DriftType::WrongTypeAccepted));

        let object_coercion = findings.iter().find(|f| {
            f.actual
                .as_ref()
                .map(|a| a.contains("object"))
                .unwrap_or(false)
        });
        assert!(object_coercion.is_some());
        assert!(object_coercion.unwrap().is_exploitable);
        assert_eq!(object_coercion.unwrap().severity, DriftSeverity::High);
    }

    #[test]
    fn wrong_types_integer_overflow_is_high_severity() {
        let config = SchemaDriftConfig::default();
        let mut detector = ApiSchemaDriftDetector::new(config);

        let int_field = vec![FieldSpec {
            name: "count".to_string(),
            field_type: "integer".to_string(),
            required: true,
            validation_regex: None,
        }];

        let findings = detector.test_wrong_types("/api/data", &int_field);

        let overflow = findings.iter().find(|f| {
            f.actual
                .as_ref()
                .map(|a| a.contains("negative_overflow"))
                .unwrap_or(false)
        });
        assert!(overflow.is_some());
        assert_eq!(overflow.unwrap().severity, DriftSeverity::High);
    }

    #[test]
    fn brute_force_finds_undocumented_endpoints() {
        let config = SchemaDriftConfig::default();
        let mut detector = ApiSchemaDriftDetector::new(config);

        let known = vec!["/api/users".to_string(), "/healthz".to_string()];
        let findings = detector.brute_force_undocumented(&known);

        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .all(|f| f.drift_type == DriftType::UndocumentedEndpoint));
        assert!(!findings.iter().any(|f| f.endpoint == "/healthz"));

        let admin_finding = findings.iter().find(|f| f.endpoint == "/admin");
        assert!(admin_finding.is_some());
        assert_eq!(admin_finding.unwrap().severity, DriftSeverity::Critical);
        assert!(admin_finding.unwrap().is_exploitable);
    }

    #[test]
    fn version_comparison_detects_auth_downgrade() {
        let config = SchemaDriftConfig::default();
        let detector = ApiSchemaDriftDetector::new(config);
        let old = v1_schema();
        let new = v2_schema_with_regressions();

        let comparison = detector.compare_versions(&old, &new);

        let auth_regressions: Vec<&DriftFinding> = comparison
            .regressions
            .iter()
            .filter(|f| f.drift_type == DriftType::AuthDowngrade)
            .collect();
        assert!(!auth_regressions.is_empty());

        let users_auth = auth_regressions.iter().find(|f| f.endpoint == "/api/users");
        assert!(users_auth.is_some());
        assert_eq!(users_auth.unwrap().severity, DriftSeverity::Critical);
        assert!(users_auth.unwrap().is_exploitable);
    }

    #[test]
    fn version_comparison_detects_rate_limit_removal() {
        let config = SchemaDriftConfig::default();
        let detector = ApiSchemaDriftDetector::new(config);
        let old = v1_schema();
        let new = v2_schema_with_regressions();

        let comparison = detector.compare_versions(&old, &new);

        let rate_regressions: Vec<&DriftFinding> = comparison
            .regressions
            .iter()
            .filter(|f| f.drift_type == DriftType::RateLimitRemoved)
            .collect();
        assert!(rate_regressions.len() >= 2);
    }

    #[test]
    fn version_comparison_detects_validation_removal() {
        let config = SchemaDriftConfig::default();
        let detector = ApiSchemaDriftDetector::new(config);
        let old = v1_schema();
        let new = v2_schema_with_regressions();

        let comparison = detector.compare_versions(&old, &new);

        let schema_violations: Vec<&DriftFinding> = comparison
            .regressions
            .iter()
            .filter(|f| f.drift_type == DriftType::SchemaViolation)
            .collect();
        assert!(!schema_violations.is_empty());

        let username_regression = schema_violations
            .iter()
            .find(|f| f.field_name.as_deref() == Some("username"));
        assert!(username_regression.is_some());
        assert_eq!(username_regression.unwrap().severity, DriftSeverity::High);
    }

    #[test]
    fn version_comparison_detects_improvements() {
        let config = SchemaDriftConfig::default();
        let detector = ApiSchemaDriftDetector::new(config);
        let old = v1_schema();
        let new = v2_schema_improved();

        let comparison = detector.compare_versions(&old, &new);

        assert!(!comparison.improvements.is_empty());
        assert!(comparison
            .improvements
            .iter()
            .any(|i| i.contains("Validation added") && i.contains("age")));
        assert!(comparison
            .improvements
            .iter()
            .any(|i| i.contains("Rate limiting added") && i.contains("/api/admin")));
    }

    #[test]
    fn mass_assignment_payloads_contain_injected_fields() {
        let config = SchemaDriftConfig::default();
        let detector = ApiSchemaDriftDetector::new(config);
        let fields = sample_fields();

        let payloads = detector.generate_mass_assignment_payloads(&fields);

        assert!(!payloads.is_empty());

        for payload in &payloads {
            let obj = payload.as_object().unwrap();
            assert!(obj.contains_key("username"));
            assert!(obj.contains_key("email"));

            let extra_keys: Vec<&String> = obj
                .keys()
                .filter(|k| !["username", "email", "age"].contains(&k.as_str()))
                .collect();
            assert_eq!(extra_keys.len(), 1);
        }
    }

    #[test]
    fn analyze_drift_combines_version_comparisons() {
        let config = SchemaDriftConfig {
            compare_versions: true,
            brute_force_paths: false,
            ..SchemaDriftConfig::default()
        };
        let mut detector = ApiSchemaDriftDetector::new(config);
        detector.add_schema(v1_schema());
        detector.add_schema(v2_schema_with_regressions());

        let findings = detector.analyze_drift();

        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.drift_type == DriftType::AuthDowngrade));
        assert!(findings
            .iter()
            .any(|f| f.drift_type == DriftType::RateLimitRemoved));

        let severities: Vec<DriftSeverity> = findings.iter().map(|f| f.severity).collect();
        for pair in severities.windows(2) {
            assert!(pair[0] >= pair[1]);
        }
    }

    #[test]
    fn analyze_drift_includes_brute_force_when_enabled() {
        let config = SchemaDriftConfig {
            compare_versions: false,
            brute_force_paths: true,
            ..SchemaDriftConfig::default()
        };
        let mut detector = ApiSchemaDriftDetector::new(config);
        detector.add_schema(v1_schema());

        let findings = detector.analyze_drift();

        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .all(|f| f.drift_type == DriftType::UndocumentedEndpoint));
    }

    #[test]
    fn generate_report_tallies_severities() {
        let config = SchemaDriftConfig::default();
        let mut detector = ApiSchemaDriftDetector::new(config);

        detector.test_extra_fields("/api/users", &sample_fields());
        detector.test_missing_required("/api/users", &sample_fields());

        let report = detector.generate_report("https://target.example.com");

        assert_eq!(
            report.total_findings,
            report.critical_count
                + report.high_count
                + report.medium_count
                + report.low_count
                + report.info_count
        );
        assert!(report.critical_count > 0);
        assert!(report.exploitable_count > 0);
        assert_eq!(report.target_url, "https://target.example.com");
    }

    #[test]
    fn severity_ordering_is_correct() {
        assert!(DriftSeverity::Critical > DriftSeverity::High);
        assert!(DriftSeverity::High > DriftSeverity::Medium);
        assert!(DriftSeverity::Medium > DriftSeverity::Low);
        assert!(DriftSeverity::Low > DriftSeverity::Info);
    }

    #[test]
    fn drift_type_display_roundtrips() {
        let types = vec![
            (DriftType::ExtraFieldAccepted, "extra_field_accepted"),
            (DriftType::MissingFieldAccepted, "missing_field_accepted"),
            (DriftType::WrongTypeAccepted, "wrong_type_accepted"),
            (DriftType::UndocumentedEndpoint, "undocumented_endpoint"),
            (DriftType::VersionRegression, "version_regression"),
            (DriftType::SchemaViolation, "schema_violation"),
            (DriftType::AuthDowngrade, "auth_downgrade"),
            (DriftType::RateLimitRemoved, "rate_limit_removed"),
        ];

        for (variant, expected_str) in types {
            assert_eq!(variant.to_string(), expected_str);
        }
    }

    #[test]
    fn default_config_enables_all_tests() {
        let config = SchemaDriftConfig::default();

        assert!(config.test_extra_fields);
        assert!(config.test_missing_fields);
        assert!(config.test_wrong_types);
        assert!(config.brute_force_paths);
        assert!(config.compare_versions);
        assert_eq!(config.max_fields_per_test, 50);
    }

    #[test]
    fn empty_schema_comparison_produces_no_regressions() {
        let config = SchemaDriftConfig::default();
        let detector = ApiSchemaDriftDetector::new(config);

        let empty_v1 = SchemaVersion {
            version: "v1".to_string(),
            endpoints: vec![],
            fields_per_endpoint: HashMap::new(),
            auth_requirements: HashMap::new(),
            rate_limited_endpoints: HashSet::new(),
        };

        let empty_v2 = SchemaVersion {
            version: "v2".to_string(),
            endpoints: vec![],
            fields_per_endpoint: HashMap::new(),
            auth_requirements: HashMap::new(),
            rate_limited_endpoints: HashSet::new(),
        };

        let comparison = detector.compare_versions(&empty_v1, &empty_v2);
        assert!(comparison.regressions.is_empty());
        assert!(comparison.improvements.is_empty());
        assert!(comparison.drift_findings.is_empty());
    }

    #[test]
    fn clear_findings_resets_state() {
        let config = SchemaDriftConfig::default();
        let mut detector = ApiSchemaDriftDetector::new(config);

        detector.test_extra_fields("/api/users", &sample_fields());
        assert!(!detector.findings().is_empty());

        detector.clear_findings();
        assert!(detector.findings().is_empty());
    }

    #[test]
    fn mass_assignment_severity_classification() {
        let config = SchemaDriftConfig::default();
        let mut detector = ApiSchemaDriftDetector::new(config);

        let findings = detector.test_extra_fields("/api/users", &[]);

        let find_severity = |name: &str| -> Option<DriftSeverity> {
            findings
                .iter()
                .find(|f| f.field_name.as_deref() == Some(name))
                .map(|f| f.severity)
        };

        assert_eq!(find_severity("isAdmin"), Some(DriftSeverity::Critical));
        assert_eq!(find_severity("is_admin"), Some(DriftSeverity::Critical));
        assert_eq!(find_severity("password"), Some(DriftSeverity::Critical));
        assert_eq!(find_severity("role"), Some(DriftSeverity::High));
        assert_eq!(find_severity("permissions"), Some(DriftSeverity::High));
        assert_eq!(find_severity("balance"), Some(DriftSeverity::Medium));
        assert_eq!(find_severity("verified"), Some(DriftSeverity::Medium));
    }
}
