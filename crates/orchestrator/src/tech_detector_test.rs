use crate::tech_detector::*;

// ============================================================
// Existing 9 tests (unchanged)
// ============================================================

#[test]
fn detect_technologies_skips_localhost() {
    let result = detect_technologies("http://localhost:8080");
    assert!(result.is_empty());
}

#[test]
fn detect_technologies_skips_loopback() {
    let result = detect_technologies("http://127.0.0.1");
    assert!(result.is_empty());
}

#[test]
fn tech_to_operations_creates_service_nodes() {
    let detections = vec![
        TechDetection {
            name: "nginx".to_string(),
            version: Some("1.24.0".to_string()),
            category: "Web Server".to_string(),
            confidence: 0.95,
            evidence: "Server: nginx/1.24.0".to_string(),
        },
        TechDetection {
            name: "WordPress".to_string(),
            version: Some("6.4".to_string()),
            category: "CMS".to_string(),
            confidence: 0.85,
            evidence: "wp-content/ found in HTML".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = tech_to_operations(&detections, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);

    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddNode {
            node_type,
            properties,
        } => {
            assert_eq!(*node_type, aegis_protocol::node::NodeType::Service);
            let name = properties.iter().find(|(k, _)| k == "name").unwrap();
            assert_eq!(name.1, "nginx");
            let version = properties.iter().find(|(k, _)| k == "version").unwrap();
            assert_eq!(version.1, "1.24.0");
            let source = properties.iter().find(|(k, _)| k == "source").unwrap();
            assert_eq!(source.1, "tech_detect");
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn tech_to_operations_omits_version_when_none() {
    let detections = vec![TechDetection {
        name: "React".to_string(),
        version: None,
        category: "JavaScript".to_string(),
        confidence: 0.8,
        evidence: "react.production.min.js".to_string(),
    }];
    let mut seq = 0;
    let ops = tech_to_operations(&detections, &mut seq);
    assert_eq!(ops.len(), 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddNode { properties, .. } => {
            assert!(properties.iter().all(|(k, _)| k != "version"));
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn dedup_detections_removes_duplicates() {
    let detections = vec![
        TechDetection {
            name: "WordPress".to_string(),
            version: Some("6.4".to_string()),
            category: "CMS".to_string(),
            confidence: 0.85,
            evidence: "wp-content/ in HTML".to_string(),
        },
        TechDetection {
            name: "WordPress".to_string(),
            version: Some("6.4".to_string()),
            category: "CMS".to_string(),
            confidence: 0.85,
            evidence: "wp-includes/ in HTML".to_string(),
        },
        TechDetection {
            name: "nginx".to_string(),
            version: None,
            category: "Web Server".to_string(),
            confidence: 0.9,
            evidence: "Server: nginx".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = tech_to_operations(&detections, &mut seq);
    // Both WordPress entries create separate ops (dedup is in detect_technologies)
    assert_eq!(ops.len(), 3);
}

#[test]
fn detect_from_parts_finds_server_header() {
    let headers = vec![("server".to_string(), "nginx/1.24.0".to_string())];
    let body = "";
    let results = detect_from_parts(&headers, body);
    assert!(
        results.iter().any(|d| d.name.contains("nginx")),
        "should detect nginx from server header, got: {results:?}"
    );
}

#[test]
fn detect_from_parts_finds_html_patterns() {
    let headers = vec![];
    let body = r#"<html><head><script src="/wp-includes/js/jquery.js"></script></head></html>"#;
    let results = detect_from_parts(&headers, body);
    assert!(
        results.iter().any(|d| d.name == "WordPress"),
        "should detect WordPress from HTML, got: {results:?}"
    );
}

#[test]
fn detect_from_parts_empty_inputs() {
    let results = detect_from_parts(&[], "");
    assert!(results.is_empty());
}

#[test]
fn detect_from_parts_deduplicates() {
    let headers = vec![("x-powered-by".to_string(), "Express".to_string())];
    let body = r#"<html><head><meta name="generator" content="Express"></head></html>"#;
    let results = detect_from_parts(&headers, body);
    let express_count = results.iter().filter(|d| d.name == "Express").count();
    assert!(express_count <= 1, "should deduplicate Express detections");
}

// ============================================================
// TechIssue Display tests
// ============================================================

#[test]
fn display_outdated_version() {
    let issue = TechIssue::OutdatedVersion {
        name: "nginx".to_string(),
        version: "1.18.0".to_string(),
        category: "Web Server".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "Outdated Web Server nginx version 1.18.0"
    );
}

#[test]
fn display_end_of_life() {
    let issue = TechIssue::EndOfLife {
        name: "PHP".to_string(),
        version: "5.6.40".to_string(),
    };
    assert_eq!(issue.to_string(), "PHP 5.6.40 has reached end of life");
}

#[test]
fn display_known_vulnerable() {
    let issue = TechIssue::KnownVulnerable {
        name: "Apache".to_string(),
        version: "2.4.49".to_string(),
    };
    assert_eq!(issue.to_string(), "Apache 2.4.49 has known vulnerabilities");
}

#[test]
fn display_default_config() {
    let issue = TechIssue::DefaultConfig {
        name: "nginx".to_string(),
        evidence: "Welcome to nginx".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "Default configuration detected for nginx: Welcome to nginx"
    );
}

#[test]
fn display_debug_mode() {
    let issue = TechIssue::DebugMode {
        name: "Django".to_string(),
        evidence: "Django Debug toolbar".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "Debug mode enabled for Django: Django Debug toolbar"
    );
}

#[test]
fn display_mixed_tech_stack() {
    let issue = TechIssue::MixedTechStack {
        technologies: vec!["nginx".to_string(), "Apache".to_string()],
    };
    assert_eq!(
        issue.to_string(),
        "Conflicting technologies detected: nginx, Apache"
    );
}

#[test]
fn display_version_exposed() {
    let issue = TechIssue::VersionExposed {
        name: "OpenSSL".to_string(),
        version: "3.1.2".to_string(),
    };
    assert_eq!(issue.to_string(), "Exact version exposed: OpenSSL/3.1.2");
}

#[test]
fn display_legacy_protocol() {
    let issue = TechIssue::LegacyProtocol {
        name: "Flash".to_string(),
        evidence: "SWF object detected".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "Legacy technology Flash detected: SWF object detected"
    );
}

// ============================================================
// Severity tests
// ============================================================

#[test]
fn severity_known_vulnerable_is_highest() {
    let issue = TechIssue::KnownVulnerable {
        name: "a".to_string(),
        version: "1".to_string(),
    };
    assert!((tech_issue_severity(&issue) - 8.0).abs() < f64::EPSILON);
}

#[test]
fn severity_end_of_life() {
    let issue = TechIssue::EndOfLife {
        name: "a".to_string(),
        version: "1".to_string(),
    };
    assert!((tech_issue_severity(&issue) - 7.0).abs() < f64::EPSILON);
}

#[test]
fn severity_debug_mode() {
    let issue = TechIssue::DebugMode {
        name: "a".to_string(),
        evidence: "x".to_string(),
    };
    assert!((tech_issue_severity(&issue) - 6.0).abs() < f64::EPSILON);
}

#[test]
fn severity_default_config() {
    let issue = TechIssue::DefaultConfig {
        name: "a".to_string(),
        evidence: "x".to_string(),
    };
    assert!((tech_issue_severity(&issue) - 5.0).abs() < f64::EPSILON);
}

#[test]
fn severity_outdated_version() {
    let issue = TechIssue::OutdatedVersion {
        name: "a".to_string(),
        version: "1".to_string(),
        category: "c".to_string(),
    };
    assert!((tech_issue_severity(&issue) - 4.0).abs() < f64::EPSILON);
}

#[test]
fn severity_legacy_protocol() {
    let issue = TechIssue::LegacyProtocol {
        name: "a".to_string(),
        evidence: "x".to_string(),
    };
    assert!((tech_issue_severity(&issue) - 4.0).abs() < f64::EPSILON);
}

#[test]
fn severity_mixed_tech_stack() {
    let issue = TechIssue::MixedTechStack {
        technologies: vec!["a".to_string()],
    };
    assert!((tech_issue_severity(&issue) - 3.0).abs() < f64::EPSILON);
}

#[test]
fn severity_version_exposed() {
    let issue = TechIssue::VersionExposed {
        name: "a".to_string(),
        version: "1".to_string(),
    };
    assert!((tech_issue_severity(&issue) - 3.0).abs() < f64::EPSILON);
}

#[test]
fn severity_ordering_known_vulnerable_gt_eol() {
    let kv = TechIssue::KnownVulnerable {
        name: "a".to_string(),
        version: "1".to_string(),
    };
    let eol = TechIssue::EndOfLife {
        name: "a".to_string(),
        version: "1".to_string(),
    };
    assert!(tech_issue_severity(&kv) > tech_issue_severity(&eol));
}

// ============================================================
// analyze_tech_stack tests
// ============================================================

#[test]
fn analyze_detects_version_exposed() {
    let detections = vec![TechDetection {
        name: "Tomcat".to_string(),
        version: Some("9.0.65".to_string()),
        category: "Application Server".to_string(),
        confidence: 0.9,
        evidence: "Server: Apache-Coyote".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(issues.iter().any(|i| matches!(i, TechIssue::VersionExposed { name, version } if name == "Tomcat" && version == "9.0.65")));
}

#[test]
fn analyze_detects_known_vulnerable_apache() {
    let detections = vec![TechDetection {
        name: "Apache".to_string(),
        version: Some("2.4.49".to_string()),
        category: "Web Server".to_string(),
        confidence: 0.95,
        evidence: "Server: Apache/2.4.49".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TechIssue::KnownVulnerable { name, .. } if name == "Apache"))
    );
}

#[test]
fn analyze_detects_known_vulnerable_openssl() {
    let detections = vec![TechDetection {
        name: "OpenSSL".to_string(),
        version: Some("3.0.0".to_string()),
        category: "Crypto Library".to_string(),
        confidence: 0.9,
        evidence: "openssl/3.0.0".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TechIssue::KnownVulnerable { name, .. } if name == "OpenSSL"))
    );
}

#[test]
fn analyze_detects_eol_php5() {
    let detections = vec![TechDetection {
        name: "PHP".to_string(),
        version: Some("5.6.40".to_string()),
        category: "Language".to_string(),
        confidence: 0.9,
        evidence: "X-Powered-By: PHP/5.6.40".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TechIssue::EndOfLife { name, .. } if name == "PHP"))
    );
}

#[test]
fn analyze_detects_eol_python2() {
    let detections = vec![TechDetection {
        name: "Python".to_string(),
        version: Some("2.7.18".to_string()),
        category: "Language".to_string(),
        confidence: 0.8,
        evidence: "Server: Python/2.7.18".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TechIssue::EndOfLife { name, .. } if name == "Python"))
    );
}

#[test]
fn analyze_detects_eol_node14() {
    let detections = vec![TechDetection {
        name: "Node.js".to_string(),
        version: Some("14.21.3".to_string()),
        category: "Runtime".to_string(),
        confidence: 0.85,
        evidence: "X-Powered-By: Node.js".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TechIssue::EndOfLife { name, .. } if name == "Node.js"))
    );
}

#[test]
fn analyze_detects_outdated_nginx() {
    let detections = vec![TechDetection {
        name: "nginx".to_string(),
        version: Some("1.18.0".to_string()),
        category: "Web Server".to_string(),
        confidence: 0.95,
        evidence: "Server: nginx/1.18.0".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TechIssue::OutdatedVersion { name, .. } if name == "nginx"))
    );
}

#[test]
fn analyze_no_outdated_for_current_version() {
    let detections = vec![TechDetection {
        name: "nginx".to_string(),
        version: Some("1.25.3".to_string()),
        category: "Web Server".to_string(),
        confidence: 0.95,
        evidence: "Server: nginx/1.25.3".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, TechIssue::OutdatedVersion { .. }))
    );
}

#[test]
fn analyze_detects_debug_mode_werkzeug() {
    let detections = vec![TechDetection {
        name: "Flask".to_string(),
        version: None,
        category: "Framework".to_string(),
        confidence: 0.8,
        evidence: "Werkzeug Debugger".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TechIssue::DebugMode { name, .. } if name == "Flask"))
    );
}

#[test]
fn analyze_detects_debug_mode_xdebug() {
    let detections = vec![TechDetection {
        name: "PHP".to_string(),
        version: None,
        category: "Language".to_string(),
        confidence: 0.7,
        evidence: "XDEBUG_SESSION cookie set".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TechIssue::DebugMode { .. }))
    );
}

#[test]
fn analyze_detects_default_config_nginx() {
    let detections = vec![TechDetection {
        name: "nginx".to_string(),
        version: None,
        category: "Web Server".to_string(),
        confidence: 0.9,
        evidence: "Welcome to nginx default page".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TechIssue::DefaultConfig { name, .. } if name == "nginx"))
    );
}

#[test]
fn analyze_detects_default_config_apache() {
    let detections = vec![TechDetection {
        name: "Apache".to_string(),
        version: None,
        category: "Web Server".to_string(),
        confidence: 0.9,
        evidence: "Apache2 Ubuntu Default Page found".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TechIssue::DefaultConfig { name, .. } if name == "Apache"))
    );
}

#[test]
fn analyze_detects_default_config_phpinfo() {
    let detections = vec![TechDetection {
        name: "PHP".to_string(),
        version: None,
        category: "Language".to_string(),
        confidence: 0.85,
        evidence: "phpinfo() output detected".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TechIssue::DefaultConfig { .. }))
    );
}

#[test]
fn analyze_detects_legacy_flash() {
    let detections = vec![TechDetection {
        name: "Flash".to_string(),
        version: None,
        category: "Plugin".to_string(),
        confidence: 0.7,
        evidence: "SWF embed tag".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TechIssue::LegacyProtocol { name, .. } if name == "Flash"))
    );
}

#[test]
fn analyze_detects_legacy_silverlight() {
    let detections = vec![TechDetection {
        name: "Silverlight".to_string(),
        version: None,
        category: "Plugin".to_string(),
        confidence: 0.6,
        evidence: "Silverlight.js detected".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TechIssue::LegacyProtocol { name, .. } if name == "Silverlight"))
    );
}

#[test]
fn analyze_detects_legacy_coldfusion() {
    let detections = vec![TechDetection {
        name: "ColdFusion".to_string(),
        version: None,
        category: "Framework".to_string(),
        confidence: 0.75,
        evidence: "cfm extension".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TechIssue::LegacyProtocol { .. }))
    );
}

#[test]
fn analyze_detects_mixed_web_servers() {
    let detections = vec![
        TechDetection {
            name: "nginx".to_string(),
            version: Some("1.25.0".to_string()),
            category: "Web Server".to_string(),
            confidence: 0.9,
            evidence: "Server: nginx".to_string(),
        },
        TechDetection {
            name: "Apache".to_string(),
            version: Some("2.4.58".to_string()),
            category: "Web Server".to_string(),
            confidence: 0.8,
            evidence: "Via: Apache".to_string(),
        },
    ];
    let issues = analyze_tech_stack(&detections);
    let mixed = issues
        .iter()
        .find(|i| matches!(i, TechIssue::MixedTechStack { .. }));
    assert!(mixed.is_some());
    if let Some(TechIssue::MixedTechStack { technologies }) = mixed {
        assert_eq!(technologies.len(), 2);
        assert!(technologies.contains(&"nginx".to_string()));
        assert!(technologies.contains(&"Apache".to_string()));
    }
}

#[test]
fn analyze_no_mixed_for_single_web_server() {
    let detections = vec![TechDetection {
        name: "nginx".to_string(),
        version: None,
        category: "Web Server".to_string(),
        confidence: 0.9,
        evidence: "Server: nginx".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, TechIssue::MixedTechStack { .. }))
    );
}

#[test]
fn analyze_empty_detections() {
    let issues = analyze_tech_stack(&[]);
    assert!(issues.is_empty());
}

#[test]
fn analyze_no_version_skips_version_checks() {
    let detections = vec![TechDetection {
        name: "React".to_string(),
        version: None,
        category: "JavaScript".to_string(),
        confidence: 0.8,
        evidence: "react.production.min.js".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(!issues.iter().any(|i| matches!(
        i,
        TechIssue::VersionExposed { .. }
            | TechIssue::KnownVulnerable { .. }
            | TechIssue::EndOfLife { .. }
            | TechIssue::OutdatedVersion { .. }
    )));
}

#[test]
fn analyze_multiple_issues_for_single_detection() {
    // PHP 5.6.40 should trigger: VersionExposed + EndOfLife + Outdated
    let detections = vec![TechDetection {
        name: "PHP".to_string(),
        version: Some("5.6.40".to_string()),
        category: "Language".to_string(),
        confidence: 0.9,
        evidence: "X-Powered-By: PHP/5.6.40".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TechIssue::VersionExposed { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TechIssue::EndOfLife { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TechIssue::OutdatedVersion { .. }))
    );
}

#[test]
fn analyze_eol_jquery1() {
    let detections = vec![TechDetection {
        name: "jQuery".to_string(),
        version: Some("1.12.4".to_string()),
        category: "JavaScript".to_string(),
        confidence: 0.85,
        evidence: "jquery-1.12.4.min.js".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TechIssue::EndOfLife { name, .. } if name == "jQuery"))
    );
}

#[test]
fn analyze_known_vulnerable_jquery() {
    let detections = vec![TechDetection {
        name: "jQuery".to_string(),
        version: Some("1.6.2".to_string()),
        category: "JavaScript".to_string(),
        confidence: 0.85,
        evidence: "jquery-1.6.2.js".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TechIssue::KnownVulnerable { name, .. } if name == "jQuery"))
    );
}

#[test]
fn analyze_outdated_wordpress() {
    let detections = vec![TechDetection {
        name: "WordPress".to_string(),
        version: Some("5.9.0".to_string()),
        category: "CMS".to_string(),
        confidence: 0.9,
        evidence: "wp-content found".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TechIssue::OutdatedVersion { name, .. } if name == "WordPress"))
    );
}

// ============================================================
// tech_issues_to_operations tests
// ============================================================

#[test]
fn issues_to_operations_creates_add_finding() {
    let issues = vec![TechIssue::KnownVulnerable {
        name: "Apache".to_string(),
        version: "2.4.49".to_string(),
    }];
    let mut seq = 0;
    let ops = tech_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            severity,
            confidence,
            vulnerability_class,
            ..
        } => {
            assert!((severity - 8.0).abs() < f64::EPSILON);
            assert!((confidence.value() - 0.5).abs() < f64::EPSILON);
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::InformationDisclosure
            );
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn issues_to_operations_empty_input() {
    let mut seq = 5;
    let ops = tech_issues_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn issues_to_operations_multiple_issues() {
    let issues = vec![
        TechIssue::VersionExposed {
            name: "nginx".to_string(),
            version: "1.24.0".to_string(),
        },
        TechIssue::OutdatedVersion {
            name: "nginx".to_string(),
            version: "1.18.0".to_string(),
            category: "Web Server".to_string(),
        },
        TechIssue::DebugMode {
            name: "Flask".to_string(),
            evidence: "Werkzeug".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = tech_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn issues_to_operations_severity_matches_issue() {
    let issues = vec![
        TechIssue::KnownVulnerable {
            name: "a".to_string(),
            version: "1".to_string(),
        },
        TechIssue::VersionExposed {
            name: "b".to_string(),
            version: "2".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = tech_issues_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 8.0).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
    match &ops[1].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 3.0).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn issues_to_operations_seq_continues() {
    let issues = vec![TechIssue::EndOfLife {
        name: "PHP".to_string(),
        version: "5.6".to_string(),
    }];
    let mut seq = 10;
    let ops = tech_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops[0].sequence_number, 11);
    assert_eq!(seq, 11);
}

#[test]
fn issues_to_operations_confidence_always_half() {
    let issues = vec![
        TechIssue::LegacyProtocol {
            name: "Flash".to_string(),
            evidence: "swf".to_string(),
        },
        TechIssue::MixedTechStack {
            technologies: vec!["a".to_string(), "b".to_string()],
        },
        TechIssue::DefaultConfig {
            name: "nginx".to_string(),
            evidence: "Welcome to nginx".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = tech_issues_to_operations(&issues, &mut seq);
    for op in &ops {
        match &op.operation {
            aegis_protocol::operation::GraphOperation::AddFinding { confidence, .. } => {
                assert!(
                    (confidence.value() - 0.5).abs() < f64::EPSILON,
                    "confidence should be 0.5"
                );
            }
            _ => panic!("expected AddFinding"),
        }
    }
}

// ============================================================
// version_less_than (tested indirectly via analyze_tech_stack)
// ============================================================

#[test]
fn outdated_equal_version_not_flagged() {
    // nginx 1.24 is the threshold; 1.24.0 should NOT be outdated
    let detections = vec![TechDetection {
        name: "nginx".to_string(),
        version: Some("1.24.0".to_string()),
        category: "Web Server".to_string(),
        confidence: 0.95,
        evidence: "Server: nginx/1.24.0".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, TechIssue::OutdatedVersion { .. }))
    );
}

#[test]
fn outdated_higher_version_not_flagged() {
    let detections = vec![TechDetection {
        name: "jQuery".to_string(),
        version: Some("3.7.1".to_string()),
        category: "JavaScript".to_string(),
        confidence: 0.85,
        evidence: "jquery-3.7.1.min.js".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, TechIssue::OutdatedVersion { .. }))
    );
}

// ============================================================
// Integration: full pipeline (detect -> analyze -> operations)
// ============================================================

#[test]
fn full_pipeline_eol_php_produces_finding() {
    let detections = vec![TechDetection {
        name: "PHP".to_string(),
        version: Some("7.4.33".to_string()),
        category: "Language".to_string(),
        confidence: 0.9,
        evidence: "X-Powered-By: PHP/7.4.33".to_string(),
    }];
    let issues = analyze_tech_stack(&detections);
    assert!(!issues.is_empty());
    let mut seq = 0;
    let ops = tech_issues_to_operations(&issues, &mut seq);
    assert!(!ops.is_empty());
    assert!(seq > 0);
}

#[test]
fn tech_issue_equality() {
    let a = TechIssue::VersionExposed {
        name: "nginx".to_string(),
        version: "1.24.0".to_string(),
    };
    let b = TechIssue::VersionExposed {
        name: "nginx".to_string(),
        version: "1.24.0".to_string(),
    };
    assert_eq!(a, b);
}

#[test]
fn tech_issue_inequality() {
    let a = TechIssue::VersionExposed {
        name: "nginx".to_string(),
        version: "1.24.0".to_string(),
    };
    let b = TechIssue::VersionExposed {
        name: "Apache".to_string(),
        version: "2.4.58".to_string(),
    };
    assert_ne!(a, b);
}

#[test]
fn tech_issue_clone() {
    let original = TechIssue::MixedTechStack {
        technologies: vec!["nginx".to_string(), "Apache".to_string()],
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn tech_issue_debug_format() {
    let issue = TechIssue::EndOfLife {
        name: "PHP".to_string(),
        version: "5.6".to_string(),
    };
    let debug = format!("{issue:?}");
    assert!(debug.contains("EndOfLife"));
    assert!(debug.contains("PHP"));
}
