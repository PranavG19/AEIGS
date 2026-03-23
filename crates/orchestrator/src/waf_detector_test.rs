use crate::waf_detector::*;

// === Existing tests (8) ===

#[test]
fn waf_to_operations_creates_defense_nodes() {
    let detections = vec![
        WafDetection {
            waf_name: "cloudflare".to_string(),
            evidence: "header: cf-ray".to_string(),
        },
        WafDetection {
            waf_name: "nginx".to_string(),
            evidence: "server: nginx/1.24".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = waf_to_operations(&detections, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
    for op in &ops {
        match &op.operation {
            aegis_protocol::operation::GraphOperation::AddNode {
                node_type,
                properties,
            } => {
                assert_eq!(*node_type, aegis_protocol::node::NodeType::Defense);
                let source = properties.iter().find(|(k, _)| k == "source").unwrap();
                assert_eq!(source.1, "waf_detect");
            }
            _ => panic!("expected AddNode"),
        }
    }
}

#[test]
fn waf_to_operations_empty() {
    let mut seq = 5;
    let ops = waf_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn waf_to_operations_preserves_waf_name() {
    let detections = vec![WafDetection {
        waf_name: "cloudflare".to_string(),
        evidence: "header: cf-ray".to_string(),
    }];
    let mut seq = 0;
    let ops = waf_to_operations(&detections, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddNode { properties, .. } => {
            let waf = properties.iter().find(|(k, _)| k == "waf_name").unwrap();
            assert_eq!(waf.1, "cloudflare");
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn detect_waf_skips_localhost() {
    let detections = detect_waf("http://localhost:8080");
    assert!(detections.is_empty());
}

#[test]
fn detect_waf_skips_invalid() {
    let detections = detect_waf("not-a-url");
    assert!(detections.is_empty());
}

#[test]
fn waf_to_operations_preserves_evidence() {
    let detections = vec![WafDetection {
        waf_name: "sucuri".to_string(),
        evidence: "header: x-sucuri-id".to_string(),
    }];
    let mut seq = 0;
    let ops = waf_to_operations(&detections, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddNode { properties, .. } => {
            let evidence = properties.iter().find(|(k, _)| k == "evidence").unwrap();
            assert_eq!(evidence.1, "header: x-sucuri-id");
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn waf_to_operations_multiple_increments_sequence() {
    let detections = vec![
        WafDetection {
            waf_name: "cloudflare".to_string(),
            evidence: "header: cf-ray".to_string(),
        },
        WafDetection {
            waf_name: "akamai".to_string(),
            evidence: "header: x-akamai-transformed".to_string(),
        },
        WafDetection {
            waf_name: "nginx".to_string(),
            evidence: "server: nginx".to_string(),
        },
    ];
    let mut seq = 10;
    let ops = waf_to_operations(&detections, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 13);
    assert_eq!(ops[0].sequence_number, 11);
    assert_eq!(ops[1].sequence_number, 12);
    assert_eq!(ops[2].sequence_number, 13);
}

#[test]
fn detect_waf_skips_loopback() {
    let detections = detect_waf("http://127.0.0.1");
    assert!(detections.is_empty());
}

// === WafIssue Display tests ===

#[test]
fn display_waf_detected() {
    let issue = WafIssue::WafDetected {
        name: "cloudflare".to_string(),
        evidence: "header: cf-ray".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "WAF detected: cloudflare (evidence: header: cf-ray)"
    );
}

#[test]
fn display_waf_bypass_possible() {
    let issue = WafIssue::WafBypassPossible {
        name: "aws-waf".to_string(),
        technique: "payload chunking".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "WAF bypass possible for aws-waf: payload chunking"
    );
}

#[test]
fn display_no_waf_detected() {
    let issue = WafIssue::NoWafDetected;
    assert_eq!(issue.to_string(), "No WAF protection detected");
}

#[test]
fn display_multiple_wafs() {
    let issue = WafIssue::MultipleWafs {
        names: vec!["cloudflare".to_string(), "aws-waf".to_string()],
    };
    assert_eq!(
        issue.to_string(),
        "Multiple WAFs detected: cloudflare, aws-waf"
    );
}

#[test]
fn display_outdated_waf() {
    let issue = WafIssue::OutdatedWaf {
        name: "nginx".to_string(),
        evidence: "nginx/1.0.15".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "Outdated WAF: nginx (evidence: nginx/1.0.15)"
    );
}

#[test]
fn display_waf_in_learning_mode() {
    let issue = WafIssue::WafInLearningMode {
        name: "modsecurity".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "WAF in learning/detection-only mode: modsecurity"
    );
}

#[test]
fn display_cdn_without_waf() {
    let issue = WafIssue::CdnWithoutWaf {
        cdn: "fastly".to_string(),
    };
    assert_eq!(issue.to_string(), "CDN without WAF rules: fastly");
}

#[test]
fn display_waf_header_leakage() {
    let issue = WafIssue::WafHeaderLeakage {
        header: "x-debug-token".to_string(),
        value: "abc123".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "WAF header leakage: x-debug-token: abc123"
    );
}

// === Severity tests ===

#[test]
fn severity_waf_detected_is_zero() {
    let issue = WafIssue::WafDetected {
        name: "cloudflare".to_string(),
        evidence: "header: cf-ray".to_string(),
    };
    assert_eq!(waf_issue_severity(&issue), 0.0);
}

#[test]
fn severity_bypass_possible() {
    let issue = WafIssue::WafBypassPossible {
        name: "aws-waf".to_string(),
        technique: "chunking".to_string(),
    };
    assert_eq!(waf_issue_severity(&issue), 6.0);
}

#[test]
fn severity_no_waf() {
    assert_eq!(waf_issue_severity(&WafIssue::NoWafDetected), 4.0);
}

#[test]
fn severity_multiple_wafs() {
    let issue = WafIssue::MultipleWafs {
        names: vec!["a".to_string(), "b".to_string()],
    };
    assert_eq!(waf_issue_severity(&issue), 2.0);
}

#[test]
fn severity_outdated() {
    let issue = WafIssue::OutdatedWaf {
        name: "nginx".to_string(),
        evidence: "nginx/1.0".to_string(),
    };
    assert_eq!(waf_issue_severity(&issue), 5.0);
}

#[test]
fn severity_learning_mode() {
    let issue = WafIssue::WafInLearningMode {
        name: "modsecurity".to_string(),
    };
    assert_eq!(waf_issue_severity(&issue), 7.0);
}

#[test]
fn severity_cdn_without_waf() {
    let issue = WafIssue::CdnWithoutWaf {
        cdn: "fastly".to_string(),
    };
    assert_eq!(waf_issue_severity(&issue), 3.0);
}

#[test]
fn severity_header_leakage() {
    let issue = WafIssue::WafHeaderLeakage {
        header: "x-debug".to_string(),
        value: "1".to_string(),
    };
    assert_eq!(waf_issue_severity(&issue), 5.5);
}

// === analyze_waf_headers tests ===

#[test]
fn analyze_headers_cloudflare_detection() {
    let headers = vec![("cf-ray", "abc123")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::WafDetected { name, .. } if name == "cloudflare"
    )));
}

#[test]
fn analyze_headers_akamai_detection() {
    let headers = vec![("x-akamai-transformed", "9 - 0 pmb=mNONE,1")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::WafDetected { name, .. } if name == "akamai"
    )));
}

#[test]
fn analyze_headers_sucuri_detection() {
    let headers = vec![("x-sucuri-id", "abc")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::WafDetected { name, .. } if name == "sucuri"
    )));
}

#[test]
fn analyze_headers_server_nginx_detection() {
    let headers = vec![("server", "nginx/1.24.0")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::WafDetected { name, .. } if name == "nginx"
    )));
}

#[test]
fn analyze_headers_no_waf_detected() {
    let headers = vec![("content-type", "text/html"), ("date", "Mon, 01 Jan 2026")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.contains(&WafIssue::NoWafDetected));
}

#[test]
fn analyze_headers_empty_input() {
    let headers: Vec<(&str, &str)> = vec![];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.contains(&WafIssue::NoWafDetected));
}

#[test]
fn analyze_headers_multiple_wafs_detected() {
    let headers = vec![("cf-ray", "abc"), ("x-akamai-transformed", "xyz")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::MultipleWafs { names } if names.len() == 2
    )));
}

#[test]
fn analyze_headers_bypass_for_cloudflare() {
    let headers = vec![("cf-ray", "abc")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::WafBypassPossible { name, .. } if name == "cloudflare"
    )));
}

#[test]
fn analyze_headers_bypass_for_aws_waf() {
    let headers = vec![("x-amzn-requestid", "abc")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::WafBypassPossible { name, .. } if name == "aws-waf"
    )));
}

#[test]
fn analyze_headers_no_bypass_for_unknown_waf() {
    let headers = vec![("server", "nginx/1.24.0")];
    let issues = analyze_waf_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, WafIssue::WafBypassPossible { .. }))
    );
}

#[test]
fn analyze_headers_debug_header_leakage() {
    let headers = vec![("x-debug-token", "abc123")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::WafHeaderLeakage { header, .. } if header == "x-debug-token"
    )));
}

#[test]
fn analyze_headers_waf_debug_leakage() {
    let headers = vec![("x-waf-debug", "enabled")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::WafHeaderLeakage { header, value } if header == "x-waf-debug" && value == "enabled"
    )));
}

#[test]
fn analyze_headers_multiple_debug_headers() {
    let headers = vec![
        ("x-debug", "1"),
        ("x-debug-token", "tok"),
        ("x-waf-debug", "on"),
    ];
    let issues = analyze_waf_headers(&headers);
    let leakage_count = issues
        .iter()
        .filter(|i| matches!(i, WafIssue::WafHeaderLeakage { .. }))
        .count();
    assert_eq!(leakage_count, 3);
}

#[test]
fn analyze_headers_cdn_without_waf() {
    let headers = vec![("x-served-by", "cache-lax-1234")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::CdnWithoutWaf { cdn } if cdn == "fastly"
    )));
}

#[test]
fn analyze_headers_cloudfront_cdn_without_waf() {
    let headers = vec![("x-amz-cf-id", "abc123")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::CdnWithoutWaf { cdn } if cdn == "cloudfront"
    )));
}

#[test]
fn analyze_headers_cdn_with_waf_no_cdn_issue() {
    let headers = vec![("x-served-by", "cache-lax-1234"), ("cf-ray", "abc")];
    let issues = analyze_waf_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, WafIssue::CdnWithoutWaf { .. }))
    );
}

#[test]
fn analyze_headers_outdated_nginx() {
    let headers = vec![("server", "nginx/1.0.15")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::OutdatedWaf { name, .. } if name == "nginx"
    )));
}

#[test]
fn analyze_headers_outdated_apache() {
    let headers = vec![("server", "Apache/2.2.34")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::OutdatedWaf { name, .. } if name == "apache"
    )));
}

#[test]
fn analyze_headers_outdated_iis6() {
    let headers = vec![("server", "Microsoft-IIS/6.0")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::OutdatedWaf { name, .. } if name == "microsoft-iis"
    )));
}

#[test]
fn analyze_headers_modern_nginx_not_outdated() {
    let headers = vec![("server", "nginx/1.24.0")];
    let issues = analyze_waf_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, WafIssue::OutdatedWaf { .. }))
    );
}

#[test]
fn analyze_headers_learning_mode_modsecurity() {
    let headers = vec![("x-waf-mode", "mod_security: detection only")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::WafInLearningMode { name } if name == "modsecurity"
    )));
}

#[test]
fn analyze_headers_learning_mode_cloudflare_simulate() {
    let headers = vec![("x-security-mode", "simulate")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::WafInLearningMode { name } if name == "cloudflare"
    )));
}

#[test]
fn analyze_headers_case_insensitive_header_names() {
    let headers = vec![("CF-RAY", "abc123")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::WafDetected { name, .. } if name == "cloudflare"
    )));
}

#[test]
fn analyze_headers_case_insensitive_server() {
    let headers = vec![("Server", "NGINX/1.24.0")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::WafDetected { name, .. } if name == "nginx"
    )));
}

#[test]
fn analyze_headers_wallarm_detection() {
    let headers = vec![("x-wallarm-waf-check", "1")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::WafDetected { name, .. } if name == "wallarm"
    )));
}

#[test]
fn analyze_headers_fortiweb_detection() {
    let headers = vec![("fortiwafsid", "abc")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::WafDetected { name, .. } if name == "fortiweb"
    )));
}

#[test]
fn analyze_headers_barracuda_detection() {
    let headers = vec![("barra_counter_session", "sid123")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::WafDetected { name, .. } if name == "barracuda"
    )));
}

// === waf_issues_to_operations tests ===

#[test]
fn issues_to_operations_empty() {
    let mut seq = 0;
    let ops = waf_issues_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn issues_to_operations_single_creates_add_finding() {
    let issues = vec![WafIssue::NoWafDetected];
    let mut seq = 0;
    let ops = waf_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            confidence,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::SecurityMisconfiguration
            );
            assert!((confidence.value() - 0.5).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn issues_to_operations_uses_correct_severity() {
    let issues = vec![WafIssue::WafInLearningMode {
        name: "modsec".to_string(),
    }];
    let mut seq = 0;
    let ops = waf_issues_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 7.0).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn issues_to_operations_multiple_increments_seq() {
    let issues = vec![
        WafIssue::NoWafDetected,
        WafIssue::WafHeaderLeakage {
            header: "x-debug".to_string(),
            value: "1".to_string(),
        },
        WafIssue::CdnWithoutWaf {
            cdn: "fastly".to_string(),
        },
    ];
    let mut seq = 5;
    let ops = waf_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 8);
    assert_eq!(ops[0].sequence_number, 6);
    assert_eq!(ops[1].sequence_number, 7);
    assert_eq!(ops[2].sequence_number, 8);
}

#[test]
fn issues_to_operations_waf_detected_zero_severity() {
    let issues = vec![WafIssue::WafDetected {
        name: "cloudflare".to_string(),
        evidence: "header: cf-ray".to_string(),
    }];
    let mut seq = 0;
    let ops = waf_issues_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 0.0).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn issues_to_operations_bypass_severity() {
    let issues = vec![WafIssue::WafBypassPossible {
        name: "cloudflare".to_string(),
        technique: "origin IP discovery".to_string(),
    }];
    let mut seq = 0;
    let ops = waf_issues_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 6.0).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

// === WafIssue equality / clone tests ===

#[test]
fn waf_issue_clone_preserves_value() {
    let original = WafIssue::WafDetected {
        name: "sucuri".to_string(),
        evidence: "x-sucuri-id".to_string(),
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn waf_issue_no_waf_equality() {
    assert_eq!(WafIssue::NoWafDetected, WafIssue::NoWafDetected);
}

#[test]
fn waf_issue_different_variants_not_equal() {
    let a = WafIssue::NoWafDetected;
    let b = WafIssue::CdnWithoutWaf {
        cdn: "fastly".to_string(),
    };
    assert_ne!(a, b);
}

// === Edge case tests ===

#[test]
fn analyze_headers_duplicate_waf_header_deduplicates() {
    let headers = vec![("cf-ray", "aaa"), ("cf-ray", "bbb")];
    let issues = analyze_waf_headers(&headers);
    let detected_count = issues
        .iter()
        .filter(|i| matches!(i, WafIssue::WafDetected { name, .. } if name == "cloudflare"))
        .count();
    assert_eq!(detected_count, 1);
}

#[test]
fn analyze_headers_three_wafs_multiple_detected() {
    let headers = vec![
        ("cf-ray", "a"),
        ("x-akamai-transformed", "b"),
        ("x-sucuri-id", "c"),
    ];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::MultipleWafs { names } if names.len() == 3
    )));
}

#[test]
fn analyze_headers_outdated_iis7() {
    let headers = vec![("server", "Microsoft-IIS/7.5")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::OutdatedWaf { name, .. } if name == "microsoft-iis"
    )));
}

#[test]
fn analyze_headers_modern_iis_not_outdated() {
    let headers = vec![("server", "Microsoft-IIS/10.0")];
    let issues = analyze_waf_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, WafIssue::OutdatedWaf { name, .. } if name == "microsoft-iis"))
    );
}

#[test]
fn analyze_headers_firewall_hint_prevents_no_waf() {
    let headers = vec![("x-firewall-status", "active")];
    let issues = analyze_waf_headers(&headers);
    assert!(!issues.contains(&WafIssue::NoWafDetected));
}

#[test]
fn analyze_headers_sucuri_bypass_technique() {
    let headers = vec![("x-sucuri-id", "abc")];
    let issues = analyze_waf_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        WafIssue::WafBypassPossible { name, technique }
            if name == "sucuri" && technique.contains("double URL encoding")
    )));
}

#[test]
fn issues_to_operations_all_have_passive_recon_module() {
    let issues = vec![
        WafIssue::NoWafDetected,
        WafIssue::WafDetected {
            name: "cf".to_string(),
            evidence: "h".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = waf_issues_to_operations(&issues, &mut seq);
    for op in &ops {
        assert_eq!(
            op.module,
            aegis_protocol::operation::ModuleIdentifier::PassiveRecon
        );
    }
}

#[test]
fn issues_to_operations_all_have_nonzero_timestamp() {
    let issues = vec![WafIssue::NoWafDetected];
    let mut seq = 0;
    let ops = waf_issues_to_operations(&issues, &mut seq);
    assert!(ops[0].timestamp_unix_ms > 0);
}
