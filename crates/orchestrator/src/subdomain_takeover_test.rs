use crate::subdomain_takeover::*;

// === Existing tests (7) ===

#[test]
fn check_subdomain_takeover_empty_input() {
    let candidates = check_subdomain_takeover(&[]);
    assert!(candidates.is_empty());
}

#[test]
fn takeover_findings_to_operations_creates_findings() {
    let candidates = vec![TakeoverCandidate {
        subdomain: "blog.example.com".to_string(),
        cname: "example.github.io".to_string(),
        service: "github.io".to_string(),
    }];
    let mut seq = 0;
    let ops = takeover_findings_to_operations(&candidates, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            severity,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::SecurityMisconfiguration
            );
            assert_eq!(*severity, 8.0);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn takeover_findings_to_operations_empty() {
    let mut seq = 5;
    let ops = takeover_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn takeover_findings_to_operations_multiple() {
    let candidates = vec![
        TakeoverCandidate {
            subdomain: "blog.example.com".to_string(),
            cname: "example.github.io".to_string(),
            service: "github.io".to_string(),
        },
        TakeoverCandidate {
            subdomain: "app.example.com".to_string(),
            cname: "example.herokuapp.com".to_string(),
            service: "herokuapp.com".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = takeover_findings_to_operations(&candidates, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn resolve_cname_nonexistent_domain() {
    let result = resolve_cname("this-domain-does-not-exist-aegis-test.invalid");
    assert!(result.is_none());
}

#[test]
fn takeover_findings_to_operations_increments_sequence() {
    let candidates = vec![
        TakeoverCandidate {
            subdomain: "a.example.com".to_string(),
            cname: "a.github.io".to_string(),
            service: "github.io".to_string(),
        },
        TakeoverCandidate {
            subdomain: "b.example.com".to_string(),
            cname: "b.herokuapp.com".to_string(),
            service: "herokuapp.com".to_string(),
        },
    ];
    let mut seq = 5;
    let ops = takeover_findings_to_operations(&candidates, &mut seq);
    assert_eq!(seq, 7);
    assert_eq!(ops[0].sequence_number, 6);
    assert_eq!(ops[1].sequence_number, 7);
}

#[test]
fn check_subdomain_takeover_filters_non_cname() {
    let subdomains = vec!["this-does-not-exist-aegis.invalid".to_string()];
    let candidates = check_subdomain_takeover(&subdomains);
    assert!(candidates.is_empty());
}

// === analyze_cname: every TAKEOVER_FINGERPRINTS service (14 tests) ===

#[test]
fn analyze_cname_github_io() {
    let issues = analyze_cname("blog.example.com", "blog.github.io");
    assert!(issues.iter().any(
        |i| matches!(i, TakeoverIssue::VulnerableCname { service, .. } if service == "github.io")
    ));
}

#[test]
fn analyze_cname_herokuapp() {
    let issues = analyze_cname("app.example.com", "app.herokuapp.com");
    assert!(issues.iter().any(|i| matches!(i, TakeoverIssue::VulnerableCname { service, .. } if service == "herokuapp.com")));
}

#[test]
fn analyze_cname_herokudns() {
    let issues = analyze_cname("api.example.com", "api.herokudns.com");
    assert!(issues.iter().any(|i| matches!(i, TakeoverIssue::VulnerableCname { service, .. } if service == "herokudns.com")));
}

#[test]
fn analyze_cname_s3() {
    let issues = analyze_cname("assets.example.com", "bucket.s3.amazonaws.com");
    assert!(issues.iter().any(|i| matches!(i, TakeoverIssue::VulnerableCname { service, .. } if service == "s3.amazonaws.com")));
}

#[test]
fn analyze_cname_cloudfront() {
    let issues = analyze_cname("cdn.example.com", "d12345.cloudfront.net");
    assert!(issues.iter().any(|i| matches!(i, TakeoverIssue::VulnerableCname { service, .. } if service == "cloudfront.net")));
}

#[test]
fn analyze_cname_azurewebsites() {
    let issues = analyze_cname("web.example.com", "myapp.azurewebsites.net");
    assert!(issues.iter().any(|i| matches!(i, TakeoverIssue::VulnerableCname { service, .. } if service == "azurewebsites.net")));
}

#[test]
fn analyze_cname_trafficmanager() {
    let issues = analyze_cname("lb.example.com", "myapp.trafficmanager.net");
    assert!(issues.iter().any(|i| matches!(i, TakeoverIssue::VulnerableCname { service, .. } if service == "trafficmanager.net")));
}

#[test]
fn analyze_cname_pantheonsite() {
    let issues = analyze_cname("cms.example.com", "mysite.pantheonsite.io");
    assert!(issues.iter().any(|i| matches!(i, TakeoverIssue::VulnerableCname { service, .. } if service == "pantheonsite.io")));
}

#[test]
fn analyze_cname_readme() {
    let issues = analyze_cname("docs.example.com", "proj.readme.io");
    assert!(issues.iter().any(
        |i| matches!(i, TakeoverIssue::VulnerableCname { service, .. } if service == "readme.io")
    ));
}

#[test]
fn analyze_cname_surge() {
    let issues = analyze_cname("demo.example.com", "mysite.surge.sh");
    assert!(issues.iter().any(
        |i| matches!(i, TakeoverIssue::VulnerableCname { service, .. } if service == "surge.sh")
    ));
}

#[test]
fn analyze_cname_bitbucket() {
    let issues = analyze_cname("site.example.com", "team.bitbucket.io");
    assert!(issues.iter().any(
        |i| matches!(i, TakeoverIssue::VulnerableCname { service, .. } if service == "bitbucket.io")
    ));
}

#[test]
fn analyze_cname_ghost() {
    let issues = analyze_cname("blog.example.com", "myblog.ghost.io");
    assert!(issues.iter().any(
        |i| matches!(i, TakeoverIssue::VulnerableCname { service, .. } if service == "ghost.io")
    ));
}

#[test]
fn analyze_cname_netlify() {
    let issues = analyze_cname("www.example.com", "mysite.netlify.app");
    assert!(issues.iter().any(
        |i| matches!(i, TakeoverIssue::VulnerableCname { service, .. } if service == "netlify.app")
    ));
}

#[test]
fn analyze_cname_fly_dev() {
    let issues = analyze_cname("api.example.com", "myapp.fly.dev");
    assert!(issues.iter().any(
        |i| matches!(i, TakeoverIssue::VulnerableCname { service, .. } if service == "fly.dev")
    ));
}

// === HighRiskService tests ===

#[test]
fn analyze_cname_high_risk_github_io() {
    let issues = analyze_cname("blog.example.com", "org.github.io");
    assert!(issues.iter().any(
        |i| matches!(i, TakeoverIssue::HighRiskService { service, .. } if service == "github.io")
    ));
}

#[test]
fn analyze_cname_high_risk_s3() {
    let issues = analyze_cname("assets.example.com", "bucket.s3.amazonaws.com");
    assert!(issues.iter().any(|i| matches!(i, TakeoverIssue::HighRiskService { service, .. } if service == "s3.amazonaws.com")));
}

#[test]
fn analyze_cname_no_high_risk_for_herokuapp() {
    let issues = analyze_cname("app.example.com", "app.herokuapp.com");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, TakeoverIssue::HighRiskService { .. }))
    );
}

// === ExpiredDomain tests ===

#[test]
fn analyze_cname_expired_invalid_tld() {
    let issues = analyze_cname("sub.example.com", "target.invalid");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TakeoverIssue::ExpiredDomain { .. }))
    );
}

#[test]
fn analyze_cname_expired_example_tld() {
    let issues = analyze_cname("sub.example.com", "target.example");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TakeoverIssue::ExpiredDomain { .. }))
    );
}

#[test]
fn analyze_cname_expired_test_tld() {
    let issues = analyze_cname("sub.example.com", "target.test");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TakeoverIssue::ExpiredDomain { .. }))
    );
}

// === DanglingCname tests ===

#[test]
fn analyze_cname_empty_cname() {
    let issues = analyze_cname("sub.example.com", "");
    assert_eq!(issues.len(), 1);
    assert!(
        matches!(&issues[0], TakeoverIssue::DanglingCname { subdomain, cname } if subdomain == "sub.example.com" && cname.is_empty())
    );
}

#[test]
fn analyze_cname_whitespace_only_cname() {
    let issues = analyze_cname("sub.example.com", "   ");
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], TakeoverIssue::DanglingCname { .. }));
}

// === Non-vulnerable CNAME ===

#[test]
fn analyze_cname_safe_cloudflare() {
    let issues = analyze_cname("www.example.com", "www.cloudflare.com");
    assert!(issues.is_empty());
}

#[test]
fn analyze_cname_safe_google() {
    let issues = analyze_cname("mail.example.com", "mail.google.com");
    assert!(issues.is_empty());
}

#[test]
fn analyze_cname_safe_fastly() {
    let issues = analyze_cname("cdn.example.com", "dualstack.fastly.net");
    assert!(issues.is_empty());
}

// === Severity ordering tests ===

#[test]
fn severity_high_risk_is_highest() {
    let high_risk = TakeoverIssue::HighRiskService {
        subdomain: "s.example.com".to_string(),
        service: "github.io".to_string(),
    };
    assert_eq!(takeover_severity(&high_risk), 9.5);
}

#[test]
fn severity_vulnerable_cname() {
    let issue = TakeoverIssue::VulnerableCname {
        subdomain: "s.example.com".to_string(),
        cname: "x.herokuapp.com".to_string(),
        service: "herokuapp.com".to_string(),
    };
    assert_eq!(takeover_severity(&issue), 9.0);
}

#[test]
fn severity_nxdomain() {
    let issue = TakeoverIssue::NxdomainCname {
        subdomain: "s.example.com".to_string(),
        cname: "gone.example.org".to_string(),
    };
    assert_eq!(takeover_severity(&issue), 8.0);
}

#[test]
fn severity_dangling() {
    let issue = TakeoverIssue::DanglingCname {
        subdomain: "s.example.com".to_string(),
        cname: "".to_string(),
    };
    assert_eq!(takeover_severity(&issue), 7.5);
}

#[test]
fn severity_expired() {
    let issue = TakeoverIssue::ExpiredDomain {
        subdomain: "s.example.com".to_string(),
        cname: "target.invalid".to_string(),
    };
    assert_eq!(takeover_severity(&issue), 7.0);
}

#[test]
fn severity_wildcard() {
    let issue = TakeoverIssue::WildcardCname {
        subdomain: "*.example.com".to_string(),
        cname: "catch-all.cdn.com".to_string(),
    };
    assert_eq!(takeover_severity(&issue), 5.0);
}

#[test]
fn severity_a_record_mismatch() {
    let issue = TakeoverIssue::ARecordMismatch {
        subdomain: "s.example.com".to_string(),
        ip: "1.2.3.4".to_string(),
    };
    assert_eq!(takeover_severity(&issue), 4.0);
}

#[test]
fn severity_ordering_descending() {
    let high_risk = takeover_severity(&TakeoverIssue::HighRiskService {
        subdomain: String::new(),
        service: String::new(),
    });
    let vulnerable = takeover_severity(&TakeoverIssue::VulnerableCname {
        subdomain: String::new(),
        cname: String::new(),
        service: String::new(),
    });
    let nxdomain = takeover_severity(&TakeoverIssue::NxdomainCname {
        subdomain: String::new(),
        cname: String::new(),
    });
    let dangling = takeover_severity(&TakeoverIssue::DanglingCname {
        subdomain: String::new(),
        cname: String::new(),
    });
    let expired = takeover_severity(&TakeoverIssue::ExpiredDomain {
        subdomain: String::new(),
        cname: String::new(),
    });
    let wildcard = takeover_severity(&TakeoverIssue::WildcardCname {
        subdomain: String::new(),
        cname: String::new(),
    });
    let a_record = takeover_severity(&TakeoverIssue::ARecordMismatch {
        subdomain: String::new(),
        ip: String::new(),
    });
    assert!(high_risk > vulnerable);
    assert!(vulnerable > nxdomain);
    assert!(nxdomain > dangling);
    assert!(dangling > expired);
    assert!(expired > wildcard);
    assert!(wildcard > a_record);
}

// === Display tests ===

#[test]
fn display_vulnerable_cname() {
    let issue = TakeoverIssue::VulnerableCname {
        subdomain: "blog.example.com".to_string(),
        cname: "org.github.io".to_string(),
        service: "github.io".to_string(),
    };
    let s = format!("{issue}");
    assert!(s.contains("vulnerable CNAME"));
    assert!(s.contains("blog.example.com"));
    assert!(s.contains("org.github.io"));
    assert!(s.contains("github.io"));
}

#[test]
fn display_dangling_cname() {
    let issue = TakeoverIssue::DanglingCname {
        subdomain: "old.example.com".to_string(),
        cname: "".to_string(),
    };
    let s = format!("{issue}");
    assert!(s.contains("dangling CNAME"));
    assert!(s.contains("old.example.com"));
}

#[test]
fn display_expired_domain() {
    let issue = TakeoverIssue::ExpiredDomain {
        subdomain: "sub.example.com".to_string(),
        cname: "target.invalid".to_string(),
    };
    let s = format!("{issue}");
    assert!(s.contains("expired domain CNAME"));
    assert!(s.contains("target.invalid"));
}

#[test]
fn display_nxdomain_cname() {
    let issue = TakeoverIssue::NxdomainCname {
        subdomain: "sub.example.com".to_string(),
        cname: "gone.org".to_string(),
    };
    let s = format!("{issue}");
    assert!(s.contains("NXDOMAIN CNAME"));
    assert!(s.contains("gone.org"));
}

#[test]
fn display_wildcard_cname() {
    let issue = TakeoverIssue::WildcardCname {
        subdomain: "*.example.com".to_string(),
        cname: "catch.cdn.com".to_string(),
    };
    let s = format!("{issue}");
    assert!(s.contains("wildcard CNAME"));
    assert!(s.contains("*.example.com"));
}

#[test]
fn display_high_risk_service() {
    let issue = TakeoverIssue::HighRiskService {
        subdomain: "blog.example.com".to_string(),
        service: "github.io".to_string(),
    };
    let s = format!("{issue}");
    assert!(s.contains("high-risk service"));
    assert!(s.contains("github.io"));
}

#[test]
fn display_a_record_mismatch() {
    let issue = TakeoverIssue::ARecordMismatch {
        subdomain: "sub.example.com".to_string(),
        ip: "1.2.3.4".to_string(),
    };
    let s = format!("{issue}");
    assert!(s.contains("A record mismatch"));
    assert!(s.contains("1.2.3.4"));
}

// === takeover_issues_to_operations tests ===

#[test]
fn issues_to_operations_single() {
    let issues = vec![TakeoverIssue::VulnerableCname {
        subdomain: "blog.example.com".to_string(),
        cname: "org.github.io".to_string(),
        service: "github.io".to_string(),
    }];
    let mut seq = 0;
    let ops = takeover_issues_to_operations(&issues, &mut seq);
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
fn issues_to_operations_empty() {
    let mut seq = 10;
    let ops = takeover_issues_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 10);
}

#[test]
fn issues_to_operations_multiple_increments_seq() {
    let issues = vec![
        TakeoverIssue::DanglingCname {
            subdomain: "a.example.com".to_string(),
            cname: "".to_string(),
        },
        TakeoverIssue::ExpiredDomain {
            subdomain: "b.example.com".to_string(),
            cname: "old.invalid".to_string(),
        },
        TakeoverIssue::NxdomainCname {
            subdomain: "c.example.com".to_string(),
            cname: "gone.org".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = takeover_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
    assert_eq!(ops[0].sequence_number, 1);
    assert_eq!(ops[1].sequence_number, 2);
    assert_eq!(ops[2].sequence_number, 3);
}

// === Edge cases ===

#[test]
fn analyze_cname_empty_subdomain() {
    let issues = analyze_cname("", "target.github.io");
    assert!(issues.iter().any(
        |i| matches!(i, TakeoverIssue::VulnerableCname { subdomain, .. } if subdomain.is_empty())
    ));
}

#[test]
fn analyze_cname_both_empty() {
    let issues = analyze_cname("", "");
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], TakeoverIssue::DanglingCname { .. }));
}

#[test]
fn analyze_cname_case_insensitive() {
    let issues = analyze_cname("sub.example.com", "ORG.GITHUB.IO");
    assert!(issues.iter().any(
        |i| matches!(i, TakeoverIssue::VulnerableCname { service, .. } if service == "github.io")
    ));
}

#[test]
fn analyze_cname_github_io_also_high_risk() {
    let issues = analyze_cname("blog.example.com", "org.github.io");
    let vulnerable_count = issues
        .iter()
        .filter(|i| matches!(i, TakeoverIssue::VulnerableCname { .. }))
        .count();
    let high_risk_count = issues
        .iter()
        .filter(|i| matches!(i, TakeoverIssue::HighRiskService { .. }))
        .count();
    assert_eq!(vulnerable_count, 1);
    assert_eq!(high_risk_count, 1);
}

#[test]
fn analyze_cname_s3_also_high_risk() {
    let issues = analyze_cname("assets.example.com", "bucket.s3.amazonaws.com");
    let vulnerable_count = issues
        .iter()
        .filter(|i| matches!(i, TakeoverIssue::VulnerableCname { .. }))
        .count();
    let high_risk_count = issues
        .iter()
        .filter(|i| matches!(i, TakeoverIssue::HighRiskService { .. }))
        .count();
    assert_eq!(vulnerable_count, 1);
    assert_eq!(high_risk_count, 1);
}

#[test]
fn takeover_issue_clone() {
    let issue = TakeoverIssue::VulnerableCname {
        subdomain: "a.com".to_string(),
        cname: "b.github.io".to_string(),
        service: "github.io".to_string(),
    };
    let cloned = issue.clone();
    assert_eq!(issue, cloned);
}

#[test]
fn takeover_issue_debug() {
    let issue = TakeoverIssue::DanglingCname {
        subdomain: "x.com".to_string(),
        cname: "".to_string(),
    };
    let debug = format!("{issue:?}");
    assert!(debug.contains("DanglingCname"));
}
