use super::objective_evaluator::*;
use std::collections::HashMap;

#[test]
fn parse_domain_admin_variants() {
    assert_eq!(
        parse_objective_type("domain admin"),
        ObjectiveType::DomainAdmin
    );
    assert_eq!(
        parse_objective_type("Domain Admin access"),
        ObjectiveType::DomainAdmin
    );
    assert_eq!(parse_objective_type("DA"), ObjectiveType::DomainAdmin);
}

#[test]
fn parse_database_access() {
    assert_eq!(
        parse_objective_type("database access"),
        ObjectiveType::DatabaseAccess
    );
    assert_eq!(
        parse_objective_type("db access"),
        ObjectiveType::DatabaseAccess
    );
}

#[test]
fn parse_file_read() {
    assert_eq!(
        parse_objective_type("file: /etc/shadow"),
        ObjectiveType::FileRead("/etc/shadow".to_string())
    );
}

#[test]
fn parse_credential_target() {
    assert_eq!(
        parse_objective_type("credential: admin"),
        ObjectiveType::CredentialTarget("admin".to_string())
    );
}

#[test]
fn parse_network_access() {
    assert_eq!(
        parse_objective_type("network: 10.0.0.0/8"),
        ObjectiveType::NetworkAccess("10.0.0.0/8".to_string())
    );
}

#[test]
fn parse_custom_objective() {
    assert_eq!(
        parse_objective_type("something else"),
        ObjectiveType::Custom("something else".to_string())
    );
}

#[test]
fn evaluate_domain_admin_achieved_via_credential() {
    let evidence = CollectedEvidence {
        credentials: vec![EvalCredential {
            username: "admin".to_string(),
            credential_type: "password".to_string(),
            access_level: "domain admin".to_string(),
            groups: vec!["Domain Admins".to_string()],
            target_host: None,
        }],
        ..Default::default()
    };

    let result = evaluate_objective("domain admin", &evidence);
    assert!(result.achieved);
    assert_eq!(result.impact_pct, 100.0);
    assert!(!result.evidence.is_empty());
    assert!(result.summary.contains("achieved"));
}

#[test]
fn evaluate_domain_admin_achieved_via_access_level() {
    let evidence = CollectedEvidence {
        access_level: "Domain Admin".to_string(),
        ..Default::default()
    };

    let result = evaluate_objective("domain admin", &evidence);
    assert!(result.achieved);
    assert_eq!(result.impact_pct, 100.0);
}

#[test]
fn evaluate_domain_admin_partial_progress() {
    let evidence = CollectedEvidence {
        credentials: vec![EvalCredential {
            username: "user1".to_string(),
            credential_type: "password".to_string(),
            access_level: "local admin".to_string(),
            groups: vec!["Administrators".to_string()],
            target_host: None,
        }],
        access_level: "local admin".to_string(),
        network_hosts: vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()],
        ..Default::default()
    };

    let result = evaluate_objective("domain admin", &evidence);
    assert!(!result.achieved);
    assert!(result.impact_pct > 0.0);
    assert!(result.impact_pct < 100.0);
    assert!(!result.partial_progress.is_empty());
}

#[test]
fn evaluate_domain_admin_no_progress() {
    let evidence = CollectedEvidence::default();
    let result = evaluate_objective("domain admin", &evidence);
    assert!(!result.achieved);
    assert_eq!(result.impact_pct, 0.0);
}

#[test]
fn evaluate_database_access_achieved() {
    let evidence = CollectedEvidence {
        db_connections: vec!["mysql://10.0.0.5:3306/app_db".to_string()],
        ..Default::default()
    };

    let result = evaluate_objective("database access", &evidence);
    assert!(result.achieved);
    assert_eq!(result.impact_pct, 100.0);
}

#[test]
fn evaluate_database_access_partial_with_creds() {
    let evidence = CollectedEvidence {
        credentials: vec![EvalCredential {
            username: "dbadmin".to_string(),
            credential_type: "database_password".to_string(),
            access_level: "authenticated".to_string(),
            groups: vec![],
            target_host: None,
        }],
        ..Default::default()
    };

    let result = evaluate_objective("database access", &evidence);
    assert!(!result.achieved);
    assert_eq!(result.impact_pct, 60.0);
    assert_eq!(result.partial_progress.len(), 1);
}

#[test]
fn evaluate_file_read_achieved() {
    let evidence = CollectedEvidence {
        file_reads: vec!["/etc/shadow".to_string()],
        ..Default::default()
    };

    let result = evaluate_objective("file: /etc/shadow", &evidence);
    assert!(result.achieved);
    assert_eq!(result.impact_pct, 100.0);
}

#[test]
fn evaluate_file_read_partial_from_same_dir() {
    let evidence = CollectedEvidence {
        file_reads: vec!["/etc/passwd".to_string(), "/etc/hosts".to_string()],
        ..Default::default()
    };

    let result = evaluate_objective("file: /etc/shadow", &evidence);
    assert!(!result.achieved);
    assert!(result.impact_pct > 0.0);
}

#[test]
fn evaluate_file_read_no_progress() {
    let evidence = CollectedEvidence::default();
    let result = evaluate_objective("file: /etc/shadow", &evidence);
    assert!(!result.achieved);
    assert_eq!(result.impact_pct, 0.0);
}

#[test]
fn evaluate_credential_target_achieved() {
    let evidence = CollectedEvidence {
        credentials: vec![EvalCredential {
            username: "admin".to_string(),
            credential_type: "password".to_string(),
            access_level: "authenticated".to_string(),
            groups: vec![],
            target_host: None,
        }],
        ..Default::default()
    };

    let result = evaluate_objective("credential: admin", &evidence);
    assert!(result.achieved);
    assert_eq!(result.impact_pct, 100.0);
}

#[test]
fn evaluate_credential_target_case_insensitive() {
    let evidence = CollectedEvidence {
        credentials: vec![EvalCredential {
            username: "Admin".to_string(),
            credential_type: "password".to_string(),
            access_level: "authenticated".to_string(),
            groups: vec![],
            target_host: None,
        }],
        ..Default::default()
    };

    let result = evaluate_objective("credential: admin", &evidence);
    assert!(result.achieved);
}

#[test]
fn evaluate_credential_target_wrong_user() {
    let evidence = CollectedEvidence {
        credentials: vec![EvalCredential {
            username: "user1".to_string(),
            credential_type: "password".to_string(),
            access_level: "authenticated".to_string(),
            groups: vec![],
            target_host: None,
        }],
        ..Default::default()
    };

    let result = evaluate_objective("credential: admin", &evidence);
    assert!(!result.achieved);
    assert_eq!(result.impact_pct, 40.0);
}

#[test]
fn evaluate_network_access_achieved() {
    let evidence = CollectedEvidence {
        network_hosts: vec![
            "10.0.0.1".to_string(),
            "10.0.0.2".to_string(),
            "10.0.0.3".to_string(),
            "10.0.0.4".to_string(),
        ],
        ..Default::default()
    };

    let result = evaluate_objective("network: 10.0.0.0/24", &evidence);
    assert!(result.achieved);
    assert_eq!(result.impact_pct, 100.0);
}

#[test]
fn evaluate_network_access_partial() {
    let evidence = CollectedEvidence {
        network_hosts: vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()],
        ..Default::default()
    };

    let result = evaluate_objective("network: 10.0.0.0/24", &evidence);
    assert!(!result.achieved);
    assert_eq!(result.impact_pct, 50.0);
    assert!(!result.partial_progress.is_empty());
}

#[test]
fn evaluate_custom_achieved() {
    let mut flags = HashMap::new();
    flags.insert("exfiltrate PII".to_string(), true);
    let evidence = CollectedEvidence {
        custom_flags: flags,
        ..Default::default()
    };

    let result = evaluate_objective("exfiltrate PII", &evidence);
    assert!(result.achieved);
    assert_eq!(result.impact_pct, 100.0);
}

#[test]
fn evaluate_custom_not_achieved() {
    let evidence = CollectedEvidence::default();
    let result = evaluate_objective("exfiltrate PII", &evidence);
    assert!(!result.achieved);
    assert_eq!(result.impact_pct, 0.0);
}

#[test]
fn evaluate_all_multiple_objectives() {
    let evidence = CollectedEvidence {
        credentials: vec![EvalCredential {
            username: "admin".to_string(),
            credential_type: "password".to_string(),
            access_level: "domain admin".to_string(),
            groups: vec!["Domain Admins".to_string()],
            target_host: None,
        }],
        db_connections: vec!["postgres://db:5432".to_string()],
        ..Default::default()
    };

    let objectives = vec![
        "domain admin".to_string(),
        "database access".to_string(),
        "credential: admin".to_string(),
    ];

    let results = evaluate_all(&objectives, &evidence);
    assert_eq!(results.len(), 3);
    assert!(results[0].achieved);
    assert!(results[1].achieved);
    assert!(results[2].achieved);
}

#[test]
fn collected_evidence_default() {
    let ev = CollectedEvidence::default();
    assert!(ev.credentials.is_empty());
    assert!(ev.file_reads.is_empty());
    assert!(ev.db_connections.is_empty());
    assert!(ev.network_hosts.is_empty());
    assert_eq!(ev.access_level, "none");
}
