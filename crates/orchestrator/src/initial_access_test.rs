use super::initial_access::*;

#[test]
fn category_display_formatting() {
    assert_eq!(
        InitialAccessCategory::RemoteCodeExecution.to_string(),
        "RCE"
    );
    assert_eq!(
        InitialAccessCategory::FileUpload.to_string(),
        "File Upload → Web Shell"
    );
    assert_eq!(
        InitialAccessCategory::SsrfToMetadata.to_string(),
        "SSRF → Metadata"
    );
    assert_eq!(
        InitialAccessCategory::CredentialStuffing.to_string(),
        "Credential Stuffing"
    );
}

#[test]
fn score_candidate_rce_highest() {
    let rce = AccessCandidate {
        vulnerability_id: "vuln-001".to_string(),
        category: InitialAccessCategory::RemoteCodeExecution,
        endpoint: "/api/exec".to_string(),
        parameter: Some("cmd".to_string()),
        exploit_reliability: 0.95,
        impact_score: 10.0,
        description: "RCE via command injection".to_string(),
    };
    let cred = AccessCandidate {
        vulnerability_id: "vuln-002".to_string(),
        category: InitialAccessCategory::CredentialStuffing,
        endpoint: "/api/login".to_string(),
        parameter: Some("email".to_string()),
        exploit_reliability: 0.2,
        impact_score: 5.0,
        description: "Credential stuffing".to_string(),
    };
    assert!(score_candidate(&rce) > score_candidate(&cred));
}

#[test]
fn rank_candidates_orders_by_score_descending() {
    let candidates = vec![
        AccessCandidate {
            vulnerability_id: "low".to_string(),
            category: InitialAccessCategory::CredentialStuffing,
            endpoint: "/login".to_string(),
            parameter: None,
            exploit_reliability: 0.2,
            impact_score: 4.0,
            description: "Low priority".to_string(),
        },
        AccessCandidate {
            vulnerability_id: "high".to_string(),
            category: InitialAccessCategory::RemoteCodeExecution,
            endpoint: "/api/exec".to_string(),
            parameter: None,
            exploit_reliability: 0.9,
            impact_score: 9.5,
            description: "High priority".to_string(),
        },
        AccessCandidate {
            vulnerability_id: "mid".to_string(),
            category: InitialAccessCategory::AuthBypass,
            endpoint: "/admin".to_string(),
            parameter: None,
            exploit_reliability: 0.6,
            impact_score: 7.0,
            description: "Medium priority".to_string(),
        },
    ];

    let ranked = rank_candidates(&candidates);
    assert_eq!(ranked.len(), 3);
    assert_eq!(ranked[0].rank, 1);
    assert_eq!(ranked[0].candidate.vulnerability_id, "high");
    assert_eq!(ranked[1].rank, 2);
    assert_eq!(ranked[2].rank, 3);
    assert!(ranked[0].composite_score >= ranked[1].composite_score);
    assert!(ranked[1].composite_score >= ranked[2].composite_score);
}

#[test]
fn select_and_execute_first_success() {
    let candidates = vec![
        AccessCandidate {
            vulnerability_id: "vuln-001".to_string(),
            category: InitialAccessCategory::SqlInjectionToShell,
            endpoint: "/api/search".to_string(),
            parameter: Some("q".to_string()),
            exploit_reliability: 0.85,
            impact_score: 9.0,
            description: "SQLi to shell".to_string(),
        },
        AccessCandidate {
            vulnerability_id: "vuln-002".to_string(),
            category: InitialAccessCategory::AuthBypass,
            endpoint: "/admin".to_string(),
            parameter: None,
            exploit_reliability: 0.5,
            impact_score: 7.0,
            description: "Auth bypass".to_string(),
        },
    ];

    let config = InitialAccessConfig::default();
    let exploit_fn = |candidate: &AccessCandidate| -> ExploitAttempt {
        let success = candidate.category == InitialAccessCategory::SqlInjectionToShell;
        ExploitAttempt {
            candidate: candidate.clone(),
            outcome: if success {
                ExploitOutcome::Success
            } else {
                ExploitOutcome::Failure
            },
            details: "Attempted exploit".to_string(),
            credentials_obtained: if success {
                vec![ObtainedCred {
                    username: "admin".to_string(),
                    credential_value: "hash:abc123".to_string(),
                    credential_type: "hash".to_string(),
                }]
            } else {
                vec![]
            },
            shell_access: success,
            duration_ms: 5000,
        }
    };

    let result = select_and_execute(&candidates, &config, exploit_fn);
    assert!(result.success);
    assert_eq!(
        result.method,
        Some(InitialAccessCategory::SqlInjectionToShell)
    );
    assert_eq!(result.credentials_obtained.len(), 1);
    assert!(result.shell_access);
    assert_eq!(result.attempts.len(), 1);
}

#[test]
fn select_and_execute_all_fail() {
    let candidates = vec![AccessCandidate {
        vulnerability_id: "vuln-001".to_string(),
        category: InitialAccessCategory::AuthBypass,
        endpoint: "/admin".to_string(),
        parameter: None,
        exploit_reliability: 0.3,
        impact_score: 5.0,
        description: "Weak attempt".to_string(),
    }];

    let config = InitialAccessConfig {
        allow_credential_stuffing: false,
        ..Default::default()
    };

    let exploit_fn = |candidate: &AccessCandidate| -> ExploitAttempt {
        ExploitAttempt {
            candidate: candidate.clone(),
            outcome: ExploitOutcome::Failure,
            details: "Blocked by WAF".to_string(),
            credentials_obtained: vec![],
            shell_access: false,
            duration_ms: 2000,
        }
    };

    let result = select_and_execute(&candidates, &config, exploit_fn);
    assert!(!result.success);
    assert!(result.method.is_none());
    assert!(result.credentials_obtained.is_empty());
    assert!(!result.shell_access);
}

#[test]
fn select_and_execute_falls_back_to_credential_stuffing() {
    let candidates = vec![AccessCandidate {
        vulnerability_id: "vuln-001".to_string(),
        category: InitialAccessCategory::AuthBypass,
        endpoint: "/admin".to_string(),
        parameter: None,
        exploit_reliability: 0.3,
        impact_score: 5.0,
        description: "Weak auth bypass".to_string(),
    }];

    let config = InitialAccessConfig {
        allow_credential_stuffing: true,
        discovered_emails: vec!["admin@target.com".to_string()],
        ..Default::default()
    };

    let mut call_count = 0;
    let exploit_fn = |candidate: &AccessCandidate| -> ExploitAttempt {
        let is_stuffing = candidate.category == InitialAccessCategory::CredentialStuffing;
        ExploitAttempt {
            candidate: candidate.clone(),
            outcome: if is_stuffing {
                ExploitOutcome::Success
            } else {
                ExploitOutcome::Failure
            },
            details: "Attempted".to_string(),
            credentials_obtained: if is_stuffing {
                vec![ObtainedCred {
                    username: "admin@target.com".to_string(),
                    credential_value: "password123".to_string(),
                    credential_type: "password".to_string(),
                }]
            } else {
                vec![]
            },
            shell_access: false,
            duration_ms: 3000,
        }
    };

    let result = select_and_execute(&candidates, &config, exploit_fn);
    assert!(result.success);
    assert_eq!(
        result.method,
        Some(InitialAccessCategory::CredentialStuffing)
    );
    assert_eq!(result.attempts.len(), 2);
}

#[test]
fn select_and_execute_respects_max_attempts() {
    let candidates: Vec<AccessCandidate> = (0..20)
        .map(|i| AccessCandidate {
            vulnerability_id: format!("vuln-{i:03}"),
            category: InitialAccessCategory::AuthBypass,
            endpoint: format!("/endpoint-{i}"),
            parameter: None,
            exploit_reliability: 0.5,
            impact_score: 6.0,
            description: format!("Candidate {i}"),
        })
        .collect();

    let config = InitialAccessConfig {
        max_attempts: 5,
        allow_credential_stuffing: false,
        ..Default::default()
    };

    let mut attempt_count = 0u32;
    let exploit_fn = |candidate: &AccessCandidate| -> ExploitAttempt {
        attempt_count += 1;
        ExploitAttempt {
            candidate: candidate.clone(),
            outcome: ExploitOutcome::Failure,
            details: "Failed".to_string(),
            credentials_obtained: vec![],
            shell_access: false,
            duration_ms: 1000,
        }
    };

    let result = select_and_execute(&candidates, &config, exploit_fn);
    assert!(!result.success);
    assert_eq!(result.attempts.len(), 5);
}

#[test]
fn generate_credential_stuffing_candidates_from_emails() {
    let emails = vec!["admin@corp.com".to_string(), "user@corp.com".to_string()];
    let candidates = generate_credential_stuffing_candidates(&emails);
    assert_eq!(candidates.len(), 2);
    assert_eq!(
        candidates[0].category,
        InitialAccessCategory::CredentialStuffing
    );
    assert!(candidates[0].vulnerability_id.contains("admin"));
}

#[test]
fn generate_default_credential_candidates_from_services() {
    let services = vec!["tomcat".to_string(), "jenkins".to_string()];
    let candidates = generate_default_credential_candidates(&services);
    assert_eq!(candidates.len(), 2);
    assert_eq!(
        candidates[0].category,
        InitialAccessCategory::DefaultCredentials
    );
    assert!(candidates[0].endpoint.contains("tomcat"));
    assert!(candidates[1].endpoint.contains("jenkins"));
}

#[test]
fn initial_access_config_defaults() {
    let config = InitialAccessConfig::default();
    assert_eq!(config.max_attempts, 10);
    assert_eq!(config.timeout_per_attempt_ms, 30_000);
    assert!(config.allow_credential_stuffing);
    assert!(config.allow_default_credentials);
    assert!(config.discovered_emails.is_empty());
}

#[test]
fn score_candidate_clamps_to_ten() {
    let candidate = AccessCandidate {
        vulnerability_id: "max".to_string(),
        category: InitialAccessCategory::RemoteCodeExecution,
        endpoint: "/exec".to_string(),
        parameter: None,
        exploit_reliability: 1.0,
        impact_score: 10.0,
        description: "Maximum score candidate".to_string(),
    };
    let score = score_candidate(&candidate);
    assert!(score <= 10.0);
    assert!(score > 0.0);
}

#[test]
fn empty_candidates_returns_failure() {
    let config = InitialAccessConfig {
        allow_credential_stuffing: false,
        ..Default::default()
    };
    let exploit_fn = |candidate: &AccessCandidate| -> ExploitAttempt {
        ExploitAttempt {
            candidate: candidate.clone(),
            outcome: ExploitOutcome::Failure,
            details: "".to_string(),
            credentials_obtained: vec![],
            shell_access: false,
            duration_ms: 0,
        }
    };

    let result = select_and_execute(&[], &config, exploit_fn);
    assert!(!result.success);
    assert_eq!(result.total_candidates, 0);
    assert!(result.attempts.is_empty());
}
