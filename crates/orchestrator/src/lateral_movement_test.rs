use super::lateral_movement::*;
use std::collections::HashSet;

#[test]
fn lateral_method_display() {
    assert_eq!(
        LateralMethod::CredentialReuse.to_string(),
        "Credential Reuse"
    );
    assert_eq!(LateralMethod::PassTheHash.to_string(), "Pass-the-Hash");
    assert_eq!(LateralMethod::Kerberoast.to_string(), "Kerberoast");
    assert_eq!(
        LateralMethod::SharedAdminCreds.to_string(),
        "Shared Admin Credentials"
    );
}

#[test]
fn build_method_priority_defaults() {
    let config = LateralMovementConfig::default();
    let methods = build_method_priority(&config);
    assert_eq!(methods.len(), 4);
    assert_eq!(methods[0], LateralMethod::CredentialReuse);
    assert_eq!(methods[1], LateralMethod::PassTheHash);
    assert_eq!(methods[2], LateralMethod::Kerberoast);
    assert_eq!(methods[3], LateralMethod::SharedAdminCreds);
}

#[test]
fn build_method_priority_subset() {
    let config = LateralMovementConfig {
        try_credential_reuse: true,
        try_pass_the_hash: false,
        try_kerberoast: false,
        try_shared_admin: true,
        ..Default::default()
    };
    let methods = build_method_priority(&config);
    assert_eq!(methods.len(), 2);
    assert_eq!(methods[0], LateralMethod::CredentialReuse);
    assert_eq!(methods[1], LateralMethod::SharedAdminCreds);
}

#[test]
fn score_host_objective_host_highest() {
    let host = NetworkHost {
        address: "10.0.0.5".to_string(),
        hostname: None,
        open_ports: vec![22],
        services: vec![],
        os_fingerprint: None,
        reachable: true,
    };
    let score_with_obj = score_host(&host, Some("10.0.0.5"));
    let score_without = score_host(&host, None);
    assert!(score_with_obj > score_without);
    assert!(score_with_obj >= 100.0);
}

#[test]
fn score_host_domain_controller_bonus() {
    let dc = NetworkHost {
        address: "10.0.0.1".to_string(),
        hostname: Some("dc01".to_string()),
        open_ports: vec![88, 445, 389],
        services: vec!["domain controller".to_string()],
        os_fingerprint: None,
        reachable: true,
    };
    let regular = NetworkHost {
        address: "10.0.0.2".to_string(),
        hostname: None,
        open_ports: vec![80],
        services: vec![],
        os_fingerprint: None,
        reachable: true,
    };
    assert!(score_host(&dc, None) > score_host(&regular, None));
}

#[test]
fn score_host_smb_and_ssh_ports() {
    let smb = NetworkHost {
        address: "10.0.0.3".to_string(),
        hostname: None,
        open_ports: vec![445],
        services: vec![],
        os_fingerprint: None,
        reachable: true,
    };
    let empty = NetworkHost {
        address: "10.0.0.4".to_string(),
        hostname: None,
        open_ports: vec![],
        services: vec![],
        os_fingerprint: None,
        reachable: true,
    };
    assert!(score_host(&smb, None) > score_host(&empty, None));
}

#[test]
fn prioritize_hosts_excludes_compromised() {
    let hosts = vec![
        NetworkHost {
            address: "10.0.0.1".to_string(),
            hostname: None,
            open_ports: vec![445],
            services: vec![],
            os_fingerprint: None,
            reachable: true,
        },
        NetworkHost {
            address: "10.0.0.2".to_string(),
            hostname: None,
            open_ports: vec![22],
            services: vec![],
            os_fingerprint: None,
            reachable: true,
        },
    ];

    let mut compromised = HashSet::new();
    compromised.insert("10.0.0.1".to_string());

    let prioritized = prioritize_hosts(&hosts, &compromised, None);
    assert_eq!(prioritized.len(), 1);
    assert_eq!(prioritized[0].0.address, "10.0.0.2");
}

#[test]
fn prioritize_hosts_excludes_unreachable() {
    let hosts = vec![
        NetworkHost {
            address: "10.0.0.1".to_string(),
            hostname: None,
            open_ports: vec![445],
            services: vec![],
            os_fingerprint: None,
            reachable: false,
        },
        NetworkHost {
            address: "10.0.0.2".to_string(),
            hostname: None,
            open_ports: vec![22],
            services: vec![],
            os_fingerprint: None,
            reachable: true,
        },
    ];

    let compromised = HashSet::new();
    let prioritized = prioritize_hosts(&hosts, &compromised, None);
    assert_eq!(prioritized.len(), 1);
    assert_eq!(prioritized[0].0.address, "10.0.0.2");
}

#[test]
fn execute_lateral_movement_single_pivot() {
    let config = LateralMovementConfig::default();

    let host_scanner = |_current: &str| -> Vec<NetworkHost> {
        vec![NetworkHost {
            address: "10.0.0.5".to_string(),
            hostname: Some("srv01".to_string()),
            open_ports: vec![445, 22],
            services: vec![],
            os_fingerprint: None,
            reachable: true,
        }]
    };

    let pivot_executor = |from: &str,
                          to: &str,
                          method: LateralMethod,
                          _creds: &[LateralCredential]|
     -> HostAccessResult {
        HostAccessResult {
            host: to.to_string(),
            accessed: method == LateralMethod::CredentialReuse,
            method: Some(LateralMethod::CredentialReuse),
            credential_used: Some("admin".to_string()),
            new_credentials_found: vec![],
            attempts: vec![],
        }
    };

    let creds = vec![LateralCredential {
        username: "admin".to_string(),
        credential_type: LateralCredentialType::Password,
        credential_value: "Password123".to_string(),
        source_host: "10.0.0.1".to_string(),
        domain: None,
    }];

    let result =
        execute_lateral_movement("10.0.0.1", &creds, &config, host_scanner, pivot_executor);
    assert_eq!(result.total_pivots, 1);
    assert!(result.hosts_compromised.contains(&"10.0.0.5".to_string()));
    assert!(result.hosts_compromised.contains(&"10.0.0.1".to_string()));
    assert_eq!(result.pivot_path.len(), 1);
    assert_eq!(result.pivot_path[0].to_host, "10.0.0.5");
}

#[test]
fn execute_lateral_movement_no_reachable_hosts() {
    let config = LateralMovementConfig::default();

    let host_scanner = |_: &str| -> Vec<NetworkHost> { vec![] };

    let pivot_executor =
        |_: &str, _: &str, _: LateralMethod, _: &[LateralCredential]| -> HostAccessResult {
            HostAccessResult {
                host: String::new(),
                accessed: false,
                method: None,
                credential_used: None,
                new_credentials_found: vec![],
                attempts: vec![],
            }
        };

    let result = execute_lateral_movement("10.0.0.1", &[], &config, host_scanner, pivot_executor);
    assert_eq!(result.total_pivots, 0);
    assert_eq!(result.hosts_compromised.len(), 1);
    assert!(!result.domain_admin_obtained);
    assert!(!result.objective_host_reached);
}

#[test]
fn execute_lateral_movement_reaches_objective() {
    let config = LateralMovementConfig {
        objective_host: Some("10.0.0.99".to_string()),
        ..Default::default()
    };

    let host_scanner = |current: &str| -> Vec<NetworkHost> {
        match current {
            "10.0.0.1" => vec![NetworkHost {
                address: "10.0.0.50".to_string(),
                hostname: None,
                open_ports: vec![445],
                services: vec![],
                os_fingerprint: None,
                reachable: true,
            }],
            "10.0.0.50" => vec![NetworkHost {
                address: "10.0.0.99".to_string(),
                hostname: None,
                open_ports: vec![22, 445],
                services: vec![],
                os_fingerprint: None,
                reachable: true,
            }],
            _ => vec![],
        }
    };

    let pivot_executor =
        |_: &str, to: &str, _: LateralMethod, _: &[LateralCredential]| -> HostAccessResult {
            HostAccessResult {
                host: to.to_string(),
                accessed: true,
                method: Some(LateralMethod::CredentialReuse),
                credential_used: Some("admin".to_string()),
                new_credentials_found: vec![],
                attempts: vec![],
            }
        };

    let result = execute_lateral_movement("10.0.0.1", &[], &config, host_scanner, pivot_executor);
    assert!(result.objective_host_reached);
    assert_eq!(result.total_pivots, 2);
}

#[test]
fn execute_lateral_movement_respects_max_pivots() {
    let config = LateralMovementConfig {
        max_pivots: 2,
        ..Default::default()
    };

    let mut counter = 0u32;
    let host_scanner = move |_: &str| -> Vec<NetworkHost> {
        counter += 1;
        vec![NetworkHost {
            address: format!("10.0.0.{counter}"),
            hostname: None,
            open_ports: vec![22],
            services: vec![],
            os_fingerprint: None,
            reachable: true,
        }]
    };

    let pivot_executor =
        |_: &str, to: &str, _: LateralMethod, _: &[LateralCredential]| -> HostAccessResult {
            HostAccessResult {
                host: to.to_string(),
                accessed: true,
                method: Some(LateralMethod::CredentialReuse),
                credential_used: None,
                new_credentials_found: vec![],
                attempts: vec![],
            }
        };

    let result = execute_lateral_movement("10.0.0.0", &[], &config, host_scanner, pivot_executor);
    assert_eq!(result.total_pivots, 2);
}

#[test]
fn execute_lateral_movement_discovers_da_creds() {
    let config = LateralMovementConfig::default();

    let host_scanner = |_: &str| -> Vec<NetworkHost> {
        vec![NetworkHost {
            address: "10.0.0.10".to_string(),
            hostname: Some("dc01".to_string()),
            open_ports: vec![88, 445],
            services: vec!["domain controller".to_string()],
            os_fingerprint: None,
            reachable: true,
        }]
    };

    let pivot_executor =
        |_: &str, to: &str, _: LateralMethod, _: &[LateralCredential]| -> HostAccessResult {
            HostAccessResult {
                host: to.to_string(),
                accessed: true,
                method: Some(LateralMethod::Kerberoast),
                credential_used: None,
                new_credentials_found: vec![LateralCredential {
                    username: "domain_admin".to_string(),
                    credential_type: LateralCredentialType::KerberosTicket,
                    credential_value: "TGT:krbtgt".to_string(),
                    source_host: to.to_string(),
                    domain: Some("corp.local".to_string()),
                }],
                attempts: vec![],
            }
        };

    let result = execute_lateral_movement("10.0.0.1", &[], &config, host_scanner, pivot_executor);
    assert!(result.domain_admin_obtained);
    assert!(!result.new_credentials_discovered.is_empty());
}

#[test]
fn lateral_movement_config_defaults() {
    let config = LateralMovementConfig::default();
    assert_eq!(config.max_pivots, 10);
    assert_eq!(config.max_hosts, 50);
    assert!(config.objective_host.is_none());
    assert!(config.try_credential_reuse);
    assert!(config.try_kerberoast);
    assert!(config.try_pass_the_hash);
    assert!(config.try_shared_admin);
    assert!(!config.stealth_mode);
}
