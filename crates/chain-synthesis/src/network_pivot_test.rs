use crate::network_pivot::*;

/// Builds a realistic test network with 3 segments and 10+ hosts.
fn build_test_network() -> NetworkPivotPlanner {
    let mut planner = NetworkPivotPlanner::new();

    planner.add_segment("dmz".into(), "10.0.1.0/24".into(), "DMZ / perimeter".into());
    planner.add_segment("corp".into(), "10.0.2.0/24".into(), "Corporate LAN".into());
    planner.add_segment(
        "prod".into(),
        "10.0.3.0/24".into(),
        "Production servers".into(),
    );

    // DMZ hosts
    let web = planner.add_host(
        "web-01".into(),
        "10.0.1.10".into(),
        "dmz".into(),
        vec![
            Service {
                port: 80,
                protocol: ServiceProtocol::Http,
                version: None,
            },
            Service {
                port: 443,
                protocol: ServiceProtocol::Https,
                version: None,
            },
            Service {
                port: 22,
                protocol: ServiceProtocol::Ssh,
                version: Some("8.9".into()),
            },
        ],
        OsType::Linux,
        false,
    );
    let _mail = planner.add_host(
        "mail-01".into(),
        "10.0.1.11".into(),
        "dmz".into(),
        vec![
            Service {
                port: 25,
                protocol: ServiceProtocol::Http,
                version: None,
            },
            Service {
                port: 22,
                protocol: ServiceProtocol::Ssh,
                version: None,
            },
        ],
        OsType::Linux,
        false,
    );
    let vpn = planner.add_host(
        "vpn-gw".into(),
        "10.0.1.12".into(),
        "dmz".into(),
        vec![
            Service {
                port: 443,
                protocol: ServiceProtocol::Https,
                version: None,
            },
            Service {
                port: 22,
                protocol: ServiceProtocol::Ssh,
                version: None,
            },
        ],
        OsType::Linux,
        false,
    );

    // Corp hosts
    let dc = planner.add_host(
        "dc-01".into(),
        "10.0.2.10".into(),
        "corp".into(),
        vec![
            Service {
                port: 445,
                protocol: ServiceProtocol::Smb,
                version: None,
            },
            Service {
                port: 88,
                protocol: ServiceProtocol::Kerberos,
                version: None,
            },
            Service {
                port: 389,
                protocol: ServiceProtocol::Ldap,
                version: None,
            },
            Service {
                port: 5985,
                protocol: ServiceProtocol::Winrm,
                version: None,
            },
            Service {
                port: 3389,
                protocol: ServiceProtocol::Rdp,
                version: None,
            },
        ],
        OsType::Windows,
        true,
    );
    let workstation = planner.add_host(
        "ws-01".into(),
        "10.0.2.11".into(),
        "corp".into(),
        vec![
            Service {
                port: 445,
                protocol: ServiceProtocol::Smb,
                version: None,
            },
            Service {
                port: 3389,
                protocol: ServiceProtocol::Rdp,
                version: None,
            },
            Service {
                port: 5985,
                protocol: ServiceProtocol::Winrm,
                version: None,
            },
        ],
        OsType::Windows,
        false,
    );
    let jump = planner.add_host(
        "jump-01".into(),
        "10.0.2.12".into(),
        "corp".into(),
        vec![
            Service {
                port: 22,
                protocol: ServiceProtocol::Ssh,
                version: None,
            },
            Service {
                port: 3389,
                protocol: ServiceProtocol::Rdp,
                version: None,
            },
        ],
        OsType::Linux,
        false,
    );
    let _fileserver = planner.add_host(
        "fs-01".into(),
        "10.0.2.13".into(),
        "corp".into(),
        vec![Service {
            port: 445,
            protocol: ServiceProtocol::Smb,
            version: None,
        }],
        OsType::Windows,
        false,
    );

    // Prod hosts
    let dbprod = planner.add_host(
        "db-prod-01".into(),
        "10.0.3.10".into(),
        "prod".into(),
        vec![
            Service {
                port: 1433,
                protocol: ServiceProtocol::Mssql,
                version: Some("2019".into()),
            },
            Service {
                port: 5985,
                protocol: ServiceProtocol::Winrm,
                version: None,
            },
        ],
        OsType::Windows,
        true,
    );
    let appprod = planner.add_host(
        "app-prod-01".into(),
        "10.0.3.11".into(),
        "prod".into(),
        vec![
            Service {
                port: 8080,
                protocol: ServiceProtocol::Http,
                version: None,
            },
            Service {
                port: 22,
                protocol: ServiceProtocol::Ssh,
                version: None,
            },
        ],
        OsType::Linux,
        true,
    );
    let container = planner.add_host(
        "k8s-node-01".into(),
        "10.0.3.12".into(),
        "prod".into(),
        vec![
            Service {
                port: 6443,
                protocol: ServiceProtocol::KubernetesApi,
                version: None,
            },
            Service {
                port: 2375,
                protocol: ServiceProtocol::DockerApi,
                version: None,
            },
        ],
        OsType::Container,
        true,
    );

    // Connectivity between segments
    planner.record_connectivity(&"dmz".into(), &"corp".into(), 22);
    planner.record_connectivity(&"dmz".into(), &"corp".into(), 3389);
    planner.record_connectivity(&"corp".into(), &"prod".into(), 22);
    planner.record_connectivity(&"corp".into(), &"prod".into(), 1433);
    planner.record_connectivity(&"corp".into(), &"prod".into(), 8080);
    planner.record_connectivity(&"corp".into(), &"prod".into(), 5985);
    planner.record_connectivity(&"corp".into(), &"prod".into(), 6443);
    planner.record_connectivity(&"corp".into(), &"prod".into(), 2375);

    // Credentials
    planner.add_credential(
        CredentialType::SshPrivateKey,
        "deploy".into(),
        web,
        vec![jump, appprod],
    );
    planner.add_credential(
        CredentialType::NtlmHash,
        "admin".into(),
        workstation,
        vec![dc, dbprod],
    );
    planner.add_credential(
        CredentialType::KerberosTicket,
        "svc-sql".into(),
        dc,
        vec![dbprod],
    );
    planner.add_credential(
        CredentialType::IamRole,
        "ecs-task-role".into(),
        container,
        vec![appprod],
    );

    // Mark web server as initial compromise
    planner.mark_compromised(web);
    planner.mark_compromised(vpn);

    planner.build_pivot_edges();
    planner
}

#[test]
fn test_network_has_ten_plus_hosts() {
    let planner = build_test_network();
    assert!(
        planner.host_count() >= 10,
        "expected ≥10 hosts, got {}",
        planner.host_count()
    );
}

#[test]
fn test_network_has_three_segments() {
    let planner = build_test_network();
    assert_eq!(planner.segment_count(), 3);
}

#[test]
fn test_hosts_per_segment() {
    let planner = build_test_network();
    let counts = planner.hosts_per_segment();
    assert_eq!(counts["dmz"], 3);
    assert_eq!(counts["corp"], 4);
    assert_eq!(counts["prod"], 3);
}

#[test]
fn test_mark_compromised() {
    let mut planner = NetworkPivotPlanner::new();
    planner.add_segment("seg".into(), "10.0.0.0/24".into(), "test".into());
    let h = planner.add_host(
        "host".into(),
        "10.0.0.1".into(),
        "seg".into(),
        vec![],
        OsType::Linux,
        false,
    );
    assert!(!planner.host(h).unwrap().compromised);
    assert!(planner.mark_compromised(h));
    assert!(planner.host(h).unwrap().compromised);
}

#[test]
fn test_mark_compromised_nonexistent_returns_false() {
    let mut planner = NetworkPivotPlanner::new();
    assert!(!planner.mark_compromised(999));
}

#[test]
fn test_pivot_edges_built() {
    let planner = build_test_network();
    assert!(
        planner.edge_count() > 0,
        "expected edges after build_pivot_edges"
    );
}

#[test]
fn test_find_optimal_path_same_segment() {
    let planner = build_test_network();
    // web-01 (id=0) to mail-01 (id=1) — same segment
    let path = planner.find_optimal_path(0, 1);
    assert!(path.is_some(), "should find path within same segment");
    let path = path.unwrap();
    assert!(!path.hops.is_empty());
    assert!(path.total_difficulty > 0.0);
}

#[test]
fn test_find_optimal_path_cross_segment() {
    let planner = build_test_network();
    // web-01 (id=0) in dmz to jump-01 (id=5) in corp
    let path = planner.find_optimal_path(0, 5);
    assert!(path.is_some(), "should find cross-segment path");
    let path = path.unwrap();
    assert!(path.total_difficulty > 0.0);
}

#[test]
fn test_find_optimal_path_no_route() {
    let mut planner = NetworkPivotPlanner::new();
    planner.add_segment("a".into(), "10.0.0.0/24".into(), "seg a".into());
    planner.add_segment("b".into(), "10.0.1.0/24".into(), "seg b".into());
    let h1 = planner.add_host(
        "h1".into(),
        "10.0.0.1".into(),
        "a".into(),
        vec![],
        OsType::Linux,
        false,
    );
    let h2 = planner.add_host(
        "h2".into(),
        "10.0.1.1".into(),
        "b".into(),
        vec![],
        OsType::Linux,
        false,
    );
    planner.build_pivot_edges();
    let path = planner.find_optimal_path(h1, h2);
    assert!(path.is_none(), "no connectivity recorded → no path");
}

#[test]
fn test_identify_pivot_points() {
    let planner = build_test_network();
    let pivots = planner.identify_pivot_points();
    assert!(
        !pivots.is_empty(),
        "compromised hosts with cross-segment reach should appear"
    );
    // web-01 is compromised and can reach corp via SSH
    let web_pivot = pivots.iter().find(|p| p.host_id == 0);
    assert!(web_pivot.is_some(), "web-01 should be a pivot point");
    let web_pivot = web_pivot.unwrap();
    assert!(
        web_pivot.reachable_segments.contains(&"corp".to_string()),
        "web-01 should reach corp segment"
    );
}

#[test]
fn test_pivot_points_sorted_by_strategic_value() {
    let planner = build_test_network();
    let pivots = planner.identify_pivot_points();
    for window in pivots.windows(2) {
        assert!(
            window[0].strategic_value >= window[1].strategic_value,
            "pivot points should be sorted descending by strategic_value"
        );
    }
}

#[test]
fn test_credential_access_matrix() {
    let planner = build_test_network();
    let matrix = planner.credential_access_matrix();
    assert!(!matrix.is_empty(), "should have credential access entries");
    // SSH key credential (id=0) should have jump-01 and app-prod-01
    let ssh_entry = matrix.iter().find(|e| e.credential_id == 0);
    assert!(ssh_entry.is_some());
    let ssh_entry = ssh_entry.unwrap();
    assert_eq!(ssh_entry.credential_type, CredentialType::SshPrivateKey);
    assert_eq!(ssh_entry.accessible_hosts.len(), 2);
}

#[test]
fn test_credential_access_matrix_sorted() {
    let planner = build_test_network();
    let matrix = planner.credential_access_matrix();
    for window in matrix.windows(2) {
        assert!(window[0].credential_id < window[1].credential_id);
    }
}

#[test]
fn test_infer_firewall_rules() {
    let planner = build_test_network();
    let rules = planner.infer_firewall_rules();
    assert!(!rules.is_empty());

    let dmz_to_corp = rules
        .iter()
        .find(|r| r.source_segment == "dmz" && r.target_segment == "corp");
    assert!(dmz_to_corp.is_some());
    let rule = dmz_to_corp.unwrap();
    assert!(rule.allowed_ports.contains(&22));
    assert!(rule.allowed_ports.contains(&3389));
    assert!(
        rule.blocked_ports.contains(&445),
        "SMB should be blocked dmz→corp"
    );
}

#[test]
fn test_firewall_rules_blocked_includes_unobserved() {
    let planner = build_test_network();
    let rules = planner.infer_firewall_rules();
    let dmz_to_prod = rules
        .iter()
        .find(|r| r.source_segment == "dmz" && r.target_segment == "prod");
    assert!(dmz_to_prod.is_some());
    let rule = dmz_to_prod.unwrap();
    // No connectivity recorded dmz→prod
    assert!(rule.allowed_ports.is_empty());
    assert!(!rule.blocked_ports.is_empty());
}

#[test]
fn test_lateral_movement_technique_count() {
    let techniques = [
        LateralMovementTechnique::SshKeyReuse,
        LateralMovementTechnique::SshAgentForwardingHijack,
        LateralMovementTechnique::SmbPassTheHash,
        LateralMovementTechnique::SmbPassTheTicket,
        LateralMovementTechnique::WmiPassTheHash,
        LateralMovementTechnique::RdpSessionHijack,
        LateralMovementTechnique::MssqlLinkedServer,
        LateralMovementTechnique::OracleDbLink,
        LateralMovementTechnique::DockerApiExploit,
        LateralMovementTechnique::KubernetesApiExploit,
        LateralMovementTechnique::CloudIamRoleChaining,
        LateralMovementTechnique::WinrmRemoteExec,
    ];
    assert!(
        techniques.len() >= 6,
        "expected ≥6 technique types, got {}",
        techniques.len()
    );
}

#[test]
fn test_technique_base_difficulty_bounds() {
    let techniques = [
        LateralMovementTechnique::SshKeyReuse,
        LateralMovementTechnique::SshAgentForwardingHijack,
        LateralMovementTechnique::SmbPassTheHash,
        LateralMovementTechnique::RdpSessionHijack,
        LateralMovementTechnique::DockerApiExploit,
        LateralMovementTechnique::CloudIamRoleChaining,
    ];
    for t in &techniques {
        let d = t.base_difficulty();
        assert!(d > 0.0 && d < 1.0, "{t}: difficulty {d} out of (0,1)");
    }
}

#[test]
fn test_technique_display() {
    assert_eq!(
        format!("{}", LateralMovementTechnique::SshKeyReuse),
        "SSH Key Reuse"
    );
    assert_eq!(
        format!("{}", LateralMovementTechnique::SmbPassTheHash),
        "SMB Pass-the-Hash"
    );
}

#[test]
fn test_service_protocol_display() {
    assert_eq!(format!("{}", ServiceProtocol::Ssh), "ssh");
    assert_eq!(
        format!("{}", ServiceProtocol::KubernetesApi),
        "kubernetes-api"
    );
}

#[test]
fn test_credential_type_display() {
    assert_eq!(
        format!("{}", CredentialType::SshPrivateKey),
        "SSH Private Key"
    );
    assert_eq!(format!("{}", CredentialType::NtlmHash), "NTLM Hash");
}

#[test]
fn test_available_techniques_from_compromised() {
    let planner = build_test_network();
    // web-01 (id=0) is Linux, should have SSH-based techniques to SSH-capable targets
    let techs = planner.available_techniques(0);
    assert!(!techs.is_empty(), "web-01 should have outgoing techniques");
    let has_ssh = techs
        .iter()
        .any(|(_, t, _)| *t == LateralMovementTechnique::SshKeyReuse);
    assert!(has_ssh, "Linux host should offer SSH key reuse");
}

#[test]
fn test_available_techniques_sorted_by_difficulty() {
    let planner = build_test_network();
    let techs = planner.available_techniques(0);
    for window in techs.windows(2) {
        assert!(
            window[0].2 <= window[1].2,
            "techniques should be sorted by difficulty"
        );
    }
}

#[test]
fn test_available_techniques_nonexistent_host() {
    let planner = build_test_network();
    let techs = planner.available_techniques(999);
    assert!(techs.is_empty());
}

#[test]
fn test_high_value_targets() {
    let planner = build_test_network();
    let targets = planner.high_value_targets();
    // dc-01 (3), db-prod-01 (7), app-prod-01 (8), k8s-node-01 (9)
    assert_eq!(targets.len(), 4);
}

#[test]
fn test_compromised_hosts() {
    let planner = build_test_network();
    let compromised = planner.compromised_hosts();
    assert_eq!(compromised.len(), 2); // web-01 and vpn-gw
    assert!(compromised.contains(&0)); // web-01
    assert!(compromised.contains(&2)); // vpn-gw
}

#[test]
fn test_all_paths_to_high_value() {
    let planner = build_test_network();
    let paths = planner.all_paths_to_high_value();
    assert!(
        !paths.is_empty(),
        "should find at least one path to a high-value target"
    );
    // Paths should be sorted by total_difficulty
    for window in paths.windows(2) {
        assert!(window[0].2.total_difficulty <= window[1].2.total_difficulty);
    }
}

#[test]
fn test_pivot_path_pivot_count() {
    let planner = build_test_network();
    // Direct same-segment path: pivot_count should be 0 (single hop = 0 pivots)
    if let Some(path) = planner.find_optimal_path(0, 1) {
        assert_eq!(path.pivot_count, path.hops.len().saturating_sub(1));
    }
}

#[test]
fn test_cross_segment_penalty_applied() {
    let planner = build_test_network();
    // Find a cross-segment edge and verify difficulty > base
    if let Some(path) = planner.find_optimal_path(0, 5) {
        let cross_hop = path.hops.iter().find(|h| {
            let from_seg = &planner.host(h.from_host).unwrap().segment;
            let to_seg = &planner.host(h.to_host).unwrap().segment;
            from_seg != to_seg
        });
        if let Some(hop) = cross_hop {
            assert!(
                hop.difficulty > hop.technique.base_difficulty(),
                "cross-segment hop should have penalty"
            );
        }
    }
}

#[test]
fn test_empty_planner() {
    let planner = NetworkPivotPlanner::new();
    assert_eq!(planner.host_count(), 0);
    assert_eq!(planner.segment_count(), 0);
    assert_eq!(planner.edge_count(), 0);
    assert_eq!(planner.credential_count(), 0);
    assert!(planner.compromised_hosts().is_empty());
    assert!(planner.high_value_targets().is_empty());
    assert!(planner.identify_pivot_points().is_empty());
    assert!(planner.credential_access_matrix().is_empty());
    assert!(planner.infer_firewall_rules().is_empty());
}

#[test]
fn test_default_impl() {
    let planner = NetworkPivotPlanner::default();
    assert_eq!(planner.host_count(), 0);
}

#[test]
fn test_os_type_constraint_blocks_technique() {
    let mut planner = NetworkPivotPlanner::new();
    planner.add_segment("s".into(), "10.0.0.0/24".into(), "test".into());
    // Linux host cannot use SMB pass-the-hash (requires Windows source)
    let linux = planner.add_host(
        "linux".into(),
        "10.0.0.1".into(),
        "s".into(),
        vec![Service {
            port: 22,
            protocol: ServiceProtocol::Ssh,
            version: None,
        }],
        OsType::Linux,
        false,
    );
    let win = planner.add_host(
        "win".into(),
        "10.0.0.2".into(),
        "s".into(),
        vec![Service {
            port: 445,
            protocol: ServiceProtocol::Smb,
            version: None,
        }],
        OsType::Windows,
        false,
    );
    planner.build_pivot_edges();
    let techs = planner.available_techniques(linux);
    let has_smb = techs
        .iter()
        .any(|(tid, t, _)| *tid == win && *t == LateralMovementTechnique::SmbPassTheHash);
    assert!(!has_smb, "Linux source should not offer SMB pass-the-hash");
}

#[test]
fn test_service_protocol_constraint_blocks_technique() {
    let mut planner = NetworkPivotPlanner::new();
    planner.add_segment("s".into(), "10.0.0.0/24".into(), "test".into());
    // Target without SSH service should not allow SSH key reuse
    let src = planner.add_host(
        "src".into(),
        "10.0.0.1".into(),
        "s".into(),
        vec![Service {
            port: 22,
            protocol: ServiceProtocol::Ssh,
            version: None,
        }],
        OsType::Linux,
        false,
    );
    let tgt = planner.add_host(
        "tgt".into(),
        "10.0.0.2".into(),
        "s".into(),
        vec![Service {
            port: 80,
            protocol: ServiceProtocol::Http,
            version: None,
        }],
        OsType::Linux,
        false,
    );
    planner.build_pivot_edges();
    let techs = planner.available_techniques(src);
    let has_ssh_to_tgt = techs
        .iter()
        .any(|(tid, t, _)| *tid == tgt && *t == LateralMovementTechnique::SshKeyReuse);
    assert!(
        !has_ssh_to_tgt,
        "target without SSH should block SSH key reuse"
    );
}

#[test]
fn test_record_connectivity_enables_cross_segment() {
    let mut planner = NetworkPivotPlanner::new();
    planner.add_segment("a".into(), "10.0.0.0/24".into(), "seg a".into());
    planner.add_segment("b".into(), "10.0.1.0/24".into(), "seg b".into());
    let h1 = planner.add_host(
        "h1".into(),
        "10.0.0.1".into(),
        "a".into(),
        vec![Service {
            port: 22,
            protocol: ServiceProtocol::Ssh,
            version: None,
        }],
        OsType::Linux,
        false,
    );
    let h2 = planner.add_host(
        "h2".into(),
        "10.0.1.1".into(),
        "b".into(),
        vec![Service {
            port: 22,
            protocol: ServiceProtocol::Ssh,
            version: None,
        }],
        OsType::Linux,
        false,
    );
    // No connectivity yet
    planner.build_pivot_edges();
    assert!(planner.find_optimal_path(h1, h2).is_none());

    // Now add connectivity and rebuild
    let mut planner2 = NetworkPivotPlanner::new();
    planner2.add_segment("a".into(), "10.0.0.0/24".into(), "seg a".into());
    planner2.add_segment("b".into(), "10.0.1.0/24".into(), "seg b".into());
    let h1 = planner2.add_host(
        "h1".into(),
        "10.0.0.1".into(),
        "a".into(),
        vec![Service {
            port: 22,
            protocol: ServiceProtocol::Ssh,
            version: None,
        }],
        OsType::Linux,
        false,
    );
    let h2 = planner2.add_host(
        "h2".into(),
        "10.0.1.1".into(),
        "b".into(),
        vec![Service {
            port: 22,
            protocol: ServiceProtocol::Ssh,
            version: None,
        }],
        OsType::Linux,
        false,
    );
    planner2.record_connectivity(&"a".into(), &"b".into(), 22);
    planner2.build_pivot_edges();
    assert!(planner2.find_optimal_path(h1, h2).is_some());
}

#[test]
fn test_credential_reuse_maps_correctly() {
    let planner = build_test_network();
    let matrix = planner.credential_access_matrix();
    // NTLM hash (id=1) should grant access to dc-01 (3) and db-prod-01 (7)
    let ntlm = matrix.iter().find(|e| e.credential_id == 1).unwrap();
    assert_eq!(ntlm.credential_type, CredentialType::NtlmHash);
    assert!(ntlm.accessible_hosts.contains(&3));
    assert!(ntlm.accessible_hosts.contains(&7));
}

#[test]
fn test_find_optimal_path_self_returns_empty_hops() {
    let planner = build_test_network();
    let path = planner.find_optimal_path(0, 0);
    if let Some(p) = path {
        assert!(p.hops.is_empty());
        assert_eq!(p.total_difficulty, 0.0);
    }
}
