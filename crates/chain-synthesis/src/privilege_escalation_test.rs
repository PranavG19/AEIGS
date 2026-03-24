use super::privilege_escalation::*;

fn make_role(name: &str, tier: PrivilegeTier, perms: &[&str], is_default: bool) -> RoleNode {
    RoleNode {
        name: name.to_string(),
        tier,
        permissions: perms.iter().map(|s| s.to_string()).collect(),
        is_default,
    }
}

fn five_role_mapper() -> PrivilegeEscalationMapper {
    let mut m = PrivilegeEscalationMapper::new();
    m.add_role(make_role(
        "anonymous",
        PrivilegeTier::Anonymous,
        &["read:public"],
        true,
    ));
    m.add_role(make_role(
        "user",
        PrivilegeTier::User,
        &["read:public", "write:own"],
        false,
    ));
    m.add_role(make_role(
        "editor",
        PrivilegeTier::Editor,
        &["read:public", "write:own", "write:others"],
        false,
    ));
    m.add_role(make_role(
        "admin",
        PrivilegeTier::Admin,
        &["read:public", "write:own", "write:others", "manage:roles"],
        false,
    ));
    m.add_role(make_role(
        "super-admin",
        PrivilegeTier::SuperAdmin,
        &[
            "read:public",
            "write:own",
            "write:others",
            "manage:roles",
            "manage:infra",
        ],
        false,
    ));
    m
}

fn edge_idor(
    param: &str,
    difficulty: f64,
    confidence: f64,
    esc_type: EscalationType,
) -> EscalationEdge {
    EscalationEdge {
        technique: EscalationTechnique::IdorExploit {
            parameter: param.to_string(),
        },
        difficulty,
        confidence,
        escalation_type: esc_type,
        evidence: None,
    }
}

fn edge_broken_auth(
    endpoint: &str,
    difficulty: f64,
    confidence: f64,
    esc_type: EscalationType,
) -> EscalationEdge {
    EscalationEdge {
        technique: EscalationTechnique::BrokenFunctionAuth {
            endpoint: endpoint.to_string(),
        },
        difficulty,
        confidence,
        escalation_type: esc_type,
        evidence: None,
    }
}

// ─── Construction ───────────────────────────────────────────────

#[test]
fn test_new_mapper_is_empty() {
    let m = PrivilegeEscalationMapper::new();
    assert_eq!(m.role_count(), 0);
    assert_eq!(m.edge_count(), 0);
}

#[test]
fn test_default_trait() {
    let m = PrivilegeEscalationMapper::default();
    assert_eq!(m.role_count(), 0);
}

#[test]
fn test_add_role_returns_name() {
    let mut m = PrivilegeEscalationMapper::new();
    let name = m.add_role(make_role("viewer", PrivilegeTier::Guest, &[], false));
    assert_eq!(name, "viewer");
    assert_eq!(m.role_count(), 1);
}

#[test]
fn test_duplicate_role_not_added() {
    let mut m = PrivilegeEscalationMapper::new();
    m.add_role(make_role("user", PrivilegeTier::User, &["a"], false));
    m.add_role(make_role("user", PrivilegeTier::User, &["b"], false));
    assert_eq!(m.role_count(), 1);
}

#[test]
fn test_five_role_graph() {
    let m = five_role_mapper();
    assert_eq!(m.role_count(), 5);
    assert!(m.role("anonymous").is_some());
    assert!(m.role("super-admin").is_some());
    assert!(m.role("nonexistent").is_none());
}

#[test]
fn test_role_names() {
    let m = five_role_mapper();
    let names = m.role_names();
    assert_eq!(names.len(), 5);
    assert!(names.contains(&"admin".to_string()));
}

// ─── Edge operations ────────────────────────────────────────────

#[test]
fn test_add_escalation_success() {
    let mut m = five_role_mapper();
    let added = m.add_escalation(
        "user",
        "admin",
        edge_broken_auth("/admin/panel", 0.3, 0.9, EscalationType::Vertical),
    );
    assert!(added);
    assert_eq!(m.edge_count(), 1);
}

#[test]
fn test_add_escalation_missing_role_returns_false() {
    let mut m = five_role_mapper();
    let added = m.add_escalation(
        "user",
        "ghost",
        edge_broken_auth("/x", 0.5, 0.5, EscalationType::Vertical),
    );
    assert!(!added);
    assert_eq!(m.edge_count(), 0);
}

// ─── Shortest path ──────────────────────────────────────────────

#[test]
fn test_shortest_path_direct() {
    let mut m = five_role_mapper();
    m.add_escalation(
        "user",
        "admin",
        edge_broken_auth("/admin", 0.4, 0.85, EscalationType::Vertical),
    );

    let path = m.shortest_path("user", "admin").unwrap();
    assert_eq!(path.source_role, "user");
    assert_eq!(path.target_role, "admin");
    assert_eq!(path.hop_count(), 1);
    assert!((path.total_difficulty - 0.4).abs() < 1e-9);
}

#[test]
fn test_shortest_path_multi_hop() {
    let mut m = five_role_mapper();
    m.add_escalation(
        "anonymous",
        "user",
        edge_idor("id", 0.2, 0.9, EscalationType::Vertical),
    );
    m.add_escalation(
        "user",
        "editor",
        edge_broken_auth("/edit", 0.3, 0.8, EscalationType::RoleBased),
    );
    m.add_escalation(
        "editor",
        "admin",
        edge_broken_auth("/admin", 0.1, 0.95, EscalationType::RoleBased),
    );

    let path = m.shortest_path("anonymous", "admin").unwrap();
    assert_eq!(path.hop_count(), 3);
    assert!((path.total_difficulty - 0.6).abs() < 1e-9);
}

#[test]
fn test_shortest_path_picks_lower_cost() {
    let mut m = five_role_mapper();
    m.add_escalation(
        "user",
        "admin",
        edge_broken_auth("/admin", 0.9, 0.5, EscalationType::Vertical),
    );
    m.add_escalation(
        "user",
        "editor",
        edge_idor("uid", 0.1, 0.9, EscalationType::RoleBased),
    );
    m.add_escalation(
        "editor",
        "admin",
        edge_broken_auth("/admin", 0.1, 0.9, EscalationType::RoleBased),
    );

    let path = m.shortest_path("user", "admin").unwrap();
    assert_eq!(path.hop_count(), 2);
    assert!(path.total_difficulty < 0.9);
}

#[test]
fn test_shortest_path_no_connection() {
    let m = five_role_mapper();
    let path = m.shortest_path("user", "admin");
    assert!(path.is_none());
}

#[test]
fn test_shortest_path_nonexistent_source() {
    let m = five_role_mapper();
    assert!(m.shortest_path("phantom", "admin").is_none());
}

// ─── All paths ──────────────────────────────────────────────────

#[test]
fn test_all_paths_finds_multiple() {
    let mut m = five_role_mapper();
    m.add_escalation(
        "user",
        "admin",
        edge_broken_auth("/admin", 0.5, 0.8, EscalationType::Vertical),
    );
    m.add_escalation(
        "user",
        "editor",
        edge_idor("uid", 0.2, 0.9, EscalationType::RoleBased),
    );
    m.add_escalation(
        "editor",
        "admin",
        edge_broken_auth("/admin", 0.3, 0.85, EscalationType::RoleBased),
    );

    let paths = m.all_paths("user", "admin", 5);
    assert_eq!(paths.len(), 2);
}

#[test]
fn test_all_paths_depth_limit() {
    let mut m = five_role_mapper();
    m.add_escalation(
        "anonymous",
        "user",
        edge_idor("id", 0.1, 0.9, EscalationType::Vertical),
    );
    m.add_escalation(
        "user",
        "editor",
        edge_idor("id", 0.1, 0.9, EscalationType::RoleBased),
    );
    m.add_escalation(
        "editor",
        "admin",
        edge_idor("id", 0.1, 0.9, EscalationType::RoleBased),
    );
    m.add_escalation(
        "admin",
        "super-admin",
        edge_idor("id", 0.1, 0.9, EscalationType::RoleBased),
    );

    let paths = m.all_paths("anonymous", "super-admin", 2);
    assert!(paths.is_empty());

    let paths = m.all_paths("anonymous", "super-admin", 5);
    assert!(!paths.is_empty());
}

#[test]
fn test_all_paths_nonexistent_returns_empty() {
    let m = five_role_mapper();
    let paths = m.all_paths("ghost", "admin", 5);
    assert!(paths.is_empty());
}

// ─── Reachable roles ────────────────────────────────────────────

#[test]
fn test_reachable_roles_chain() {
    let mut m = five_role_mapper();
    m.add_escalation(
        "anonymous",
        "user",
        edge_idor("id", 0.2, 0.9, EscalationType::Vertical),
    );
    m.add_escalation(
        "user",
        "editor",
        edge_idor("id", 0.2, 0.9, EscalationType::RoleBased),
    );
    m.add_escalation(
        "editor",
        "admin",
        edge_idor("id", 0.2, 0.9, EscalationType::RoleBased),
    );

    let reachable = m.reachable_roles("anonymous");
    assert!(reachable.contains(&"user".to_string()));
    assert!(reachable.contains(&"editor".to_string()));
    assert!(reachable.contains(&"admin".to_string()));
    assert!(!reachable.contains(&"super-admin".to_string()));
}

#[test]
fn test_reachable_roles_isolated() {
    let m = five_role_mapper();
    let reachable = m.reachable_roles("user");
    assert!(reachable.is_empty());
}

#[test]
fn test_reachable_roles_nonexistent() {
    let m = five_role_mapper();
    let reachable = m.reachable_roles("phantom");
    assert!(reachable.is_empty());
}

// ─── Classification ─────────────────────────────────────────────

#[test]
fn test_classify_vertical() {
    let m = five_role_mapper();
    let esc = m.classify_escalation("anonymous", "admin").unwrap();
    assert_eq!(esc, EscalationType::Vertical);
}

#[test]
fn test_classify_role_based_single_step() {
    let m = five_role_mapper();
    let esc = m.classify_escalation("user", "editor").unwrap();
    assert_eq!(esc, EscalationType::RoleBased);
}

#[test]
fn test_classify_horizontal() {
    let mut m = PrivilegeEscalationMapper::new();
    m.add_role(make_role("user-a", PrivilegeTier::User, &[], false));
    m.add_role(make_role("user-b", PrivilegeTier::User, &[], false));
    let esc = m.classify_escalation("user-a", "user-b").unwrap();
    assert_eq!(esc, EscalationType::Horizontal);
}

#[test]
fn test_classify_nonexistent_returns_none() {
    let m = five_role_mapper();
    assert!(m.classify_escalation("ghost", "admin").is_none());
}

// ─── IDOR finding ingestion ─────────────────────────────────────

#[test]
fn test_ingest_idor_findings_creates_edges() {
    let mut m = five_role_mapper();
    let findings = vec![IdorFinding {
        endpoint: "/api/users/123".to_string(),
        parameter: "user_id".to_string(),
        source_privilege: PrivilegeTier::User,
        target_privilege: PrivilegeTier::Admin,
        confidence: 0.85,
    }];
    m.ingest_idor_findings(&findings);
    assert!(m.edge_count() >= 1);
}

#[test]
fn test_ingest_idor_creates_missing_roles() {
    let mut m = PrivilegeEscalationMapper::new();
    let findings = vec![IdorFinding {
        endpoint: "/api/data".to_string(),
        parameter: "obj_id".to_string(),
        source_privilege: PrivilegeTier::Guest,
        target_privilege: PrivilegeTier::Moderator,
        confidence: 0.7,
    }];
    m.ingest_idor_findings(&findings);
    assert_eq!(m.role_count(), 2);
    assert!(m.role("guest").is_some());
    assert!(m.role("moderator").is_some());
}

// ─── Auth finding ingestion ─────────────────────────────────────

#[test]
fn test_ingest_auth_findings() {
    let mut m = five_role_mapper();
    let findings = vec![AuthBreakFinding {
        endpoint: "/api/admin/config".to_string(),
        technique: EscalationTechnique::BrokenFunctionAuth {
            endpoint: "/api/admin/config".to_string(),
        },
        source_role: "user".to_string(),
        target_role: "admin".to_string(),
        confidence: 0.9,
    }];
    m.ingest_auth_findings(&findings);
    assert_eq!(m.edge_count(), 1);
}

#[test]
fn test_ingest_auth_findings_skips_unknown_roles() {
    let mut m = five_role_mapper();
    let findings = vec![AuthBreakFinding {
        endpoint: "/x".to_string(),
        technique: EscalationTechnique::DefaultCredentials,
        source_role: "phantom".to_string(),
        target_role: "admin".to_string(),
        confidence: 0.5,
    }];
    m.ingest_auth_findings(&findings);
    assert_eq!(m.edge_count(), 0);
}

// ─── Implicit escalation detection ──────────────────────────────

#[test]
fn test_detect_implicit_escalations() {
    let mut m = PrivilegeEscalationMapper::new();
    m.add_role(make_role(
        "default-user",
        PrivilegeTier::Guest,
        &["read:public", "read:data", "write:comments", "read:config"],
        true,
    ));
    m.add_role(make_role(
        "editor",
        PrivilegeTier::Editor,
        &[
            "read:public",
            "read:data",
            "write:comments",
            "write:articles",
            "read:config",
        ],
        false,
    ));
    m.detect_implicit_escalations();
    assert!(m.edge_count() >= 1);
}

#[test]
fn test_detect_implicit_no_defaults() {
    let mut m = five_role_mapper();
    let was = m.edge_count();
    m.detect_implicit_escalations();
    let after = m.edge_count();
    assert!(after >= was);
}

// ─── Risk scoring and path properties ───────────────────────────

#[test]
fn test_risk_score_calculation() {
    let path = EscalationPath {
        source_role: "user".to_string(),
        target_role: "admin".to_string(),
        escalation_type: EscalationType::Vertical,
        steps: vec![EscalationStep {
            from_role: "user".to_string(),
            to_role: "admin".to_string(),
            technique: EscalationTechnique::DefaultCredentials,
            difficulty: 0.2,
            confidence: 0.9,
        }],
        total_difficulty: 0.2,
        min_confidence: 0.9,
    };
    let risk = path.risk_score();
    assert!((risk - 0.72).abs() < 1e-9);
}

#[test]
fn test_empty_path_risk_is_zero() {
    let path = EscalationPath {
        source_role: "a".to_string(),
        target_role: "b".to_string(),
        escalation_type: EscalationType::Vertical,
        steps: vec![],
        total_difficulty: 0.0,
        min_confidence: 0.0,
    };
    assert!((path.risk_score() - 0.0).abs() < 1e-9);
}

#[test]
fn test_hop_count() {
    let path = EscalationPath {
        source_role: "a".to_string(),
        target_role: "c".to_string(),
        escalation_type: EscalationType::RoleBased,
        steps: vec![
            EscalationStep {
                from_role: "a".to_string(),
                to_role: "b".to_string(),
                technique: EscalationTechnique::SessionManipulation,
                difficulty: 0.3,
                confidence: 0.8,
            },
            EscalationStep {
                from_role: "b".to_string(),
                to_role: "c".to_string(),
                technique: EscalationTechnique::ApiKeyLeakage,
                difficulty: 0.4,
                confidence: 0.7,
            },
        ],
        total_difficulty: 0.7,
        min_confidence: 0.7,
    };
    assert_eq!(path.hop_count(), 2);
}

// ─── Direct targets ─────────────────────────────────────────────

#[test]
fn test_direct_targets() {
    let mut m = five_role_mapper();
    m.add_escalation(
        "user",
        "editor",
        edge_idor("id", 0.2, 0.9, EscalationType::RoleBased),
    );
    m.add_escalation(
        "user",
        "admin",
        edge_broken_auth("/admin", 0.5, 0.7, EscalationType::Vertical),
    );

    let targets = m.direct_targets("user");
    assert_eq!(targets.len(), 2);
    let target_names: Vec<String> = targets.iter().map(|(n, _)| n.clone()).collect();
    assert!(target_names.contains(&"editor".to_string()));
    assert!(target_names.contains(&"admin".to_string()));
}

#[test]
fn test_direct_targets_empty() {
    let m = five_role_mapper();
    let targets = m.direct_targets("admin");
    assert!(targets.is_empty());
}

// ─── Roles with escalation potential ────────────────────────────

#[test]
fn test_roles_with_escalation_potential() {
    let mut m = five_role_mapper();
    m.add_escalation(
        "user",
        "admin",
        edge_broken_auth("/admin", 0.3, 0.9, EscalationType::Vertical),
    );
    m.add_escalation(
        "anonymous",
        "user",
        edge_idor("id", 0.5, 0.7, EscalationType::Vertical),
    );

    let potential = m.roles_with_escalation_potential();
    assert!(potential.contains(&"user".to_string()));
    assert!(potential.contains(&"anonymous".to_string()));
    assert!(!potential.contains(&"admin".to_string()));
}

// ─── Standard hierarchy builder ─────────────────────────────────

#[test]
fn test_build_standard_role_hierarchy() {
    let m = build_standard_role_hierarchy();
    assert_eq!(m.role_count(), 7);
    assert!(m.role("anonymous").is_some());
    assert!(m.role("guest").is_some());
    assert!(m.role("user").is_some());
    assert!(m.role("editor").is_some());
    assert!(m.role("moderator").is_some());
    assert!(m.role("admin").is_some());
    assert!(m.role("super-admin").is_some());
}

#[test]
fn test_standard_hierarchy_tiers_ordered() {
    let m = build_standard_role_hierarchy();
    let anon = m.role("anonymous").unwrap();
    let user = m.role("user").unwrap();
    let admin = m.role("admin").unwrap();
    assert!(anon.tier < user.tier);
    assert!(user.tier < admin.tier);
}

// ─── Display impls ──────────────────────────────────────────────

#[test]
fn test_escalation_type_display() {
    assert_eq!(EscalationType::Horizontal.to_string(), "horizontal");
    assert_eq!(EscalationType::Vertical.to_string(), "vertical");
    assert_eq!(EscalationType::RoleBased.to_string(), "role-based");
    assert_eq!(EscalationType::FunctionLevel.to_string(), "function-level");
    assert_eq!(EscalationType::DataLevel.to_string(), "data-level");
    assert_eq!(EscalationType::Implicit.to_string(), "implicit");
}

#[test]
fn test_privilege_tier_display() {
    assert_eq!(PrivilegeTier::Anonymous.to_string(), "anonymous");
    assert_eq!(PrivilegeTier::SuperAdmin.to_string(), "super-admin");
}

#[test]
fn test_technique_display() {
    let t = EscalationTechnique::JwtTampering {
        claim: "role".to_string(),
    };
    assert_eq!(t.to_string(), "jwt-tampering(role)");

    let t2 = EscalationTechnique::MassAssignment {
        field: "isAdmin".to_string(),
    };
    assert_eq!(t2.to_string(), "mass-assignment(isAdmin)");
}

// ─── Summary ────────────────────────────────────────────────────

#[test]
fn test_summarize_empty_graph() {
    let m = PrivilegeEscalationMapper::new();
    let summary = m.summarize(5);
    assert_eq!(summary.total_roles, 0);
    assert_eq!(summary.total_paths, 0);
    assert!(summary.highest_risk_path.is_none());
}

#[test]
fn test_summarize_with_paths() {
    let mut m = five_role_mapper();
    m.add_escalation(
        "anonymous",
        "user",
        edge_idor("id", 0.2, 0.9, EscalationType::Vertical),
    );
    m.add_escalation(
        "user",
        "editor",
        edge_broken_auth("/edit", 0.3, 0.8, EscalationType::RoleBased),
    );
    m.add_escalation(
        "user",
        "admin",
        edge_broken_auth("/admin", 0.4, 0.85, EscalationType::Vertical),
    );

    let summary = m.summarize(5);
    assert_eq!(summary.total_roles, 5);
    assert!(summary.total_paths > 0);
    assert!(summary.highest_risk_path.is_some());
}

// ─── Critical roles ─────────────────────────────────────────────

#[test]
fn test_critical_roles() {
    let mut m = five_role_mapper();
    m.add_escalation(
        "anonymous",
        "admin",
        edge_broken_auth("/admin", 0.3, 0.9, EscalationType::Vertical),
    );
    m.add_escalation(
        "user",
        "admin",
        edge_broken_auth("/admin", 0.4, 0.8, EscalationType::Vertical),
    );
    m.add_escalation(
        "editor",
        "admin",
        edge_broken_auth("/admin", 0.2, 0.95, EscalationType::Vertical),
    );

    let critical = m.critical_roles(5);
    assert!(!critical.is_empty());
    assert_eq!(critical[0].0, "admin");
}

// ─── Tier numeric rank ──────────────────────────────────────────

#[test]
fn test_tier_numeric_rank_ordering() {
    assert!(PrivilegeTier::Anonymous.numeric_rank() < PrivilegeTier::Guest.numeric_rank());
    assert!(PrivilegeTier::Guest.numeric_rank() < PrivilegeTier::User.numeric_rank());
    assert!(PrivilegeTier::User.numeric_rank() < PrivilegeTier::Editor.numeric_rank());
    assert!(PrivilegeTier::Editor.numeric_rank() < PrivilegeTier::Moderator.numeric_rank());
    assert!(PrivilegeTier::Moderator.numeric_rank() < PrivilegeTier::Admin.numeric_rank());
    assert!(PrivilegeTier::Admin.numeric_rank() < PrivilegeTier::SuperAdmin.numeric_rank());
}

// ─── Inner graph access ─────────────────────────────────────────

#[test]
fn test_inner_graph_accessible() {
    let mut m = five_role_mapper();
    m.add_escalation(
        "user",
        "admin",
        edge_broken_auth("/admin", 0.3, 0.9, EscalationType::Vertical),
    );
    let g = m.inner_graph();
    assert_eq!(g.node_count(), 5);
    assert_eq!(g.edge_count(), 1);
}

// ─── Integration: full chain with ingested findings ─────────────

#[test]
fn test_full_integration_idor_plus_auth_chain() {
    let mut m = build_standard_role_hierarchy();

    let idor_findings = vec![
        IdorFinding {
            endpoint: "/api/users/profile".to_string(),
            parameter: "user_id".to_string(),
            source_privilege: PrivilegeTier::User,
            target_privilege: PrivilegeTier::User,
            confidence: 0.92,
        },
        IdorFinding {
            endpoint: "/api/admin/settings".to_string(),
            parameter: "admin_id".to_string(),
            source_privilege: PrivilegeTier::User,
            target_privilege: PrivilegeTier::Admin,
            confidence: 0.78,
        },
    ];
    m.ingest_idor_findings(&idor_findings);

    let auth_findings = vec![AuthBreakFinding {
        endpoint: "/api/roles/assign".to_string(),
        technique: EscalationTechnique::RoleInjection {
            parameter: "role".to_string(),
        },
        source_role: "editor".to_string(),
        target_role: "admin".to_string(),
        confidence: 0.88,
    }];
    m.ingest_auth_findings(&auth_findings);

    m.detect_implicit_escalations();

    assert!(m.edge_count() >= 3);

    let path = m.shortest_path("user", "admin");
    assert!(path.is_some());

    let summary = m.summarize(4);
    assert!(summary.total_paths > 0);
    assert!(!summary.critical_roles.is_empty());
}
