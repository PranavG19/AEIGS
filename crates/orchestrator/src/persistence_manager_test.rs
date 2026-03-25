use super::persistence_manager::*;

fn linux_env() -> TargetEnvironment {
    TargetEnvironment {
        os: OsFamily::Linux,
        web_server: Some("nginx".to_string()),
        framework: Some("express".to_string()),
        language: "php".to_string(),
        writable_paths: vec!["/var/www/html/uploads".to_string()],
        has_cron: true,
        has_scheduled_tasks: false,
        has_middleware_support: true,
        has_route_injection: true,
        detection_capabilities: Vec::new(),
    }
}

fn windows_env() -> TargetEnvironment {
    TargetEnvironment {
        os: OsFamily::Windows,
        web_server: Some("IIS".to_string()),
        framework: Some("aspnet".to_string()),
        language: "csharp".to_string(),
        writable_paths: vec!["C:\\inetpub\\wwwroot\\uploads".to_string()],
        has_cron: false,
        has_scheduled_tasks: true,
        has_middleware_support: true,
        has_route_injection: false,
        detection_capabilities: Vec::new(),
    }
}

fn hardened_env() -> TargetEnvironment {
    TargetEnvironment {
        os: OsFamily::Linux,
        web_server: Some("nginx".to_string()),
        framework: Some("django".to_string()),
        language: "python".to_string(),
        writable_paths: vec!["/tmp/uploads".to_string()],
        has_cron: true,
        has_scheduled_tasks: false,
        has_middleware_support: false,
        has_route_injection: false,
        detection_capabilities: vec![
            DetectionCapability::FileIntegrityMonitor,
            DetectionCapability::Edr,
            DetectionCapability::LogAggregation,
        ],
    }
}

#[test]
fn plan_linux_generates_candidates() {
    let mut mgr = PersistenceManager::new(linux_env());
    let plan = mgr.plan();

    assert!(plan.total_candidates >= 3);
    assert!(!plan.primary.name.is_empty());
    assert!(!plan.reasoning.is_empty());
}

#[test]
fn plan_windows_generates_scheduled_task() {
    let mut mgr = PersistenceManager::new(windows_env());
    let plan = mgr.plan();

    let has_schtask = plan.primary.mechanism_type == PersistenceType::ScheduledTask
        || plan
            .fallbacks
            .iter()
            .any(|f| f.mechanism_type == PersistenceType::ScheduledTask);
    assert!(has_schtask);
}

#[test]
fn plan_hardened_filters_by_detection() {
    let mut mgr = PersistenceManager::new(hardened_env());
    let plan = mgr.plan();

    assert!(plan.filtered_by_detection > 0);
    assert!(plan.reasoning.iter().any(|r| r.contains("Filtered")));
}

#[test]
fn deploy_creates_instance() {
    let mut mgr = PersistenceManager::new(linux_env());
    let plan = mgr.plan();

    let idx = mgr.deploy(plan.primary, 1000);
    assert_eq!(idx, 0);
    assert_eq!(mgr.active_instances().len(), 1);
    assert_eq!(mgr.all_instances()[0].state, PersistenceState::Deployed);
}

#[test]
fn verify_updates_state() {
    let mut mgr = PersistenceManager::new(linux_env());
    let plan = mgr.plan();

    let idx = mgr.deploy(plan.primary, 1000);
    assert!(mgr.verify(idx, 2000));
    assert_eq!(mgr.all_instances()[idx].state, PersistenceState::Verified);
    assert_eq!(mgr.all_instances()[idx].last_verified_at_ms, Some(2000));
}

#[test]
fn monitoring_lifecycle() {
    let mut mgr = PersistenceManager::new(linux_env());
    let plan = mgr.plan();

    let idx = mgr.deploy(plan.primary, 1000);
    mgr.verify(idx, 2000);
    assert!(mgr.start_monitoring(idx));
    assert_eq!(mgr.all_instances()[idx].state, PersistenceState::Monitoring);
}

#[test]
fn detection_critical_triggers_cleanup() {
    let mut mgr = PersistenceManager::new(linux_env());
    let plan = mgr.plan();

    let idx = mgr.deploy(plan.primary, 1000);
    let event = DetectionEvent {
        timestamp_ms: 3000,
        indicator: "File integrity alert on web shell path".to_string(),
        severity: DetectionSeverity::Critical,
        source: "OSSEC".to_string(),
    };

    let action = mgr.report_detection(idx, event);
    assert_eq!(action, Some(PersistenceAction::ImmediateCleanup));
    assert_eq!(mgr.all_instances()[idx].state, PersistenceState::Cleaning);
}

#[test]
fn detection_high_triggers_rotation() {
    let mut mgr = PersistenceManager::new(linux_env());
    let plan = mgr.plan();

    let idx = mgr.deploy(plan.primary, 1000);
    let event = DetectionEvent {
        timestamp_ms: 3000,
        indicator: "Anomalous file access pattern".to_string(),
        severity: DetectionSeverity::High,
        source: "EDR".to_string(),
    };

    let action = mgr.report_detection(idx, event);
    assert_eq!(action, Some(PersistenceAction::RotateNow));
    assert_eq!(mgr.all_instances()[idx].state, PersistenceState::Rotating);
}

#[test]
fn detection_medium_increases_monitoring() {
    let mut mgr = PersistenceManager::new(linux_env());
    let plan = mgr.plan();

    let idx = mgr.deploy(plan.primary, 1000);
    let event = DetectionEvent {
        timestamp_ms: 3000,
        indicator: "Unusual HTTP request pattern".to_string(),
        severity: DetectionSeverity::Medium,
        source: "WAF".to_string(),
    };

    let action = mgr.report_detection(idx, event);
    assert_eq!(action, Some(PersistenceAction::IncreaseMonitoring));
}

#[test]
fn detection_low_continues() {
    let mut mgr = PersistenceManager::new(linux_env());
    let plan = mgr.plan();

    let idx = mgr.deploy(plan.primary, 1000);
    let event = DetectionEvent {
        timestamp_ms: 3000,
        indicator: "Minor log entry".to_string(),
        severity: DetectionSeverity::Low,
        source: "syslog".to_string(),
    };

    let action = mgr.report_detection(idx, event);
    assert_eq!(action, Some(PersistenceAction::Continue));
}

#[test]
fn rotate_resets_instance() {
    let mut mgr = PersistenceManager::new(linux_env());
    let plan = mgr.plan();

    let idx = mgr.deploy(plan.primary, 1000);
    mgr.verify(idx, 2000);
    mgr.start_monitoring(idx);

    assert!(mgr.rotate(idx, 5000));
    assert_eq!(mgr.all_instances()[idx].state, PersistenceState::Deployed);
    assert_eq!(mgr.all_instances()[idx].rotation_count, 1);
    assert_eq!(mgr.all_instances()[idx].deployed_at_ms, Some(5000));
}

#[test]
fn cleanup_marks_cleaned() {
    let mut mgr = PersistenceManager::new(linux_env());
    let plan = mgr.plan();

    let idx = mgr.deploy(plan.primary, 1000);
    assert!(mgr.cleanup(idx));
    assert_eq!(mgr.all_instances()[idx].state, PersistenceState::Cleaned);
    assert!(mgr.active_instances().is_empty());
}

#[test]
fn emergency_cleanup_all() {
    let mut mgr = PersistenceManager::new(linux_env());
    let plan = mgr.plan();

    mgr.deploy(plan.primary.clone(), 1000);
    for fb in &plan.fallbacks {
        mgr.deploy(fb.clone(), 2000);
    }

    let cleaned = mgr.emergency_cleanup();
    assert!(cleaned >= 1);
    assert!(mgr.active_instances().is_empty());
}

#[test]
fn full_lifecycle_deploy_verify_monitor_rotate_clean() {
    let mut mgr = PersistenceManager::new(linux_env());
    let plan = mgr.plan();

    let idx = mgr.deploy(plan.primary, 1000);
    assert_eq!(mgr.all_instances()[idx].state, PersistenceState::Deployed);

    mgr.verify(idx, 2000);
    assert_eq!(mgr.all_instances()[idx].state, PersistenceState::Verified);

    mgr.start_monitoring(idx);
    assert_eq!(mgr.all_instances()[idx].state, PersistenceState::Monitoring);

    mgr.rotate(idx, 5000);
    assert_eq!(mgr.all_instances()[idx].state, PersistenceState::Deployed);
    assert_eq!(mgr.all_instances()[idx].rotation_count, 1);

    mgr.cleanup(idx);
    assert_eq!(mgr.all_instances()[idx].state, PersistenceState::Cleaned);
}

#[test]
fn web_shell_is_polymorphic() {
    let mut mgr = PersistenceManager::new(linux_env());
    let plan = mgr.plan();

    let all_mechs: Vec<&PersistenceMechanism> = std::iter::once(&plan.primary)
        .chain(plan.fallbacks.iter())
        .collect();

    let web_shell = all_mechs
        .iter()
        .find(|m| m.mechanism_type == PersistenceType::WebShell);

    if let Some(ws) = web_shell {
        assert!(ws.polymorphic);
    }
}

#[test]
fn primary_selected_by_combined_score() {
    let mut mgr = PersistenceManager::new(linux_env());
    let plan = mgr.plan();

    let primary_score = plan.primary.stealth_score * 0.6 + plan.primary.reliability_score * 0.4;
    for fb in &plan.fallbacks {
        let fb_score = fb.stealth_score * 0.6 + fb.reliability_score * 0.4;
        assert!(primary_score >= fb_score - 0.001);
    }
}

#[test]
fn detection_events_tracked() {
    let mut mgr = PersistenceManager::new(linux_env());
    let plan = mgr.plan();

    let idx = mgr.deploy(plan.primary, 1000);
    mgr.report_detection(
        idx,
        DetectionEvent {
            timestamp_ms: 2000,
            indicator: "test".to_string(),
            severity: DetectionSeverity::Low,
            source: "test".to_string(),
        },
    );
    mgr.report_detection(
        idx,
        DetectionEvent {
            timestamp_ms: 3000,
            indicator: "test2".to_string(),
            severity: DetectionSeverity::Low,
            source: "test".to_string(),
        },
    );

    assert_eq!(mgr.all_instances()[idx].detection_events.len(), 2);
}

#[test]
fn cleanup_procedures_present() {
    let mut mgr = PersistenceManager::new(linux_env());
    let plan = mgr.plan();

    assert!(!plan.primary.cleanup_procedure.is_empty());
    for fb in &plan.fallbacks {
        assert!(!fb.cleanup_procedure.is_empty());
    }
}

#[test]
fn edr_filters_scheduled_tasks_on_windows() {
    let mut env = windows_env();
    env.detection_capabilities = vec![DetectionCapability::Edr];
    let mut mgr = PersistenceManager::new(env);
    let plan = mgr.plan();

    assert!(plan.filtered_by_detection > 0);
    let has_no_schtask_primary = plan.primary.mechanism_type != PersistenceType::ScheduledTask;
    assert!(has_no_schtask_primary);
}

#[test]
fn av_filters_non_polymorphic_webshell() {
    let mut env = linux_env();
    env.detection_capabilities = vec![DetectionCapability::Av];
    let mut mgr = PersistenceManager::new(env);
    let plan = mgr.plan();

    let all: Vec<&PersistenceMechanism> = std::iter::once(&plan.primary)
        .chain(plan.fallbacks.iter())
        .collect();

    for m in &all {
        if m.mechanism_type == PersistenceType::WebShell {
            assert!(m.polymorphic);
        }
    }
}

#[test]
fn invalid_index_returns_false() {
    let mut mgr = PersistenceManager::new(linux_env());
    assert!(!mgr.verify(999, 1000));
    assert!(!mgr.start_monitoring(999));
    assert!(!mgr.rotate(999, 1000));
    assert!(!mgr.cleanup(999));
    assert_eq!(
        mgr.report_detection(
            999,
            DetectionEvent {
                timestamp_ms: 1000,
                indicator: "test".to_string(),
                severity: DetectionSeverity::Low,
                source: "test".to_string(),
            }
        ),
        None
    );
}
