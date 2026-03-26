use super::k8s_operator::*;
use std::collections::HashMap;

fn make_crd(name: &str, target: &str, preset: &str) -> AegisScanCrd {
    AegisScanCrd {
        api_version: "aegis.io/v1".to_string(),
        kind: "AegisScan".to_string(),
        metadata: CrdMetadata {
            name: name.to_string(),
            namespace: "security".to_string(),
            uid: format!("uid-{name}"),
            labels: HashMap::from([("app".to_string(), "aegis".to_string())]),
            creation_timestamp: 1_700_000_000,
        },
        spec: AegisScanSpec {
            target_url: target.to_string(),
            scan_preset: preset.to_string(),
            schedule: None,
            max_duration_secs: 3600,
            use_llm: true,
            stealth_mode: false,
            scope_domains: vec!["example.com".to_string()],
            notifications: NotificationConfig {
                slack_webhook: Some("https://hooks.slack.com/test".to_string()),
                email: None,
                pagerduty_key: None,
            },
        },
        status: None,
    }
}

fn make_status(phase: ScanPhase) -> AegisScanStatus {
    AegisScanStatus {
        phase,
        start_time: Some(1_700_000_100),
        completion_time: None,
        findings_count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        report_path: None,
        error_message: None,
        last_reconciled: 1_700_000_200,
    }
}

#[test]
fn operator_creation_starts_empty() {
    let op = K8sOperator::new();
    assert!(op.crds.is_empty());
    assert_eq!(op.reconcile_count, 0);
    assert_eq!(op.event_count(), 0);
}

#[test]
fn register_crd_succeeds() {
    let mut op = K8sOperator::new();
    let crd = make_crd("scan-alpha", "http://localhost:3000", "quick");
    assert!(op.register_crd(crd).is_ok());
    assert_eq!(op.crds.len(), 1);
    assert!(op.get_crd("scan-alpha").is_some());
}

#[test]
fn duplicate_crd_rejected() {
    let mut op = K8sOperator::new();
    let crd1 = make_crd("scan-dup", "http://localhost:3000", "quick");
    let crd2 = make_crd("scan-dup", "http://localhost:4000", "thorough");
    op.register_crd(crd1).unwrap();
    let err = op.register_crd(crd2).unwrap_err();
    assert_eq!(err, OperatorError::CrdAlreadyExists("scan-dup".to_string()));
}

#[test]
fn reconcile_no_status_creates() {
    let mut op = K8sOperator::new();
    op.register_crd(make_crd("scan-new", "http://localhost:3000", "thorough"))
        .unwrap();
    let result = op.reconcile("scan-new").unwrap();
    assert_eq!(result.action, ReconcileAction::Create);
    assert!(result.message.contains("Pending"));
    assert_eq!(op.reconcile_count, 1);
}

#[test]
fn reconcile_pending_transitions_to_provisioning() {
    let mut op = K8sOperator::new();
    op.register_crd(make_crd("scan-pend", "http://localhost:3000", "quick"))
        .unwrap();
    op.update_status("scan-pend", make_status(ScanPhase::Pending))
        .unwrap();
    let result = op.reconcile("scan-pend").unwrap();
    assert_eq!(result.action, ReconcileAction::Update);
    assert!(result.message.contains("Provisioning"));
    assert_eq!(result.requeue_after_secs, Some(5));
}

#[test]
fn reconcile_with_status_update_tracks_phase() {
    let mut op = K8sOperator::new();
    op.register_crd(make_crd("scan-upd", "http://localhost:3000", "thorough"))
        .unwrap();

    op.update_status("scan-upd", make_status(ScanPhase::Running))
        .unwrap();

    let crd = op.get_crd("scan-upd").unwrap();
    assert_eq!(crd.status.as_ref().unwrap().phase, ScanPhase::Running);

    let result = op.reconcile("scan-upd").unwrap();
    assert_eq!(result.action, ReconcileAction::Update);
    assert!(result.message.contains("Analyzing"));
}

#[test]
fn unregister_crd_removes_and_returns() {
    let mut op = K8sOperator::new();
    op.register_crd(make_crd("scan-rm", "http://localhost:3000", "quick"))
        .unwrap();
    let removed = op.unregister_crd("scan-rm").unwrap();
    assert_eq!(removed.metadata.name, "scan-rm");
    assert!(op.get_crd("scan-rm").is_none());
}

#[test]
fn unregister_missing_crd_errors() {
    let mut op = K8sOperator::new();
    let err = op.unregister_crd("ghost").unwrap_err();
    assert_eq!(err, OperatorError::CrdNotFound("ghost".to_string()));
}

#[test]
fn get_and_list_crds() {
    let mut op = K8sOperator::new();
    op.register_crd(make_crd("s1", "http://localhost:3000", "quick"))
        .unwrap();
    op.register_crd(make_crd("s2", "http://localhost:4000", "thorough"))
        .unwrap();
    op.register_crd(make_crd("s3", "http://localhost:5000", "paranoid"))
        .unwrap();

    assert!(op.get_crd("s2").is_some());
    assert!(op.get_crd("s99").is_none());
    assert_eq!(op.list_crds().len(), 3);
}

#[test]
fn helm_chart_generation_quick() {
    let mut op = K8sOperator::new();
    op.register_crd(make_crd("helm-q", "http://localhost:3000", "quick"))
        .unwrap();
    let yaml = op.generate_helm_chart("helm-q").unwrap();
    assert!(yaml.contains("ghcr.io/aegis/scanner"));
    assert!(yaml.contains("500m"));
    assert!(yaml.contains("512Mi"));
    assert!(yaml.contains("\"replicas\": 1"));
    assert!(yaml.contains("http://localhost:3000"));
}

#[test]
fn helm_chart_generation_paranoid_gets_more_resources() {
    let mut op = K8sOperator::new();
    op.register_crd(make_crd("helm-p", "http://localhost:3000", "paranoid"))
        .unwrap();
    let yaml = op.generate_helm_chart("helm-p").unwrap();
    assert!(yaml.contains("2000m"));
    assert!(yaml.contains("2Gi"));
    assert!(yaml.contains("\"replicas\": 3"));
}

#[test]
fn helm_chart_missing_crd_errors() {
    let op = K8sOperator::new();
    let err = op.generate_helm_chart("nope").unwrap_err();
    assert_eq!(err, OperatorError::CrdNotFound("nope".to_string()));
}

#[test]
fn pv_config_generation() {
    let mut op = K8sOperator::new();
    op.register_crd(make_crd("pv-t", "http://localhost:3000", "thorough"))
        .unwrap();
    let pv = op.generate_pv_config("pv-t").unwrap();
    assert_eq!(pv.storage_class, "standard");
    assert_eq!(pv.size, "10Gi");
    assert_eq!(pv.access_mode, "ReadWriteOnce");
    assert_eq!(pv.mount_path, "/data/aegis-scans");
}

#[test]
fn pv_config_paranoid_larger() {
    let mut op = K8sOperator::new();
    op.register_crd(make_crd("pv-p", "http://localhost:3000", "paranoid"))
        .unwrap();
    let pv = op.generate_pv_config("pv-p").unwrap();
    assert_eq!(pv.size, "20Gi");
}

#[test]
fn event_logging_accumulates() {
    let mut op = K8sOperator::new();
    op.register_crd(make_crd("ev-1", "http://localhost:3000", "quick"))
        .unwrap();
    let initial = op.event_count();
    assert!(initial >= 1);

    op.reconcile("ev-1").unwrap();
    assert!(op.event_count() > initial);

    let last = op.event_log.last().unwrap();
    assert_eq!(last.crd_name, "ev-1");
}

#[test]
fn reconcile_invalid_empty_target_url() {
    let mut op = K8sOperator::new();
    op.register_crd(make_crd("bad-url", "", "quick")).unwrap();
    let err = op.reconcile("bad-url").unwrap_err();
    assert_eq!(
        err,
        OperatorError::InvalidSpec("target_url must not be empty".to_string())
    );
}

#[test]
fn reconcile_invalid_preset() {
    let mut op = K8sOperator::new();
    op.register_crd(make_crd("bad-preset", "http://localhost:3000", "yolo"))
        .unwrap();
    let err = op.reconcile("bad-preset").unwrap_err();
    match err {
        OperatorError::InvalidSpec(msg) => assert!(msg.contains("yolo")),
        other => panic!("expected InvalidSpec, got {other:?}"),
    }
}

#[test]
fn scan_phase_full_lifecycle() {
    let mut op = K8sOperator::new();
    op.register_crd(make_crd("lifecycle", "http://localhost:3000", "thorough"))
        .unwrap();

    let r = op.reconcile("lifecycle").unwrap();
    assert_eq!(r.action, ReconcileAction::Create);

    let phases = [
        ScanPhase::Pending,
        ScanPhase::Provisioning,
        ScanPhase::Running,
        ScanPhase::Analyzing,
        ScanPhase::Reporting,
    ];

    let expected_next = [
        "Provisioning",
        "Running",
        "Analyzing",
        "Reporting",
        "Completed",
    ];

    for (phase, expected_msg) in phases.iter().zip(expected_next.iter()) {
        op.update_status("lifecycle", make_status(phase.clone()))
            .unwrap();
        let res = op.reconcile("lifecycle").unwrap();
        assert_eq!(res.action, ReconcileAction::Update);
        assert!(
            res.message.contains(expected_msg),
            "expected message to contain '{expected_msg}', got '{}'",
            res.message
        );
    }

    op.update_status("lifecycle", make_status(ScanPhase::Completed))
        .unwrap();
    let final_r = op.reconcile("lifecycle").unwrap();
    assert_eq!(final_r.action, ReconcileAction::NoOp);
}

#[test]
fn failed_and_cancelled_are_terminal() {
    let mut op = K8sOperator::new();
    op.register_crd(make_crd("t-fail", "http://localhost:3000", "quick"))
        .unwrap();
    op.register_crd(make_crd("t-cancel", "http://localhost:3000", "quick"))
        .unwrap();

    op.update_status("t-fail", make_status(ScanPhase::Failed))
        .unwrap();
    op.update_status("t-cancel", make_status(ScanPhase::Cancelled))
        .unwrap();

    assert_eq!(
        op.reconcile("t-fail").unwrap().action,
        ReconcileAction::NoOp
    );
    assert_eq!(
        op.reconcile("t-cancel").unwrap().action,
        ReconcileAction::NoOp
    );
}

#[test]
fn crd_serialization_roundtrip() {
    let crd = make_crd("serde-rt", "http://localhost:3000", "quick");
    let json = serde_json::to_string(&crd).unwrap();
    let deserialized: AegisScanCrd = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.metadata.name, "serde-rt");
    assert_eq!(deserialized.spec.scan_preset, "quick");
    assert_eq!(deserialized.api_version, "aegis.io/v1");
    assert_eq!(deserialized.kind, "AegisScan");
}

#[test]
fn status_update_on_missing_crd_errors() {
    let mut op = K8sOperator::new();
    let err = op
        .update_status("nonexistent", make_status(ScanPhase::Running))
        .unwrap_err();
    assert_eq!(err, OperatorError::CrdNotFound("nonexistent".to_string()));
}
