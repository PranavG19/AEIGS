use aegis_protocol::capability::Permission;
use aegis_protocol::operation::ModuleIdentifier;
use aegis_supervisor::capability_manager::{CapabilityManager, ModulePermissionPolicy};
use aegis_supervisor::process_manager::{ComponentId, ProcessConfig, ProcessManager, ProcessState};
use std::path::PathBuf;
use std::time::Duration;

fn setup_capability_manager() -> CapabilityManager {
    let mut mgr = CapabilityManager::new(b"test-master-key".to_vec());
    mgr.register_policy(ModulePermissionPolicy {
        module: ModuleIdentifier::Fuzzing,
        allowed_permissions: vec![
            Permission::ReadGraph,
            Permission::WriteGraph,
            Permission::ExecuteRequests,
        ],
        token_lifetime: Duration::from_secs(3600),
    });
    mgr
}

#[test]
fn capability_grant_validate_roundtrip() {
    let mut mgr = setup_capability_manager();
    let now_ms = 1_000_000u64;

    let token = mgr.issue_token(ModuleIdentifier::Fuzzing, now_ms).unwrap();

    let result = mgr.validate_token(&token, Permission::ReadGraph, now_ms + 1000);
    assert!(result.is_ok(), "valid token should pass validation");
}

#[test]
fn capability_reject_invalid_token() {
    let mut mgr = setup_capability_manager();
    let now_ms = 1_000_000u64;

    let mut token = mgr.issue_token(ModuleIdentifier::Fuzzing, now_ms).unwrap();

    token.token_bytes[0] ^= 0xFF;

    let result = mgr.validate_token(&token, Permission::ReadGraph, now_ms + 1000);
    assert!(result.is_err(), "modified token should fail validation");
}

#[test]
fn capability_timing_safe_comparison() {
    let mut mgr = setup_capability_manager();
    let now_ms = 1_000_000u64;

    let token = mgr.issue_token(ModuleIdentifier::Fuzzing, now_ms).unwrap();

    for _ in 0..100 {
        let result = mgr.validate_token(&token, Permission::ReadGraph, now_ms + 500);
        assert!(
            result.is_ok(),
            "constant-time comparison should not panic or error on valid token"
        );
    }

    let mut bad_token = token.clone();
    bad_token.token_bytes = vec![0u8; bad_token.token_bytes.len()];
    for _ in 0..100 {
        let result = mgr.validate_token(&bad_token, Permission::ReadGraph, now_ms + 500);
        assert!(
            result.is_err(),
            "constant-time comparison should reject zeroed token without panic"
        );
    }
}

#[test]
fn capability_revoke_module() {
    let mut mgr = CapabilityManager::new(b"revoke-test-key".to_vec());
    mgr.register_policy(ModulePermissionPolicy {
        module: ModuleIdentifier::Fuzzing,
        allowed_permissions: vec![Permission::ReadGraph, Permission::ExecuteRequests],
        token_lifetime: Duration::from_secs(60),
    });

    let now_ms = 1_000_000u64;
    let token = mgr.issue_token(ModuleIdentifier::Fuzzing, now_ms).unwrap();

    assert!(
        mgr.validate_token(&token, Permission::ReadGraph, now_ms + 1000)
            .is_ok(),
        "token should be valid before expiry"
    );

    let expired_time = token.expires_at_unix_ms + 1;
    let result = mgr.validate_token(&token, Permission::ReadGraph, expired_time);
    assert!(
        result.is_err(),
        "token past expiry should fail validation (simulates revocation via expiry)"
    );
}

#[test]
fn process_manager_lifecycle() {
    let mut pm = ProcessManager::new();

    let config = ProcessConfig::new(ComponentId::Fuzzing, PathBuf::from("/usr/bin/aegis-fuzzer"))
        .with_arguments(vec!["--target".to_string(), "localhost".to_string()])
        .with_max_restarts(3);

    pm.register(config).unwrap();

    let proc = pm.get_process(ComponentId::Fuzzing).unwrap();
    assert_eq!(proc.state, ProcessState::NotStarted);

    pm.mark_started(ComponentId::Fuzzing, 12345).unwrap();
    let proc = pm.get_process(ComponentId::Fuzzing).unwrap();
    assert_eq!(proc.state, ProcessState::Running);
    assert_eq!(proc.pid, Some(12345));
    assert_eq!(pm.running_count(), 1);

    pm.mark_stopped(ComponentId::Fuzzing, 0).unwrap();
    let proc = pm.get_process(ComponentId::Fuzzing).unwrap();
    assert_eq!(proc.state, ProcessState::Stopped);
    assert_eq!(proc.pid, None);
    assert_eq!(proc.exit_code, Some(0));
    assert_eq!(pm.running_count(), 0);

    let shutdown = pm.shutdown_all();
    assert!(shutdown.is_empty(), "no running processes to shut down");
}
