#[cfg(test)]
mod tests {
    use crate::capability_manager::{CapabilityError, CapabilityManager, ModulePermissionPolicy};
    use aegis_protocol::capability::Permission;
    use aegis_protocol::operation::ModuleIdentifier;
    use std::time::Duration;

    fn recon_policy() -> ModulePermissionPolicy {
        ModulePermissionPolicy {
            module: ModuleIdentifier::PassiveRecon,
            allowed_permissions: vec![Permission::ReadGraph, Permission::ReadFilesystem],
            token_lifetime: Duration::from_secs(3600),
        }
    }

    fn fuzzing_policy() -> ModulePermissionPolicy {
        ModulePermissionPolicy {
            module: ModuleIdentifier::Fuzzing,
            allowed_permissions: vec![
                Permission::ReadGraph,
                Permission::WriteGraph,
                Permission::ExecuteRequests,
            ],
            token_lifetime: Duration::from_secs(1800),
        }
    }

    #[test]
    fn issue_token_with_valid_policy() {
        let mut manager = CapabilityManager::new(b"master-key".to_vec());
        manager.register_policy(recon_policy());

        let token = manager
            .issue_token(ModuleIdentifier::PassiveRecon, 1000)
            .unwrap();

        assert_eq!(token.module, ModuleIdentifier::PassiveRecon);
        assert_eq!(token.permissions.len(), 2);
        assert!(token.permissions.contains(&Permission::ReadGraph));
        assert!(token.permissions.contains(&Permission::ReadFilesystem));
        assert_eq!(token.expires_at_unix_ms, 1000 + 3_600_000);
        assert!(!token.token_bytes.is_empty());
    }

    #[test]
    fn issue_token_for_unknown_module_fails() {
        let mut manager = CapabilityManager::new(b"key".to_vec());
        let result = manager.issue_token(ModuleIdentifier::Fuzzing, 1000);
        assert!(matches!(result, Err(CapabilityError::UnknownModule(_))));
    }

    #[test]
    fn validate_token_succeeds_for_valid_permission() {
        let mut manager = CapabilityManager::new(b"master-key".to_vec());
        manager.register_policy(recon_policy());

        let token = manager
            .issue_token(ModuleIdentifier::PassiveRecon, 1000)
            .unwrap();

        let result = manager.validate_token(&token, Permission::ReadGraph, 2000);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_expired_token_fails() {
        let mut manager = CapabilityManager::new(b"master-key".to_vec());
        manager.register_policy(recon_policy());

        let token = manager
            .issue_token(ModuleIdentifier::PassiveRecon, 1000)
            .unwrap();

        let far_future = token.expires_at_unix_ms + 1;
        let result = manager.validate_token(&token, Permission::ReadGraph, far_future);
        assert!(matches!(result, Err(CapabilityError::TokenExpired)));
    }

    #[test]
    fn validate_token_with_missing_permission_fails() {
        let mut manager = CapabilityManager::new(b"master-key".to_vec());
        manager.register_policy(recon_policy());

        let token = manager
            .issue_token(ModuleIdentifier::PassiveRecon, 1000)
            .unwrap();

        let result = manager.validate_token(&token, Permission::WriteGraph, 2000);
        assert!(matches!(
            result,
            Err(CapabilityError::InsufficientPermissions(
                Permission::WriteGraph
            ))
        ));
    }

    #[test]
    fn validate_tampered_token_fails() {
        let mut manager = CapabilityManager::new(b"master-key".to_vec());
        manager.register_policy(recon_policy());

        let mut token = manager
            .issue_token(ModuleIdentifier::PassiveRecon, 1000)
            .unwrap();

        token.token_bytes[0] ^= 0xFF;

        let result = manager.validate_token(&token, Permission::ReadGraph, 2000);
        assert!(matches!(result, Err(CapabilityError::InvalidToken)));
    }

    #[test]
    fn different_keys_produce_different_tokens() {
        let mut manager1 = CapabilityManager::new(b"key-one".to_vec());
        let mut manager2 = CapabilityManager::new(b"key-two".to_vec());

        manager1.register_policy(recon_policy());
        manager2.register_policy(recon_policy());

        let token1 = manager1
            .issue_token(ModuleIdentifier::PassiveRecon, 1000)
            .unwrap();
        let token2 = manager2
            .issue_token(ModuleIdentifier::PassiveRecon, 1000)
            .unwrap();

        assert_ne!(token1.token_bytes, token2.token_bytes);
    }

    #[test]
    fn issued_count_tracks_token_creation() {
        let mut manager = CapabilityManager::new(b"key".to_vec());
        manager.register_policy(recon_policy());
        manager.register_policy(fuzzing_policy());

        assert_eq!(manager.issued_count(), 0);

        manager
            .issue_token(ModuleIdentifier::PassiveRecon, 1000)
            .unwrap();
        assert_eq!(manager.issued_count(), 1);

        manager
            .issue_token(ModuleIdentifier::Fuzzing, 2000)
            .unwrap();
        assert_eq!(manager.issued_count(), 2);
    }

    #[test]
    fn has_policy_and_policy_for() {
        let mut manager = CapabilityManager::new(b"key".to_vec());
        assert!(!manager.has_policy(ModuleIdentifier::PassiveRecon));

        manager.register_policy(recon_policy());
        assert!(manager.has_policy(ModuleIdentifier::PassiveRecon));
        assert!(!manager.has_policy(ModuleIdentifier::Fuzzing));

        let policy = manager.policy_for(ModuleIdentifier::PassiveRecon).unwrap();
        assert_eq!(policy.allowed_permissions.len(), 2);
        assert_eq!(policy.token_lifetime, Duration::from_secs(3600));

        assert!(manager.policy_for(ModuleIdentifier::Fuzzing).is_none());
    }

    #[test]
    fn multiple_modules_get_distinct_tokens() {
        let mut manager = CapabilityManager::new(b"key".to_vec());
        manager.register_policy(recon_policy());
        manager.register_policy(fuzzing_policy());

        let recon_token = manager
            .issue_token(ModuleIdentifier::PassiveRecon, 1000)
            .unwrap();
        let fuzz_token = manager
            .issue_token(ModuleIdentifier::Fuzzing, 1000)
            .unwrap();

        assert_ne!(recon_token.token_bytes, fuzz_token.token_bytes);
        assert_eq!(recon_token.permissions.len(), 2);
        assert_eq!(fuzz_token.permissions.len(), 3);
    }

    #[test]
    fn error_display_is_descriptive() {
        let err = CapabilityError::TokenExpired;
        assert!(err.to_string().contains("expired"));

        let err = CapabilityError::InsufficientPermissions(Permission::WriteGraph);
        assert!(err.to_string().contains("missing permission"));

        let err = CapabilityError::UnknownModule(ModuleIdentifier::Fuzzing);
        assert!(err.to_string().contains("unknown module"));

        let err = CapabilityError::InvalidToken;
        assert!(err.to_string().contains("invalid"));
    }

    #[test]
    fn token_valid_at_boundary_before_expiry() {
        let mut manager = CapabilityManager::new(b"key".to_vec());
        manager.register_policy(recon_policy());

        let token = manager
            .issue_token(ModuleIdentifier::PassiveRecon, 1000)
            .unwrap();

        let just_before_expiry = token.expires_at_unix_ms - 1;
        assert!(
            manager
                .validate_token(&token, Permission::ReadGraph, just_before_expiry)
                .is_ok()
        );

        let at_expiry = token.expires_at_unix_ms;
        assert!(matches!(
            manager.validate_token(&token, Permission::ReadGraph, at_expiry),
            Err(CapabilityError::TokenExpired)
        ));
    }

    #[test]
    fn cross_module_token_validation_with_wrong_key_fails() {
        let mut manager = CapabilityManager::new(b"original-key".to_vec());
        manager.register_policy(recon_policy());
        let token = manager
            .issue_token(ModuleIdentifier::PassiveRecon, 1000)
            .unwrap();

        let other_manager = CapabilityManager::new(b"different-key".to_vec());
        let result = other_manager.validate_token(&token, Permission::ReadGraph, 2000);
        assert!(matches!(result, Err(CapabilityError::InvalidToken)));
    }
}
