use aegis_protocol::capability::{CapabilityToken, Permission};
use aegis_protocol::operation::ModuleIdentifier;
use std::collections::HashMap;
use std::time::Duration;
use subtle::ConstantTimeEq;

#[derive(Debug)]
pub enum CapabilityError {
    TokenExpired,
    InsufficientPermissions(Permission),
    UnknownModule(ModuleIdentifier),
    InvalidToken,
}

impl std::fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TokenExpired => write!(f, "capability token has expired"),
            Self::InsufficientPermissions(p) => write!(f, "missing permission: {p:?}"),
            Self::UnknownModule(m) => write!(f, "unknown module: {m:?}"),
            Self::InvalidToken => write!(f, "invalid capability token"),
        }
    }
}

impl std::error::Error for CapabilityError {}

#[derive(Debug, Clone)]
pub struct ModulePermissionPolicy {
    pub module: ModuleIdentifier,
    pub allowed_permissions: Vec<Permission>,
    pub token_lifetime: Duration,
}

pub struct CapabilityManager {
    policies: HashMap<ModuleIdentifier, ModulePermissionPolicy>,
    master_key: Vec<u8>,
    issued_count: u64,
}

impl CapabilityManager {
    pub fn new(master_key: Vec<u8>) -> Self {
        Self {
            policies: HashMap::new(),
            master_key,
            issued_count: 0,
        }
    }

    pub fn register_policy(&mut self, policy: ModulePermissionPolicy) {
        self.policies.insert(policy.module, policy);
    }

    pub fn issue_token(
        &mut self,
        module: ModuleIdentifier,
        current_time_ms: u64,
    ) -> Result<CapabilityToken, CapabilityError> {
        let policy = self
            .policies
            .get(&module)
            .ok_or(CapabilityError::UnknownModule(module))?;

        let expires_at = current_time_ms + policy.token_lifetime.as_millis() as u64;

        let token_bytes = self.compute_token_bytes(module, expires_at);

        self.issued_count += 1;

        Ok(CapabilityToken {
            module,
            permissions: policy.allowed_permissions.clone(),
            expires_at_unix_ms: expires_at,
            token_bytes,
        })
    }

    pub fn validate_token(
        &self,
        token: &CapabilityToken,
        required_permission: Permission,
        current_time_ms: u64,
    ) -> Result<(), CapabilityError> {
        if current_time_ms >= token.expires_at_unix_ms {
            return Err(CapabilityError::TokenExpired);
        }

        let expected_bytes = self.compute_token_bytes(token.module, token.expires_at_unix_ms);
        let token_valid = bool::from(token.token_bytes.ct_eq(&expected_bytes));
        if !token_valid {
            return Err(CapabilityError::InvalidToken);
        }

        if !token.permissions.contains(&required_permission) {
            return Err(CapabilityError::InsufficientPermissions(
                required_permission,
            ));
        }

        Ok(())
    }

    pub fn issued_count(&self) -> u64 {
        self.issued_count
    }

    pub fn has_policy(&self, module: ModuleIdentifier) -> bool {
        self.policies.contains_key(&module)
    }

    pub fn policy_for(&self, module: ModuleIdentifier) -> Option<&ModulePermissionPolicy> {
        self.policies.get(&module)
    }

    fn compute_token_bytes(&self, module: ModuleIdentifier, expires_at: u64) -> Vec<u8> {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&self.master_key);
        hasher.update(format!("{module:?}").as_bytes());
        hasher.update(expires_at.to_le_bytes());
        hasher.finalize().to_vec()
    }
}
