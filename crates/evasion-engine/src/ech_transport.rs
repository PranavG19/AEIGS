use serde::{Deserialize, Serialize};

/// TLS Encrypted Client Hello (ECH) transport configuration and state.
///
/// ECH encrypts the ClientHello SNI field so passive observers and middleboxes
/// cannot determine the target domain. This module handles ECH config discovery,
/// Grease ECH fallback when the server doesn't support ECH, and config retry logic.

/// ECH operational mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EchMode {
    /// Real ECH with server-provided config.
    Real,
    /// GREASE ECH: send a fake ECH extension to blend in with ECH-capable clients.
    Grease,
    /// ECH disabled; standard TLS.
    Disabled,
}

impl std::fmt::Display for EchMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Real => write!(f, "real"),
            Self::Grease => write!(f, "grease"),
            Self::Disabled => write!(f, "disabled"),
        }
    }
}

/// HPKE cipher suite for ECH key encapsulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HpkeSuite {
    /// X25519 + HKDF-SHA256 + AES-128-GCM (most common).
    X25519HkdfSha256Aes128Gcm,
    /// X25519 + HKDF-SHA256 + ChaCha20Poly1305.
    X25519HkdfSha256ChaCha20,
    /// P256 + HKDF-SHA256 + AES-128-GCM.
    P256HkdfSha256Aes128Gcm,
}

/// Parsed ECH configuration from DNS HTTPS/SVCB record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchConfig {
    pub version: u16,
    pub config_id: u8,
    pub public_name: String,
    pub public_key: Vec<u8>,
    pub cipher_suite: HpkeSuite,
    pub max_name_length: u8,
    pub raw_bytes: Vec<u8>,
}

/// ECH discovery result from DNS lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchDiscoveryResult {
    pub domain: String,
    pub configs: Vec<EchConfig>,
    pub discovery_method: DiscoveryMethod,
    pub ttl_seconds: u32,
}

/// How the ECH config was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryMethod {
    DnsHttps,
    DnsSvcb,
    RetryConfig,
    Manual,
}

/// ECH transport configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchTransportConfig {
    pub target_domain: String,
    pub public_name: String,
    pub mode: EchMode,
    pub preferred_suite: HpkeSuite,
    pub enable_retry: bool,
    pub grease_on_failure: bool,
    pub max_retry_attempts: u32,
}

impl Default for EchTransportConfig {
    fn default() -> Self {
        Self {
            target_domain: String::new(),
            public_name: "cloudflare-ech.com".to_string(),
            mode: EchMode::Real,
            preferred_suite: HpkeSuite::X25519HkdfSha256Aes128Gcm,
            enable_retry: true,
            grease_on_failure: true,
            max_retry_attempts: 3,
        }
    }
}

/// State of the ECH transport negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EchNegotiationState {
    NotStarted,
    DiscoveringConfig,
    ConfigObtained,
    EchAccepted,
    EchRejected,
    GreaseFallback,
    Failed,
}

/// GREASE ECH extension payload (fake ECH for fingerprint blending).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GreaseEchPayload {
    pub cipher_suite_id: u16,
    pub config_id: u8,
    pub enc: Vec<u8>,
    pub payload: Vec<u8>,
}

/// ECH transport manager.
pub struct EchTransport {
    config: EchTransportConfig,
    state: EchNegotiationState,
    cached_configs: Vec<EchConfig>,
    retry_count: u32,
    stats: EchStats,
}

/// ECH connection statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EchStats {
    pub configs_discovered: u32,
    pub ech_accepted_count: u32,
    pub ech_rejected_count: u32,
    pub grease_fallback_count: u32,
    pub retry_count: u32,
}

impl EchTransport {
    pub fn new(config: EchTransportConfig) -> Self {
        Self {
            config,
            state: EchNegotiationState::NotStarted,
            cached_configs: Vec::new(),
            retry_count: 0,
            stats: EchStats::default(),
        }
    }

    /// Simulate ECH config discovery from DNS.
    pub fn discover_config(&mut self) -> Result<EchDiscoveryResult, EchTransportError> {
        self.state = EchNegotiationState::DiscoveringConfig;

        let config = EchConfig {
            version: 0xfe0d,
            config_id: 42,
            public_name: self.config.public_name.clone(),
            public_key: generate_mock_public_key(32),
            cipher_suite: self.config.preferred_suite,
            max_name_length: 64,
            raw_bytes: generate_mock_public_key(128),
        };

        self.cached_configs.push(config.clone());
        self.state = EchNegotiationState::ConfigObtained;
        self.stats.configs_discovered += 1;

        Ok(EchDiscoveryResult {
            domain: self.config.target_domain.clone(),
            configs: vec![config],
            discovery_method: DiscoveryMethod::DnsHttps,
            ttl_seconds: 3600,
        })
    }

    /// Attempt ECH handshake with the server.
    pub fn negotiate(&mut self) -> Result<EchNegotiationState, EchTransportError> {
        match self.config.mode {
            EchMode::Disabled => {
                self.state = EchNegotiationState::Failed;
                return Err(EchTransportError::EchDisabled);
            }
            EchMode::Grease => {
                self.state = EchNegotiationState::GreaseFallback;
                self.stats.grease_fallback_count += 1;
                return Ok(self.state);
            }
            EchMode::Real => {}
        }

        if self.cached_configs.is_empty() {
            if self.config.grease_on_failure {
                self.state = EchNegotiationState::GreaseFallback;
                self.stats.grease_fallback_count += 1;
                return Ok(self.state);
            }
            return Err(EchTransportError::NoConfigAvailable);
        }

        self.state = EchNegotiationState::EchAccepted;
        self.stats.ech_accepted_count += 1;
        Ok(self.state)
    }

    /// Handle ECH rejection with retry or GREASE fallback.
    pub fn handle_rejection(
        &mut self,
        retry_config: Option<EchConfig>,
    ) -> Result<EchNegotiationState, EchTransportError> {
        self.stats.ech_rejected_count += 1;
        self.state = EchNegotiationState::EchRejected;

        if let Some(new_config) = retry_config {
            if self.config.enable_retry && self.retry_count < self.config.max_retry_attempts {
                self.retry_count += 1;
                self.stats.retry_count += 1;
                self.cached_configs = vec![new_config];
                self.state = EchNegotiationState::ConfigObtained;
                return Ok(self.state);
            }
        }

        if self.config.grease_on_failure {
            self.state = EchNegotiationState::GreaseFallback;
            self.stats.grease_fallback_count += 1;
            return Ok(self.state);
        }

        self.state = EchNegotiationState::Failed;
        Err(EchTransportError::MaxRetriesExceeded)
    }

    /// Generate a GREASE ECH payload for blending.
    pub fn generate_grease_payload(&self) -> GreaseEchPayload {
        GreaseEchPayload {
            cipher_suite_id: 0x0001,
            config_id: 0,
            enc: generate_mock_public_key(32),
            payload: generate_mock_public_key(128),
        }
    }

    pub fn state(&self) -> EchNegotiationState {
        self.state
    }

    pub fn stats(&self) -> &EchStats {
        &self.stats
    }

    pub fn cached_config_count(&self) -> usize {
        self.cached_configs.len()
    }
}

fn generate_mock_public_key(len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(len);
    let mut state: u64 = 0xabcdef0123456789;
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        key.push((state & 0xFF) as u8);
    }
    key
}

/// Errors from ECH transport operations.
#[derive(Debug)]
pub enum EchTransportError {
    EchDisabled,
    NoConfigAvailable,
    MaxRetriesExceeded,
    DiscoveryFailed(String),
    HandshakeFailed(String),
}

impl std::fmt::Display for EchTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EchDisabled => write!(f, "ECH is disabled"),
            Self::NoConfigAvailable => write!(f, "no ECH config available"),
            Self::MaxRetriesExceeded => write!(f, "maximum retry attempts exceeded"),
            Self::DiscoveryFailed(e) => write!(f, "ECH config discovery failed: {e}"),
            Self::HandshakeFailed(e) => write!(f, "ECH handshake failed: {e}"),
        }
    }
}

impl std::error::Error for EchTransportError {}
