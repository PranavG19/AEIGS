use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::persona::PersonaId;

/// TLS fingerprint to emulate during HTTP connections.
///
/// Each variant corresponds to a real browser or tool's JA3 fingerprint,
/// enabling the transport layer to mimic legitimate TLS client hellos
/// when a fingerprint-capable backend (rquest) is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlsFingerprint {
    Chrome120,
    Firefox121,
    Safari17,
    Edge120,
    Curl,
    Default,
}

impl fmt::Display for TlsFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", describe_fingerprint(self))
    }
}

/// Minimum TLS protocol version for connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls12 => write!(f, "TLS 1.2"),
            Self::Tls13 => write!(f, "TLS 1.3"),
        }
    }
}

/// Which HTTP client backend to use for requests.
///
/// `Reqwest` is always available. `Rquest` will provide TLS fingerprint
/// control via JA3/JA4 emulation once the rquest crate is integrated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpClientBackend {
    Reqwest,
    Rquest,
}

impl fmt::Display for HttpClientBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reqwest => write!(f, "reqwest"),
            Self::Rquest => write!(f, "rquest"),
        }
    }
}

/// TLS-level configuration for HTTP connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub fingerprint: TlsFingerprint,
    pub min_tls_version: TlsVersion,
    pub enable_http2: bool,
    pub accept_invalid_certs: bool,
}

impl TlsConfig {
    pub fn with_fingerprint(mut self, fingerprint: TlsFingerprint) -> Self {
        self.fingerprint = fingerprint;
        self
    }

    pub fn with_min_tls_version(mut self, version: TlsVersion) -> Self {
        self.min_tls_version = version;
        self
    }

    pub fn with_http2(mut self, enabled: bool) -> Self {
        self.enable_http2 = enabled;
        self
    }

    pub fn with_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.accept_invalid_certs = accept;
        self
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        default_tls_config()
    }
}

/// Full HTTP client configuration combining backend selection, TLS settings,
/// and connection parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpClientConfig {
    pub backend: HttpClientBackend,
    pub tls: TlsConfig,
    pub timeout_ms: u64,
    pub max_redirects: u32,
    pub user_agent: Option<String>,
}

impl HttpClientConfig {
    pub fn with_backend(mut self, backend: HttpClientBackend) -> Self {
        self.backend = backend;
        self
    }

    pub fn with_tls(mut self, tls: TlsConfig) -> Self {
        self.tls = tls;
        self
    }

    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    pub fn with_max_redirects(mut self, max_redirects: u32) -> Self {
        self.max_redirects = max_redirects;
        self
    }

    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        default_http_client_config()
    }
}

/// Maps persona identities to their corresponding TLS fingerprints,
/// ensuring consistency between HTTP-level persona headers and the
/// TLS client hello fingerprint.
#[derive(Debug, Clone)]
pub struct FingerprintMapping {
    pub mapping: HashMap<PersonaId, TlsFingerprint>,
}

impl FingerprintMapping {
    /// Creates a mapping covering all known persona identities.
    pub fn all_personas() -> Self {
        let personas = [
            PersonaId::ChromeDesktop,
            PersonaId::FirefoxDesktop,
            PersonaId::SafariDesktop,
            PersonaId::ChromeMobile,
            PersonaId::Googlebot,
            PersonaId::EdgeDesktop,
            PersonaId::OperaDesktop,
            PersonaId::SafariMobile,
            PersonaId::CurlClient,
            PersonaId::PythonRequests,
        ];
        let mapping = personas
            .into_iter()
            .map(|p| (p, fingerprint_for_persona(p)))
            .collect();
        Self { mapping }
    }
}

#[derive(Debug, Clone)]
pub enum TlsConfigError {
    UnsupportedBackend(String),
    InvalidFingerprint(String),
    IncompatibleConfig(String),
}

impl fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedBackend(msg) => {
                write!(f, "unsupported backend: {msg}")
            }
            Self::InvalidFingerprint(msg) => {
                write!(f, "invalid fingerprint: {msg}")
            }
            Self::IncompatibleConfig(msg) => {
                write!(f, "incompatible config: {msg}")
            }
        }
    }
}

impl std::error::Error for TlsConfigError {}

/// Returns the TLS fingerprint that matches a given persona's browser identity.
pub fn fingerprint_for_persona(persona_id: PersonaId) -> TlsFingerprint {
    match persona_id {
        PersonaId::ChromeDesktop | PersonaId::ChromeMobile => TlsFingerprint::Chrome120,
        PersonaId::FirefoxDesktop => TlsFingerprint::Firefox121,
        PersonaId::SafariDesktop | PersonaId::SafariMobile => TlsFingerprint::Safari17,
        PersonaId::EdgeDesktop => TlsFingerprint::Edge120,
        PersonaId::CurlClient | PersonaId::PythonRequests => TlsFingerprint::Curl,
        PersonaId::Googlebot | PersonaId::OperaDesktop => TlsFingerprint::Default,
    }
}

/// Returns the JA3 hash string for the given TLS fingerprint.
///
/// These hashes represent the TLS client hello parameters that fingerprint-aware
/// backends (rquest) will emulate. The `Default` variant returns an empty string,
/// meaning no fingerprint emulation is applied.
pub fn ja3_hash(fingerprint: &TlsFingerprint) -> &'static str {
    match fingerprint {
        TlsFingerprint::Chrome120 => {
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
        }
        TlsFingerprint::Firefox121 => {
            "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-27,29-23-24-25-256-257,0"
        }
        TlsFingerprint::Safari17 => {
            "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
        }
        TlsFingerprint::Edge120 => {
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
        }
        TlsFingerprint::Curl => {
            "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-13-43-45-51,29-23-24-25,0"
        }
        TlsFingerprint::Default => "",
    }
}

/// Returns the default TLS configuration: TLS 1.2 minimum, HTTP/2 enabled,
/// no fingerprint emulation, and strict certificate validation.
pub fn default_tls_config() -> TlsConfig {
    TlsConfig {
        fingerprint: TlsFingerprint::Default,
        min_tls_version: TlsVersion::Tls12,
        enable_http2: true,
        accept_invalid_certs: false,
    }
}

/// Returns the default HTTP client configuration: reqwest backend,
/// default TLS settings, 30-second timeout, and 10 max redirects.
pub fn default_http_client_config() -> HttpClientConfig {
    HttpClientConfig {
        backend: HttpClientBackend::Reqwest,
        tls: default_tls_config(),
        timeout_ms: 30000,
        max_redirects: 10,
        user_agent: None,
    }
}

/// Validates that a TLS configuration has no conflicting settings.
///
/// Currently a passthrough stub — all combinations are technically valid.
/// Future backends may impose additional constraints (e.g., rquest may
/// require specific TLS version + fingerprint pairings).
pub fn validate_tls_config(_config: &TlsConfig) -> Result<(), TlsConfigError> {
    Ok(())
}

/// Creates a TLS configuration matching the given persona's expected fingerprint.
///
/// Browser personas get HTTP/2 enabled; CurlClient gets HTTP/2 disabled
/// to match real curl behavior.
pub fn persona_tls_config(persona_id: PersonaId) -> TlsConfig {
    let fingerprint = fingerprint_for_persona(persona_id);
    let enable_http2 = persona_id != PersonaId::CurlClient;
    TlsConfig {
        fingerprint,
        min_tls_version: TlsVersion::Tls12,
        enable_http2,
        accept_invalid_certs: false,
    }
}

/// Returns a human-readable description of the TLS fingerprint.
pub fn describe_fingerprint(fingerprint: &TlsFingerprint) -> &'static str {
    match fingerprint {
        TlsFingerprint::Chrome120 => "Chrome 120 (Windows/macOS)",
        TlsFingerprint::Firefox121 => "Firefox 121 (Windows/macOS/Linux)",
        TlsFingerprint::Safari17 => "Safari 17 (macOS/iOS)",
        TlsFingerprint::Edge120 => "Edge 120 (Windows)",
        TlsFingerprint::Curl => "curl/libcurl default",
        TlsFingerprint::Default => "no fingerprint emulation",
    }
}

#[cfg(test)]
#[path = "tls_config_test.rs"]
mod tls_config_test;
