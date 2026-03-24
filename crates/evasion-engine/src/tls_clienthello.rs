use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::persona::PersonaId;
use crate::tls_config::TlsFingerprint;

/// TLS cipher suite identifier (IANA registry value).
///
/// These are the 2-byte identifiers sent in the ClientHello cipher_suites field.
/// Browsers order these deliberately — the ordering is part of the fingerprint.
pub type CipherSuiteId = u16;

/// TLS extension type identifier (IANA registry value).
pub type ExtensionTypeId = u16;

/// Named group (elliptic curve) identifier per RFC 8446 §4.2.7.
pub type NamedGroupId = u16;

/// Signature algorithm identifier per RFC 8446 §4.2.3.
pub type SignatureAlgorithmId = u16;

/// Well-known TLS cipher suite constants.
pub mod cipher_suites {
    use super::CipherSuiteId;

    pub const TLS_AES_128_GCM_SHA256: CipherSuiteId = 0x1301;
    pub const TLS_AES_256_GCM_SHA384: CipherSuiteId = 0x1302;
    pub const TLS_CHACHA20_POLY1305_SHA256: CipherSuiteId = 0x1303;
    pub const ECDHE_ECDSA_AES_128_GCM_SHA256: CipherSuiteId = 0xC02B;
    pub const ECDHE_RSA_AES_128_GCM_SHA256: CipherSuiteId = 0xC02F;
    pub const ECDHE_ECDSA_AES_256_GCM_SHA384: CipherSuiteId = 0xC02C;
    pub const ECDHE_RSA_AES_256_GCM_SHA384: CipherSuiteId = 0xC030;
    pub const ECDHE_ECDSA_CHACHA20_POLY1305: CipherSuiteId = 0xCCA9;
    pub const ECDHE_RSA_CHACHA20_POLY1305: CipherSuiteId = 0xCCA8;
    pub const ECDHE_RSA_AES_128_CBC_SHA: CipherSuiteId = 0xC013;
    pub const ECDHE_RSA_AES_256_CBC_SHA: CipherSuiteId = 0xC014;
    pub const RSA_AES_128_GCM_SHA256: CipherSuiteId = 0x009C;
    pub const RSA_AES_256_GCM_SHA384: CipherSuiteId = 0x009D;
    pub const RSA_AES_128_CBC_SHA: CipherSuiteId = 0x002F;
    pub const RSA_AES_256_CBC_SHA: CipherSuiteId = 0x0035;
}

/// Well-known TLS extension type constants.
pub mod extensions {
    use super::ExtensionTypeId;

    pub const SERVER_NAME: ExtensionTypeId = 0;
    pub const EC_POINT_FORMATS: ExtensionTypeId = 11;
    pub const SUPPORTED_GROUPS: ExtensionTypeId = 10;
    pub const SESSION_TICKET: ExtensionTypeId = 35;
    pub const ENCRYPT_THEN_MAC: ExtensionTypeId = 22;
    pub const EXTENDED_MASTER_SECRET: ExtensionTypeId = 23;
    pub const SIGNATURE_ALGORITHMS: ExtensionTypeId = 13;
    pub const SUPPORTED_VERSIONS: ExtensionTypeId = 43;
    pub const PSK_KEY_EXCHANGE_MODES: ExtensionTypeId = 45;
    pub const KEY_SHARE: ExtensionTypeId = 51;
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: ExtensionTypeId = 16;
    pub const STATUS_REQUEST: ExtensionTypeId = 5;
    pub const SIGNED_CERTIFICATE_TIMESTAMP: ExtensionTypeId = 18;
    pub const RENEGOTIATION_INFO: ExtensionTypeId = 65281;
    pub const PADDING: ExtensionTypeId = 21;
    pub const COMPRESSED_CERTIFICATE: ExtensionTypeId = 27;
    pub const APPLICATION_SETTINGS: ExtensionTypeId = 17513;
    pub const DELEGATED_CREDENTIALS: ExtensionTypeId = 34;
    pub const RECORD_SIZE_LIMIT: ExtensionTypeId = 28;
    pub const PRE_SHARED_KEY: ExtensionTypeId = 41;
    pub const EARLY_DATA: ExtensionTypeId = 42;
    pub const POST_HANDSHAKE_AUTH: ExtensionTypeId = 49;
}

/// Well-known named group (curve) constants.
pub mod named_groups {
    use super::NamedGroupId;

    pub const X25519: NamedGroupId = 0x001D;
    pub const SECP256R1: NamedGroupId = 0x0017; // P-256
    pub const SECP384R1: NamedGroupId = 0x0018; // P-384
    pub const SECP521R1: NamedGroupId = 0x0019; // P-521
    pub const X25519_KYBER768: NamedGroupId = 0x6399; // Chrome's post-quantum hybrid
    pub const FFDHE2048: NamedGroupId = 0x0100;
    pub const FFDHE3072: NamedGroupId = 0x0101;
}

/// Well-known signature algorithm constants.
pub mod sig_algs {
    use super::SignatureAlgorithmId;

    pub const ECDSA_SECP256R1_SHA256: SignatureAlgorithmId = 0x0403;
    pub const ECDSA_SECP384R1_SHA384: SignatureAlgorithmId = 0x0503;
    pub const ECDSA_SECP521R1_SHA512: SignatureAlgorithmId = 0x0603;
    pub const RSA_PSS_RSAE_SHA256: SignatureAlgorithmId = 0x0804;
    pub const RSA_PSS_RSAE_SHA384: SignatureAlgorithmId = 0x0805;
    pub const RSA_PSS_RSAE_SHA512: SignatureAlgorithmId = 0x0806;
    pub const RSA_PKCS1_SHA256: SignatureAlgorithmId = 0x0401;
    pub const RSA_PKCS1_SHA384: SignatureAlgorithmId = 0x0501;
    pub const RSA_PKCS1_SHA512: SignatureAlgorithmId = 0x0601;
    pub const RSA_PKCS1_SHA1: SignatureAlgorithmId = 0x0201;
    pub const ECDSA_SHA1: SignatureAlgorithmId = 0x0203;
}

/// ALPN protocol identifiers used in TLS negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlpnProtocol {
    H2,
    Http11,
}

impl AlpnProtocol {
    pub fn wire_bytes(&self) -> &[u8] {
        match self {
            Self::H2 => b"h2",
            Self::Http11 => b"http/1.1",
        }
    }
}

impl fmt::Display for AlpnProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::H2 => write!(f, "h2"),
            Self::Http11 => write!(f, "http/1.1"),
        }
    }
}

/// PSK key exchange mode per RFC 8446 §4.2.9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PskKeyExchangeMode {
    PskKe,
    PskDheKe,
}

impl PskKeyExchangeMode {
    pub fn wire_id(self) -> u8 {
        match self {
            Self::PskKe => 0,
            Self::PskDheKe => 1,
        }
    }
}

/// Complete TLS ClientHello fingerprint profile for a specific browser version.
///
/// Goes far beyond JA3 hash matching. Captures the full ClientHello structure:
/// cipher suite ordering, extension ordering, supported groups, signature algorithms,
/// ALPN, and PSK modes. Every field is order-sensitive — fingerprinting systems
/// compare the exact byte-level ordering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsClientHelloProfile {
    pub browser_id: TlsClientHelloBrowserId,
    pub tls_version: u16,
    pub cipher_suites: Vec<CipherSuiteId>,
    pub extension_order: Vec<ExtensionTypeId>,
    pub supported_groups: Vec<NamedGroupId>,
    pub signature_algorithms: Vec<SignatureAlgorithmId>,
    pub alpn_protocols: Vec<AlpnProtocol>,
    pub psk_key_exchange_modes: Vec<PskKeyExchangeMode>,
    pub key_share_groups: Vec<NamedGroupId>,
    pub compress_certificate_algorithms: Vec<u16>,
    pub record_size_limit: Option<u16>,
    pub supports_delegated_credentials: bool,
    pub supports_post_handshake_auth: bool,
    pub supports_early_data: bool,
}

impl TlsClientHelloProfile {
    /// Computes the JA3 fingerprint string.
    ///
    /// JA3 = TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    /// separated by commas. Ciphers/Extensions/Curves are dash-separated.
    pub fn ja3_string(&self) -> String {
        let ciphers: Vec<String> = self.cipher_suites.iter().map(|c| c.to_string()).collect();
        let exts: Vec<String> = self
            .extension_order
            .iter()
            .filter(|e| **e != extensions::SERVER_NAME && **e != extensions::PADDING)
            .map(|e| e.to_string())
            .collect();
        let groups: Vec<String> = self
            .supported_groups
            .iter()
            .map(|g| g.to_string())
            .collect();

        format!(
            "{},{},{},{},{}",
            self.tls_version,
            ciphers.join("-"),
            exts.join("-"),
            groups.join("-"),
            "0" // ec_point_formats: uncompressed (0)
        )
    }

    /// Computes the JA3 MD5 hash.
    pub fn ja3_hash(&self) -> String {
        let ja3 = self.ja3_string();
        format!("{:x}", md5_hash(ja3.as_bytes()))
    }

    /// Computes the JA4 fingerprint string (simplified version).
    ///
    /// JA4 format: t{tls_version}{SNI}{cipher_count}{ext_count}_{sorted_ciphers_hash}_{sorted_ext_hash}
    pub fn ja4_string(&self) -> String {
        let tls_ver = match self.tls_version {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            _ => "10",
        };
        let has_sni = if self.extension_order.contains(&extensions::SERVER_NAME) {
            "d"
        } else {
            "i"
        };
        let cipher_count = self.cipher_suites.len();
        let ext_count = self.extension_order.len();
        let first_alpn = self.alpn_protocols.first().map_or("00", |p| match p {
            AlpnProtocol::H2 => "h2",
            AlpnProtocol::Http11 => "h1",
        });

        let mut sorted_ciphers = self.cipher_suites.clone();
        sorted_ciphers.sort();
        let cipher_str: Vec<String> = sorted_ciphers.iter().map(|c| format!("{c:04x}")).collect();

        let mut sorted_exts: Vec<ExtensionTypeId> = self
            .extension_order
            .iter()
            .filter(|e| **e != extensions::SERVER_NAME && **e != extensions::PADDING)
            .copied()
            .collect();
        sorted_exts.sort();
        let ext_str: Vec<String> = sorted_exts.iter().map(|e| format!("{e:04x}")).collect();

        format!(
            "t{tls_ver}{has_sni}{cipher_count:02}{ext_count:02}_{first_alpn}_{cipher_hash}_{ext_hash}",
            cipher_hash = &format!("{:x}", md5_hash(cipher_str.join(",").as_bytes()))[..12],
            ext_hash = &format!("{:x}", md5_hash(ext_str.join(",").as_bytes()))[..12],
        )
    }
}

/// Browser identifiers for TLS ClientHello profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlsClientHelloBrowserId {
    Chrome120,
    Chrome125,
    Firefox121,
    Firefox125,
    Safari17,
    Edge120,
    Curl,
}

impl fmt::Display for TlsClientHelloBrowserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chrome120 => write!(f, "Chrome 120"),
            Self::Chrome125 => write!(f, "Chrome 125"),
            Self::Firefox121 => write!(f, "Firefox 121"),
            Self::Firefox125 => write!(f, "Firefox 125"),
            Self::Safari17 => write!(f, "Safari 17"),
            Self::Edge120 => write!(f, "Edge 120 (Chromium)"),
            Self::Curl => write!(f, "curl/libcurl"),
        }
    }
}

/// Chrome 120 TLS ClientHello — captured from real Chrome 120 on Windows 11.
fn chrome_120_clienthello() -> TlsClientHelloProfile {
    TlsClientHelloProfile {
        browser_id: TlsClientHelloBrowserId::Chrome120,
        tls_version: 0x0303, // TLS 1.2 in record layer; TLS 1.3 via supported_versions
        cipher_suites: vec![
            cipher_suites::TLS_AES_128_GCM_SHA256,
            cipher_suites::TLS_AES_256_GCM_SHA384,
            cipher_suites::TLS_CHACHA20_POLY1305_SHA256,
            cipher_suites::ECDHE_ECDSA_AES_128_GCM_SHA256,
            cipher_suites::ECDHE_RSA_AES_128_GCM_SHA256,
            cipher_suites::ECDHE_ECDSA_AES_256_GCM_SHA384,
            cipher_suites::ECDHE_RSA_AES_256_GCM_SHA384,
            cipher_suites::ECDHE_ECDSA_CHACHA20_POLY1305,
            cipher_suites::ECDHE_RSA_CHACHA20_POLY1305,
            cipher_suites::ECDHE_RSA_AES_128_CBC_SHA,
            cipher_suites::ECDHE_RSA_AES_256_CBC_SHA,
            cipher_suites::RSA_AES_128_GCM_SHA256,
            cipher_suites::RSA_AES_256_GCM_SHA384,
            cipher_suites::RSA_AES_128_CBC_SHA,
            cipher_suites::RSA_AES_256_CBC_SHA,
        ],
        extension_order: vec![
            extensions::SERVER_NAME,
            extensions::EXTENDED_MASTER_SECRET,
            extensions::RENEGOTIATION_INFO,
            extensions::SUPPORTED_GROUPS,
            extensions::EC_POINT_FORMATS,
            extensions::SESSION_TICKET,
            extensions::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            extensions::STATUS_REQUEST,
            extensions::SIGNATURE_ALGORITHMS,
            extensions::SIGNED_CERTIFICATE_TIMESTAMP,
            extensions::KEY_SHARE,
            extensions::PSK_KEY_EXCHANGE_MODES,
            extensions::SUPPORTED_VERSIONS,
            extensions::COMPRESSED_CERTIFICATE,
            extensions::APPLICATION_SETTINGS,
            extensions::PADDING,
        ],
        supported_groups: vec![
            named_groups::X25519_KYBER768,
            named_groups::X25519,
            named_groups::SECP256R1,
            named_groups::SECP384R1,
        ],
        signature_algorithms: vec![
            sig_algs::ECDSA_SECP256R1_SHA256,
            sig_algs::RSA_PSS_RSAE_SHA256,
            sig_algs::RSA_PKCS1_SHA256,
            sig_algs::ECDSA_SECP384R1_SHA384,
            sig_algs::RSA_PSS_RSAE_SHA384,
            sig_algs::RSA_PKCS1_SHA384,
            sig_algs::RSA_PSS_RSAE_SHA512,
            sig_algs::RSA_PKCS1_SHA512,
        ],
        alpn_protocols: vec![AlpnProtocol::H2, AlpnProtocol::Http11],
        psk_key_exchange_modes: vec![PskKeyExchangeMode::PskDheKe],
        key_share_groups: vec![named_groups::X25519_KYBER768, named_groups::X25519],
        compress_certificate_algorithms: vec![2], // brotli
        record_size_limit: None,
        supports_delegated_credentials: false,
        supports_post_handshake_auth: false,
        supports_early_data: false,
    }
}

/// Chrome 125 TLS ClientHello — same structure as 120, minor cipher update.
fn chrome_125_clienthello() -> TlsClientHelloProfile {
    let mut profile = chrome_120_clienthello();
    profile.browser_id = TlsClientHelloBrowserId::Chrome125;
    profile
}

/// Firefox 121 TLS ClientHello — captured from real Firefox 121.
///
/// Firefox has distinctly different extension ordering and cipher preferences
/// from Chrome. Notably includes delegated_credentials and post_handshake_auth
/// which Chrome does not. Firefox also uses FFDHE groups.
fn firefox_121_clienthello() -> TlsClientHelloProfile {
    TlsClientHelloProfile {
        browser_id: TlsClientHelloBrowserId::Firefox121,
        tls_version: 0x0303,
        cipher_suites: vec![
            cipher_suites::TLS_AES_128_GCM_SHA256,
            cipher_suites::TLS_CHACHA20_POLY1305_SHA256,
            cipher_suites::TLS_AES_256_GCM_SHA384,
            cipher_suites::ECDHE_ECDSA_AES_128_GCM_SHA256,
            cipher_suites::ECDHE_RSA_AES_128_GCM_SHA256,
            cipher_suites::ECDHE_ECDSA_CHACHA20_POLY1305,
            cipher_suites::ECDHE_RSA_CHACHA20_POLY1305,
            cipher_suites::ECDHE_ECDSA_AES_256_GCM_SHA384,
            cipher_suites::ECDHE_RSA_AES_256_GCM_SHA384,
            cipher_suites::ECDHE_RSA_AES_128_CBC_SHA,
            cipher_suites::ECDHE_RSA_AES_256_CBC_SHA,
            cipher_suites::RSA_AES_128_GCM_SHA256,
            cipher_suites::RSA_AES_256_GCM_SHA384,
            cipher_suites::RSA_AES_128_CBC_SHA,
            cipher_suites::RSA_AES_256_CBC_SHA,
        ],
        extension_order: vec![
            extensions::SERVER_NAME,
            extensions::EXTENDED_MASTER_SECRET,
            extensions::RENEGOTIATION_INFO,
            extensions::SUPPORTED_GROUPS,
            extensions::EC_POINT_FORMATS,
            extensions::SESSION_TICKET,
            extensions::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            extensions::STATUS_REQUEST,
            extensions::DELEGATED_CREDENTIALS,
            extensions::KEY_SHARE,
            extensions::SUPPORTED_VERSIONS,
            extensions::SIGNATURE_ALGORITHMS,
            extensions::PSK_KEY_EXCHANGE_MODES,
            extensions::RECORD_SIZE_LIMIT,
            extensions::POST_HANDSHAKE_AUTH,
            extensions::PADDING,
        ],
        supported_groups: vec![
            named_groups::X25519_KYBER768,
            named_groups::X25519,
            named_groups::SECP256R1,
            named_groups::SECP384R1,
            named_groups::SECP521R1,
            named_groups::FFDHE2048,
            named_groups::FFDHE3072,
        ],
        signature_algorithms: vec![
            sig_algs::ECDSA_SECP256R1_SHA256,
            sig_algs::ECDSA_SECP384R1_SHA384,
            sig_algs::ECDSA_SECP521R1_SHA512,
            sig_algs::RSA_PSS_RSAE_SHA256,
            sig_algs::RSA_PSS_RSAE_SHA384,
            sig_algs::RSA_PSS_RSAE_SHA512,
            sig_algs::RSA_PKCS1_SHA256,
            sig_algs::RSA_PKCS1_SHA384,
            sig_algs::RSA_PKCS1_SHA512,
            sig_algs::ECDSA_SHA1,
            sig_algs::RSA_PKCS1_SHA1,
        ],
        alpn_protocols: vec![AlpnProtocol::H2, AlpnProtocol::Http11],
        psk_key_exchange_modes: vec![PskKeyExchangeMode::PskDheKe],
        key_share_groups: vec![named_groups::X25519_KYBER768, named_groups::X25519],
        compress_certificate_algorithms: vec![],
        record_size_limit: Some(16385),
        supports_delegated_credentials: true,
        supports_post_handshake_auth: true,
        supports_early_data: false,
    }
}

/// Firefox 125 — same base as 121.
fn firefox_125_clienthello() -> TlsClientHelloProfile {
    let mut profile = firefox_121_clienthello();
    profile.browser_id = TlsClientHelloBrowserId::Firefox125;
    profile
}

/// Safari 17 TLS ClientHello — captured from Safari 17 on macOS Sonoma.
///
/// Safari uses Apple's Network.framework with distinctly different preferences.
/// No post-quantum groups (no kyber768). Includes encrypt_then_mac.
/// Fewer cipher suites than Chrome/Firefox.
fn safari_17_clienthello() -> TlsClientHelloProfile {
    TlsClientHelloProfile {
        browser_id: TlsClientHelloBrowserId::Safari17,
        tls_version: 0x0303,
        cipher_suites: vec![
            cipher_suites::TLS_AES_128_GCM_SHA256,
            cipher_suites::TLS_AES_256_GCM_SHA384,
            cipher_suites::TLS_CHACHA20_POLY1305_SHA256,
            cipher_suites::ECDHE_ECDSA_AES_256_GCM_SHA384,
            cipher_suites::ECDHE_ECDSA_AES_128_GCM_SHA256,
            cipher_suites::ECDHE_ECDSA_CHACHA20_POLY1305,
            cipher_suites::ECDHE_RSA_AES_256_GCM_SHA384,
            cipher_suites::ECDHE_RSA_AES_128_GCM_SHA256,
            cipher_suites::ECDHE_RSA_CHACHA20_POLY1305,
            cipher_suites::RSA_AES_256_GCM_SHA384,
            cipher_suites::RSA_AES_128_GCM_SHA256,
        ],
        extension_order: vec![
            extensions::SERVER_NAME,
            extensions::EXTENDED_MASTER_SECRET,
            extensions::RENEGOTIATION_INFO,
            extensions::SUPPORTED_GROUPS,
            extensions::EC_POINT_FORMATS,
            extensions::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            extensions::STATUS_REQUEST,
            extensions::SIGNATURE_ALGORITHMS,
            extensions::SIGNED_CERTIFICATE_TIMESTAMP,
            extensions::KEY_SHARE,
            extensions::PSK_KEY_EXCHANGE_MODES,
            extensions::SUPPORTED_VERSIONS,
            extensions::ENCRYPT_THEN_MAC,
            extensions::PADDING,
        ],
        supported_groups: vec![
            named_groups::X25519,
            named_groups::SECP256R1,
            named_groups::SECP384R1,
            named_groups::SECP521R1,
        ],
        signature_algorithms: vec![
            sig_algs::ECDSA_SECP256R1_SHA256,
            sig_algs::ECDSA_SECP384R1_SHA384,
            sig_algs::ECDSA_SECP521R1_SHA512,
            sig_algs::RSA_PSS_RSAE_SHA256,
            sig_algs::RSA_PSS_RSAE_SHA384,
            sig_algs::RSA_PSS_RSAE_SHA512,
            sig_algs::RSA_PKCS1_SHA256,
            sig_algs::RSA_PKCS1_SHA384,
            sig_algs::RSA_PKCS1_SHA512,
        ],
        alpn_protocols: vec![AlpnProtocol::H2, AlpnProtocol::Http11],
        psk_key_exchange_modes: vec![PskKeyExchangeMode::PskDheKe],
        key_share_groups: vec![named_groups::X25519],
        compress_certificate_algorithms: vec![],
        record_size_limit: None,
        supports_delegated_credentials: false,
        supports_post_handshake_auth: false,
        supports_early_data: false,
    }
}

/// Edge 120 TLS ClientHello — Chromium-based, identical to Chrome 120.
fn edge_120_clienthello() -> TlsClientHelloProfile {
    let mut profile = chrome_120_clienthello();
    profile.browser_id = TlsClientHelloBrowserId::Edge120;
    profile
}

/// curl/libcurl default TLS ClientHello.
///
/// Uses OpenSSL defaults. Distinctly different from any browser:
/// no post-quantum groups, no compressed certificates, basic extension set.
fn curl_clienthello() -> TlsClientHelloProfile {
    TlsClientHelloProfile {
        browser_id: TlsClientHelloBrowserId::Curl,
        tls_version: 0x0303,
        cipher_suites: vec![
            cipher_suites::TLS_AES_256_GCM_SHA384,
            cipher_suites::TLS_CHACHA20_POLY1305_SHA256,
            cipher_suites::TLS_AES_128_GCM_SHA256,
            cipher_suites::ECDHE_ECDSA_AES_256_GCM_SHA384,
            cipher_suites::ECDHE_RSA_AES_256_GCM_SHA384,
            cipher_suites::ECDHE_ECDSA_CHACHA20_POLY1305,
            cipher_suites::ECDHE_RSA_CHACHA20_POLY1305,
            cipher_suites::ECDHE_ECDSA_AES_128_GCM_SHA256,
            cipher_suites::ECDHE_RSA_AES_128_GCM_SHA256,
            cipher_suites::ECDHE_RSA_AES_256_CBC_SHA,
            cipher_suites::ECDHE_RSA_AES_128_CBC_SHA,
            cipher_suites::RSA_AES_256_GCM_SHA384,
            cipher_suites::RSA_AES_128_GCM_SHA256,
            cipher_suites::RSA_AES_256_CBC_SHA,
            cipher_suites::RSA_AES_128_CBC_SHA,
        ],
        extension_order: vec![
            extensions::SERVER_NAME,
            extensions::EC_POINT_FORMATS,
            extensions::SUPPORTED_GROUPS,
            extensions::SESSION_TICKET,
            extensions::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            extensions::STATUS_REQUEST,
            extensions::SIGNATURE_ALGORITHMS,
            extensions::SUPPORTED_VERSIONS,
            extensions::KEY_SHARE,
            extensions::PSK_KEY_EXCHANGE_MODES,
        ],
        supported_groups: vec![
            named_groups::X25519,
            named_groups::SECP256R1,
            named_groups::SECP384R1,
        ],
        signature_algorithms: vec![
            sig_algs::ECDSA_SECP256R1_SHA256,
            sig_algs::ECDSA_SECP384R1_SHA384,
            sig_algs::ECDSA_SECP521R1_SHA512,
            sig_algs::RSA_PSS_RSAE_SHA256,
            sig_algs::RSA_PSS_RSAE_SHA384,
            sig_algs::RSA_PSS_RSAE_SHA512,
            sig_algs::RSA_PKCS1_SHA256,
            sig_algs::RSA_PKCS1_SHA384,
            sig_algs::RSA_PKCS1_SHA512,
        ],
        alpn_protocols: vec![AlpnProtocol::H2, AlpnProtocol::Http11],
        psk_key_exchange_modes: vec![PskKeyExchangeMode::PskDheKe],
        key_share_groups: vec![named_groups::X25519],
        compress_certificate_algorithms: vec![],
        record_size_limit: None,
        supports_delegated_credentials: false,
        supports_post_handshake_auth: false,
        supports_early_data: false,
    }
}

/// Complete TLS ClientHello fingerprint database.
///
/// Maps browser identifiers and persona IDs to full ClientHello profiles
/// for TLS fingerprint synthesis. Combined with the HTTP/2 fingerprint database,
/// this enables coherent browser identity at both the TLS and application layers.
pub struct TlsClientHelloDb {
    profiles: HashMap<TlsClientHelloBrowserId, TlsClientHelloProfile>,
    persona_mapping: HashMap<PersonaId, TlsClientHelloBrowserId>,
    fingerprint_mapping: HashMap<TlsFingerprint, TlsClientHelloBrowserId>,
}

impl TlsClientHelloDb {
    pub fn new() -> Self {
        let profiles: HashMap<TlsClientHelloBrowserId, TlsClientHelloProfile> = [
            (TlsClientHelloBrowserId::Chrome120, chrome_120_clienthello()),
            (TlsClientHelloBrowserId::Chrome125, chrome_125_clienthello()),
            (
                TlsClientHelloBrowserId::Firefox121,
                firefox_121_clienthello(),
            ),
            (
                TlsClientHelloBrowserId::Firefox125,
                firefox_125_clienthello(),
            ),
            (TlsClientHelloBrowserId::Safari17, safari_17_clienthello()),
            (TlsClientHelloBrowserId::Edge120, edge_120_clienthello()),
            (TlsClientHelloBrowserId::Curl, curl_clienthello()),
        ]
        .into_iter()
        .collect();

        let persona_mapping: HashMap<PersonaId, TlsClientHelloBrowserId> = [
            (PersonaId::ChromeDesktop, TlsClientHelloBrowserId::Chrome125),
            (PersonaId::ChromeMobile, TlsClientHelloBrowserId::Chrome125),
            (
                PersonaId::FirefoxDesktop,
                TlsClientHelloBrowserId::Firefox125,
            ),
            (PersonaId::SafariDesktop, TlsClientHelloBrowserId::Safari17),
            (PersonaId::SafariMobile, TlsClientHelloBrowserId::Safari17),
            (PersonaId::EdgeDesktop, TlsClientHelloBrowserId::Edge120),
            (PersonaId::OperaDesktop, TlsClientHelloBrowserId::Chrome125),
            (PersonaId::Googlebot, TlsClientHelloBrowserId::Chrome120),
            (PersonaId::CurlClient, TlsClientHelloBrowserId::Curl),
            (PersonaId::PythonRequests, TlsClientHelloBrowserId::Curl),
        ]
        .into_iter()
        .collect();

        let fingerprint_mapping: HashMap<TlsFingerprint, TlsClientHelloBrowserId> = [
            (
                TlsFingerprint::Chrome120,
                TlsClientHelloBrowserId::Chrome120,
            ),
            (
                TlsFingerprint::Firefox121,
                TlsClientHelloBrowserId::Firefox121,
            ),
            (TlsFingerprint::Safari17, TlsClientHelloBrowserId::Safari17),
            (TlsFingerprint::Edge120, TlsClientHelloBrowserId::Edge120),
            (TlsFingerprint::Curl, TlsClientHelloBrowserId::Curl),
        ]
        .into_iter()
        .collect();

        Self {
            profiles,
            persona_mapping,
            fingerprint_mapping,
        }
    }

    pub fn get(&self, browser_id: &TlsClientHelloBrowserId) -> Option<&TlsClientHelloProfile> {
        self.profiles.get(browser_id)
    }

    pub fn for_persona(&self, persona_id: PersonaId) -> Option<&TlsClientHelloProfile> {
        self.persona_mapping
            .get(&persona_id)
            .and_then(|bid| self.profiles.get(bid))
    }

    pub fn for_tls_fingerprint(
        &self,
        fingerprint: TlsFingerprint,
    ) -> Option<&TlsClientHelloProfile> {
        self.fingerprint_mapping
            .get(&fingerprint)
            .and_then(|bid| self.profiles.get(bid))
    }

    pub fn all(&self) -> impl Iterator<Item = &TlsClientHelloProfile> {
        self.profiles.values()
    }

    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// Checks whether a cipher suite ordering matches any known browser profile.
    pub fn identify_by_cipher_order(
        &self,
        observed_ciphers: &[CipherSuiteId],
    ) -> Option<TlsClientHelloBrowserId> {
        for (browser_id, profile) in &self.profiles {
            if profile.cipher_suites == observed_ciphers {
                return Some(*browser_id);
            }
        }
        None
    }
}

impl Default for TlsClientHelloDb {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the TLS ClientHello profile for a persona.
pub fn clienthello_for_persona(persona_id: PersonaId) -> TlsClientHelloProfile {
    let db = TlsClientHelloDb::new();
    db.for_persona(persona_id)
        .cloned()
        .unwrap_or_else(chrome_120_clienthello)
}

/// Validates that a TLS ClientHello profile is internally consistent.
///
/// Checks: key_share groups are subset of supported_groups,
/// TLS 1.3 cipher suites present if PSK modes are set, etc.
pub fn validate_clienthello(profile: &TlsClientHelloProfile) -> Vec<String> {
    let mut issues = Vec::new();

    for kg in &profile.key_share_groups {
        if !profile.supported_groups.contains(kg) {
            issues.push(format!(
                "key_share group 0x{kg:04X} not in supported_groups"
            ));
        }
    }

    let has_tls13_cipher = profile.cipher_suites.iter().any(|c| {
        *c == cipher_suites::TLS_AES_128_GCM_SHA256
            || *c == cipher_suites::TLS_AES_256_GCM_SHA384
            || *c == cipher_suites::TLS_CHACHA20_POLY1305_SHA256
    });
    if !profile.psk_key_exchange_modes.is_empty() && !has_tls13_cipher {
        issues.push("PSK modes set but no TLS 1.3 cipher suites present".to_string());
    }

    if profile.cipher_suites.is_empty() {
        issues.push("empty cipher suite list".to_string());
    }

    if profile.supported_groups.is_empty() {
        issues.push("empty supported groups".to_string());
    }

    if profile.signature_algorithms.is_empty() {
        issues.push("empty signature algorithms".to_string());
    }

    issues
}

/// Minimal MD5 for JA3/JA4 hashing (fingerprint computation only — not security-sensitive).
fn md5_hash(data: &[u8]) -> u128 {
    use std::num::Wrapping;

    let s: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let orig_len_bits = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&orig_len_bits.to_le_bytes());

    let (mut a0, mut b0, mut c0, mut d0) = (
        Wrapping(0x67452301u32),
        Wrapping(0xefcdab89u32),
        Wrapping(0x98badcfeu32),
        Wrapping(0x10325476u32),
    );

    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            m[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }

        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let f = f + a + Wrapping(k[i]) + Wrapping(m[g]);
            a = d;
            d = c;
            c = b;
            b += Wrapping(f.0.rotate_left(s[i]));
        }

        a0 += a;
        b0 += b;
        c0 += c;
        d0 += d;
    }

    let bytes: [u8; 16] = [
        a0.0 as u8,
        (a0.0 >> 8) as u8,
        (a0.0 >> 16) as u8,
        (a0.0 >> 24) as u8,
        b0.0 as u8,
        (b0.0 >> 8) as u8,
        (b0.0 >> 16) as u8,
        (b0.0 >> 24) as u8,
        c0.0 as u8,
        (c0.0 >> 8) as u8,
        (c0.0 >> 16) as u8,
        (c0.0 >> 24) as u8,
        d0.0 as u8,
        (d0.0 >> 8) as u8,
        (d0.0 >> 16) as u8,
        (d0.0 >> 24) as u8,
    ];
    u128::from_be_bytes(bytes)
}

#[cfg(test)]
#[path = "tls_clienthello_test.rs"]
mod tls_clienthello_test;
