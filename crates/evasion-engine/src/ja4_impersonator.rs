use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// JA4 TLS fingerprint capturing cipher suites, extensions, and ALPN.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ja4Fingerprint {
    pub tls_version: String,
    pub cipher_suites: Vec<String>,
    pub extensions: Vec<String>,
    pub alpn: Vec<String>,
    pub sig_algos: Vec<String>,
    pub hash: String,
}

/// JA4H HTTP fingerprint capturing header ordering and cookie count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ja4hFingerprint {
    pub method: String,
    pub version: String,
    pub headers: Vec<String>,
    pub cookie_count: usize,
    pub hash: String,
}

/// JA4T TCP fingerprint capturing OS-level TCP stack characteristics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ja4tFingerprint {
    pub window_size: u32,
    pub ttl: u8,
    pub options: Vec<String>,
    pub df_bit: bool,
    pub hash: String,
}

/// JA4X X.509 certificate fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ja4xFingerprint {
    pub issuer_cn: String,
    pub subject_cn: String,
    pub extensions: Vec<String>,
    pub hash: String,
}

/// Complete browser profile combining TLS, HTTP, TCP, and certificate
/// fingerprints for consistent impersonation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserProfile {
    pub name: String,
    pub ja4: Ja4Fingerprint,
    pub ja4h: Ja4hFingerprint,
    pub ja4t: Ja4tFingerprint,
    pub ja4x: Option<Ja4xFingerprint>,
}

/// Generates and validates complete JA4+ fingerprint profiles that
/// perfectly impersonate real browser TLS/HTTP/TCP stacks, defeating
/// JA4-based bot detection and traffic classification.
pub struct Ja4Impersonator;

impl Ja4Impersonator {
    pub fn new() -> Self {
        Self
    }

    pub fn chrome_124_profile() -> BrowserProfile {
        let ja4 = Ja4Fingerprint {
            tls_version: "1.3".to_string(),
            cipher_suites: vec![
                "TLS_AES_128_GCM_SHA256".to_string(),
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(),
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string(),
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
            ],
            extensions: vec![
                "server_name".to_string(),
                "extended_master_secret".to_string(),
                "renegotiation_info".to_string(),
                "supported_groups".to_string(),
                "ec_point_formats".to_string(),
                "session_ticket".to_string(),
                "application_layer_protocol_negotiation".to_string(),
                "status_request".to_string(),
                "signature_algorithms".to_string(),
                "signed_certificate_timestamp".to_string(),
                "key_share".to_string(),
                "psk_key_exchange_modes".to_string(),
                "supported_versions".to_string(),
                "compress_certificate".to_string(),
                "application_settings".to_string(),
                "encrypted_client_hello".to_string(),
            ],
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            sig_algos: vec![
                "ecdsa_secp256r1_sha256".to_string(),
                "rsa_pss_rsae_sha256".to_string(),
                "rsa_pkcs1_sha256".to_string(),
                "ecdsa_secp384r1_sha384".to_string(),
                "rsa_pss_rsae_sha384".to_string(),
                "rsa_pkcs1_sha384".to_string(),
                "rsa_pss_rsae_sha512".to_string(),
                "rsa_pkcs1_sha512".to_string(),
            ],
            hash: String::new(),
        };
        let ja4_hash = Self::compute_ja4_hash(&ja4);

        let ja4h = Ja4hFingerprint {
            method: "GET".to_string(),
            version: "2".to_string(),
            headers: vec![
                "Host".to_string(),
                "sec-ch-ua".to_string(),
                "sec-ch-ua-mobile".to_string(),
                "sec-ch-ua-platform".to_string(),
                "Upgrade-Insecure-Requests".to_string(),
                "User-Agent".to_string(),
                "Accept".to_string(),
                "Sec-Fetch-Site".to_string(),
                "Sec-Fetch-Mode".to_string(),
                "Sec-Fetch-User".to_string(),
                "Sec-Fetch-Dest".to_string(),
                "Accept-Encoding".to_string(),
                "Accept-Language".to_string(),
            ],
            cookie_count: 0,
            hash: String::new(),
        };
        let ja4h_hash = Self::compute_ja4h_hash(&ja4h);

        let ja4t = Ja4tFingerprint {
            window_size: 65535,
            ttl: 128,
            options: vec![
                "MSS".to_string(),
                "NOP".to_string(),
                "WS".to_string(),
                "NOP".to_string(),
                "NOP".to_string(),
                "SACK".to_string(),
            ],
            df_bit: true,
            hash: String::new(),
        };
        let ja4t_hash = Self::compute_ja4t_hash(&ja4t);

        BrowserProfile {
            name: "Chrome 124".to_string(),
            ja4: Ja4Fingerprint {
                hash: ja4_hash,
                ..ja4
            },
            ja4h: Ja4hFingerprint {
                hash: ja4h_hash,
                ..ja4h
            },
            ja4t: Ja4tFingerprint {
                hash: ja4t_hash,
                ..ja4t
            },
            ja4x: None,
        }
    }

    pub fn firefox_125_profile() -> BrowserProfile {
        let ja4 = Ja4Fingerprint {
            tls_version: "1.3".to_string(),
            cipher_suites: vec![
                "TLS_AES_128_GCM_SHA256".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(),
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string(),
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA".to_string(),
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA".to_string(),
                "TLS_RSA_WITH_AES_128_GCM_SHA256".to_string(),
                "TLS_RSA_WITH_AES_256_GCM_SHA384".to_string(),
                "TLS_RSA_WITH_AES_128_CBC_SHA".to_string(),
                "TLS_RSA_WITH_AES_256_CBC_SHA".to_string(),
            ],
            extensions: vec![
                "server_name".to_string(),
                "extended_master_secret".to_string(),
                "renegotiation_info".to_string(),
                "supported_groups".to_string(),
                "ec_point_formats".to_string(),
                "session_ticket".to_string(),
                "application_layer_protocol_negotiation".to_string(),
                "status_request".to_string(),
                "delegated_credentials".to_string(),
                "key_share".to_string(),
                "supported_versions".to_string(),
                "signature_algorithms".to_string(),
                "psk_key_exchange_modes".to_string(),
                "record_size_limit".to_string(),
            ],
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            sig_algos: vec![
                "ecdsa_secp256r1_sha256".to_string(),
                "ecdsa_secp384r1_sha384".to_string(),
                "ecdsa_secp521r1_sha512".to_string(),
                "rsa_pss_rsae_sha256".to_string(),
                "rsa_pss_rsae_sha384".to_string(),
                "rsa_pss_rsae_sha512".to_string(),
                "rsa_pkcs1_sha256".to_string(),
                "rsa_pkcs1_sha384".to_string(),
                "rsa_pkcs1_sha512".to_string(),
            ],
            hash: String::new(),
        };
        let ja4_hash = Self::compute_ja4_hash(&ja4);

        let ja4h = Ja4hFingerprint {
            method: "GET".to_string(),
            version: "2".to_string(),
            headers: vec![
                "Host".to_string(),
                "User-Agent".to_string(),
                "Accept".to_string(),
                "Accept-Language".to_string(),
                "Accept-Encoding".to_string(),
                "Connection".to_string(),
                "Upgrade-Insecure-Requests".to_string(),
                "Sec-Fetch-Dest".to_string(),
                "Sec-Fetch-Mode".to_string(),
                "Sec-Fetch-Site".to_string(),
                "Sec-Fetch-User".to_string(),
                "Priority".to_string(),
            ],
            cookie_count: 0,
            hash: String::new(),
        };
        let ja4h_hash = Self::compute_ja4h_hash(&ja4h);

        let ja4t = Ja4tFingerprint {
            window_size: 65535,
            ttl: 64,
            options: vec![
                "MSS".to_string(),
                "SACK".to_string(),
                "TS".to_string(),
                "NOP".to_string(),
                "WS".to_string(),
            ],
            df_bit: true,
            hash: String::new(),
        };
        let ja4t_hash = Self::compute_ja4t_hash(&ja4t);

        BrowserProfile {
            name: "Firefox 125".to_string(),
            ja4: Ja4Fingerprint {
                hash: ja4_hash,
                ..ja4
            },
            ja4h: Ja4hFingerprint {
                hash: ja4h_hash,
                ..ja4h
            },
            ja4t: Ja4tFingerprint {
                hash: ja4t_hash,
                ..ja4t
            },
            ja4x: None,
        }
    }

    pub fn safari_17_profile() -> BrowserProfile {
        let ja4 = Ja4Fingerprint {
            tls_version: "1.3".to_string(),
            cipher_suites: vec![
                "TLS_AES_128_GCM_SHA256".to_string(),
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string(),
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(),
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
                "TLS_RSA_WITH_AES_256_GCM_SHA384".to_string(),
                "TLS_RSA_WITH_AES_128_GCM_SHA256".to_string(),
            ],
            extensions: vec![
                "server_name".to_string(),
                "extended_master_secret".to_string(),
                "renegotiation_info".to_string(),
                "supported_groups".to_string(),
                "ec_point_formats".to_string(),
                "application_layer_protocol_negotiation".to_string(),
                "status_request".to_string(),
                "signature_algorithms".to_string(),
                "signed_certificate_timestamp".to_string(),
                "key_share".to_string(),
                "psk_key_exchange_modes".to_string(),
                "supported_versions".to_string(),
            ],
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            sig_algos: vec![
                "ecdsa_secp256r1_sha256".to_string(),
                "rsa_pss_rsae_sha256".to_string(),
                "rsa_pkcs1_sha256".to_string(),
                "ecdsa_secp384r1_sha384".to_string(),
                "rsa_pss_rsae_sha384".to_string(),
                "rsa_pkcs1_sha384".to_string(),
                "rsa_pss_rsae_sha512".to_string(),
                "rsa_pkcs1_sha512".to_string(),
            ],
            hash: String::new(),
        };
        let ja4_hash = Self::compute_ja4_hash(&ja4);

        let ja4h = Ja4hFingerprint {
            method: "GET".to_string(),
            version: "2".to_string(),
            headers: vec![
                "Host".to_string(),
                "Accept".to_string(),
                "Sec-Fetch-Site".to_string(),
                "Accept-Language".to_string(),
                "Sec-Fetch-Mode".to_string(),
                "User-Agent".to_string(),
                "Accept-Encoding".to_string(),
                "Sec-Fetch-Dest".to_string(),
            ],
            cookie_count: 0,
            hash: String::new(),
        };
        let ja4h_hash = Self::compute_ja4h_hash(&ja4h);

        let ja4t = Ja4tFingerprint {
            window_size: 65535,
            ttl: 64,
            options: vec![
                "MSS".to_string(),
                "NOP".to_string(),
                "WS".to_string(),
                "NOP".to_string(),
                "NOP".to_string(),
                "TS".to_string(),
                "SACK".to_string(),
            ],
            df_bit: true,
            hash: String::new(),
        };
        let ja4t_hash = Self::compute_ja4t_hash(&ja4t);

        BrowserProfile {
            name: "Safari 17".to_string(),
            ja4: Ja4Fingerprint {
                hash: ja4_hash,
                ..ja4
            },
            ja4h: Ja4hFingerprint {
                hash: ja4h_hash,
                ..ja4h
            },
            ja4t: Ja4tFingerprint {
                hash: ja4t_hash,
                ..ja4t
            },
            ja4x: None,
        }
    }

    /// Check that TLS version, cipher suite ordering, ALPN, and TCP
    /// fingerprint are mutually consistent for the named browser.
    pub fn validate_consistency(profile: &BrowserProfile) -> Vec<String> {
        let mut issues = Vec::new();

        if profile.ja4.tls_version == "1.3"
            && !profile
                .ja4
                .cipher_suites
                .iter()
                .any(|c| c.starts_with("TLS_AES") || c.starts_with("TLS_CHACHA20"))
        {
            issues.push("TLS 1.3 profile missing TLS 1.3 cipher suites".to_string());
        }

        if !profile
            .ja4
            .extensions
            .iter()
            .any(|e| e == "supported_versions")
            && profile.ja4.tls_version == "1.3"
        {
            issues.push("TLS 1.3 profile missing supported_versions extension".to_string());
        }

        if profile.ja4h.headers.is_empty() {
            issues.push("JA4H profile has no headers".to_string());
        }

        let expected_hash = Self::compute_ja4_hash(&profile.ja4);
        if !profile.ja4.hash.is_empty() && profile.ja4.hash != expected_hash {
            issues.push("JA4 hash does not match computed value".to_string());
        }

        let expected_ja4h = Self::compute_ja4h_hash(&profile.ja4h);
        if !profile.ja4h.hash.is_empty() && profile.ja4h.hash != expected_ja4h {
            issues.push("JA4H hash does not match computed value".to_string());
        }

        let expected_ja4t = Self::compute_ja4t_hash(&profile.ja4t);
        if !profile.ja4t.hash.is_empty() && profile.ja4t.hash != expected_ja4t {
            issues.push("JA4T hash does not match computed value".to_string());
        }

        if profile.name.contains("Chrome") && profile.ja4t.ttl != 128 {
            issues.push(format!(
                "Chrome profile TTL should be 128, got {}",
                profile.ja4t.ttl
            ));
        }

        if profile.name.contains("Firefox") && profile.ja4t.ttl != 64 {
            issues.push(format!(
                "Firefox profile TTL should be 64, got {}",
                profile.ja4t.ttl
            ));
        }

        if profile.name.contains("Safari") && profile.ja4t.ttl != 64 {
            issues.push(format!(
                "Safari profile TTL should be 64, got {}",
                profile.ja4t.ttl
            ));
        }

        issues
    }

    /// Simplified JA4 hash: version + cipher count + extension count +
    /// truncated hash of sorted cipher names.
    pub fn compute_ja4_hash(fp: &Ja4Fingerprint) -> String {
        let mut hasher = DefaultHasher::new();
        fp.tls_version.hash(&mut hasher);
        for cs in &fp.cipher_suites {
            cs.hash(&mut hasher);
        }
        for ext in &fp.extensions {
            ext.hash(&mut hasher);
        }
        for alpn in &fp.alpn {
            alpn.hash(&mut hasher);
        }
        let h = hasher.finish();
        format!(
            "t{}_{:02}_{:02}_{:012x}",
            fp.tls_version.replace('.', ""),
            fp.cipher_suites.len(),
            fp.extensions.len(),
            h & 0xFFFF_FFFF_FFFF
        )
    }

    /// Simplified JA4H hash: method + version + header count + cookie
    /// count + truncated hash of header ordering.
    pub fn compute_ja4h_hash(fp: &Ja4hFingerprint) -> String {
        let mut hasher = DefaultHasher::new();
        fp.method.hash(&mut hasher);
        fp.version.hash(&mut hasher);
        for h in &fp.headers {
            h.hash(&mut hasher);
        }
        fp.cookie_count.hash(&mut hasher);
        let h = hasher.finish();
        format!(
            "{}{}_{:02}_{:02}_{:012x}",
            fp.method.chars().next().unwrap_or('G'),
            fp.version,
            fp.headers.len(),
            fp.cookie_count,
            h & 0xFFFF_FFFF_FFFF
        )
    }

    /// Simplified JA4T hash: window size + TTL + option count +
    /// truncated hash of TCP options.
    pub fn compute_ja4t_hash(fp: &Ja4tFingerprint) -> String {
        let mut hasher = DefaultHasher::new();
        fp.window_size.hash(&mut hasher);
        fp.ttl.hash(&mut hasher);
        for opt in &fp.options {
            opt.hash(&mut hasher);
        }
        fp.df_bit.hash(&mut hasher);
        let h = hasher.finish();
        format!(
            "{}_{}_{:02}_{:012x}",
            fp.window_size,
            fp.ttl,
            fp.options.len(),
            h & 0xFFFF_FFFF_FFFF
        )
    }
}

impl Default for Ja4Impersonator {
    fn default() -> Self {
        Self::new()
    }
}
