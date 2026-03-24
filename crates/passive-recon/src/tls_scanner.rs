/// TLS misconfiguration scanner — analyzes parsed certificate and handshake data
/// for security weaknesses without making live connections.
///
/// Covers 10+ misconfiguration patterns: deprecated protocols, weak ciphers,
/// certificate issues, HSTS gaps, chain problems, key sizes, OCSP stapling,
/// insecure renegotiation, protocol-level attacks, and CT compliance.
use std::fmt;
use std::time::{Duration, SystemTime};

/// Severity of a TLS finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

/// Classification for cipher suite strength.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherStrength {
    Strong,
    Acceptable,
    Weak,
    Insecure,
}

impl fmt::Display for CipherStrength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CipherStrength::Strong => write!(f, "strong"),
            CipherStrength::Acceptable => write!(f, "acceptable"),
            CipherStrength::Weak => write!(f, "weak"),
            CipherStrength::Insecure => write!(f, "insecure"),
        }
    }
}

/// TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersion {
    SslV2,
    SslV3,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsVersion::SslV2 => write!(f, "SSLv2"),
            TlsVersion::SslV3 => write!(f, "SSLv3"),
            TlsVersion::Tls10 => write!(f, "TLS 1.0"),
            TlsVersion::Tls11 => write!(f, "TLS 1.1"),
            TlsVersion::Tls12 => write!(f, "TLS 1.2"),
            TlsVersion::Tls13 => write!(f, "TLS 1.3"),
        }
    }
}

impl TlsVersion {
    pub fn is_deprecated(&self) -> bool {
        matches!(
            self,
            TlsVersion::SslV2 | TlsVersion::SslV3 | TlsVersion::Tls10 | TlsVersion::Tls11
        )
    }
}

/// Key algorithm and size info extracted from certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyInfo {
    Rsa { bits: u32 },
    Ecc { bits: u32 },
    Dsa { bits: u32 },
}

/// Certificate metadata parsed from a TLS handshake.
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
    pub is_self_signed: bool,
    pub is_wildcard: bool,
    pub key_info: KeyInfo,
    pub has_ct_scts: bool,
    pub serial_number: String,
}

/// A single certificate in a chain, with its position.
#[derive(Debug, Clone)]
pub struct ChainCertificate {
    pub cert: CertificateInfo,
    pub is_root: bool,
    pub depth: usize,
}

/// HSTS configuration parsed from response headers.
#[derive(Debug, Clone)]
pub struct HstsConfig {
    pub present: bool,
    pub max_age_seconds: Option<u64>,
    pub include_sub_domains: bool,
    pub preload: bool,
}

/// OCSP stapling status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OcspStaplingStatus {
    Present { is_valid: bool },
    Missing,
}

/// Full TLS handshake data to analyze.
#[derive(Debug, Clone)]
pub struct TlsHandshakeData {
    pub supported_versions: Vec<TlsVersion>,
    pub cipher_suites: Vec<String>,
    pub certificate_chain: Vec<ChainCertificate>,
    pub hsts: Option<HstsConfig>,
    pub ocsp_stapling: OcspStaplingStatus,
    pub supports_secure_renegotiation: bool,
    pub supports_compression: bool,
    pub server_name: String,
}

/// Category of TLS misconfiguration found.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TlsFindingKind {
    DeprecatedProtocol,
    WeakCipher,
    CertificateExpired,
    CertificateNotYetValid,
    SelfSignedCertificate,
    WildcardCertificate,
    MissingHsts,
    WeakHsts,
    IncompleteCertificateChain,
    WeakKeySize,
    DeprecatedKeyAlgorithm,
    MissingOcspStapling,
    ExpiredOcspStapling,
    InsecureRenegotiation,
    CompressionEnabled,
    MissingCertificateTransparency,
    CertificateChainOrderError,
    UnnecessaryRootInChain,
    ExcessiveWildcardScope,
}

/// A single TLS misconfiguration finding.
#[derive(Debug, Clone)]
pub struct TlsFinding {
    pub kind: TlsFindingKind,
    pub severity: Severity,
    pub description: String,
    pub remediation: String,
}

/// Result of a full TLS configuration scan.
#[derive(Debug, Clone)]
pub struct TlsScanResult {
    pub server_name: String,
    pub findings: Vec<TlsFinding>,
    pub cipher_classifications: Vec<(String, CipherStrength)>,
}

impl TlsScanResult {
    pub fn critical_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count()
    }

    pub fn high_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count()
    }

    pub fn has_finding(&self, kind: &TlsFindingKind) -> bool {
        self.findings.iter().any(|f| &f.kind == kind)
    }
}

/// Minimum acceptable HSTS max-age (1 year = 31536000 seconds).
const HSTS_MIN_MAX_AGE: u64 = 31_536_000;

/// Classify a cipher suite name into a strength category.
pub fn classify_cipher(cipher: &str) -> CipherStrength {
    let upper = cipher.to_uppercase();

    // Insecure: NULL encryption, anonymous key exchange, EXPORT-grade, DES (not 3DES)
    if upper.contains("NULL")
        || upper.contains("ANON")
        || upper.contains("EXPORT")
        || (upper.contains("_DES_") && !upper.contains("3DES") && !upper.contains("DES_CBC3"))
    {
        return CipherStrength::Insecure;
    }

    // Weak: RC4, 3DES, MD5-based MACs
    if upper.contains("RC4")
        || upper.contains("3DES")
        || upper.contains("DES_CBC3")
        || upper.contains("_MD5")
    {
        return CipherStrength::Weak;
    }

    // Strong: TLS 1.3 suites, CHACHA20, AES-GCM with ECDHE
    if upper.contains("TLS_AES_")
        || upper.contains("TLS_CHACHA20_")
        || upper.contains("CHACHA20_POLY1305")
        || (upper.contains("ECDHE") && upper.contains("GCM"))
    {
        return CipherStrength::Strong;
    }

    // Acceptable: everything else (DHE-AES-CBC, RSA-AES-GCM, etc.)
    CipherStrength::Acceptable
}

/// Run full TLS misconfiguration analysis on parsed handshake data.
pub fn scan_tls(handshake: &TlsHandshakeData) -> TlsScanResult {
    let mut findings = Vec::new();

    check_protocol_versions(handshake, &mut findings);
    check_cipher_suites(handshake, &mut findings);
    check_certificates(handshake, &mut findings);
    check_hsts(handshake, &mut findings);
    check_certificate_chain(handshake, &mut findings);
    check_key_sizes(handshake, &mut findings);
    check_ocsp_stapling(handshake, &mut findings);
    check_renegotiation(handshake, &mut findings);
    check_compression(handshake, &mut findings);
    check_certificate_transparency(handshake, &mut findings);

    let cipher_classifications: Vec<(String, CipherStrength)> = handshake
        .cipher_suites
        .iter()
        .map(|c| (c.clone(), classify_cipher(c)))
        .collect();

    TlsScanResult {
        server_name: handshake.server_name.clone(),
        findings,
        cipher_classifications,
    }
}

/// 1. Deprecated protocol detection.
fn check_protocol_versions(handshake: &TlsHandshakeData, findings: &mut Vec<TlsFinding>) {
    for version in &handshake.supported_versions {
        if version.is_deprecated() {
            let severity = match version {
                TlsVersion::SslV2 => Severity::Critical,
                TlsVersion::SslV3 => Severity::Critical,
                TlsVersion::Tls10 => Severity::High,
                TlsVersion::Tls11 => Severity::High,
                _ => Severity::Medium,
            };
            findings.push(TlsFinding {
                kind: TlsFindingKind::DeprecatedProtocol,
                severity,
                description: format!(
                    "{version} is deprecated and known to have security vulnerabilities"
                ),
                remediation:
                    "Disable deprecated protocol versions; require TLS 1.2 or TLS 1.3 minimum"
                        .into(),
            });
        }
    }
}

/// 2. Weak cipher suite detection.
fn check_cipher_suites(handshake: &TlsHandshakeData, findings: &mut Vec<TlsFinding>) {
    for cipher in &handshake.cipher_suites {
        let strength = classify_cipher(cipher);
        let (severity, label) = match strength {
            CipherStrength::Insecure => (Severity::Critical, "insecure"),
            CipherStrength::Weak => (Severity::High, "weak"),
            _ => continue,
        };
        findings.push(TlsFinding {
            kind: TlsFindingKind::WeakCipher,
            severity,
            description: format!("Cipher suite {cipher} is classified as {label}"),
            remediation:
                "Remove weak and insecure cipher suites; prefer AEAD ciphers with forward secrecy"
                    .into(),
        });
    }
}

/// 3. Certificate validation — expiry, self-signed, wildcard.
fn check_certificates(handshake: &TlsHandshakeData, findings: &mut Vec<TlsFinding>) {
    let now = SystemTime::now();

    for chain_cert in &handshake.certificate_chain {
        let cert = &chain_cert.cert;

        if cert.not_after < now {
            findings.push(TlsFinding {
                kind: TlsFindingKind::CertificateExpired,
                severity: Severity::Critical,
                description: format!("Certificate for '{}' has expired", cert.subject),
                remediation: "Renew the certificate before expiry; implement automated certificate management".into(),
            });
        }

        if cert.not_before > now {
            findings.push(TlsFinding {
                kind: TlsFindingKind::CertificateNotYetValid,
                severity: Severity::Critical,
                description: format!("Certificate for '{}' is not yet valid", cert.subject),
                remediation:
                    "Check system clock synchronization or wait for the certificate validity period"
                        .into(),
            });
        }

        if cert.is_self_signed && !chain_cert.is_root {
            findings.push(TlsFinding {
                kind: TlsFindingKind::SelfSignedCertificate,
                severity: Severity::High,
                description: format!("Certificate for '{}' is self-signed", cert.subject),
                remediation: "Use certificates issued by a trusted Certificate Authority".into(),
            });
        }

        if cert.is_wildcard {
            findings.push(TlsFinding {
                kind: TlsFindingKind::WildcardCertificate,
                severity: Severity::Low,
                description: format!("Wildcard certificate in use: {}", cert.subject),
                remediation:
                    "Consider using specific SANs instead of wildcards to reduce blast radius"
                        .into(),
            });

            // Excessive scope: wildcard on a high-value subject
            if cert.subject.starts_with("*.") && cert.subject.matches('.').count() == 1 {
                findings.push(TlsFinding {
                    kind: TlsFindingKind::ExcessiveWildcardScope,
                    severity: Severity::Medium,
                    description: format!(
                        "Top-level wildcard '{}' covers all subdomains of a TLD-adjacent domain",
                        cert.subject,
                    ),
                    remediation:
                        "Scope wildcards to specific subdomain levels (e.g., *.app.example.com)"
                            .into(),
                });
            }
        }
    }
}

/// 4. HSTS analysis.
fn check_hsts(handshake: &TlsHandshakeData, findings: &mut Vec<TlsFinding>) {
    match &handshake.hsts {
        None => {
            findings.push(TlsFinding {
                kind: TlsFindingKind::MissingHsts,
                severity: Severity::High,
                description: "HTTP Strict Transport Security header is missing".into(),
                remediation: "Add Strict-Transport-Security header with max-age >= 31536000, includeSubDomains, and preload".into(),
            });
        }
        Some(hsts) if !hsts.present => {
            findings.push(TlsFinding {
                kind: TlsFindingKind::MissingHsts,
                severity: Severity::High,
                description: "HTTP Strict Transport Security header is missing".into(),
                remediation: "Add Strict-Transport-Security header with max-age >= 31536000, includeSubDomains, and preload".into(),
            });
        }
        Some(hsts) => {
            let mut weak_reasons = Vec::new();

            if let Some(max_age) = hsts.max_age_seconds
                && max_age < HSTS_MIN_MAX_AGE
            {
                weak_reasons.push(format!(
                    "max-age is {max_age}s (should be >= {HSTS_MIN_MAX_AGE}s)"
                ));
            }

            if !hsts.include_sub_domains {
                weak_reasons.push("missing includeSubDomains directive".into());
            }

            if !hsts.preload {
                weak_reasons.push("missing preload directive".into());
            }

            if !weak_reasons.is_empty() {
                findings.push(TlsFinding {
                    kind: TlsFindingKind::WeakHsts,
                    severity: Severity::Medium,
                    description: format!("HSTS configuration is weak: {}", weak_reasons.join("; ")),
                    remediation: "Set max-age to at least 31536000 (1 year), enable includeSubDomains and preload".into(),
                });
            }
        }
    }
}

/// 5. Certificate chain validation.
fn check_certificate_chain(handshake: &TlsHandshakeData, findings: &mut Vec<TlsFinding>) {
    let chain = &handshake.certificate_chain;

    if chain.is_empty() {
        return;
    }

    // Check for incomplete chain (single leaf cert without intermediates for non-self-signed)
    if chain.len() == 1 && !chain[0].cert.is_self_signed {
        findings.push(TlsFinding {
            kind: TlsFindingKind::IncompleteCertificateChain,
            severity: Severity::High,
            description: "Certificate chain is incomplete — missing intermediate certificates"
                .into(),
            remediation: "Include all intermediate certificates in the TLS handshake".into(),
        });
    }

    // Check ordering: leaf should be at depth 0, each subsequent cert at increasing depth
    let mut ordering_error = false;
    for (idx, chain_cert) in chain.iter().enumerate() {
        if chain_cert.depth != idx {
            ordering_error = true;
            break;
        }
    }
    if ordering_error {
        findings.push(TlsFinding {
            kind: TlsFindingKind::CertificateChainOrderError,
            severity: Severity::Medium,
            description: "Certificate chain is not in the correct order (leaf → intermediates → root)".into(),
            remediation: "Order certificates: leaf first, followed by intermediates, root last (or omitted)".into(),
        });
    }

    // Unnecessary root in chain
    if chain.len() > 1 && chain.last().is_some_and(|c| c.is_root) {
        findings.push(TlsFinding {
            kind: TlsFindingKind::UnnecessaryRootInChain,
            severity: Severity::Low,
            description: "Root CA certificate is included in the chain (unnecessary, adds handshake overhead)".into(),
            remediation: "Remove the root CA from the chain; clients already have it in their trust store".into(),
        });
    }
}

/// 6. Key size checks.
fn check_key_sizes(handshake: &TlsHandshakeData, findings: &mut Vec<TlsFinding>) {
    for chain_cert in &handshake.certificate_chain {
        match &chain_cert.cert.key_info {
            KeyInfo::Rsa { bits } if *bits < 2048 => {
                findings.push(TlsFinding {
                    kind: TlsFindingKind::WeakKeySize,
                    severity: Severity::Critical,
                    description: format!("RSA key is {bits} bits (minimum 2048 required)"),
                    remediation:
                        "Generate a new RSA key with at least 2048 bits, or preferably 4096 bits"
                            .into(),
                });
            }
            KeyInfo::Ecc { bits } if *bits < 256 => {
                findings.push(TlsFinding {
                    kind: TlsFindingKind::WeakKeySize,
                    severity: Severity::High,
                    description: format!("ECC key is {bits} bits (minimum 256 required)"),
                    remediation: "Generate a new ECC key with at least 256 bits (P-256 or P-384)"
                        .into(),
                });
            }
            KeyInfo::Dsa { bits } => {
                findings.push(TlsFinding {
                    kind: TlsFindingKind::DeprecatedKeyAlgorithm,
                    severity: Severity::High,
                    description: format!("DSA key algorithm is deprecated ({bits} bits)"),
                    remediation:
                        "Migrate to RSA (2048+) or ECC (P-256+); DSA is no longer considered secure"
                            .into(),
                });
            }
            _ => {}
        }
    }
}

/// 7. OCSP stapling.
fn check_ocsp_stapling(handshake: &TlsHandshakeData, findings: &mut Vec<TlsFinding>) {
    match &handshake.ocsp_stapling {
        OcspStaplingStatus::Missing => {
            findings.push(TlsFinding {
                kind: TlsFindingKind::MissingOcspStapling,
                severity: Severity::Low,
                description: "OCSP stapling is not enabled".into(),
                remediation:
                    "Enable OCSP stapling to improve certificate validation performance and privacy"
                        .into(),
            });
        }
        OcspStaplingStatus::Present { is_valid: false } => {
            findings.push(TlsFinding {
                kind: TlsFindingKind::ExpiredOcspStapling,
                severity: Severity::Medium,
                description: "OCSP stapled response is expired or invalid".into(),
                remediation: "Ensure OCSP responder is reachable and stapled responses are refreshed before expiry".into(),
            });
        }
        OcspStaplingStatus::Present { is_valid: true } => {}
    }
}

/// 8. Insecure renegotiation (CVE-2009-3555).
fn check_renegotiation(handshake: &TlsHandshakeData, findings: &mut Vec<TlsFinding>) {
    if !handshake.supports_secure_renegotiation {
        findings.push(TlsFinding {
            kind: TlsFindingKind::InsecureRenegotiation,
            severity: Severity::High,
            description: "Server does not support secure renegotiation (RFC 5746), vulnerable to CVE-2009-3555".into(),
            remediation: "Enable the renegotiation_info extension (RFC 5746) on the server".into(),
        });
    }
}

/// 9. CRIME/BREACH — TLS-level compression enables side-channel attacks.
fn check_compression(handshake: &TlsHandshakeData, findings: &mut Vec<TlsFinding>) {
    if handshake.supports_compression {
        findings.push(TlsFinding {
            kind: TlsFindingKind::CompressionEnabled,
            severity: Severity::High,
            description: "TLS compression is enabled, making the connection vulnerable to CRIME/BREACH attacks".into(),
            remediation: "Disable TLS-level compression; use HTTP-level compression only for non-secret content".into(),
        });
    }
}

/// 10. Certificate transparency — SCT presence.
fn check_certificate_transparency(handshake: &TlsHandshakeData, findings: &mut Vec<TlsFinding>) {
    for chain_cert in &handshake.certificate_chain {
        if chain_cert.depth == 0 && !chain_cert.cert.has_ct_scts {
            findings.push(TlsFinding {
                kind: TlsFindingKind::MissingCertificateTransparency,
                severity: Severity::Medium,
                description: format!(
                    "Leaf certificate '{}' is missing Certificate Transparency SCTs",
                    chain_cert.cert.subject,
                ),
                remediation: "Obtain certificates from CAs that embed SCTs or configure OCSP stapling with SCTs".into(),
            });
        }
    }
}

/// Convenience builder for test and integration use.
pub struct TlsHandshakeDataBuilder {
    data: TlsHandshakeData,
}

impl TlsHandshakeDataBuilder {
    pub fn new(server_name: &str) -> Self {
        Self {
            data: TlsHandshakeData {
                supported_versions: vec![TlsVersion::Tls12, TlsVersion::Tls13],
                cipher_suites: vec!["TLS_AES_256_GCM_SHA384".into()],
                certificate_chain: vec![],
                hsts: Some(HstsConfig {
                    present: true,
                    max_age_seconds: Some(HSTS_MIN_MAX_AGE),
                    include_sub_domains: true,
                    preload: true,
                }),
                ocsp_stapling: OcspStaplingStatus::Present { is_valid: true },
                supports_secure_renegotiation: true,
                supports_compression: false,
                server_name: server_name.into(),
            },
        }
    }

    pub fn with_versions(mut self, versions: Vec<TlsVersion>) -> Self {
        self.data.supported_versions = versions;
        self
    }

    pub fn with_ciphers(mut self, ciphers: Vec<&str>) -> Self {
        self.data.cipher_suites = ciphers.into_iter().map(String::from).collect();
        self
    }

    pub fn with_leaf_cert(mut self, cert: CertificateInfo) -> Self {
        self.data.certificate_chain.push(ChainCertificate {
            cert,
            is_root: false,
            depth: 0,
        });
        self
    }

    pub fn with_chain_cert(mut self, cert: CertificateInfo, depth: usize, is_root: bool) -> Self {
        self.data.certificate_chain.push(ChainCertificate {
            cert,
            is_root,
            depth,
        });
        self
    }

    pub fn with_hsts(mut self, hsts: Option<HstsConfig>) -> Self {
        self.data.hsts = hsts;
        self
    }

    pub fn with_ocsp(mut self, status: OcspStaplingStatus) -> Self {
        self.data.ocsp_stapling = status;
        self
    }

    pub fn with_secure_renegotiation(mut self, secure: bool) -> Self {
        self.data.supports_secure_renegotiation = secure;
        self
    }

    pub fn with_compression(mut self, enabled: bool) -> Self {
        self.data.supports_compression = enabled;
        self
    }

    pub fn build(self) -> TlsHandshakeData {
        self.data
    }
}

/// Helper to create a test certificate.
pub fn make_test_cert(
    subject: &str,
    issuer: &str,
    valid_from: SystemTime,
    valid_until: SystemTime,
    key_info: KeyInfo,
) -> CertificateInfo {
    let is_self_signed = subject == issuer;
    let is_wildcard = subject.starts_with("*.");
    CertificateInfo {
        subject: subject.into(),
        issuer: issuer.into(),
        not_before: valid_from,
        not_after: valid_until,
        is_self_signed,
        is_wildcard,
        key_info,
        has_ct_scts: true,
        serial_number: format!("SN-{subject}"),
    }
}

/// Helper to create a valid leaf certificate for the common case.
pub fn make_valid_leaf(subject: &str) -> CertificateInfo {
    let now = SystemTime::now();
    let one_year = Duration::from_secs(365 * 24 * 3600);
    make_test_cert(
        subject,
        "Let's Encrypt Authority X3",
        now - one_year,
        now + one_year,
        KeyInfo::Rsa { bits: 2048 },
    )
}
