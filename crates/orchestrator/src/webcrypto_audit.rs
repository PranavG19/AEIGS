use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebCryptoIssue {
    WeakHashAlgorithm { algorithm: String },
    WeakEncryptionAlgorithm { algorithm: String },
    HardcodedKey,
    HardcodedIv,
    InsecureRandomUsage,
    MathRandomForCrypto,
    ExportedCryptoKey,
    NonExtractableKeyMissing,
}

impl std::fmt::Display for WebCryptoIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WeakHashAlgorithm { algorithm } => write!(f, "weak_hash:{algorithm}"),
            Self::WeakEncryptionAlgorithm { algorithm } => {
                write!(f, "weak_cipher:{algorithm}")
            }
            Self::HardcodedKey => write!(f, "hardcoded_key"),
            Self::HardcodedIv => write!(f, "hardcoded_iv"),
            Self::InsecureRandomUsage => write!(f, "insecure_random"),
            Self::MathRandomForCrypto => write!(f, "math_random_crypto"),
            Self::ExportedCryptoKey => write!(f, "exported_crypto_key"),
            Self::NonExtractableKeyMissing => write!(f, "non_extractable_missing"),
        }
    }
}

const WEAK_HASHES: &[&str] = &["sha-1", "md5", "md4", "md2"];
const WEAK_CIPHERS: &[&str] = &["des", "3des", "rc4", "rc2", "blowfish"];

pub fn audit_webcrypto(target: &str) -> Vec<WebCryptoIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    analyze_webcrypto(&body)
}

pub fn analyze_webcrypto(body: &str) -> Vec<WebCryptoIssue> {
    if !has_crypto_indicators(body) {
        return Vec::new();
    }

    let lower = body.to_ascii_lowercase();
    let mut issues = Vec::new();

    check_weak_hashes(&lower, &mut issues);
    check_weak_ciphers(&lower, &mut issues);
    check_hardcoded_key(body, &mut issues);
    check_hardcoded_iv(body, &mut issues);
    check_insecure_random(body, &mut issues);
    check_exported_key(body, &mut issues);
    check_extractable(body, &mut issues);

    issues
}

fn has_crypto_indicators(body: &str) -> bool {
    body.contains("crypto.subtle")
        || body.contains("CryptoKey")
        || body.contains("crypto.getRandomValues")
        || body.contains("SubtleCrypto")
        || body.contains("Math.random")
            && (body.contains("encrypt") || body.contains("hash") || body.contains("key"))
}

fn check_weak_hashes(lower: &str, issues: &mut Vec<WebCryptoIssue>) {
    if !lower.contains("digest") && !lower.contains("hash") {
        return;
    }
    for alg in WEAK_HASHES {
        if lower.contains(alg) {
            issues.push(WebCryptoIssue::WeakHashAlgorithm {
                algorithm: alg.to_uppercase(),
            });
        }
    }
}

fn check_weak_ciphers(lower: &str, issues: &mut Vec<WebCryptoIssue>) {
    if !lower.contains("encrypt") && !lower.contains("decrypt") {
        return;
    }
    for alg in WEAK_CIPHERS {
        if lower.contains(alg) {
            issues.push(WebCryptoIssue::WeakEncryptionAlgorithm {
                algorithm: alg.to_uppercase(),
            });
        }
    }
}

fn check_hardcoded_key(body: &str, issues: &mut Vec<WebCryptoIssue>) {
    let key_patterns = [
        "importKey(\"raw\"",
        "importKey('raw'",
        "new Uint8Array([",
    ];
    let crypto_context = body.contains("crypto.subtle") || body.contains("CryptoKey");
    if crypto_context && key_patterns.iter().any(|p| body.contains(p)) {
        issues.push(WebCryptoIssue::HardcodedKey);
    }
}

fn check_hardcoded_iv(body: &str, issues: &mut Vec<WebCryptoIssue>) {
    let iv_patterns = [
        "iv: new Uint8Array([",
        "iv:new Uint8Array([",
        "iv: [",
        "iv:[",
    ];
    if iv_patterns.iter().any(|p| body.contains(p)) {
        issues.push(WebCryptoIssue::HardcodedIv);
    }
}

fn check_insecure_random(body: &str, issues: &mut Vec<WebCryptoIssue>) {
    if !body.contains("Math.random") {
        return;
    }
    let crypto_context = [
        "key", "encrypt", "decrypt", "token", "nonce", "salt", "iv", "secret",
    ];
    let has_crypto_nearby = crypto_context.iter().any(|c| body.contains(c));
    if has_crypto_nearby {
        issues.push(WebCryptoIssue::MathRandomForCrypto);
    }

    if !body.contains("crypto.getRandomValues") && body.contains("Math.random") {
        let random_for_security = body.contains("random()")
            && (body.contains("password") || body.contains("token") || body.contains("id"));
        if random_for_security {
            issues.push(WebCryptoIssue::InsecureRandomUsage);
        }
    }
}

fn check_exported_key(body: &str, issues: &mut Vec<WebCryptoIssue>) {
    if body.contains("exportKey") || body.contains("wrapKey") {
        issues.push(WebCryptoIssue::ExportedCryptoKey);
    }
}

fn check_extractable(body: &str, issues: &mut Vec<WebCryptoIssue>) {
    if !body.contains("generateKey") && !body.contains("importKey") {
        return;
    }
    if body.contains("extractable: true") || body.contains("extractable:true") {
        issues.push(WebCryptoIssue::NonExtractableKeyMissing);
    }
}

pub fn webcrypto_severity(issue: &WebCryptoIssue) -> f64 {
    match issue {
        WebCryptoIssue::HardcodedKey => 8.0,
        WebCryptoIssue::HardcodedIv => 7.5,
        WebCryptoIssue::MathRandomForCrypto => 7.0,
        WebCryptoIssue::InsecureRandomUsage => 6.5,
        WebCryptoIssue::WeakEncryptionAlgorithm { .. } => 6.0,
        WebCryptoIssue::WeakHashAlgorithm { .. } => 5.5,
        WebCryptoIssue::NonExtractableKeyMissing => 4.0,
        WebCryptoIssue::ExportedCryptoKey => 3.5,
    }
}

pub fn webcrypto_to_operations(
    issues: &[WebCryptoIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::WeakCryptography,
                webcrypto_severity(issue),
                0.75,
            )
        })
        .collect()
}
