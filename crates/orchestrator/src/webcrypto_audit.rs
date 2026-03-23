use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum WebCryptoIssue {
    ApiDetected,
    WeakHashAlgorithm { algorithm: String },
    WeakEncryptionAlgorithm { algorithm: String },
    AesCbcWithoutHmac,
    RsaOaepShortKey,
    HardcodedKey,
    HardcodedIv,
    InsecureRandomUsage,
    MathRandomForCrypto,
    ExportedCryptoKey,
    UnwrappedKeyExport,
    NonExtractableKeyMissing,
    MissingKeyUsageRestriction,
}

impl std::fmt::Display for WebCryptoIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::WeakHashAlgorithm { algorithm } => write!(f, "weak_hash:{algorithm}"),
            Self::WeakEncryptionAlgorithm { algorithm } => write!(f, "weak_cipher:{algorithm}"),
            Self::AesCbcWithoutHmac => write!(f, "aes_cbc_no_integrity"),
            Self::RsaOaepShortKey => write!(f, "rsa_short_key"),
            Self::HardcodedKey => write!(f, "hardcoded_key"),
            Self::HardcodedIv => write!(f, "hardcoded_iv"),
            Self::InsecureRandomUsage => write!(f, "insecure_random"),
            Self::MathRandomForCrypto => write!(f, "math_random_crypto"),
            Self::ExportedCryptoKey => write!(f, "exported_crypto_key"),
            Self::UnwrappedKeyExport => write!(f, "unwrapped_key_export"),
            Self::NonExtractableKeyMissing => write!(f, "non_extractable_missing"),
            Self::MissingKeyUsageRestriction => write!(f, "missing_key_usage"),
        }
    }
}

pub fn webcrypto_severity(issue: &WebCryptoIssue) -> f64 {
    match issue {
        WebCryptoIssue::HardcodedKey => 9.0,
        WebCryptoIssue::HardcodedIv => 8.0,
        WebCryptoIssue::MathRandomForCrypto => 7.5,
        WebCryptoIssue::WeakEncryptionAlgorithm { .. } => 7.0,
        WebCryptoIssue::AesCbcWithoutHmac => 6.5,
        WebCryptoIssue::InsecureRandomUsage => 6.0,
        WebCryptoIssue::WeakHashAlgorithm { .. } => 5.5,
        WebCryptoIssue::RsaOaepShortKey => 5.0,
        WebCryptoIssue::UnwrappedKeyExport => 4.5,
        WebCryptoIssue::NonExtractableKeyMissing => 4.0,
        WebCryptoIssue::MissingKeyUsageRestriction => 3.5,
        WebCryptoIssue::ExportedCryptoKey => 3.0,
        WebCryptoIssue::ApiDetected => 2.0,
    }
}

pub fn audit_webcrypto(target: &str) -> Vec<WebCryptoIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send() {
        Ok(r) => r.text().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    analyze_webcrypto(&body)
}

pub fn analyze_webcrypto(body: &str) -> Vec<WebCryptoIssue> {
    if !has_crypto_indicators(body) {
        return Vec::new();
    }

    let mut issues = Vec::new();

    issues.push(WebCryptoIssue::ApiDetected);
    check_weak_hashes(body, &mut issues);
    check_weak_ciphers(body, &mut issues);
    check_aes_cbc(body, &mut issues);
    check_rsa_key_size(body, &mut issues);
    check_hardcoded_key(body, &mut issues);
    check_hardcoded_iv(body, &mut issues);
    check_insecure_random(body, &mut issues);
    check_exported_key(body, &mut issues);
    check_extractable(body, &mut issues);
    check_key_usage(body, &mut issues);

    issues
}

fn has_crypto_indicators(body: &str) -> bool {
    body.contains("crypto.subtle")
        || body.contains("CryptoKey")
        || body.contains("SubtleCrypto")
        || body.contains("generateKey")
        || body.contains("importKey")
        || body.contains("crypto.getRandomValues")
}

fn check_weak_hashes(body: &str, issues: &mut Vec<WebCryptoIssue>) {
    let weak_hashes = [
        ("SHA-1", "SHA-1"),
        ("sha-1", "SHA-1"),
        ("MD5", "MD5"),
        ("md5", "MD5"),
        ("MD4", "MD4"),
        ("md4", "MD4"),
    ];

    for (pattern, name) in &weak_hashes {
        if body.contains("digest") && body.contains(pattern) {
            issues.push(WebCryptoIssue::WeakHashAlgorithm {
                algorithm: name.to_string(),
            });
        }
    }
}

fn check_weak_ciphers(body: &str, issues: &mut Vec<WebCryptoIssue>) {
    let weak_ciphers = [
        ("DES", "DES"),
        ("des", "DES"),
        ("3DES", "3DES"),
        ("RC4", "RC4"),
        ("rc4", "RC4"),
        ("RC2", "RC2"),
        ("rc2", "RC2"),
        ("Blowfish", "Blowfish"),
        ("blowfish", "Blowfish"),
    ];

    let has_encrypt_context = body.contains("encrypt") || body.contains("decrypt");
    if !has_encrypt_context {
        return;
    }

    for (pattern, name) in &weak_ciphers {
        if body.contains(pattern) {
            issues.push(WebCryptoIssue::WeakEncryptionAlgorithm {
                algorithm: name.to_string(),
            });
        }
    }
}

fn check_aes_cbc(body: &str, issues: &mut Vec<WebCryptoIssue>) {
    let has_aes_cbc = body.contains("AES-CBC") || body.contains("aes-cbc");
    if !has_aes_cbc {
        return;
    }

    let has_hmac = body.contains("HMAC") || body.contains("hmac") || body.contains("sign");
    if !has_hmac {
        issues.push(WebCryptoIssue::AesCbcWithoutHmac);
    }
}

fn check_rsa_key_size(body: &str, issues: &mut Vec<WebCryptoIssue>) {
    if !body.contains("RSA-OAEP") && !body.contains("rsa-oaep") {
        return;
    }

    let short_key_patterns = [
        "modulusLength: 512",
        "modulusLength: 1024",
        "modulusLength:512",
        "modulusLength:1024",
    ];

    if short_key_patterns.iter().any(|p| body.contains(p)) {
        issues.push(WebCryptoIssue::RsaOaepShortKey);
    }
}

fn check_hardcoded_key(body: &str, issues: &mut Vec<WebCryptoIssue>) {
    let key_patterns = [
        "importKey(\"raw\"",
        "importKey('raw'",
        "new Uint8Array([",
        "const key = [",
        "var key = [",
        "let key = [",
    ];

    let has_crypto = body.contains("crypto.subtle") || body.contains("CryptoKey");
    if has_crypto && key_patterns.iter().any(|p| body.contains(p)) {
        issues.push(WebCryptoIssue::HardcodedKey);
    }
}

fn check_hardcoded_iv(body: &str, issues: &mut Vec<WebCryptoIssue>) {
    let iv_patterns = [
        "iv: new Uint8Array([",
        "iv:new Uint8Array([",
        "iv: [",
        "iv:[",
        "const iv = new Uint8Array([",
        "var iv = new Uint8Array([",
        "let iv = new Uint8Array([",
        "const iv = [",
        "var iv = [",
        "let iv = [",
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
        "key", "encrypt", "decrypt", "token", "nonce", "salt", "iv", "secret", "password",
    ];

    let has_crypto_nearby = crypto_context.iter().any(|c| body.contains(c));
    if has_crypto_nearby {
        issues.push(WebCryptoIssue::MathRandomForCrypto);
    }

    if !body.contains("crypto.getRandomValues") {
        let security_context = body.contains("random()")
            && (body.contains("password")
                || body.contains("token")
                || body.contains("session")
                || body.contains("id"));
        if security_context {
            issues.push(WebCryptoIssue::InsecureRandomUsage);
        }
    }
}

fn check_exported_key(body: &str, issues: &mut Vec<WebCryptoIssue>) {
    if body.contains("exportKey") {
        let has_encryption = body.contains("encrypt") || body.contains("wrapKey");
        if has_encryption {
            issues.push(WebCryptoIssue::ExportedCryptoKey);
        } else {
            issues.push(WebCryptoIssue::UnwrappedKeyExport);
        }
    }

    if body.contains("wrapKey") && !body.contains("exportKey") {
        issues.push(WebCryptoIssue::ExportedCryptoKey);
    }
}

fn check_extractable(body: &str, issues: &mut Vec<WebCryptoIssue>) {
    if !body.contains("generateKey") && !body.contains("importKey") {
        return;
    }

    let extractable_true = body.contains("extractable: true") || body.contains("extractable:true");
    if extractable_true {
        issues.push(WebCryptoIssue::NonExtractableKeyMissing);
    }
}

fn check_key_usage(body: &str, issues: &mut Vec<WebCryptoIssue>) {
    if !body.contains("generateKey") {
        return;
    }

    let has_sign = body.contains("\"sign\"") || body.contains("'sign'");
    if !has_sign {
        return;
    }

    let has_extractable_false = body.contains("extractable: false")
        || body.contains("extractable:false")
        || body.contains(", false,");

    if !has_extractable_false {
        issues.push(WebCryptoIssue::MissingKeyUsageRestriction);
    }
}

pub fn webcrypto_to_operations(issues: &[WebCryptoIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::WeakCryptography,
                webcrypto_severity(issue),
                0.5,
            )
        })
        .collect()
}
