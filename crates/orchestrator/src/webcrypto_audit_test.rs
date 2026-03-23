use crate::webcrypto_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_webcrypto("");
    assert!(issues.is_empty());
}

#[test]
fn no_crypto_indicators() {
    let body = "var x = 1 + 2;";
    let issues = analyze_webcrypto(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_api_usage() {
    let body = "crypto.subtle.generateKey(algo, true, ['encrypt']);";
    let issues = analyze_webcrypto(body);
    assert!(issues.contains(&WebCryptoIssue::ApiDetected));
}

#[test]
fn detects_sha1_weak_hash() {
    let body = r#"crypto.subtle.digest("SHA-1", data);"#;
    let issues = analyze_webcrypto(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        WebCryptoIssue::WeakHashAlgorithm { algorithm } if algorithm == "SHA-1"
    )));
}

#[test]
fn detects_sha1_lowercase() {
    let body = r#"crypto.subtle.digest("sha-1", data);"#;
    let issues = analyze_webcrypto(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        WebCryptoIssue::WeakHashAlgorithm { algorithm } if algorithm == "SHA-1"
    )));
}

#[test]
fn detects_md5_weak_hash() {
    let body = r#"crypto.subtle.digest("MD5", data);"#;
    let issues = analyze_webcrypto(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        WebCryptoIssue::WeakHashAlgorithm { algorithm } if algorithm == "MD5"
    )));
}

#[test]
fn detects_md4_weak_hash() {
    let body = r#"crypto.subtle.digest("MD4", data);"#;
    let issues = analyze_webcrypto(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        WebCryptoIssue::WeakHashAlgorithm { algorithm } if algorithm == "MD4"
    )));
}

#[test]
fn sha256_no_weak_hash_issue() {
    let body = r#"crypto.subtle.digest("SHA-256", data);"#;
    let issues = analyze_webcrypto(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, WebCryptoIssue::WeakHashAlgorithm { .. }))
    );
}

#[test]
fn detects_des_weak_cipher() {
    let body = r#"crypto.subtle.encrypt({name: "DES"}, key, data);"#;
    let issues = analyze_webcrypto(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        WebCryptoIssue::WeakEncryptionAlgorithm { algorithm } if algorithm == "DES"
    )));
}

#[test]
fn detects_rc4_weak_cipher() {
    let body = r#"crypto.subtle.encrypt({name: "RC4"}, key, data);"#;
    let issues = analyze_webcrypto(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        WebCryptoIssue::WeakEncryptionAlgorithm { algorithm } if algorithm == "RC4"
    )));
}

#[test]
fn detects_3des_weak_cipher() {
    let body = r#"crypto.subtle.encrypt({name: "3DES"}, key, data);"#;
    let issues = analyze_webcrypto(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        WebCryptoIssue::WeakEncryptionAlgorithm { algorithm } if algorithm == "3DES"
    )));
}

#[test]
fn aes_gcm_no_weak_cipher_issue() {
    let body = r#"crypto.subtle.encrypt({name: "AES-GCM"}, key, data);"#;
    let issues = analyze_webcrypto(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, WebCryptoIssue::WeakEncryptionAlgorithm { .. }))
    );
}

#[test]
fn detects_aes_cbc_without_hmac() {
    let body = r#"crypto.subtle.encrypt({name: "AES-CBC", iv: iv}, key, data);"#;
    let issues = analyze_webcrypto(body);
    assert!(issues.contains(&WebCryptoIssue::AesCbcWithoutHmac));
}

#[test]
fn aes_cbc_with_hmac_no_issue() {
    let body = r#"
        crypto.subtle.encrypt({name: "AES-CBC", iv: iv}, key, data);
        crypto.subtle.sign("HMAC", hmacKey, ciphertext);
    "#;
    let issues = analyze_webcrypto(body);
    assert!(!issues.contains(&WebCryptoIssue::AesCbcWithoutHmac));
}

#[test]
fn detects_rsa_512_short_key() {
    let body = r#"
        crypto.subtle.generateKey({name: "RSA-OAEP", modulusLength: 512}, true, ["encrypt"]);
    "#;
    let issues = analyze_webcrypto(body);
    assert!(issues.contains(&WebCryptoIssue::RsaOaepShortKey));
}

#[test]
fn detects_rsa_1024_short_key() {
    let body = r#"
        crypto.subtle.generateKey({name: "RSA-OAEP", modulusLength: 1024}, true, ["encrypt"]);
    "#;
    let issues = analyze_webcrypto(body);
    assert!(issues.contains(&WebCryptoIssue::RsaOaepShortKey));
}

#[test]
fn rsa_2048_no_short_key_issue() {
    let body = r#"
        crypto.subtle.generateKey({name: "RSA-OAEP", modulusLength: 2048}, true, ["encrypt"]);
    "#;
    let issues = analyze_webcrypto(body);
    assert!(!issues.contains(&WebCryptoIssue::RsaOaepShortKey));
}

#[test]
fn detects_hardcoded_key_import() {
    let body = r#"
        crypto.subtle.importKey("raw", new Uint8Array([1,2,3,4]), "AES-GCM", true, ["encrypt"]);
    "#;
    let issues = analyze_webcrypto(body);
    assert!(issues.contains(&WebCryptoIssue::HardcodedKey));
}

#[test]
fn detects_hardcoded_key_var() {
    let body = r#"
        var key = [1, 2, 3, 4];
        crypto.subtle.importKey("raw", key, "AES-GCM", true, ["encrypt"]);
    "#;
    let issues = analyze_webcrypto(body);
    assert!(issues.contains(&WebCryptoIssue::HardcodedKey));
}

#[test]
fn detects_hardcoded_iv_inline() {
    let body = r#"
        crypto.subtle.encrypt({name: "AES-GCM", iv: new Uint8Array([1,2,3])}, key, data);
    "#;
    let issues = analyze_webcrypto(body);
    assert!(issues.contains(&WebCryptoIssue::HardcodedIv));
}

#[test]
fn detects_hardcoded_iv_const() {
    let body = r#"
        const iv = new Uint8Array([1,2,3,4,5,6,7,8]);
        crypto.subtle.encrypt({name: "AES-GCM", iv: iv}, key, data);
    "#;
    let issues = analyze_webcrypto(body);
    assert!(issues.contains(&WebCryptoIssue::HardcodedIv));
}

#[test]
fn detects_hardcoded_iv_array() {
    let body = r#"
        crypto.subtle.encrypt({name: "AES-GCM", iv: [1,2,3,4]}, key, data);
    "#;
    let issues = analyze_webcrypto(body);
    assert!(issues.contains(&WebCryptoIssue::HardcodedIv));
}

#[test]
fn detects_math_random_in_crypto_context() {
    let body = r#"
        var key = Math.random().toString(36);
        crypto.subtle.encrypt(algo, key, data);
    "#;
    let issues = analyze_webcrypto(body);
    assert!(issues.contains(&WebCryptoIssue::MathRandomForCrypto));
}

#[test]
fn detects_math_random_for_nonce() {
    let body = r#"
        var nonce = Math.random().toString(36);
        crypto.subtle.encrypt(algo, key, data);
    "#;
    let issues = analyze_webcrypto(body);
    assert!(issues.contains(&WebCryptoIssue::MathRandomForCrypto));
}

#[test]
fn detects_insecure_random_for_token() {
    let body = r#"
        var token = Math.random().toString(36);
        crypto.subtle.importKey("raw", token, "AES-GCM", true, ["encrypt"]);
    "#;
    let issues = analyze_webcrypto(body);
    assert!(issues.contains(&WebCryptoIssue::InsecureRandomUsage));
}

#[test]
fn detects_insecure_random_for_session() {
    let body = r#"
        var sessionId = Math.random().toString(36);
        crypto.subtle.encrypt(algo, key, data);
    "#;
    let issues = analyze_webcrypto(body);
    assert!(issues.contains(&WebCryptoIssue::InsecureRandomUsage));
}

#[test]
fn detects_exported_key() {
    let body = r#"crypto.subtle.exportKey("jwk", key);"#;
    let issues = analyze_webcrypto(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        WebCryptoIssue::ExportedCryptoKey | WebCryptoIssue::UnwrappedKeyExport
    )));
}

#[test]
fn detects_unwrapped_key_export() {
    let body = r#"crypto.subtle.exportKey("raw", key);"#;
    let issues = analyze_webcrypto(body);
    assert!(issues.contains(&WebCryptoIssue::UnwrappedKeyExport));
}

#[test]
fn detects_wrap_key() {
    let body = r#"crypto.subtle.wrapKey("jwk", key, wrappingKey, algo);"#;
    let issues = analyze_webcrypto(body);
    assert!(issues.contains(&WebCryptoIssue::ExportedCryptoKey));
}

#[test]
fn detects_extractable_true() {
    let body = r#"
        crypto.subtle.generateKey(algo, extractable: true, ["encrypt"]);
    "#;
    let issues = analyze_webcrypto(body);
    assert!(issues.contains(&WebCryptoIssue::NonExtractableKeyMissing));
}

#[test]
fn extractable_false_no_issue() {
    let body = r#"
        crypto.subtle.generateKey(algo, false, ["encrypt"]);
    "#;
    let issues = analyze_webcrypto(body);
    assert!(!issues.contains(&WebCryptoIssue::NonExtractableKeyMissing));
}

#[test]
fn detects_missing_key_usage_for_signing() {
    let body = r#"
        crypto.subtle.generateKey(algo, true, ["sign"]);
    "#;
    let issues = analyze_webcrypto(body);
    assert!(issues.contains(&WebCryptoIssue::MissingKeyUsageRestriction));
}

#[test]
fn key_usage_with_extractable_false_no_issue() {
    let body = r#"
        crypto.subtle.generateKey(algo, false, ["sign"]);
    "#;
    let issues = analyze_webcrypto(body);
    assert!(!issues.contains(&WebCryptoIssue::MissingKeyUsageRestriction));
}

#[test]
fn severity_hardcoded_key_highest() {
    assert_eq!(webcrypto_severity(&WebCryptoIssue::HardcodedKey), 9.0);
}

#[test]
fn severity_api_detected_lowest() {
    assert_eq!(webcrypto_severity(&WebCryptoIssue::ApiDetected), 2.0);
}

#[test]
fn severity_aes_cbc_medium_high() {
    assert_eq!(webcrypto_severity(&WebCryptoIssue::AesCbcWithoutHmac), 6.5);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        WebCryptoIssue::HardcodedKey,
        WebCryptoIssue::MathRandomForCrypto,
    ];
    let mut seq = 0u64;
    let ops = webcrypto_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn to_operations_empty_input() {
    let issues: Vec<WebCryptoIssue> = vec![];
    let mut seq = 0u64;
    let ops = webcrypto_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 0);
}

#[test]
fn display_api_detected() {
    assert_eq!(WebCryptoIssue::ApiDetected.to_string(), "api_detected");
}

#[test]
fn display_hardcoded_key() {
    assert_eq!(WebCryptoIssue::HardcodedKey.to_string(), "hardcoded_key");
}

#[test]
fn display_hardcoded_iv() {
    assert_eq!(WebCryptoIssue::HardcodedIv.to_string(), "hardcoded_iv");
}

#[test]
fn display_insecure_random() {
    assert_eq!(
        WebCryptoIssue::InsecureRandomUsage.to_string(),
        "insecure_random"
    );
}

#[test]
fn display_math_random_crypto() {
    assert_eq!(
        WebCryptoIssue::MathRandomForCrypto.to_string(),
        "math_random_crypto"
    );
}

#[test]
fn display_exported_key() {
    assert_eq!(
        WebCryptoIssue::ExportedCryptoKey.to_string(),
        "exported_crypto_key"
    );
}

#[test]
fn display_unwrapped_key_export() {
    assert_eq!(
        WebCryptoIssue::UnwrappedKeyExport.to_string(),
        "unwrapped_key_export"
    );
}

#[test]
fn display_non_extractable_missing() {
    assert_eq!(
        WebCryptoIssue::NonExtractableKeyMissing.to_string(),
        "non_extractable_missing"
    );
}

#[test]
fn display_missing_key_usage() {
    assert_eq!(
        WebCryptoIssue::MissingKeyUsageRestriction.to_string(),
        "missing_key_usage"
    );
}

#[test]
fn display_aes_cbc() {
    assert_eq!(
        WebCryptoIssue::AesCbcWithoutHmac.to_string(),
        "aes_cbc_no_integrity"
    );
}

#[test]
fn display_rsa_short_key() {
    assert_eq!(WebCryptoIssue::RsaOaepShortKey.to_string(), "rsa_short_key");
}

#[test]
fn display_weak_hash() {
    let issue = WebCryptoIssue::WeakHashAlgorithm {
        algorithm: "SHA-1".to_string(),
    };
    assert_eq!(issue.to_string(), "weak_hash:SHA-1");
}

#[test]
fn display_weak_cipher() {
    let issue = WebCryptoIssue::WeakEncryptionAlgorithm {
        algorithm: "DES".to_string(),
    };
    assert_eq!(issue.to_string(), "weak_cipher:DES");
}
