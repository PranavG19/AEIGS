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
fn detects_sha1_weak_hash() {
    let body = r#"crypto.subtle.digest("SHA-1", data);"#;
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
fn sha256_no_weak_hash_issue() {
    let body = r#"crypto.subtle.digest("SHA-256", data);"#;
    let issues = analyze_webcrypto(body);
    assert!(!issues.iter().any(|i| matches!(
        i,
        WebCryptoIssue::WeakHashAlgorithm { .. }
    )));
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
fn aes_no_weak_cipher_issue() {
    let body = r#"crypto.subtle.encrypt({name: "AES-GCM"}, key, data);"#;
    let issues = analyze_webcrypto(body);
    assert!(!issues.iter().any(|i| matches!(
        i,
        WebCryptoIssue::WeakEncryptionAlgorithm { .. }
    )));
}

#[test]
fn detects_hardcoded_key() {
    let body = r#"
        crypto.subtle.importKey("raw", new Uint8Array([1,2,3,4]), "AES-GCM", true, ["encrypt"]);
    "#;
    let issues = analyze_webcrypto(body);
    assert!(issues.contains(&WebCryptoIssue::HardcodedKey));
}

#[test]
fn detects_hardcoded_iv() {
    let body = r#"
        crypto.subtle.encrypt({name: "AES-GCM", iv: new Uint8Array([1,2,3])}, key, data);
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
fn detects_insecure_random_for_token() {
    let body = r#"
        var token = Math.random().toString(36);
        var key = deriveKey(token);
    "#;
    let issues = analyze_webcrypto(body);
    assert!(issues.contains(&WebCryptoIssue::InsecureRandomUsage));
}

#[test]
fn detects_exported_key() {
    let body = r#"crypto.subtle.exportKey("jwk", key);"#;
    let issues = analyze_webcrypto(body);
    assert!(issues.contains(&WebCryptoIssue::ExportedCryptoKey));
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
fn severity_hardcoded_key_highest() {
    assert_eq!(webcrypto_severity(&WebCryptoIssue::HardcodedKey), 8.0);
}

#[test]
fn severity_exported_key_lowest() {
    assert_eq!(webcrypto_severity(&WebCryptoIssue::ExportedCryptoKey), 3.5);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        WebCryptoIssue::HardcodedKey,
        WebCryptoIssue::MathRandomForCrypto,
    ];
    let mut seq = 0;
    let ops = webcrypto_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(WebCryptoIssue::HardcodedKey.to_string(), "hardcoded_key");
    assert_eq!(WebCryptoIssue::HardcodedIv.to_string(), "hardcoded_iv");
    assert_eq!(
        WebCryptoIssue::InsecureRandomUsage.to_string(),
        "insecure_random"
    );
    assert_eq!(
        WebCryptoIssue::MathRandomForCrypto.to_string(),
        "math_random_crypto"
    );
    assert_eq!(
        WebCryptoIssue::ExportedCryptoKey.to_string(),
        "exported_crypto_key"
    );
    assert_eq!(
        WebCryptoIssue::NonExtractableKeyMissing.to_string(),
        "non_extractable_missing"
    );
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
