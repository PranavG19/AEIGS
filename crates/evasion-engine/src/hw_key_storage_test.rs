use crate::hw_key_storage::*;

#[test]
fn test_generate_and_sign() {
    let mut store = HardwareKeyStore::with_backend(KeyBackend::SoftwareFallback);
    let handle = store.generate_key("ed25519").unwrap();

    assert_eq!(handle.backend, KeyBackend::SoftwareFallback);
    assert!(handle.id.starts_with("sw-key-"));

    let data = b"payload to sign";
    let signature = store.sign(&handle, data).unwrap();
    assert_eq!(signature.len(), 64);
    assert!(signature.iter().any(|b| *b != 0));
}

#[test]
fn test_sign_verify_roundtrip() {
    let mut store = HardwareKeyStore::with_backend(KeyBackend::SoftwareFallback);
    let handle = store.generate_key("ed25519").unwrap();

    let data = b"authenticated message content";
    let signature = store.sign(&handle, data).unwrap();

    let valid = store.verify(&handle, data, &signature).unwrap();
    assert!(valid);

    let mut tampered_sig = signature.clone();
    tampered_sig[0] ^= 0xFF;
    let invalid = store.verify(&handle, data, &tampered_sig).unwrap();
    assert!(!invalid);

    let wrong_data = b"different message entirely";
    let mismatch = store.verify(&handle, wrong_data, &signature).unwrap();
    assert!(!mismatch);
}

#[test]
fn test_key_not_extractable() {
    let mut store = HardwareKeyStore::with_backend(KeyBackend::SoftwareFallback);
    let handle = store.generate_key("ecdsa-p256").unwrap();

    let keys = store.list_keys();
    let meta = keys.iter().find(|m| m.handle.id == handle.id).unwrap();
    assert!(!meta.extractable);
    assert_eq!(meta.algorithm, "ecdsa-p256");
    assert!(meta.created_at_ms > 0);
}

#[test]
fn test_delete_key() {
    let mut store = HardwareKeyStore::with_backend(KeyBackend::SoftwareFallback);
    let handle = store.generate_key("hmac-sha256").unwrap();

    assert_eq!(store.list_keys().len(), 1);

    let result = store.delete_key(&handle);
    assert!(result.is_ok());
    assert!(store.list_keys().is_empty());

    let sign_result = store.sign(&handle, b"data");
    assert_eq!(sign_result, Err(KeyStoreError::KeyNotFound));

    let delete_again = store.delete_key(&handle);
    assert_eq!(delete_again, Err(KeyStoreError::KeyNotFound));
}

#[test]
fn test_list_keys() {
    let mut store = HardwareKeyStore::with_backend(KeyBackend::SoftwareFallback);

    assert!(store.list_keys().is_empty());

    let handle_a = store.generate_key("ed25519").unwrap();
    let handle_b = store.generate_key("ecdsa-p256").unwrap();
    let handle_c = store.generate_key("hmac-sha256").unwrap();

    let keys = store.list_keys();
    assert_eq!(keys.len(), 3);

    let ids: Vec<&str> = keys.iter().map(|m| m.handle.id.as_str()).collect();
    assert!(ids.contains(&handle_a.id.as_str()));
    assert!(ids.contains(&handle_b.id.as_str()));
    assert!(ids.contains(&handle_c.id.as_str()));

    let algos: Vec<&str> = keys.iter().map(|m| m.algorithm.as_str()).collect();
    assert!(algos.contains(&"ed25519"));
    assert!(algos.contains(&"ecdsa-p256"));
    assert!(algos.contains(&"hmac-sha256"));
}

#[test]
fn test_software_fallback() {
    let mut sw_store = SoftwareKeyStore::new();
    let handle = sw_store.generate_key("ed25519").unwrap();
    assert_eq!(handle.backend, KeyBackend::SoftwareFallback);

    let data = b"software fallback test data";
    let sig = sw_store.sign(&handle, data).unwrap();
    let valid = sw_store.verify(&handle, data, &sig).unwrap();
    assert!(valid);

    assert!(sw_store.has_key(&handle));
    sw_store.delete_key(&handle).unwrap();
    assert!(!sw_store.has_key(&handle));
}

#[test]
fn test_unsupported_algorithm_fails() {
    let mut store = HardwareKeyStore::with_backend(KeyBackend::SoftwareFallback);
    let result = store.generate_key("quantum-lattice-4096");
    assert_eq!(result, Err(KeyStoreError::GenerationFailed));
}

#[test]
fn test_sign_nonexistent_key_fails() {
    let store = HardwareKeyStore::with_backend(KeyBackend::SoftwareFallback);
    let phantom = KeyHandle {
        id: "sw-key-9999".to_string(),
        backend: KeyBackend::SoftwareFallback,
    };
    let result = store.sign(&phantom, b"data");
    assert_eq!(result, Err(KeyStoreError::KeyNotFound));
}

#[test]
fn test_verify_nonexistent_key_fails() {
    let store = HardwareKeyStore::with_backend(KeyBackend::SoftwareFallback);
    let phantom = KeyHandle {
        id: "sw-key-9999".to_string(),
        backend: KeyBackend::SoftwareFallback,
    };
    let result = store.verify(&phantom, b"data", &[0u8; 64]);
    assert_eq!(result, Err(KeyStoreError::KeyNotFound));
}

#[test]
fn test_different_keys_produce_different_signatures() {
    let mut store = HardwareKeyStore::with_backend(KeyBackend::SoftwareFallback);
    let handle_a = store.generate_key("ed25519").unwrap();
    let handle_b = store.generate_key("ed25519").unwrap();

    let data = b"identical payload";
    let sig_a = store.sign(&handle_a, data).unwrap();
    let sig_b = store.sign(&handle_b, data).unwrap();
    assert_ne!(sig_a, sig_b);
}

#[test]
fn test_key_store_error_display() {
    assert_eq!(format!("{}", KeyStoreError::KeyNotFound), "key-not-found");
    assert_eq!(
        format!("{}", KeyStoreError::GenerationFailed),
        "generation-failed"
    );
    assert_eq!(
        format!("{}", KeyStoreError::SigningFailed),
        "signing-failed"
    );
    assert_eq!(
        format!("{}", KeyStoreError::VerificationFailed),
        "verification-failed"
    );
    assert_eq!(
        format!("{}", KeyStoreError::BackendUnavailable),
        "backend-unavailable"
    );
}

#[test]
fn test_key_backend_display() {
    assert_eq!(format!("{}", KeyBackend::MacOsKeychain), "macos-keychain");
    assert_eq!(format!("{}", KeyBackend::LinuxTpm2), "linux-tpm2");
    assert_eq!(format!("{}", KeyBackend::WindowsCng), "windows-cng");
    assert_eq!(
        format!("{}", KeyBackend::SoftwareFallback),
        "software-fallback"
    );
}

#[test]
fn test_platform_detection() {
    let store = HardwareKeyStore::new();
    let backend = store.backend();
    if cfg!(target_os = "macos") {
        assert_eq!(*backend, KeyBackend::MacOsKeychain);
    } else if cfg!(target_os = "linux") {
        assert_eq!(*backend, KeyBackend::LinuxTpm2);
    } else if cfg!(target_os = "windows") {
        assert_eq!(*backend, KeyBackend::WindowsCng);
    } else {
        assert_eq!(*backend, KeyBackend::SoftwareFallback);
    }
}

#[test]
fn test_multiple_algorithms_coexist() {
    let mut store = HardwareKeyStore::with_backend(KeyBackend::SoftwareFallback);
    let ed_handle = store.generate_key("ed25519").unwrap();
    let ec_handle = store.generate_key("ecdsa-p256").unwrap();
    let hmac_handle = store.generate_key("hmac-sha256").unwrap();

    let data = b"multi-algorithm test";
    for handle in [&ed_handle, &ec_handle, &hmac_handle] {
        let sig = store.sign(handle, data).unwrap();
        let valid = store.verify(handle, data, &sig).unwrap();
        assert!(valid);
    }
}
