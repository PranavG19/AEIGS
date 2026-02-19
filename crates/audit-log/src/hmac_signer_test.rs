#[cfg(test)]
mod tests {
    use crate::hmac_signer::HmacSigner;

    #[test]
    fn sign_produces_deterministic_output() {
        let signer = HmacSigner::new(b"secret-key");
        let mac1 = signer.sign(b"hello world");
        let mac2 = signer.sign(b"hello world");
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn different_data_produces_different_mac() {
        let signer = HmacSigner::new(b"secret-key");
        let mac1 = signer.sign(b"hello");
        let mac2 = signer.sign(b"world");
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn verify_returns_true_for_valid_signature() {
        let signer = HmacSigner::new(b"secret-key");
        let mac = signer.sign(b"test data");
        assert!(signer.verify(b"test data", &mac));
    }

    #[test]
    fn verify_returns_false_for_tampered_data() {
        let signer = HmacSigner::new(b"secret-key");
        let mac = signer.sign(b"original data");
        assert!(!signer.verify(b"tampered data", &mac));
    }

    #[test]
    fn verify_returns_false_for_wrong_key() {
        let signer1 = HmacSigner::new(b"key-one");
        let signer2 = HmacSigner::new(b"key-two");

        let mac = signer1.sign(b"test data");
        assert!(!signer2.verify(b"test data", &mac));
    }

    #[test]
    fn different_keys_produce_different_macs() {
        let signer1 = HmacSigner::new(b"key-one");
        let signer2 = HmacSigner::new(b"key-two");

        let mac1 = signer1.sign(b"same data");
        let mac2 = signer2.sign(b"same data");
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn empty_data_produces_valid_mac() {
        let signer = HmacSigner::new(b"key");
        let mac = signer.sign(b"");
        assert!(signer.verify(b"", &mac));
    }

    #[test]
    fn empty_key_produces_valid_mac() {
        let signer = HmacSigner::new(b"");
        let mac = signer.sign(b"data");
        assert!(signer.verify(b"data", &mac));
    }

    #[test]
    fn mac_is_32_bytes() {
        let signer = HmacSigner::new(b"key");
        let mac = signer.sign(b"data");
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn tampered_mac_rejected() {
        let signer = HmacSigner::new(b"key");
        let mut mac = signer.sign(b"data");
        mac[0] ^= 0xFF;
        assert!(!signer.verify(b"data", &mac));
    }

    #[test]
    fn with_derived_key_deterministic() {
        let signer1 = HmacSigner::with_derived_key(b"my-passphrase");
        let signer2 = HmacSigner::with_derived_key(b"my-passphrase");
        let mac1 = signer1.sign(b"data");
        let mac2 = signer2.sign(b"data");
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn with_derived_key_different_passphrases_different_keys() {
        let signer1 = HmacSigner::with_derived_key(b"passphrase-a");
        let signer2 = HmacSigner::with_derived_key(b"passphrase-b");
        let mac1 = signer1.sign(b"data");
        let mac2 = signer2.sign(b"data");
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn key_file_roundtrip() {
        let dir = std::env::temp_dir().join("aegis-test-hmac");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("key-{}.bin", std::process::id()));

        let signer = HmacSigner::new(b"file-based-key");
        signer.save_key_to_file(&path).unwrap();

        let restored = HmacSigner::with_key_file(&path).unwrap();
        let mac_original = signer.sign(b"test");
        let mac_restored = restored.sign(b"test");
        assert_eq!(mac_original, mac_restored);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn with_key_file_nonexistent_returns_error() {
        let result = HmacSigner::with_key_file(std::path::Path::new("/nonexistent/key.bin"));
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn save_key_file_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join("aegis-test-hmac-perms");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("key-perms-{}.bin", std::process::id()));

        let signer = HmacSigner::new(b"secret");
        signer.save_key_to_file(&path).unwrap();

        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);

        std::fs::remove_file(&path).ok();
    }
}
