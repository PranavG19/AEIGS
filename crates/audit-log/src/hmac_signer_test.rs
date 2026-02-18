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
}
