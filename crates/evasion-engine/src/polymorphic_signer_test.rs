#[cfg(test)]
mod tests {
    use crate::polymorphic_signer::{PolymorphicConfig, PolymorphicSigner, TransferEncoding};
    use std::collections::HashSet;

    fn default_config() -> PolymorphicConfig {
        PolymorphicConfig::default()
    }

    #[test]
    fn test_two_sessions_differ() {
        let a = PolymorphicSigner::with_seed(default_config(), 1);
        let b = PolymorphicSigner::with_seed(default_config(), 2);
        assert_ne!(a.session_fingerprint(), b.session_fingerprint());
    }

    #[test]
    fn test_same_seed_same_fingerprint() {
        let a = PolymorphicSigner::with_seed(default_config(), 42);
        let b = PolymorphicSigner::with_seed(default_config(), 42);
        assert_eq!(a.session_fingerprint(), b.session_fingerprint());
    }

    #[test]
    fn test_exploration_constant_in_range() {
        let config = PolymorphicConfig::default().with_c_range(0.5, 3.0);
        for seed in 0..100 {
            let signer = PolymorphicSigner::with_seed(config.clone(), seed);
            let c = signer.exploration_constant();
            assert!(
                c >= 0.5 && c <= 3.0,
                "exploration constant {c} out of range [0.5, 3.0] for seed {seed}"
            );
        }
    }

    #[test]
    fn test_exploration_constant_default_range() {
        for seed in 0..50 {
            let signer = PolymorphicSigner::with_seed(default_config(), seed);
            let c = signer.exploration_constant();
            assert!(
                c >= 0.8 && c <= 2.2,
                "exploration constant {c} outside default range"
            );
        }
    }

    #[test]
    fn test_timing_noise_applied() {
        let config = PolymorphicConfig::default().with_timing_noise_pct(0.20);
        let mut signer = PolymorphicSigner::with_seed(config, 42);
        let base = 1000u64;
        let max_deviation = (base as f64 * 0.20).round() as u64;
        let mut saw_different = false;
        for _ in 0..200 {
            let noisy = signer.apply_timing_noise(base);
            let diff = (noisy as i64 - base as i64).unsigned_abs();
            assert!(
                diff <= max_deviation,
                "timing noise {noisy} deviates more than {max_deviation} from base {base}"
            );
            if noisy != base {
                saw_different = true;
            }
        }
        assert!(saw_different, "timing noise never deviated from base");
    }

    #[test]
    fn test_timing_noise_zero_base() {
        let mut signer = PolymorphicSigner::with_seed(default_config(), 42);
        assert_eq!(signer.apply_timing_noise(0), 0);
    }

    #[test]
    fn test_timing_noise_zero_pct() {
        let config = PolymorphicConfig::default().with_timing_noise_pct(0.0);
        let mut signer = PolymorphicSigner::with_seed(config, 42);
        for _ in 0..50 {
            assert_eq!(signer.apply_timing_noise(1000), 1000);
        }
    }

    #[test]
    fn test_header_randomization() {
        let mut signer = PolymorphicSigner::with_seed(default_config(), 42);
        let headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("Accept".to_string(), "text/html".to_string()),
            ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
            ("Accept-Encoding".to_string(), "gzip, deflate".to_string()),
            ("Connection".to_string(), "keep-alive".to_string()),
        ];
        let original_keys: HashSet<String> = headers.iter().map(|(k, _)| k.clone()).collect();
        let shuffled = signer.randomize_headers(headers.clone());
        let shuffled_keys: HashSet<String> = shuffled.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(original_keys, shuffled_keys);
        assert_eq!(shuffled.len(), 5);

        let original_values: HashSet<String> = headers.iter().map(|(_, v)| v.clone()).collect();
        let shuffled_values: HashSet<String> = shuffled.iter().map(|(_, v)| v.clone()).collect();
        assert_eq!(original_values, shuffled_values);
    }

    #[test]
    fn test_header_randomization_disabled() {
        let config = PolymorphicConfig::default().with_header_randomize(false);
        let mut signer = PolymorphicSigner::with_seed(config, 42);
        let headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("Accept".to_string(), "text/html".to_string()),
        ];
        let result = signer.randomize_headers(headers.clone());
        assert_eq!(result, headers);
    }

    #[test]
    fn test_header_randomization_single_header() {
        let mut signer = PolymorphicSigner::with_seed(default_config(), 42);
        let headers = vec![("Host".to_string(), "example.com".to_string())];
        let result = signer.randomize_headers(headers.clone());
        assert_eq!(result, headers);
    }

    #[test]
    fn test_chunk_size_varies() {
        let mut signer = PolymorphicSigner::with_seed(default_config(), 42);
        let mut sizes: HashSet<usize> = HashSet::new();
        for _ in 0..100 {
            let size = signer.vary_chunk_size();
            assert!(
                size >= 1024 && size <= 16384,
                "chunk size {size} out of range [1024, 16384]"
            );
            sizes.insert(size);
        }
        assert!(
            sizes.len() > 5,
            "expected more than 5 distinct chunk sizes, got {}",
            sizes.len()
        );
    }

    #[test]
    fn test_transfer_encoding_variants() {
        let mut signer = PolymorphicSigner::with_seed(default_config(), 42);
        let mut seen = HashSet::new();
        for _ in 0..100 {
            seen.insert(signer.vary_transfer_encoding());
        }
        assert!(
            seen.contains(&TransferEncoding::Chunked),
            "never saw Chunked"
        );
        assert!(
            seen.contains(&TransferEncoding::Identity),
            "never saw Identity"
        );
        assert!(seen.contains(&TransferEncoding::Gzip), "never saw Gzip");
    }

    #[test]
    fn test_transfer_encoding_display() {
        assert_eq!(TransferEncoding::Chunked.to_string(), "chunked");
        assert_eq!(TransferEncoding::Identity.to_string(), "identity");
        assert_eq!(TransferEncoding::Gzip.to_string(), "gzip");
    }

    #[test]
    fn test_config_builder() {
        let config = PolymorphicConfig::default()
            .with_c_range(1.0, 1.5)
            .with_timing_noise_pct(0.25)
            .with_header_randomize(false);
        assert_eq!(config.c_range, (1.0, 1.5));
        assert!((config.timing_noise_pct - 0.25).abs() < f64::EPSILON);
        assert!(!config.header_randomize);
    }

    #[test]
    fn test_fingerprint_is_32_bytes() {
        let signer = PolymorphicSigner::with_seed(default_config(), 99);
        assert_eq!(signer.session_fingerprint().len(), 32);
    }

    #[test]
    fn test_many_sessions_unique_fingerprints() {
        let fingerprints: Vec<[u8; 32]> = (0..200u64)
            .map(|seed| {
                let s = PolymorphicSigner::with_seed(default_config(), seed);
                *s.session_fingerprint()
            })
            .collect();
        let unique: HashSet<[u8; 32]> = fingerprints.iter().cloned().collect();
        assert_eq!(unique.len(), fingerprints.len());
    }
}
