#[cfg(test)]
mod tests {
    use crate::payload_cache::{PayloadCache, PayloadCacheConfig};

    fn default_cache() -> PayloadCache {
        PayloadCache::with_default_config()
    }

    fn small_cache(per_context: usize, total: usize) -> PayloadCache {
        let config = PayloadCacheConfig::default()
            .with_max_entries_per_context(per_context)
            .with_max_total_entries(total);
        PayloadCache::new(config)
    }

    #[test]
    fn default_config_creation() {
        let config = PayloadCacheConfig::default();
        assert_eq!(config.max_entries_per_context, 1000);
        assert_eq!(config.max_total_entries, 10_000);
        assert!(config.enable_stats);
    }

    #[test]
    fn builder_pattern_clamps_values() {
        let config = PayloadCacheConfig::default()
            .with_max_entries_per_context(0)
            .with_max_total_entries(0)
            .with_stats_enabled(false);
        assert_eq!(config.max_entries_per_context, 1);
        assert_eq!(config.max_total_entries, 1);
        assert!(!config.enable_stats);

        let config_upper = PayloadCacheConfig::default()
            .with_max_entries_per_context(999_999)
            .with_max_total_entries(9_999_999);
        assert_eq!(config_upper.max_entries_per_context, 100_000);
        assert_eq!(config_upper.max_total_entries, 1_000_000);
    }

    #[test]
    fn insert_and_get() {
        let mut cache = default_cache();
        assert!(cache.insert("XSS", "<script>alert(1)</script>".to_string()));
        let entry = cache.get("XSS", "<script>alert(1)</script>");
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.payload, "<script>alert(1)</script>");
        assert_eq!(entry.context, "XSS");
        assert_eq!(entry.access_count, 1);
    }

    #[test]
    fn lru_eviction_when_context_full() {
        let mut cache = small_cache(3, 100);
        cache.insert("SQLi", "payload-a".to_string());
        cache.insert("SQLi", "payload-b".to_string());
        cache.insert("SQLi", "payload-c".to_string());
        cache.insert("SQLi", "payload-d".to_string());
        assert!(!cache.contains("SQLi", "payload-a"));
        assert!(cache.contains("SQLi", "payload-b"));
        assert!(cache.contains("SQLi", "payload-c"));
        assert!(cache.contains("SQLi", "payload-d"));
        assert_eq!(cache.context_count("SQLi"), 3);
    }

    #[test]
    fn cache_hit_increments_stats() {
        let mut cache = default_cache();
        cache.insert("XSS", "p1".to_string());
        cache.get("XSS", "p1");
        cache.get("XSS", "p1");
        assert_eq!(cache.stats().total_hits, 2);
    }

    #[test]
    fn cache_miss_increments_stats() {
        let mut cache = default_cache();
        cache.get("XSS", "nonexistent");
        cache.get("SQLi", "also-nonexistent");
        assert_eq!(cache.stats().total_misses, 2);
        assert_eq!(cache.stats().total_hits, 0);
    }

    #[test]
    fn remove_entry() {
        let mut cache = default_cache();
        cache.insert("SSTI", "{{7*7}}".to_string());
        assert!(cache.contains("SSTI", "{{7*7}}"));
        assert!(cache.remove("SSTI", "{{7*7}}"));
        assert!(!cache.contains("SSTI", "{{7*7}}"));
        assert!(!cache.remove("SSTI", "{{7*7}}"));
    }

    #[test]
    fn contains_check() {
        let mut cache = default_cache();
        assert!(!cache.contains("XSS", "missing"));
        cache.insert("XSS", "present".to_string());
        assert!(cache.contains("XSS", "present"));
        assert!(!cache.contains("SQLi", "present"));
    }

    #[test]
    fn warm_from_dictionary() {
        let mut cache = default_cache();
        let payloads = vec![
            "<img onerror=alert(1)>".to_string(),
            "<svg onload=alert(1)>".to_string(),
            "javascript:alert(1)".to_string(),
        ];
        let inserted = cache.warm_from_dictionary("XSS", payloads);
        assert_eq!(inserted, 3);
        assert_eq!(cache.context_count("XSS"), 3);
        assert!(cache.contains("XSS", "<img onerror=alert(1)>"));
    }

    #[test]
    fn warm_respects_max_size() {
        let mut cache = small_cache(2, 100);
        let payloads: Vec<String> = (0..5).map(|i| format!("payload-{i}")).collect();
        let inserted = cache.warm_from_dictionary("XSS", payloads);
        assert_eq!(cache.context_count("XSS"), 2);
        assert_eq!(inserted, 5);
        assert!(cache.contains("XSS", "payload-3"));
        assert!(cache.contains("XSS", "payload-4"));
    }

    #[test]
    fn clear_context() {
        let mut cache = default_cache();
        cache.insert("XSS", "p1".to_string());
        cache.insert("XSS", "p2".to_string());
        cache.insert("SQLi", "q1".to_string());
        let removed = cache.clear_context("XSS");
        assert_eq!(removed, 2);
        assert_eq!(cache.context_count("XSS"), 0);
        assert_eq!(cache.context_count("SQLi"), 1);
    }

    #[test]
    fn clear_all() {
        let mut cache = default_cache();
        cache.insert("XSS", "p1".to_string());
        cache.insert("SQLi", "q1".to_string());
        cache.insert("SSTI", "r1".to_string());
        cache.clear_all();
        assert_eq!(cache.total_entries(), 0);
        assert!(cache.contexts().is_empty());
    }

    #[test]
    fn lazy_generator_registration_and_generation() {
        let mut cache = default_cache();
        cache.register_generator(
            "SSRF",
            Box::new(|| {
                vec![
                    "http://169.254.169.254/".to_string(),
                    "http://[::1]/".to_string(),
                    "file:///etc/passwd".to_string(),
                ]
            }),
        );
        let payloads = cache.get_or_generate("SSRF");
        assert_eq!(payloads.len(), 3);
        assert!(payloads.contains(&"http://169.254.169.254/".to_string()));
        assert_eq!(cache.context_count("SSRF"), 3);
    }

    #[test]
    fn get_all_for_context() {
        let mut cache = default_cache();
        cache.insert("XSS", "alpha".to_string());
        cache.insert("XSS", "beta".to_string());
        cache.insert("XSS", "gamma".to_string());
        let all = cache.get_all_for_context("XSS");
        assert_eq!(all.len(), 3);
        assert_eq!(all, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn multiple_contexts_isolation() {
        let mut cache = default_cache();
        cache.insert("XSS", "xss-payload".to_string());
        cache.insert("SQLi", "sqli-payload".to_string());
        cache.insert("SSTI", "ssti-payload".to_string());
        assert!(cache.contains("XSS", "xss-payload"));
        assert!(!cache.contains("XSS", "sqli-payload"));
        assert!(!cache.contains("SQLi", "xss-payload"));
        assert!(cache.contains("SQLi", "sqli-payload"));
        assert!(cache.contains("SSTI", "ssti-payload"));
        assert_eq!(cache.total_entries(), 3);
    }

    #[test]
    fn total_entries_tracking() {
        let mut cache = default_cache();
        assert_eq!(cache.total_entries(), 0);
        cache.insert("XSS", "a".to_string());
        cache.insert("SQLi", "b".to_string());
        assert_eq!(cache.total_entries(), 2);
        assert_eq!(cache.stats().total_entries, 2);
        cache.remove("XSS", "a");
        assert_eq!(cache.total_entries(), 1);
        assert_eq!(cache.stats().total_entries, 1);
    }

    #[test]
    fn stats_reset() {
        let mut cache = default_cache();
        cache.insert("XSS", "p".to_string());
        cache.get("XSS", "p");
        cache.get("XSS", "missing");
        assert!(cache.stats().total_hits > 0);
        assert!(cache.stats().total_misses > 0);
        cache.reset_stats();
        assert_eq!(cache.stats().total_hits, 0);
        assert_eq!(cache.stats().total_misses, 0);
        assert_eq!(cache.stats().total_evictions, 0);
    }

    #[test]
    fn access_count_tracking() {
        let mut cache = default_cache();
        cache.insert("XSS", "tracked".to_string());
        cache.get("XSS", "tracked");
        cache.get("XSS", "tracked");
        cache.get("XSS", "tracked");
        let entry = cache.get("XSS", "tracked").unwrap();
        assert_eq!(entry.access_count, 4);
    }

    #[test]
    fn duplicate_insert_returns_false() {
        let mut cache = default_cache();
        assert!(cache.insert("XSS", "dup".to_string()));
        assert!(!cache.insert("XSS", "dup".to_string()));
        assert_eq!(cache.context_count("XSS"), 1);
    }

    #[test]
    fn lru_order_updated_on_access() {
        let mut cache = small_cache(3, 100);
        cache.insert("XSS", "oldest".to_string());
        cache.insert("XSS", "middle".to_string());
        cache.insert("XSS", "newest".to_string());
        cache.get("XSS", "oldest");
        cache.insert("XSS", "evicts-middle".to_string());
        assert!(cache.contains("XSS", "oldest"));
        assert!(!cache.contains("XSS", "middle"));
        assert!(cache.contains("XSS", "newest"));
        assert!(cache.contains("XSS", "evicts-middle"));
    }

    #[test]
    fn get_or_generate_without_generator_returns_empty() {
        let mut cache = default_cache();
        let payloads = cache.get_or_generate("NoGenerator");
        assert!(payloads.is_empty());
    }

    #[test]
    fn get_or_generate_uses_cache_on_second_call() {
        let mut cache = default_cache();
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter = call_count.clone();
        cache.register_generator(
            "Counted",
            Box::new(move || {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                vec!["generated".to_string()]
            }),
        );
        let first = cache.get_or_generate("Counted");
        assert_eq!(first, vec!["generated"]);
        let second = cache.get_or_generate("Counted");
        assert_eq!(second, vec!["generated"]);
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn per_context_counts_in_stats() {
        let mut cache = default_cache();
        cache.insert("XSS", "a".to_string());
        cache.insert("XSS", "b".to_string());
        cache.insert("SQLi", "c".to_string());
        let stats = cache.stats();
        assert_eq!(stats.per_context_counts.get("XSS"), Some(&2));
        assert_eq!(stats.per_context_counts.get("SQLi"), Some(&1));
        assert_eq!(stats.contexts_tracked, 2);
    }

    #[test]
    fn eviction_increments_eviction_count() {
        let mut cache = small_cache(2, 100);
        cache.insert("XSS", "first".to_string());
        cache.insert("XSS", "second".to_string());
        cache.insert("XSS", "third".to_string());
        assert!(cache.stats().total_evictions >= 1);
    }

    #[test]
    fn total_limit_triggers_cross_context_eviction() {
        let mut cache = small_cache(5, 4);
        cache.insert("XSS", "x1".to_string());
        cache.insert("XSS", "x2".to_string());
        cache.insert("SQLi", "s1".to_string());
        cache.insert("SQLi", "s2".to_string());
        cache.insert("SSTI", "t1".to_string());
        assert!(cache.total_entries() <= 4);
        assert!(cache.stats().total_evictions >= 1);
    }

    #[test]
    fn get_all_for_nonexistent_context_returns_empty() {
        let cache = default_cache();
        assert!(cache.get_all_for_context("Nonexistent").is_empty());
    }

    #[test]
    fn contexts_returns_all_active_context_names() {
        let mut cache = default_cache();
        cache.insert("XSS", "a".to_string());
        cache.insert("SQLi", "b".to_string());
        cache.insert("SSTI", "c".to_string());
        let mut ctx_names = cache.contexts();
        ctx_names.sort();
        assert_eq!(ctx_names, vec!["SQLi", "SSTI", "XSS"]);
    }

    #[test]
    fn stats_disabled_does_not_track() {
        let config = PayloadCacheConfig::default().with_stats_enabled(false);
        let mut cache = PayloadCache::new(config);
        cache.insert("XSS", "p".to_string());
        cache.get("XSS", "p");
        cache.get("XSS", "miss");
        assert_eq!(cache.stats().total_hits, 0);
        assert_eq!(cache.stats().total_misses, 0);
    }

    #[test]
    fn remove_from_nonexistent_context_returns_false() {
        let mut cache = default_cache();
        assert!(!cache.remove("Ghost", "phantom"));
    }

    #[test]
    fn clear_nonexistent_context_returns_zero() {
        let mut cache = default_cache();
        assert_eq!(cache.clear_context("Ghost"), 0);
    }

    #[test]
    fn warm_deduplicates_within_batch() {
        let mut cache = default_cache();
        let payloads = vec!["dup".to_string(), "dup".to_string(), "unique".to_string()];
        let inserted = cache.warm_from_dictionary("XSS", payloads);
        assert_eq!(inserted, 2);
        assert_eq!(cache.context_count("XSS"), 2);
    }
}
