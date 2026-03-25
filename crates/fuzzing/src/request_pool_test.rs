use super::*;
use std::time::Duration;

#[test]
fn default_config_has_sensible_values() {
    let config = PoolConfig::default();
    assert_eq!(config.max_connections_per_host, 10);
    assert_eq!(config.keep_alive_timeout, Duration::from_secs(30));
    assert_eq!(config.dns_cache_ttl, Duration::from_secs(300));
    assert_eq!(config.max_total_connections, 200);
    assert_eq!(config.warm_up_connections, 2);
    assert_eq!(config.connection_timeout, Duration::from_secs(10));
}

#[test]
fn builder_pattern_clamps_per_host_limits() {
    let config = PoolConfig::default()
        .with_max_connections_per_host(0)
        .with_keep_alive_timeout(Duration::from_secs(60))
        .with_dns_cache_ttl(Duration::from_secs(120))
        .with_max_total_connections(500)
        .with_warm_up_connections(5)
        .with_connection_timeout(Duration::from_secs(20));

    assert_eq!(config.max_connections_per_host, 1);
    assert_eq!(config.keep_alive_timeout, Duration::from_secs(60));
    assert_eq!(config.dns_cache_ttl, Duration::from_secs(120));
    assert_eq!(config.max_total_connections, 500);
    assert_eq!(config.warm_up_connections, 5);
    assert_eq!(config.connection_timeout, Duration::from_secs(20));

    let clamped_high = PoolConfig::default().with_max_connections_per_host(999);
    assert_eq!(clamped_high.max_connections_per_host, 100);

    let clamped_total = PoolConfig::default().with_max_total_connections(9999);
    assert_eq!(clamped_total.max_total_connections, 1000);
}

#[test]
fn acquire_and_release_connection_flow() {
    let mut pool = RequestPoolManager::with_default_config();
    let handle = pool.acquire_connection("example.com").unwrap();

    assert_eq!(handle.host, "example.com");
    assert_eq!(pool.stats().active_connections, 1);
    assert_eq!(pool.stats().total_connections, 1);
    assert_eq!(pool.total_hosts(), 1);

    pool.release_connection(handle);
    assert_eq!(pool.stats().active_connections, 0);
    assert_eq!(pool.stats().idle_connections, 1);
    assert_eq!(pool.stats().total_connections, 1);
}

#[test]
fn released_connection_is_reused_on_next_acquire() {
    let mut pool = RequestPoolManager::with_default_config();
    let h1 = pool.acquire_connection("reuse.test").unwrap();
    pool.release_connection(h1);
    assert_eq!(pool.stats().idle_connections, 1);
    assert_eq!(pool.stats().total_connections, 1);

    let _h2 = pool.acquire_connection("reuse.test").unwrap();
    assert_eq!(pool.stats().active_connections, 1);
    assert_eq!(pool.stats().idle_connections, 0);
    assert_eq!(pool.stats().total_connections, 1);
}

#[test]
fn pool_exhaustion_error_when_per_host_limit_reached() {
    let config = PoolConfig::default().with_max_connections_per_host(2);
    let mut pool = RequestPoolManager::new(config);

    let _h1 = pool.acquire_connection("limited.host").unwrap();
    let _h2 = pool.acquire_connection("limited.host").unwrap();

    let result = pool.acquire_connection("limited.host");
    assert!(result.is_err());
    match result.unwrap_err() {
        PoolError::PoolExhausted { host, max } => {
            assert_eq!(host, "limited.host");
            assert_eq!(max, 2);
        }
        other => panic!("expected PoolExhausted, got: {other}"),
    }
}

#[test]
fn total_limit_reached_error() {
    let config = PoolConfig::default()
        .with_max_connections_per_host(5)
        .with_max_total_connections(3);
    let mut pool = RequestPoolManager::new(config);

    let _h1 = pool.acquire_connection("a.com").unwrap();
    let _h2 = pool.acquire_connection("b.com").unwrap();
    let _h3 = pool.acquire_connection("c.com").unwrap();

    let result = pool.acquire_connection("d.com");
    assert!(result.is_err());
    match result.unwrap_err() {
        PoolError::TotalLimitReached { max } => assert_eq!(max, 3),
        other => panic!("expected TotalLimitReached, got: {other}"),
    }
}

#[test]
fn invalid_host_rejected() {
    let mut pool = RequestPoolManager::with_default_config();
    let result = pool.acquire_connection("");
    assert!(result.is_err());
    match result.unwrap_err() {
        PoolError::InvalidHost(h) => assert_eq!(h, ""),
        other => panic!("expected InvalidHost, got: {other}"),
    }
}

#[test]
fn dns_caching_and_lookup() {
    let mut pool = RequestPoolManager::with_default_config();

    let miss = pool.resolve_dns("uncached.host");
    assert!(miss.is_none());
    assert_eq!(pool.stats().dns_cache_misses, 1);

    pool.cache_dns(
        "cached.host".to_string(),
        vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()],
    );

    let hit = pool.resolve_dns("cached.host");
    assert!(hit.is_some());
    let entry = hit.unwrap();
    assert_eq!(entry.addresses, vec!["1.2.3.4", "5.6.7.8"]);
    assert_eq!(pool.stats().dns_cache_hits, 1);
    assert_eq!(pool.stats().dns_cache_misses, 1);
}

#[test]
fn dns_cache_expiry() {
    let config = PoolConfig::default().with_dns_cache_ttl(Duration::from_millis(1));
    let mut pool = RequestPoolManager::new(config);

    pool.cache_dns("ephemeral.host".to_string(), vec!["10.0.0.1".to_string()]);
    std::thread::sleep(Duration::from_millis(5));

    let result = pool.resolve_dns("ephemeral.host");
    assert!(result.is_none());
    assert_eq!(pool.stats().dns_cache_misses, 1);
}

#[test]
fn dns_invalidation() {
    let mut pool = RequestPoolManager::with_default_config();

    pool.cache_dns("remove.me".to_string(), vec!["127.0.0.1".to_string()]);
    assert!(pool.resolve_dns("remove.me").is_some());

    pool.invalidate_dns("remove.me");
    let result = pool.resolve_dns("remove.me");
    assert!(result.is_none());
}

#[test]
fn tls_session_tracking() {
    let mut pool = RequestPoolManager::with_default_config();

    assert!(!pool.is_tls_cached("secure.host"));
    assert_eq!(pool.stats().tls_sessions_cached, 0);

    pool.mark_tls_cached("secure.host");
    assert!(pool.is_tls_cached("secure.host"));
    assert_eq!(pool.stats().tls_sessions_cached, 1);

    pool.mark_tls_cached("secure.host");
    assert_eq!(pool.stats().tls_sessions_cached, 1);

    pool.mark_tls_cached("other.secure.host");
    assert_eq!(pool.stats().tls_sessions_cached, 2);
}

#[test]
fn warm_up_pre_establishes_idle_connections() {
    let config = PoolConfig::default().with_warm_up_connections(3);
    let mut pool = RequestPoolManager::new(config);

    let hosts = vec!["alpha.com".to_string(), "beta.com".to_string()];
    pool.warm_up(&hosts);

    assert_eq!(pool.total_hosts(), 2);
    assert_eq!(pool.stats().warm_up_completed, 2);
    assert_eq!(pool.stats().idle_connections, 6);
    assert_eq!(pool.stats().active_connections, 0);

    let alpha = pool.host_pool_info("alpha.com").unwrap();
    assert_eq!(alpha.idle_connections, 3);
    assert_eq!(alpha.active_connections, 0);
}

#[test]
fn warm_up_skips_empty_hosts() {
    let mut pool = RequestPoolManager::with_default_config();
    pool.warm_up(&["".to_string(), "valid.host".to_string()]);

    assert_eq!(pool.total_hosts(), 1);
    assert_eq!(pool.stats().warm_up_completed, 1);
}

#[test]
fn evict_expired_connections() {
    let config = PoolConfig::default().with_keep_alive_timeout(Duration::from_millis(1));
    let mut pool = RequestPoolManager::new(config);

    pool.warm_up(&["expire-me.com".to_string()]);
    assert_eq!(pool.total_hosts(), 1);

    std::thread::sleep(Duration::from_millis(5));

    let evicted = pool.evict_expired();
    assert_eq!(evicted, 1);
    assert_eq!(pool.total_hosts(), 0);
    assert_eq!(pool.stats().idle_connections, 0);
}

#[test]
fn evict_skips_pools_with_active_connections() {
    let config = PoolConfig::default().with_keep_alive_timeout(Duration::from_millis(1));
    let mut pool = RequestPoolManager::new(config);

    let _handle = pool.acquire_connection("busy.host").unwrap();

    std::thread::sleep(Duration::from_millis(5));
    let evicted = pool.evict_expired();
    assert_eq!(evicted, 0);
    assert_eq!(pool.total_hosts(), 1);
}

#[test]
fn stats_tracking_accuracy() {
    let mut pool = RequestPoolManager::with_default_config();

    let h1 = pool.acquire_connection("stats.host").unwrap();
    let h2 = pool.acquire_connection("stats.host").unwrap();
    assert_eq!(pool.stats().active_connections, 2);
    assert_eq!(pool.stats().total_connections, 2);
    assert_eq!(pool.stats().hosts_tracked, 1);

    pool.release_connection(h1);
    assert_eq!(pool.stats().active_connections, 1);
    assert_eq!(pool.stats().idle_connections, 1);

    pool.release_connection(h2);
    assert_eq!(pool.stats().active_connections, 0);
    assert_eq!(pool.stats().idle_connections, 2);

    let host_info = pool.host_pool_info("stats.host").unwrap();
    assert_eq!(host_info.total_requests, 2);
}

#[test]
fn multiple_hosts_isolation() {
    let config = PoolConfig::default().with_max_connections_per_host(2);
    let mut pool = RequestPoolManager::new(config);

    let _a1 = pool.acquire_connection("host-a.com").unwrap();
    let _a2 = pool.acquire_connection("host-a.com").unwrap();
    let _b1 = pool.acquire_connection("host-b.com").unwrap();

    assert!(pool.acquire_connection("host-a.com").is_err());
    assert!(pool.acquire_connection("host-b.com").is_ok());

    assert_eq!(pool.total_hosts(), 2);
    assert_eq!(pool.stats().active_connections, 4);

    let a_info = pool.host_pool_info("host-a.com").unwrap();
    assert_eq!(a_info.active_connections, 2);
    let b_info = pool.host_pool_info("host-b.com").unwrap();
    assert_eq!(b_info.active_connections, 2);
}

#[test]
fn reset_stats_preserves_pool_state() {
    let mut pool = RequestPoolManager::with_default_config();

    pool.cache_dns("dns.host".to_string(), vec!["1.1.1.1".to_string()]);
    pool.resolve_dns("dns.host");
    pool.resolve_dns("missing.host");
    let _h = pool.acquire_connection("conn.host").unwrap();
    pool.mark_tls_cached("conn.host");

    assert_eq!(pool.stats().dns_cache_hits, 1);
    assert_eq!(pool.stats().dns_cache_misses, 1);

    pool.reset_stats();

    assert_eq!(pool.stats().dns_cache_hits, 0);
    assert_eq!(pool.stats().dns_cache_misses, 0);
    assert_eq!(pool.stats().warm_up_completed, 0);
    assert_eq!(pool.stats().hosts_tracked, 1);
    assert_eq!(pool.stats().active_connections, 1);
    assert_eq!(pool.stats().tls_sessions_cached, 1);
}

#[test]
fn pool_error_display_messages() {
    let exhausted = PoolError::PoolExhausted {
        host: "h.com".to_string(),
        max: 5,
    };
    assert!(exhausted.to_string().contains("h.com"));
    assert!(exhausted.to_string().contains("5"));

    let total = PoolError::TotalLimitReached { max: 100 };
    assert!(total.to_string().contains("100"));

    let invalid = PoolError::InvalidHost("".to_string());
    assert!(invalid.to_string().contains("invalid host"));
}

#[test]
fn connection_handles_have_unique_ids() {
    let mut pool = RequestPoolManager::with_default_config();
    let h1 = pool.acquire_connection("id-test.com").unwrap();
    let h2 = pool.acquire_connection("id-test.com").unwrap();
    assert_ne!(h1.id, h2.id);
}

#[test]
fn dns_cache_entry_expiry_check() {
    let fresh = DnsCacheEntry {
        addresses: vec!["127.0.0.1".to_string()],
        resolved_at: std::time::Instant::now(),
        ttl: Duration::from_secs(300),
    };
    assert!(!fresh.is_expired());

    let stale = DnsCacheEntry {
        addresses: vec!["127.0.0.1".to_string()],
        resolved_at: std::time::Instant::now() - Duration::from_secs(600),
        ttl: Duration::from_secs(300),
    };
    assert!(stale.is_expired());
}

#[test]
fn uptime_increases_over_time() {
    let pool = RequestPoolManager::with_default_config();
    let first = pool.uptime();
    std::thread::sleep(Duration::from_millis(2));
    let second = pool.uptime();
    assert!(second > first);
}
