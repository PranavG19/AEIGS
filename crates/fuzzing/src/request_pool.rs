use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static CONNECTION_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

const MIN_CONNECTIONS_PER_HOST: usize = 1;
const MAX_CONNECTIONS_PER_HOST: usize = 100;
const MAX_TOTAL_CONNECTIONS_LIMIT: usize = 1000;
const DEFAULT_CONNECTIONS_PER_HOST: usize = 10;
const DEFAULT_KEEP_ALIVE_SECS: u64 = 30;
const DEFAULT_DNS_CACHE_TTL_SECS: u64 = 300;
const DEFAULT_MAX_TOTAL_CONNECTIONS: usize = 200;
const DEFAULT_WARM_UP_CONNECTIONS: usize = 2;
const DEFAULT_CONNECTION_TIMEOUT_SECS: u64 = 10;

/// Configuration governing pool sizing, timeouts, and caching behavior.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub max_connections_per_host: usize,
    pub keep_alive_timeout: Duration,
    pub dns_cache_ttl: Duration,
    pub max_total_connections: usize,
    pub warm_up_connections: usize,
    pub connection_timeout: Duration,
}

impl PoolConfig {
    pub fn with_max_connections_per_host(mut self, n: usize) -> Self {
        self.max_connections_per_host = n.clamp(MIN_CONNECTIONS_PER_HOST, MAX_CONNECTIONS_PER_HOST);
        self
    }

    pub fn with_keep_alive_timeout(mut self, timeout: Duration) -> Self {
        self.keep_alive_timeout = timeout;
        self
    }

    pub fn with_dns_cache_ttl(mut self, ttl: Duration) -> Self {
        self.dns_cache_ttl = ttl;
        self
    }

    pub fn with_max_total_connections(mut self, n: usize) -> Self {
        self.max_total_connections = n.clamp(1, MAX_TOTAL_CONNECTIONS_LIMIT);
        self
    }

    pub fn with_warm_up_connections(mut self, n: usize) -> Self {
        self.warm_up_connections = n;
        self
    }

    pub fn with_connection_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = timeout;
        self
    }
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_host: DEFAULT_CONNECTIONS_PER_HOST,
            keep_alive_timeout: Duration::from_secs(DEFAULT_KEEP_ALIVE_SECS),
            dns_cache_ttl: Duration::from_secs(DEFAULT_DNS_CACHE_TTL_SECS),
            max_total_connections: DEFAULT_MAX_TOTAL_CONNECTIONS,
            warm_up_connections: DEFAULT_WARM_UP_CONNECTIONS,
            connection_timeout: Duration::from_secs(DEFAULT_CONNECTION_TIMEOUT_SECS),
        }
    }
}

/// A cached DNS resolution with expiry tracking.
#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    pub addresses: Vec<String>,
    pub resolved_at: Instant,
    pub ttl: Duration,
}

impl DnsCacheEntry {
    pub fn is_expired(&self) -> bool {
        self.resolved_at.elapsed() >= self.ttl
    }
}

/// Per-host connection pool tracking active/idle counts and TLS state.
#[derive(Debug)]
pub struct HostPool {
    pub host: String,
    pub active_connections: usize,
    pub idle_connections: usize,
    pub max_connections: usize,
    pub last_activity: Instant,
    pub tls_session_cached: bool,
    pub total_requests: u64,
}

impl HostPool {
    fn new(host: String, max_connections: usize) -> Self {
        Self {
            host,
            active_connections: 0,
            idle_connections: 0,
            max_connections,
            last_activity: Instant::now(),
            tls_session_cached: false,
            total_requests: 0,
        }
    }

    fn total_connections(&self) -> usize {
        self.active_connections + self.idle_connections
    }

    fn is_expired(&self, keep_alive_timeout: Duration) -> bool {
        self.active_connections == 0 && self.last_activity.elapsed() >= keep_alive_timeout
    }
}

/// Aggregate statistics across all host pools.
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    pub total_connections: usize,
    pub active_connections: usize,
    pub idle_connections: usize,
    pub dns_cache_hits: u64,
    pub dns_cache_misses: u64,
    pub tls_sessions_cached: usize,
    pub hosts_tracked: usize,
    pub warm_up_completed: usize,
}

/// Handle representing an acquired connection, returned to the pool on release.
#[derive(Debug)]
pub struct ConnectionHandle {
    pub host: String,
    pub id: u64,
    pub acquired_at: Instant,
}

/// Errors arising from pool operations.
#[derive(Debug)]
pub enum PoolError {
    PoolExhausted { host: String, max: usize },
    TotalLimitReached { max: usize },
    InvalidHost(String),
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PoolExhausted { host, max } => {
                write!(
                    f,
                    "pool exhausted for host {host}: {max} connections in use"
                )
            }
            Self::TotalLimitReached { max } => {
                write!(f, "total connection limit reached: {max}")
            }
            Self::InvalidHost(host) => {
                write!(f, "invalid host: {host}")
            }
        }
    }
}

impl std::error::Error for PoolError {}

/// Connection pool manager providing per-host pooling, DNS caching, and TLS
/// session tracking for the fuzzing HTTP pipeline.
pub struct RequestPoolManager {
    config: PoolConfig,
    host_pools: HashMap<String, HostPool>,
    dns_cache: HashMap<String, DnsCacheEntry>,
    stats: PoolStats,
    created_at: Instant,
}

impl RequestPoolManager {
    pub fn new(config: PoolConfig) -> Self {
        Self {
            config,
            host_pools: HashMap::new(),
            dns_cache: HashMap::new(),
            stats: PoolStats::default(),
            created_at: Instant::now(),
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(PoolConfig::default())
    }

    /// Acquires a connection to `host`, creating the host pool if needed.
    ///
    /// Returns `PoolError::InvalidHost` for empty hostnames,
    /// `PoolError::TotalLimitReached` when the global cap is hit, and
    /// `PoolError::PoolExhausted` when the per-host cap is hit.
    pub fn acquire_connection(&mut self, host: &str) -> Result<ConnectionHandle, PoolError> {
        if host.is_empty() {
            return Err(PoolError::InvalidHost(host.to_string()));
        }
        if self.total_active_connections() >= self.config.max_total_connections {
            return Err(PoolError::TotalLimitReached {
                max: self.config.max_total_connections,
            });
        }
        let max_per_host = self.config.max_connections_per_host;
        let pool = self
            .host_pools
            .entry(host.to_string())
            .or_insert_with(|| HostPool::new(host.to_string(), max_per_host));

        if pool.active_connections >= pool.max_connections {
            return Err(PoolError::PoolExhausted {
                host: host.to_string(),
                max: pool.max_connections,
            });
        }

        self.promote_or_create_connection(host)
    }

    /// Returns a connection handle to the pool, moving it from active to idle.
    pub fn release_connection(&mut self, handle: ConnectionHandle) {
        if let Some(pool) = self.host_pools.get_mut(&handle.host)
            && pool.active_connections > 0
        {
            pool.active_connections -= 1;
            pool.idle_connections += 1;
            pool.last_activity = Instant::now();
            self.stats.active_connections = self.stats.active_connections.saturating_sub(1);
            self.stats.idle_connections += 1;
        }
    }

    /// Looks up a cached DNS entry, recording a cache hit or miss.
    ///
    /// Expired entries are treated as misses and removed.
    pub fn resolve_dns(&mut self, host: &str) -> Option<&DnsCacheEntry> {
        let expired = self
            .dns_cache
            .get(host)
            .is_some_and(|entry| entry.is_expired());
        if expired {
            self.dns_cache.remove(host);
            self.stats.dns_cache_misses += 1;
            return None;
        }
        if self.dns_cache.contains_key(host) {
            self.stats.dns_cache_hits += 1;
            self.dns_cache.get(host)
        } else {
            self.stats.dns_cache_misses += 1;
            None
        }
    }

    /// Inserts or replaces a DNS cache entry for `host`.
    pub fn cache_dns(&mut self, host: String, addresses: Vec<String>) {
        let ttl = self.config.dns_cache_ttl;
        self.dns_cache.insert(
            host,
            DnsCacheEntry {
                addresses,
                resolved_at: Instant::now(),
                ttl,
            },
        );
    }

    /// Removes the DNS cache entry for `host`.
    pub fn invalidate_dns(&mut self, host: &str) {
        self.dns_cache.remove(host);
    }

    /// Marks TLS session data as cached for `host`.
    pub fn mark_tls_cached(&mut self, host: &str) {
        let max_per_host = self.config.max_connections_per_host;
        let pool = self
            .host_pools
            .entry(host.to_string())
            .or_insert_with(|| HostPool::new(host.to_string(), max_per_host));

        if !pool.tls_session_cached {
            pool.tls_session_cached = true;
            self.stats.tls_sessions_cached += 1;
        }
    }

    /// Returns whether TLS session data is cached for `host`.
    pub fn is_tls_cached(&self, host: &str) -> bool {
        self.host_pools
            .get(host)
            .is_some_and(|p| p.tls_session_cached)
    }

    /// Pre-establishes idle connections for the given hosts up to
    /// `config.warm_up_connections` each.
    pub fn warm_up(&mut self, hosts: &[String]) {
        let warm_count = self.config.warm_up_connections;
        let max_per_host = self.config.max_connections_per_host;
        for host in hosts {
            if host.is_empty() {
                continue;
            }
            let pool = self
                .host_pools
                .entry(host.clone())
                .or_insert_with(|| HostPool::new(host.clone(), max_per_host));

            let slots = warm_count.saturating_sub(pool.total_connections());
            pool.idle_connections += slots;
            self.stats.idle_connections += slots;
            self.stats.total_connections += slots;
            self.stats.warm_up_completed += 1;
        }
        self.stats.hosts_tracked = self.host_pools.len();
    }

    /// Removes host pools whose idle connections have exceeded the
    /// keep-alive timeout. Returns the number of evicted pools.
    pub fn evict_expired(&mut self) -> usize {
        let timeout = self.config.keep_alive_timeout;
        let expired_hosts: Vec<String> = self
            .host_pools
            .iter()
            .filter(|(_, pool)| pool.is_expired(timeout))
            .map(|(host, _)| host.clone())
            .collect();

        let evicted = expired_hosts.len();
        for host in &expired_hosts {
            if let Some(pool) = self.host_pools.remove(host) {
                let idle = pool.idle_connections;
                self.stats.idle_connections = self.stats.idle_connections.saturating_sub(idle);
                self.stats.total_connections = self.stats.total_connections.saturating_sub(idle);
                if pool.tls_session_cached {
                    self.stats.tls_sessions_cached =
                        self.stats.tls_sessions_cached.saturating_sub(1);
                }
            }
        }
        self.stats.hosts_tracked = self.host_pools.len();
        evicted
    }

    /// Returns a reference to current pool statistics.
    pub fn stats(&self) -> &PoolStats {
        &self.stats
    }

    /// Resets all counters in the stats snapshot to zero.
    pub fn reset_stats(&mut self) {
        self.stats = PoolStats::default();
        self.stats.hosts_tracked = self.host_pools.len();
        self.recompute_connection_stats();
    }

    /// Returns pool information for a specific host, if tracked.
    pub fn host_pool_info(&self, host: &str) -> Option<&HostPool> {
        self.host_pools.get(host)
    }

    /// Returns the number of distinct hosts with tracked pools.
    pub fn total_hosts(&self) -> usize {
        self.host_pools.len()
    }

    /// Returns a reference to the pool configuration.
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    /// Returns how long the pool manager has been alive.
    pub fn uptime(&self) -> Duration {
        self.created_at.elapsed()
    }

    fn total_active_connections(&self) -> usize {
        self.host_pools.values().map(|p| p.active_connections).sum()
    }

    fn promote_or_create_connection(&mut self, host: &str) -> Result<ConnectionHandle, PoolError> {
        let pool = self.host_pools.get_mut(host).unwrap();
        if pool.idle_connections > 0 {
            pool.idle_connections -= 1;
            self.stats.idle_connections = self.stats.idle_connections.saturating_sub(1);
        } else {
            self.stats.total_connections += 1;
        }
        pool.active_connections += 1;
        pool.total_requests += 1;
        pool.last_activity = Instant::now();
        self.stats.active_connections += 1;
        self.stats.hosts_tracked = self.host_pools.len();

        let id = CONNECTION_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        Ok(ConnectionHandle {
            host: host.to_string(),
            id,
            acquired_at: Instant::now(),
        })
    }

    fn recompute_connection_stats(&mut self) {
        let mut total = 0usize;
        let mut active = 0usize;
        let mut idle = 0usize;
        let mut tls = 0usize;
        for pool in self.host_pools.values() {
            total += pool.total_connections();
            active += pool.active_connections;
            idle += pool.idle_connections;
            if pool.tls_session_cached {
                tls += 1;
            }
        }
        self.stats.total_connections = total;
        self.stats.active_connections = active;
        self.stats.idle_connections = idle;
        self.stats.tls_sessions_cached = tls;
    }
}
