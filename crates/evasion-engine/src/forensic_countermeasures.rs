use std::collections::HashMap;
use std::fmt;

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// Log evasion technique that exploits timing or rule gaps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LogEvasionTechnique {
    TimingBetweenRotations,
    RequestPatternBypass,
    LogFieldTruncation,
    UnicodeObfuscation,
    ChunkedRequestSplitting,
    SlowDripFeeding,
}

impl fmt::Display for LogEvasionTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimingBetweenRotations => write!(f, "timing-rotation-gap"),
            Self::RequestPatternBypass => write!(f, "pattern-bypass"),
            Self::LogFieldTruncation => write!(f, "field-truncation"),
            Self::UnicodeObfuscation => write!(f, "unicode-obfuscation"),
            Self::ChunkedRequestSplitting => write!(f, "chunked-splitting"),
            Self::SlowDripFeeding => write!(f, "slow-drip"),
        }
    }
}

/// Memory-only operation design pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryOnlyPattern {
    InMemoryBuffer,
    PipeChaining,
    MmapAnonymous,
    TmpfsVolatile,
    RamDisk,
}

impl fmt::Display for MemoryOnlyPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InMemoryBuffer => write!(f, "in-memory-buffer"),
            Self::PipeChaining => write!(f, "pipe-chain"),
            Self::MmapAnonymous => write!(f, "mmap-anon"),
            Self::TmpfsVolatile => write!(f, "tmpfs"),
            Self::RamDisk => write!(f, "ramdisk"),
        }
    }
}

/// Perfect forward secrecy cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PfsCipherSuite {
    Tls13Aes256Gcm,
    Tls13Chacha20Poly1305,
    EcdhEcdsaAes256Gcm,
    EcdhRsaAes256Gcm,
}

impl PfsCipherSuite {
    /// Returns the OpenSSL cipher string for this suite.
    pub fn openssl_name(&self) -> &'static str {
        match self {
            Self::Tls13Aes256Gcm => "TLS_AES_256_GCM_SHA384",
            Self::Tls13Chacha20Poly1305 => "TLS_CHACHA20_POLY1305_SHA256",
            Self::EcdhEcdsaAes256Gcm => "ECDHE-ECDSA-AES256-GCM-SHA384",
            Self::EcdhRsaAes256Gcm => "ECDHE-RSA-AES256-GCM-SHA384",
        }
    }

    /// All PFS suites provide forward secrecy by definition.
    pub fn has_forward_secrecy(&self) -> bool {
        true
    }
}

impl fmt::Display for PfsCipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.openssl_name())
    }
}

/// Metadata field that may leak identifying information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MetadataField {
    UserAgent,
    XForwardedFor,
    XRealIp,
    Via,
    Server,
    XPoweredBy,
    Date,
    Cookie,
    Referer,
    AcceptLanguage,
}

impl fmt::Display for MetadataField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserAgent => write!(f, "User-Agent"),
            Self::XForwardedFor => write!(f, "X-Forwarded-For"),
            Self::XRealIp => write!(f, "X-Real-IP"),
            Self::Via => write!(f, "Via"),
            Self::Server => write!(f, "Server"),
            Self::XPoweredBy => write!(f, "X-Powered-By"),
            Self::Date => write!(f, "Date"),
            Self::Cookie => write!(f, "Cookie"),
            Self::Referer => write!(f, "Referer"),
            Self::AcceptLanguage => write!(f, "Accept-Language"),
        }
    }
}

/// Headers that should be stripped from outgoing requests to avoid attribution.
const STRIP_HEADERS: &[MetadataField] = &[
    MetadataField::XForwardedFor,
    MetadataField::XRealIp,
    MetadataField::Via,
    MetadataField::XPoweredBy,
];

/// Safe User-Agent strings that don't reveal scanner identity.
const SAFE_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
];

/// Scanner-identifying UA patterns that must never be sent.
const SCANNER_UA_PATTERNS: &[&str] = &[
    "sqlmap",
    "nikto",
    "nmap",
    "burp",
    "zap",
    "w3af",
    "dirbuster",
    "gobuster",
    "ffuf",
    "nuclei",
    "wpscan",
    "joomscan",
    "masscan",
    "aegis",
    "scanner",
    "crawler",
    "bot",
    "spider",
];

/// Connection cleanup strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionCleanup {
    GracefulFinAck,
    LingerZero,
    KeepAliveTimeout,
    IdleDisconnect,
}

/// Log evasion timing window recommendation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogTimingWindow {
    pub technique: LogEvasionTechnique,
    pub recommended_hour_utc: u8,
    pub reason: String,
    pub estimated_detection_reduction_pct: f64,
}

/// Metadata stripping result showing what was removed from headers.
#[derive(Debug, Clone)]
pub struct MetadataStripResult {
    pub original_headers: HashMap<String, String>,
    pub stripped_headers: HashMap<String, String>,
    pub fields_removed: Vec<MetadataField>,
    pub ua_replaced: bool,
}

/// Clock synchronization recommendation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockSyncRecommendation {
    pub use_utc: bool,
    pub ntp_servers: Vec<String>,
    pub jitter_range_ms: u64,
    pub avoid_round_timestamps: bool,
}

/// TCP connection cleanup recommendation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionCleanupPlan {
    pub strategy: ConnectionCleanup,
    pub linger_timeout_ms: u64,
    pub keepalive_interval_secs: u64,
    pub max_idle_secs: u64,
}

/// Configuration for forensic countermeasures.
#[derive(Debug, Clone)]
pub struct ForensicCountermeasureConfig {
    pub log_evasion_enabled: bool,
    pub memory_only_mode: bool,
    pub pfs_cipher: PfsCipherSuite,
    pub strip_metadata: bool,
    pub clock_jitter_ms: u64,
    pub safe_ua_rotation: bool,
    pub connection_cleanup: ConnectionCleanup,
}

impl Default for ForensicCountermeasureConfig {
    fn default() -> Self {
        Self {
            log_evasion_enabled: true,
            memory_only_mode: true,
            pfs_cipher: PfsCipherSuite::Tls13Aes256Gcm,
            strip_metadata: true,
            clock_jitter_ms: 500,
            safe_ua_rotation: true,
            connection_cleanup: ConnectionCleanup::GracefulFinAck,
        }
    }
}

impl ForensicCountermeasureConfig {
    pub fn with_pfs_cipher(mut self, cipher: PfsCipherSuite) -> Self {
        self.pfs_cipher = cipher;
        self
    }

    pub fn with_clock_jitter(mut self, ms: u64) -> Self {
        self.clock_jitter_ms = ms;
        self
    }

    pub fn with_connection_cleanup(mut self, strategy: ConnectionCleanup) -> Self {
        self.connection_cleanup = strategy;
        self
    }

    pub fn with_memory_only(mut self, enabled: bool) -> Self {
        self.memory_only_mode = enabled;
        self
    }
}

/// Forensic countermeasures engine that minimizes forensic evidence
/// through log evasion, memory-only operations, PFS encryption,
/// metadata stripping, clock synchronization, and connection cleanup.
pub struct ForensicCountermeasureEngine {
    config: ForensicCountermeasureConfig,
    rng: StdRng,
    ua_index: usize,
    stripped_count: u64,
}

impl ForensicCountermeasureEngine {
    pub fn new(config: ForensicCountermeasureConfig) -> Self {
        Self {
            config,
            rng: StdRng::from_os_rng(),
            ua_index: 0,
            stripped_count: 0,
        }
    }

    pub fn with_seed(config: ForensicCountermeasureConfig, seed: u64) -> Self {
        Self {
            config,
            rng: StdRng::seed_from_u64(seed),
            ua_index: 0,
            stripped_count: 0,
        }
    }

    /// Returns recommended timing windows for log evasion.
    pub fn log_evasion_windows(&self) -> Vec<LogTimingWindow> {
        vec![
            LogTimingWindow {
                technique: LogEvasionTechnique::TimingBetweenRotations,
                recommended_hour_utc: 4,
                reason: "Most log rotation cron jobs run at 00:00, 04:00, or 06:00 UTC; requests during rotation may be dropped".to_string(),
                estimated_detection_reduction_pct: 30.0,
            },
            LogTimingWindow {
                technique: LogEvasionTechnique::SlowDripFeeding,
                recommended_hour_utc: 14,
                reason: "Business hours traffic volume provides natural cover for slow-rate requests".to_string(),
                estimated_detection_reduction_pct: 25.0,
            },
            LogTimingWindow {
                technique: LogEvasionTechnique::RequestPatternBypass,
                recommended_hour_utc: 2,
                reason: "Low-traffic window means fewer log entries to correlate against".to_string(),
                estimated_detection_reduction_pct: 20.0,
            },
            LogTimingWindow {
                technique: LogEvasionTechnique::LogFieldTruncation,
                recommended_hour_utc: 0,
                reason: "Oversized header values may truncate in fixed-width log formats".to_string(),
                estimated_detection_reduction_pct: 15.0,
            },
        ]
    }

    /// Returns recommended memory-only operation patterns.
    pub fn memory_only_patterns(&self) -> Vec<(MemoryOnlyPattern, &'static str)> {
        vec![
            (
                MemoryOnlyPattern::InMemoryBuffer,
                "All scan results buffered in Vec<u8>; never flushed to disk",
            ),
            (
                MemoryOnlyPattern::PipeChaining,
                "Pipe stdout of one process directly to stdin of next; no intermediate files",
            ),
            (
                MemoryOnlyPattern::MmapAnonymous,
                "MAP_ANONYMOUS|MAP_PRIVATE for temporary large allocations",
            ),
            (
                MemoryOnlyPattern::TmpfsVolatile,
                "Mount tmpfs for any required temp files; contents lost on reboot",
            ),
            (
                MemoryOnlyPattern::RamDisk,
                "Dedicated ramdisk partition for scan workspace",
            ),
        ]
    }

    /// Returns the configured PFS cipher suite and its properties.
    pub fn encryption_config(&self) -> (PfsCipherSuite, &'static str, bool) {
        let cipher = self.config.pfs_cipher;
        (cipher, cipher.openssl_name(), cipher.has_forward_secrecy())
    }

    /// Strips identifying metadata from request headers.
    pub fn strip_metadata(&mut self, headers: &HashMap<String, String>) -> MetadataStripResult {
        let mut stripped = headers.clone();
        let mut removed = Vec::new();

        for field in STRIP_HEADERS {
            let key = format!("{field}");
            if stripped.remove(&key).is_some() {
                removed.push(*field);
            }
        }

        let ua_replaced = if self.config.safe_ua_rotation {
            if let Some(ua) = stripped.get("User-Agent") {
                let lower = ua.to_lowercase();
                let is_scanner = SCANNER_UA_PATTERNS.iter().any(|p| lower.contains(p));
                if is_scanner {
                    let safe_ua = SAFE_USER_AGENTS[self.ua_index % SAFE_USER_AGENTS.len()];
                    self.ua_index += 1;
                    stripped.insert("User-Agent".to_string(), safe_ua.to_string());
                    true
                } else {
                    false
                }
            } else {
                let safe_ua = SAFE_USER_AGENTS[self.ua_index % SAFE_USER_AGENTS.len()];
                self.ua_index += 1;
                stripped.insert("User-Agent".to_string(), safe_ua.to_string());
                true
            }
        } else {
            false
        };

        self.stripped_count += 1;

        MetadataStripResult {
            original_headers: headers.clone(),
            stripped_headers: stripped,
            fields_removed: removed,
            ua_replaced,
        }
    }

    /// Checks if a User-Agent string contains scanner-identifying patterns.
    pub fn is_scanner_ua(ua: &str) -> bool {
        let lower = ua.to_lowercase();
        SCANNER_UA_PATTERNS.iter().any(|p| lower.contains(p))
    }

    /// Returns a safe User-Agent string.
    pub fn safe_user_agent(&mut self) -> &'static str {
        let ua = SAFE_USER_AGENTS[self.ua_index % SAFE_USER_AGENTS.len()];
        self.ua_index += 1;
        ua
    }

    /// Returns clock synchronization recommendations.
    pub fn clock_sync_recommendation(&self) -> ClockSyncRecommendation {
        ClockSyncRecommendation {
            use_utc: true,
            ntp_servers: vec![
                "pool.ntp.org".to_string(),
                "time.cloudflare.com".to_string(),
                "time.google.com".to_string(),
            ],
            jitter_range_ms: self.config.clock_jitter_ms,
            avoid_round_timestamps: true,
        }
    }

    /// Adds random jitter to a timestamp to avoid timezone/location inference.
    pub fn jittered_timestamp(&mut self, base_epoch_ms: u64) -> u64 {
        let jitter = self.rng.random_range(0..self.config.clock_jitter_ms);
        if self.rng.random_bool(0.5) {
            base_epoch_ms.saturating_add(jitter)
        } else {
            base_epoch_ms.saturating_sub(jitter)
        }
    }

    /// Returns connection cleanup plan for avoiding forensic artifacts.
    pub fn connection_cleanup_plan(&self) -> ConnectionCleanupPlan {
        match self.config.connection_cleanup {
            ConnectionCleanup::GracefulFinAck => ConnectionCleanupPlan {
                strategy: ConnectionCleanup::GracefulFinAck,
                linger_timeout_ms: 0,
                keepalive_interval_secs: 30,
                max_idle_secs: 60,
            },
            ConnectionCleanup::LingerZero => ConnectionCleanupPlan {
                strategy: ConnectionCleanup::LingerZero,
                linger_timeout_ms: 0,
                keepalive_interval_secs: 0,
                max_idle_secs: 0,
            },
            ConnectionCleanup::KeepAliveTimeout => ConnectionCleanupPlan {
                strategy: ConnectionCleanup::KeepAliveTimeout,
                linger_timeout_ms: 5000,
                keepalive_interval_secs: 15,
                max_idle_secs: 30,
            },
            ConnectionCleanup::IdleDisconnect => ConnectionCleanupPlan {
                strategy: ConnectionCleanup::IdleDisconnect,
                linger_timeout_ms: 1000,
                keepalive_interval_secs: 0,
                max_idle_secs: 10,
            },
        }
    }

    /// Returns the number of metadata strip operations performed.
    pub fn stripped_count(&self) -> u64 {
        self.stripped_count
    }
}
