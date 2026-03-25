use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

/// Strategy to apply when a specific error type occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryStrategy {
    Retry,
    RetryWithBackoff,
    SwitchEvasion,
    Skip,
    Abort,
    EmergencySave,
}

/// Categorized error types for recovery decisions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ErrorCategory {
    NetworkTimeout,
    ConnectionRefused,
    WafBlocked,
    RateLimited,
    ModuleCrash(String),
    DiskFull,
    AuthExpired,
    Unknown(String),
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NetworkTimeout => write!(f, "network timeout"),
            Self::ConnectionRefused => write!(f, "connection refused"),
            Self::WafBlocked => write!(f, "WAF blocked"),
            Self::RateLimited => write!(f, "rate limited"),
            Self::ModuleCrash(name) => write!(f, "module crash: {name}"),
            Self::DiskFull => write!(f, "disk full"),
            Self::AuthExpired => write!(f, "auth expired"),
            Self::Unknown(msg) => write!(f, "unknown: {msg}"),
        }
    }
}

/// Record of a single error occurrence.
#[derive(Debug, Clone)]
pub struct ErrorRecord {
    pub category: ErrorCategory,
    pub module: String,
    pub message: String,
    pub timestamp: Instant,
    pub recovery_applied: RecoveryStrategy,
    pub recovered: bool,
}

/// Per-module error tracking.
#[derive(Debug, Clone, Default)]
pub struct ModuleErrorStats {
    pub total_errors: u64,
    pub consecutive_errors: u64,
    pub last_error: Option<Instant>,
    pub disabled: bool,
}

/// Manages error recovery across scan modules.
///
/// Handles failures gracefully: module crash → isolate and continue.
/// Network timeout → retry with backoff. WAF block → switch evasion strategy.
/// Disk full → emergency save state. Tracks error rates per module and
/// disables flaky modules after threshold breaches.
pub struct ErrorRecoveryManager {
    max_retries: u32,
    max_consecutive_errors: u64,
    backoff_base: Duration,
    backoff_max: Duration,
    module_stats: HashMap<String, ModuleErrorStats>,
    error_log: Vec<ErrorRecord>,
    disabled_modules: Vec<String>,
    recovery_map: HashMap<ErrorCategory, RecoveryStrategy>,
}

impl ErrorRecoveryManager {
    pub fn new() -> Self {
        Self {
            max_retries: 3,
            max_consecutive_errors: 5,
            backoff_base: Duration::from_millis(500),
            backoff_max: Duration::from_secs(30),
            module_stats: HashMap::new(),
            error_log: Vec::new(),
            disabled_modules: Vec::new(),
            recovery_map: Self::default_recovery_map(),
        }
    }

    pub fn with_max_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }

    pub fn with_max_consecutive_errors(mut self, n: u64) -> Self {
        self.max_consecutive_errors = n;
        self
    }

    /// Classify a raw error message into an error category.
    pub fn classify_error(&self, message: &str) -> ErrorCategory {
        let lower = message.to_lowercase();
        if lower.contains("timeout") || lower.contains("timed out") {
            ErrorCategory::NetworkTimeout
        } else if lower.contains("connection refused") || lower.contains("connrefused") {
            ErrorCategory::ConnectionRefused
        } else if lower.contains("waf")
            || lower.contains("403 forbidden")
            || lower.contains("blocked")
        {
            ErrorCategory::WafBlocked
        } else if lower.contains("rate limit")
            || lower.contains("429")
            || lower.contains("too many")
        {
            ErrorCategory::RateLimited
        } else if lower.contains("disk full") || lower.contains("no space") {
            ErrorCategory::DiskFull
        } else if lower.contains("auth")
            && (lower.contains("expired") || lower.contains("invalid token"))
        {
            ErrorCategory::AuthExpired
        } else if lower.contains("panic") || lower.contains("crash") || lower.contains("segfault") {
            ErrorCategory::ModuleCrash("unknown".into())
        } else {
            ErrorCategory::Unknown(message.to_string())
        }
    }

    /// Determine the recovery strategy for an error category.
    pub fn strategy_for(&self, category: &ErrorCategory) -> RecoveryStrategy {
        self.recovery_map
            .get(category)
            .copied()
            .unwrap_or(RecoveryStrategy::Skip)
    }

    /// Record an error from a module and determine recovery action.
    pub fn record_error(&mut self, module: &str, message: &str) -> RecoveryStrategy {
        let category = self.classify_error(message);
        let strategy = self.strategy_for(&category);

        let stats = self.module_stats.entry(module.to_string()).or_default();
        stats.total_errors += 1;
        stats.consecutive_errors += 1;
        stats.last_error = Some(Instant::now());

        if stats.consecutive_errors >= self.max_consecutive_errors && !stats.disabled {
            stats.disabled = true;
            self.disabled_modules.push(module.to_string());
        }

        self.error_log.push(ErrorRecord {
            category,
            module: module.to_string(),
            message: message.to_string(),
            timestamp: Instant::now(),
            recovery_applied: strategy,
            recovered: false,
        });

        if stats.disabled {
            return RecoveryStrategy::Skip;
        }

        strategy
    }

    /// Mark a module as recovered (reset consecutive error counter).
    pub fn record_success(&mut self, module: &str) {
        if let Some(stats) = self.module_stats.get_mut(module) {
            stats.consecutive_errors = 0;
        }
    }

    /// Calculate backoff duration for retry attempt number `attempt` (0-indexed).
    pub fn backoff_duration(&self, attempt: u32) -> Duration {
        let base_ms = self.backoff_base.as_millis() as u64;
        let backoff_ms = base_ms.saturating_mul(2u64.saturating_pow(attempt));
        let max_ms = self.backoff_max.as_millis() as u64;
        Duration::from_millis(backoff_ms.min(max_ms))
    }

    /// Whether a module has been disabled due to excessive errors.
    pub fn is_module_disabled(&self, module: &str) -> bool {
        self.module_stats.get(module).is_some_and(|s| s.disabled)
    }

    /// List of all disabled modules.
    pub fn disabled_modules(&self) -> &[String] {
        &self.disabled_modules
    }

    /// Total error count across all modules.
    pub fn total_errors(&self) -> u64 {
        self.module_stats.values().map(|s| s.total_errors).sum()
    }

    /// Error count for a specific module.
    pub fn module_error_count(&self, module: &str) -> u64 {
        self.module_stats
            .get(module)
            .map(|s| s.total_errors)
            .unwrap_or(0)
    }

    /// Whether more retries are available for a given attempt count.
    pub fn should_retry(&self, attempt: u32) -> bool {
        attempt < self.max_retries
    }

    /// Full error log for post-scan analysis.
    pub fn error_log(&self) -> &[ErrorRecord] {
        &self.error_log
    }

    /// Re-enable a previously disabled module (manual override).
    pub fn reenable_module(&mut self, module: &str) -> bool {
        if let Some(stats) = self.module_stats.get_mut(module) {
            stats.disabled = false;
            stats.consecutive_errors = 0;
            self.disabled_modules.retain(|m| m != module);
            true
        } else {
            false
        }
    }

    fn default_recovery_map() -> HashMap<ErrorCategory, RecoveryStrategy> {
        let mut map = HashMap::new();
        map.insert(
            ErrorCategory::NetworkTimeout,
            RecoveryStrategy::RetryWithBackoff,
        );
        map.insert(
            ErrorCategory::ConnectionRefused,
            RecoveryStrategy::RetryWithBackoff,
        );
        map.insert(ErrorCategory::WafBlocked, RecoveryStrategy::SwitchEvasion);
        map.insert(
            ErrorCategory::RateLimited,
            RecoveryStrategy::RetryWithBackoff,
        );
        map.insert(ErrorCategory::DiskFull, RecoveryStrategy::EmergencySave);
        map.insert(ErrorCategory::AuthExpired, RecoveryStrategy::Retry);
        map
    }
}

impl Default for ErrorRecoveryManager {
    fn default() -> Self {
        Self::new()
    }
}
