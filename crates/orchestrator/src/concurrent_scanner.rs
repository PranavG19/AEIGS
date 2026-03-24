use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Configuration for the concurrent scanner.
#[derive(Debug, Clone)]
pub struct ConcurrencyConfig {
    pub max_concurrency: usize,
    pub per_host_rps: f64,
    pub request_timeout: Duration,
    pub total_timeout: Option<Duration>,
}

impl Default for ConcurrencyConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 50,
            per_host_rps: 10.0,
            request_timeout: Duration::from_secs(30),
            total_timeout: None,
        }
    }
}

/// Priority level for endpoint scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EndpointPriority {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// An endpoint queued for scanning.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ScanEndpoint {
    pub url: String,
    pub method: String,
    pub priority: EndpointPriority,
    pub host: String,
}

impl Ord for ScanEndpoint {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority.cmp(&other.priority)
    }
}

impl PartialOrd for ScanEndpoint {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Real-time progress of the scan.
#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub total_endpoints: u64,
    pub completed: u64,
    pub findings_so_far: u64,
    pub elapsed: Duration,
    pub estimated_remaining: Option<Duration>,
    pub active_workers: u64,
}

/// Shared atomic counters for lock-free progress tracking.
#[derive(Debug)]
pub struct ProgressTracker {
    total: AtomicU64,
    completed: AtomicU64,
    findings: AtomicU64,
    active: AtomicU64,
    shutdown: AtomicBool,
    start_time: Instant,
}

impl ProgressTracker {
    pub fn new(total: u64) -> Self {
        Self {
            total: AtomicU64::new(total),
            completed: AtomicU64::new(0),
            findings: AtomicU64::new(0),
            active: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
            start_time: Instant::now(),
        }
    }

    pub fn record_completion(&self, findings: u64) {
        self.completed.fetch_add(1, Ordering::Relaxed);
        if findings > 0 {
            self.findings.fetch_add(findings, Ordering::Relaxed);
        }
    }

    pub fn worker_started(&self) {
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn worker_finished(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> ScanProgress {
        let total = self.total.load(Ordering::Relaxed);
        let completed = self.completed.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed();
        let estimated_remaining = if completed > 0 {
            let per_endpoint = elapsed.as_secs_f64() / completed as f64;
            let remaining = (total.saturating_sub(completed)) as f64 * per_endpoint;
            Some(Duration::from_secs_f64(remaining))
        } else {
            None
        };

        ScanProgress {
            total_endpoints: total,
            completed,
            findings_so_far: self.findings.load(Ordering::Relaxed),
            elapsed,
            estimated_remaining,
            active_workers: self.active.load(Ordering::Relaxed),
        }
    }

    pub fn percent_complete(&self) -> f64 {
        let total = self.total.load(Ordering::Relaxed);
        let completed = self.completed.load(Ordering::Relaxed);
        if total == 0 {
            100.0
        } else {
            (completed as f64 / total as f64) * 100.0
        }
    }
}

/// Simple per-host rate limiter using token bucket.
#[derive(Debug)]
pub struct RateLimiter {
    interval: Duration,
    last_request: Mutex<HashMap<String, Instant>>,
}

impl RateLimiter {
    pub fn new(rps: f64) -> Self {
        let interval = if rps <= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(1.0 / rps)
        };
        Self {
            interval,
            last_request: Mutex::new(HashMap::new()),
        }
    }

    pub async fn wait_for_host(&self, host: &str) {
        let wait_duration = {
            let mut map = self.last_request.lock().unwrap();
            let now = Instant::now();
            if let Some(last) = map.get(host) {
                let elapsed = now.duration_since(*last);
                if elapsed < self.interval {
                    let wait = self.interval - elapsed;
                    map.insert(host.to_string(), now + wait);
                    wait
                } else {
                    map.insert(host.to_string(), now);
                    Duration::ZERO
                }
            } else {
                map.insert(host.to_string(), now);
                Duration::ZERO
            }
        };
        if !wait_duration.is_zero() {
            tokio::time::sleep(wait_duration).await;
        }
    }
}

/// Result of scanning a single endpoint.
#[derive(Debug, Clone)]
pub struct EndpointResult {
    pub url: String,
    pub findings_count: u64,
    pub error: Option<String>,
    pub duration: Duration,
}

/// Build a priority queue from a list of endpoints, auto-assigning priority
/// based on URL patterns.
pub fn prioritize_endpoints(endpoints: Vec<(String, String)>) -> Vec<ScanEndpoint> {
    let mut queue: Vec<ScanEndpoint> = endpoints
        .into_iter()
        .map(|(url, method)| {
            let priority = classify_priority(&url);
            let host = extract_host_from_url(&url);
            ScanEndpoint {
                url,
                method,
                priority,
                host,
            }
        })
        .collect();
    queue.sort_by(|a, b| b.priority.cmp(&a.priority));
    queue
}

fn classify_priority(url: &str) -> EndpointPriority {
    let lower = url.to_lowercase();
    if lower.contains("/admin")
        || lower.contains("/auth")
        || lower.contains("/login")
        || lower.contains("/api/v")
        || lower.contains("/token")
        || lower.contains("/oauth")
    {
        EndpointPriority::Critical
    } else if lower.contains("/api/")
        || lower.contains("/graphql")
        || lower.contains("/user")
        || lower.contains("/account")
        || lower.contains("/payment")
    {
        EndpointPriority::High
    } else if lower.contains("/search")
        || lower.contains("/upload")
        || lower.contains("/download")
        || lower.contains("/file")
    {
        EndpointPriority::Medium
    } else {
        EndpointPriority::Low
    }
}

fn extract_host_from_url(url: &str) -> String {
    url.split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("unknown")
        .split(':')
        .next()
        .unwrap_or("unknown")
        .to_string()
}

/// State for scan resume.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ScanState {
    pub completed_urls: Vec<String>,
    pub pending_urls: Vec<String>,
    pub findings_count: u64,
    pub elapsed_ms: u64,
}

impl ScanState {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
#[path = "concurrent_scanner_test.rs"]
mod concurrent_scanner_test;
