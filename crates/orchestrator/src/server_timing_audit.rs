use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const SENSITIVE_METRIC_PATTERNS: &[(&str, f64)] = &[
    ("db", 4.0),
    ("database", 4.0),
    ("mysql", 4.5),
    ("postgres", 4.5),
    ("redis", 4.0),
    ("mongo", 4.0),
    ("cache", 3.0),
    ("memcache", 3.5),
    ("queue", 3.0),
    ("auth", 3.5),
    ("internal", 4.0),
    ("backend", 3.5),
    ("upstream", 3.0),
    ("cdn", 2.0),
];

#[derive(Debug, Clone)]
pub struct ServerTimingLeak {
    pub metric_name: String,
    pub severity: f64,
}

pub fn audit_server_timing(target: &str) -> Vec<ServerTimingLeak> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let values: Vec<String> = resp
        .headers()
        .get_all("server-timing")
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
        .collect();

    analyze_server_timing(&values)
}

pub fn analyze_server_timing(values: &[String]) -> Vec<ServerTimingLeak> {
    let mut leaks = Vec::new();
    let mut seen = Vec::new();

    for value in values {
        for metric in value.split(',') {
            let name = metric.split(';').next().unwrap_or("").trim();
            let lower = name.to_ascii_lowercase();

            for (pattern, severity) in SENSITIVE_METRIC_PATTERNS {
                if lower.contains(pattern) && !seen.contains(&lower) {
                    seen.push(lower.clone());
                    leaks.push(ServerTimingLeak {
                        metric_name: name.to_string(),
                        severity: *severity,
                    });
                    break;
                }
            }
        }
    }

    leaks
}

pub fn server_timing_to_operations(
    leaks: &[ServerTimingLeak],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if leaks.is_empty() {
        return Vec::new();
    }

    let max_severity = leaks.iter().map(|l| l.severity).fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::InformationDisclosure,
        max_severity,
        0.8,
    )]
}

#[derive(Debug, Clone, PartialEq)]
pub enum ServerTimingIssue {
    DatabaseTiming {
        metric: String,
        duration_ms: Option<f64>,
    },
    CacheTiming {
        metric: String,
        hit: bool,
    },
    InternalServiceTiming {
        metric: String,
        duration_ms: Option<f64>,
    },
    AuthTiming {
        metric: String,
    },
    SlowQuery {
        metric: String,
        duration_ms: f64,
    },
    ExcessiveMetrics {
        count: usize,
    },
    HighPrecisionTiming {
        metric: String,
    },
    BackendInfraLeak {
        metric: String,
    },
    QueueTiming {
        metric: String,
    },
    CdnTiming {
        metric: String,
    },
}

impl std::fmt::Display for ServerTimingIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerTimingIssue::DatabaseTiming {
                metric,
                duration_ms,
            } => {
                write!(f, "Database timing leak: {} ({:?} ms)", metric, duration_ms)
            }
            ServerTimingIssue::CacheTiming { metric, hit } => {
                write!(f, "Cache timing leak: {} (hit: {})", metric, hit)
            }
            ServerTimingIssue::InternalServiceTiming {
                metric,
                duration_ms,
            } => {
                write!(
                    f,
                    "Internal service timing: {} ({:?} ms)",
                    metric, duration_ms
                )
            }
            ServerTimingIssue::AuthTiming { metric } => {
                write!(f, "Auth timing leak: {}", metric)
            }
            ServerTimingIssue::SlowQuery {
                metric,
                duration_ms,
            } => {
                write!(f, "Slow query leak: {} ({} ms)", metric, duration_ms)
            }
            ServerTimingIssue::ExcessiveMetrics { count } => {
                write!(f, "Excessive metrics: {} entries", count)
            }
            ServerTimingIssue::HighPrecisionTiming { metric } => {
                write!(f, "High precision timing: {}", metric)
            }
            ServerTimingIssue::BackendInfraLeak { metric } => {
                write!(f, "Backend infrastructure leak: {}", metric)
            }
            ServerTimingIssue::QueueTiming { metric } => {
                write!(f, "Queue timing leak: {}", metric)
            }
            ServerTimingIssue::CdnTiming { metric } => {
                write!(f, "CDN timing leak: {}", metric)
            }
        }
    }
}

pub fn server_timing_issue_severity(issue: &ServerTimingIssue) -> f64 {
    match issue {
        ServerTimingIssue::SlowQuery { .. } => 6.0,
        ServerTimingIssue::DatabaseTiming { .. } => 5.0,
        ServerTimingIssue::AuthTiming { .. } => 4.5,
        ServerTimingIssue::InternalServiceTiming { .. } => 4.0,
        ServerTimingIssue::BackendInfraLeak { .. } => 4.0,
        ServerTimingIssue::CacheTiming { .. } => 3.0,
        ServerTimingIssue::QueueTiming { .. } => 3.0,
        ServerTimingIssue::HighPrecisionTiming { .. } => 3.5,
        ServerTimingIssue::ExcessiveMetrics { .. } => 3.0,
        ServerTimingIssue::CdnTiming { .. } => 2.0,
    }
}

pub fn analyze_timing_metrics(values: &[String]) -> Vec<ServerTimingIssue> {
    let mut issues = Vec::new();
    let mut metric_count = 0;

    for value in values {
        for metric in value.split(',') {
            metric_count += 1;
            let parts: Vec<&str> = metric.split(';').collect();
            let name = parts[0].trim().to_ascii_lowercase();
            let duration = extract_duration(parts.as_slice());
            let desc = extract_desc(parts.as_slice());

            // Database metrics
            let db_patterns = [
                "db", "database", "mysql", "postgres", "mongo", "sqlite", "sql",
            ];
            if db_patterns.iter().any(|p| name.contains(p)) {
                issues.push(ServerTimingIssue::DatabaseTiming {
                    metric: name.clone(),
                    duration_ms: duration,
                });
                if let Some(dur) = duration
                    && dur > 1000.0
                {
                    issues.push(ServerTimingIssue::SlowQuery {
                        metric: name.clone(),
                        duration_ms: dur,
                    });
                }
            }

            // Cache metrics
            let cache_patterns = ["cache", "memcache", "redis", "varnish"];
            if cache_patterns.iter().any(|p| name.contains(p)) {
                let hit = desc
                    .as_ref()
                    .map(|d| d.to_ascii_lowercase().contains("hit"))
                    .unwrap_or(false);
                issues.push(ServerTimingIssue::CacheTiming {
                    metric: name.clone(),
                    hit,
                });
            }

            // Auth metrics
            if name.contains("auth") || name.contains("token") || name.contains("session") {
                issues.push(ServerTimingIssue::AuthTiming {
                    metric: name.clone(),
                });
            }

            // Internal service metrics
            if name.contains("internal") || name.contains("backend") || name.contains("upstream") {
                issues.push(ServerTimingIssue::InternalServiceTiming {
                    metric: name.clone(),
                    duration_ms: duration,
                });
            }

            // Queue metrics
            if name.contains("queue") || name.contains("worker") || name.contains("job") {
                issues.push(ServerTimingIssue::QueueTiming {
                    metric: name.clone(),
                });
            }

            // CDN metrics
            if name.contains("cdn") || name.contains("edge") || name.contains("pop") {
                issues.push(ServerTimingIssue::CdnTiming {
                    metric: name.clone(),
                });
            }

            // Backend infra leak
            if name.contains("k8s")
                || name.contains("docker")
                || name.contains("lambda")
                || name.contains("fargate")
            {
                issues.push(ServerTimingIssue::BackendInfraLeak {
                    metric: name.clone(),
                });
            }

            // High precision timing (sub-millisecond)
            if let Some(dur) = duration
                && dur > 0.0
                && dur < 1.0
            {
                issues.push(ServerTimingIssue::HighPrecisionTiming {
                    metric: name.clone(),
                });
            }
        }
    }

    if metric_count > 10 {
        issues.push(ServerTimingIssue::ExcessiveMetrics {
            count: metric_count,
        });
    }

    issues
}

fn extract_duration(parts: &[&str]) -> Option<f64> {
    parts
        .iter()
        .find(|p| p.trim().starts_with("dur="))
        .and_then(|p| p.trim().strip_prefix("dur="))
        .and_then(|v| v.parse().ok())
}

fn extract_desc(parts: &[&str]) -> Option<String> {
    parts
        .iter()
        .find(|p| p.trim().starts_with("desc="))
        .map(|p| {
            p.trim()
                .strip_prefix("desc=")
                .unwrap_or("")
                .trim_matches('"')
                .to_string()
        })
}

pub fn server_timing_issues_to_operations(
    issues: &[ServerTimingIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                server_timing_issue_severity(issue),
                0.5,
            )
        })
        .collect()
}
