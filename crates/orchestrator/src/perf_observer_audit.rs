use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum PerfObserverIssue {
    ObserverDetected,
    ResourceTimingObserved,
    NavigationTimingObserved,
    LongTaskObserved,
    GetEntriesByType,
    BufferedFlag,
    ExcessiveEntryTypes,
}

impl std::fmt::Display for PerfObserverIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ObserverDetected => write!(f, "observer_detected"),
            Self::ResourceTimingObserved => write!(f, "resource_timing_observed"),
            Self::NavigationTimingObserved => write!(f, "navigation_timing_observed"),
            Self::LongTaskObserved => write!(f, "long_task_observed"),
            Self::GetEntriesByType => write!(f, "get_entries_by_type"),
            Self::BufferedFlag => write!(f, "buffered_flag"),
            Self::ExcessiveEntryTypes => write!(f, "excessive_entry_types"),
        }
    }
}

pub fn audit_perf_observer(target: &str) -> Vec<PerfObserverIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send() {
        Ok(r) => r.text().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    analyze_perf_observer(&body)
}

pub fn analyze_perf_observer(body: &str) -> Vec<PerfObserverIssue> {
    let has_observer = body.contains("PerformanceObserver");
    let has_get_entries = body.contains("getEntriesByType")
        || body.contains("getEntriesByName")
        || body.contains("getEntries()");
    if !has_observer && !has_get_entries {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if has_observer {
        issues.push(PerfObserverIssue::ObserverDetected);

        if body.contains("\"resource\"") || body.contains("'resource'") {
            issues.push(PerfObserverIssue::ResourceTimingObserved);
        }

        if body.contains("\"navigation\"") || body.contains("'navigation'") {
            issues.push(PerfObserverIssue::NavigationTimingObserved);
        }

        if body.contains("\"longtask\"") || body.contains("'longtask'") {
            issues.push(PerfObserverIssue::LongTaskObserved);
        }

        if body.contains("buffered") && body.contains("true") {
            issues.push(PerfObserverIssue::BufferedFlag);
        }

        let type_count = count_observed_types(body);
        if type_count > 3 {
            issues.push(PerfObserverIssue::ExcessiveEntryTypes);
        }
    }

    if has_get_entries {
        issues.push(PerfObserverIssue::GetEntriesByType);
    }

    issues
}

fn count_observed_types(body: &str) -> usize {
    let types = [
        "resource",
        "navigation",
        "longtask",
        "mark",
        "measure",
        "paint",
        "largest-contentful-paint",
        "first-input",
        "layout-shift",
        "element",
    ];
    types
        .iter()
        .filter(|t| {
            let dq = format!("\"{t}\"");
            let sq = format!("'{t}'");
            body.contains(dq.as_str()) || body.contains(sq.as_str())
        })
        .count()
}

pub fn perf_observer_severity(issue: &PerfObserverIssue) -> f64 {
    match issue {
        PerfObserverIssue::ResourceTimingObserved => 5.5,
        PerfObserverIssue::BufferedFlag => 5.0,
        PerfObserverIssue::NavigationTimingObserved => 4.5,
        PerfObserverIssue::ExcessiveEntryTypes => 4.5,
        PerfObserverIssue::LongTaskObserved => 4.0,
        PerfObserverIssue::GetEntriesByType => 3.5,
        PerfObserverIssue::ObserverDetected => 3.0,
    }
}

pub fn perf_observer_to_operations(
    issues: &[PerfObserverIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                perf_observer_severity(issue),
                0.7,
            )
        })
        .collect()
}
