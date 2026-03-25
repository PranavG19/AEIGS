use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Represents a snapshot of a target's observable state at a point in time.
///
/// Collected during each scan to enable diff-based change detection between
/// consecutive runs. Every field is optional so partial snapshots are valid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetSnapshot {
    pub timestamp_ms: u64,
    pub target_url: String,
    pub endpoints: HashSet<String>,
    pub subdomains: HashSet<String>,
    pub response_signatures: HashMap<String, ResponseSignature>,
    pub tls_certificate_fingerprint: Option<String>,
    pub technology_stack: HashSet<String>,
    pub dns_records: HashMap<String, Vec<String>>,
}

impl TargetSnapshot {
    pub fn new(target_url: &str, timestamp_ms: u64) -> Self {
        Self {
            timestamp_ms,
            target_url: target_url.to_string(),
            endpoints: HashSet::new(),
            subdomains: HashSet::new(),
            response_signatures: HashMap::new(),
            tls_certificate_fingerprint: None,
            technology_stack: HashSet::new(),
            dns_records: HashMap::new(),
        }
    }
}

/// Compact signature of an HTTP response used for change detection.
///
/// Two responses with the same status, content length range, and header
/// hash are considered equivalent. The content_hash provides a tighter
/// comparison when available.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseSignature {
    pub status_code: u16,
    pub content_length_bucket: ContentLengthBucket,
    pub header_hash: u64,
    pub content_hash: Option<u64>,
}

/// Coarse buckets for content-length so minor padding changes are ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContentLengthBucket {
    Empty,
    Tiny,      // 1–1 KB
    Small,     // 1–10 KB
    Medium,    // 10–100 KB
    Large,     // 100 KB–1 MB
    VeryLarge, // > 1 MB
}

impl ContentLengthBucket {
    pub fn from_length(len: u64) -> Self {
        match len {
            0 => Self::Empty,
            1..=1024 => Self::Tiny,
            1025..=10240 => Self::Small,
            10241..=102400 => Self::Medium,
            102401..=1048576 => Self::Large,
            _ => Self::VeryLarge,
        }
    }
}

/// Classification of a detected change.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChangeType {
    EndpointAdded(String),
    EndpointRemoved(String),
    ResponseChanged(String),
    SubdomainAdded(String),
    SubdomainRemoved(String),
    CertificateChanged,
    TechnologyAdded(String),
    TechnologyRemoved(String),
    DnsRecordAdded { record_type: String, value: String },
    DnsRecordRemoved { record_type: String, value: String },
}

/// Severity of a detected change, used to prioritize alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ChangeSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// A single detected change between two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedChange {
    pub change_type: ChangeType,
    pub severity: ChangeSeverity,
    pub description: String,
    pub detected_at_ms: u64,
}

/// Summary of all changes between two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeReport {
    pub target_url: String,
    pub baseline_timestamp_ms: u64,
    pub current_timestamp_ms: u64,
    pub changes: Vec<DetectedChange>,
    pub total_changes: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

impl ChangeReport {
    /// True when no changes were detected.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Returns the highest severity among all changes, or None if empty.
    pub fn max_severity(&self) -> Option<ChangeSeverity> {
        self.changes.iter().map(|c| c.severity).max()
    }
}

/// Detects changes between two `TargetSnapshot` instances.
pub struct ChangeDetector;

impl ChangeDetector {
    pub fn new() -> Self {
        Self
    }

    /// Compares a baseline snapshot against a current snapshot and returns
    /// all detected changes with severities and descriptions.
    pub fn detect(&self, baseline: &TargetSnapshot, current: &TargetSnapshot) -> ChangeReport {
        let mut changes = Vec::new();
        let detected_at = current.timestamp_ms;

        self.detect_endpoint_changes(baseline, current, detected_at, &mut changes);
        self.detect_subdomain_changes(baseline, current, detected_at, &mut changes);
        self.detect_response_changes(baseline, current, detected_at, &mut changes);
        self.detect_certificate_changes(baseline, current, detected_at, &mut changes);
        self.detect_technology_changes(baseline, current, detected_at, &mut changes);
        self.detect_dns_changes(baseline, current, detected_at, &mut changes);

        let critical_count = changes
            .iter()
            .filter(|c| c.severity == ChangeSeverity::Critical)
            .count();
        let high_count = changes
            .iter()
            .filter(|c| c.severity == ChangeSeverity::High)
            .count();
        let medium_count = changes
            .iter()
            .filter(|c| c.severity == ChangeSeverity::Medium)
            .count();
        let low_count = changes
            .iter()
            .filter(|c| c.severity == ChangeSeverity::Low)
            .count();
        let total_changes = changes.len();

        ChangeReport {
            target_url: current.target_url.clone(),
            baseline_timestamp_ms: baseline.timestamp_ms,
            current_timestamp_ms: current.timestamp_ms,
            changes,
            total_changes,
            critical_count,
            high_count,
            medium_count,
            low_count,
        }
    }

    fn detect_endpoint_changes(
        &self,
        baseline: &TargetSnapshot,
        current: &TargetSnapshot,
        ts: u64,
        out: &mut Vec<DetectedChange>,
    ) {
        for ep in current.endpoints.difference(&baseline.endpoints) {
            out.push(DetectedChange {
                change_type: ChangeType::EndpointAdded(ep.clone()),
                severity: ChangeSeverity::Medium,
                description: format!("New endpoint discovered: {ep}"),
                detected_at_ms: ts,
            });
        }
        for ep in baseline.endpoints.difference(&current.endpoints) {
            out.push(DetectedChange {
                change_type: ChangeType::EndpointRemoved(ep.clone()),
                severity: ChangeSeverity::Low,
                description: format!("Endpoint no longer present: {ep}"),
                detected_at_ms: ts,
            });
        }
    }

    fn detect_subdomain_changes(
        &self,
        baseline: &TargetSnapshot,
        current: &TargetSnapshot,
        ts: u64,
        out: &mut Vec<DetectedChange>,
    ) {
        for sub in current.subdomains.difference(&baseline.subdomains) {
            out.push(DetectedChange {
                change_type: ChangeType::SubdomainAdded(sub.clone()),
                severity: ChangeSeverity::High,
                description: format!("New subdomain detected: {sub}"),
                detected_at_ms: ts,
            });
        }
        for sub in baseline.subdomains.difference(&current.subdomains) {
            out.push(DetectedChange {
                change_type: ChangeType::SubdomainRemoved(sub.clone()),
                severity: ChangeSeverity::Medium,
                description: format!("Subdomain removed: {sub}"),
                detected_at_ms: ts,
            });
        }
    }

    fn detect_response_changes(
        &self,
        baseline: &TargetSnapshot,
        current: &TargetSnapshot,
        ts: u64,
        out: &mut Vec<DetectedChange>,
    ) {
        for (ep, current_sig) in &current.response_signatures {
            if let Some(baseline_sig) = baseline.response_signatures.get(ep)
                && baseline_sig != current_sig
            {
                    out.push(DetectedChange {
                        change_type: ChangeType::ResponseChanged(ep.clone()),
                        severity: if baseline_sig.status_code != current_sig.status_code {
                            ChangeSeverity::High
                        } else {
                            ChangeSeverity::Medium
                        },
                        description: format!(
                            "Response changed for {ep}: status {}→{}, size {:?}→{:?}",
                            baseline_sig.status_code,
                            current_sig.status_code,
                            baseline_sig.content_length_bucket,
                            current_sig.content_length_bucket,
                        ),
                        detected_at_ms: ts,
                    });
            }
        }
    }

    fn detect_certificate_changes(
        &self,
        baseline: &TargetSnapshot,
        current: &TargetSnapshot,
        ts: u64,
        out: &mut Vec<DetectedChange>,
    ) {
        match (
            &baseline.tls_certificate_fingerprint,
            &current.tls_certificate_fingerprint,
        ) {
            (Some(old), Some(new)) if old != new => {
                out.push(DetectedChange {
                    change_type: ChangeType::CertificateChanged,
                    severity: ChangeSeverity::Critical,
                    description: format!("TLS certificate changed: {old} → {new}"),
                    detected_at_ms: ts,
                });
            }
            (None, Some(new)) => {
                out.push(DetectedChange {
                    change_type: ChangeType::CertificateChanged,
                    severity: ChangeSeverity::High,
                    description: format!("TLS certificate appeared: {new}"),
                    detected_at_ms: ts,
                });
            }
            (Some(old), None) => {
                out.push(DetectedChange {
                    change_type: ChangeType::CertificateChanged,
                    severity: ChangeSeverity::Critical,
                    description: format!("TLS certificate disappeared: {old}"),
                    detected_at_ms: ts,
                });
            }
            _ => {}
        }
    }

    fn detect_technology_changes(
        &self,
        baseline: &TargetSnapshot,
        current: &TargetSnapshot,
        ts: u64,
        out: &mut Vec<DetectedChange>,
    ) {
        for tech in current
            .technology_stack
            .difference(&baseline.technology_stack)
        {
            out.push(DetectedChange {
                change_type: ChangeType::TechnologyAdded(tech.clone()),
                severity: ChangeSeverity::Medium,
                description: format!("New technology detected: {tech}"),
                detected_at_ms: ts,
            });
        }
        for tech in baseline
            .technology_stack
            .difference(&current.technology_stack)
        {
            out.push(DetectedChange {
                change_type: ChangeType::TechnologyRemoved(tech.clone()),
                severity: ChangeSeverity::Low,
                description: format!("Technology removed: {tech}"),
                detected_at_ms: ts,
            });
        }
    }

    fn detect_dns_changes(
        &self,
        baseline: &TargetSnapshot,
        current: &TargetSnapshot,
        ts: u64,
        out: &mut Vec<DetectedChange>,
    ) {
        let all_keys: HashSet<_> = baseline
            .dns_records
            .keys()
            .chain(current.dns_records.keys())
            .collect();

        for key in all_keys {
            let old_vals: HashSet<_> = baseline
                .dns_records
                .get(key)
                .map(|v| v.iter().collect())
                .unwrap_or_default();
            let new_vals: HashSet<_> = current
                .dns_records
                .get(key)
                .map(|v| v.iter().collect())
                .unwrap_or_default();

            for val in new_vals.difference(&old_vals) {
                out.push(DetectedChange {
                    change_type: ChangeType::DnsRecordAdded {
                        record_type: key.clone(),
                        value: (*val).clone(),
                    },
                    severity: ChangeSeverity::High,
                    description: format!("DNS {key} record added: {val}"),
                    detected_at_ms: ts,
                });
            }
            for val in old_vals.difference(&new_vals) {
                out.push(DetectedChange {
                    change_type: ChangeType::DnsRecordRemoved {
                        record_type: key.clone(),
                        value: (*val).clone(),
                    },
                    severity: ChangeSeverity::Medium,
                    description: format!("DNS {key} record removed: {val}"),
                    detected_at_ms: ts,
                });
            }
        }
    }
}

impl Default for ChangeDetector {
    fn default() -> Self {
        Self::new()
    }
}
