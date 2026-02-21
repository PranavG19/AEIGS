use aegis_protocol::audit::{AuditEntry, AuditEventType};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Filter criteria for querying audit entries.
///
/// All fields are optional; `None` means no constraint on that axis.
/// When multiple fields are set, they are combined with AND semantics.
#[derive(Debug, Clone, Default)]
pub struct EventQuery {
    pub event_types: Option<Vec<String>>,
    pub after_sequence: Option<u64>,
    pub before_sequence: Option<u64>,
    pub after_timestamp_ms: Option<u64>,
    pub before_timestamp_ms: Option<u64>,
}

/// Reconstructed scan state from replaying audit entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSnapshot {
    pub target_description: Option<String>,
    pub active_modules: Vec<String>,
    pub findings: Vec<FindingRecord>,
    pub total_findings: Option<u64>,
    pub config_changes: Vec<ConfigChangeRecord>,
    pub key_events: Vec<String>,
    pub last_sequence: u64,
    pub last_timestamp_ms: u64,
    pub is_complete: bool,
}

/// A finding recorded during a scan, captured from a `FindingRecorded` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRecord {
    pub finding_id: u64,
    pub vulnerability_class: String,
    pub sequence_number: u64,
    pub timestamp_ms: u64,
}

/// A configuration change captured from a `ConfigChange` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigChangeRecord {
    pub key: String,
    pub old_value: String,
    pub new_value: String,
    pub sequence_number: u64,
    pub timestamp_ms: u64,
}

/// Differences between two scan snapshots.
#[derive(Debug, Clone)]
pub struct SnapshotDiff {
    pub new_findings: Vec<FindingRecord>,
    pub new_modules: Vec<String>,
    pub new_config_changes: Vec<ConfigChangeRecord>,
    pub new_key_events: Vec<String>,
}

/// Result of replaying audit entries through the event store.
#[derive(Debug, Clone)]
pub struct ReplayResult {
    pub snapshot: ScanSnapshot,
    pub entries_replayed: u64,
    pub entries_skipped: u64,
}

/// Errors that can occur during event store operations.
#[derive(Debug)]
pub enum EventStoreError {
    VerificationFailed(String),
    DeserializationFailed(String),
    InvalidQuery(String),
    Io(std::io::Error),
}

impl std::fmt::Display for EventStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VerificationFailed(msg) => write!(f, "verification failed: {msg}"),
            Self::DeserializationFailed(msg) => write!(f, "deserialization failed: {msg}"),
            Self::InvalidQuery(msg) => write!(f, "invalid query: {msg}"),
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for EventStoreError {}

impl From<std::io::Error> for EventStoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Replay audit entries in sequence order to reconstruct scan state.
pub fn replay_from_entries(entries: &[AuditEntry]) -> ScanSnapshot {
    let mut snapshot = ScanSnapshot {
        target_description: None,
        active_modules: Vec::new(),
        findings: Vec::new(),
        total_findings: None,
        config_changes: Vec::new(),
        key_events: Vec::new(),
        last_sequence: 0,
        last_timestamp_ms: 0,
        is_complete: false,
    };

    for entry in entries {
        apply_event_to_snapshot(&mut snapshot, entry);
    }

    snapshot
}

fn apply_event_to_snapshot(snapshot: &mut ScanSnapshot, entry: &AuditEntry) {
    snapshot.last_sequence = entry.sequence_number;
    snapshot.last_timestamp_ms = entry.timestamp_unix_ms;

    match &entry.event {
        AuditEventType::ScanStarted { target_description } => {
            snapshot.target_description = Some(target_description.clone());
        }
        AuditEventType::ModuleStarted { module } => {
            snapshot.active_modules.push(format!("{module:?}"));
        }
        AuditEventType::FindingRecorded {
            finding_id,
            vulnerability_class,
        } => {
            snapshot.findings.push(FindingRecord {
                finding_id: *finding_id,
                vulnerability_class: format!("{vulnerability_class}"),
                sequence_number: entry.sequence_number,
                timestamp_ms: entry.timestamp_unix_ms,
            });
        }
        AuditEventType::ScanCompleted { total_findings } => {
            snapshot.total_findings = Some(*total_findings);
            snapshot.is_complete = true;
        }
        AuditEventType::KeyEvent { description } => {
            snapshot.key_events.push(description.clone());
        }
        AuditEventType::ConfigChange {
            key,
            old_value,
            new_value,
        } => {
            snapshot.config_changes.push(ConfigChangeRecord {
                key: key.clone(),
                old_value: old_value.clone(),
                new_value: new_value.clone(),
                sequence_number: entry.sequence_number,
                timestamp_ms: entry.timestamp_unix_ms,
            });
        }
    }
}

/// Filter entries by the given query criteria.
///
/// Returns references to matching entries. Returns `InvalidQuery` if
/// `after_sequence >= before_sequence` or `after_timestamp_ms >= before_timestamp_ms`.
pub fn filter_entries<'a>(
    entries: &'a [AuditEntry],
    query: &EventQuery,
) -> Result<Vec<&'a AuditEntry>, EventStoreError> {
    validate_query(query)?;

    let type_set: Option<HashSet<&str>> = query
        .event_types
        .as_ref()
        .map(|types| types.iter().map(String::as_str).collect());

    let filtered = entries
        .iter()
        .filter(|entry| {
            if let Some(ref types) = type_set
                && !types.contains(classify_event(&entry.event))
            {
                return false;
            }
            if let Some(after) = query.after_sequence
                && entry.sequence_number <= after
            {
                return false;
            }
            if let Some(before) = query.before_sequence
                && entry.sequence_number >= before
            {
                return false;
            }
            if let Some(after_ts) = query.after_timestamp_ms
                && entry.timestamp_unix_ms <= after_ts
            {
                return false;
            }
            if let Some(before_ts) = query.before_timestamp_ms
                && entry.timestamp_unix_ms >= before_ts
            {
                return false;
            }
            true
        })
        .collect();

    Ok(filtered)
}

fn validate_query(query: &EventQuery) -> Result<(), EventStoreError> {
    if let (Some(after), Some(before)) = (query.after_sequence, query.before_sequence)
        && after >= before
    {
        return Err(EventStoreError::InvalidQuery(format!(
            "after_sequence ({after}) must be less than before_sequence ({before})"
        )));
    }
    if let (Some(after), Some(before)) = (query.after_timestamp_ms, query.before_timestamp_ms)
        && after >= before
    {
        return Err(EventStoreError::InvalidQuery(format!(
            "after_timestamp_ms ({after}) must be less than before_timestamp_ms ({before})"
        )));
    }
    Ok(())
}

/// Return the string classification name for an audit event type.
pub fn classify_event(event: &AuditEventType) -> &'static str {
    match event {
        AuditEventType::ScanStarted { .. } => "ScanStarted",
        AuditEventType::ModuleStarted { .. } => "ModuleStarted",
        AuditEventType::FindingRecorded { .. } => "FindingRecorded",
        AuditEventType::ScanCompleted { .. } => "ScanCompleted",
        AuditEventType::KeyEvent { .. } => "KeyEvent",
        AuditEventType::ConfigChange { .. } => "ConfigChange",
    }
}

/// Build a timeline of (timestamp_ms, human-readable description) pairs.
pub fn compute_scan_timeline(entries: &[AuditEntry]) -> Vec<(u64, String)> {
    entries
        .iter()
        .map(|entry| {
            let description = describe_event(&entry.event);
            (entry.timestamp_unix_ms, description)
        })
        .collect()
}

fn describe_event(event: &AuditEventType) -> String {
    match event {
        AuditEventType::ScanStarted { target_description } => {
            format!("Scan started: {target_description}")
        }
        AuditEventType::ModuleStarted { module } => {
            format!("Module started: {module:?}")
        }
        AuditEventType::FindingRecorded {
            finding_id,
            vulnerability_class,
        } => {
            format!("Finding #{finding_id}: {vulnerability_class}")
        }
        AuditEventType::ScanCompleted { total_findings } => {
            format!("Scan completed: {total_findings} findings")
        }
        AuditEventType::KeyEvent { description } => {
            format!("Key event: {description}")
        }
        AuditEventType::ConfigChange {
            key,
            old_value,
            new_value,
        } => {
            format!("Config changed: {key} ({old_value} -> {new_value})")
        }
    }
}

/// Compare two snapshots and return the differences.
///
/// Findings are compared by `finding_id`; modules, config changes, and
/// key events are compared by position (items in `after` beyond the
/// length of `before` are considered new).
pub fn diff_snapshots(before: &ScanSnapshot, after: &ScanSnapshot) -> SnapshotDiff {
    let before_finding_ids: HashSet<u64> = before.findings.iter().map(|f| f.finding_id).collect();
    let new_findings = after
        .findings
        .iter()
        .filter(|f| !before_finding_ids.contains(&f.finding_id))
        .cloned()
        .collect();

    let before_modules: HashSet<&str> = before.active_modules.iter().map(String::as_str).collect();
    let new_modules = after
        .active_modules
        .iter()
        .filter(|m| !before_modules.contains(m.as_str()))
        .cloned()
        .collect();

    let new_config_changes = after
        .config_changes
        .iter()
        .skip(before.config_changes.len())
        .cloned()
        .collect();

    let new_key_events = after
        .key_events
        .iter()
        .skip(before.key_events.len())
        .cloned()
        .collect();

    SnapshotDiff {
        new_findings,
        new_modules,
        new_config_changes,
        new_key_events,
    }
}
