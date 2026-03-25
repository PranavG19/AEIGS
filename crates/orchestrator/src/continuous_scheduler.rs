use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Days of the week for scheduling purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DayOfWeek {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

impl DayOfWeek {
    /// Returns the ISO 8601 day-of-week number (Monday = 1, Sunday = 7).
    pub fn iso_number(self) -> u8 {
        match self {
            DayOfWeek::Monday => 1,
            DayOfWeek::Tuesday => 2,
            DayOfWeek::Wednesday => 3,
            DayOfWeek::Thursday => 4,
            DayOfWeek::Friday => 5,
            DayOfWeek::Saturday => 6,
            DayOfWeek::Sunday => 7,
        }
    }

    /// Converts an ISO 8601 day number back to enum. Returns None for out-of-range.
    pub fn from_iso(n: u8) -> Option<Self> {
        match n {
            1 => Some(DayOfWeek::Monday),
            2 => Some(DayOfWeek::Tuesday),
            3 => Some(DayOfWeek::Wednesday),
            4 => Some(DayOfWeek::Thursday),
            5 => Some(DayOfWeek::Friday),
            6 => Some(DayOfWeek::Saturday),
            7 => Some(DayOfWeek::Sunday),
            _ => None,
        }
    }
}

/// Risk-level classification for scan targets, controlling default frequency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
}

impl RiskLevel {
    /// Default scan interval in seconds for this risk level.
    pub fn default_interval_secs(self) -> u64 {
        match self {
            RiskLevel::Critical => 3600, // 1 hour
            RiskLevel::High => 14400,    // 4 hours
            RiskLevel::Medium => 86400,  // 24 hours
            RiskLevel::Low => 604800,    // 7 days
        }
    }
}

/// Quiet-hours window preventing scans during off-peak or maintenance periods.
///
/// Times are expressed as hour-of-day (0–23) in the target's local timezone.
/// If `start_hour` > `end_hour`, the window wraps past midnight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuietHours {
    pub start_hour: u8,
    pub end_hour: u8,
    pub days: Vec<DayOfWeek>,
}

impl QuietHours {
    /// Returns true when the given hour and day fall inside the quiet window.
    pub fn is_quiet(&self, hour: u8, day: DayOfWeek) -> bool {
        if !self.days.contains(&day) {
            return false;
        }
        if self.start_hour <= self.end_hour {
            hour >= self.start_hour && hour < self.end_hour
        } else {
            hour >= self.start_hour || hour < self.end_hour
        }
    }
}

/// Bandwidth limits controlling concurrent scan throughput.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BandwidthLimits {
    pub max_requests_per_second: u32,
    pub max_concurrent_scans: u32,
    pub max_bandwidth_bytes_per_sec: u64,
}

impl Default for BandwidthLimits {
    fn default() -> Self {
        Self {
            max_requests_per_second: 50,
            max_concurrent_scans: 2,
            max_bandwidth_bytes_per_sec: 10_485_760, // 10 MB/s
        }
    }
}

/// Cron-like schedule specifying when scans run.
///
/// Supports a subset of cron fields: minute, hour, day-of-week.
/// Wildcards are represented by `None` (matching any value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CronSchedule {
    pub minutes: Option<Vec<u8>>,
    pub hours: Option<Vec<u8>>,
    pub days_of_week: Option<Vec<DayOfWeek>>,
}

impl CronSchedule {
    /// Checks whether the schedule matches the given minute, hour, and day.
    pub fn matches(&self, minute: u8, hour: u8, day: DayOfWeek) -> bool {
        let minute_ok = self
            .minutes
            .as_ref()
            .is_none_or(|mins| mins.contains(&minute));
        let hour_ok = self.hours.as_ref().is_none_or(|hrs| hrs.contains(&hour));
        let day_ok = self
            .days_of_week
            .as_ref()
            .is_none_or(|days| days.contains(&day));
        minute_ok && hour_ok && day_ok
    }
}

/// Scan mode controlling whether to test all endpoints or only changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanMode {
    Full,
    DiffOnly,
}

/// Configuration for a single scheduled scan target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledScan {
    pub target_url: String,
    pub scan_id: String,
    pub schedule: CronSchedule,
    pub risk_level: RiskLevel,
    pub mode: ScanMode,
    pub alert_on_new_findings: bool,
    pub quiet_hours: Option<QuietHours>,
    pub bandwidth_limits: BandwidthLimits,
    pub last_run_timestamp_ms: Option<u64>,
    pub enabled: bool,
}

/// Result of evaluating which scans are due at a given point in time.
#[derive(Debug, Clone)]
pub struct ScheduleEvaluation {
    pub due_scans: Vec<String>,
    pub skipped_quiet_hours: Vec<String>,
    pub skipped_bandwidth: Vec<String>,
    pub next_possible_window_secs: Option<u64>,
}

/// Manages a collection of scheduled scans and determines which are due.
pub struct ContinuousScheduler {
    scans: HashMap<String, ScheduledScan>,
    active_scan_count: u32,
}

impl ContinuousScheduler {
    pub fn new() -> Self {
        Self {
            scans: HashMap::new(),
            active_scan_count: 0,
        }
    }

    /// Registers a scheduled scan. Replaces any existing scan with the same ID.
    pub fn add_scan(&mut self, scan: ScheduledScan) {
        self.scans.insert(scan.scan_id.clone(), scan);
    }

    /// Removes a scan by ID. Returns the removed scan, if present.
    pub fn remove_scan(&mut self, scan_id: &str) -> Option<ScheduledScan> {
        self.scans.remove(scan_id)
    }

    /// Returns a reference to a registered scan by ID.
    pub fn get_scan(&self, scan_id: &str) -> Option<&ScheduledScan> {
        self.scans.get(scan_id)
    }

    /// Returns the number of registered scans.
    pub fn scan_count(&self) -> usize {
        self.scans.len()
    }

    /// Notifies the scheduler that a scan started.
    pub fn mark_scan_started(&mut self, scan_id: &str, timestamp_ms: u64) {
        self.active_scan_count = self.active_scan_count.saturating_add(1);
        if let Some(scan) = self.scans.get_mut(scan_id) {
            scan.last_run_timestamp_ms = Some(timestamp_ms);
        }
    }

    /// Notifies the scheduler that a scan completed (or failed).
    pub fn mark_scan_completed(&mut self) {
        self.active_scan_count = self.active_scan_count.saturating_sub(1);
    }

    /// Evaluates the schedule at the given wall-clock values and returns
    /// which scans are due, which were skipped, and the next window.
    pub fn evaluate(
        &self,
        current_timestamp_ms: u64,
        minute: u8,
        hour: u8,
        day: DayOfWeek,
    ) -> ScheduleEvaluation {
        let mut due = Vec::new();
        let mut skipped_quiet = Vec::new();
        let mut skipped_bw = Vec::new();

        for (id, scan) in &self.scans {
            if !scan.enabled {
                continue;
            }

            if !scan.schedule.matches(minute, hour, day) {
                continue;
            }

            if let Some(qh) = &scan.quiet_hours
                && qh.is_quiet(hour, day)
            {
                skipped_quiet.push(id.clone());
                continue;
            }

            if let Some(last) = scan.last_run_timestamp_ms {
                let interval_ms = scan.risk_level.default_interval_secs() * 1000;
                if current_timestamp_ms.saturating_sub(last) < interval_ms {
                    continue;
                }
            }

            if self.active_scan_count >= scan.bandwidth_limits.max_concurrent_scans {
                skipped_bw.push(id.clone());
                continue;
            }

            due.push(id.clone());
        }

        due.sort();
        skipped_quiet.sort();
        skipped_bw.sort();

        let next_window = if skipped_quiet.is_empty() {
            None
        } else {
            Some(3600)
        };

        ScheduleEvaluation {
            due_scans: due,
            skipped_quiet_hours: skipped_quiet,
            skipped_bandwidth: skipped_bw,
            next_possible_window_secs: next_window,
        }
    }

    /// Returns scan IDs sorted by risk level priority (Critical first).
    pub fn scans_by_priority(&self) -> Vec<String> {
        let mut entries: Vec<_> = self.scans.iter().filter(|(_, s)| s.enabled).collect();
        entries.sort_by(|a, b| {
            let priority = |r: RiskLevel| -> u8 {
                match r {
                    RiskLevel::Critical => 0,
                    RiskLevel::High => 1,
                    RiskLevel::Medium => 2,
                    RiskLevel::Low => 3,
                }
            };
            priority(a.1.risk_level)
                .cmp(&priority(b.1.risk_level))
                .then_with(|| a.0.cmp(b.0))
        });
        entries.into_iter().map(|(id, _)| id.clone()).collect()
    }

    /// Returns all scan IDs whose risk-level interval has elapsed since last run.
    pub fn overdue_scans(&self, current_timestamp_ms: u64) -> Vec<String> {
        let mut overdue = Vec::new();
        for (id, scan) in &self.scans {
            if !scan.enabled {
                continue;
            }
            let interval_ms = scan.risk_level.default_interval_secs() * 1000;
            let elapsed = match scan.last_run_timestamp_ms {
                Some(last) => current_timestamp_ms.saturating_sub(last),
                None => u64::MAX,
            };
            if elapsed >= interval_ms {
                overdue.push(id.clone());
            }
        }
        overdue.sort();
        overdue
    }
}

impl Default for ContinuousScheduler {
    fn default() -> Self {
        Self::new()
    }
}
