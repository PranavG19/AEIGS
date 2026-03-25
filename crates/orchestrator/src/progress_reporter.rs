use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Current status of a scan module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
}

/// Progress snapshot for a single module.
#[derive(Debug, Clone)]
pub struct ModuleProgress {
    pub name: String,
    pub status: ModuleStatus,
    pub started_at: Option<Instant>,
    pub duration: Option<Duration>,
    pub findings_count: u64,
}

/// Overall scan progress snapshot for reporting.
#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub current_phase: String,
    pub phases_completed: u32,
    pub phases_total: u32,
    pub findings_so_far: u64,
    pub active_modules: Vec<String>,
    pub elapsed: Duration,
    pub estimated_remaining: Option<Duration>,
    pub percent_complete: f64,
    pub module_details: Vec<ModuleProgress>,
}

/// Output format for progress reports.
#[derive(Debug, Clone)]
pub enum ProgressOutput {
    Terminal(String),
    Json(String),
    Webhook { url: String, payload: String },
}

/// Tracks real-time scan progress across phases and modules.
///
/// Generates snapshots for terminal display, JSON for TUI consumption,
/// or webhook payloads for remote monitoring.
pub struct ProgressReporter {
    scan_start: Instant,
    phases_total: u32,
    phases_completed: u32,
    current_phase: String,
    findings_total: u64,
    modules: HashMap<String, ModuleProgress>,
    estimated_durations: HashMap<String, Duration>,
}

impl ProgressReporter {
    pub fn new(phases_total: u32) -> Self {
        Self {
            scan_start: Instant::now(),
            phases_total,
            phases_completed: 0,
            current_phase: "initializing".into(),
            findings_total: 0,
            modules: HashMap::new(),
            estimated_durations: HashMap::new(),
        }
    }

    /// Set estimated duration for a phase (used for ETA calculation).
    pub fn set_phase_estimate(&mut self, phase: &str, duration: Duration) {
        self.estimated_durations.insert(phase.to_string(), duration);
    }

    /// Mark a phase as started.
    pub fn begin_phase(&mut self, phase: &str) {
        self.current_phase = phase.to_string();
    }

    /// Mark a phase as completed.
    pub fn complete_phase(&mut self, phase: &str, findings: u64) {
        self.phases_completed += 1;
        self.findings_total += findings;
        if self.current_phase == phase {
            self.current_phase = if self.phases_completed >= self.phases_total {
                "done".into()
            } else {
                "transitioning".into()
            };
        }
    }

    /// Register a module as running.
    pub fn start_module(&mut self, name: &str) {
        self.modules.insert(
            name.to_string(),
            ModuleProgress {
                name: name.to_string(),
                status: ModuleStatus::Running,
                started_at: Some(Instant::now()),
                duration: None,
                findings_count: 0,
            },
        );
    }

    /// Mark a module as completed with its finding count.
    pub fn complete_module(&mut self, name: &str, findings: u64) {
        if let Some(m) = self.modules.get_mut(name) {
            m.status = ModuleStatus::Completed;
            m.findings_count = findings;
            if let Some(start) = m.started_at {
                m.duration = Some(start.elapsed());
            }
        }
    }

    /// Mark a module as failed.
    pub fn fail_module(&mut self, name: &str) {
        if let Some(m) = self.modules.get_mut(name) {
            m.status = ModuleStatus::Failed;
            if let Some(start) = m.started_at {
                m.duration = Some(start.elapsed());
            }
        }
    }

    /// Add findings to the running total.
    pub fn add_findings(&mut self, count: u64) {
        self.findings_total += count;
    }

    /// Take a snapshot of current progress.
    pub fn snapshot(&self) -> ScanProgress {
        let elapsed = self.scan_start.elapsed();
        let percent = if self.phases_total > 0 {
            (self.phases_completed as f64 / self.phases_total as f64) * 100.0
        } else {
            0.0
        };

        let active: Vec<String> = self
            .modules
            .values()
            .filter(|m| m.status == ModuleStatus::Running)
            .map(|m| m.name.clone())
            .collect();

        let estimated_remaining = self.estimate_remaining(elapsed);

        let mut details: Vec<ModuleProgress> = self.modules.values().cloned().collect();
        details.sort_by(|a, b| a.name.cmp(&b.name));

        ScanProgress {
            current_phase: self.current_phase.clone(),
            phases_completed: self.phases_completed,
            phases_total: self.phases_total,
            findings_so_far: self.findings_total,
            active_modules: active,
            elapsed,
            estimated_remaining,
            percent_complete: percent,
            module_details: details,
        }
    }

    /// Format progress for terminal display.
    pub fn format_terminal(&self) -> ProgressOutput {
        let snap = self.snapshot();
        let bar_width = 30;
        let filled = ((snap.percent_complete / 100.0) * bar_width as f64) as usize;
        let empty = bar_width - filled;
        let bar = format!(
            "[{}{}] {:.1}%",
            "#".repeat(filled),
            "-".repeat(empty),
            snap.percent_complete
        );

        let eta = snap
            .estimated_remaining
            .map(|d| format!("ETA: {}s", d.as_secs()))
            .unwrap_or_else(|| "ETA: --".into());

        let active = if snap.active_modules.is_empty() {
            "none".into()
        } else {
            snap.active_modules.join(", ")
        };

        let text = format!(
            "{bar} | Phase: {phase} ({done}/{total}) | Findings: {findings} | Active: {active} | {eta}",
            bar = bar,
            phase = snap.current_phase,
            done = snap.phases_completed,
            total = snap.phases_total,
            findings = snap.findings_so_far,
            active = active,
            eta = eta,
        );
        ProgressOutput::Terminal(text)
    }

    /// Format progress as JSON for TUI consumption.
    pub fn format_json(&self) -> ProgressOutput {
        let snap = self.snapshot();
        let json = format!(
            r#"{{"phase":"{}","phases_completed":{},"phases_total":{},"findings":{},"percent":{:.1},"elapsed_ms":{},"active_modules":[{}]}}"#,
            snap.current_phase,
            snap.phases_completed,
            snap.phases_total,
            snap.findings_so_far,
            snap.percent_complete,
            snap.elapsed.as_millis(),
            snap.active_modules
                .iter()
                .map(|m| format!("\"{}\"", m))
                .collect::<Vec<_>>()
                .join(","),
        );
        ProgressOutput::Json(json)
    }

    /// Format progress as a webhook payload.
    pub fn format_webhook(&self, webhook_url: &str) -> ProgressOutput {
        if let ProgressOutput::Json(payload) = self.format_json() {
            ProgressOutput::Webhook {
                url: webhook_url.to_string(),
                payload,
            }
        } else {
            unreachable!()
        }
    }

    fn estimate_remaining(&self, elapsed: Duration) -> Option<Duration> {
        if self.phases_completed == 0 || self.phases_completed >= self.phases_total {
            return None;
        }
        let avg_per_phase = elapsed.as_millis() / self.phases_completed as u128;
        let remaining_phases = self.phases_total - self.phases_completed;
        let remaining_ms = avg_per_phase * remaining_phases as u128;
        Some(Duration::from_millis(remaining_ms as u64))
    }
}
