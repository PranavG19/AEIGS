use std::time::Instant;

use crate::event::TuiEvent;

/// Scan phases matching the AEGIS pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScanPhase {
    Recon,
    Crawl,
    Enumerate,
    Fuzz,
    Exploit,
    Chain,
    Report,
    Done,
}

impl ScanPhase {
    pub const ALL: [ScanPhase; 7] = [
        ScanPhase::Recon,
        ScanPhase::Crawl,
        ScanPhase::Enumerate,
        ScanPhase::Fuzz,
        ScanPhase::Exploit,
        ScanPhase::Chain,
        ScanPhase::Report,
    ];

    pub fn label(self) -> &'static str {
        match self {
            ScanPhase::Recon => "RECON",
            ScanPhase::Crawl => "CRAWL",
            ScanPhase::Enumerate => "ENUMERATE",
            ScanPhase::Fuzz => "FUZZ",
            ScanPhase::Exploit => "EXPLOIT",
            ScanPhase::Chain => "CHAIN",
            ScanPhase::Report => "REPORT",
            ScanPhase::Done => "DONE",
        }
    }

    pub fn index(self) -> usize {
        match self {
            ScanPhase::Recon => 0,
            ScanPhase::Crawl => 1,
            ScanPhase::Enumerate => 2,
            ScanPhase::Fuzz => 3,
            ScanPhase::Exploit => 4,
            ScanPhase::Chain => 5,
            ScanPhase::Report => 6,
            ScanPhase::Done => 7,
        }
    }
}

/// Severity level for discovered findings.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }

    #[allow(dead_code)]
    pub fn from_score(score: f64) -> Self {
        if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else if score >= 0.1 {
            Severity::Low
        } else {
            Severity::Info
        }
    }
}

/// A single finding discovered during the scan.
#[derive(Debug, Clone)]
pub struct Finding {
    pub id: u64,
    pub severity: Severity,
    pub vuln_type: String,
    pub endpoint: String,
    pub method: String,
    pub confidence: f64,
    pub discovered_at: Instant,
    pub description: String,
    pub evidence_request: String,
    pub evidence_response: String,
    pub curl_command: String,
    pub remediation: String,
    pub cvss_score: f64,
    pub cvss_vector: String,
    pub cwe_id: String,
    pub attack_technique: String,
}

/// A link in an attack chain.
#[derive(Debug, Clone)]
pub struct ChainNode {
    pub label: String,
    pub finding_id: u64,
}

/// An attack chain connecting multiple findings.
#[derive(Debug, Clone)]
pub struct AttackChain {
    pub nodes: Vec<ChainNode>,
    pub total_severity: f64,
}

/// An active module currently running.
#[derive(Debug, Clone)]
pub struct ActiveModule {
    pub name: String,
    pub spinner_tick: u8,
}

impl ActiveModule {
    pub fn spinner_char(&self) -> char {
        const FRAMES: &[char] = &['|', '/', '-', '\\'];
        FRAMES[self.spinner_tick as usize % FRAMES.len()]
    }

    pub fn tick(&mut self) {
        self.spinner_tick = self.spinner_tick.wrapping_add(1);
    }
}

/// Log entry with level information.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub level: LogLevel,
    pub message: String,
    pub elapsed_ms: u64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Which view is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveView {
    Dashboard,
    FindingDetail,
    Stats,
}

/// The scan profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanProfile {
    Quick,
    Standard,
    Deep,
    Stealth,
}

impl ScanProfile {
    pub fn label(self) -> &'static str {
        match self {
            ScanProfile::Quick => "QUICK",
            ScanProfile::Standard => "STANDARD",
            ScanProfile::Deep => "DEEP",
            ScanProfile::Stealth => "STEALTH",
        }
    }
}

impl std::str::FromStr for ScanProfile {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "quick" => Ok(ScanProfile::Quick),
            "standard" => Ok(ScanProfile::Standard),
            "deep" => Ok(ScanProfile::Deep),
            "stealth" => Ok(ScanProfile::Stealth),
            other => Err(format!("unknown profile: {other}")),
        }
    }
}

/// Top-level application state.
pub struct App {
    pub target_url: String,
    pub profile: ScanProfile,
    pub scan_start: Instant,
    pub current_phase: ScanPhase,
    pub phase_progress: [f64; 7],
    pub findings: Vec<Finding>,
    pub attack_chains: Vec<AttackChain>,
    pub active_modules: Vec<ActiveModule>,
    pub log_lines: Vec<LogEntry>,
    pub request_count: u64,
    pub endpoints_discovered: u64,
    pub endpoints_tested: u64,
    pub stealth_score: u8,
    pub active_view: ActiveView,
    pub selected_finding: usize,
    pub findings_scroll_offset: usize,
    #[allow(dead_code)]
    pub log_scroll_offset: usize,
    pub should_quit: bool,
    pub is_paused: bool,
    pub is_scan_complete: bool,
    pub risk_score: f64,
}

impl App {
    pub fn new(target_url: String, profile: ScanProfile) -> Self {
        Self {
            target_url,
            profile,
            scan_start: Instant::now(),
            current_phase: ScanPhase::Recon,
            phase_progress: [0.0; 7],
            findings: Vec::new(),
            attack_chains: Vec::new(),
            active_modules: Vec::new(),
            log_lines: Vec::new(),
            request_count: 0,
            endpoints_discovered: 0,
            endpoints_tested: 0,
            stealth_score: 95,
            active_view: ActiveView::Dashboard,
            selected_finding: 0,
            findings_scroll_offset: 0,
            log_scroll_offset: 0,
            should_quit: false,
            is_paused: false,
            is_scan_complete: false,
            risk_score: 0.0,
        }
    }

    /// Elapsed time since scan start.
    pub fn elapsed_secs(&self) -> u64 {
        self.scan_start.elapsed().as_secs()
    }

    /// Formatted elapsed time as MM:SS.
    pub fn elapsed_display(&self) -> String {
        let secs = self.elapsed_secs();
        format!("{:02}:{:02}", secs / 60, secs % 60)
    }

    /// Process an incoming TUI event and mutate state accordingly.
    pub fn apply_event(&mut self, event: TuiEvent) {
        match event {
            TuiEvent::PhaseChanged { phase, progress } => {
                self.current_phase = phase;
                if phase.index() < 7 {
                    self.phase_progress[phase.index()] = progress;
                }
            }
            TuiEvent::PhaseProgress { phase, progress } => {
                if phase.index() < 7 {
                    self.phase_progress[phase.index()] = progress;
                }
            }
            TuiEvent::EndpointDiscovered { endpoint, method } => {
                self.endpoints_discovered += 1;
                self.push_log(LogLevel::Info, format!("Discovered {method} {endpoint}"));
            }
            TuiEvent::FindingConfirmed(finding) => {
                self.push_log(
                    LogLevel::Warn,
                    format!(
                        "[{}] {} on {}",
                        finding.severity.label(),
                        finding.vuln_type,
                        finding.endpoint
                    ),
                );
                self.findings.push(*finding);
                self.findings.sort_by(|a, b| a.severity.cmp(&b.severity));
                self.recalculate_risk();
            }
            TuiEvent::ChainDiscovered(chain) => {
                let labels: Vec<&str> = chain.nodes.iter().map(|n| n.label.as_str()).collect();
                self.push_log(
                    LogLevel::Error,
                    format!("Attack chain: {}", labels.join(" -> ")),
                );
                self.attack_chains.push(chain);
            }
            TuiEvent::ModuleStarted { name } => {
                self.active_modules.push(ActiveModule {
                    name,
                    spinner_tick: 0,
                });
            }
            TuiEvent::ModuleStopped { name } => {
                self.active_modules.retain(|m| m.name != name);
            }
            TuiEvent::RequestMade => {
                self.request_count += 1;
            }
            TuiEvent::StealthUpdate { score } => {
                self.stealth_score = score;
            }
            TuiEvent::Log { level, message } => {
                self.push_log(level, message);
            }
            TuiEvent::ScanComplete => {
                self.is_scan_complete = true;
                self.current_phase = ScanPhase::Done;
                self.push_log(LogLevel::Info, "Scan complete.".to_string());
            }
            TuiEvent::Tick => {
                for module in &mut self.active_modules {
                    module.tick();
                }
            }
        }
    }

    fn push_log(&mut self, level: LogLevel, message: String) {
        let elapsed_ms = self.scan_start.elapsed().as_millis() as u64;
        self.log_lines.push(LogEntry {
            level,
            message,
            elapsed_ms,
        });
        if self.log_lines.len() > 500 {
            self.log_lines.drain(..self.log_lines.len() - 500);
        }
    }

    fn recalculate_risk(&mut self) {
        let mut score: f64 = 0.0;
        for f in &self.findings {
            score += match f.severity {
                Severity::Critical => 25.0,
                Severity::High => 15.0,
                Severity::Medium => 8.0,
                Severity::Low => 3.0,
                Severity::Info => 1.0,
            };
        }
        self.risk_score = score.min(100.0);
    }

    /// Total findings by severity.
    pub fn severity_counts(&self) -> [usize; 5] {
        let mut counts = [0usize; 5];
        for f in &self.findings {
            match f.severity {
                Severity::Critical => counts[0] += 1,
                Severity::High => counts[1] += 1,
                Severity::Medium => counts[2] += 1,
                Severity::Low => counts[3] += 1,
                Severity::Info => counts[4] += 1,
            }
        }
        counts
    }

    /// Risk grade letter.
    pub fn risk_grade(&self) -> &'static str {
        if self.risk_score >= 80.0 {
            "F"
        } else if self.risk_score >= 60.0 {
            "D"
        } else if self.risk_score >= 40.0 {
            "C"
        } else if self.risk_score >= 20.0 {
            "B"
        } else {
            "A"
        }
    }
}

#[cfg(test)]
#[path = "app_test.rs"]
mod app_test;
