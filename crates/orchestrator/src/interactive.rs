use serde::Serialize;

/// Commands that can be issued during an interactive scan session.
///
/// Parsed from user input via `parse_command()`. Each variant maps to a
/// specific control action: pause/resume fuzzing, inspect state, adjust
/// priorities, or abort the scan.
#[derive(Debug, Clone)]
pub enum InteractiveCommand {
    Pause,
    Resume,
    Status,
    ListFindings,
    ListEndpoints,
    AdjustPriority { endpoint: String, boost: f64 },
    SkipPhase,
    Quit,
}

impl PartialEq for InteractiveCommand {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Pause, Self::Pause)
            | (Self::Resume, Self::Resume)
            | (Self::Status, Self::Status)
            | (Self::ListFindings, Self::ListFindings)
            | (Self::ListEndpoints, Self::ListEndpoints)
            | (Self::SkipPhase, Self::SkipPhase)
            | (Self::Quit, Self::Quit) => true,
            (
                Self::AdjustPriority {
                    endpoint: e1,
                    boost: b1,
                },
                Self::AdjustPriority {
                    endpoint: e2,
                    boost: b2,
                },
            ) => e1 == e2 && b1.to_bits() == b2.to_bits(),
            _ => false,
        }
    }
}

impl Eq for InteractiveCommand {}

/// Snapshot of the current scan state, returned in response to a `Status` command.
#[derive(Debug, Clone, Serialize)]
pub struct ScanStatus {
    pub current_phase: String,
    pub is_paused: bool,
    pub findings_count: usize,
    pub endpoints_count: usize,
    pub elapsed_ms: u64,
    pub iterations_completed: u32,
}

/// Responses returned by `InteractiveSession::handle_command()`.
#[derive(Debug, Clone)]
pub enum InteractiveResponse {
    StatusReport(ScanStatus),
    FindingsList(Vec<FindingSummary>),
    EndpointsList(Vec<String>),
    Acknowledged(String),
    Error(String),
}

/// Compact representation of a finding for interactive display.
#[derive(Debug, Clone, Serialize)]
pub struct FindingSummary {
    pub id: u64,
    pub endpoint: String,
    pub vulnerability_class: String,
    pub severity: f64,
    pub confidence: f64,
}

/// Errors produced when parsing interactive command input.
#[derive(Debug)]
pub enum CommandParseError {
    UnknownCommand(String),
    MissingArgument(String),
    InvalidArgument(String),
}

impl std::fmt::Display for CommandParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownCommand(cmd) => write!(f, "unknown command: {cmd}"),
            Self::MissingArgument(msg) => write!(f, "missing argument: {msg}"),
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
        }
    }
}

impl std::error::Error for CommandParseError {}

/// Parses a user input string into an `InteractiveCommand`.
///
/// Recognised commands (case-insensitive, whitespace-trimmed):
/// - `pause`, `resume`, `status`, `findings`, `endpoints`, `skip`
/// - `priority <endpoint> <boost>` where boost is a finite f64
/// - `quit`, `exit`, `q`
pub fn parse_command(input: &str) -> Result<InteractiveCommand, CommandParseError> {
    let trimmed = input.trim();
    let lower = trimmed.to_ascii_lowercase();
    let parts: Vec<&str> = lower.split_whitespace().collect();

    if parts.is_empty() {
        return Err(CommandParseError::UnknownCommand(String::new()));
    }

    match parts[0] {
        "pause" => Ok(InteractiveCommand::Pause),
        "resume" => Ok(InteractiveCommand::Resume),
        "status" => Ok(InteractiveCommand::Status),
        "findings" => Ok(InteractiveCommand::ListFindings),
        "endpoints" => Ok(InteractiveCommand::ListEndpoints),
        "skip" => Ok(InteractiveCommand::SkipPhase),
        "quit" | "exit" | "q" => Ok(InteractiveCommand::Quit),
        "priority" => parse_priority_command(trimmed),
        other => Err(CommandParseError::UnknownCommand(other.to_string())),
    }
}

fn parse_priority_command(input: &str) -> Result<InteractiveCommand, CommandParseError> {
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(CommandParseError::MissingArgument(
            "priority requires <endpoint> <boost>".to_string(),
        ));
    }
    let endpoint = parts[1].to_string();
    let boost: f64 = parts[2].parse().map_err(|_| {
        CommandParseError::InvalidArgument(format!("boost must be a number, got '{}'", parts[2]))
    })?;
    if !boost.is_finite() {
        return Err(CommandParseError::InvalidArgument(
            "boost must be a finite number".to_string(),
        ));
    }
    Ok(InteractiveCommand::AdjustPriority { endpoint, boost })
}

/// Manages interactive scan session state.
///
/// Tracks pause/quit/skip flags, accumulated findings and endpoints,
/// priority adjustments, and current phase metadata. All state is
/// query-able and modifiable through the public API.
#[derive(Debug)]
pub struct InteractiveSession {
    paused: bool,
    quit: bool,
    skip_phase: bool,
    current_phase: String,
    elapsed_ms: u64,
    iterations_completed: u32,
    findings: Vec<FindingSummary>,
    endpoints: Vec<String>,
    priority_adjustments: Vec<(String, f64)>,
}

impl Default for InteractiveSession {
    fn default() -> Self {
        Self::new()
    }
}

impl InteractiveSession {
    pub fn new() -> Self {
        Self {
            paused: false,
            quit: false,
            skip_phase: false,
            current_phase: String::new(),
            elapsed_ms: 0,
            iterations_completed: 0,
            findings: Vec::new(),
            endpoints: Vec::new(),
            priority_adjustments: Vec::new(),
        }
    }

    /// Process an interactive command and return the appropriate response.
    pub fn handle_command(&mut self, cmd: &InteractiveCommand) -> InteractiveResponse {
        match cmd {
            InteractiveCommand::Pause => {
                self.paused = true;
                InteractiveResponse::Acknowledged("scan paused".to_string())
            }
            InteractiveCommand::Resume => {
                self.paused = false;
                InteractiveResponse::Acknowledged("scan resumed".to_string())
            }
            InteractiveCommand::Status => InteractiveResponse::StatusReport(self.current_status()),
            InteractiveCommand::ListFindings => {
                InteractiveResponse::FindingsList(self.findings.clone())
            }
            InteractiveCommand::ListEndpoints => {
                InteractiveResponse::EndpointsList(self.endpoints.clone())
            }
            InteractiveCommand::AdjustPriority { endpoint, boost } => {
                self.priority_adjustments.push((endpoint.clone(), *boost));
                InteractiveResponse::Acknowledged(format!(
                    "priority for {endpoint} adjusted by {boost}"
                ))
            }
            InteractiveCommand::SkipPhase => {
                self.skip_phase = true;
                InteractiveResponse::Acknowledged("current phase will be skipped".to_string())
            }
            InteractiveCommand::Quit => {
                self.quit = true;
                InteractiveResponse::Acknowledged("scan will terminate".to_string())
            }
        }
    }

    pub fn is_paused(&self) -> bool {
        self.paused
    }

    pub fn should_quit(&self) -> bool {
        self.quit
    }

    pub fn should_skip_phase(&self) -> bool {
        self.skip_phase
    }

    pub fn clear_skip_flag(&mut self) {
        self.skip_phase = false;
    }

    pub fn add_finding(&mut self, summary: FindingSummary) {
        self.findings.push(summary);
    }

    pub fn add_endpoint(&mut self, endpoint: String) {
        self.endpoints.push(endpoint);
    }

    pub fn set_current_phase(&mut self, phase: &str) {
        self.current_phase = phase.to_string();
    }

    pub fn set_elapsed_ms(&mut self, ms: u64) {
        self.elapsed_ms = ms;
    }

    pub fn set_iterations(&mut self, count: u32) {
        self.iterations_completed = count;
    }

    pub fn priority_adjustments(&self) -> &[(String, f64)] {
        &self.priority_adjustments
    }

    fn current_status(&self) -> ScanStatus {
        ScanStatus {
            current_phase: self.current_phase.clone(),
            is_paused: self.paused,
            findings_count: self.findings.len(),
            endpoints_count: self.endpoints.len(),
            elapsed_ms: self.elapsed_ms,
            iterations_completed: self.iterations_completed,
        }
    }
}

/// Format a `ScanStatus` as a human-readable multi-line string.
pub fn format_status(status: &ScanStatus) -> String {
    let paused_label = if status.is_paused { " [PAUSED]" } else { "" };
    format!(
        "Phase: {}{}\nFindings: {} | Endpoints: {} | Iterations: {} | Elapsed: {}ms",
        status.current_phase,
        paused_label,
        status.findings_count,
        status.endpoints_count,
        status.iterations_completed,
        status.elapsed_ms,
    )
}

/// Format a `FindingSummary` as a single human-readable line.
pub fn format_finding_summary(finding: &FindingSummary) -> String {
    format!(
        "[#{}] {} on {} (severity: {:.1}, confidence: {:.2})",
        finding.id,
        finding.vulnerability_class,
        finding.endpoint,
        finding.severity,
        finding.confidence,
    )
}
