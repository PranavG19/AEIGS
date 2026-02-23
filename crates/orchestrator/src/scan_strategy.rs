use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Discovery technique that the strategy can recommend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryType {
    DirectoryBruteForce,
    ParameterDiscovery,
    JavaScriptAnalysis,
    VhostDiscovery,
}

impl std::fmt::Display for DiscoveryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirectoryBruteForce => write!(f, "Directory Brute Force"),
            Self::ParameterDiscovery => write!(f, "Parameter Discovery"),
            Self::JavaScriptAnalysis => write!(f, "JavaScript Analysis"),
            Self::VhostDiscovery => write!(f, "Virtual Host Discovery"),
        }
    }
}

/// Action recommended by the adaptive scan strategy engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StrategyAction {
    ContinueFuzzing {
        focus_classes: Vec<String>,
        focus_endpoints: Vec<String>,
    },
    RunExploitation {
        finding_id: u64,
        tool: String,
    },
    DiscoverMore {
        discovery_type: DiscoveryType,
    },
    DeepenAnalysis {
        vulnerability_class: String,
        technique: String,
    },
    GenerateReport,
}

/// Runtime scan state snapshot used by the strategy engine to decide next actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanState {
    pub target: String,
    pub tech_stack: Vec<String>,
    pub endpoints_discovered: usize,
    pub findings_count: usize,
    pub findings_by_severity: HashMap<String, usize>,
    pub phases_completed: Vec<String>,
    pub iterations_remaining: u32,
    pub defense_profile: String,
    pub last_iteration_new_findings: bool,
    pub consecutive_zero_finding_rounds: u32,
    pub exploitation_tools: Vec<String>,
    pub critical_finding_ids: Vec<u64>,
}

/// Rule-based adaptive scan strategy engine.
///
/// Analyzes current scan state and recommends the next action. Works without
/// an LLM — the rules are deterministic heuristics. Also generates structured
/// context strings for injection into LLM prompts when a backend is available.
pub struct ScanStrategy;

impl ScanStrategy {
    /// Evaluates scan state and returns the recommended next action.
    ///
    /// Rule priority (first match wins):
    /// 1. Few endpoints and directory brute-force not yet run -> discover more
    /// 2. Critical findings exist and exploitation tools available -> exploit
    /// 3. Iterations remain and last iteration productive -> continue fuzzing
    /// 4. No iterations left or two consecutive dry rounds -> report
    /// 5. Default: continue fuzzing with all classes
    pub fn suggest_next_action(state: &ScanState) -> StrategyAction {
        if Self::should_discover_more(state) {
            return StrategyAction::DiscoverMore {
                discovery_type: DiscoveryType::DirectoryBruteForce,
            };
        }

        if let Some(action) = Self::try_exploitation(state) {
            return action;
        }

        if Self::should_continue_fuzzing(state) {
            return Self::focused_fuzzing(state);
        }

        if Self::should_generate_report(state) {
            return StrategyAction::GenerateReport;
        }

        StrategyAction::ContinueFuzzing {
            focus_classes: Vec::new(),
            focus_endpoints: Vec::new(),
        }
    }

    fn should_discover_more(state: &ScanState) -> bool {
        state.endpoints_discovered < 10
            && !state
                .phases_completed
                .iter()
                .any(|p| p == "DirectoryBruteForce")
    }

    fn try_exploitation(state: &ScanState) -> Option<StrategyAction> {
        let has_critical = state
            .findings_by_severity
            .get("critical")
            .is_some_and(|&count| count > 0);

        if has_critical && !state.exploitation_tools.is_empty() {
            let finding_id = state.critical_finding_ids.first().copied().unwrap_or(0);
            let tool = state.exploitation_tools[0].clone();
            return Some(StrategyAction::RunExploitation { finding_id, tool });
        }
        None
    }

    fn should_continue_fuzzing(state: &ScanState) -> bool {
        state.iterations_remaining > 0 && state.last_iteration_new_findings
    }

    fn should_generate_report(state: &ScanState) -> bool {
        state.iterations_remaining == 0 || state.consecutive_zero_finding_rounds >= 2
    }

    fn focused_fuzzing(state: &ScanState) -> StrategyAction {
        let focus_classes: Vec<String> = state
            .findings_by_severity
            .iter()
            .filter(|(_, count)| **count > 0)
            .map(|(severity, _)| severity.clone())
            .collect();

        StrategyAction::ContinueFuzzing {
            focus_classes,
            focus_endpoints: Vec::new(),
        }
    }

    /// Formats scan state as XML context for LLM prompt injection.
    pub fn build_strategy_context(state: &ScanState) -> String {
        let tech = state.tech_stack.join(", ");
        let findings = Self::format_findings_xml(&state.findings_by_severity);

        format!(
            "<scan_state>\n\
             \x20   <target>{target}</target>\n\
             \x20   <technology>{tech}</technology>\n\
             \x20   <endpoints_discovered>{endpoints}</endpoints_discovered>\n\
             \x20   <findings>\n\
             {findings}\
             \x20   </findings>\n\
             \x20   <defenses>{defenses}</defenses>\n\
             \x20   <iterations_remaining>{remaining}</iterations_remaining>\n\
             </scan_state>",
            target = state.target,
            endpoints = state.endpoints_discovered,
            defenses = state.defense_profile,
            remaining = state.iterations_remaining,
        )
    }

    fn format_findings_xml(findings: &HashMap<String, usize>) -> String {
        let mut sorted: Vec<_> = findings.iter().collect();
        sorted.sort_by_key(|(k, _)| severity_sort_key(k));

        sorted
            .iter()
            .map(|(severity, count)| format!("        <{severity}>{count}</{severity}>\n"))
            .collect()
    }
}

fn severity_sort_key(severity: &str) -> u8 {
    match severity {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
    }
}
