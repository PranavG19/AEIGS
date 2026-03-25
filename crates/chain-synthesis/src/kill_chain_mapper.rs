use std::collections::HashMap;
use std::fmt;

use crate::attack_graph::{AttackGraph, AttackNodeType};

/// Phases of the Lockheed Martin Cyber Kill Chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum KillChainPhase {
    Reconnaissance,
    Weaponization,
    Delivery,
    Exploitation,
    Installation,
    CommandAndControl,
    ActionsOnObjectives,
}

impl fmt::Display for KillChainPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Reconnaissance => "Reconnaissance",
            Self::Weaponization => "Weaponization",
            Self::Delivery => "Delivery",
            Self::Exploitation => "Exploitation",
            Self::Installation => "Installation",
            Self::CommandAndControl => "Command & Control",
            Self::ActionsOnObjectives => "Actions on Objectives",
        };
        write!(f, "{label}")
    }
}

/// All seven phases in order for iteration.
pub const KILL_CHAIN_PHASES: [KillChainPhase; 7] = [
    KillChainPhase::Reconnaissance,
    KillChainPhase::Weaponization,
    KillChainPhase::Delivery,
    KillChainPhase::Exploitation,
    KillChainPhase::Installation,
    KillChainPhase::CommandAndControl,
    KillChainPhase::ActionsOnObjectives,
];

/// A finding mapped to a Kill Chain phase with supporting context.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KillChainMapping {
    pub node_id: u64,
    pub label: String,
    pub phase: KillChainPhase,
    pub confidence: f64,
    pub rationale: String,
}

/// Summary of Kill Chain coverage showing which phases are achievable.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KillChainReport {
    pub mappings: Vec<KillChainMapping>,
    pub phase_coverage: HashMap<KillChainPhase, Vec<KillChainMapping>>,
    pub achievable_phases: Vec<KillChainPhase>,
    pub coverage_ratio: f64,
    pub longest_chain_length: usize,
}

/// Maps findings from an `AttackGraph` to Cyber Kill Chain phases.
///
/// Classification heuristic: entry points → Reconnaissance/Delivery,
/// vulnerabilities → Exploitation/Weaponization, security boundaries →
/// Installation/C2, assets → Actions on Objectives.
pub struct KillChainMapper<'a> {
    graph: &'a AttackGraph,
    custom_rules: Vec<Box<dyn Fn(&str, AttackNodeType) -> Option<KillChainPhase> + 'a>>,
}

impl<'a> KillChainMapper<'a> {
    pub fn new(graph: &'a AttackGraph) -> Self {
        Self {
            graph,
            custom_rules: Vec::new(),
        }
    }

    /// Add a custom classification rule evaluated before the default heuristic.
    pub fn add_rule(&mut self, rule: impl Fn(&str, AttackNodeType) -> Option<KillChainPhase> + 'a) {
        self.custom_rules.push(Box::new(rule));
    }

    /// Map all graph nodes to Kill Chain phases and produce a report.
    pub fn map(&self) -> KillChainReport {
        let mut mappings = Vec::new();

        let inner = self.graph.inner_graph();
        for node_idx in inner.node_indices() {
            let node = &inner[node_idx];
            let (phase, confidence, rationale) = self.classify(&node.label, node.node_type);
            mappings.push(KillChainMapping {
                node_id: node.id,
                label: node.label.clone(),
                phase,
                confidence,
                rationale,
            });
        }

        let mut phase_coverage: HashMap<KillChainPhase, Vec<KillChainMapping>> = HashMap::new();
        for m in &mappings {
            phase_coverage.entry(m.phase).or_default().push(m.clone());
        }

        let achievable: Vec<KillChainPhase> = KILL_CHAIN_PHASES
            .iter()
            .filter(|p| phase_coverage.contains_key(p))
            .copied()
            .collect();

        let coverage_ratio = achievable.len() as f64 / KILL_CHAIN_PHASES.len() as f64;

        let longest = self.longest_contiguous_chain(&achievable);

        KillChainReport {
            mappings,
            phase_coverage,
            achievable_phases: achievable,
            coverage_ratio,
            longest_chain_length: longest,
        }
    }

    fn classify(&self, label: &str, node_type: AttackNodeType) -> (KillChainPhase, f64, String) {
        for rule in &self.custom_rules {
            if let Some(phase) = rule(label, node_type) {
                return (phase, 0.9, "custom rule match".to_string());
            }
        }

        let label_lower = label.to_lowercase();

        if let Some((phase, rationale)) = self.keyword_match(&label_lower) {
            return (phase, 0.8, rationale);
        }

        let (phase, rationale) = match node_type {
            AttackNodeType::EntryPoint => {
                if label_lower.contains("scan") || label_lower.contains("enum") {
                    (
                        KillChainPhase::Reconnaissance,
                        "entry point with recon indicators",
                    )
                } else {
                    (
                        KillChainPhase::Delivery,
                        "entry point classified as delivery vector",
                    )
                }
            }
            AttackNodeType::Vulnerability => {
                if self.has_downstream_asset(label) {
                    (
                        KillChainPhase::Exploitation,
                        "vulnerability with path to asset",
                    )
                } else {
                    (
                        KillChainPhase::Weaponization,
                        "vulnerability without direct asset path",
                    )
                }
            }
            AttackNodeType::SecurityBoundary => (
                KillChainPhase::Installation,
                "security boundary indicates persistence layer",
            ),
            AttackNodeType::Asset => (
                KillChainPhase::ActionsOnObjectives,
                "asset node represents attacker objective",
            ),
        };

        (phase, 0.6, rationale.to_string())
    }

    fn keyword_match(&self, label: &str) -> Option<(KillChainPhase, String)> {
        let recon_keywords = [
            "recon",
            "scan",
            "enumerate",
            "discover",
            "fingerprint",
            "osint",
        ];
        let weapon_keywords = ["payload", "craft", "encode", "obfuscate", "weaponize"];
        let delivery_keywords = ["phish", "email", "upload", "inject", "deliver", "entry"];
        let exploit_keywords = [
            "exploit",
            "sqli",
            "xss",
            "rce",
            "ssrf",
            "lfi",
            "overflow",
            "deserializ",
        ];
        let install_keywords = [
            "persist", "backdoor", "implant", "rootkit", "webshell", "cron",
        ];
        let c2_keywords = [
            "c2",
            "beacon",
            "callback",
            "reverse shell",
            "command and control",
            "exfil",
        ];
        let action_keywords = [
            "dump",
            "extract",
            "credential",
            "database",
            "secret",
            "key",
            "token",
            "flag",
        ];

        for kw in &recon_keywords {
            if label.contains(kw) {
                return Some((
                    KillChainPhase::Reconnaissance,
                    format!("keyword match: '{kw}'"),
                ));
            }
        }
        for kw in &weapon_keywords {
            if label.contains(kw) {
                return Some((
                    KillChainPhase::Weaponization,
                    format!("keyword match: '{kw}'"),
                ));
            }
        }
        for kw in &delivery_keywords {
            if label.contains(kw) {
                return Some((KillChainPhase::Delivery, format!("keyword match: '{kw}'")));
            }
        }
        for kw in &exploit_keywords {
            if label.contains(kw) {
                return Some((
                    KillChainPhase::Exploitation,
                    format!("keyword match: '{kw}'"),
                ));
            }
        }
        for kw in &install_keywords {
            if label.contains(kw) {
                return Some((
                    KillChainPhase::Installation,
                    format!("keyword match: '{kw}'"),
                ));
            }
        }
        for kw in &c2_keywords {
            if label.contains(kw) {
                return Some((
                    KillChainPhase::CommandAndControl,
                    format!("keyword match: '{kw}'"),
                ));
            }
        }
        for kw in &action_keywords {
            if label.contains(kw) {
                return Some((
                    KillChainPhase::ActionsOnObjectives,
                    format!("keyword match: '{kw}'"),
                ));
            }
        }

        None
    }

    fn has_downstream_asset(&self, _label: &str) -> bool {
        // Simplified check: any vulnerability with outgoing edges likely has asset path
        true
    }

    fn longest_contiguous_chain(&self, achievable: &[KillChainPhase]) -> usize {
        if achievable.is_empty() {
            return 0;
        }

        let phase_set: std::collections::HashSet<KillChainPhase> =
            achievable.iter().copied().collect();

        let mut max_len = 0;
        let mut current_len = 0;

        for phase in &KILL_CHAIN_PHASES {
            if phase_set.contains(phase) {
                current_len += 1;
                if current_len > max_len {
                    max_len = current_len;
                }
            } else {
                current_len = 0;
            }
        }

        max_len
    }
}
