use std::fmt::Write as FmtWrite;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// The embedded default mission prompt (loaded from prompts/aegis_mind.md at compile time).
const DEFAULT_MISSION_PROMPT: &str = include_str!("../prompts/aegis_mind.md");

/// Configuration for assembling the complete AEGIS-MIND context window.
///
/// The final prompt sent to the LLM is:
/// `[system prompt] + [memory context] + [defense map] + [scan briefing]`
///
/// `max_context_tokens` controls the total token budget. Sections are
/// prioritized: system prompt > briefing > memory > defense map. Lower
/// priority sections are truncated first when the budget is exceeded.
#[derive(Debug, Clone)]
pub struct MindPromptConfig {
    pub persona: AgentPersona,
    pub methodology: Methodology,
    pub max_context_tokens: usize,
    pub include_memory_context: bool,
    pub include_defense_map: bool,
    pub include_tech_attack_patterns: bool,
    pub output_format: OutputFormatSpec,
    pub custom_instructions: Vec<String>,
}

impl Default for MindPromptConfig {
    fn default() -> Self {
        Self {
            persona: AgentPersona::RedTeamOperator,
            methodology: Methodology::OHPEL,
            max_context_tokens: 32000,
            include_memory_context: true,
            include_defense_map: true,
            include_tech_attack_patterns: true,
            output_format: OutputFormatSpec::StructuredJson,
            custom_instructions: Vec::new(),
        }
    }
}

/// The persona the LLM should adopt during reasoning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentPersona {
    RedTeamOperator,
    BugBountyHunter,
    ComplianceAuditor,
    PenetrationTester,
}

impl AgentPersona {
    fn description(&self) -> &'static str {
        match self {
            Self::RedTeamOperator => {
                "You are a world-class red team operator. Think adversarially. \
                 Assume every endpoint has a vulnerability until proven otherwise. \
                 Chain findings into attack graphs. Never accept 'not vulnerable' \
                 without exhausting encoding, evasion, and timing variations."
            }
            Self::BugBountyHunter => {
                "You are an elite bug bounty hunter targeting maximum impact per finding. \
                 Focus on unique, high-severity vulnerabilities that bypass existing defenses. \
                 Prioritize critical impact: RCE, auth bypass, data exfiltration."
            }
            Self::ComplianceAuditor => {
                "You are a thorough compliance auditor checking against OWASP Top 10 2021, \
                 PCI-DSS, and CWE standards. Systematically verify each control category. \
                 Document evidence level for every finding."
            }
            Self::PenetrationTester => {
                "You are a methodical penetration tester following OWASP WSTG methodology. \
                 Test every input vector systematically. Escalate from detection to exploitation \
                 to proof of impact. Maintain clean audit trail."
            }
        }
    }
}

impl std::fmt::Display for AgentPersona {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RedTeamOperator => write!(f, "Red Team Operator"),
            Self::BugBountyHunter => write!(f, "Bug Bounty Hunter"),
            Self::ComplianceAuditor => write!(f, "Compliance Auditor"),
            Self::PenetrationTester => write!(f, "Penetration Tester"),
        }
    }
}

/// The reasoning methodology the LLM should follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Methodology {
    /// Observe → Hypothesize → Plan → Execute → Learn
    OHPEL,
    /// Reconnaissance → Enumeration → Exploitation → Post-Exploitation
    REEP,
}

impl Methodology {
    fn steps(&self) -> Vec<&'static str> {
        match self {
            Self::OHPEL => vec![
                "OBSERVE: Read the briefing. Map endpoints, defenses, tech stack, existing findings.",
                "HYPOTHESIZE: Generate specific vulnerability hypotheses with confidence levels.",
                "PLAN: Prioritize hypotheses. Design payloads. Consider evasion requirements.",
                "EXECUTE: Specify exact payloads, encoding, headers for each test.",
                "LEARN: Analyze results. Update priors. Adapt strategy.",
            ],
            Self::REEP => vec![
                "RECON: Analyze discovered services, endpoints, technology stack.",
                "ENUMERATE: Identify input vectors, authentication flows, API schemas.",
                "EXPLOIT: Generate targeted payloads for confirmed attack surfaces.",
                "POST-EXPLOIT: Chain findings, pivot, escalate access.",
            ],
        }
    }
}

/// Expected output format from the LLM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormatSpec {
    StructuredJson,
    FreeformWithJson,
}

/// Context injected from cross-session memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryContext {
    pub historical_success_rates: Vec<(String, f64)>,
    pub known_bypasses: Vec<String>,
    pub stack_correlations: Vec<(String, String, f64)>,
}

/// The complete assembled prompt ready for submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssembledPrompt {
    pub system_prompt: String,
    pub user_prompt: String,
    pub total_token_estimate: usize,
    pub sections_included: Vec<String>,
}

/// Load the mission prompt from a file or fall back to the embedded default.
pub fn load_mission_prompt(path: Option<&Path>) -> Result<String, std::io::Error> {
    match path {
        Some(p) => std::fs::read_to_string(p),
        None => Ok(DEFAULT_MISSION_PROMPT.to_string()),
    }
}

/// Get the embedded default mission prompt.
pub fn default_mission_prompt() -> &'static str {
    DEFAULT_MISSION_PROMPT
}

/// Assemble the complete AEGIS-MIND prompt from components.
///
/// Combines: persona + methodology + knowledge base + output format +
/// custom instructions into the system prompt. The user prompt contains
/// the scan briefing + memory context + defense map.
pub fn assemble_prompt(
    config: &MindPromptConfig,
    scan_briefing: &str,
    memory_context: Option<&MemoryContext>,
    defense_map: Option<&str>,
) -> AssembledPrompt {
    let mut sections = Vec::new();

    let mut system = String::with_capacity(8192);

    // Persona section
    let _ = writeln!(system, "# AEGIS-MIND | {}", config.persona);
    let _ = writeln!(system);
    let _ = writeln!(system, "{}", config.persona.description());
    let _ = writeln!(system);
    sections.push("PERSONA".to_string());

    // Methodology section
    let _ = writeln!(system, "## Methodology: {:?}", config.methodology);
    for step in config.methodology.steps() {
        let _ = writeln!(system, "- {}", step);
    }
    let _ = writeln!(system);
    sections.push("METHODOLOGY".to_string());

    // Knowledge base (OWASP, CWE taxonomy, bypass techniques)
    let _ = write!(system, "{}", build_knowledge_section(config));
    sections.push("KNOWLEDGE".to_string());

    // Output format specification
    let _ = write!(
        system,
        "{}",
        build_output_format_section(&config.output_format)
    );
    sections.push("OUTPUT_FORMAT".to_string());

    // Behavioral rules
    let _ = write!(system, "{}", build_behavioral_rules());
    sections.push("BEHAVIORAL_RULES".to_string());

    // Custom instructions
    if !config.custom_instructions.is_empty() {
        let _ = writeln!(system, "## Additional Instructions");
        for inst in &config.custom_instructions {
            let _ = writeln!(system, "- {}", inst);
        }
        let _ = writeln!(system);
        sections.push("CUSTOM_INSTRUCTIONS".to_string());
    }

    // Build user prompt (briefing + context)
    let mut user = String::with_capacity(4096);

    if let Some(mem) = memory_context
        && config.include_memory_context
    {
        let _ = write!(user, "{}", format_memory_context(mem));
        sections.push("MEMORY_CONTEXT".to_string());
    }

    if let Some(dmap) = defense_map
        && config.include_defense_map
    {
        let _ = writeln!(user, "## DEFENSE MAP");
        let _ = writeln!(user, "{}", dmap);
        let _ = writeln!(user);
        sections.push("DEFENSE_MAP".to_string());
    }

    let _ = write!(user, "{}", scan_briefing);
    sections.push("SCAN_BRIEFING".to_string());

    let total_tokens = estimate_tokens(&system) + estimate_tokens(&user);

    AssembledPrompt {
        system_prompt: system,
        user_prompt: user,
        total_token_estimate: total_tokens,
        sections_included: sections,
    }
}

/// Build a standalone system prompt (without scan briefing) for testing.
pub fn build_system_prompt(config: &MindPromptConfig) -> String {
    let prompt = assemble_prompt(config, "", None, None);
    prompt.system_prompt
}

fn build_knowledge_section(config: &MindPromptConfig) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "## Knowledge Base");
    let _ = writeln!(s, "You have deep expertise in:");
    let _ = writeln!(s, "- OWASP Top 10 2021 and API Security Top 10 2023");
    let _ = writeln!(s, "- CWE taxonomy and CVE correlation");
    let _ = writeln!(
        s,
        "- WAF evasion: encoding chains, Unicode normalization, chunked encoding"
    );
    let _ = writeln!(
        s,
        "- Authentication bypass: JWT, OAuth 2.0, session management"
    );
    let _ = writeln!(
        s,
        "- Injection: SQL, NoSQL, LDAP, SSTI, command, expression languages"
    );
    let _ = writeln!(s, "- Client-side: XSS, DOM clobbering, prototype pollution");
    let _ = writeln!(
        s,
        "- Server-side: SSRF, request smuggling, deserialization, race conditions"
    );
    let _ = writeln!(s, "- Cloud: AWS/GCP/Azure misconfiguration, IAM escalation");
    let _ = writeln!(s);

    if config.include_tech_attack_patterns {
        let _ = writeln!(s, "## Tech Stack Attack Patterns");
        let _ = writeln!(
            s,
            "- Express/Node.js → prototype pollution, SSTI (EJS/Pug), event loop blocking"
        );
        let _ = writeln!(
            s,
            "- Django/Python → SSTI (Jinja2), ORM injection, pickle deserialization"
        );
        let _ = writeln!(
            s,
            "- Spring/Java → SpEL injection, deserialization, actuator endpoints"
        );
        let _ = writeln!(
            s,
            "- Laravel/PHP → SSTI (Blade), file upload RCE, mass assignment"
        );
        let _ = writeln!(
            s,
            "- GraphQL → introspection disclosure, batch query DoS, IDOR via node IDs"
        );
        let _ = writeln!(
            s,
            "- Nginx → alias traversal, off-by-slash, proxy_pass SSRF"
        );
        let _ = writeln!(
            s,
            "- Cloudflare WAF → Unicode normalization, chunked encoding, origin IP discovery"
        );
        let _ = writeln!(s);
    }

    s
}

fn build_output_format_section(format: &OutputFormatSpec) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "## Output Format");
    match format {
        OutputFormatSpec::StructuredJson => {
            let _ = writeln!(s, "You MUST respond with valid JSON matching this schema:");
            let _ = writeln!(s, "```json");
            let _ = writeln!(s, "{{");
            let _ = writeln!(s, "  \"hypotheses\": [{{");
            let _ = writeln!(s, "    \"endpoint\": \"/api/example\",");
            let _ = writeln!(s, "    \"vulnerability_class\": \"SQL Injection\",");
            let _ = writeln!(
                s,
                "    \"reasoning\": \"Why this vulnerability might exist...\","
            );
            let _ = writeln!(
                s,
                "    \"suggested_payloads\": [\"' OR 1=1--\", \"' UNION SELECT NULL--\"],"
            );
            let _ = writeln!(s, "    \"confidence\": 0.85,");
            let _ = writeln!(s, "    \"priority\": 1");
            let _ = writeln!(s, "  }}],");
            let _ = writeln!(s, "  \"actions\": [{{");
            let _ = writeln!(s, "    \"action_type\": \"fuzz\",");
            let _ = writeln!(s, "    \"target\": \"/api/v2/\",");
            let _ = writeln!(s, "    \"parameters\": {{}},");
            let _ = writeln!(s, "    \"rationale\": \"Reason for this action\"");
            let _ = writeln!(s, "  }}],");
            let _ = writeln!(
                s,
                "  \"reasoning_summary\": \"Brief assessment and strategy\""
            );
            let _ = writeln!(s, "}}");
            let _ = writeln!(s, "```");
        }
        OutputFormatSpec::FreeformWithJson => {
            let _ = writeln!(
                s,
                "Provide your analysis in natural language, then include a ```json``` block with structured hypotheses and actions."
            );
        }
    }
    let _ = writeln!(s);
    s
}

fn build_behavioral_rules() -> String {
    let mut s = String::new();
    let _ = writeln!(s, "## Behavioral Rules");
    let _ = writeln!(s, "1. Be aggressive. Find vulnerabilities, not excuses.");
    let _ = writeln!(
        s,
        "2. Be creative. Mutate, chain, and invent beyond standard payloads."
    );
    let _ = writeln!(
        s,
        "3. Be specific. Exact payloads, exact endpoints, exact encoding."
    );
    let _ = writeln!(
        s,
        "4. Be adaptive. If WAF blocks X, try Y with different evasion."
    );
    let _ = writeln!(
        s,
        "5. Chain everything. Single findings are starting points, not endpoints."
    );
    let _ = writeln!(s, "6. Never repeat failed attempts without a new angle.");
    let _ = writeln!(
        s,
        "7. Think about absence. Missing headers, no rate limiting, no CSRF tokens — absence is evidence."
    );
    let _ = writeln!(s);
    s
}

fn format_memory_context(mem: &MemoryContext) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "## CROSS-SESSION MEMORY");

    if !mem.historical_success_rates.is_empty() {
        let _ = writeln!(s, "### Historical Success Rates");
        for (class, rate) in &mem.historical_success_rates {
            let _ = writeln!(s, "- {}: {:.0}%", class, rate * 100.0);
        }
    }

    if !mem.known_bypasses.is_empty() {
        let _ = writeln!(s, "### Known Working Bypasses");
        for bypass in &mem.known_bypasses {
            let _ = writeln!(s, "- {}", bypass);
        }
    }

    if !mem.stack_correlations.is_empty() {
        let _ = writeln!(s, "### Stack → Vulnerability Correlations");
        for (stack, class, rate) in &mem.stack_correlations {
            let _ = writeln!(s, "- {} + {} → {:.0}% success", stack, class, rate * 100.0);
        }
    }

    let _ = writeln!(s);
    s
}

fn estimate_tokens(text: &str) -> usize {
    text.len() / 4
}

#[cfg(test)]
#[path = "aegis_mind_prompt_test.rs"]
mod aegis_mind_prompt_test;
