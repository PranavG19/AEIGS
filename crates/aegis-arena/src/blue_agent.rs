use crate::arena_target::{PatchRule, RequestLogEntry};
use crate::red_agent::OpencodeRunner;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

/// HTTP exchange summary for blue agent briefings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpExchange {
    pub method: String,
    pub path: String,
    pub query_string: String,
    pub body: String,
    pub status: u16,
    pub response_snippet: String,
}

impl From<&RequestLogEntry> for HttpExchange {
    fn from(entry: &RequestLogEntry) -> Self {
        let snippet = if entry.response_body.len() > 200 {
            format!("{}...", &entry.response_body[..200])
        } else {
            entry.response_body.clone()
        };
        Self {
            method: entry.method.clone(),
            path: entry.path.clone(),
            query_string: entry.query_string.clone(),
            body: entry.body.clone(),
            status: entry.status,
            response_snippet: snippet,
        }
    }
}

/// Blue Agent — the defensive side of the arena.
/// Analyzes Red's attack traffic and generates patch rules.
pub struct BlueAgent {
    /// Tracks all patches already generated to avoid duplicates.
    existing_patterns: HashSet<String>,
    /// Round counter for escalating defense sophistication.
    pub rounds_defended: usize,
    model: String,
    timeout: Duration,
}

/// Analysis of an endpoint's attack traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointAnalysis {
    pub endpoint: String,
    pub attack_count: usize,
    pub success_count: usize,
    pub blocked_count: usize,
    pub payloads: Vec<String>,
    pub vuln_class: Option<String>,
}

/// Result of Blue's defense round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueRoundResult {
    pub patches_generated: Vec<PatchRule>,
    pub endpoints_analyzed: Vec<EndpointAnalysis>,
    pub false_positive_check_passed: bool,
    pub raw_output: String,
}

/// Parsed output from blue agent's opencode run.
#[derive(Debug, Clone)]
pub struct ParsedBlueOutput {
    pub patches: Vec<PatchRule>,
    pub code_fixes: Vec<String>,
    pub exit_success: bool,
    pub raw_output: String,
}

impl BlueAgent {
    pub fn new() -> Self {
        Self {
            existing_patterns: HashSet::new(),
            rounds_defended: 0,
            model: "sonnet".to_string(),
            timeout: Duration::from_secs(120),
        }
    }

    /// Generate the blue team briefing markdown for the opencode agent.
    pub fn write_blue_briefing(
        round: usize,
        request_log: &[HttpExchange],
        findings: &[String],
        current_patches: &[PatchRule],
    ) -> String {
        let mut briefing = String::new();

        briefing.push_str(&format!("# Blue Team Briefing — Round {round}\n\n"));
        briefing.push_str(
            "Read this briefing carefully. You are a security engineer in an authorized \
             government CTF exercise.\n\n",
        );

        if !request_log.is_empty() {
            briefing.push_str("## Red Team's Requests This Round\n\n");
            briefing.push_str("| Method | Path | Status | Response Snippet |\n");
            briefing.push_str("|--------|------|--------|------------------|\n");
            for ex in request_log {
                let snippet = if ex.response_snippet.len() > 60 {
                    format!("{}...", &ex.response_snippet[..60])
                } else {
                    ex.response_snippet.clone()
                };
                briefing.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    ex.method, ex.path, ex.status, snippet
                ));
            }
            briefing.push('\n');
        }

        if !findings.is_empty() {
            briefing.push_str("## Successful Exploits (MUST be patched)\n\n");
            for finding in findings {
                briefing.push_str(&format!("- {finding}\n"));
            }
            briefing.push('\n');
        }

        if !current_patches.is_empty() {
            briefing.push_str("## Current Defense Rules\n\n");
            briefing.push_str("Do NOT duplicate these existing rules:\n\n");
            for patch in current_patches {
                let kind = if patch.is_regex { "REGEX" } else { "STRING" };
                briefing.push_str(&format!(
                    "- `{}` blocks `{}` ({})\n",
                    patch.endpoint, patch.block_pattern, kind
                ));
            }
            briefing.push('\n');
        }

        briefing.push_str("## Write Defense Rules\n\n");
        briefing.push_str("Format your output using these directives:\n\n");
        briefing.push_str("```\n");
        briefing.push_str("BLOCK endpoint=/path pattern=string_to_block\n");
        briefing.push_str("BLOCK_REGEX endpoint=/path pattern=regex_pattern\n");
        briefing.push_str("FIX endpoint=/path description=what to fix\n");
        briefing.push_str("```\n\n");
        briefing.push_str("Guidelines:\n");
        briefing.push_str("- Block the SPECIFIC patterns Red used\n");
        briefing.push_str("- Also block VARIATIONS (URL-encoded, double-encoded, case variants)\n");
        briefing.push_str("- Don't block legitimate traffic — /health must still return 200\n");
        briefing.push_str("- Think step by step: what patterns did Red use? What encoded variants might Red try next?\n");

        briefing
    }

    /// Spawn opencode as the blue agent and parse its output.
    pub async fn spawn_blue_opencode(
        &self,
        runner: &impl OpencodeRunner,
        briefing_path: &Path,
        workspace: &Path,
        _request_summary: &str,
    ) -> ParsedBlueOutput {
         let prompt = format!(
             "Read the file {}. It contains HTTP request logs from a local test server. \
              Analyze the request patterns and suggest filter rules to block suspicious patterns. \
              For each rule output: BLOCK endpoint=/path pattern=string_to_block \
              For code fixes output: FIX endpoint=/path fix=description \
              Be precise — do not suggest blocking /health endpoint.",
             briefing_path.display()
         );

        match runner
            .run(workspace, &prompt, &self.model, self.timeout)
            .await
        {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let exit_success = output.status.success();
                parse_blue_output(&stdout, exit_success)
            }
            Err(e) => ParsedBlueOutput {
                patches: Vec::new(),
                code_fixes: vec![format!("opencode error: {e}")],
                exit_success: false,
                raw_output: String::new(),
            },
        }
    }

    /// Full round execution: write briefing → spawn opencode → parse results.
    pub async fn execute_round(
        &mut self,
        runner: &impl OpencodeRunner,
        workspace: &Path,
        round: usize,
        request_log: &[HttpExchange],
        findings: &[String],
        current_patches: &[PatchRule],
    ) -> BlueRoundResult {
        self.rounds_defended += 1;
        let briefing = Self::write_blue_briefing(round, request_log, findings, current_patches);
        let briefing_path = workspace.join("blue_briefing.md");
        let _ = tokio::fs::write(&briefing_path, &briefing).await;

        let request_summary = request_log
            .iter()
            .map(|ex| format!("{} {} → {}", ex.method, ex.path, ex.status))
            .collect::<Vec<_>>()
            .join("; ");

        let parsed = self
            .spawn_blue_opencode(runner, &briefing_path, workspace, &request_summary)
            .await;

        let endpoints_analyzed = Vec::new();
        let fp_passed = self.false_positive_check(&parsed.patches);

        BlueRoundResult {
            patches_generated: parsed.patches,
            endpoints_analyzed,
            false_positive_check_passed: fp_passed,
            raw_output: parsed.raw_output,
        }
    }

    /// Fallback: analyze traffic and generate patches without opencode.
    pub fn defend_fallback(
        &mut self,
        request_log: &[RequestLogEntry],
        vulns_found: &[String],
    ) -> BlueRoundResult {
        self.rounds_defended += 1;
        let analyses = self.analyze_traffic(request_log);
        let mut patches = Vec::new();

        for analysis in &analyses {
            if analysis.success_count == 0 && analysis.attack_count == 0 {
                continue;
            }

            let new_patches = if self.rounds_defended >= 5 {
                self.generate_advanced_patches(analysis)
            } else if self.rounds_defended >= 3 {
                self.generate_intermediate_patches(analysis)
            } else {
                self.generate_basic_patches(analysis)
            };

            for patch in new_patches {
                let key = format!("{}:{}", patch.endpoint, patch.block_pattern);
                if self.existing_patterns.insert(key) {
                    patches.push(patch);
                }
            }
        }

        let fp_passed = self.false_positive_check(&patches);
        let _ = vulns_found; // used for context in opencode mode

        BlueRoundResult {
            patches_generated: patches,
            endpoints_analyzed: analyses,
            false_positive_check_passed: fp_passed,
            raw_output: String::new(),
        }
    }

    /// Analyze attack traffic by endpoint.
    fn analyze_traffic(&self, log: &[RequestLogEntry]) -> Vec<EndpointAnalysis> {
        let mut by_endpoint: HashMap<String, EndpointAnalysis> = HashMap::new();

        for entry in log {
            let endpoint = normalize_endpoint(&entry.path);
            let analysis = by_endpoint
                .entry(endpoint.clone())
                .or_insert_with(|| EndpointAnalysis {
                    endpoint: endpoint.clone(),
                    attack_count: 0,
                    success_count: 0,
                    blocked_count: 0,
                    payloads: Vec::new(),
                    vuln_class: detect_vuln_class(&endpoint, &entry.query_string, &entry.body),
                });

            analysis.attack_count += 1;

            if entry.status == 403 {
                analysis.blocked_count += 1;
            } else if is_successful_attack(entry) {
                analysis.success_count += 1;
                let payload = if entry.query_string.is_empty() {
                    entry.body.clone()
                } else {
                    entry.query_string.clone()
                };
                if !payload.is_empty() {
                    analysis.payloads.push(payload);
                }
            }
        }

        by_endpoint.into_values().collect()
    }

    /// Basic patches: simple string matching on known attack patterns.
    fn generate_basic_patches(&self, analysis: &EndpointAnalysis) -> Vec<PatchRule> {
        let mut patches = Vec::new();
        let ep = &analysis.endpoint;

        match analysis.vuln_class.as_deref() {
            Some("sqli") => {
                patches.push(PatchRule::new(ep, "OR ", false));
                patches.push(PatchRule::new(ep, "UNION ", false));
                patches.push(PatchRule::new(ep, "'", false));
                patches.push(PatchRule::new(ep, "--", false));
            }
            Some("lfi") => {
                patches.push(PatchRule::new(ep, "..", false));
                patches.push(PatchRule::new(ep, "/etc/", false));
            }
            Some("ssti") => {
                patches.push(PatchRule::new(ep, "{{", false));
                patches.push(PatchRule::new(ep, "{%", false));
            }
            Some("jwt") | Some("idor") => {
                for payload in &analysis.payloads {
                    if payload.contains("none") {
                        patches.push(PatchRule::new(ep, "none", false));
                    }
                    if payload.contains("admin") {
                        patches.push(PatchRule::new(ep, "admin", false));
                    }
                }
            }
            Some("xss") => {
                patches.push(PatchRule::new(ep, "<script", false));
                patches.push(PatchRule::new(ep, "javascript:", false));
                patches.push(PatchRule::new(ep, "onerror", false));
            }
            _ => {
                for payload in &analysis.payloads {
                    if let Some(pattern) = extract_attack_pattern(payload) {
                        patches.push(PatchRule::new(ep, &pattern, false));
                    }
                }
            }
        }

        patches
    }

    /// Intermediate patches: regex-based broader blocking.
    fn generate_intermediate_patches(&self, analysis: &EndpointAnalysis) -> Vec<PatchRule> {
        let mut patches = self.generate_basic_patches(analysis);
        let ep = &analysis.endpoint;

        match analysis.vuln_class.as_deref() {
            Some("sqli") => {
                patches.push(PatchRule::new(
                    ep,
                    r"(?i)(union|select|insert|drop|delete|update|or|and)\s",
                    true,
                ));
                patches.push(PatchRule::new(ep, r"(/\*|\*/|--|;)", true));
            }
            Some("lfi") => {
                patches.push(PatchRule::new(
                    ep,
                    r"(\.\.|%2e%2e|%252e|/etc/|/proc/|%00)",
                    true,
                ));
            }
            Some("ssti") => {
                patches.push(PatchRule::new(
                    ep,
                    r"(\{\{|\{%|%7b%7b|\\u007b)",
                    true,
                ));
            }
            Some("xss") => {
                patches.push(PatchRule::new(
                    ep,
                    r"(?i)(<script|javascript:|on\w+=|<img|<svg|<iframe)",
                    true,
                ));
            }
            _ => {}
        }

        patches
    }

    /// Advanced patches: comprehensive regex covering evasion techniques.
    fn generate_advanced_patches(&self, analysis: &EndpointAnalysis) -> Vec<PatchRule> {
        let mut patches = self.generate_intermediate_patches(analysis);
        let ep = &analysis.endpoint;

        match analysis.vuln_class.as_deref() {
            Some("sqli") => {
                patches.push(PatchRule::new(
                    ep,
                    r#"(?i)[\s'"`;/\*]+(or|and|union|select|from|where|having|group|order)\b"#,
                    true,
                ));
                patches.push(PatchRule::new(ep, r"(0x[0-9a-f]+|char\(|concat\()", true));
            }
            Some("lfi") => {
                patches.push(PatchRule::new(
                    ep,
                    r"(\.{2,}|%2e{2,}|%252e|/etc|/proc|/var|\\\\)",
                    true,
                ));
            }
            Some("ssti") => {
                patches.push(PatchRule::new(
                    ep,
                    r"(\{[\{%]|__\w+__|class|import|eval|exec|system|subprocess|popen)",
                    true,
                ));
            }
            _ => {}
        }

        patches
    }

    /// Verify patches don't create false positives on normal traffic.
    fn false_positive_check(&self, patches: &[PatchRule]) -> bool {
        let normal_requests = vec![
            ("/search", "q=running+shoes"),
            ("/file", "path=readme.txt"),
            ("/health", ""),
            ("/profile", ""),
        ];

        for (endpoint, query) in normal_requests {
            let full = format!("{endpoint}?{query}");
            for patch in patches {
                if patch.matches(endpoint, &full) {
                    if endpoint == "/health" {
                        return false;
                    }
                }
            }
        }
        true
    }
}

/// Parameters for generating the infinite-mode blue team prompt.
pub struct InfiniteBlueBriefingParams<'a> {
    pub cycle: usize,
    pub total_blocks: usize,
    pub times_bypassed: usize,
    pub ban_list: &'a str,
    pub remaining_ban_budget: usize,
    pub last_attack_details: &'a str,
    pub history_summary: &'a str,
    pub lessons: &'a str,
    pub capabilities: Vec<String>,
    pub safety_rules: &'a str,
}

/// Generate the infinite-mode blue team briefing.
pub fn write_infinite_blue_briefing(params: &InfiniteBlueBriefingParams) -> String {
    let mut b = String::new();

    b.push_str(&format!("# Blue Team — INFINITE MODE — Cycle {}\n\n", params.cycle));
    b.push_str("You are the permanent defender. You run forever. The red team WILL adapt to every defense.\n\n");
    b.push_str(&format!(
        "This is cycle **{}**. You have blocked **{}** attacks. Red has bypassed you **{}** times.\n\n",
        params.cycle, params.total_blocks, params.times_bypassed,
    ));

    // Active bans
    if !params.ban_list.is_empty() {
        b.push_str("### Your Active Bans\n\n");
        b.push_str(params.ban_list);
        b.push_str(&format!(
            "\n**Budget:** {}/3 new bans this cycle\n\n",
            params.remaining_ban_budget,
        ));
    }

    // Last attack details
    if !params.last_attack_details.is_empty() {
        b.push_str("### Red's Last Attack\n\n");
        b.push_str(params.last_attack_details);
        b.push('\n');
    }

    b.push_str("## Directives\n\n");
    b.push_str("1. Analyze Red's PATTERN, not just the specific payload\n");
    b.push_str("2. Write bans that catch the CATEGORY of attack, not just the exact string\n");
    b.push_str("3. Consider encoding variants Red will try next cycle\n");
    b.push_str("4. Don't waste bans on attacks that aren't working (Red will change approach anyway)\n");
    b.push_str("5. NEVER ban patterns that match /health — that costs you 20 points\n\n");
    b.push_str("Your patches are PERMANENT — they accumulate. Make each one count.\n");
    b.push_str("Think about what Red will try NEXT, not what Red tried LAST.\n\n");

    if !params.capabilities.is_empty() {
        b.push_str("### Unlocked Capabilities\n\n");
        for cap in &params.capabilities {
            b.push_str(&format!("- {cap}\n"));
        }
        b.push('\n');
    }

    // History
    if !params.history_summary.is_empty() {
        b.push_str("## Recent History\n\n");
        b.push_str(params.history_summary);
        b.push('\n');
    }

    // Lessons
    if !params.lessons.is_empty() {
        b.push_str("## Lessons\n\n");
        b.push_str(params.lessons);
        b.push('\n');
    }

    // Safety rules
    if !params.safety_rules.is_empty() {
        b.push_str(&format!("\n---\n{}\n", params.safety_rules));
    }

    b.push_str("\n## Write Defense Rules\n\n");
    b.push_str("Format your output using these directives:\n");
    b.push_str("```\n");
    b.push_str("BLOCK endpoint=/path pattern=string_to_block\n");
    b.push_str("BLOCK_REGEX endpoint=/path pattern=regex_pattern\n");
    b.push_str("BAN type=IP|UA|Timing|TLS|ReqPattern pattern=value confidence=0.9\n");
    b.push_str("```\n");

    b
}

impl Default for BlueAgent {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Output parsing ─────────────────────────────────────────────────────────

/// Parse the raw stdout from an opencode blue agent run.
pub fn parse_blue_output(output: &str, exit_success: bool) -> ParsedBlueOutput {
    let mut patches = Vec::new();
    let mut code_fixes = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();

        if let Some(rest) = trimmed.strip_prefix("BLOCK_REGEX ") {
            if let Some(patch) = parse_block_directive(rest, true) {
                patches.push(patch);
            }
        } else if let Some(rest) = trimmed.strip_prefix("BLOCK ") {
            if let Some(patch) = parse_block_directive(rest, false) {
                patches.push(patch);
            }
        } else if let Some(rest) = trimmed.strip_prefix("FIX ") {
            if let Some(desc) = parse_fix_directive(rest) {
                code_fixes.push(desc);
            }
        }
    }

    ParsedBlueOutput {
        patches,
        code_fixes,
        exit_success,
        raw_output: output.to_string(),
    }
}

/// Parse a BLOCK/BLOCK_REGEX directive line.
fn parse_block_directive(rest: &str, is_regex: bool) -> Option<PatchRule> {
    let mut endpoint = None;
    let mut pattern = None;

    let parts: Vec<&str> = rest.splitn(2, "pattern=").collect();
    if parts.len() == 2 {
        let ep_part = parts[0].trim();
        let pat_part = parts[1].trim();

        if let Some(ep) = ep_part.strip_prefix("endpoint=") {
            endpoint = Some(ep.trim().to_string());
        }

        // Strip surrounding quotes if present
        let clean_pattern = pat_part
            .trim_start_matches('\'')
            .trim_end_matches('\'')
            .trim_start_matches('"')
            .trim_end_matches('"')
            .to_string();
        pattern = Some(clean_pattern);
    }

    match (endpoint, pattern) {
        (Some(ep), Some(pat)) if !ep.is_empty() && !pat.is_empty() => {
            Some(PatchRule::new(&ep, &pat, is_regex))
        }
        _ => None,
    }
}

/// Parse a FIX directive line.
fn parse_fix_directive(rest: &str) -> Option<String> {
    // FIX endpoint=/path description=what to fix
    if let Some(desc_idx) = rest.find("description=") {
        let desc = rest[desc_idx + "description=".len()..].trim();
        if !desc.is_empty() {
            return Some(desc.to_string());
        }
    }
    None
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Normalize endpoint paths (strip trailing IDs from paths like /profile/123).
fn normalize_endpoint(path: &str) -> String {
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    if parts.len() <= 1 {
        return format!("/{}", parts.first().unwrap_or(&""));
    }
    let last = parts.last().unwrap_or(&"");
    if last.chars().all(|c| c.is_ascii_digit()) {
        format!("/{}", parts[..parts.len() - 1].join("/"))
    } else {
        format!("/{}", parts.join("/"))
    }
}

/// Detect vulnerability class from endpoint and payload.
fn detect_vuln_class(endpoint: &str, query: &str, body: &str) -> Option<String> {
    let combined = format!("{endpoint} {query} {body}").to_lowercase();

    if endpoint.contains("search") || endpoint.contains("login") {
        if combined.contains("or ")
            || combined.contains("union")
            || combined.contains("select")
            || combined.contains("'")
            || combined.contains("--")
        {
            return Some("sqli".to_string());
        }
    }

    if endpoint.contains("file") {
        if combined.contains("..") || combined.contains("/etc") || combined.contains("passwd") {
            return Some("lfi".to_string());
        }
    }

    if endpoint.contains("template") {
        if combined.contains("{{") || combined.contains("{%") || combined.contains("config") {
            return Some("ssti".to_string());
        }
    }

    if endpoint.contains("admin") || endpoint.contains("flag") {
        return Some("jwt".to_string());
    }

    if endpoint.contains("profile") {
        return Some("idor".to_string());
    }

    if endpoint.contains("comment") {
        if combined.contains("<script")
            || combined.contains("javascript:")
            || combined.contains("onerror")
        {
            return Some("xss".to_string());
        }
    }

    None
}

/// Check if a request log entry indicates a successful attack.
fn is_successful_attack(entry: &RequestLogEntry) -> bool {
    if entry.status == 403 {
        return false;
    }
    entry.response_body.contains("CTF{")
        || entry.response_body.contains("SQL Error")
        || entry.response_body.contains("root:x:0")
        || entry.response_body.contains("Rendered:")
        || entry.response_body.contains("Admin Control Panel")
        || (entry.response_body.contains("authenticated")
            && entry.response_body.contains("true"))
}

/// Extract an attack pattern from a payload string.
fn extract_attack_pattern(payload: &str) -> Option<String> {
    let dangerous = [
        "' OR", "UNION", "../", "{{", "{%", "<script", "javascript:",
    ];
    for pattern in dangerous {
        if payload.to_uppercase().contains(&pattern.to_uppercase()) {
            return Some(pattern.to_string());
        }
    }
    None
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "blue_agent_test.rs"]
mod blue_agent_test;
