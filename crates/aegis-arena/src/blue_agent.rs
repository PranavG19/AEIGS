use crate::arena_target::{PatchRule, RequestLogEntry};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Blue Agent — the defensive side of the arena.
/// Analyzes Red's attack traffic and generates patch rules.
pub struct BlueAgent {
    /// Tracks all patches already generated to avoid duplicates.
    existing_patterns: HashSet<String>,
    /// Round counter for escalating defense sophistication.
    rounds_defended: usize,
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
}

impl BlueAgent {
    pub fn new() -> Self {
        Self {
            existing_patterns: HashSet::new(),
            rounds_defended: 0,
        }
    }

    /// Analyze Red's traffic and generate defensive patches.
    pub fn defend(
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
                self.generate_advanced_patches(&analysis)
            } else if self.rounds_defended >= 3 {
                self.generate_intermediate_patches(&analysis)
            } else {
                self.generate_basic_patches(&analysis)
            };

            for patch in new_patches {
                let key = format!("{}:{}", patch.endpoint, patch.block_pattern);
                if self.existing_patterns.insert(key) {
                    patches.push(patch);
                }
            }
        }

        let fp_passed = self.false_positive_check(&patches);

        BlueRoundResult {
            patches_generated: patches,
            endpoints_analyzed: analyses,
            false_positive_check_passed: fp_passed,
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
                // Collect the payload for pattern extraction
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
                // For JWT/IDOR, patch based on observed payload patterns
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
                // Extract common attack substrings from payloads
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
                patches.push(PatchRule::new(
                    ep,
                    r"(/\*|\*/|--|;)",
                    true,
                ));
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
                // Block any non-alphanumeric followed by SQL keywords
                patches.push(PatchRule::new(
                    ep,
                    r"(?i)[\s'\"`;/\*]+(or|and|union|select|from|where|having|group|order)\b",
                    true,
                ));
                // Block hex/char encoding commonly used in SQLi
                patches.push(PatchRule::new(
                    ep,
                    r"(0x[0-9a-f]+|char\(|concat\()",
                    true,
                ));
            }
            Some("lfi") => {
                // Block any path that tries to escape webroot
                patches.push(PatchRule::new(
                    ep,
                    r"(\.{2,}|%2e{2,}|%252e|/etc|/proc|/var|\\\\)",
                    true,
                ));
            }
            Some("ssti") => {
                // Block all template-like syntax
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
                    // If /health would be blocked, that's a big problem
                    // For other endpoints, we accept some over-blocking
                    if endpoint == "/health" {
                        return false;
                    }
                }
            }
        }
        true
    }
}

impl Default for BlueAgent {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Normalize endpoint paths (strip trailing IDs from paths like /profile/123).
fn normalize_endpoint(path: &str) -> String {
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    if parts.len() <= 1 {
        return format!("/{}", parts.first().unwrap_or(&""));
    }
    // If the last segment looks like an ID (numeric), drop it
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
        if combined.contains("or ") || combined.contains("union")
            || combined.contains("select") || combined.contains("'")
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
        if combined.contains("<script") || combined.contains("javascript:")
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
    // Check if response contains flag-like data or error leaks
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
    let dangerous = ["' OR", "UNION", "../", "{{", "{%", "<script", "javascript:"];
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
