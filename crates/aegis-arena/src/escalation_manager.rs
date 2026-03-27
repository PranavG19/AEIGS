use serde::{Deserialize, Serialize};

/// A vulnerable endpoint that can be added to the target during escalation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationEndpoint {
    /// URL path of the endpoint.
    pub path: String,
    /// Vulnerability class this endpoint exposes.
    pub vuln_class: String,
    /// Human-readable description.
    pub description: String,
    /// Cycle at which this endpoint was unlocked (0 = not yet unlocked).
    pub unlocked_at_cycle: usize,
}

/// A capability unlock for Red or Blue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityUnlock {
    /// Name of the capability.
    pub name: String,
    /// Description of what it enables.
    pub description: String,
    /// Cycle threshold at which this unlocks.
    pub unlock_cycle: usize,
    /// Whether this is for Red (true) or Blue (false).
    pub is_red: bool,
    /// Whether this has been unlocked yet.
    pub unlocked: bool,
}

/// Manages progressive difficulty escalation for infinite mode.
///
/// Every N cycles a new endpoint is added; every M cycles new capabilities unlock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationManager {
    /// Pool of endpoints waiting to be unlocked.
    pub endpoint_pool: Vec<EscalationEndpoint>,
    /// Index of the next endpoint to unlock from the pool.
    pub next_endpoint_index: usize,
    /// Capability unlocks for both Red and Blue.
    pub capabilities: Vec<CapabilityUnlock>,
    /// Currently active endpoint paths.
    pub active_endpoints: Vec<String>,
    /// Cycles between endpoint additions.
    pub endpoint_interval: usize,
    /// Cycles between capability unlocks.
    pub capability_interval: usize,
}

impl EscalationManager {
    /// Create a new escalation manager with the default endpoint and capability pools.
    pub fn new(endpoint_interval: usize, capability_interval: usize) -> Self {
        Self {
            endpoint_pool: default_endpoint_pool(),
            next_endpoint_index: 0,
            capabilities: default_capabilities(),
            active_endpoints: initial_endpoints(),
            endpoint_interval,
            capability_interval,
        }
    }

    /// Check and apply escalation for the given cycle.
    /// Returns a summary of what was unlocked.
    pub fn check_escalation(&mut self, cycle: usize) -> EscalationEvent {
        let mut event = EscalationEvent {
            cycle,
            new_endpoint: None,
            new_capabilities: Vec::new(),
        };

        // Endpoint escalation
        if self.endpoint_interval > 0 && cycle % self.endpoint_interval == 0 {
            if let Some(endpoint) = self.add_next_endpoint(cycle) {
                event.new_endpoint = Some(endpoint);
            }
        }

        // Capability escalation
        if self.capability_interval > 0 && cycle % self.capability_interval == 0 {
            let unlocked = self.unlock_capabilities_for_cycle(cycle);
            event.new_capabilities = unlocked;
        }

        event
    }

    /// Add the next endpoint from the pool to the active set.
    pub fn add_next_endpoint(&mut self, cycle: usize) -> Option<String> {
        if self.next_endpoint_index >= self.endpoint_pool.len() {
            return None;
        }

        let endpoint = &mut self.endpoint_pool[self.next_endpoint_index];
        endpoint.unlocked_at_cycle = cycle;
        let path = endpoint.path.clone();
        self.active_endpoints.push(path.clone());
        self.next_endpoint_index += 1;
        Some(path)
    }

    /// Unlock all capabilities scheduled for the given cycle.
    fn unlock_capabilities_for_cycle(&mut self, cycle: usize) -> Vec<String> {
        let mut unlocked = Vec::new();
        for cap in &mut self.capabilities {
            if !cap.unlocked && cap.unlock_cycle <= cycle {
                cap.unlocked = true;
                unlocked.push(cap.name.clone());
            }
        }
        unlocked
    }

    /// Get all currently unlocked Red capabilities.
    pub fn red_capabilities(&self) -> Vec<&CapabilityUnlock> {
        self.capabilities
            .iter()
            .filter(|c| c.is_red && c.unlocked)
            .collect()
    }

    /// Get all currently unlocked Blue capabilities.
    pub fn blue_capabilities(&self) -> Vec<&CapabilityUnlock> {
        self.capabilities
            .iter()
            .filter(|c| !c.is_red && c.unlocked)
            .collect()
    }

    /// Get all active endpoint paths.
    pub fn active_endpoint_paths(&self) -> &[String] {
        &self.active_endpoints
    }

    /// Count of endpoints added beyond the initial set.
    pub fn escalated_endpoint_count(&self) -> usize {
        self.next_endpoint_index
    }

    /// The current escalation level (number of times escalation triggered).
    pub fn escalation_level(&self) -> usize {
        let endpoint_level = self.next_endpoint_index;
        let cap_level = self.capabilities.iter().filter(|c| c.unlocked).count();
        endpoint_level + cap_level
    }

    /// Generate a briefing section describing current escalation state.
    pub fn escalation_briefing(&self) -> String {
        let mut briefing = String::new();
        briefing.push_str("### Escalation Status\n\n");
        briefing.push_str(&format!(
            "**Active endpoints:** {} ({} base + {} escalated)\n",
            self.active_endpoints.len(),
            initial_endpoints().len(),
            self.escalated_endpoint_count(),
        ));

        // Recently added endpoints
        let recent: Vec<_> = self
            .endpoint_pool
            .iter()
            .filter(|ep| ep.unlocked_at_cycle > 0)
            .collect();
        if !recent.is_empty() {
            briefing.push_str("\n**Escalated endpoints:**\n");
            for ep in recent {
                briefing.push_str(&format!(
                    "- `{}` — {} (unlocked cycle {})\n",
                    ep.path, ep.vuln_class, ep.unlocked_at_cycle
                ));
            }
        }

        // Unlocked capabilities
        let red_caps = self.red_capabilities();
        if !red_caps.is_empty() {
            briefing.push_str("\n**Red capabilities unlocked:**\n");
            for cap in &red_caps {
                briefing.push_str(&format!("- {} — {}\n", cap.name, cap.description));
            }
        }

        let blue_caps = self.blue_capabilities();
        if !blue_caps.is_empty() {
            briefing.push_str("\n**Blue capabilities unlocked:**\n");
            for cap in &blue_caps {
                briefing.push_str(&format!("- {} — {}\n", cap.name, cap.description));
            }
        }

        briefing.push('\n');
        briefing
    }

    /// Get new endpoints added since a given cycle (for Red's "new since last cycle" section).
    pub fn endpoints_since(&self, since_cycle: usize) -> Vec<&EscalationEndpoint> {
        self.endpoint_pool
            .iter()
            .filter(|ep| ep.unlocked_at_cycle > since_cycle)
            .collect()
    }
}

impl Default for EscalationManager {
    fn default() -> Self {
        Self::new(10, 25)
    }
}

/// Event describing what was unlocked during escalation.
#[derive(Debug, Clone)]
pub struct EscalationEvent {
    pub cycle: usize,
    pub new_endpoint: Option<String>,
    pub new_capabilities: Vec<String>,
}

impl EscalationEvent {
    /// Whether anything was unlocked this cycle.
    pub fn has_changes(&self) -> bool {
        self.new_endpoint.is_some() || !self.new_capabilities.is_empty()
    }
}

/// Initial 8 endpoints available from the start.
fn initial_endpoints() -> Vec<String> {
    vec![
        "/search".to_string(),
        "/file".to_string(),
        "/template".to_string(),
        "/admin".to_string(),
        "/profile".to_string(),
        "/login".to_string(),
        "/flag".to_string(),
        "/health".to_string(),
    ]
}

/// Pool of 20 additional vulnerable endpoints unlocked via escalation.
fn default_endpoint_pool() -> Vec<EscalationEndpoint> {
    vec![
        EscalationEndpoint {
            path: "/api/graphql".to_string(),
            vuln_class: "GraphQL Injection".to_string(),
            description: "GraphQL endpoint vulnerable to query depth attacks and injection".to_string(),
            unlocked_at_cycle: 0,
        },
        EscalationEndpoint {
            path: "/upload".to_string(),
            vuln_class: "File Upload".to_string(),
            description: "File upload with insufficient type validation — shell upload possible".to_string(),
            unlocked_at_cycle: 0,
        },
        EscalationEndpoint {
            path: "/webhook".to_string(),
            vuln_class: "SSRF".to_string(),
            description: "Webhook callback URL vulnerable to SSRF via user-controlled URL".to_string(),
            unlocked_at_cycle: 0,
        },
        EscalationEndpoint {
            path: "/export".to_string(),
            vuln_class: "CSV/PDF Injection".to_string(),
            description: "Export endpoint vulnerable to formula injection in CSV and PDF generation".to_string(),
            unlocked_at_cycle: 0,
        },
        EscalationEndpoint {
            path: "/reset-password".to_string(),
            vuln_class: "Token Prediction".to_string(),
            description: "Password reset with predictable token generation (timestamp-based)".to_string(),
            unlocked_at_cycle: 0,
        },
        EscalationEndpoint {
            path: "/2fa".to_string(),
            vuln_class: "MFA Bypass".to_string(),
            description: "Two-factor auth with brute-forceable 4-digit code and no rate limit".to_string(),
            unlocked_at_cycle: 0,
        },
        EscalationEndpoint {
            path: "/ws".to_string(),
            vuln_class: "WebSocket Injection".to_string(),
            description: "WebSocket endpoint with unvalidated message injection".to_string(),
            unlocked_at_cycle: 0,
        },
        EscalationEndpoint {
            path: "/grpc".to_string(),
            vuln_class: "gRPC Exploitation".to_string(),
            description: "gRPC service with reflection enabled and no auth on admin methods".to_string(),
            unlocked_at_cycle: 0,
        },
        EscalationEndpoint {
            path: "/api/v2/query".to_string(),
            vuln_class: "NoSQL Injection".to_string(),
            description: "MongoDB-style query endpoint vulnerable to operator injection".to_string(),
            unlocked_at_cycle: 0,
        },
        EscalationEndpoint {
            path: "/api/xml".to_string(),
            vuln_class: "XXE".to_string(),
            description: "XML parser with external entity processing enabled".to_string(),
            unlocked_at_cycle: 0,
        },
        EscalationEndpoint {
            path: "/redirect".to_string(),
            vuln_class: "Open Redirect".to_string(),
            description: "Unvalidated redirect parameter allowing phishing via trusted domain".to_string(),
            unlocked_at_cycle: 0,
        },
        EscalationEndpoint {
            path: "/api/deserialize".to_string(),
            vuln_class: "Insecure Deserialization".to_string(),
            description: "Accepts serialized objects without type verification".to_string(),
            unlocked_at_cycle: 0,
        },
        EscalationEndpoint {
            path: "/cors-proxy".to_string(),
            vuln_class: "CORS Misconfiguration".to_string(),
            description: "Reflects arbitrary Origin headers in Access-Control-Allow-Origin".to_string(),
            unlocked_at_cycle: 0,
        },
        EscalationEndpoint {
            path: "/api/cache".to_string(),
            vuln_class: "Cache Poisoning".to_string(),
            description: "CDN cache key ignores query parameters, enabling cache poisoning".to_string(),
            unlocked_at_cycle: 0,
        },
        EscalationEndpoint {
            path: "/api/oauth/callback".to_string(),
            vuln_class: "OAuth Flaw".to_string(),
            description: "OAuth callback without state parameter — CSRF on auth flow".to_string(),
            unlocked_at_cycle: 0,
        },
        EscalationEndpoint {
            path: "/api/pdf-gen".to_string(),
            vuln_class: "SSTI via PDF".to_string(),
            description: "PDF generation with user-controlled template data — server-side rendering".to_string(),
            unlocked_at_cycle: 0,
        },
        EscalationEndpoint {
            path: "/api/logs".to_string(),
            vuln_class: "Log Injection".to_string(),
            description: "Log viewer with unescaped user input — log forging and XSS".to_string(),
            unlocked_at_cycle: 0,
        },
        EscalationEndpoint {
            path: "/api/config".to_string(),
            vuln_class: "Info Disclosure".to_string(),
            description: "Config endpoint leaks database credentials and API keys in debug mode".to_string(),
            unlocked_at_cycle: 0,
        },
        EscalationEndpoint {
            path: "/api/cron".to_string(),
            vuln_class: "Command Injection".to_string(),
            description: "Cron job scheduler with unsanitized command field".to_string(),
            unlocked_at_cycle: 0,
        },
        EscalationEndpoint {
            path: "/api/import".to_string(),
            vuln_class: "RCE via Import".to_string(),
            description: "Data import with YAML deserialization — arbitrary code execution".to_string(),
            unlocked_at_cycle: 0,
        },
    ]
}

/// Default capability unlocks for Red and Blue.
fn default_capabilities() -> Vec<CapabilityUnlock> {
    vec![
        // Red capabilities
        CapabilityUnlock {
            name: "payload_obfuscation".to_string(),
            description: "URL encoding, Unicode normalization, comment injection in payloads".to_string(),
            unlock_cycle: 25,
            is_red: true,
            unlocked: false,
        },
        CapabilityUnlock {
            name: "waf_grammar_inference".to_string(),
            description: "Analyze WAF responses to infer blocking grammar and find bypasses".to_string(),
            unlock_cycle: 50,
            is_red: true,
            unlocked: false,
        },
        CapabilityUnlock {
            name: "llm_novel_payloads".to_string(),
            description: "LLM-powered generation of completely novel attack payloads".to_string(),
            unlock_cycle: 75,
            is_red: true,
            unlocked: false,
        },
        CapabilityUnlock {
            name: "multi_vector_chaining".to_string(),
            description: "Chain attacks across multiple endpoints simultaneously".to_string(),
            unlock_cycle: 100,
            is_red: true,
            unlocked: false,
        },
        // Blue capabilities
        CapabilityUnlock {
            name: "regex_bans".to_string(),
            description: "Regex-based ban patterns instead of just string matching".to_string(),
            unlock_cycle: 25,
            is_red: false,
            unlocked: false,
        },
        CapabilityUnlock {
            name: "rate_limiting".to_string(),
            description: "Per-identity rate limiting to throttle suspicious traffic".to_string(),
            unlock_cycle: 50,
            is_red: false,
            unlocked: false,
        },
        CapabilityUnlock {
            name: "behavioral_anomaly".to_string(),
            description: "Behavioral anomaly detection based on request timing and patterns".to_string(),
            unlock_cycle: 75,
            is_red: false,
            unlocked: false,
        },
        CapabilityUnlock {
            name: "ml_classification".to_string(),
            description: "ML-based request classification for automated threat detection".to_string(),
            unlock_cycle: 100,
            is_red: false,
            unlocked: false,
        },
    ]
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "escalation_manager_test.rs"]
mod escalation_manager_test;
