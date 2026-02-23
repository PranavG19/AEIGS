use std::fmt;
use std::time::{Duration, Instant};

use aegis_protocol::target_validation::validate_target_is_localhost;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DEPTH_TIMEOUT: Duration = Duration::from_secs(6);
const DEPTH_SLOW_THRESHOLD: Duration = Duration::from_secs(5);

const BATCH_SIZE: usize = 50;
const DEPTH_LEVELS: usize = 15;
const ALIAS_COUNT: usize = 20;

const BATCHING_SEVERITY: f64 = 5.0;
const DEPTH_DOS_SEVERITY: f64 = 5.5;
const ALIAS_BRUTEFORCE_SEVERITY: f64 = 7.0;
const INTROSPECTION_SEVERITY: f64 = 3.0;
const FIELD_SUGGESTION_SEVERITY: f64 = 2.5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GraphQlAttack {
    BatchingAbuse,
    DepthDenialOfService,
    AliasBruteForce,
    IntrospectionEnabled,
    FieldSuggestionLeak,
}

impl GraphQlAttack {
    pub fn severity(self) -> f64 {
        match self {
            Self::BatchingAbuse => BATCHING_SEVERITY,
            Self::DepthDenialOfService => DEPTH_DOS_SEVERITY,
            Self::AliasBruteForce => ALIAS_BRUTEFORCE_SEVERITY,
            Self::IntrospectionEnabled => INTROSPECTION_SEVERITY,
            Self::FieldSuggestionLeak => FIELD_SUGGESTION_SEVERITY,
        }
    }
}

impl fmt::Display for GraphQlAttack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::BatchingAbuse => "batching-abuse",
            Self::DepthDenialOfService => "depth-denial-of-service",
            Self::AliasBruteForce => "alias-brute-force",
            Self::IntrospectionEnabled => "introspection-enabled",
            Self::FieldSuggestionLeak => "field-suggestion-leak",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone)]
pub struct GraphQlFinding {
    pub endpoint: String,
    pub attack_type: GraphQlAttack,
    pub severity: f64,
    pub evidence: String,
}

pub struct GraphQlTester {
    client: reqwest::blocking::Client,
    depth_client: reqwest::blocking::Client,
}

impl Default for GraphQlTester {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphQlTester {
    pub fn new() -> Self {
        Self {
            client: reqwest::blocking::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("failed to build HTTP client"),
            depth_client: reqwest::blocking::Client::builder()
                .timeout(DEPTH_TIMEOUT)
                .build()
                .expect("failed to build depth HTTP client"),
        }
    }

    pub fn with_client(client: reqwest::blocking::Client) -> Self {
        Self {
            depth_client: client.clone(),
            client,
        }
    }

    pub fn test_all(&self, endpoint: &str) -> Vec<GraphQlFinding> {
        if validate_target_is_localhost(endpoint).is_err() {
            return Vec::new();
        }

        let mut findings = Vec::new();
        if let Some(f) = self.test_batching(endpoint) {
            findings.push(f);
        }
        if let Some(f) = self.test_depth(endpoint) {
            findings.push(f);
        }
        if let Some(f) = self.test_alias_bruteforce(endpoint) {
            findings.push(f);
        }
        if let Some(f) = self.test_introspection(endpoint) {
            findings.push(f);
        }
        if let Some(f) = self.test_field_suggestion(endpoint) {
            findings.push(f);
        }
        findings
    }

    pub fn test_batching(&self, endpoint: &str) -> Option<GraphQlFinding> {
        if validate_target_is_localhost(endpoint).is_err() {
            return None;
        }

        let batch = build_batch_query(BATCH_SIZE);
        let resp = self
            .client
            .post(endpoint)
            .header("Content-Type", "application/json")
            .body(batch)
            .send()
            .ok()?;

        if resp.status().as_u16() != 200 {
            return None;
        }

        let body = resp.text().ok()?;
        let parsed: serde_json::Value = serde_json::from_str(&body).ok()?;
        let arr = parsed.as_array()?;

        if arr.len() != BATCH_SIZE {
            return None;
        }

        Some(GraphQlFinding {
            endpoint: endpoint.to_string(),
            attack_type: GraphQlAttack::BatchingAbuse,
            severity: GraphQlAttack::BatchingAbuse.severity(),
            evidence: format!(
                "Server accepted batched query of {BATCH_SIZE} operations and returned {BATCH_SIZE} results"
            ),
        })
    }

    pub fn test_depth(&self, endpoint: &str) -> Option<GraphQlFinding> {
        if validate_target_is_localhost(endpoint).is_err() {
            return None;
        }

        let query = build_depth_query(DEPTH_LEVELS);
        let payload = serde_json::json!({ "query": query }).to_string();

        let start = Instant::now();
        let result = self
            .depth_client
            .post(endpoint)
            .header("Content-Type", "application/json")
            .body(payload)
            .send();

        let elapsed = start.elapsed();

        if elapsed > DEPTH_SLOW_THRESHOLD {
            return Some(GraphQlFinding {
                endpoint: endpoint.to_string(),
                attack_type: GraphQlAttack::DepthDenialOfService,
                severity: GraphQlAttack::DepthDenialOfService.severity(),
                evidence: format!(
                    "Deeply nested query ({DEPTH_LEVELS} levels) took {:.1}s to process — no depth limit enforced",
                    elapsed.as_secs_f64()
                ),
            });
        }

        let resp = result.ok()?;
        if resp.status().as_u16() != 200 {
            return None;
        }

        let body = resp.text().ok()?;
        let parsed: serde_json::Value = serde_json::from_str(&body).ok()?;

        if parsed.get("data").is_some() && parsed.get("errors").is_none() {
            return Some(GraphQlFinding {
                endpoint: endpoint.to_string(),
                attack_type: GraphQlAttack::DepthDenialOfService,
                severity: GraphQlAttack::DepthDenialOfService.severity(),
                evidence: format!(
                    "Deeply nested query ({DEPTH_LEVELS} levels) returned 200 with data — no depth limit enforced"
                ),
            });
        }

        None
    }

    pub fn test_alias_bruteforce(&self, endpoint: &str) -> Option<GraphQlFinding> {
        if validate_target_is_localhost(endpoint).is_err() {
            return None;
        }

        let query = build_alias_query(ALIAS_COUNT);
        let payload = serde_json::json!({ "query": query }).to_string();

        let resp = self
            .client
            .post(endpoint)
            .header("Content-Type", "application/json")
            .body(payload)
            .send()
            .ok()?;

        if resp.status().as_u16() != 200 {
            return None;
        }

        let body = resp.text().ok()?;
        let parsed: serde_json::Value = serde_json::from_str(&body).ok()?;
        let data = parsed.get("data")?;

        let resolved = (1..=ALIAS_COUNT)
            .filter(|i| {
                let key = format!("a{i}");
                data.get(key.as_str()).is_some()
            })
            .count();

        if resolved == ALIAS_COUNT {
            return Some(GraphQlFinding {
                endpoint: endpoint.to_string(),
                attack_type: GraphQlAttack::AliasBruteForce,
                severity: GraphQlAttack::AliasBruteForce.severity(),
                evidence: format!(
                    "All {ALIAS_COUNT} aliases resolved — rate limiting bypass possible via query aliases"
                ),
            });
        }

        None
    }

    pub fn test_introspection(&self, endpoint: &str) -> Option<GraphQlFinding> {
        if validate_target_is_localhost(endpoint).is_err() {
            return None;
        }

        let query = r#"{ __schema { types { name } } }"#;
        let payload = serde_json::json!({ "query": query }).to_string();

        let resp = self
            .client
            .post(endpoint)
            .header("Content-Type", "application/json")
            .body(payload)
            .send()
            .ok()?;

        if resp.status().as_u16() != 200 {
            return None;
        }

        let body = resp.text().ok()?;
        let parsed: serde_json::Value = serde_json::from_str(&body).ok()?;
        let types = parsed
            .pointer("/data/__schema/types")
            .and_then(|v| v.as_array())?;

        let has_schema_type = types.iter().any(|t| {
            t.get("name")
                .and_then(|n| n.as_str())
                .is_some_and(|n| n == "__Schema")
        });

        if has_schema_type {
            return Some(GraphQlFinding {
                endpoint: endpoint.to_string(),
                attack_type: GraphQlAttack::IntrospectionEnabled,
                severity: GraphQlAttack::IntrospectionEnabled.severity(),
                evidence: format!(
                    "Introspection query returned __Schema type with {} types exposed",
                    types.len()
                ),
            });
        }

        None
    }

    pub fn test_field_suggestion(&self, endpoint: &str) -> Option<GraphQlFinding> {
        if validate_target_is_localhost(endpoint).is_err() {
            return None;
        }

        let query = r#"{ __typoname }"#;
        let payload = serde_json::json!({ "query": query }).to_string();

        let resp = self
            .client
            .post(endpoint)
            .header("Content-Type", "application/json")
            .body(payload)
            .send()
            .ok()?;

        let body = resp.text().ok()?;
        let parsed: serde_json::Value = serde_json::from_str(&body).ok()?;
        let errors = parsed.get("errors").and_then(|e| e.as_array())?;

        let suggestion = errors.iter().find_map(|e| {
            let msg = e.get("message")?.as_str()?;
            if msg.contains("Did you mean") {
                Some(msg.to_string())
            } else {
                None
            }
        })?;

        Some(GraphQlFinding {
            endpoint: endpoint.to_string(),
            attack_type: GraphQlAttack::FieldSuggestionLeak,
            severity: GraphQlAttack::FieldSuggestionLeak.severity(),
            evidence: format!("Error message leaks field names: {suggestion}"),
        })
    }
}

pub fn build_batch_query(count: usize) -> String {
    let item = r#"{"query":"{ __typename }"}"#;
    let items: Vec<&str> = (0..count).map(|_| item).collect();
    format!("[{}]", items.join(","))
}

pub fn build_depth_query(levels: usize) -> String {
    let mut query = String::from("{ ");
    for _ in 0..levels {
        query.push_str("a { ");
    }
    query.push_str("__typename");
    for _ in 0..levels {
        query.push_str(" }");
    }
    query.push_str(" }");
    query
}

pub fn build_alias_query(count: usize) -> String {
    let aliases: Vec<String> = (1..=count).map(|i| format!("a{i}: __typename")).collect();
    format!("{{ {} }}", aliases.join(", "))
}

#[cfg(test)]
#[path = "graphql_tester_test.rs"]
mod graphql_tester_test;
