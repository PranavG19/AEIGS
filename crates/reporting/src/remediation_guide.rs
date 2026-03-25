use aegis_protocol::finding::VulnerabilityClass;
use serde::Serialize;

use crate::sarif_emitter::{SarifFinding, SarifLevel};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum FixEffort {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeFixSuggestion {
    pub tech_stack: String,
    pub description: String,
    pub code_example: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConfigChange {
    pub component: String,
    pub setting: String,
    pub recommended_value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WafRule {
    pub rule_type: String,
    pub pattern: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemediationEntry {
    pub rule_id: String,
    pub vulnerability_class: String,
    pub severity_rating: String,
    pub composite_score: f64,
    pub fix_effort: FixEffort,
    pub impact_reduction: f64,
    pub priority_rank: usize,
    pub code_fixes: Vec<CodeFixSuggestion>,
    pub config_changes: Vec<ConfigChange>,
    pub library_upgrades: Vec<String>,
    pub waf_rules: Vec<WafRule>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemediationGuide {
    pub entries: Vec<RemediationEntry>,
    pub total_findings: usize,
    pub estimated_risk_reduction: f64,
}

pub fn remediation_severity_rating(score: f64) -> &'static str {
    if score >= 70.0 {
        "Critical"
    } else if score >= 40.0 {
        "High"
    } else if score >= 20.0 {
        "Medium"
    } else {
        "Low"
    }
}

pub fn fix_effort_for(class: &VulnerabilityClass) -> FixEffort {
    match class {
        VulnerabilityClass::MissingSecurityHeader
        | VulnerabilityClass::OpenRedirect
        | VulnerabilityClass::Clickjacking
        | VulnerabilityClass::InformationDisclosure => FixEffort::Low,

        VulnerabilityClass::BrokenAuthentication
        | VulnerabilityClass::InsecureDeserialization
        | VulnerabilityClass::RaceCondition
        | VulnerabilityClass::HttpRequestSmuggling
        | VulnerabilityClass::PrototypePollution => FixEffort::High,

        _ => FixEffort::Medium,
    }
}

fn severity_weight(class: &VulnerabilityClass) -> f64 {
    match class {
        VulnerabilityClass::SqlInjection
        | VulnerabilityClass::CommandInjection
        | VulnerabilityClass::NoSqlInjection
        | VulnerabilityClass::ServerSideTemplateInjection
        | VulnerabilityClass::XmlExternalEntity
        | VulnerabilityClass::ServerSideRequestForgery
        | VulnerabilityClass::PathTraversal
        | VulnerabilityClass::CrlfInjection
        | VulnerabilityClass::HeaderInjection
        | VulnerabilityClass::CrossSiteScripting => 1.2,

        VulnerabilityClass::BrokenAuthentication
        | VulnerabilityClass::BrokenAuthorization
        | VulnerabilityClass::JwtVulnerability
        | VulnerabilityClass::InsecureDirectObjectReference => 1.1,

        VulnerabilityClass::SecurityMisconfiguration
        | VulnerabilityClass::CloudMisconfiguration
        | VulnerabilityClass::CrossOriginMisconfiguration => 0.9,

        VulnerabilityClass::MissingSecurityHeader
        | VulnerabilityClass::Clickjacking
        | VulnerabilityClass::InformationDisclosure
        | VulnerabilityClass::OpenRedirect => 0.8,

        _ => 1.0,
    }
}

pub fn impact_reduction_for(composite_score: f64, class: &VulnerabilityClass) -> f64 {
    let weighted = composite_score * severity_weight(class);
    weighted.clamp(0.0, 100.0)
}

pub fn code_fixes_for(class: &VulnerabilityClass) -> Vec<CodeFixSuggestion> {
    match class {
        VulnerabilityClass::SqlInjection => vec![
            CodeFixSuggestion {
                tech_stack: "Node.js/Express".to_string(),
                description: "Use parameterized queries with pg driver".to_string(),
                code_example: r#"const { rows } = await pool.query(
  'SELECT * FROM users WHERE id = $1 AND email = $2',
  [userId, email]
);"#
                .to_string(),
            },
            CodeFixSuggestion {
                tech_stack: "Python/Django".to_string(),
                description: "Use Django ORM or parameterized raw queries".to_string(),
                code_example: r#"# ORM (preferred)
users = User.objects.filter(id=user_id, email=email)

# Raw query with params
from django.db import connection
with connection.cursor() as cursor:
    cursor.execute(
        "SELECT * FROM users WHERE id = %s AND email = %s",
        [user_id, email]
    )"#
                .to_string(),
            },
            CodeFixSuggestion {
                tech_stack: "Java/Spring".to_string(),
                description: "Use JPA named parameters or JdbcTemplate".to_string(),
                code_example: r#"// JPA
@Query("SELECT u FROM User u WHERE u.id = :id AND u.email = :email")
List<User> findByIdAndEmail(@Param("id") Long id, @Param("email") String email);

// JdbcTemplate
jdbcTemplate.query(
    "SELECT * FROM users WHERE id = ? AND email = ?",
    new Object[]{userId, email},
    new BeanPropertyRowMapper<>(User.class)
);"#
                .to_string(),
            },
        ],
        VulnerabilityClass::CrossSiteScripting => vec![
            CodeFixSuggestion {
                tech_stack: "Node.js/Express".to_string(),
                description: "Use context-aware output encoding with DOMPurify".to_string(),
                code_example: r#"import DOMPurify from 'isomorphic-dompurify';

// Sanitize HTML content
const clean = DOMPurify.sanitize(userInput);

// For template engines, enable auto-escaping
app.set('view engine', 'ejs');
// Use <%- for raw, <%= for escaped (default safe)"#
                    .to_string(),
            },
            CodeFixSuggestion {
                tech_stack: "Python/Django".to_string(),
                description: "Django auto-escapes templates; use bleach for rich text".to_string(),
                code_example: r#"import bleach

# Django templates auto-escape by default: {{ user_input }}
# For rich text fields:
allowed_tags = ['p', 'b', 'i', 'em', 'strong', 'a']
allowed_attrs = {'a': ['href', 'title']}
clean_html = bleach.clean(
    user_input,
    tags=allowed_tags,
    attributes=allowed_attrs,
    strip=True
)"#
                .to_string(),
            },
            CodeFixSuggestion {
                tech_stack: "Java/Spring".to_string(),
                description: "Use OWASP Java Encoder for context-specific encoding".to_string(),
                code_example: r#"import org.owasp.encoder.Encode;

// HTML context
String safe = Encode.forHtml(userInput);

// JavaScript context
String jsafe = Encode.forJavaScript(userInput);

// URL parameter context
String urlSafe = Encode.forUriComponent(userInput);

// Thymeleaf auto-escapes with th:text (safe)
// Avoid th:utext unless input is sanitized"#
                    .to_string(),
            },
        ],
        VulnerabilityClass::CommandInjection => vec![
            CodeFixSuggestion {
                tech_stack: "Node.js/Express".to_string(),
                description: "Use execFile with argument array instead of shell exec".to_string(),
                code_example: r#"import { execFile } from 'node:child_process';

// WRONG: exec('ping ' + userInput)
// RIGHT: pass args as array, no shell interpolation
execFile('ping', ['-c', '4', hostname], (error, stdout) => {
  if (error) { return res.status(400).json({ error: 'command failed' }); }
  res.json({ output: stdout });
});"#
                    .to_string(),
            },
            CodeFixSuggestion {
                tech_stack: "Python/Django".to_string(),
                description: "Use subprocess with shell=False and argument list".to_string(),
                code_example: r#"import subprocess
import shlex

# WRONG: os.system(f"ping {user_input}")
# RIGHT: argument list, no shell
result = subprocess.run(
    ["ping", "-c", "4", hostname],
    capture_output=True,
    text=True,
    timeout=30,
    shell=False  # explicit, though False is default
)"#
                .to_string(),
            },
        ],
        VulnerabilityClass::PathTraversal => vec![
            CodeFixSuggestion {
                tech_stack: "Node.js/Express".to_string(),
                description: "Canonicalize and validate paths stay within base directory"
                    .to_string(),
                code_example: r#"import path from 'node:path';
import fs from 'node:fs';

const BASE_DIR = '/var/app/uploads';

function safePath(userPath) {
  const resolved = path.resolve(BASE_DIR, userPath);
  if (!resolved.startsWith(BASE_DIR + path.sep) && resolved !== BASE_DIR) {
    throw new Error('path traversal blocked');
  }
  return resolved;
}

app.get('/files/:name', (req, res) => {
  const filePath = safePath(req.params.name);
  res.sendFile(filePath);
});"#
                    .to_string(),
            },
            CodeFixSuggestion {
                tech_stack: "Python/Django".to_string(),
                description: "Use pathlib to resolve and constrain paths".to_string(),
                code_example: r#"from pathlib import Path

BASE_DIR = Path("/var/app/uploads").resolve()

def safe_path(user_path: str) -> Path:
    resolved = (BASE_DIR / user_path).resolve()
    if not str(resolved).startswith(str(BASE_DIR) + "/"):
        raise ValueError("path traversal blocked")
    return resolved"#
                    .to_string(),
            },
        ],
        VulnerabilityClass::BrokenAuthentication => vec![CodeFixSuggestion {
            tech_stack: "Node.js/Express".to_string(),
            description: "Implement secure session handling with express-session".to_string(),
            code_example: r#"import session from 'express-session';
import RedisStore from 'connect-redis';

app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,      // HTTPS only
    httpOnly: true,     // no JS access
    sameSite: 'strict', // CSRF protection
    maxAge: 30 * 60 * 1000 // 30 min
  }
}));"#
                .to_string(),
        }],
        _ => vec![CodeFixSuggestion {
            tech_stack: "General".to_string(),
            description: format!("Apply remediation for {}", class),
            code_example: format!(
                "// Refer to CWE and OWASP guidance for {}\n// See: https://cwe.mitre.org/",
                class
            ),
        }],
    }
}

pub fn config_changes_for(class: &VulnerabilityClass) -> Vec<ConfigChange> {
    match class {
        VulnerabilityClass::SecurityMisconfiguration => vec![
            ConfigChange {
                component: "Application Server".to_string(),
                setting: "debug_mode".to_string(),
                recommended_value: "false".to_string(),
            },
            ConfigChange {
                component: "HTTP Server".to_string(),
                setting: "server_tokens".to_string(),
                recommended_value: "off".to_string(),
            },
            ConfigChange {
                component: "HTTP Server".to_string(),
                setting: "X-Content-Type-Options".to_string(),
                recommended_value: "nosniff".to_string(),
            },
            ConfigChange {
                component: "Application Server".to_string(),
                setting: "directory_listing".to_string(),
                recommended_value: "disabled".to_string(),
            },
        ],
        VulnerabilityClass::MissingSecurityHeader => vec![
            ConfigChange {
                component: "HTTP Server".to_string(),
                setting: "Strict-Transport-Security".to_string(),
                recommended_value: "max-age=31536000; includeSubDomains; preload".to_string(),
            },
            ConfigChange {
                component: "HTTP Server".to_string(),
                setting: "Content-Security-Policy".to_string(),
                recommended_value: "default-src 'self'".to_string(),
            },
            ConfigChange {
                component: "HTTP Server".to_string(),
                setting: "X-Frame-Options".to_string(),
                recommended_value: "DENY".to_string(),
            },
        ],
        VulnerabilityClass::CrossOriginMisconfiguration => vec![ConfigChange {
            component: "HTTP Server".to_string(),
            setting: "Access-Control-Allow-Origin".to_string(),
            recommended_value: "https://trusted.example.com (specific origin, not *)".to_string(),
        }],
        VulnerabilityClass::CloudMisconfiguration => vec![
            ConfigChange {
                component: "IAM".to_string(),
                setting: "policy_scope".to_string(),
                recommended_value: "least-privilege per-service roles".to_string(),
            },
            ConfigChange {
                component: "Storage".to_string(),
                setting: "public_access".to_string(),
                recommended_value: "block_all".to_string(),
            },
        ],
        VulnerabilityClass::Clickjacking => vec![ConfigChange {
            component: "HTTP Server".to_string(),
            setting: "X-Frame-Options".to_string(),
            recommended_value: "DENY".to_string(),
        }],
        VulnerabilityClass::BrokenAuthentication => vec![
            ConfigChange {
                component: "Application".to_string(),
                setting: "session_timeout_minutes".to_string(),
                recommended_value: "30".to_string(),
            },
            ConfigChange {
                component: "Application".to_string(),
                setting: "mfa_enabled".to_string(),
                recommended_value: "true".to_string(),
            },
        ],
        VulnerabilityClass::SensitiveDataExposure => vec![ConfigChange {
            component: "HTTP Server".to_string(),
            setting: "Strict-Transport-Security".to_string(),
            recommended_value: "max-age=31536000; includeSubDomains".to_string(),
        }],
        _ => vec![],
    }
}

pub fn waf_rules_for(class: &VulnerabilityClass) -> Vec<WafRule> {
    match class {
        VulnerabilityClass::SqlInjection => vec![
            WafRule {
                rule_type: "regex_block".to_string(),
                pattern: r"(?i)\b(union\s+select|insert\s+into|delete\s+from|drop\s+table|;--)\b"
                    .to_string(),
                action: "block".to_string(),
            },
            WafRule {
                rule_type: "regex_block".to_string(),
                pattern: r"(?i)(\b(or|and)\b\s+\d+\s*=\s*\d+|'\s*(or|and)\s+')".to_string(),
                action: "block".to_string(),
            },
        ],
        VulnerabilityClass::CrossSiteScripting => vec![
            WafRule {
                rule_type: "regex_block".to_string(),
                pattern: r"<script[^>]*>.*?</script>".to_string(),
                action: "block".to_string(),
            },
            WafRule {
                rule_type: "regex_block".to_string(),
                pattern: r"(?i)(on(load|error|click|mouseover)\s*=|javascript:)".to_string(),
                action: "block".to_string(),
            },
        ],
        VulnerabilityClass::CommandInjection => vec![WafRule {
            rule_type: "regex_block".to_string(),
            pattern: r"[;&|`$]|\b(exec|system|passthru|popen)\b".to_string(),
            action: "block".to_string(),
        }],
        VulnerabilityClass::PathTraversal => vec![WafRule {
            rule_type: "regex_block".to_string(),
            pattern: r"(\.\.[\\/]|%2e%2e[\\/]|%252e%252e[\\/])".to_string(),
            action: "block".to_string(),
        }],
        VulnerabilityClass::NoSqlInjection => vec![WafRule {
            rule_type: "regex_block".to_string(),
            pattern: r#"(\$where|\$gt|\$lt|\$ne|\$regex|\$exists)"#.to_string(),
            action: "block".to_string(),
        }],
        VulnerabilityClass::XmlExternalEntity => vec![WafRule {
            rule_type: "regex_block".to_string(),
            pattern: r"(?i)(<!DOCTYPE|<!ENTITY|SYSTEM\s+)".to_string(),
            action: "block".to_string(),
        }],
        VulnerabilityClass::ServerSideTemplateInjection => vec![WafRule {
            rule_type: "regex_block".to_string(),
            pattern: r"(\{\{|\$\{|<%|#\{)".to_string(),
            action: "block".to_string(),
        }],
        VulnerabilityClass::ServerSideRequestForgery => vec![WafRule {
            rule_type: "regex_block".to_string(),
            pattern: r"(?i)(127\.0\.0\.1|localhost|0\.0\.0\.0|::1|169\.254\.)".to_string(),
            action: "block".to_string(),
        }],
        VulnerabilityClass::HeaderInjection | VulnerabilityClass::CrlfInjection => vec![WafRule {
            rule_type: "regex_block".to_string(),
            pattern: r"(%0d|%0a|\r|\n)".to_string(),
            action: "block".to_string(),
        }],
        _ => vec![],
    }
}

fn library_upgrades_for(class: &VulnerabilityClass) -> Vec<String> {
    match class {
        VulnerabilityClass::KnownVulnerableDependency => {
            vec!["Run dependency audit (npm audit / pip-audit / mvn dependency-check) and upgrade flagged packages".to_string()]
        }
        VulnerabilityClass::WeakCryptography => {
            vec!["Upgrade to a library supporting AES-256-GCM or ChaCha20-Poly1305".to_string()]
        }
        VulnerabilityClass::InsecureDeserialization => {
            vec!["Replace native deserialization with a safe format (JSON) or use a hardened library".to_string()]
        }
        _ => vec![],
    }
}

fn effort_rank(effort: FixEffort) -> u8 {
    match effort {
        FixEffort::Low => 0,
        FixEffort::Medium => 1,
        FixEffort::High => 2,
    }
}

fn description_for(finding: &SarifFinding, class: &VulnerabilityClass) -> String {
    let level_str = match finding.level {
        SarifLevel::Error => "error",
        SarifLevel::Warning => "warning",
        SarifLevel::Note => "note",
        SarifLevel::None => "info",
    };
    format!(
        "{} ({level_str}): {}. Remediate by applying fixes for {} (composite score {:.1}).",
        finding.rule_id, finding.message, class, finding.composite_score
    )
}

pub fn generate_remediation_guide(findings: &[SarifFinding]) -> RemediationGuide {
    if findings.is_empty() {
        return RemediationGuide {
            entries: vec![],
            total_findings: 0,
            estimated_risk_reduction: 0.0,
        };
    }

    let mut entries: Vec<RemediationEntry> = findings
        .iter()
        .map(|f| {
            let class = f
                .vulnerability_class
                .unwrap_or(VulnerabilityClass::InsufficientInputValidation);
            let effort = fix_effort_for(&class);
            let impact = impact_reduction_for(f.composite_score, &class);

            RemediationEntry {
                rule_id: f.rule_id.clone(),
                vulnerability_class: format!("{}", class),
                severity_rating: remediation_severity_rating(f.composite_score).to_string(),
                composite_score: f.composite_score,
                fix_effort: effort,
                impact_reduction: impact,
                priority_rank: 0,
                code_fixes: code_fixes_for(&class),
                config_changes: config_changes_for(&class),
                library_upgrades: library_upgrades_for(&class),
                waf_rules: waf_rules_for(&class),
                description: description_for(f, &class),
            }
        })
        .collect();

    entries.sort_by(|a, b| {
        let effort_cmp = effort_rank(a.fix_effort).cmp(&effort_rank(b.fix_effort));
        let impact_cmp = b
            .impact_reduction
            .partial_cmp(&a.impact_reduction)
            .unwrap_or(std::cmp::Ordering::Equal);
        let score_cmp = b
            .composite_score
            .partial_cmp(&a.composite_score)
            .unwrap_or(std::cmp::Ordering::Equal);
        impact_cmp.then(effort_cmp).then(score_cmp)
    });

    for (i, entry) in entries.iter_mut().enumerate() {
        entry.priority_rank = i + 1;
    }

    let total_impact: f64 = entries.iter().map(|e| e.impact_reduction).sum();
    let max_possible = entries.len() as f64 * 100.0;
    let risk_reduction = if max_possible > 0.0 {
        (total_impact / max_possible) * 100.0
    } else {
        0.0
    };

    RemediationGuide {
        entries,
        total_findings: findings.len(),
        estimated_risk_reduction: risk_reduction,
    }
}

pub fn remediation_guide_to_json(guide: &RemediationGuide) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(guide)
}
