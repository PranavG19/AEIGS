use regex::Regex;
use std::collections::HashMap;

/// Severity of a discovered secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for SecretSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
            Self::Low => write!(f, "Low"),
            Self::Info => write!(f, "Info"),
        }
    }
}

/// Category of the leaked secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretCategory {
    ApiKey,
    Token,
    DatabaseCredential,
    CloudCredential,
    PrivateKey,
    InternalUrl,
    DebugEndpoint,
    PasswordPattern,
}

impl std::fmt::Display for SecretCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey => write!(f, "API Key"),
            Self::Token => write!(f, "Token"),
            Self::DatabaseCredential => write!(f, "Database Credential"),
            Self::CloudCredential => write!(f, "Cloud Credential"),
            Self::PrivateKey => write!(f, "Private Key"),
            Self::InternalUrl => write!(f, "Internal URL"),
            Self::DebugEndpoint => write!(f, "Debug Endpoint"),
            Self::PasswordPattern => write!(f, "Password Pattern"),
        }
    }
}

/// A single secret finding in scanned content.
#[derive(Debug, Clone)]
pub struct SecretFinding {
    pub pattern_name: String,
    pub category: SecretCategory,
    pub severity: SecretSeverity,
    pub matched_text: String,
    pub line_number: usize,
    pub entropy: Option<f64>,
    pub confidence: f64,
}

/// Definition of a secret pattern to scan for.
struct SecretPattern {
    name: &'static str,
    category: SecretCategory,
    severity: SecretSeverity,
    regex: Regex,
    entropy_threshold: Option<f64>,
    /// Index of the capture group holding the secret value for entropy checks.
    /// `None` means use the full match.
    secret_group: Option<usize>,
}

/// Compiled scanner holding all patterns and false-positive filters.
pub struct SecretScanner {
    patterns: Vec<SecretPattern>,
    fp_filters: Vec<Regex>,
}

/// Shannon entropy of a byte string.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<u8, usize> = HashMap::new();
    for &b in s.as_bytes() {
        *freq.entry(b).or_insert(0) += 1;
    }
    let len = s.len() as f64;
    freq.values().fold(0.0_f64, |acc, &count| {
        let p = count as f64 / len;
        acc - p * p.log2()
    })
}

/// Placeholder / example values that should not be flagged.
const FALSE_POSITIVE_PATTERNS: &[&str] = &[
    r"(?i)example\.com",
    r"(?i)placeholder",
    r"(?i)your[_-]?api[_-]?key",
    r"(?i)insert[_-]?token[_-]?here",
    r"(?i)xxxx+",
    r"(?i)test[_-]?key",
    r"(?i)dummy",
    r"(?i)changeme",
    r"(?i)TODO",
    r"(?i)<your[_-]",
    r"(?i)REPLACE_ME",
    r"(?i)fake[_-]?secret",
    r"(?i)sample[_-]?key",
    r"(?i)my[_-]?secret",
    r"(?i)secret[_-]?here",
    r"(?i)AKIAIOSFODNN7EXAMPLE",
    r"(?i)wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    r"\*{4,}",
    r"\.{4,}",
];

fn build_patterns() -> Vec<SecretPattern> {
    vec![
        // 1. AWS Access Key ID
        SecretPattern {
            name: "AWS Access Key ID",
            category: SecretCategory::ApiKey,
            severity: SecretSeverity::Critical,
            regex: Regex::new(r"(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)").unwrap(),
            entropy_threshold: None,
            secret_group: Some(1),
        },
        // 2. AWS Secret Access Key
        SecretPattern {
            name: "AWS Secret Access Key",
            category: SecretCategory::CloudCredential,
            severity: SecretSeverity::Critical,
            regex: Regex::new(r##"(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?"##).unwrap(),
            entropy_threshold: Some(4.0),
            secret_group: Some(1),
        },
        // 3. AWS STS Temporary Token
        SecretPattern {
            name: "AWS STS Session Token",
            category: SecretCategory::CloudCredential,
            severity: SecretSeverity::Critical,
            regex: Regex::new(r##"(?i)(?:aws_session_token|security_token)\s*[=:]\s*["']?([A-Za-z0-9/+=]{100,})["']?"##).unwrap(),
            entropy_threshold: Some(4.0),
            secret_group: Some(1),
        },
        // 4. GCP API Key
        SecretPattern {
            name: "GCP API Key",
            category: SecretCategory::ApiKey,
            severity: SecretSeverity::High,
            regex: Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap(),
            entropy_threshold: None,
            secret_group: None,
        },
        // 5. GCP Service Account JSON
        SecretPattern {
            name: "GCP Service Account JSON",
            category: SecretCategory::CloudCredential,
            severity: SecretSeverity::Critical,
            regex: Regex::new(r##""type"\s*:\s*"service_account""##).unwrap(),
            entropy_threshold: None,
            secret_group: None,
        },
        // 6. Azure Subscription Key
        SecretPattern {
            name: "Azure Subscription Key",
            category: SecretCategory::ApiKey,
            severity: SecretSeverity::High,
            regex: Regex::new(r##"(?i)(?:subscription[_-]?key|ocp-apim-subscription-key)\s*[=:]\s*["']?([0-9a-f]{32})["']?"##).unwrap(),
            entropy_threshold: Some(3.5),
            secret_group: Some(1),
        },
        // 7. Azure AD Token / Client Secret
        SecretPattern {
            name: "Azure AD Client Secret",
            category: SecretCategory::CloudCredential,
            severity: SecretSeverity::Critical,
            regex: Regex::new(r##"(?i)(?:client_secret|azure_secret)\s*[=:]\s*["']?([A-Za-z0-9~._\-]{34,})["']?"##).unwrap(),
            entropy_threshold: Some(4.0),
            secret_group: Some(1),
        },
        // 8. Stripe Secret Key
        SecretPattern {
            name: "Stripe Secret Key",
            category: SecretCategory::ApiKey,
            severity: SecretSeverity::Critical,
            regex: Regex::new(r"sk_live_[0-9a-zA-Z]{24,}").unwrap(),
            entropy_threshold: None,
            secret_group: None,
        },
        // 9. Stripe Publishable Key
        SecretPattern {
            name: "Stripe Publishable Key",
            category: SecretCategory::ApiKey,
            severity: SecretSeverity::Low,
            regex: Regex::new(r"pk_live_[0-9a-zA-Z]{24,}").unwrap(),
            entropy_threshold: None,
            secret_group: None,
        },
        // 10. Twilio API Key
        SecretPattern {
            name: "Twilio API Key",
            category: SecretCategory::ApiKey,
            severity: SecretSeverity::High,
            regex: Regex::new(r"SK[0-9a-fA-F]{32}").unwrap(),
            entropy_threshold: Some(3.5),
            secret_group: None,
        },
        // 11. SendGrid API Key
        SecretPattern {
            name: "SendGrid API Key",
            category: SecretCategory::ApiKey,
            severity: SecretSeverity::High,
            regex: Regex::new(r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}").unwrap(),
            entropy_threshold: None,
            secret_group: None,
        },
        // 12. Slack Token (xoxb / xoxp / xoxs)
        SecretPattern {
            name: "Slack Token",
            category: SecretCategory::Token,
            severity: SecretSeverity::High,
            regex: Regex::new(r"xox[bpsa]-[0-9]{10,13}-[0-9a-zA-Z\-]{20,}").unwrap(),
            entropy_threshold: None,
            secret_group: None,
        },
        // 13. Slack Webhook URL
        SecretPattern {
            name: "Slack Webhook URL",
            category: SecretCategory::Token,
            severity: SecretSeverity::Medium,
            regex: Regex::new(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24,}").unwrap(),
            entropy_threshold: None,
            secret_group: None,
        },
        // 14. GitHub Personal Access Token (classic)
        SecretPattern {
            name: "GitHub Personal Access Token",
            category: SecretCategory::Token,
            severity: SecretSeverity::Critical,
            regex: Regex::new(r"ghp_[0-9a-zA-Z]{36}").unwrap(),
            entropy_threshold: None,
            secret_group: None,
        },
        // 15. GitHub OAuth Access Token
        SecretPattern {
            name: "GitHub OAuth Token",
            category: SecretCategory::Token,
            severity: SecretSeverity::Critical,
            regex: Regex::new(r"gho_[0-9a-zA-Z]{36}").unwrap(),
            entropy_threshold: None,
            secret_group: None,
        },
        // 16. GitHub App Token
        SecretPattern {
            name: "GitHub App Token",
            category: SecretCategory::Token,
            severity: SecretSeverity::High,
            regex: Regex::new(r"(?:ghu|ghs)_[0-9a-zA-Z]{36}").unwrap(),
            entropy_threshold: None,
            secret_group: None,
        },
        // 17. JWT Token
        SecretPattern {
            name: "JWT Token",
            category: SecretCategory::Token,
            severity: SecretSeverity::High,
            regex: Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]+").unwrap(),
            entropy_threshold: Some(4.0),
            secret_group: None,
        },
        // 18. OAuth Bearer Token (in header-like context)
        SecretPattern {
            name: "OAuth Bearer Token",
            category: SecretCategory::Token,
            severity: SecretSeverity::High,
            regex: Regex::new(r##"(?i)(?:bearer|authorization)\s*[=:]\s*["']?([A-Za-z0-9_\-.]{20,})["']?"##).unwrap(),
            entropy_threshold: Some(4.0),
            secret_group: Some(1),
        },
        // 19. PostgreSQL Connection String
        SecretPattern {
            name: "PostgreSQL Connection String",
            category: SecretCategory::DatabaseCredential,
            severity: SecretSeverity::Critical,
            regex: Regex::new(r##"postgres(?:ql)?://[^\s'"<>]{8,}"##).unwrap(),
            entropy_threshold: None,
            secret_group: None,
        },
        // 20. MongoDB Connection String
        SecretPattern {
            name: "MongoDB Connection String",
            category: SecretCategory::DatabaseCredential,
            severity: SecretSeverity::Critical,
            regex: Regex::new(r##"mongodb(?:\+srv)?://[^\s'"<>]{8,}"##).unwrap(),
            entropy_threshold: None,
            secret_group: None,
        },
        // 21. MySQL Connection String
        SecretPattern {
            name: "MySQL Connection String",
            category: SecretCategory::DatabaseCredential,
            severity: SecretSeverity::Critical,
            regex: Regex::new(r##"mysql://[^\s'"<>]{8,}"##).unwrap(),
            entropy_threshold: None,
            secret_group: None,
        },
        // 22. Redis Connection String
        SecretPattern {
            name: "Redis Connection String",
            category: SecretCategory::DatabaseCredential,
            severity: SecretSeverity::High,
            regex: Regex::new(r##"redis://[^\s'"<>]{8,}"##).unwrap(),
            entropy_threshold: None,
            secret_group: None,
        },
        // 23. RSA Private Key
        SecretPattern {
            name: "RSA Private Key",
            category: SecretCategory::PrivateKey,
            severity: SecretSeverity::Critical,
            regex: Regex::new(r"-----BEGIN RSA PRIVATE KEY-----").unwrap(),
            entropy_threshold: None,
            secret_group: None,
        },
        // 24. EC Private Key
        SecretPattern {
            name: "EC Private Key",
            category: SecretCategory::PrivateKey,
            severity: SecretSeverity::Critical,
            regex: Regex::new(r"-----BEGIN EC PRIVATE KEY-----").unwrap(),
            entropy_threshold: None,
            secret_group: None,
        },
        // 25. PGP Private Key Block
        SecretPattern {
            name: "PGP Private Key",
            category: SecretCategory::PrivateKey,
            severity: SecretSeverity::Critical,
            regex: Regex::new(r"-----BEGIN PGP PRIVATE KEY BLOCK-----").unwrap(),
            entropy_threshold: None,
            secret_group: None,
        },
        // 26. Generic Private Key Header
        SecretPattern {
            name: "Generic Private Key",
            category: SecretCategory::PrivateKey,
            severity: SecretSeverity::Critical,
            regex: Regex::new(r"-----BEGIN (?:OPENSSH |DSA )?PRIVATE KEY-----").unwrap(),
            entropy_threshold: None,
            secret_group: None,
        },
        // 27. Internal URL (.internal / .local / .corp)
        SecretPattern {
            name: "Internal URL Leak",
            category: SecretCategory::InternalUrl,
            severity: SecretSeverity::Medium,
            regex: Regex::new(r##"https?://[a-zA-Z0-9._-]+\.(?:internal|local|corp|intranet)(?:[:/][^\s'"<>]*)?"##).unwrap(),
            entropy_threshold: None,
            secret_group: None,
        },
        // 28. Internal IP Address Reference (RFC 1918)
        SecretPattern {
            name: "Internal IP Reference",
            category: SecretCategory::InternalUrl,
            severity: SecretSeverity::Medium,
            regex: Regex::new(r##"https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?:[:/][^\s'"<>]*)?"##).unwrap(),
            entropy_threshold: None,
            secret_group: None,
        },
        // 29. Debug/Admin Endpoint — /admin variants
        SecretPattern {
            name: "Admin Endpoint Exposed",
            category: SecretCategory::DebugEndpoint,
            severity: SecretSeverity::Medium,
            regex: Regex::new(r##"(?:href|src|action|url)\s*[=:]\s*["']?(/(?:admin|_admin|administrator)[^\s"'<>]*)"##).unwrap(),
            entropy_threshold: None,
            secret_group: Some(1),
        },
        // 30. Debug Endpoint — /debug, /phpinfo, /__debug__
        SecretPattern {
            name: "Debug Endpoint Exposed",
            category: SecretCategory::DebugEndpoint,
            severity: SecretSeverity::Medium,
            regex: Regex::new(r##"(?:href|src|action|url)\s*[=:]\s*["']?(/(?:debug|phpinfo|__debug__|_debug|server-status|server-info|elmah\.axd|trace\.axd)[^\s"'<>]*)"##).unwrap(),
            entropy_threshold: None,
            secret_group: Some(1),
        },
        // 31. Password in URL
        SecretPattern {
            name: "Password in URL",
            category: SecretCategory::PasswordPattern,
            severity: SecretSeverity::High,
            regex: Regex::new(r##"(?i)[?&](?:password|passwd|pwd|pass)=([^\s&'"<>]{3,})"##).unwrap(),
            entropy_threshold: None,
            secret_group: Some(1),
        },
        // 32. Hardcoded Password in JS/Config
        SecretPattern {
            name: "Hardcoded Password",
            category: SecretCategory::PasswordPattern,
            severity: SecretSeverity::High,
            regex: Regex::new(r##"(?i)(?:password|passwd|pwd|secret|api_?key)\s*[=:]\s*["']([^"']{8,})["']"##).unwrap(),
            entropy_threshold: Some(3.0),
            secret_group: Some(1),
        },
        // 33. Mailgun API Key
        SecretPattern {
            name: "Mailgun API Key",
            category: SecretCategory::ApiKey,
            severity: SecretSeverity::High,
            regex: Regex::new(r"key-[0-9a-zA-Z]{32}").unwrap(),
            entropy_threshold: None,
            secret_group: None,
        },
        // 34. Heroku API Key
        SecretPattern {
            name: "Heroku API Key",
            category: SecretCategory::ApiKey,
            severity: SecretSeverity::High,
            regex: Regex::new(r##"(?i)(?:heroku_api_key|heroku_secret)\s*[=:]\s*["']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["']?"##).unwrap(),
            entropy_threshold: None,
            secret_group: Some(1),
        },
        // 35. Generic High-Entropy Hex Secret (≥32 hex chars assigned to secret-like vars)
        SecretPattern {
            name: "High-Entropy Hex Secret",
            category: SecretCategory::ApiKey,
            severity: SecretSeverity::Medium,
            regex: Regex::new(r##"(?i)(?:secret|token|apikey|api_key|auth_token|access_token)\s*[=:]\s*["']?([0-9a-f]{32,})["']?"##).unwrap(),
            entropy_threshold: Some(4.0),
            secret_group: Some(1),
        },
    ]
}

impl SecretScanner {
    /// Create a new scanner with all built-in patterns and false-positive filters.
    pub fn new() -> Self {
        let fp_filters = FALSE_POSITIVE_PATTERNS
            .iter()
            .map(|p| Regex::new(p).unwrap())
            .collect();

        Self {
            patterns: build_patterns(),
            fp_filters,
        }
    }

    /// Number of distinct secret patterns in the scanner.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Scan content (HTTP response body, JS file, etc.) and return all findings.
    pub fn scan(&self, content: &str) -> Vec<SecretFinding> {
        let mut findings = Vec::new();

        for pattern in &self.patterns {
            for (line_idx, line) in content.lines().enumerate() {
                for caps in pattern.regex.captures_iter(line) {
                    let full_match = caps.get(0).unwrap().as_str().to_string();
                    let secret_value = pattern
                        .secret_group
                        .and_then(|g| caps.get(g))
                        .map(|m| m.as_str())
                        .unwrap_or(&full_match);

                    if self.is_false_positive(secret_value) || self.is_false_positive(&full_match) {
                        continue;
                    }

                    let entropy = if secret_value.len() >= 8 {
                        Some(shannon_entropy(secret_value))
                    } else {
                        None
                    };

                    if let Some(threshold) = pattern.entropy_threshold {
                        match entropy {
                            Some(e) if e < threshold => continue,
                            None => continue,
                            _ => {}
                        }
                    }

                    let confidence = self.compute_confidence(pattern, entropy);

                    findings.push(SecretFinding {
                        pattern_name: pattern.name.to_string(),
                        category: pattern.category,
                        severity: pattern.severity,
                        matched_text: full_match,
                        line_number: line_idx + 1,
                        entropy,
                        confidence,
                    });
                }
            }
        }

        findings
    }

    fn is_false_positive(&self, value: &str) -> bool {
        self.fp_filters.iter().any(|fp| fp.is_match(value))
    }

    fn compute_confidence(&self, pattern: &SecretPattern, entropy: Option<f64>) -> f64 {
        let base: f64 = match pattern.severity {
            SecretSeverity::Critical => 0.90,
            SecretSeverity::High => 0.80,
            SecretSeverity::Medium => 0.70,
            SecretSeverity::Low => 0.60,
            SecretSeverity::Info => 0.50,
        };

        let entropy_boost: f64 = match entropy {
            Some(e) if e > 5.0 => 0.10,
            Some(e) if e > 4.5 => 0.05,
            _ => 0.0,
        };

        (base + entropy_boost).min(1.0)
    }
}

impl Default for SecretScanner {
    fn default() -> Self {
        Self::new()
    }
}
