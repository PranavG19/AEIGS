use std::collections::HashMap;

use regex::Regex;

/// Format of a credential dump line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DumpFormat {
    EmailPassword,
    EmailHash,
    UserPassword,
    UserHash,
    ComboList,
    Unknown,
}

impl std::fmt::Display for DumpFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmailPassword => write!(f, "email:password"),
            Self::EmailHash => write!(f, "email:hash"),
            Self::UserPassword => write!(f, "user:password"),
            Self::UserHash => write!(f, "user:hash"),
            Self::ComboList => write!(f, "combo_list"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// A single parsed credential entry from a breach dump.
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialEntry {
    pub identifier: String,
    pub credential: String,
    pub format: DumpFormat,
    pub source: Option<String>,
}

/// Password policy analysis result.
#[derive(Debug, Clone, PartialEq)]
pub struct PasswordPolicyAnalysis {
    pub avg_length: f64,
    pub min_length: usize,
    pub max_length: usize,
    pub has_uppercase_pct: f64,
    pub has_lowercase_pct: f64,
    pub has_digit_pct: f64,
    pub has_special_pct: f64,
    pub common_patterns: Vec<PasswordPattern>,
    pub reuse_rate: f64,
    pub total_analyzed: usize,
}

/// Common password pattern detected.
#[derive(Debug, Clone, PartialEq)]
pub struct PasswordPattern {
    pub pattern: String,
    pub description: String,
    pub frequency: f64,
    pub examples_count: usize,
}

/// Credential stuffing candidate.
#[derive(Debug, Clone, PartialEq)]
pub struct StuffingCandidate {
    pub email: String,
    pub password_candidates: Vec<String>,
    pub confidence: f64,
    pub rationale: String,
}

/// Hash type detected from format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashType {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Bcrypt,
    Scrypt,
    Argon2,
    Ntlm,
    DesUnix,
    Unknown,
}

impl std::fmt::Display for HashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Md5 => write!(f, "MD5"),
            Self::Sha1 => write!(f, "SHA-1"),
            Self::Sha256 => write!(f, "SHA-256"),
            Self::Sha512 => write!(f, "SHA-512"),
            Self::Bcrypt => write!(f, "bcrypt"),
            Self::Scrypt => write!(f, "scrypt"),
            Self::Argon2 => write!(f, "Argon2"),
            Self::Ntlm => write!(f, "NTLM"),
            Self::DesUnix => write!(f, "DES (Unix)"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Discovered API key with classification.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredApiKey {
    pub key_type: ApiKeyType,
    pub key_value: String,
    pub source_url: String,
    pub domain_match: bool,
    pub is_active: Option<bool>,
    pub confidence: f64,
}

/// Type of API key or cloud credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiKeyType {
    AwsAccessKey,
    AwsSecretKey,
    GcpServiceAccount,
    AzureConnectionString,
    GitHubToken,
    GitLabToken,
    SlackToken,
    StripeKey,
    SendGridKey,
    TwilioKey,
    HerokuApiKey,
    FirebaseKey,
    JwtSecret,
    GenericApiKey,
    SshPrivateKey,
    PgpPrivateKey,
}

impl std::fmt::Display for ApiKeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AwsAccessKey => write!(f, "AWS Access Key"),
            Self::AwsSecretKey => write!(f, "AWS Secret Key"),
            Self::GcpServiceAccount => write!(f, "GCP Service Account"),
            Self::AzureConnectionString => write!(f, "Azure Connection String"),
            Self::GitHubToken => write!(f, "GitHub Token"),
            Self::GitLabToken => write!(f, "GitLab Token"),
            Self::SlackToken => write!(f, "Slack Token"),
            Self::StripeKey => write!(f, "Stripe Key"),
            Self::SendGridKey => write!(f, "SendGrid Key"),
            Self::TwilioKey => write!(f, "Twilio Key"),
            Self::HerokuApiKey => write!(f, "Heroku API Key"),
            Self::FirebaseKey => write!(f, "Firebase Key"),
            Self::JwtSecret => write!(f, "JWT Secret"),
            Self::GenericApiKey => write!(f, "Generic API Key"),
            Self::SshPrivateKey => write!(f, "SSH Private Key"),
            Self::PgpPrivateKey => write!(f, "PGP Private Key"),
        }
    }
}

/// Session token found in archived content.
#[derive(Debug, Clone, PartialEq)]
pub struct ArchivedToken {
    pub token_type: TokenType,
    pub token_value: String,
    pub source_url: String,
    pub archive_date: Option<String>,
    pub is_expired: Option<bool>,
}

/// Type of session token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenType {
    Jwt,
    SessionCookie,
    OAuthBearer,
    ApiToken,
    SamlAssertion,
    BasicAuth,
    Unknown,
}

impl std::fmt::Display for TokenType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Jwt => write!(f, "JWT"),
            Self::SessionCookie => write!(f, "Session Cookie"),
            Self::OAuthBearer => write!(f, "OAuth Bearer"),
            Self::ApiToken => write!(f, "API Token"),
            Self::SamlAssertion => write!(f, "SAML Assertion"),
            Self::BasicAuth => write!(f, "Basic Auth"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Dark web paste site finding.
#[derive(Debug, Clone, PartialEq)]
pub struct DarkWebFinding {
    pub source_type: DarkWebSource,
    pub content_preview: String,
    pub date: Option<String>,
    pub credential_count: usize,
    pub domain_matches: Vec<String>,
}

/// Type of dark web source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DarkWebSource {
    PasteSite,
    ForumPost,
    MarketplaceListing,
    TelegramChannel,
    IrcLog,
    Unknown,
}

impl std::fmt::Display for DarkWebSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PasteSite => write!(f, "Paste Site"),
            Self::ForumPost => write!(f, "Forum Post"),
            Self::MarketplaceListing => write!(f, "Marketplace Listing"),
            Self::TelegramChannel => write!(f, "Telegram Channel"),
            Self::IrcLog => write!(f, "IRC Log"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Full credential intelligence report.
#[derive(Debug, Clone)]
pub struct CredentialIntelReport {
    pub target_domain: String,
    pub parsed_credentials: Vec<CredentialEntry>,
    pub password_analysis: Option<PasswordPolicyAnalysis>,
    pub stuffing_candidates: Vec<StuffingCandidate>,
    pub discovered_api_keys: Vec<DiscoveredApiKey>,
    pub archived_tokens: Vec<ArchivedToken>,
    pub dark_web_findings: Vec<DarkWebFinding>,
    pub total_credentials_found: usize,
    pub risk_score: f64,
}

/// Parse a credential dump in common formats.
pub fn parse_credential_dump(raw_lines: &[&str], source: Option<&str>) -> Vec<CredentialEntry> {
    let email_re = Regex::new(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$").unwrap();

    raw_lines
        .iter()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }

            let (identifier, credential, format) = if let Some((left, right)) = line.split_once(':')
            {
                let left = left.trim();
                let right = right.trim();
                if email_re.is_match(left) {
                    let fmt = if is_hash(right) {
                        DumpFormat::EmailHash
                    } else {
                        DumpFormat::EmailPassword
                    };
                    (left, right, fmt)
                } else {
                    let fmt = if is_hash(right) {
                        DumpFormat::UserHash
                    } else {
                        DumpFormat::UserPassword
                    };
                    (left, right, fmt)
                }
            } else if let Some((left, right)) = line.split_once(';') {
                (left.trim(), right.trim(), DumpFormat::ComboList)
            } else if let Some((left, right)) = line.split_once('|') {
                (left.trim(), right.trim(), DumpFormat::ComboList)
            } else {
                return None;
            };

            Some(CredentialEntry {
                identifier: identifier.to_string(),
                credential: credential.to_string(),
                format,
                source: source.map(String::from),
            })
        })
        .collect()
}

fn is_hash(value: &str) -> bool {
    let hex_re = Regex::new(r"^[a-fA-F0-9]+$").unwrap();
    let len = value.len();

    if value.starts_with("$2b$") || value.starts_with("$2a$") || value.starts_with("$2y$") {
        return true;
    }
    if value.starts_with("$argon2") {
        return true;
    }
    if value.starts_with("$6$") || value.starts_with("$5$") || value.starts_with("$1$") {
        return true;
    }

    if hex_re.is_match(value) {
        matches!(len, 32 | 40 | 64 | 128)
    } else {
        false
    }
}

/// Identify the hash type from its format.
pub fn identify_hash_type(hash: &str) -> HashType {
    if hash.starts_with("$2b$") || hash.starts_with("$2a$") || hash.starts_with("$2y$") {
        return HashType::Bcrypt;
    }
    if hash.starts_with("$argon2") {
        return HashType::Argon2;
    }
    if hash.starts_with("$scrypt$") {
        return HashType::Scrypt;
    }
    if hash.starts_with("$6$") {
        return HashType::Sha512;
    }
    if hash.starts_with("$5$") {
        return HashType::Sha256;
    }
    if hash.starts_with("$1$") {
        return HashType::Md5;
    }

    let hex_re = Regex::new(r"^[a-fA-F0-9]+$").unwrap();
    if hex_re.is_match(hash) {
        return match hash.len() {
            32 => {
                if hash
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                {
                    HashType::Ntlm
                } else {
                    HashType::Md5
                }
            }
            40 => HashType::Sha1,
            64 => HashType::Sha256,
            128 => HashType::Sha512,
            _ => HashType::Unknown,
        };
    }

    HashType::Unknown
}

/// Analyze password patterns from a list of plaintext passwords.
pub fn analyze_password_patterns(passwords: &[&str]) -> PasswordPolicyAnalysis {
    if passwords.is_empty() {
        return PasswordPolicyAnalysis {
            avg_length: 0.0,
            min_length: 0,
            max_length: 0,
            has_uppercase_pct: 0.0,
            has_lowercase_pct: 0.0,
            has_digit_pct: 0.0,
            has_special_pct: 0.0,
            common_patterns: Vec::new(),
            reuse_rate: 0.0,
            total_analyzed: 0,
        };
    }

    let total = passwords.len() as f64;
    let lengths: Vec<usize> = passwords.iter().map(|p| p.len()).collect();
    let avg_length = lengths.iter().sum::<usize>() as f64 / total;
    let min_length = *lengths.iter().min().unwrap_or(&0);
    let max_length = *lengths.iter().max().unwrap_or(&0);

    let has_upper = passwords
        .iter()
        .filter(|p| p.chars().any(|c| c.is_uppercase()))
        .count();
    let has_lower = passwords
        .iter()
        .filter(|p| p.chars().any(|c| c.is_lowercase()))
        .count();
    let has_digit = passwords
        .iter()
        .filter(|p| p.chars().any(|c| c.is_ascii_digit()))
        .count();
    let has_special = passwords
        .iter()
        .filter(|p| p.chars().any(|c| !c.is_alphanumeric()))
        .count();

    let mut pattern_counts: HashMap<&str, usize> = HashMap::new();

    let trailing_digits_re = Regex::new(r"\d+$").unwrap();
    let year_re = Regex::new(r"(19|20)\d{2}").unwrap();
    let keyboard_walk = ["qwerty", "123456", "asdf", "zxcv", "qazwsx"];
    let season_patterns = ["spring", "summer", "fall", "autumn", "winter"];
    let leet_re = Regex::new(r"[0-9]").unwrap();

    for pw in passwords {
        let lower = pw.to_lowercase();

        if trailing_digits_re.is_match(pw) {
            *pattern_counts.entry("trailing_digits").or_insert(0) += 1;
        }
        if year_re.is_match(pw) {
            *pattern_counts.entry("contains_year").or_insert(0) += 1;
        }
        if keyboard_walk.iter().any(|w| lower.contains(w)) {
            *pattern_counts.entry("keyboard_walk").or_insert(0) += 1;
        }
        if season_patterns.iter().any(|s| lower.contains(s)) {
            *pattern_counts.entry("season_based").or_insert(0) += 1;
        }
        if pw.chars().next().map_or(false, |c| c.is_uppercase())
            && pw[1..]
                .chars()
                .all(|c| c.is_lowercase() || c.is_ascii_digit())
        {
            *pattern_counts.entry("capitalize_first").or_insert(0) += 1;
        }
        if lower != *pw && leet_re.is_match(pw) {
            let letter_count = pw.chars().filter(|c| c.is_alphabetic()).count();
            let digit_count = pw.chars().filter(|c| c.is_ascii_digit()).count();
            if letter_count > 0 && digit_count > 0 && digit_count <= letter_count {
                *pattern_counts.entry("leet_speak").or_insert(0) += 1;
            }
        }
        if pw.len() <= 6 {
            *pattern_counts.entry("short_password").or_insert(0) += 1;
        }
        if pw.chars().all(|c| c.is_lowercase()) {
            *pattern_counts.entry("all_lowercase").or_insert(0) += 1;
        }
    }

    let descriptions: HashMap<&str, &str> = [
        ("trailing_digits", "Ends with digits (e.g., password123)"),
        ("contains_year", "Contains a year (e.g., pass2024)"),
        ("keyboard_walk", "Keyboard walk pattern (e.g., qwerty)"),
        ("season_based", "Season-based password (e.g., Summer2024)"),
        ("capitalize_first", "First letter capitalized only"),
        ("leet_speak", "Leet speak substitutions (e.g., p@ssw0rd)"),
        ("short_password", "Short password (6 chars or less)"),
        ("all_lowercase", "All lowercase letters"),
    ]
    .into_iter()
    .collect();

    let common_patterns: Vec<PasswordPattern> = pattern_counts
        .into_iter()
        .map(|(pattern, count)| PasswordPattern {
            pattern: pattern.to_string(),
            description: descriptions.get(pattern).unwrap_or(&"").to_string(),
            frequency: count as f64 / total,
            examples_count: count,
        })
        .collect();

    let mut seen = std::collections::HashSet::new();
    let mut dupes = 0usize;
    for pw in passwords {
        if !seen.insert(*pw) {
            dupes += 1;
        }
    }
    let reuse_rate = dupes as f64 / total;

    PasswordPolicyAnalysis {
        avg_length,
        min_length,
        max_length,
        has_uppercase_pct: has_upper as f64 / total,
        has_lowercase_pct: has_lower as f64 / total,
        has_digit_pct: has_digit as f64 / total,
        has_special_pct: has_special as f64 / total,
        common_patterns,
        reuse_rate,
        total_analyzed: passwords.len(),
    }
}

/// Generate credential stuffing candidates from emails and password patterns.
pub fn generate_stuffing_candidates(
    emails: &[&str],
    known_passwords: &[&str],
    password_analysis: &PasswordPolicyAnalysis,
) -> Vec<StuffingCandidate> {
    let base_passwords: Vec<String> = if !known_passwords.is_empty() {
        let mut freq: HashMap<&str, usize> = HashMap::new();
        for pw in known_passwords {
            *freq.entry(pw).or_insert(0) += 1;
        }
        let mut sorted: Vec<_> = freq.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted
            .into_iter()
            .take(10)
            .map(|(pw, _)| pw.to_string())
            .collect()
    } else {
        vec![
            "password".to_string(),
            "123456".to_string(),
            "password1".to_string(),
            "qwerty".to_string(),
            "letmein".to_string(),
        ]
    };

    let mut mutations = Vec::new();
    for base in &base_passwords {
        mutations.push(base.clone());
        if !base.chars().next().map_or(false, |c| c.is_uppercase()) {
            let mut chars = base.chars();
            if let Some(first) = chars.next() {
                mutations.push(format!("{}{}", first.to_uppercase(), chars.as_str()));
            }
        }
        mutations.push(format!("{base}1"));
        mutations.push(format!("{base}!"));
        mutations.push(format!("{base}123"));
        mutations.push(format!("{base}2024"));
        mutations.push(format!("{base}2025"));
    }

    mutations.sort();
    mutations.dedup();

    emails
        .iter()
        .map(|email| {
            let local = email.split('@').next().unwrap_or(email);
            let mut candidates = mutations.clone();
            candidates.push(local.to_string());
            candidates.push(format!("{local}123"));
            candidates.push(format!("{local}!"));
            candidates.dedup();

            let confidence = if !known_passwords.is_empty() {
                0.60 + (password_analysis.reuse_rate * 0.30)
            } else {
                0.20
            };

            StuffingCandidate {
                email: email.to_string(),
                password_candidates: candidates,
                confidence,
                rationale: if !known_passwords.is_empty() {
                    format!(
                        "Based on {} known passwords with {:.0}% reuse rate",
                        known_passwords.len(),
                        password_analysis.reuse_rate * 100.0,
                    )
                } else {
                    "Generic common passwords only".to_string()
                },
            }
        })
        .collect()
}

/// Scan text content for leaked API keys matching known patterns.
pub fn scan_for_api_keys(content: &str, target_domains: &[&str]) -> Vec<DiscoveredApiKey> {
    let patterns: Vec<(&str, ApiKeyType, &str)> = vec![
        (r"AKIA[0-9A-Z]{16}", ApiKeyType::AwsAccessKey, ""),
        (
            r#""type"\s*:\s*"service_account""#,
            ApiKeyType::GcpServiceAccount,
            "",
        ),
        (
            r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+",
            ApiKeyType::AzureConnectionString,
            "",
        ),
        (r"ghp_[a-zA-Z0-9]{36}", ApiKeyType::GitHubToken, ""),
        (r"glpat-[a-zA-Z0-9\-_]{20}", ApiKeyType::GitLabToken, ""),
        (
            r"xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+",
            ApiKeyType::SlackToken,
            "",
        ),
        (r"sk_live_[a-zA-Z0-9]{24,}", ApiKeyType::StripeKey, ""),
        (
            r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
            ApiKeyType::SendGridKey,
            "",
        ),
        (r"SK[a-f0-9]{32}", ApiKeyType::TwilioKey, ""),
        (r"AIza[a-zA-Z0-9_\-]{35}", ApiKeyType::FirebaseKey, ""),
        (
            r"heroku[_\-]?api[_\-]?key[=:\s]+[a-f0-9\-]{36}",
            ApiKeyType::HerokuApiKey,
            "",
        ),
        (
            r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
            ApiKeyType::JwtSecret,
            "",
        ),
        (
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            ApiKeyType::SshPrivateKey,
            "",
        ),
        (
            r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
            ApiKeyType::PgpPrivateKey,
            "",
        ),
    ];

    let mut results = Vec::new();

    for (pattern, key_type, _) in &patterns {
        let re = match Regex::new(pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };

        for mat in re.find_iter(content) {
            let key_value = mat.as_str().to_string();
            let domain_match = target_domains.iter().any(|d| content.contains(d));

            let confidence = if domain_match { 0.85 } else { 0.50 };

            results.push(DiscoveredApiKey {
                key_type: *key_type,
                key_value,
                source_url: String::new(),
                domain_match,
                is_active: None,
                confidence,
            });
        }
    }

    results
}

/// Classify a token found in archived content.
pub fn classify_archived_token(token: &str) -> TokenType {
    if token.starts_with("eyJ") && token.matches('.').count() == 2 {
        TokenType::Jwt
    } else if token.starts_with("Bearer ") {
        TokenType::OAuthBearer
    } else if token.contains("SAML") || token.contains("saml") {
        TokenType::SamlAssertion
    } else if token.starts_with("Basic ") {
        TokenType::BasicAuth
    } else if token.len() >= 20
        && token
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        TokenType::ApiToken
    } else if token.len() >= 16 && token.len() <= 64 {
        TokenType::SessionCookie
    } else {
        TokenType::Unknown
    }
}

/// Parse dark web paste content for credential-related findings.
pub fn parse_dark_web_paste(
    content: &str,
    target_domains: &[&str],
    source_type: DarkWebSource,
    date: Option<&str>,
) -> Option<DarkWebFinding> {
    let email_re = Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap();
    let emails: Vec<String> = email_re
        .find_iter(content)
        .map(|m| m.as_str().to_string())
        .collect();

    let matching_domains: Vec<String> = target_domains
        .iter()
        .filter(|d| content.to_lowercase().contains(&d.to_lowercase()))
        .map(|d| d.to_string())
        .collect();

    if matching_domains.is_empty() && emails.is_empty() {
        return None;
    }

    let preview = if content.len() > 200 {
        format!("{}...", &content[..200])
    } else {
        content.to_string()
    };

    let cred_lines = content
        .lines()
        .filter(|l| l.contains(':') && email_re.is_match(l))
        .count();

    Some(DarkWebFinding {
        source_type,
        content_preview: preview,
        date: date.map(String::from),
        credential_count: cred_lines.max(emails.len()),
        domain_matches: matching_domains,
    })
}

/// Build the full credential intelligence report.
pub fn build_credential_intel_report(
    target_domain: &str,
    parsed_credentials: Vec<CredentialEntry>,
    password_analysis: Option<PasswordPolicyAnalysis>,
    stuffing_candidates: Vec<StuffingCandidate>,
    discovered_api_keys: Vec<DiscoveredApiKey>,
    archived_tokens: Vec<ArchivedToken>,
    dark_web_findings: Vec<DarkWebFinding>,
) -> CredentialIntelReport {
    let total = parsed_credentials.len();

    let cred_score = (total as f64 / 100.0).min(1.0) * 30.0;
    let api_score = (discovered_api_keys.len() as f64 / 5.0).min(1.0) * 25.0;
    let dark_web_score = (dark_web_findings.len() as f64 / 3.0).min(1.0) * 20.0;
    let reuse_score = password_analysis
        .as_ref()
        .map(|a| a.reuse_rate * 15.0)
        .unwrap_or(0.0);
    let token_score = (archived_tokens.len() as f64 / 5.0).min(1.0) * 10.0;

    let risk_score =
        (cred_score + api_score + dark_web_score + reuse_score + token_score).min(100.0);

    CredentialIntelReport {
        target_domain: target_domain.to_string(),
        parsed_credentials,
        password_analysis,
        stuffing_candidates,
        discovered_api_keys,
        archived_tokens,
        dark_web_findings,
        total_credentials_found: total,
        risk_score,
    }
}
