use std::collections::HashSet;
use std::fmt;

/// Source from which a credential was harvested during a penetration test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialSource {
    /// Leaked in JavaScript source files.
    JsFile,
    /// Found inside HTML comments.
    HtmlComment,
    /// Extracted from configuration files via LFI/file read (.env, config, etc.).
    ConfigFile,
    /// Extracted via SQL injection database dump.
    DatabaseDump,
    /// Cloud instance metadata (AWS/GCP/Azure IMDS).
    CloudMetadata,
    /// Captured session tokens from traffic or storage.
    SessionToken,
    /// Leaked in API response bodies.
    ApiResponse,
    /// Exposed `.git` directory contents.
    GitExposure,
    /// Found in backup files (.bak, .old, .tar.gz, etc.).
    BackupFile,
    /// Leaked in error messages or stack traces.
    ErrorMessage,
    /// Known default credentials for services.
    DefaultCreds,
    /// Exposed `.svn`, `.hg`, or other VCS metadata.
    VersionControl,
}

impl fmt::Display for CredentialSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::JsFile => "js-file",
            Self::HtmlComment => "html-comment",
            Self::ConfigFile => "config-file",
            Self::DatabaseDump => "database-dump",
            Self::CloudMetadata => "cloud-metadata",
            Self::SessionToken => "session-token",
            Self::ApiResponse => "api-response",
            Self::GitExposure => "git-exposure",
            Self::BackupFile => "backup-file",
            Self::ErrorMessage => "error-message",
            Self::DefaultCreds => "default-creds",
            Self::VersionControl => "version-control",
        };
        write!(f, "{label}")
    }
}

/// Type of credential found during harvesting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialType {
    UsernamePassword,
    ApiKey,
    BearerToken,
    JwtToken,
    SessionCookie,
    SshKey,
    DatabaseConnectionString,
    AwsAccessKey,
    AwsSecretKey,
    GcpServiceAccount,
    AzureClientSecret,
    OAuthToken,
    PrivateKey,
    BasicAuthHeader,
    SmtpCredential,
    FtpCredential,
    GenericSecret,
}

impl fmt::Display for CredentialType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::UsernamePassword => "username-password",
            Self::ApiKey => "api-key",
            Self::BearerToken => "bearer-token",
            Self::JwtToken => "jwt-token",
            Self::SessionCookie => "session-cookie",
            Self::SshKey => "ssh-key",
            Self::DatabaseConnectionString => "database-connection-string",
            Self::AwsAccessKey => "aws-access-key",
            Self::AwsSecretKey => "aws-secret-key",
            Self::GcpServiceAccount => "gcp-service-account",
            Self::AzureClientSecret => "azure-client-secret",
            Self::OAuthToken => "oauth-token",
            Self::PrivateKey => "private-key",
            Self::BasicAuthHeader => "basic-auth-header",
            Self::SmtpCredential => "smtp-credential",
            Self::FtpCredential => "ftp-credential",
            Self::GenericSecret => "generic-secret",
        };
        write!(f, "{label}")
    }
}

/// Access level that a harvested credential provides.
///
/// Ordered from least to most privileged; derives `PartialOrd`/`Ord`
/// so comparisons follow variant declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AccessLevel {
    Unknown,
    ReadOnly,
    Standard,
    Elevated,
    Admin,
    Root,
}

impl fmt::Display for AccessLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Unknown => "unknown",
            Self::ReadOnly => "read-only",
            Self::Standard => "standard",
            Self::Elevated => "elevated",
            Self::Admin => "admin",
            Self::Root => "root",
        };
        write!(f, "{label}")
    }
}

/// The actual credential value, typed by shape.
#[derive(Debug, Clone)]
pub enum CredentialValue {
    Pair {
        username: String,
        password: String,
    },
    Token(String),
    KeyPair {
        public_key: String,
        private_key: String,
    },
    ConnectionString(String),
    Cookie {
        name: String,
        value: String,
    },
    Header {
        name: String,
        value: String,
    },
}

impl CredentialValue {
    /// Produces a deterministic byte representation for hashing.
    fn canonical_bytes(&self) -> Vec<u8> {
        match self {
            Self::Pair { username, password } => format!("pair:{username}:{password}").into_bytes(),
            Self::Token(t) => format!("token:{t}").into_bytes(),
            Self::KeyPair {
                public_key,
                private_key,
            } => format!("keypair:{public_key}:{private_key}").into_bytes(),
            Self::ConnectionString(c) => format!("connstr:{c}").into_bytes(),
            Self::Cookie { name, value } => format!("cookie:{name}:{value}").into_bytes(),
            Self::Header { name, value } => format!("header:{name}:{value}").into_bytes(),
        }
    }
}

/// A single harvested credential with provenance and scoring metadata.
#[derive(Debug, Clone)]
pub struct HarvestedCredential {
    /// Unique identifier — CRC32 hex of (type, value, scope).
    pub id: String,
    pub credential_type: CredentialType,
    pub source: CredentialSource,
    pub value: CredentialValue,
    pub access_level: AccessLevel,
    /// What service/system this credential accesses.
    pub scope: String,
    /// 0.0–1.0 confidence that this credential is valid.
    pub confidence: f64,
    /// Where it was found (URL, file path, etc.).
    pub location: String,
    /// Whether the credential has been confirmed to work.
    pub validated: bool,
    /// Additional metadata tags.
    pub tags: Vec<String>,
}

/// Pattern for detecting credentials in text content.
#[derive(Debug, Clone)]
pub struct CredentialPattern {
    pub name: String,
    /// Regex pattern string (not compiled — kept as data).
    pub pattern: String,
    pub credential_type: CredentialType,
    /// Default confidence when this pattern matches.
    pub confidence: f64,
    pub description: String,
}

/// Summary statistics across all harvested credentials.
#[derive(Debug, Clone)]
pub struct HarvestSummary {
    pub total_found: usize,
    pub unique_credentials: usize,
    pub duplicates_removed: usize,
    pub by_source: Vec<(CredentialSource, usize)>,
    pub by_type: Vec<(CredentialType, usize)>,
    pub by_access_level: Vec<(AccessLevel, usize)>,
    pub highest_access: AccessLevel,
    pub validated_count: usize,
    pub critical_findings: Vec<String>,
}

/// Coordinates discovery, deduplication, validation, and scoring of
/// credentials from all possible sources during a penetration test.
#[derive(Debug, Clone)]
pub struct CredentialHarvester {
    credentials: Vec<HarvestedCredential>,
    patterns: Vec<CredentialPattern>,
    seen_hashes: HashSet<String>,
}

/// Errors that can occur during credential harvesting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HarvestError {
    DuplicateCredential(String),
    InvalidCredential(String),
    PatternError(String),
}

impl fmt::Display for HarvestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateCredential(id) => write!(f, "duplicate credential: {id}"),
            Self::InvalidCredential(msg) => write!(f, "invalid credential: {msg}"),
            Self::PatternError(msg) => write!(f, "pattern error: {msg}"),
        }
    }
}

impl std::error::Error for HarvestError {}

/// Computes a deterministic CRC32-based hash for deduplication.
///
/// Concatenates the credential type discriminant, canonical value bytes,
/// and returns the CRC32 digest as an 8-char hex string.
pub fn compute_credential_hash(cred_type: CredentialType, value: &CredentialValue) -> String {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(format!("{cred_type:?}:").as_bytes());
    hasher.update(&value.canonical_bytes());
    format!("{:08x}", hasher.finalize())
}

/// Returns the built-in set of credential detection patterns.
pub fn default_credential_patterns() -> Vec<CredentialPattern> {
    vec![
        CredentialPattern {
            name: "aws-access-key".into(),
            pattern: r"AKIA[0-9A-Z]{16}".into(),
            credential_type: CredentialType::AwsAccessKey,
            confidence: 0.95,
            description: "AWS access key ID starting with AKIA".into(),
        },
        CredentialPattern {
            name: "bearer-token".into(),
            pattern: r"Bearer [a-zA-Z0-9._\-]+".into(),
            credential_type: CredentialType::BearerToken,
            confidence: 0.85,
            description: "HTTP Bearer token in Authorization header".into(),
        },
        CredentialPattern {
            name: "basic-auth".into(),
            pattern: r"Basic [A-Za-z0-9+/=]+".into(),
            credential_type: CredentialType::BasicAuthHeader,
            confidence: 0.80,
            description: "HTTP Basic authentication header value".into(),
        },
        CredentialPattern {
            name: "jwt-token".into(),
            pattern: r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+".into(),
            credential_type: CredentialType::JwtToken,
            confidence: 0.90,
            description: "JSON Web Token (three base64url segments)".into(),
        },
        CredentialPattern {
            name: "connection-string".into(),
            pattern: r"(mysql|postgres|mongodb|redis)://[^\s]+".into(),
            credential_type: CredentialType::DatabaseConnectionString,
            confidence: 0.90,
            description: "Database connection string URI".into(),
        },
        CredentialPattern {
            name: "private-key".into(),
            pattern: r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----".into(),
            credential_type: CredentialType::PrivateKey,
            confidence: 0.95,
            description: "PEM-encoded private key header".into(),
        },
        CredentialPattern {
            name: "password-assignment".into(),
            pattern: r#"password["\s:=]+[^\s"']+"#.into(),
            credential_type: CredentialType::UsernamePassword,
            confidence: 0.70,
            description: "Password value assignment pattern".into(),
        },
        CredentialPattern {
            name: "generic-secret".into(),
            pattern: r"(secret|token|key|password|passwd|pwd)\s*[=:]\s*[^\s]{8,}".into(),
            credential_type: CredentialType::GenericSecret,
            confidence: 0.60,
            description: "Generic secret/key/token assignment with 8+ char value".into(),
        },
        CredentialPattern {
            name: "api-key-context".into(),
            pattern: r"(api_key|apikey|api-key|secret_key)\s*[=:]\s*[a-zA-Z0-9]{32,}".into(),
            credential_type: CredentialType::ApiKey,
            confidence: 0.80,
            description: "API key near identifying keyword with 32+ char value".into(),
        },
    ]
}

/// Heuristic classification of access level based on credential type and scope string.
///
/// SSH/private keys → Admin, AWS/database creds → Elevated,
/// session tokens → Standard, generic → Unknown.
/// If `scope` contains "admin" or "root" the level is bumped one notch.
pub fn classify_access_level(credential_type: CredentialType, scope: &str) -> AccessLevel {
    let base = match credential_type {
        CredentialType::SshKey | CredentialType::PrivateKey => AccessLevel::Admin,
        CredentialType::AwsAccessKey
        | CredentialType::AwsSecretKey
        | CredentialType::GcpServiceAccount
        | CredentialType::AzureClientSecret
        | CredentialType::DatabaseConnectionString => AccessLevel::Elevated,
        CredentialType::SessionCookie
        | CredentialType::BearerToken
        | CredentialType::JwtToken
        | CredentialType::OAuthToken
        | CredentialType::BasicAuthHeader => AccessLevel::Standard,
        CredentialType::UsernamePassword
        | CredentialType::ApiKey
        | CredentialType::SmtpCredential
        | CredentialType::FtpCredential => AccessLevel::ReadOnly,
        CredentialType::GenericSecret => AccessLevel::Unknown,
    };

    let scope_lower = scope.to_ascii_lowercase();
    if scope_lower.contains("root") {
        bump_access(bump_access(base))
    } else if scope_lower.contains("admin") {
        bump_access(base)
    } else {
        base
    }
}

fn bump_access(level: AccessLevel) -> AccessLevel {
    match level {
        AccessLevel::Unknown => AccessLevel::ReadOnly,
        AccessLevel::ReadOnly => AccessLevel::Standard,
        AccessLevel::Standard => AccessLevel::Elevated,
        AccessLevel::Elevated => AccessLevel::Admin,
        AccessLevel::Admin => AccessLevel::Root,
        AccessLevel::Root => AccessLevel::Root,
    }
}

impl Default for CredentialHarvester {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialHarvester {
    /// Creates an empty harvester pre-loaded with the default detection patterns.
    pub fn new() -> Self {
        Self {
            credentials: Vec::new(),
            patterns: default_credential_patterns(),
            seen_hashes: HashSet::new(),
        }
    }

    /// Adds a credential, deduplicating by hash of (type, value, scope).
    ///
    /// Returns `Ok(true)` if the credential was new and added,
    /// `Ok(false)` if it was a duplicate (silently skipped).
    pub fn add_credential(&mut self, cred: HarvestedCredential) -> Result<bool, HarvestError> {
        if cred.confidence < 0.0 || cred.confidence > 1.0 {
            return Err(HarvestError::InvalidCredential(
                "confidence must be in [0.0, 1.0]".into(),
            ));
        }
        if self.seen_hashes.contains(&cred.id) {
            return Ok(false);
        }
        self.seen_hashes.insert(cred.id.clone());
        self.credentials.push(cred);
        Ok(true)
    }

    /// Scans raw text for credential patterns and returns newly added credentials.
    ///
    /// Each match is constructed, hashed, and deduplicated before insertion.
    pub fn scan_text_for_credentials(
        &mut self,
        text: &str,
        source: CredentialSource,
        location: &str,
    ) -> Vec<HarvestedCredential> {
        let mut found = Vec::new();
        let patterns = self.patterns.clone();

        for pat in &patterns {
            for matched in simple_pattern_scan(text, &pat.pattern) {
                let value = value_from_match(pat.credential_type, &matched);
                let id = compute_credential_hash(pat.credential_type, &value);
                let access = classify_access_level(pat.credential_type, "");

                let cred = HarvestedCredential {
                    id,
                    credential_type: pat.credential_type,
                    source,
                    value,
                    access_level: access,
                    scope: String::new(),
                    confidence: pat.confidence,
                    location: location.to_string(),
                    validated: false,
                    tags: vec![pat.name.clone()],
                };

                if let Ok(true) = self.add_credential(cred.clone()) {
                    found.push(cred);
                }
            }
        }
        found
    }

    /// Returns a slice of all harvested credentials.
    pub fn get_credentials(&self) -> &[HarvestedCredential] {
        &self.credentials
    }

    /// Returns credentials from a specific source.
    pub fn get_by_source(&self, source: CredentialSource) -> Vec<&HarvestedCredential> {
        self.credentials
            .iter()
            .filter(|c| c.source == source)
            .collect()
    }

    /// Returns credentials of a specific type.
    pub fn get_by_type(&self, cred_type: CredentialType) -> Vec<&HarvestedCredential> {
        self.credentials
            .iter()
            .filter(|c| c.credential_type == cred_type)
            .collect()
    }

    /// Returns credentials at or above the given access level.
    pub fn get_by_access_level(&self, min_level: AccessLevel) -> Vec<&HarvestedCredential> {
        self.credentials
            .iter()
            .filter(|c| c.access_level >= min_level)
            .collect()
    }

    /// Scores a credential on a 0.0–10.0 scale.
    ///
    /// Base score from access level (Root=10, Admin=8, Elevated=6, Standard=4,
    /// ReadOnly=2, Unknown=1), multiplied by confidence, then 1.5x if validated.
    pub fn score_credential(cred: &HarvestedCredential) -> f64 {
        let base = match cred.access_level {
            AccessLevel::Root => 10.0,
            AccessLevel::Admin => 8.0,
            AccessLevel::Elevated => 6.0,
            AccessLevel::Standard => 4.0,
            AccessLevel::ReadOnly => 2.0,
            AccessLevel::Unknown => 1.0,
        };
        let score = base * cred.confidence;
        if cred.validated {
            score * 1.5
        } else {
            score
        }
    }

    /// Generates summary statistics for all harvested credentials.
    pub fn summarize(&self) -> HarvestSummary {
        let total = self.credentials.len();
        let duplicates = total.saturating_sub(self.seen_hashes.len());

        let by_source = count_by(&self.credentials, |c| c.source);
        let by_type = count_by(&self.credentials, |c| c.credential_type);
        let by_access = count_by(&self.credentials, |c| c.access_level);

        let highest = self
            .credentials
            .iter()
            .map(|c| c.access_level)
            .max()
            .unwrap_or(AccessLevel::Unknown);

        let validated_count = self.credentials.iter().filter(|c| c.validated).count();

        let critical = self
            .credentials
            .iter()
            .filter(|c| c.access_level >= AccessLevel::Admin)
            .map(|c| {
                format!(
                    "{} ({}) at {} — access: {}",
                    c.credential_type, c.source, c.location, c.access_level
                )
            })
            .collect();

        HarvestSummary {
            total_found: total,
            unique_credentials: self.seen_hashes.len(),
            duplicates_removed: duplicates,
            by_source,
            by_type,
            by_access_level: by_access,
            highest_access: highest,
            validated_count,
            critical_findings: critical,
        }
    }

    /// Removes exact duplicates (same id), returns count removed.
    pub fn deduplicate(&mut self) -> usize {
        let before = self.credentials.len();
        let mut seen = HashSet::new();
        self.credentials.retain(|c| seen.insert(c.id.clone()));
        self.seen_hashes = seen;
        before - self.credentials.len()
    }
}

fn count_by<K, F>(creds: &[HarvestedCredential], key_fn: F) -> Vec<(K, usize)>
where
    K: Eq + std::hash::Hash + Copy,
    F: Fn(&HarvestedCredential) -> K,
{
    let mut map = std::collections::HashMap::new();
    for c in creds {
        *map.entry(key_fn(c)).or_insert(0usize) += 1;
    }
    map.into_iter().collect()
}

/// Minimal pattern scanner that avoids pulling in the `regex` crate.
///
/// Handles the fixed/simple patterns used in credential detection via
/// substring search with lightweight character-class validation.
fn simple_pattern_scan(text: &str, pattern: &str) -> Vec<String> {
    let mut results = Vec::new();

    if pattern.starts_with("AKIA") {
        scan_aws_keys(text, &mut results);
    } else if pattern.starts_with("Bearer") {
        scan_bearer(text, &mut results);
    } else if pattern.starts_with("Basic") {
        scan_basic_auth(text, &mut results);
    } else if pattern.starts_with("eyJ") {
        scan_jwt(text, &mut results);
    } else if pattern.starts_with("(mysql") {
        scan_connection_strings(text, &mut results);
    } else if pattern.starts_with("-----BEGIN") {
        scan_private_keys(text, &mut results);
    } else if pattern.starts_with("password") {
        scan_password_assignments(text, &mut results);
    } else if pattern.starts_with("(secret") {
        scan_generic_secrets(text, &mut results);
    } else if pattern.starts_with("(api_key") {
        scan_api_keys(text, &mut results);
    }

    results
}

fn scan_aws_keys(text: &str, out: &mut Vec<String>) {
    let mut start = 0;
    while let Some(pos) = text[start..].find("AKIA") {
        let abs = start + pos;
        let candidate = &text[abs..];
        if candidate.len() >= 20 {
            let key = &candidate[..20];
            if key[4..]
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            {
                out.push(key.to_string());
            }
        }
        start = abs + 4;
    }
}

fn scan_bearer(text: &str, out: &mut Vec<String>) {
    let mut start = 0;
    while let Some(pos) = text[start..].find("Bearer ") {
        let abs = start + pos + 7;
        let token_end = text[abs..]
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '_' && c != '-')
            .map(|e| abs + e)
            .unwrap_or(text.len());
        if token_end > abs {
            out.push(format!("Bearer {}", &text[abs..token_end]));
        }
        start = token_end;
    }
}

fn scan_basic_auth(text: &str, out: &mut Vec<String>) {
    let mut start = 0;
    while let Some(pos) = text[start..].find("Basic ") {
        let abs = start + pos + 6;
        let end = text[abs..]
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '+' && c != '/' && c != '=')
            .map(|e| abs + e)
            .unwrap_or(text.len());
        if end > abs {
            out.push(format!("Basic {}", &text[abs..end]));
        }
        start = end;
    }
}

fn scan_jwt(text: &str, out: &mut Vec<String>) {
    let mut start = 0;
    while let Some(pos) = text[start..].find("eyJ") {
        let abs = start + pos;
        let rest = &text[abs..];
        let end = rest
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '_' && c != '-')
            .unwrap_or(rest.len());
        let candidate = &rest[..end];
        let dot_count = candidate.chars().filter(|&c| c == '.').count();
        if dot_count >= 2 && candidate.len() > 20 {
            out.push(candidate.to_string());
        }
        start = abs + end.max(3);
    }
}

fn scan_connection_strings(text: &str, out: &mut Vec<String>) {
    for prefix in &["mysql://", "postgres://", "mongodb://", "redis://"] {
        let mut start = 0;
        while let Some(pos) = text[start..].find(prefix) {
            let abs = start + pos;
            let end = text[abs..]
                .find(|c: char| c.is_ascii_whitespace())
                .map(|e| abs + e)
                .unwrap_or(text.len());
            if end > abs {
                out.push(text[abs..end].to_string());
            }
            start = end;
        }
    }
}

fn scan_private_keys(text: &str, out: &mut Vec<String>) {
    let mut start = 0;
    while let Some(pos) = text[start..].find("-----BEGIN ") {
        let abs = start + pos;
        let rest = &text[abs..];
        if rest.contains("PRIVATE KEY-----") {
            let header_end = rest
                .find("-----\n")
                .or_else(|| rest.find("-----\r"))
                .map(|e| e + 6)
                .unwrap_or_else(|| rest.find("PRIVATE KEY-----").unwrap() + 16);
            out.push(rest[..header_end.min(rest.len())].trim().to_string());
        }
        start = abs + 11;
    }
}

fn scan_password_assignments(text: &str, out: &mut Vec<String>) {
    let lower = text.to_ascii_lowercase();
    let mut start = 0;
    while let Some(pos) = lower[start..].find("password") {
        let abs = start + pos;
        let after = abs + 8;
        if after >= text.len() {
            break;
        }
        let rest = &text[after..];
        let delim_pos = rest.find(['=', ':']);
        if let Some(dp) = delim_pos
            && dp <= 3
        {
            let val_start = after + dp + 1;
            let val_text = text[val_start..].trim_start();
            let val_offset = text.len() - val_text.len();
            let val_end = val_text
                .find(|c: char| c.is_ascii_whitespace() || c == '"' || c == '\'')
                .unwrap_or(val_text.len());
            if val_end > 0 {
                let full_match = text[abs..val_offset + val_end].to_string();
                out.push(full_match);
            }
        }
        start = after;
    }
}

fn scan_generic_secrets(text: &str, out: &mut Vec<String>) {
    let lower = text.to_ascii_lowercase();
    for keyword in &["secret", "token", "key", "password", "passwd", "pwd"] {
        let mut start = 0;
        while let Some(pos) = lower[start..].find(keyword) {
            let abs = start + pos;
            let after_kw = abs + keyword.len();
            if after_kw >= text.len() {
                break;
            }
            let rest = &text[after_kw..];
            let trimmed = rest.trim_start();
            let trim_offset = rest.len() - trimmed.len();
            if trimmed.starts_with('=') || trimmed.starts_with(':') {
                let val_start = after_kw + trim_offset + 1;
                let val_text = text[val_start..].trim_start();
                let val_real_start = text.len() - val_text.len();
                let val_end = val_text
                    .find(|c: char| c.is_ascii_whitespace())
                    .unwrap_or(val_text.len());
                if val_end >= 8 {
                    let full = text[abs..val_real_start + val_end].to_string();
                    out.push(full);
                }
            }
            start = after_kw;
        }
    }
}

fn scan_api_keys(text: &str, out: &mut Vec<String>) {
    let lower = text.to_ascii_lowercase();
    for keyword in &["api_key", "apikey", "api-key", "secret_key"] {
        let mut start = 0;
        while let Some(pos) = lower[start..].find(keyword) {
            let abs = start + pos;
            let after_kw = abs + keyword.len();
            if after_kw >= text.len() {
                break;
            }
            let rest = &text[after_kw..];
            let trimmed = rest.trim_start();
            let trim_offset = rest.len() - trimmed.len();
            if trimmed.starts_with('=') || trimmed.starts_with(':') {
                let val_start = after_kw + trim_offset + 1;
                let val_text = text[val_start..].trim_start();
                let val_real_start = text.len() - val_text.len();
                let val_end = val_text
                    .find(|c: char| !c.is_ascii_alphanumeric())
                    .unwrap_or(val_text.len());
                if val_end >= 32 {
                    let full = text[abs..val_real_start + val_end].to_string();
                    out.push(full);
                }
            }
            start = after_kw;
        }
    }
}

fn value_from_match(cred_type: CredentialType, matched: &str) -> CredentialValue {
    match cred_type {
        CredentialType::BearerToken | CredentialType::JwtToken | CredentialType::OAuthToken => {
            CredentialValue::Token(matched.to_string())
        }
        CredentialType::BasicAuthHeader => CredentialValue::Header {
            name: "Authorization".to_string(),
            value: matched.to_string(),
        },
        CredentialType::DatabaseConnectionString => {
            CredentialValue::ConnectionString(matched.to_string())
        }
        CredentialType::PrivateKey | CredentialType::SshKey => CredentialValue::KeyPair {
            public_key: String::new(),
            private_key: matched.to_string(),
        },
        CredentialType::UsernamePassword => CredentialValue::Pair {
            username: String::new(),
            password: matched.to_string(),
        },
        _ => CredentialValue::Token(matched.to_string()),
    }
}
