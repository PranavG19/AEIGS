use std::collections::HashMap;
use std::fmt;

/// SHA1 prefix length for HIBP k-anonymity model.
const HIBP_PREFIX_LEN: usize = 5;

/// Risk severity for breach findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BreachSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for BreachSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "Info"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// Type of credential exposure found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExposureType {
    PasswordHash,
    PlaintextPassword,
    EmailOnly,
    ComboList,
    PasteExposure,
    DatabaseDump,
}

impl fmt::Display for ExposureType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PasswordHash => write!(f, "Password Hash"),
            Self::PlaintextPassword => write!(f, "Plaintext Password"),
            Self::EmailOnly => write!(f, "Email Only"),
            Self::ComboList => write!(f, "Combo List"),
            Self::PasteExposure => write!(f, "Paste Exposure"),
            Self::DatabaseDump => write!(f, "Database Dump"),
        }
    }
}

/// HIBP k-anonymity query result for a single hash suffix match.
#[derive(Debug, Clone, PartialEq)]
pub struct HibpSuffixMatch {
    pub hash_suffix: String,
    pub occurrence_count: u64,
}

/// Result of querying the HIBP k-anonymity API for a password.
#[derive(Debug, Clone, PartialEq)]
pub struct HibpPasswordResult {
    pub sha1_prefix: String,
    pub sha1_full: String,
    pub found: bool,
    pub occurrence_count: u64,
    pub severity: BreachSeverity,
}

/// A single breach record for a credential.
#[derive(Debug, Clone, PartialEq)]
pub struct BreachRecord {
    pub breach_name: String,
    pub breach_date: String,
    pub exposure_type: ExposureType,
    pub data_classes: Vec<String>,
    pub is_verified: bool,
    pub is_sensitive: bool,
    pub pwn_count: u64,
}

/// Correlation between email and known breaches.
#[derive(Debug, Clone, PartialEq)]
pub struct EmailBreachCorrelation {
    pub email: String,
    pub domain: String,
    pub breaches: Vec<BreachRecord>,
    pub total_exposures: usize,
    pub severity: BreachSeverity,
    pub password_reuse_likelihood: f64,
    pub recommended_actions: Vec<String>,
}

/// Combo credential entry for checking.
#[derive(Debug, Clone, PartialEq)]
pub struct ComboEntry {
    pub email: String,
    pub password_or_hash: String,
    pub source: Option<String>,
}

/// Result of a combo check against HIBP.
#[derive(Debug, Clone, PartialEq)]
pub struct ComboCheckResult {
    pub email: String,
    pub password_compromised: bool,
    pub password_occurrences: u64,
    pub email_in_breaches: Vec<String>,
    pub severity: BreachSeverity,
}

/// Full breach correlation report for an organization.
#[derive(Debug, Clone, PartialEq)]
pub struct BreachCorrelationReport {
    pub target_domain: String,
    pub total_emails_checked: usize,
    pub total_compromised: usize,
    pub breach_timeline: Vec<(String, usize)>,
    pub severity_distribution: HashMap<BreachSeverity, usize>,
    pub top_breaches: Vec<(String, usize)>,
    pub email_correlations: Vec<EmailBreachCorrelation>,
    pub combo_results: Vec<ComboCheckResult>,
    pub overall_risk: BreachSeverity,
}

/// Computes SHA1 hash of a password, returns uppercase hex string.
pub fn sha1_hash(password: &str) -> String {
    let mut hasher = Sha1Hasher::new();
    hasher.update(password.as_bytes());
    hasher.finalize_hex().to_uppercase()
}

/// Extracts the k-anonymity prefix (first 5 hex chars) from a SHA1 hash.
pub fn extract_prefix(sha1_hex: &str) -> &str {
    &sha1_hex[..HIBP_PREFIX_LEN]
}

/// Extracts the suffix (remaining chars after prefix) from a SHA1 hash.
pub fn extract_suffix(sha1_hex: &str) -> &str {
    &sha1_hex[HIBP_PREFIX_LEN..]
}

/// Parses the HIBP range API response into suffix matches.
/// Response format: SUFFIX:COUNT\r\n per line.
pub fn parse_hibp_range_response(response_body: &str) -> Vec<HibpSuffixMatch> {
    response_body
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() != 2 {
                return None;
            }
            let hash_suffix = parts[0].trim().to_uppercase();
            let count = parts[1].trim().parse::<u64>().ok()?;
            Some(HibpSuffixMatch {
                hash_suffix,
                occurrence_count: count,
            })
        })
        .collect()
}

/// Checks a password against a parsed HIBP range response.
pub fn check_password_in_range(password: &str, range_response: &str) -> HibpPasswordResult {
    let sha1_full = sha1_hash(password);
    let prefix = extract_prefix(&sha1_full).to_string();
    let target_suffix = extract_suffix(&sha1_full).to_uppercase();

    let matches = parse_hibp_range_response(range_response);
    let found_match = matches.iter().find(|m| m.hash_suffix == target_suffix);

    let (found, count) = match found_match {
        Some(m) => (true, m.occurrence_count),
        None => (false, 0),
    };

    let severity = classify_password_severity(count);

    HibpPasswordResult {
        sha1_prefix: prefix,
        sha1_full,
        found,
        occurrence_count: count,
        severity,
    }
}

/// Classifies severity based on breach occurrence count.
pub fn classify_password_severity(occurrence_count: u64) -> BreachSeverity {
    match occurrence_count {
        0 => BreachSeverity::Info,
        1..=10 => BreachSeverity::Low,
        11..=100 => BreachSeverity::Medium,
        101..=10_000 => BreachSeverity::High,
        _ => BreachSeverity::Critical,
    }
}

/// Builds the HIBP range API URL from a SHA1 prefix.
pub fn build_hibp_range_url(sha1_prefix: &str) -> String {
    format!("https://api.pwnedpasswords.com/range/{}", sha1_prefix)
}

/// Builds the HIBP breached account API URL.
pub fn build_hibp_breach_url(email: &str) -> String {
    format!(
        "https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=false",
        email
    )
}

/// Parses a HIBP breach API JSON response into breach records.
pub fn parse_breach_response(json_body: &str) -> Vec<BreachRecord> {
    let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(json_body) else {
        return Vec::new();
    };

    entries
        .iter()
        .filter_map(|entry| {
            let name = entry.get("Name")?.as_str()?.to_string();
            let date = entry
                .get("BreachDate")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let data_classes: Vec<String> = entry
                .get("DataClasses")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let is_verified = entry
                .get("IsVerified")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let is_sensitive = entry
                .get("IsSensitive")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let pwn_count = entry.get("PwnCount").and_then(|v| v.as_u64()).unwrap_or(0);

            let exposure_type = classify_exposure_type(&data_classes);

            Some(BreachRecord {
                breach_name: name,
                breach_date: date,
                exposure_type,
                data_classes,
                is_verified,
                is_sensitive,
                pwn_count,
            })
        })
        .collect()
}

/// Classifies the type of exposure from data classes.
pub fn classify_exposure_type(data_classes: &[String]) -> ExposureType {
    let lower: Vec<String> = data_classes.iter().map(|s| s.to_lowercase()).collect();
    let has_passwords = lower.iter().any(|s| s.contains("password"));
    let has_hashes = lower.iter().any(|s| s.contains("hash"));
    let has_email = lower.iter().any(|s| s.contains("email"));

    if has_passwords && !has_hashes {
        ExposureType::PlaintextPassword
    } else if has_hashes {
        ExposureType::PasswordHash
    } else if has_email {
        ExposureType::EmailOnly
    } else {
        ExposureType::DatabaseDump
    }
}

/// Correlates breaches for a single email address.
pub fn correlate_email_breaches(email: &str, breach_json: &str) -> EmailBreachCorrelation {
    let domain = email.split('@').nth(1).unwrap_or("unknown").to_string();

    let breaches = parse_breach_response(breach_json);
    let total_exposures = breaches.len();

    let has_password_exposure = breaches.iter().any(|b| {
        matches!(
            b.exposure_type,
            ExposureType::PlaintextPassword | ExposureType::PasswordHash
        )
    });

    let password_reuse_likelihood = if has_password_exposure {
        let password_breaches = breaches
            .iter()
            .filter(|b| {
                matches!(
                    b.exposure_type,
                    ExposureType::PlaintextPassword | ExposureType::PasswordHash
                )
            })
            .count();
        (password_breaches as f64 / 10.0).min(1.0)
    } else {
        0.0
    };

    let severity = match total_exposures {
        0 => BreachSeverity::Info,
        1..=2 => BreachSeverity::Low,
        3..=5 => BreachSeverity::Medium,
        6..=10 => BreachSeverity::High,
        _ => BreachSeverity::Critical,
    };

    let mut recommended_actions = Vec::new();
    if has_password_exposure {
        recommended_actions.push("Force password reset for this account".to_string());
        recommended_actions.push("Check for credential reuse across services".to_string());
    }
    if total_exposures > 5 {
        recommended_actions.push("Enable MFA immediately".to_string());
        recommended_actions.push("Consider account replacement with new email".to_string());
    }
    if breaches.iter().any(|b| b.is_sensitive) {
        recommended_actions.push("Monitor for targeted phishing attempts".to_string());
    }

    EmailBreachCorrelation {
        email: email.to_string(),
        domain,
        breaches,
        total_exposures,
        severity,
        password_reuse_likelihood,
        recommended_actions,
    }
}

/// Checks a combo list entry (email + password) against HIBP data.
pub fn check_combo_entry(
    entry: &ComboEntry,
    range_response: &str,
    breach_json: &str,
) -> ComboCheckResult {
    let pw_result = check_password_in_range(&entry.password_or_hash, range_response);
    let breaches = parse_breach_response(breach_json);
    let breach_names: Vec<String> = breaches.iter().map(|b| b.breach_name.clone()).collect();

    let severity = if pw_result.found && !breach_names.is_empty() {
        BreachSeverity::Critical
    } else if pw_result.found {
        BreachSeverity::High
    } else if !breach_names.is_empty() {
        BreachSeverity::Medium
    } else {
        BreachSeverity::Info
    };

    ComboCheckResult {
        email: entry.email.clone(),
        password_compromised: pw_result.found,
        password_occurrences: pw_result.occurrence_count,
        email_in_breaches: breach_names,
        severity,
    }
}

/// Generates a breach timeline from correlations, sorted by date.
pub fn build_breach_timeline(correlations: &[EmailBreachCorrelation]) -> Vec<(String, usize)> {
    let mut timeline: HashMap<String, usize> = HashMap::new();
    for corr in correlations {
        for breach in &corr.breaches {
            *timeline.entry(breach.breach_date.clone()).or_insert(0) += 1;
        }
    }
    let mut sorted: Vec<(String, usize)> = timeline.into_iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    sorted
}

/// Computes the overall risk for a breach correlation report.
pub fn compute_overall_risk(
    correlations: &[EmailBreachCorrelation],
    combo_results: &[ComboCheckResult],
) -> BreachSeverity {
    let max_email = correlations
        .iter()
        .map(|c| c.severity)
        .max()
        .unwrap_or(BreachSeverity::Info);
    let max_combo = combo_results
        .iter()
        .map(|c| c.severity)
        .max()
        .unwrap_or(BreachSeverity::Info);

    max_email.max(max_combo)
}

/// Builds a full breach correlation report for a domain.
pub fn build_correlation_report(
    target_domain: &str,
    correlations: Vec<EmailBreachCorrelation>,
    combo_results: Vec<ComboCheckResult>,
) -> BreachCorrelationReport {
    let total_emails_checked = correlations.len();
    let total_compromised = correlations
        .iter()
        .filter(|c| c.total_exposures > 0)
        .count();

    let breach_timeline = build_breach_timeline(&correlations);

    let mut severity_dist: HashMap<BreachSeverity, usize> = HashMap::new();
    for corr in &correlations {
        *severity_dist.entry(corr.severity).or_insert(0) += 1;
    }

    let mut breach_counts: HashMap<String, usize> = HashMap::new();
    for corr in &correlations {
        for breach in &corr.breaches {
            *breach_counts.entry(breach.breach_name.clone()).or_insert(0) += 1;
        }
    }
    let mut top_breaches: Vec<(String, usize)> = breach_counts.into_iter().collect();
    top_breaches.sort_by(|a, b| b.1.cmp(&a.1));
    top_breaches.truncate(10);

    let overall_risk = compute_overall_risk(&correlations, &combo_results);

    BreachCorrelationReport {
        target_domain: target_domain.to_string(),
        total_emails_checked,
        total_compromised,
        breach_timeline,
        severity_distribution: severity_dist,
        top_breaches,
        email_correlations: correlations,
        combo_results,
        overall_risk,
    }
}

/// Minimal SHA1 implementation for HIBP k-anonymity (no external dep).
struct Sha1Hasher {
    state: [u32; 5],
    buffer: Vec<u8>,
    total_len: u64,
}

impl Sha1Hasher {
    fn new() -> Self {
        Self {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            buffer: Vec::new(),
            total_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
        self.total_len += data.len() as u64;

        while self.buffer.len() >= 64 {
            let block: Vec<u8> = self.buffer.drain(..64).collect();
            self.process_block(&block);
        }
    }

    fn process_block(&mut self, block: &[u8]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = self.state;

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }

    fn finalize_hex(mut self) -> String {
        let bit_len = self.total_len * 8;
        self.buffer.push(0x80);
        while self.buffer.len() % 64 != 56 {
            self.buffer.push(0);
        }
        self.buffer.extend_from_slice(&bit_len.to_be_bytes());

        while self.buffer.len() >= 64 {
            let block: Vec<u8> = self.buffer.drain(..64).collect();
            self.process_block(&block);
        }

        format!(
            "{:08x}{:08x}{:08x}{:08x}{:08x}",
            self.state[0], self.state[1], self.state[2], self.state[3], self.state[4]
        )
    }
}
