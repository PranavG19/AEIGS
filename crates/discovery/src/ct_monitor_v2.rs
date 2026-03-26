use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Core types — certificate identity and metadata
// ---------------------------------------------------------------------------

/// Issuer metadata extracted from a crt.sh certificate entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertIssuer {
    pub organization: String,
    pub common_name: String,
    pub country: String,
}

impl CertIssuer {
    pub fn parse_from_dn(dn: &str) -> Self {
        let org = extract_dn_field(dn, "O");
        let cn = extract_dn_field(dn, "CN");
        let country = extract_dn_field(dn, "C");
        Self {
            organization: org,
            common_name: cn,
            country,
        }
    }

    pub fn is_known_ca(&self) -> bool {
        let known = [
            "let's encrypt",
            "digicert",
            "comodo",
            "sectigo",
            "globalsign",
            "godaddy",
            "entrust",
            "geotrust",
            "thawte",
            "verisign",
            "amazon",
            "google trust services",
            "cloudflare",
            "zerossl",
            "buypass",
            "actalis",
            "certum",
            "ssl.com",
            "starfield",
            "microsoft",
            "apple",
            "trustwave",
            "rapidssl",
        ];
        let org_lower = self.organization.to_lowercase();
        let cn_lower = self.common_name.to_lowercase();
        known
            .iter()
            .any(|ca| org_lower.contains(ca) || cn_lower.contains(ca))
    }
}

impl fmt::Display for CertIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.organization.is_empty() {
            write!(f, "{}", self.common_name)
        } else {
            write!(f, "{} ({})", self.common_name, self.organization)
        }
    }
}

/// Full certificate information parsed from a crt.sh JSON entry.
#[derive(Debug, Clone, PartialEq)]
pub struct CertInfo {
    pub serial: String,
    pub fingerprint: String,
    pub subject_cn: String,
    pub sans: Vec<String>,
    pub issuer: CertIssuer,
    pub not_before: String,
    pub not_after: String,
    pub is_wildcard: bool,
    pub crtsh_id: i64,
}

impl CertInfo {
    pub fn all_domains(&self) -> Vec<String> {
        let mut domains = Vec::with_capacity(1 + self.sans.len());
        if !self.subject_cn.is_empty() {
            domains.push(self.subject_cn.clone());
        }
        for san in &self.sans {
            if !domains.contains(san) {
                domains.push(san.clone());
            }
        }
        domains
    }

    pub fn san_count(&self) -> usize {
        self.sans.len()
    }
}

impl fmt::Display for CertInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Cert[{}] CN={} issuer={} valid={}..{} SANs={}",
            truncate_serial(&self.serial, 12),
            self.subject_cn,
            self.issuer,
            self.not_before,
            self.not_after,
            self.sans.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Alert and risk classification
// ---------------------------------------------------------------------------

/// Type of certificate transparency alert raised during monitoring.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CertAlertType {
    NewCert,
    RevokedCert,
    ExpiringSoon,
    SuspiciousCert,
    WildcardCert,
    PhishingCert,
}

impl fmt::Display for CertAlertType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::NewCert => "new-cert",
            Self::RevokedCert => "revoked-cert",
            Self::ExpiringSoon => "expiring-soon",
            Self::SuspiciousCert => "suspicious-cert",
            Self::WildcardCert => "wildcard-cert",
            Self::PhishingCert => "phishing-cert",
        };
        write!(f, "{label}")
    }
}

/// Risk factors identified during certificate risk assessment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CertRisk {
    SelfSigned,
    Expired,
    WeakKey,
    UnknownCA,
    TooManySans,
    ShortLived,
    WildcardAbuse,
    PhishingDomain,
}

impl fmt::Display for CertRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::SelfSigned => "self-signed",
            Self::Expired => "expired",
            Self::WeakKey => "weak-key",
            Self::UnknownCA => "unknown-ca",
            Self::TooManySans => "too-many-sans",
            Self::ShortLived => "short-lived",
            Self::WildcardAbuse => "wildcard-abuse",
            Self::PhishingDomain => "phishing-domain",
        };
        write!(f, "{label}")
    }
}

/// A single alert generated during CT monitoring.
#[derive(Debug, Clone, PartialEq)]
pub struct CertAlert {
    pub alert_type: CertAlertType,
    pub cert: CertInfo,
    pub description: String,
    pub severity: AlertSeverity,
}

impl fmt::Display for CertAlert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} — {} ({})",
            self.severity, self.alert_type, self.description, self.cert.subject_cn
        )
    }
}

/// Severity level for alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Query construction
// ---------------------------------------------------------------------------

/// Search mode for crt.sh queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrtShSearchMode {
    Domain,
    Wildcard,
    Organization,
}

impl fmt::Display for CrtShSearchMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Domain => "domain",
            Self::Wildcard => "wildcard",
            Self::Organization => "organization",
        };
        write!(f, "{label}")
    }
}

/// Parameterized crt.sh query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrtShQuery {
    pub search_term: String,
    pub mode: CrtShSearchMode,
    pub exclude_expired: bool,
}

impl CrtShQuery {
    pub fn domain(domain: &str) -> Self {
        Self {
            search_term: domain.to_lowercase(),
            mode: CrtShSearchMode::Domain,
            exclude_expired: false,
        }
    }

    pub fn wildcard(domain: &str) -> Self {
        Self {
            search_term: domain.to_lowercase(),
            mode: CrtShSearchMode::Wildcard,
            exclude_expired: false,
        }
    }

    pub fn organization(org: &str) -> Self {
        Self {
            search_term: org.to_string(),
            mode: CrtShSearchMode::Organization,
            exclude_expired: false,
        }
    }

    pub fn with_exclude_expired(mut self, exclude: bool) -> Self {
        self.exclude_expired = exclude;
        self
    }
}

impl fmt::Display for CrtShQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "crt.sh query [{}]: {}", self.mode, self.search_term)
    }
}

/// Build the full crt.sh URL for a given query.
pub fn build_crtsh_query_url(query: &CrtShQuery) -> String {
    let search_param = match query.mode {
        CrtShSearchMode::Domain => format!("%.{}", query.search_term),
        CrtShSearchMode::Wildcard => format!("*.{}", query.search_term),
        CrtShSearchMode::Organization => format!("O={}", query.search_term),
    };

    let mut url = format!("https://crt.sh/?q={search_param}&output=json");
    if query.exclude_expired {
        url.push_str("&exclude=expired");
    }
    url
}

// ---------------------------------------------------------------------------
// JSON response parsing
// ---------------------------------------------------------------------------

/// Raw JSON entry from crt.sh API response.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CrtShJsonEntry {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub issuer_ca_id: i64,
    #[serde(default)]
    pub issuer_name: String,
    #[serde(default, alias = "common_name")]
    pub common_name: String,
    #[serde(default, alias = "name_value")]
    pub name_value: String,
    #[serde(default)]
    pub serial_number: String,
    #[serde(default)]
    pub not_before: String,
    #[serde(default)]
    pub not_after: String,
    #[serde(default)]
    pub entry_timestamp: String,
    #[serde(default)]
    pub result_count: i64,
}

/// Errors from CT monitor v2 operations.
#[derive(Debug)]
pub enum CtMonitorV2Error {
    JsonParse(serde_json::Error),
    InvalidInput(String),
}

impl fmt::Display for CtMonitorV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JsonParse(e) => write!(f, "JSON parse error: {e}"),
            Self::InvalidInput(msg) => write!(f, "Invalid input: {msg}"),
        }
    }
}

impl std::error::Error for CtMonitorV2Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::JsonParse(e) => Some(e),
            Self::InvalidInput(_) => None,
        }
    }
}

/// Parse a raw crt.sh JSON response body into a list of `CertInfo` structs.
pub fn parse_crtsh_response(json_body: &str) -> Result<Vec<CertInfo>, CtMonitorV2Error> {
    let entries: Vec<CrtShJsonEntry> =
        serde_json::from_str(json_body).map_err(CtMonitorV2Error::JsonParse)?;

    let mut certs = Vec::with_capacity(entries.len());
    for entry in entries {
        let issuer = CertIssuer::parse_from_dn(&entry.issuer_name);
        let sans = extract_sans_from_cert(&entry.name_value);
        let cn = entry.common_name.trim().to_string();
        let is_wildcard = cn.starts_with("*.") || sans.iter().any(|s| s.starts_with("*."));

        certs.push(CertInfo {
            serial: entry.serial_number,
            fingerprint: format!("crtsh:{}", entry.id),
            subject_cn: cn,
            sans,
            issuer,
            not_before: entry.not_before,
            not_after: entry.not_after,
            is_wildcard,
            crtsh_id: entry.id,
        });
    }
    Ok(certs)
}

/// Extract Subject Alternative Names from the crt.sh `name_value` field.
///
/// crt.sh encodes SANs as newline-separated values, sometimes with leading
/// whitespace or wildcard prefixes.
pub fn extract_sans_from_cert(name_value: &str) -> Vec<String> {
    let mut sans = Vec::new();
    for line in name_value.split('\n') {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            sans.push(trimmed.to_string());
        }
    }
    sans.sort();
    sans.dedup();
    sans
}

// ---------------------------------------------------------------------------
// Certificate analysis
// ---------------------------------------------------------------------------

/// Analysis result for a single certificate.
#[derive(Debug, Clone, PartialEq)]
pub struct CertAnalysis {
    pub cert: CertInfo,
    pub risks: Vec<CertRisk>,
    pub alerts: Vec<CertAlert>,
    pub risk_score: f64,
}

/// Analyze a certificate for risk factors and generate alerts.
///
/// `reference_date` is an ISO-8601 date string (YYYY-MM-DD or full timestamp)
/// used for expired/expiring-soon checks. `monitored_domain` is the domain
/// being monitored — used for phishing detection.
pub fn analyze_certificate(
    cert: &CertInfo,
    reference_date: &str,
    monitored_domain: &str,
) -> CertAnalysis {
    let mut risks = Vec::new();
    let mut alerts = Vec::new();

    let ref_date_prefix = &reference_date[..reference_date.len().min(10)];

    if is_cert_expired(cert, reference_date) {
        risks.push(CertRisk::Expired);
        alerts.push(CertAlert {
            alert_type: CertAlertType::SuspiciousCert,
            cert: cert.clone(),
            description: format!("Certificate expired (not_after={})", cert.not_after),
            severity: AlertSeverity::High,
        });
    } else if is_cert_expiring_soon(cert, ref_date_prefix, 30) {
        alerts.push(CertAlert {
            alert_type: CertAlertType::ExpiringSoon,
            cert: cert.clone(),
            description: format!(
                "Certificate expiring within 30 days (not_after={})",
                cert.not_after
            ),
            severity: AlertSeverity::Medium,
        });
    }

    if is_self_signed(cert) {
        risks.push(CertRisk::SelfSigned);
        alerts.push(CertAlert {
            alert_type: CertAlertType::SuspiciousCert,
            cert: cert.clone(),
            description: "Certificate appears self-signed".to_string(),
            severity: AlertSeverity::High,
        });
    }

    if !cert.issuer.is_known_ca() {
        risks.push(CertRisk::UnknownCA);
        alerts.push(CertAlert {
            alert_type: CertAlertType::SuspiciousCert,
            cert: cert.clone(),
            description: format!("Unknown CA: {}", cert.issuer),
            severity: AlertSeverity::Medium,
        });
    }

    if cert.san_count() > 100 {
        risks.push(CertRisk::TooManySans);
        alerts.push(CertAlert {
            alert_type: CertAlertType::SuspiciousCert,
            cert: cert.clone(),
            description: format!("Excessive SANs: {} entries", cert.san_count()),
            severity: AlertSeverity::Medium,
        });
    }

    if is_short_lived(cert, 7) {
        risks.push(CertRisk::ShortLived);
        alerts.push(CertAlert {
            alert_type: CertAlertType::SuspiciousCert,
            cert: cert.clone(),
            description: "Short-lived certificate (< 7 days validity)".to_string(),
            severity: AlertSeverity::Low,
        });
    }

    if cert.is_wildcard {
        risks.push(CertRisk::WildcardAbuse);
        alerts.push(CertAlert {
            alert_type: CertAlertType::WildcardCert,
            cert: cert.clone(),
            description: format!("Wildcard certificate: {}", cert.subject_cn),
            severity: AlertSeverity::Low,
        });
    }

    let phishing = detect_phishing_cert(cert, monitored_domain);
    if phishing.is_phishing {
        risks.push(CertRisk::PhishingDomain);
        alerts.push(CertAlert {
            alert_type: CertAlertType::PhishingCert,
            cert: cert.clone(),
            description: format!(
                "Possible phishing cert — similarity={:.2} domain={}",
                phishing.max_similarity, phishing.closest_domain
            ),
            severity: AlertSeverity::Critical,
        });
    }

    let risk_score = compute_risk_score(&risks);

    CertAnalysis {
        cert: cert.clone(),
        risks,
        alerts,
        risk_score,
    }
}

/// Determine whether a certificate has expired relative to a reference date.
///
/// Comparison is lexicographic on the first 10 characters (YYYY-MM-DD prefix).
pub fn is_cert_expired(cert: &CertInfo, reference_date: &str) -> bool {
    let not_after_prefix = extract_date_prefix(&cert.not_after);
    let ref_prefix = extract_date_prefix(reference_date);
    not_after_prefix < ref_prefix
}

fn is_cert_expiring_soon(cert: &CertInfo, ref_date_prefix: &str, days_threshold: u32) -> bool {
    let not_after_prefix = extract_date_prefix(&cert.not_after);
    if not_after_prefix.as_str() <= ref_date_prefix {
        return false;
    }
    let days_remaining = estimate_day_diff(ref_date_prefix, &not_after_prefix);
    days_remaining <= days_threshold
}

fn is_self_signed(cert: &CertInfo) -> bool {
    let cn_lower = cert.subject_cn.to_lowercase();
    let issuer_cn_lower = cert.issuer.common_name.to_lowercase();
    !cn_lower.is_empty() && cn_lower == issuer_cn_lower && cert.issuer.organization.is_empty()
}

fn is_short_lived(cert: &CertInfo, max_days: u32) -> bool {
    let start = extract_date_prefix(&cert.not_before);
    let end = extract_date_prefix(&cert.not_after);
    if start.is_empty() || end.is_empty() {
        return false;
    }
    let diff = estimate_day_diff(&start, &end);
    diff > 0 && diff <= max_days
}

fn compute_risk_score(risks: &[CertRisk]) -> f64 {
    let mut score = 0.0_f64;
    for risk in risks {
        score += match risk {
            CertRisk::SelfSigned => 9.0,
            CertRisk::Expired => 8.0,
            CertRisk::WeakKey => 7.5,
            CertRisk::UnknownCA => 6.0,
            CertRisk::PhishingDomain => 9.5,
            CertRisk::TooManySans => 4.0,
            CertRisk::ShortLived => 3.0,
            CertRisk::WildcardAbuse => 2.5,
        };
    }
    score.min(10.0)
}

// ---------------------------------------------------------------------------
// Risk assessment (standalone function for external callers)
// ---------------------------------------------------------------------------

/// Assess risk factors for a certificate without generating alerts.
pub fn assess_cert_risk(cert: &CertInfo, reference_date: &str) -> Vec<CertRisk> {
    let mut risks = Vec::new();

    if is_cert_expired(cert, reference_date) {
        risks.push(CertRisk::Expired);
    }
    if is_self_signed(cert) {
        risks.push(CertRisk::SelfSigned);
    }
    if !cert.issuer.is_known_ca() {
        risks.push(CertRisk::UnknownCA);
    }
    if cert.san_count() > 100 {
        risks.push(CertRisk::TooManySans);
    }
    if is_short_lived(cert, 7) {
        risks.push(CertRisk::ShortLived);
    }
    if cert.is_wildcard {
        risks.push(CertRisk::WildcardAbuse);
    }

    risks
}

// ---------------------------------------------------------------------------
// Phishing / typosquat detection
// ---------------------------------------------------------------------------

/// Result of phishing analysis for a certificate.
#[derive(Debug, Clone, PartialEq)]
pub struct PhishingDetection {
    pub is_phishing: bool,
    pub max_similarity: f64,
    pub closest_domain: String,
    pub suspicious_domains: Vec<String>,
}

/// Detect whether a certificate may be used for phishing/typosquatting
/// against `monitored_domain`.
///
/// Checks the subject CN and all SANs for similarity to the monitored domain.
/// A similarity score >= 0.75 (but < 1.0 exact match) triggers a phishing flag.
pub fn detect_phishing_cert(cert: &CertInfo, monitored_domain: &str) -> PhishingDetection {
    let monitored_lower = monitored_domain.to_lowercase();
    let monitored_base = strip_wildcard(&monitored_lower);
    let mut max_similarity = 0.0_f64;
    let mut closest_domain = String::new();
    let mut suspicious = Vec::new();

    let all_domains = cert.all_domains();
    for domain in all_domains {
        let domain_lower = domain.to_lowercase();
        let domain_base = strip_wildcard(&domain_lower);

        if domain_base == monitored_base {
            continue;
        }

        if domain_base.ends_with(&format!(".{monitored_base}"))
            || monitored_base.ends_with(&format!(".{domain_base}"))
        {
            continue;
        }

        let sim = calculate_domain_similarity(&domain_base, &monitored_base);
        if sim > max_similarity {
            max_similarity = sim;
            closest_domain = domain_base.clone();
        }
        if sim >= PHISHING_SIMILARITY_THRESHOLD {
            suspicious.push(domain_base);
        }
    }

    PhishingDetection {
        is_phishing: max_similarity >= PHISHING_SIMILARITY_THRESHOLD,
        max_similarity,
        closest_domain,
        suspicious_domains: suspicious,
    }
}

const PHISHING_SIMILARITY_THRESHOLD: f64 = 0.75;

/// Calculate similarity between two domain strings.
///
/// Uses a combination of Levenshtein distance (normalised) and bigram
/// overlap (Dice coefficient). Final score = 0.6 * levenshtein_sim + 0.4 * dice.
pub fn calculate_domain_similarity(domain_a: &str, domain_b: &str) -> f64 {
    if domain_a.is_empty() && domain_b.is_empty() {
        return 0.0;
    }
    if domain_a == domain_b {
        return 1.0;
    }
    if domain_a.is_empty() || domain_b.is_empty() {
        return 0.0;
    }

    let lev_sim = levenshtein_similarity(domain_a, domain_b);
    let dice = bigram_dice(domain_a, domain_b);
    0.6 * lev_sim + 0.4 * dice
}

fn levenshtein_similarity(a: &str, b: &str) -> f64 {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let a_len = a_chars.len();
    let b_len = b_chars.len();

    if a_len == 0 && b_len == 0 {
        return 1.0;
    }

    let max_len = a_len.max(b_len) as f64;
    let mut prev_row: Vec<usize> = (0..=b_len).collect();
    let mut curr_row = vec![0usize; b_len + 1];

    for i in 1..=a_len {
        curr_row[0] = i;
        for j in 1..=b_len {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };
            curr_row[j] = (prev_row[j] + 1)
                .min(curr_row[j - 1] + 1)
                .min(prev_row[j - 1] + cost);
        }
        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    let distance = prev_row[b_len] as f64;
    1.0 - (distance / max_len)
}

fn bigram_dice(a: &str, b: &str) -> f64 {
    let a_bigrams = collect_bigrams(a);
    let b_bigrams = collect_bigrams(b);

    if a_bigrams.is_empty() && b_bigrams.is_empty() {
        return 1.0;
    }
    if a_bigrams.is_empty() || b_bigrams.is_empty() {
        return 0.0;
    }

    let mut intersection = 0usize;
    let mut b_remaining: Vec<(char, char)> = b_bigrams.clone();

    for bigram in &a_bigrams {
        if let Some(pos) = b_remaining.iter().position(|b| b == bigram) {
            intersection += 1;
            b_remaining.swap_remove(pos);
        }
    }

    (2 * intersection) as f64 / (a_bigrams.len() + b_bigrams.len()) as f64
}

fn collect_bigrams(s: &str) -> Vec<(char, char)> {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 2 {
        return Vec::new();
    }
    chars.windows(2).map(|w| (w[0], w[1])).collect()
}

// ---------------------------------------------------------------------------
// Monitoring state and delta computation
// ---------------------------------------------------------------------------

/// Tracks previously seen certificates for delta detection.
#[derive(Debug, Clone)]
pub struct CertMonitorState {
    pub monitored_domain: String,
    known_serials: HashMap<String, CertInfo>,
    scan_count: u32,
}

impl CertMonitorState {
    pub fn new(domain: &str) -> Self {
        Self {
            monitored_domain: domain.to_lowercase(),
            known_serials: HashMap::new(),
            scan_count: 0,
        }
    }

    pub fn known_cert_count(&self) -> usize {
        self.known_serials.len()
    }

    pub fn scan_count(&self) -> u32 {
        self.scan_count
    }

    pub fn contains_serial(&self, serial: &str) -> bool {
        self.known_serials.contains_key(serial)
    }

    pub fn ingest(&mut self, certs: &[CertInfo]) -> CertDelta {
        self.scan_count += 1;
        compute_cert_delta(self, certs)
    }
}

impl fmt::Display for CertMonitorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CertMonitor[{}] known={} scans={}",
            self.monitored_domain,
            self.known_serials.len(),
            self.scan_count
        )
    }
}

/// Delta between two scans: new, removed, and unchanged certificates.
#[derive(Debug, Clone, PartialEq)]
pub struct CertDelta {
    pub new_certs: Vec<CertInfo>,
    pub removed_serials: Vec<String>,
    pub unchanged_count: usize,
}

impl CertDelta {
    pub fn has_changes(&self) -> bool {
        !self.new_certs.is_empty() || !self.removed_serials.is_empty()
    }

    pub fn new_count(&self) -> usize {
        self.new_certs.len()
    }

    pub fn removed_count(&self) -> usize {
        self.removed_serials.len()
    }
}

impl fmt::Display for CertDelta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Delta: +{} new, -{} removed, {} unchanged",
            self.new_certs.len(),
            self.removed_serials.len(),
            self.unchanged_count
        )
    }
}

/// Compute the delta between the current monitoring state and a fresh scan.
///
/// Updates `state.known_serials` as a side-effect: new certs are added,
/// removed certs are purged.
pub fn compute_cert_delta(state: &mut CertMonitorState, current_certs: &[CertInfo]) -> CertDelta {
    let current_serials: HashMap<String, &CertInfo> = current_certs
        .iter()
        .map(|c| (c.serial.clone(), c))
        .collect();

    let mut new_certs = Vec::new();
    for (serial, cert) in &current_serials {
        if !state.known_serials.contains_key(serial) {
            new_certs.push((*cert).clone());
        }
    }

    let mut removed_serials = Vec::new();
    let previous_serials: Vec<String> = state.known_serials.keys().cloned().collect();
    for serial in previous_serials {
        if !current_serials.contains_key(&serial) {
            removed_serials.push(serial);
        }
    }

    let unchanged_count = current_certs.len() - new_certs.len();

    for serial in &removed_serials {
        state.known_serials.remove(serial);
    }
    for cert in &new_certs {
        state
            .known_serials
            .insert(cert.serial.clone(), cert.clone());
    }

    new_certs.sort_by(|a, b| a.serial.cmp(&b.serial));
    removed_serials.sort();

    CertDelta {
        new_certs,
        removed_serials,
        unchanged_count,
    }
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

/// Comprehensive CT monitoring report aggregating analysis across certs.
#[derive(Debug, Clone)]
pub struct CtMonitorReport {
    pub domain: String,
    pub total_certs: usize,
    pub wildcard_count: usize,
    pub expired_count: usize,
    pub alerts: Vec<CertAlert>,
    pub risk_scores: Vec<f64>,
    pub issuer_distribution: HashMap<String, usize>,
    pub delta: Option<CertDelta>,
}

impl CtMonitorReport {
    pub fn max_risk_score(&self) -> f64 {
        self.risk_scores.iter().copied().fold(0.0_f64, f64::max)
    }

    pub fn average_risk_score(&self) -> f64 {
        if self.risk_scores.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.risk_scores.iter().sum();
        sum / self.risk_scores.len() as f64
    }

    pub fn critical_alert_count(&self) -> usize {
        self.alerts
            .iter()
            .filter(|a| a.severity == AlertSeverity::Critical)
            .count()
    }

    pub fn alert_count(&self) -> usize {
        self.alerts.len()
    }
}

impl fmt::Display for CtMonitorReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CT Report[{}]: {} certs, {} wildcards, {} expired, {} alerts (max_risk={:.1})",
            self.domain,
            self.total_certs,
            self.wildcard_count,
            self.expired_count,
            self.alerts.len(),
            self.max_risk_score()
        )
    }
}

/// Build a full CT monitoring report from a list of certificates.
pub fn build_ct_monitor_report(
    domain: &str,
    certs: &[CertInfo],
    reference_date: &str,
    delta: Option<CertDelta>,
) -> CtMonitorReport {
    let mut all_alerts = Vec::new();
    let mut risk_scores = Vec::new();
    let mut issuer_distribution: HashMap<String, usize> = HashMap::new();
    let mut wildcard_count = 0usize;
    let mut expired_count = 0usize;

    for cert in certs {
        let analysis = analyze_certificate(cert, reference_date, domain);
        all_alerts.extend(analysis.alerts);
        risk_scores.push(analysis.risk_score);

        let issuer_key = if cert.issuer.organization.is_empty() {
            cert.issuer.common_name.clone()
        } else {
            cert.issuer.organization.clone()
        };
        *issuer_distribution.entry(issuer_key).or_insert(0) += 1;

        if cert.is_wildcard {
            wildcard_count += 1;
        }
        if is_cert_expired(cert, reference_date) {
            expired_count += 1;
        }
    }

    if let Some(ref d) = delta {
        for new_cert in &d.new_certs {
            all_alerts.push(CertAlert {
                alert_type: CertAlertType::NewCert,
                cert: new_cert.clone(),
                description: format!("New certificate detected: {}", new_cert.subject_cn),
                severity: AlertSeverity::Info,
            });
        }
        for serial in &d.removed_serials {
            all_alerts.push(CertAlert {
                alert_type: CertAlertType::RevokedCert,
                cert: CertInfo {
                    serial: serial.clone(),
                    fingerprint: String::new(),
                    subject_cn: format!("<removed:{}>", truncate_serial(serial, 8)),
                    sans: Vec::new(),
                    issuer: CertIssuer {
                        organization: String::new(),
                        common_name: String::new(),
                        country: String::new(),
                    },
                    not_before: String::new(),
                    not_after: String::new(),
                    is_wildcard: false,
                    crtsh_id: 0,
                },
                description: format!(
                    "Certificate no longer observed: serial={}",
                    truncate_serial(serial, 12)
                ),
                severity: AlertSeverity::Medium,
            });
        }
    }

    CtMonitorReport {
        domain: domain.to_string(),
        total_certs: certs.len(),
        wildcard_count,
        expired_count,
        alerts: all_alerts,
        risk_scores,
        issuer_distribution,
        delta,
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn extract_dn_field(dn: &str, field: &str) -> String {
    let prefix = format!("{field}=");
    for part in dn.split(',') {
        let trimmed = part.trim();
        if let Some(stripped) = trimmed.strip_prefix(&prefix) {
            return stripped.trim().to_string();
        }
    }
    String::new()
}

fn extract_date_prefix(date_str: &str) -> String {
    let s = date_str.trim();
    if s.len() >= 10 {
        s[..10].to_string()
    } else {
        s.to_string()
    }
}

fn estimate_day_diff(date_a: &str, date_b: &str) -> u32 {
    let parse = |s: &str| -> Option<(i32, u32, u32)> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() < 3 {
            return None;
        }
        let y = parts[0].parse::<i32>().ok()?;
        let m = parts[1].parse::<u32>().ok()?;
        let d = parts[2].parse::<u32>().ok()?;
        Some((y, m, d))
    };

    let a = match parse(date_a) {
        Some(v) => v,
        None => return 0,
    };
    let b = match parse(date_b) {
        Some(v) => v,
        None => return 0,
    };

    let days_a = a.0 as i64 * 365 + a.1 as i64 * 30 + a.2 as i64;
    let days_b = b.0 as i64 * 365 + b.1 as i64 * 30 + b.2 as i64;
    (days_b - days_a).unsigned_abs() as u32
}

fn strip_wildcard(domain: &str) -> String {
    domain.strip_prefix("*.").unwrap_or(domain).to_string()
}

fn truncate_serial(serial: &str, max_len: usize) -> String {
    if serial.len() <= max_len {
        serial.to_string()
    } else {
        format!("{}...", &serial[..max_len])
    }
}
