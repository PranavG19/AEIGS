use std::collections::HashMap;
use std::fmt;

use regex::Regex;

/// Category of dark web content found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DarkWebContentType {
    PastedCredentials,
    DatabaseDump,
    RansomwareLeak,
    ForumPost,
    MarketplaceListing,
    ExploitDisclosure,
    SourceCodeLeak,
    ApiKeyExposure,
    InternalDocument,
}

impl fmt::Display for DarkWebContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PastedCredentials => write!(f, "Pasted Credentials"),
            Self::DatabaseDump => write!(f, "Database Dump"),
            Self::RansomwareLeak => write!(f, "Ransomware Leak"),
            Self::ForumPost => write!(f, "Forum Post"),
            Self::MarketplaceListing => write!(f, "Marketplace Listing"),
            Self::ExploitDisclosure => write!(f, "Exploit Disclosure"),
            Self::SourceCodeLeak => write!(f, "Source Code Leak"),
            Self::ApiKeyExposure => write!(f, "API Key Exposure"),
            Self::InternalDocument => write!(f, "Internal Document"),
        }
    }
}

/// Risk level for dark web findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DarkWebRisk {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for DarkWebRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// A detected .onion URL.
#[derive(Debug, Clone, PartialEq)]
pub struct OnionUrl {
    pub url: String,
    pub domain: String,
    pub is_v3: bool,
    pub context: String,
}

/// A parsed paste entry (Pastebin, etc.).
#[derive(Debug, Clone, PartialEq)]
pub struct PasteEntry {
    pub source: PasteSource,
    pub paste_id: String,
    pub title: Option<String>,
    pub content_preview: String,
    pub detected_emails: Vec<String>,
    pub detected_credentials: Vec<ParsedCredential>,
    pub content_type: DarkWebContentType,
    pub timestamp: Option<String>,
}

/// Where the paste was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PasteSource {
    Pastebin,
    GhostBin,
    Rentry,
    PrivBin,
    JustPaste,
    IxIo,
    DPaste,
    Unknown,
}

impl fmt::Display for PasteSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pastebin => write!(f, "Pastebin"),
            Self::GhostBin => write!(f, "GhostBin"),
            Self::Rentry => write!(f, "Rentry"),
            Self::PrivBin => write!(f, "PrivBin"),
            Self::JustPaste => write!(f, "JustPaste.it"),
            Self::IxIo => write!(f, "ix.io"),
            Self::DPaste => write!(f, "dpaste"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// A parsed credential from dark web content.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedCredential {
    pub username_or_email: String,
    pub credential: String,
    pub credential_type: CredentialType,
}

/// Type of credential found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialType {
    Plaintext,
    Md5Hash,
    Sha1Hash,
    Sha256Hash,
    BcryptHash,
    NtlmHash,
    Unknown,
}

impl fmt::Display for CredentialType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plaintext => write!(f, "Plaintext"),
            Self::Md5Hash => write!(f, "MD5"),
            Self::Sha1Hash => write!(f, "SHA1"),
            Self::Sha256Hash => write!(f, "SHA256"),
            Self::BcryptHash => write!(f, "bcrypt"),
            Self::NtlmHash => write!(f, "NTLM"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Tor search engine query format.
#[derive(Debug, Clone, PartialEq)]
pub struct TorSearchQuery {
    pub engine: TorSearchEngine,
    pub query_url: String,
    pub search_term: String,
}

/// Known Tor search engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TorSearchEngine {
    Ahmia,
    TorchOnion,
    Haystack,
    DarkSearch,
    NotEvil,
    Kilos,
}

impl fmt::Display for TorSearchEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ahmia => write!(f, "Ahmia"),
            Self::TorchOnion => write!(f, "TORCH"),
            Self::Haystack => write!(f, "Haystack"),
            Self::DarkSearch => write!(f, "DarkSearch"),
            Self::NotEvil => write!(f, "not Evil"),
            Self::Kilos => write!(f, "Kilos"),
        }
    }
}

/// A single dark web monitoring finding.
#[derive(Debug, Clone, PartialEq)]
pub struct DarkWebFinding {
    pub content_type: DarkWebContentType,
    pub risk: DarkWebRisk,
    pub source_url: Option<String>,
    pub description: String,
    pub matched_keywords: Vec<String>,
    pub detected_data: DetectedData,
    pub timestamp: Option<String>,
}

/// Data extracted from dark web content.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedData {
    pub emails: Vec<String>,
    pub credentials: Vec<ParsedCredential>,
    pub domains: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub onion_urls: Vec<OnionUrl>,
}

/// Full dark web monitoring report.
#[derive(Debug, Clone, PartialEq)]
pub struct DarkWebReport {
    pub target_domain: String,
    pub findings: Vec<DarkWebFinding>,
    pub paste_entries: Vec<PasteEntry>,
    pub onion_urls: Vec<OnionUrl>,
    pub search_queries_generated: Vec<TorSearchQuery>,
    pub total_credentials_found: usize,
    pub risk_summary: HashMap<DarkWebRisk, usize>,
    pub overall_risk: DarkWebRisk,
}

/// Extracts .onion URLs (v2 and v3) from text.
pub fn extract_onion_urls(text: &str) -> Vec<OnionUrl> {
    let re = Regex::new(r"(?i)(https?://)?([a-z2-7]{16}(?:[a-z2-7]{40})?\.onion)(/[^\s]*)?")
        .expect("valid onion regex");

    re.captures_iter(text)
        .map(|cap| {
            let full_match = cap.get(0).unwrap().as_str().to_string();
            let domain = cap.get(2).unwrap().as_str().to_string();
            let is_v3 = domain.len() > 22;
            let start = cap.get(0).unwrap().start();
            let context_start = text[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
            let context_end = text[start..]
                .find('\n')
                .map(|i| start + i)
                .unwrap_or(text.len());
            let context = text[context_start..context_end].trim().to_string();

            OnionUrl {
                url: full_match,
                domain,
                is_v3,
                context,
            }
        })
        .collect()
}

/// Detects the hash type from a credential string.
pub fn detect_hash_type(hash: &str) -> CredentialType {
    let trimmed = hash.trim();
    let len = trimmed.len();

    if trimmed.starts_with("$2a$") || trimmed.starts_with("$2b$") || trimmed.starts_with("$2y$") {
        return CredentialType::BcryptHash;
    }

    let is_hex = trimmed.chars().all(|c| c.is_ascii_hexdigit());

    if is_hex {
        return match len {
            32 => {
                if trimmed.contains(':') {
                    CredentialType::NtlmHash
                } else {
                    CredentialType::Md5Hash
                }
            }
            40 => CredentialType::Sha1Hash,
            64 => CredentialType::Sha256Hash,
            _ => CredentialType::Unknown,
        };
    }

    if len > 0 && len < 128 && !is_hex {
        CredentialType::Plaintext
    } else {
        CredentialType::Unknown
    }
}

/// Parses credential lines from paste content (email:password / user:hash).
pub fn parse_credentials_from_paste(content: &str) -> Vec<ParsedCredential> {
    let re_email_cred = Regex::new(r"([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})[:\|;](.+)")
        .expect("valid cred regex");
    let re_user_cred =
        Regex::new(r"^([a-zA-Z0-9._\-]{3,})[:\|;](.+)$").expect("valid user cred regex");

    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }

        if let Some(cap) = re_email_cred.captures(line) {
            let email = cap.get(1).unwrap().as_str().to_string();
            let cred = cap.get(2).unwrap().as_str().trim().to_string();
            let key = format!("{}:{}", email, cred);
            if seen.insert(key) {
                let cred_type = detect_hash_type(&cred);
                results.push(ParsedCredential {
                    username_or_email: email,
                    credential: cred,
                    credential_type: cred_type,
                });
            }
        } else if let Some(cap) = re_user_cred.captures(line) {
            let user = cap.get(1).unwrap().as_str().to_string();
            let cred = cap.get(2).unwrap().as_str().trim().to_string();
            let key = format!("{}:{}", user, cred);
            if seen.insert(key) {
                let cred_type = detect_hash_type(&cred);
                results.push(ParsedCredential {
                    username_or_email: user,
                    credential: cred,
                    credential_type: cred_type,
                });
            }
        }
    }

    results
}

/// Extracts emails matching a target domain from text.
pub fn extract_domain_emails(text: &str, target_domain: &str) -> Vec<String> {
    let pattern = format!(r"[a-zA-Z0-9._%+\-]+@{}", regex::escape(target_domain));
    let re = Regex::new(&pattern).expect("valid email domain regex");
    let mut emails: Vec<String> = re
        .find_iter(text)
        .map(|m| m.as_str().to_lowercase())
        .collect();
    emails.sort();
    emails.dedup();
    emails
}

/// Generates Tor search engine query URLs for a target.
pub fn generate_tor_search_queries(target: &str) -> Vec<TorSearchQuery> {
    let engines = vec![
        (TorSearchEngine::Ahmia, "https://ahmia.fi/search/?q={}"),
        (
            TorSearchEngine::DarkSearch,
            "https://darksearch.io/api/search?query={}",
        ),
    ];

    let search_terms = vec![
        target.to_string(),
        format!("{} database", target),
        format!("{} credentials", target),
        format!("{} leak", target),
        format!("{} dump", target),
        format!("\"{}\" password", target),
    ];

    let mut queries = Vec::new();
    for (engine, url_template) in &engines {
        for term in &search_terms {
            let encoded = term.replace(' ', "+");
            queries.push(TorSearchQuery {
                engine: *engine,
                query_url: url_template.replace("{}", &encoded),
                search_term: term.clone(),
            });
        }
    }
    queries
}

/// Classifies paste content type from text content.
pub fn classify_paste_content(content: &str) -> DarkWebContentType {
    let lower = content.to_lowercase();

    if lower.contains("ransom") || lower.contains("encrypted your files") {
        return DarkWebContentType::RansomwareLeak;
    }
    if lower.contains("api_key") || lower.contains("apikey") || lower.contains("bearer ") {
        return DarkWebContentType::ApiKeyExposure;
    }
    if lower.contains("select ") && lower.contains("from ") && lower.contains("where ") {
        return DarkWebContentType::DatabaseDump;
    }
    if lower.contains("function ") || lower.contains("class ") || lower.contains("def ") {
        return DarkWebContentType::SourceCodeLeak;
    }
    if lower.contains("confidential") || lower.contains("internal only") {
        return DarkWebContentType::InternalDocument;
    }
    if lower.contains("exploit") || lower.contains("cve-") || lower.contains("poc") {
        return DarkWebContentType::ExploitDisclosure;
    }

    let creds = parse_credentials_from_paste(content);
    if !creds.is_empty() {
        return DarkWebContentType::PastedCredentials;
    }

    DarkWebContentType::ForumPost
}

/// Parses a paste into a structured entry.
pub fn parse_paste(
    source: PasteSource,
    paste_id: &str,
    title: Option<&str>,
    content: &str,
    target_domain: &str,
    timestamp: Option<&str>,
) -> PasteEntry {
    let credentials = parse_credentials_from_paste(content);
    let emails = extract_domain_emails(content, target_domain);
    let content_type = classify_paste_content(content);
    let preview_len = content.len().min(500);

    PasteEntry {
        source,
        paste_id: paste_id.to_string(),
        title: title.map(String::from),
        content_preview: content[..preview_len].to_string(),
        detected_emails: emails,
        detected_credentials: credentials,
        content_type,
        timestamp: timestamp.map(String::from),
    }
}

/// Classifies overall risk from a set of findings.
pub fn classify_overall_risk(findings: &[DarkWebFinding]) -> DarkWebRisk {
    findings
        .iter()
        .map(|f| f.risk)
        .max()
        .unwrap_or(DarkWebRisk::Low)
}

/// Builds risk summary from findings.
pub fn build_risk_summary(findings: &[DarkWebFinding]) -> HashMap<DarkWebRisk, usize> {
    let mut summary = HashMap::new();
    for f in findings {
        *summary.entry(f.risk).or_insert(0) += 1;
    }
    summary
}

/// Creates a finding from a paste entry.
pub fn finding_from_paste(paste: &PasteEntry, target_domain: &str) -> DarkWebFinding {
    let risk = if !paste.detected_credentials.is_empty() {
        if paste
            .detected_credentials
            .iter()
            .any(|c| c.credential_type == CredentialType::Plaintext)
        {
            DarkWebRisk::Critical
        } else {
            DarkWebRisk::High
        }
    } else if !paste.detected_emails.is_empty() {
        DarkWebRisk::Medium
    } else {
        DarkWebRisk::Low
    };

    let mut matched_keywords = vec![target_domain.to_string()];
    if !paste.detected_emails.is_empty() {
        matched_keywords.push(format!("{} emails found", paste.detected_emails.len()));
    }

    DarkWebFinding {
        content_type: paste.content_type,
        risk,
        source_url: Some(format!("paste://{}:{}", paste.source, paste.paste_id)),
        description: format!(
            "{} found on {} ({}): {} credentials, {} emails",
            paste.content_type,
            paste.source,
            paste.paste_id,
            paste.detected_credentials.len(),
            paste.detected_emails.len(),
        ),
        matched_keywords,
        detected_data: DetectedData {
            emails: paste.detected_emails.clone(),
            credentials: paste.detected_credentials.clone(),
            domains: vec![target_domain.to_string()],
            ip_addresses: vec![],
            onion_urls: vec![],
        },
        timestamp: paste.timestamp.clone(),
    }
}

/// Builds a full dark web monitoring report.
pub fn build_darkweb_report(
    target_domain: &str,
    paste_entries: Vec<PasteEntry>,
    extra_onion_urls: Vec<OnionUrl>,
) -> DarkWebReport {
    let mut findings: Vec<DarkWebFinding> = paste_entries
        .iter()
        .map(|p| finding_from_paste(p, target_domain))
        .collect();

    let total_creds: usize = paste_entries
        .iter()
        .map(|p| p.detected_credentials.len())
        .sum();

    let mut all_onions = extra_onion_urls;
    for f in &findings {
        all_onions.extend(f.detected_data.onion_urls.clone());
    }

    let search_queries = generate_tor_search_queries(target_domain);
    let risk_summary = build_risk_summary(&findings);
    let overall_risk = classify_overall_risk(&findings);

    findings.sort_by(|a, b| b.risk.cmp(&a.risk));

    DarkWebReport {
        target_domain: target_domain.to_string(),
        findings,
        paste_entries,
        onion_urls: all_onions,
        search_queries_generated: search_queries,
        total_credentials_found: total_creds,
        risk_summary,
        overall_risk,
    }
}
