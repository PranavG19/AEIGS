use std::collections::HashMap;
use std::fmt;

use regex::Regex;

/// Title/role category for executive profiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutiveRole {
    Ceo,
    Cto,
    Cfo,
    Ciso,
    Coo,
    Cmo,
    Cpo,
    Cio,
    VpEngineering,
    VpSecurity,
    VpSales,
    BoardMember,
    Director,
    Founder,
}

impl fmt::Display for ExecutiveRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ceo => write!(f, "CEO"),
            Self::Cto => write!(f, "CTO"),
            Self::Cfo => write!(f, "CFO"),
            Self::Ciso => write!(f, "CISO"),
            Self::Coo => write!(f, "COO"),
            Self::Cmo => write!(f, "CMO"),
            Self::Cpo => write!(f, "CPO"),
            Self::Cio => write!(f, "CIO"),
            Self::VpEngineering => write!(f, "VP Engineering"),
            Self::VpSecurity => write!(f, "VP Security"),
            Self::VpSales => write!(f, "VP Sales"),
            Self::BoardMember => write!(f, "Board Member"),
            Self::Director => write!(f, "Director"),
            Self::Founder => write!(f, "Founder"),
        }
    }
}

/// An inferred email format for a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmailFormat {
    FirstDotLast,
    FirstInitialLast,
    FirstLast,
    First,
    LastDotFirst,
    FirstDotLastInitial,
    LastFirst,
    Unknown,
}

impl EmailFormat {
    /// Generates an email from first/last name using this format.
    pub fn generate(&self, first: &str, last: &str, domain: &str) -> Option<String> {
        let first = first.to_lowercase();
        let last = last.to_lowercase();
        let fi = first.chars().next()?;
        let li = last.chars().next()?;

        let local = match self {
            Self::FirstDotLast => format!("{}.{}", first, last),
            Self::FirstInitialLast => format!("{}{}", fi, last),
            Self::FirstLast => format!("{}{}", first, last),
            Self::First => first.clone(),
            Self::LastDotFirst => format!("{}.{}", last, first),
            Self::FirstDotLastInitial => format!("{}.{}", first, li),
            Self::LastFirst => format!("{}{}", last, first),
            Self::Unknown => return None,
        };
        Some(format!("{}@{}", local, domain))
    }
}

impl fmt::Display for EmailFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FirstDotLast => write!(f, "first.last"),
            Self::FirstInitialLast => write!(f, "flast"),
            Self::FirstLast => write!(f, "firstlast"),
            Self::First => write!(f, "first"),
            Self::LastDotFirst => write!(f, "last.first"),
            Self::FirstDotLastInitial => write!(f, "first.l"),
            Self::LastFirst => write!(f, "lastfirst"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// A conference or speaking engagement appearance.
#[derive(Debug, Clone, PartialEq)]
pub struct ConferenceAppearance {
    pub conference_name: String,
    pub year: Option<u16>,
    pub talk_title: Option<String>,
    pub role_at_conference: String,
    pub bio_text: Option<String>,
}

/// SEC filing type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecFilingType {
    Form10K,
    Form10Q,
    Form8K,
    FormDef14A,
    FormS1,
    Form4,
    Form13F,
    FormAnnualReport,
}

impl fmt::Display for SecFilingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Form10K => write!(f, "10-K"),
            Self::Form10Q => write!(f, "10-Q"),
            Self::Form8K => write!(f, "8-K"),
            Self::FormDef14A => write!(f, "DEF 14A"),
            Self::FormS1 => write!(f, "S-1"),
            Self::Form4 => write!(f, "Form 4"),
            Self::Form13F => write!(f, "13-F"),
            Self::FormAnnualReport => write!(f, "Annual Report"),
        }
    }
}

/// A board member extracted from SEC filings.
#[derive(Debug, Clone, PartialEq)]
pub struct BoardMember {
    pub name: String,
    pub title: String,
    pub role: ExecutiveRole,
    pub committees: Vec<String>,
    pub other_boards: Vec<String>,
    pub compensation: Option<u64>,
    pub filing_source: SecFilingType,
}

/// An executive profile aggregated from multiple sources.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutiveProfile {
    pub full_name: String,
    pub role: ExecutiveRole,
    pub organization: String,
    pub inferred_emails: Vec<String>,
    pub conference_appearances: Vec<ConferenceAppearance>,
    pub board_memberships: Vec<String>,
    pub social_links: Vec<String>,
    pub bio_snippets: Vec<String>,
    pub education: Vec<String>,
    pub previous_companies: Vec<String>,
}

/// Inferred email format result.
#[derive(Debug, Clone, PartialEq)]
pub struct EmailFormatInference {
    pub domain: String,
    pub detected_format: EmailFormat,
    pub confidence: f64,
    pub sample_emails: Vec<String>,
    pub generated_emails: Vec<String>,
}

/// Full executive profiling report.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutiveProfileReport {
    pub organization: String,
    pub domain: String,
    pub executives: Vec<ExecutiveProfile>,
    pub board_members: Vec<BoardMember>,
    pub email_format: EmailFormatInference,
    pub total_profiles: usize,
    pub sec_filings_analyzed: usize,
    pub conferences_found: usize,
}

/// Parses an executive role from title text.
pub fn parse_executive_role(title: &str) -> Option<ExecutiveRole> {
    let lower = title.to_lowercase();
    let lower = lower.trim();

    if lower.contains("founder") || lower.contains("co-founder") {
        return Some(ExecutiveRole::Founder);
    }
    if lower.contains("chief executive")
        || lower == "ceo"
        || lower.contains("ceo ")
        || lower.ends_with(" ceo")
    {
        return Some(ExecutiveRole::Ceo);
    }
    if lower.contains("chief technology")
        || lower == "cto"
        || lower.contains("cto ")
        || lower.ends_with(" cto")
    {
        return Some(ExecutiveRole::Cto);
    }
    if lower.contains("chief financial")
        || lower == "cfo"
        || lower.contains("cfo ")
        || lower.ends_with(" cfo")
    {
        return Some(ExecutiveRole::Cfo);
    }
    if lower.contains("chief information security") || lower == "ciso" || lower.contains("ciso ") {
        return Some(ExecutiveRole::Ciso);
    }
    if lower.contains("chief operating") || lower == "coo" || lower.contains("coo ") {
        return Some(ExecutiveRole::Coo);
    }
    if lower.contains("chief marketing") || lower == "cmo" {
        return Some(ExecutiveRole::Cmo);
    }
    if lower.contains("chief product") || lower == "cpo" {
        return Some(ExecutiveRole::Cpo);
    }
    if lower.contains("chief information officer") || (lower == "cio") {
        return Some(ExecutiveRole::Cio);
    }
    if lower.contains("vp") && lower.contains("engineer") {
        return Some(ExecutiveRole::VpEngineering);
    }
    if lower.contains("vp") && lower.contains("secur") {
        return Some(ExecutiveRole::VpSecurity);
    }
    if lower.contains("vp") && lower.contains("sale") {
        return Some(ExecutiveRole::VpSales);
    }
    if lower.contains("board") || lower.contains("independent director") {
        return Some(ExecutiveRole::BoardMember);
    }
    if lower.contains("director") {
        return Some(ExecutiveRole::Director);
    }

    None
}

/// Parses a conference bio for executive details.
pub fn parse_conference_bio(bio_text: &str) -> Vec<(String, ExecutiveRole, Vec<String>)> {
    let name_title_re = Regex::new(
        r"(?i)([A-Z][a-z]+(?:\s[A-Z][a-z]+)+)\s*[,\-–]\s*((?:Chief|CEO|CTO|CFO|CISO|COO|CMO|CPO|CIO|VP|Director|Founder|Co-Founder)[^.;]*)"
    ).expect("valid bio regex");

    let education_re = Regex::new(
        r"(?i)(?:graduated|degree|alumni|MBA|Ph\.?D|B\.?S\.?|M\.?S\.?|bachelor|master)\s+(?:from\s+|in\s+)?([A-Z][^.,;]+)"
    ).expect("valid edu regex");

    let mut results = Vec::new();

    for cap in name_title_re.captures_iter(bio_text) {
        let name = cap.get(1).unwrap().as_str().trim().to_string();
        let title_text = cap.get(2).unwrap().as_str().trim();

        if let Some(role) = parse_executive_role(title_text) {
            let mut education = Vec::new();
            for edu_cap in education_re.captures_iter(bio_text) {
                education.push(edu_cap.get(1).unwrap().as_str().trim().to_string());
            }
            results.push((name, role, education));
        }
    }

    results
}

/// Extracts board members from SEC DEF 14A proxy filing text.
pub fn parse_sec_board_members(filing_text: &str) -> Vec<BoardMember> {
    let director_re = Regex::new(
        r"(?i)([A-Z][a-z]+(?:\s[A-Z][a-z]+)+)\s*(?:has\s+(?:been|served)\s+as\s+|[,\-–]\s*)((?:Independent\s+)?(?:Director|Board\s+Member|Chairman)[^.]*)"
    ).expect("valid director regex");

    let committee_re = Regex::new(
        r"(?i)(Audit|Compensation|Nominating|Governance|Risk|Technology|Finance)\s+Committee",
    )
    .expect("valid committee regex");

    let mut members = Vec::new();

    for cap in director_re.captures_iter(filing_text) {
        let name = cap.get(1).unwrap().as_str().trim().to_string();
        let title = cap.get(2).unwrap().as_str().trim().to_string();

        let remaining = &filing_text[cap.get(0).unwrap().end()..];
        let section = &remaining[..remaining.len().min(500)];

        let committees: Vec<String> = committee_re
            .captures_iter(section)
            .map(|c| format!("{} Committee", c.get(1).unwrap().as_str()))
            .collect();

        let other_board_re = Regex::new(
            r"(?i)(?:also\s+serves?\s+on|board\s+of|director\s+(?:of|at))\s+([A-Z][A-Za-z\s&]+(?:Inc|Corp|Ltd|LLC|Co)?\.?)"
        ).expect("valid other board regex");
        let other_boards: Vec<String> = other_board_re
            .captures_iter(section)
            .map(|c| c.get(1).unwrap().as_str().trim().to_string())
            .collect();

        members.push(BoardMember {
            name,
            title,
            role: ExecutiveRole::BoardMember,
            committees,
            other_boards,
            compensation: None,
            filing_source: SecFilingType::FormDef14A,
        });
    }

    members
}

/// Infers the email format from known email samples.
pub fn infer_email_format(
    known_emails: &[(&str, &str, &str)],
    domain: &str,
) -> EmailFormatInference {
    let formats = [
        EmailFormat::FirstDotLast,
        EmailFormat::FirstInitialLast,
        EmailFormat::FirstLast,
        EmailFormat::First,
        EmailFormat::LastDotFirst,
        EmailFormat::FirstDotLastInitial,
        EmailFormat::LastFirst,
    ];

    let mut format_scores: HashMap<EmailFormat, usize> = HashMap::new();

    for &(first, last, email) in known_emails {
        let email_lower = email.to_lowercase();
        for fmt in &formats {
            if let Some(generated) = fmt.generate(first, last, domain) {
                if generated.to_lowercase() == email_lower {
                    *format_scores.entry(*fmt).or_insert(0) += 1;
                }
            }
        }
    }

    let total_samples = known_emails.len().max(1);
    let (best_format, best_count) = format_scores
        .iter()
        .max_by_key(|(_, count)| *count)
        .map(|(&fmt, &count)| (fmt, count))
        .unwrap_or((EmailFormat::Unknown, 0));

    let confidence = best_count as f64 / total_samples as f64;

    let sample_emails: Vec<String> = known_emails
        .iter()
        .map(|&(_, _, e)| e.to_string())
        .collect();

    EmailFormatInference {
        domain: domain.to_string(),
        detected_format: best_format,
        confidence,
        sample_emails,
        generated_emails: Vec::new(),
    }
}

/// Generates possible emails for a name given an inferred format.
pub fn generate_executive_emails(
    first: &str,
    last: &str,
    domain: &str,
    format: &EmailFormat,
) -> Vec<String> {
    let mut emails = Vec::new();

    if let Some(primary) = format.generate(first, last, domain) {
        emails.push(primary);
    }

    let all_formats = [
        EmailFormat::FirstDotLast,
        EmailFormat::FirstInitialLast,
        EmailFormat::FirstLast,
    ];
    for fmt in &all_formats {
        if fmt != format {
            if let Some(alt) = fmt.generate(first, last, domain) {
                emails.push(alt);
            }
        }
    }

    emails
}

/// Parses previous companies from a bio text.
pub fn extract_previous_companies(bio_text: &str) -> Vec<String> {
    let re = Regex::new(
        r"(?i)(?:previously|formerly|prior)\s+(?:at|with|served\s+at)\s+([A-Z][A-Za-z\s&]+(?:Inc|Corp|Ltd|LLC|Co)?\.?)"
    ).expect("valid prev company regex");

    re.captures_iter(bio_text)
        .map(|c| c.get(1).unwrap().as_str().trim().to_string())
        .collect()
}

/// Builds an executive profile from available data.
pub fn build_executive_profile(
    name: &str,
    role: ExecutiveRole,
    organization: &str,
    domain: &str,
    email_format: &EmailFormat,
    bio_text: Option<&str>,
    conferences: Vec<ConferenceAppearance>,
) -> ExecutiveProfile {
    let name_parts: Vec<&str> = name.split_whitespace().collect();
    let first = name_parts.first().copied().unwrap_or("");
    let last = name_parts.last().copied().unwrap_or("");

    let inferred_emails = if !first.is_empty() && !last.is_empty() && first != last {
        generate_executive_emails(first, last, domain, email_format)
    } else {
        Vec::new()
    };

    let mut education = Vec::new();
    let mut previous_companies = Vec::new();
    let mut bio_snippets = Vec::new();

    if let Some(bio) = bio_text {
        bio_snippets.push(bio.to_string());
        previous_companies = extract_previous_companies(bio);

        let edu_re = Regex::new(
            r"(?i)(MBA|Ph\.?D|B\.?S\.?|M\.?S\.?|bachelor|master)\s+(?:from\s+|in\s+|degree\s+)?([A-Z][^.,;]{3,40})"
        ).expect("valid edu regex");
        for cap in edu_re.captures_iter(bio) {
            let degree = cap.get(1).unwrap().as_str();
            let school = cap.get(2).unwrap().as_str().trim();
            education.push(format!("{} from {}", degree, school));
        }
    }

    ExecutiveProfile {
        full_name: name.to_string(),
        role,
        organization: organization.to_string(),
        inferred_emails,
        conference_appearances: conferences,
        board_memberships: Vec::new(),
        social_links: Vec::new(),
        bio_snippets,
        education,
        previous_companies,
    }
}

/// Builds a full executive profile report.
pub fn build_executive_report(
    organization: &str,
    domain: &str,
    executives: Vec<ExecutiveProfile>,
    board_members: Vec<BoardMember>,
    email_format: EmailFormatInference,
    sec_filings_count: usize,
) -> ExecutiveProfileReport {
    let total_profiles = executives.len();
    let conferences_found: usize = executives
        .iter()
        .map(|e| e.conference_appearances.len())
        .sum();

    ExecutiveProfileReport {
        organization: organization.to_string(),
        domain: domain.to_string(),
        executives,
        board_members,
        email_format,
        total_profiles,
        sec_filings_analyzed: sec_filings_count,
        conferences_found,
    }
}
