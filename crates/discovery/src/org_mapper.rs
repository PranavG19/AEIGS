use std::collections::HashMap;

/// Domain ownership record from reverse WHOIS or CT logs.
#[derive(Debug, Clone, PartialEq)]
pub struct OwnedDomain {
    pub domain: String,
    pub registrar: Option<String>,
    pub registration_date: Option<String>,
    pub expiry_date: Option<String>,
    pub nameservers: Vec<String>,
    pub source: DomainSource,
    pub confidence: f64,
}

/// How a domain was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainSource {
    ReverseWhois,
    CertificateTransparency,
    DnsEnumeration,
    SubdomainBrute,
    WebCrawl,
    SearchEngine,
    PassiveDns,
    Manual,
}

impl std::fmt::Display for DomainSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReverseWhois => write!(f, "Reverse WHOIS"),
            Self::CertificateTransparency => write!(f, "Certificate Transparency"),
            Self::DnsEnumeration => write!(f, "DNS Enumeration"),
            Self::SubdomainBrute => write!(f, "Subdomain Brute Force"),
            Self::WebCrawl => write!(f, "Web Crawl"),
            Self::SearchEngine => write!(f, "Search Engine"),
            Self::PassiveDns => write!(f, "Passive DNS"),
            Self::Manual => write!(f, "Manual"),
        }
    }
}

/// IP range with ASN information.
#[derive(Debug, Clone, PartialEq)]
pub struct IpRange {
    pub cidr: String,
    pub asn: Option<u32>,
    pub as_name: Option<String>,
    pub country: Option<String>,
    pub num_hosts: u32,
}

/// BGP prefix entry.
#[derive(Debug, Clone, PartialEq)]
pub struct BgpPrefix {
    pub prefix: String,
    pub asn: u32,
    pub as_name: String,
    pub announced: bool,
}

/// Employee discovered during org enumeration.
#[derive(Debug, Clone, PartialEq)]
pub struct OrgEmployee {
    pub name: String,
    pub title: Option<String>,
    pub department: Option<String>,
    pub email: Option<String>,
    pub source: EmployeeSource,
    pub confidence: f64,
}

/// Source of employee data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmployeeSource {
    LinkedIn,
    GitHubOrg,
    JobPosting,
    EmailHarvest,
    WebScrape,
    SocialMedia,
    PublicFiling,
}

impl std::fmt::Display for EmployeeSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LinkedIn => write!(f, "LinkedIn"),
            Self::GitHubOrg => write!(f, "GitHub Org"),
            Self::JobPosting => write!(f, "Job Posting"),
            Self::EmailHarvest => write!(f, "Email Harvest"),
            Self::WebScrape => write!(f, "Web Scrape"),
            Self::SocialMedia => write!(f, "Social Media"),
            Self::PublicFiling => write!(f, "Public Filing"),
        }
    }
}

/// Technology stack item discovered from job postings or code.
#[derive(Debug, Clone, PartialEq)]
pub struct OrgTechStackItem {
    pub technology: String,
    pub category: TechCategory,
    pub evidence: Vec<TechEvidence>,
    pub confidence: f64,
}

/// Technology category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TechCategory {
    Language,
    Framework,
    Database,
    Cloud,
    Cdn,
    Ci,
    Monitoring,
    Security,
    Container,
    MessageQueue,
    Analytics,
    Other,
}

impl std::fmt::Display for TechCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Language => write!(f, "Language"),
            Self::Framework => write!(f, "Framework"),
            Self::Database => write!(f, "Database"),
            Self::Cloud => write!(f, "Cloud"),
            Self::Cdn => write!(f, "CDN"),
            Self::Ci => write!(f, "CI/CD"),
            Self::Monitoring => write!(f, "Monitoring"),
            Self::Security => write!(f, "Security"),
            Self::Container => write!(f, "Container"),
            Self::MessageQueue => write!(f, "Message Queue"),
            Self::Analytics => write!(f, "Analytics"),
            Self::Other => write!(f, "Other"),
        }
    }
}

/// Evidence source for a tech detection.
#[derive(Debug, Clone, PartialEq)]
pub struct TechEvidence {
    pub source_type: TechEvidenceType,
    pub detail: String,
}

/// Type of tech evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TechEvidenceType {
    JobPosting,
    GitHubRepo,
    JsInclude,
    DnsRecord,
    HttpHeader,
    HtmlMeta,
    ErrorMessage,
    ApiResponse,
}

impl std::fmt::Display for TechEvidenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JobPosting => write!(f, "Job Posting"),
            Self::GitHubRepo => write!(f, "GitHub Repo"),
            Self::JsInclude => write!(f, "JS Include"),
            Self::DnsRecord => write!(f, "DNS Record"),
            Self::HttpHeader => write!(f, "HTTP Header"),
            Self::HtmlMeta => write!(f, "HTML Meta"),
            Self::ErrorMessage => write!(f, "Error Message"),
            Self::ApiResponse => write!(f, "API Response"),
        }
    }
}

/// Third-party vendor or service integrated by the org.
#[derive(Debug, Clone, PartialEq)]
pub struct VendorIntegration {
    pub vendor_name: String,
    pub service_type: VendorServiceType,
    pub detection_method: String,
    pub domains: Vec<String>,
    pub confidence: f64,
}

/// Type of vendor service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VendorServiceType {
    EmailProvider,
    CdnProvider,
    DnsProvider,
    AnalyticsProvider,
    PaymentProcessor,
    AuthProvider,
    CloudProvider,
    MarketingTool,
    SecurityTool,
    Other,
}

impl std::fmt::Display for VendorServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmailProvider => write!(f, "Email Provider"),
            Self::CdnProvider => write!(f, "CDN Provider"),
            Self::DnsProvider => write!(f, "DNS Provider"),
            Self::AnalyticsProvider => write!(f, "Analytics Provider"),
            Self::PaymentProcessor => write!(f, "Payment Processor"),
            Self::AuthProvider => write!(f, "Auth Provider"),
            Self::CloudProvider => write!(f, "Cloud Provider"),
            Self::MarketingTool => write!(f, "Marketing Tool"),
            Self::SecurityTool => write!(f, "Security Tool"),
            Self::Other => write!(f, "Other"),
        }
    }
}

/// Physical location of the organization.
#[derive(Debug, Clone, PartialEq)]
pub struct PhysicalLocation {
    pub address: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub source: String,
    pub is_headquarters: bool,
}

/// Subsidiary or related company.
#[derive(Debug, Clone, PartialEq)]
pub struct Subsidiary {
    pub name: String,
    pub relationship: SubsidiaryRelationship,
    pub shared_infra: Vec<String>,
    pub confidence: f64,
}

/// Relationship between parent and subsidiary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubsidiaryRelationship {
    WhollyOwned,
    PartialOwnership,
    Acquisition,
    Merger,
    SharedInfrastructure,
    Partnership,
    Unknown,
}

impl std::fmt::Display for SubsidiaryRelationship {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WhollyOwned => write!(f, "Wholly Owned"),
            Self::PartialOwnership => write!(f, "Partial Ownership"),
            Self::Acquisition => write!(f, "Acquisition"),
            Self::Merger => write!(f, "Merger"),
            Self::SharedInfrastructure => write!(f, "Shared Infrastructure"),
            Self::Partnership => write!(f, "Partnership"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// M&A event that might create security gaps.
#[derive(Debug, Clone, PartialEq)]
pub struct MaEvent {
    pub event_type: MaEventType,
    pub target_company: String,
    pub date: Option<String>,
    pub security_implications: Vec<String>,
    pub risk_score: f64,
}

/// Type of M&A event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MaEventType {
    Acquisition,
    Merger,
    Divestiture,
    Spin_off,
    ManagementChange,
}

impl std::fmt::Display for MaEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Acquisition => write!(f, "Acquisition"),
            Self::Merger => write!(f, "Merger"),
            Self::Divestiture => write!(f, "Divestiture"),
            Self::Spin_off => write!(f, "Spin-off"),
            Self::ManagementChange => write!(f, "Management Change"),
        }
    }
}

/// Full organization footprint report.
#[derive(Debug, Clone)]
pub struct OrgFootprint {
    pub primary_domain: String,
    pub owned_domains: Vec<OwnedDomain>,
    pub ip_ranges: Vec<IpRange>,
    pub bgp_prefixes: Vec<BgpPrefix>,
    pub employees: Vec<OrgEmployee>,
    pub tech_stack: Vec<OrgTechStackItem>,
    pub vendors: Vec<VendorIntegration>,
    pub locations: Vec<PhysicalLocation>,
    pub subsidiaries: Vec<Subsidiary>,
    pub ma_events: Vec<MaEvent>,
    pub email_format: Option<String>,
    pub total_exposure_score: f64,
}

/// Enumerate domains from a list of CT log entries.
pub fn enumerate_domains_from_ct(ct_entries: &[(&str, &str, &str)]) -> Vec<OwnedDomain> {
    let mut seen = std::collections::HashSet::new();
    let mut domains = Vec::new();

    for &(domain, issuer, not_before) in ct_entries {
        let base = extract_base_domain(domain);
        if seen.insert(base.clone()) {
            domains.push(OwnedDomain {
                domain: base,
                registrar: None,
                registration_date: Some(not_before.to_string()),
                expiry_date: None,
                nameservers: Vec::new(),
                source: DomainSource::CertificateTransparency,
                confidence: ct_confidence(issuer),
            });
        }
    }

    domains
}

fn ct_confidence(issuer: &str) -> f64 {
    let issuer_lower = issuer.to_lowercase();
    if issuer_lower.contains("let's encrypt") || issuer_lower.contains("letsencrypt") {
        0.95
    } else if issuer_lower.contains("digicert") || issuer_lower.contains("comodo") {
        0.90
    } else if issuer_lower.contains("google") || issuer_lower.contains("cloudflare") {
        0.85
    } else {
        0.70
    }
}

/// Extract base domain from a potentially wildcarded or subdomain string.
pub fn extract_base_domain(input: &str) -> String {
    let cleaned = input.trim_start_matches("*.");
    let parts: Vec<&str> = cleaned.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        cleaned.to_string()
    }
}

/// Map IP ranges from ASN lookup results.
pub fn map_ip_ranges(asn_entries: &[(u32, &str, &str, &str, u32)]) -> Vec<IpRange> {
    asn_entries
        .iter()
        .map(|&(asn, cidr, as_name, country, hosts)| IpRange {
            cidr: cidr.to_string(),
            asn: Some(asn),
            as_name: Some(as_name.to_string()),
            country: Some(country.to_string()),
            num_hosts: hosts,
        })
        .collect()
}

/// Parse BGP prefix announcements.
pub fn parse_bgp_prefixes(raw_prefixes: &[(&str, u32, &str, bool)]) -> Vec<BgpPrefix> {
    raw_prefixes
        .iter()
        .map(|&(prefix, asn, name, announced)| BgpPrefix {
            prefix: prefix.to_string(),
            asn,
            as_name: name.to_string(),
            announced,
        })
        .collect()
}

/// Discover email format from a list of known employee emails.
pub fn discover_email_format(emails: &[&str], domain: &str) -> Option<String> {
    let domain_lower = domain.to_lowercase();
    let matching: Vec<&str> = emails
        .iter()
        .filter(|e| e.to_lowercase().ends_with(&format!("@{domain_lower}")))
        .copied()
        .collect();

    if matching.is_empty() {
        return None;
    }

    let mut format_counts: HashMap<&str, usize> = HashMap::new();

    for email in &matching {
        let local = match email.split('@').next() {
            Some(l) => l.to_lowercase(),
            None => continue,
        };

        let format = if local.contains('.') {
            let parts: Vec<&str> = local.split('.').collect();
            if parts.len() == 2 && parts[0].len() > 1 && parts[1].len() > 1 {
                "first.last"
            } else if parts.len() == 2 && parts[0].len() == 1 {
                "f.last"
            } else if parts.len() == 2 && parts[1].len() == 1 {
                "first.l"
            } else {
                "other"
            }
        } else if local.contains('_') {
            "first_last"
        } else if local.contains('-') {
            "first-last"
        } else {
            "other"
        };

        *format_counts.entry(format).or_insert(0) += 1;
    }

    format_counts
        .into_iter()
        .max_by_key(|&(_, count)| count)
        .map(|(fmt, _)| fmt.to_string())
}

/// Extract technology stack from job posting text.
pub fn extract_tech_from_job_postings(postings: &[&str]) -> Vec<OrgTechStackItem> {
    let tech_patterns: Vec<(&str, TechCategory)> = vec![
        ("python", TechCategory::Language),
        ("java ", TechCategory::Language),
        ("javascript", TechCategory::Language),
        ("typescript", TechCategory::Language),
        ("golang", TechCategory::Language),
        ("rust", TechCategory::Language),
        ("c++", TechCategory::Language),
        ("c#", TechCategory::Language),
        ("ruby", TechCategory::Language),
        ("kotlin", TechCategory::Language),
        ("swift", TechCategory::Language),
        ("scala", TechCategory::Language),
        ("react", TechCategory::Framework),
        ("angular", TechCategory::Framework),
        ("vue", TechCategory::Framework),
        ("django", TechCategory::Framework),
        ("flask", TechCategory::Framework),
        ("spring", TechCategory::Framework),
        ("rails", TechCategory::Framework),
        ("express", TechCategory::Framework),
        ("next.js", TechCategory::Framework),
        ("fastapi", TechCategory::Framework),
        ("postgresql", TechCategory::Database),
        ("mysql", TechCategory::Database),
        ("mongodb", TechCategory::Database),
        ("redis", TechCategory::Database),
        ("elasticsearch", TechCategory::Database),
        ("dynamodb", TechCategory::Database),
        ("cassandra", TechCategory::Database),
        ("aws", TechCategory::Cloud),
        ("azure", TechCategory::Cloud),
        ("gcp", TechCategory::Cloud),
        ("google cloud", TechCategory::Cloud),
        ("docker", TechCategory::Container),
        ("kubernetes", TechCategory::Container),
        ("terraform", TechCategory::Container),
        ("jenkins", TechCategory::Ci),
        ("github actions", TechCategory::Ci),
        ("gitlab ci", TechCategory::Ci),
        ("circleci", TechCategory::Ci),
        ("datadog", TechCategory::Monitoring),
        ("prometheus", TechCategory::Monitoring),
        ("grafana", TechCategory::Monitoring),
        ("new relic", TechCategory::Monitoring),
        ("kafka", TechCategory::MessageQueue),
        ("rabbitmq", TechCategory::MessageQueue),
        ("sqs", TechCategory::MessageQueue),
        ("cloudflare", TechCategory::Cdn),
        ("akamai", TechCategory::Cdn),
        ("fastly", TechCategory::Cdn),
    ];

    let mut found: HashMap<String, (TechCategory, usize)> = HashMap::new();

    for posting in postings {
        let lower = posting.to_lowercase();
        for &(pattern, category) in &tech_patterns {
            if lower.contains(pattern) {
                let entry = found
                    .entry(pattern.trim().to_string())
                    .or_insert((category, 0));
                entry.1 += 1;
            }
        }
    }

    let total_postings = postings.len().max(1) as f64;
    let mut items: Vec<OrgTechStackItem> = found
        .into_iter()
        .map(|(tech, (category, count))| {
            let confidence = (count as f64 / total_postings).min(1.0);
            OrgTechStackItem {
                technology: tech,
                category,
                evidence: vec![TechEvidence {
                    source_type: TechEvidenceType::JobPosting,
                    detail: format!("Found in {count} of {total_postings} job postings"),
                }],
                confidence,
            }
        })
        .collect();

    items.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
    items
}

/// Detect vendor integrations from DNS records (SPF, MX, CNAME).
pub fn detect_vendors_from_dns(
    mx_records: &[&str],
    spf_record: Option<&str>,
    cname_records: &[(&str, &str)],
) -> Vec<VendorIntegration> {
    let mut vendors = Vec::new();

    let mx_vendors: Vec<(&str, &str)> = vec![
        ("google", "Google Workspace"),
        ("outlook", "Microsoft 365"),
        ("protonmail", "ProtonMail"),
        ("zoho", "Zoho Mail"),
        ("mimecast", "Mimecast"),
        ("barracuda", "Barracuda"),
        ("pphosted", "Proofpoint"),
        ("messagelabs", "Symantec MessageLabs"),
    ];

    for mx in mx_records {
        let lower = mx.to_lowercase();
        for &(pattern, vendor) in &mx_vendors {
            if lower.contains(pattern) {
                vendors.push(VendorIntegration {
                    vendor_name: vendor.to_string(),
                    service_type: VendorServiceType::EmailProvider,
                    detection_method: format!("MX record: {mx}"),
                    domains: vec![mx.to_string()],
                    confidence: 0.95,
                });
            }
        }
    }

    if let Some(spf) = spf_record {
        let spf_vendors: Vec<(&str, &str, VendorServiceType)> = vec![
            (
                "include:_spf.google.com",
                "Google Workspace",
                VendorServiceType::EmailProvider,
            ),
            (
                "include:spf.protection.outlook.com",
                "Microsoft 365",
                VendorServiceType::EmailProvider,
            ),
            (
                "include:sendgrid.net",
                "SendGrid",
                VendorServiceType::MarketingTool,
            ),
            (
                "include:amazonses.com",
                "Amazon SES",
                VendorServiceType::EmailProvider,
            ),
            (
                "include:mailgun.org",
                "Mailgun",
                VendorServiceType::MarketingTool,
            ),
            (
                "include:servers.mcsv.net",
                "Mailchimp",
                VendorServiceType::MarketingTool,
            ),
            (
                "include:sparkpostmail.com",
                "SparkPost",
                VendorServiceType::MarketingTool,
            ),
            ("include:zendesk.com", "Zendesk", VendorServiceType::Other),
            (
                "include:freshdesk.com",
                "Freshdesk",
                VendorServiceType::Other,
            ),
            (
                "include:helpscout.net",
                "HelpScout",
                VendorServiceType::Other,
            ),
        ];

        for &(pattern, vendor, ref svc_type) in &spf_vendors {
            if spf.contains(pattern) {
                vendors.push(VendorIntegration {
                    vendor_name: vendor.to_string(),
                    service_type: *svc_type,
                    detection_method: format!("SPF include: {pattern}"),
                    domains: vec![],
                    confidence: 0.90,
                });
            }
        }
    }

    let cname_vendors: Vec<(&str, &str, VendorServiceType)> = vec![
        (
            "cloudfront.net",
            "AWS CloudFront",
            VendorServiceType::CdnProvider,
        ),
        ("cloudflare", "Cloudflare", VendorServiceType::CdnProvider),
        ("akamaiedge.net", "Akamai", VendorServiceType::CdnProvider),
        ("fastly.net", "Fastly", VendorServiceType::CdnProvider),
        ("azureedge.net", "Azure CDN", VendorServiceType::CdnProvider),
        ("herokuapp.com", "Heroku", VendorServiceType::CloudProvider),
        ("netlify.app", "Netlify", VendorServiceType::CloudProvider),
        ("vercel", "Vercel", VendorServiceType::CloudProvider),
        (
            "wpengine.com",
            "WP Engine",
            VendorServiceType::CloudProvider,
        ),
        ("pantheon.io", "Pantheon", VendorServiceType::CloudProvider),
        ("auth0.com", "Auth0", VendorServiceType::AuthProvider),
        ("okta.com", "Okta", VendorServiceType::AuthProvider),
        ("stripe.com", "Stripe", VendorServiceType::PaymentProcessor),
    ];

    for &(subdomain, target) in cname_records {
        let lower = target.to_lowercase();
        for &(pattern, vendor, ref svc_type) in &cname_vendors {
            if lower.contains(pattern) {
                vendors.push(VendorIntegration {
                    vendor_name: vendor.to_string(),
                    service_type: *svc_type,
                    detection_method: format!("CNAME: {subdomain} -> {target}"),
                    domains: vec![subdomain.to_string(), target.to_string()],
                    confidence: 0.85,
                });
            }
        }
    }

    vendors
}

/// Detect vendor integrations from JavaScript includes on pages.
pub fn detect_vendors_from_js(js_urls: &[&str]) -> Vec<VendorIntegration> {
    let js_vendors: Vec<(&str, &str, VendorServiceType)> = vec![
        (
            "google-analytics.com",
            "Google Analytics",
            VendorServiceType::AnalyticsProvider,
        ),
        (
            "googletagmanager.com",
            "Google Tag Manager",
            VendorServiceType::AnalyticsProvider,
        ),
        (
            "segment.com",
            "Segment",
            VendorServiceType::AnalyticsProvider,
        ),
        (
            "mixpanel.com",
            "Mixpanel",
            VendorServiceType::AnalyticsProvider,
        ),
        (
            "amplitude.com",
            "Amplitude",
            VendorServiceType::AnalyticsProvider,
        ),
        ("hotjar.com", "Hotjar", VendorServiceType::AnalyticsProvider),
        (
            "fullstory.com",
            "FullStory",
            VendorServiceType::AnalyticsProvider,
        ),
        ("intercom.io", "Intercom", VendorServiceType::MarketingTool),
        ("drift.com", "Drift", VendorServiceType::MarketingTool),
        ("hubspot.com", "HubSpot", VendorServiceType::MarketingTool),
        ("stripe.com", "Stripe", VendorServiceType::PaymentProcessor),
        (
            "js.braintreegateway.com",
            "Braintree",
            VendorServiceType::PaymentProcessor,
        ),
        ("sentry.io", "Sentry", VendorServiceType::SecurityTool),
        ("datadoghq.com", "Datadog", VendorServiceType::SecurityTool),
        ("newrelic.com", "New Relic", VendorServiceType::SecurityTool),
        ("cdn.auth0.com", "Auth0", VendorServiceType::AuthProvider),
        (
            "recaptcha",
            "Google reCAPTCHA",
            VendorServiceType::SecurityTool,
        ),
        ("hcaptcha.com", "hCaptcha", VendorServiceType::SecurityTool),
        ("cloudflare", "Cloudflare", VendorServiceType::CdnProvider),
    ];

    let mut vendors = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for url in js_urls {
        let lower = url.to_lowercase();
        for &(pattern, vendor, ref svc_type) in &js_vendors {
            if lower.contains(pattern) && seen.insert(vendor) {
                vendors.push(VendorIntegration {
                    vendor_name: vendor.to_string(),
                    service_type: *svc_type,
                    detection_method: format!("JS include: {url}"),
                    domains: vec![url.to_string()],
                    confidence: 0.80,
                });
            }
        }
    }

    vendors
}

/// Identify subsidiaries from shared infrastructure patterns.
pub fn identify_subsidiaries(
    shared_ns: &[(&str, &[&str])],
    shared_asn: &[(&str, u32)],
    known_acquisitions: &[(&str, &str, Option<&str>)],
) -> Vec<Subsidiary> {
    let mut subsidiaries = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for &(company, nameservers) in shared_ns {
        if seen.insert(company.to_lowercase()) {
            subsidiaries.push(Subsidiary {
                name: company.to_string(),
                relationship: SubsidiaryRelationship::SharedInfrastructure,
                shared_infra: nameservers.iter().map(|s| s.to_string()).collect(),
                confidence: 0.60,
            });
        }
    }

    for &(company, asn) in shared_asn {
        let lower = company.to_lowercase();
        if let Some(existing) = subsidiaries
            .iter_mut()
            .find(|s| s.name.to_lowercase() == lower)
        {
            existing.shared_infra.push(format!("ASN:{asn}"));
            existing.confidence = (existing.confidence + 0.15).min(1.0);
        } else if seen.insert(lower) {
            subsidiaries.push(Subsidiary {
                name: company.to_string(),
                relationship: SubsidiaryRelationship::SharedInfrastructure,
                shared_infra: vec![format!("ASN:{asn}")],
                confidence: 0.50,
            });
        }
    }

    for &(target, event_type, date) in known_acquisitions {
        let lower = target.to_lowercase();
        let relationship = match event_type {
            "acquisition" => SubsidiaryRelationship::Acquisition,
            "merger" => SubsidiaryRelationship::Merger,
            "partnership" => SubsidiaryRelationship::Partnership,
            _ => SubsidiaryRelationship::Unknown,
        };

        if let Some(existing) = subsidiaries
            .iter_mut()
            .find(|s| s.name.to_lowercase() == lower)
        {
            existing.relationship = relationship;
            existing.confidence = 0.90;
            if let Some(d) = date {
                existing.shared_infra.push(format!("acquired:{d}"));
            }
        } else {
            seen.insert(lower);
            let mut infra = Vec::new();
            if let Some(d) = date {
                infra.push(format!("acquired:{d}"));
            }
            subsidiaries.push(Subsidiary {
                name: target.to_string(),
                relationship,
                shared_infra: infra,
                confidence: 0.90,
            });
        }
    }

    subsidiaries
}

/// Assess M&A security implications.
pub fn assess_ma_security(events: &[(&str, &str, Option<&str>)]) -> Vec<MaEvent> {
    events
        .iter()
        .map(|&(target, event_type, date)| {
            let etype = match event_type {
                "acquisition" => MaEventType::Acquisition,
                "merger" => MaEventType::Merger,
                "divestiture" => MaEventType::Divestiture,
                "spinoff" => MaEventType::Spin_off,
                _ => MaEventType::ManagementChange,
            };

            let implications = match etype {
                MaEventType::Acquisition => vec![
                    "Legacy systems may not be fully integrated".to_string(),
                    "Separate authentication systems may persist".to_string(),
                    "Network segmentation likely incomplete".to_string(),
                    "Old domain names may still resolve".to_string(),
                ],
                MaEventType::Merger => vec![
                    "Dual infrastructure during integration".to_string(),
                    "Policy conflicts between merged entities".to_string(),
                    "Employee access sprawl".to_string(),
                ],
                MaEventType::Divestiture | MaEventType::Spin_off => vec![
                    "Shared credentials may not be rotated".to_string(),
                    "Divested systems may retain access".to_string(),
                    "DNS/infrastructure overlap persists".to_string(),
                ],
                MaEventType::ManagementChange => vec![
                    "Security priorities may shift".to_string(),
                    "Audit trail gaps during transition".to_string(),
                ],
            };

            let risk_score = match etype {
                MaEventType::Acquisition => 0.80,
                MaEventType::Merger => 0.75,
                MaEventType::Divestiture | MaEventType::Spin_off => 0.70,
                MaEventType::ManagementChange => 0.40,
            };

            MaEvent {
                event_type: etype,
                target_company: target.to_string(),
                date: date.map(String::from),
                security_implications: implications,
                risk_score,
            }
        })
        .collect()
}

/// Build the full org footprint from gathered intelligence.
pub fn build_org_footprint(
    primary_domain: &str,
    owned_domains: Vec<OwnedDomain>,
    ip_ranges: Vec<IpRange>,
    bgp_prefixes: Vec<BgpPrefix>,
    employees: Vec<OrgEmployee>,
    tech_stack: Vec<OrgTechStackItem>,
    vendors: Vec<VendorIntegration>,
    locations: Vec<PhysicalLocation>,
    subsidiaries: Vec<Subsidiary>,
    ma_events: Vec<MaEvent>,
    email_format: Option<String>,
) -> OrgFootprint {
    let domain_score = (owned_domains.len() as f64 / 10.0).min(1.0) * 15.0;
    let ip_score = (ip_ranges.len() as f64 / 5.0).min(1.0) * 15.0;
    let employee_score = (employees.len() as f64 / 100.0).min(1.0) * 20.0;
    let tech_score = (tech_stack.len() as f64 / 20.0).min(1.0) * 10.0;
    let vendor_score = (vendors.len() as f64 / 10.0).min(1.0) * 15.0;
    let subsidiary_score = (subsidiaries.len() as f64 / 5.0).min(1.0) * 10.0;
    let ma_score = ma_events
        .iter()
        .map(|e| e.risk_score)
        .sum::<f64>()
        .min(15.0);

    let total = (domain_score
        + ip_score
        + employee_score
        + tech_score
        + vendor_score
        + subsidiary_score
        + ma_score)
        .min(100.0);

    OrgFootprint {
        primary_domain: primary_domain.to_string(),
        owned_domains,
        ip_ranges,
        bgp_prefixes,
        employees,
        tech_stack,
        vendors,
        locations,
        subsidiaries,
        ma_events,
        email_format,
        total_exposure_score: total,
    }
}
