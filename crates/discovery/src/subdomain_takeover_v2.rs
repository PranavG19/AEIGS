use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

/// Maximum depth for CNAME chain resolution.
const MAX_CNAME_DEPTH: usize = 10;

/// Default concurrency limit for parallel DNS resolution.
const DEFAULT_CONCURRENCY: usize = 50;

/// Default HTTP verification timeout in seconds.
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 10;

/// Cloud service provider that a CNAME may point to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CloudService {
    GithubPages,
    Heroku,
    AwsS3,
    AwsElasticBeanstalk,
    AwsCloudFront,
    AzureWebsites,
    AzureTrafficManager,
    Shopify,
    Fastly,
    Pantheon,
    Tumblr,
    WordPress,
    Ghost,
    Surge,
    Bitbucket,
    Zendesk,
    Readme,
    CargoCollective,
    Fly,
    Netlify,
    Unknown(String),
}

impl fmt::Display for CloudService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloudService::GithubPages => write!(f, "GitHub Pages"),
            CloudService::Heroku => write!(f, "Heroku"),
            CloudService::AwsS3 => write!(f, "AWS S3"),
            CloudService::AwsElasticBeanstalk => write!(f, "AWS Elastic Beanstalk"),
            CloudService::AwsCloudFront => write!(f, "AWS CloudFront"),
            CloudService::AzureWebsites => write!(f, "Azure Websites"),
            CloudService::AzureTrafficManager => write!(f, "Azure Traffic Manager"),
            CloudService::Shopify => write!(f, "Shopify"),
            CloudService::Fastly => write!(f, "Fastly"),
            CloudService::Pantheon => write!(f, "Pantheon"),
            CloudService::Tumblr => write!(f, "Tumblr"),
            CloudService::WordPress => write!(f, "WordPress"),
            CloudService::Ghost => write!(f, "Ghost"),
            CloudService::Surge => write!(f, "Surge"),
            CloudService::Bitbucket => write!(f, "Bitbucket"),
            CloudService::Zendesk => write!(f, "Zendesk"),
            CloudService::Readme => write!(f, "Readme.io"),
            CloudService::CargoCollective => write!(f, "Cargo Collective"),
            CloudService::Fly => write!(f, "Fly.io"),
            CloudService::Netlify => write!(f, "Netlify"),
            CloudService::Unknown(s) => write!(f, "Unknown({})", s),
        }
    }
}

/// Confidence level for takeover detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TakeoverConfidence {
    /// DNS points to service but not conclusively vulnerable.
    Possible,
    /// CNAME is dangling and service pattern matches.
    Likely,
    /// HTTP verification confirmed the takeover signature.
    Confirmed,
}

impl TakeoverConfidence {
    /// Numeric priority score for ranking findings.
    pub fn priority_score(&self) -> f64 {
        match self {
            TakeoverConfidence::Possible => 0.3,
            TakeoverConfidence::Likely => 0.7,
            TakeoverConfidence::Confirmed => 1.0,
        }
    }
}

impl fmt::Display for TakeoverConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TakeoverConfidence::Possible => write!(f, "possible"),
            TakeoverConfidence::Likely => write!(f, "likely"),
            TakeoverConfidence::Confirmed => write!(f, "confirmed"),
        }
    }
}

/// A single link in a CNAME resolution chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CnameLink {
    pub source: String,
    pub target: String,
}

/// Full CNAME chain from original subdomain to terminal record.
#[derive(Debug, Clone)]
pub struct CnameChain {
    pub links: Vec<CnameLink>,
    pub is_dangling: bool,
}

impl CnameChain {
    pub fn depth(&self) -> usize {
        self.links.len()
    }

    pub fn terminal(&self) -> Option<&str> {
        self.links.last().map(|l| l.target.as_str())
    }

    pub fn root(&self) -> Option<&str> {
        self.links.first().map(|l| l.source.as_str())
    }
}

/// Known takeover signature: CNAME pattern + HTTP body fingerprint.
#[derive(Debug, Clone)]
pub struct TakeoverSignature {
    pub service: CloudService,
    pub cname_patterns: Vec<String>,
    pub http_fingerprints: Vec<String>,
    pub is_edge_case: bool,
}

/// A confirmed or suspected subdomain takeover finding.
#[derive(Debug, Clone)]
pub struct TakeoverFinding {
    pub subdomain: String,
    pub service: CloudService,
    pub confidence: TakeoverConfidence,
    pub cname_chain: CnameChain,
    pub http_body_match: Option<String>,
    pub priority_score: f64,
}

/// DNS resolution result for a single subdomain (takeover-specific).
#[derive(Debug, Clone)]
pub struct TakeoverDnsResult {
    pub subdomain: String,
    pub cname_chain: CnameChain,
    pub a_records: Vec<String>,
    pub error: Option<String>,
}

/// Configuration for subdomain takeover scanning.
#[derive(Debug, Clone)]
pub struct TakeoverConfig {
    pub concurrency: usize,
    pub max_cname_depth: usize,
    pub http_timeout: Duration,
    pub verify_http: bool,
    pub user_agent: String,
}

impl Default for TakeoverConfig {
    fn default() -> Self {
        Self {
            concurrency: DEFAULT_CONCURRENCY,
            max_cname_depth: MAX_CNAME_DEPTH,
            http_timeout: Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS),
            verify_http: true,
            user_agent: "Mozilla/5.0 (compatible; Aegis-Scanner/1.0)".to_string(),
        }
    }
}

impl TakeoverConfig {
    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }

    pub fn with_max_cname_depth(mut self, depth: usize) -> Self {
        self.max_cname_depth = depth;
        self
    }

    pub fn with_http_timeout(mut self, timeout: Duration) -> Self {
        self.http_timeout = timeout;
        self
    }

    pub fn with_verify_http(mut self, verify: bool) -> Self {
        self.verify_http = verify;
        self
    }

    pub fn with_user_agent(mut self, agent: String) -> Self {
        self.user_agent = agent;
        self
    }
}

/// Builds the full signature database for known cloud service takeover patterns.
pub fn build_signature_database() -> Vec<TakeoverSignature> {
    vec![
        TakeoverSignature {
            service: CloudService::GithubPages,
            cname_patterns: vec![
                ".github.io".to_string(),
                ".githubusercontent.com".to_string(),
            ],
            http_fingerprints: vec![
                "There isn't a GitHub Pages site here.".to_string(),
                "For root URLs (like http://example.com/) you must provide an index.html file"
                    .to_string(),
            ],
            is_edge_case: false,
        },
        TakeoverSignature {
            service: CloudService::Heroku,
            cname_patterns: vec![
                ".herokudns.com".to_string(),
                ".herokussl.com".to_string(),
                ".herokuapp.com".to_string(),
            ],
            http_fingerprints: vec![
                "No such app".to_string(),
                "no-such-app".to_string(),
                "herokucdn.com/error-pages/no-such-app.html".to_string(),
            ],
            is_edge_case: false,
        },
        TakeoverSignature {
            service: CloudService::AwsS3,
            cname_patterns: vec![
                ".s3.amazonaws.com".to_string(),
                ".s3-website".to_string(),
                ".s3.".to_string(),
            ],
            http_fingerprints: vec![
                "NoSuchBucket".to_string(),
                "The specified bucket does not exist".to_string(),
            ],
            is_edge_case: false,
        },
        TakeoverSignature {
            service: CloudService::AwsElasticBeanstalk,
            cname_patterns: vec![".elasticbeanstalk.com".to_string()],
            http_fingerprints: vec![],
            is_edge_case: true,
        },
        TakeoverSignature {
            service: CloudService::AwsCloudFront,
            cname_patterns: vec![".cloudfront.net".to_string()],
            http_fingerprints: vec![
                "Bad request".to_string(),
                "ERROR: The request could not be satisfied".to_string(),
            ],
            is_edge_case: true,
        },
        TakeoverSignature {
            service: CloudService::AzureWebsites,
            cname_patterns: vec![
                ".azurewebsites.net".to_string(),
                ".cloudapp.net".to_string(),
                ".cloudapp.azure.com".to_string(),
            ],
            http_fingerprints: vec![
                "404 Web Site not found".to_string(),
                "Azure Web Apps".to_string(),
            ],
            is_edge_case: false,
        },
        TakeoverSignature {
            service: CloudService::AzureTrafficManager,
            cname_patterns: vec![".trafficmanager.net".to_string()],
            http_fingerprints: vec![],
            is_edge_case: true,
        },
        TakeoverSignature {
            service: CloudService::Shopify,
            cname_patterns: vec![
                ".myshopify.com".to_string(),
                "shops.myshopify.com".to_string(),
            ],
            http_fingerprints: vec![
                "Sorry, this shop is currently unavailable.".to_string(),
                "Only one step left!".to_string(),
            ],
            is_edge_case: false,
        },
        TakeoverSignature {
            service: CloudService::Fastly,
            cname_patterns: vec![
                ".fastly.net".to_string(),
                ".fastlylb.net".to_string(),
                ".map.fastly.net".to_string(),
            ],
            http_fingerprints: vec![
                "Fastly error: unknown domain".to_string(),
                "Fastly - Error".to_string(),
            ],
            is_edge_case: false,
        },
        TakeoverSignature {
            service: CloudService::Pantheon,
            cname_patterns: vec![".pantheonsite.io".to_string(), ".pantheon.io".to_string()],
            http_fingerprints: vec![
                "404 error unknown site!".to_string(),
                "The gods are wise".to_string(),
            ],
            is_edge_case: false,
        },
        TakeoverSignature {
            service: CloudService::Tumblr,
            cname_patterns: vec![".tumblr.com".to_string(), "domains.tumblr.com".to_string()],
            http_fingerprints: vec![
                "Whatever you were looking for doesn't currently exist at this address".to_string(),
                "There's nothing here.".to_string(),
            ],
            is_edge_case: false,
        },
        TakeoverSignature {
            service: CloudService::WordPress,
            cname_patterns: vec![".wordpress.com".to_string()],
            http_fingerprints: vec!["Do you want to register".to_string()],
            is_edge_case: false,
        },
        TakeoverSignature {
            service: CloudService::Ghost,
            cname_patterns: vec![".ghost.io".to_string()],
            http_fingerprints: vec!["The thing you were looking for is no longer here".to_string()],
            is_edge_case: false,
        },
        TakeoverSignature {
            service: CloudService::Surge,
            cname_patterns: vec![".surge.sh".to_string()],
            http_fingerprints: vec!["project not found".to_string()],
            is_edge_case: false,
        },
        TakeoverSignature {
            service: CloudService::Bitbucket,
            cname_patterns: vec![".bitbucket.io".to_string()],
            http_fingerprints: vec!["Repository not found".to_string()],
            is_edge_case: false,
        },
        TakeoverSignature {
            service: CloudService::Zendesk,
            cname_patterns: vec![".zendesk.com".to_string()],
            http_fingerprints: vec![
                "Help Center Closed".to_string(),
                "this help center no longer exists".to_string(),
            ],
            is_edge_case: false,
        },
        TakeoverSignature {
            service: CloudService::Readme,
            cname_patterns: vec![".readme.io".to_string()],
            http_fingerprints: vec!["Project doesnt exist".to_string()],
            is_edge_case: false,
        },
        TakeoverSignature {
            service: CloudService::CargoCollective,
            cname_patterns: vec![
                ".cargocollective.com".to_string(),
                "subdomain.cargocollective.com".to_string(),
            ],
            http_fingerprints: vec!["404 Not Found".to_string()],
            is_edge_case: false,
        },
        TakeoverSignature {
            service: CloudService::Fly,
            cname_patterns: vec![".fly.dev".to_string()],
            http_fingerprints: vec!["404 Not Found".to_string()],
            is_edge_case: false,
        },
        TakeoverSignature {
            service: CloudService::Netlify,
            cname_patterns: vec![".netlify.app".to_string(), ".netlify.com".to_string()],
            http_fingerprints: vec!["Not Found - Request ID".to_string()],
            is_edge_case: false,
        },
    ]
}

/// Identify which cloud service a CNAME target points to.
pub fn identify_service(
    cname_target: &str,
    signatures: &[TakeoverSignature],
) -> Option<CloudService> {
    let lower = cname_target.to_lowercase();
    for sig in signatures {
        for pattern in &sig.cname_patterns {
            if lower.ends_with(pattern) || lower.contains(pattern) {
                return Some(sig.service.clone());
            }
        }
    }
    None
}

/// Check HTTP response body against known takeover fingerprints.
pub fn check_http_fingerprint(
    body: &str,
    service: &CloudService,
    signatures: &[TakeoverSignature],
) -> Option<String> {
    for sig in signatures {
        if sig.service != *service {
            continue;
        }
        for fingerprint in &sig.http_fingerprints {
            if body.contains(fingerprint) {
                return Some(fingerprint.clone());
            }
        }
    }
    None
}

/// Determine if a CNAME chain is dangling (terminal record doesn't resolve).
pub fn is_dangling_cname(chain: &CnameChain, a_records: &[String]) -> bool {
    if chain.links.is_empty() {
        return false;
    }
    chain.is_dangling || a_records.is_empty()
}

/// Assess takeover confidence based on available evidence.
pub fn assess_confidence(
    chain: &CnameChain,
    a_records: &[String],
    service: &CloudService,
    http_body_match: &Option<String>,
    signatures: &[TakeoverSignature],
) -> TakeoverConfidence {
    let is_edge = signatures
        .iter()
        .find(|s| s.service == *service)
        .map(|s| s.is_edge_case)
        .unwrap_or(false);

    if http_body_match.is_some() {
        return TakeoverConfidence::Confirmed;
    }

    if is_dangling_cname(chain, a_records) && !is_edge {
        return TakeoverConfidence::Likely;
    }

    TakeoverConfidence::Possible
}

/// Compute priority score from confidence and service risk.
pub fn compute_priority(confidence: TakeoverConfidence, service: &CloudService) -> f64 {
    let base = confidence.priority_score();
    let service_multiplier = match service {
        CloudService::AwsS3 => 1.0,
        CloudService::GithubPages => 0.95,
        CloudService::AzureWebsites => 0.95,
        CloudService::Heroku => 0.9,
        CloudService::Shopify => 0.85,
        CloudService::Fastly => 0.9,
        CloudService::AwsCloudFront => 0.9,
        CloudService::AwsElasticBeanstalk => 0.85,
        CloudService::AzureTrafficManager => 0.85,
        CloudService::Netlify => 0.8,
        CloudService::Pantheon => 0.75,
        CloudService::Tumblr => 0.7,
        CloudService::WordPress => 0.7,
        CloudService::Ghost => 0.65,
        CloudService::Surge => 0.6,
        CloudService::Bitbucket => 0.75,
        CloudService::Zendesk => 0.7,
        CloudService::Readme => 0.6,
        CloudService::CargoCollective => 0.5,
        CloudService::Fly => 0.75,
        CloudService::Unknown(_) => 0.4,
    };
    base * service_multiplier
}

/// Analyze a single DNS result for potential subdomain takeover.
pub fn analyze_dns_result(
    dns_result: &DnsResult,
    signatures: &[TakeoverSignature],
    http_body: Option<&str>,
) -> Option<TakeoverFinding> {
    let terminal = dns_result.cname_chain.terminal()?;
    let service = identify_service(terminal, signatures)?;

    let http_body_match =
        http_body.and_then(|body| check_http_fingerprint(body, &service, signatures));

    let confidence = assess_confidence(
        &dns_result.cname_chain,
        &dns_result.a_records,
        &service,
        &http_body_match,
        signatures,
    );

    let priority_score = compute_priority(confidence, &service);

    Some(TakeoverFinding {
        subdomain: dns_result.subdomain.clone(),
        service,
        confidence,
        cname_chain: dns_result.cname_chain.clone(),
        http_body_match,
        priority_score,
    })
}

/// Batch analyze multiple DNS results.
pub fn analyze_batch(
    dns_results: &[DnsResult],
    signatures: &[TakeoverSignature],
    http_bodies: &HashMap<String, String>,
) -> Vec<TakeoverFinding> {
    let mut findings: Vec<TakeoverFinding> = dns_results
        .iter()
        .filter_map(|result| {
            let body = http_bodies.get(&result.subdomain).map(|s| s.as_str());
            analyze_dns_result(result, signatures, body)
        })
        .collect();

    findings.sort_by(|a, b| {
        b.priority_score
            .partial_cmp(&a.priority_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    findings
}

/// Parse raw CNAME chain data into a structured chain.
pub fn parse_cname_chain(records: &[(String, String)], max_depth: usize) -> CnameChain {
    let mut links = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for (i, (source, target)) in records.iter().enumerate() {
        if i >= max_depth {
            break;
        }
        let key = (source.clone(), target.clone());
        if seen.contains(&key) {
            break;
        }
        seen.insert(key);
        links.push(CnameLink {
            source: source.clone(),
            target: target.clone(),
        });
    }

    CnameChain {
        links,
        is_dangling: false,
    }
}

/// Follow a CNAME chain through a lookup table, resolving up to max_depth levels.
pub fn resolve_cname_chain(
    start: &str,
    lookup: &HashMap<String, String>,
    max_depth: usize,
) -> CnameChain {
    let mut links = Vec::new();
    let mut current = start.to_string();
    let mut visited = std::collections::HashSet::new();

    for _ in 0..max_depth {
        if visited.contains(&current) {
            break;
        }
        visited.insert(current.clone());

        match lookup.get(&current) {
            Some(target) => {
                links.push(CnameLink {
                    source: current.clone(),
                    target: target.clone(),
                });
                current = target.clone();
            }
            None => break,
        }
    }

    let is_dangling = !links.is_empty() && !lookup.contains_key(&current);

    CnameChain { links, is_dangling }
}

/// Categorize all findings by service provider.
pub fn group_by_service(
    findings: &[TakeoverFinding],
) -> HashMap<CloudService, Vec<&TakeoverFinding>> {
    let mut groups: HashMap<CloudService, Vec<&TakeoverFinding>> = HashMap::new();
    for finding in findings {
        groups
            .entry(finding.service.clone())
            .or_default()
            .push(finding);
    }
    groups
}

/// Filter findings at or above a minimum confidence level.
pub fn filter_by_confidence(
    findings: &[TakeoverFinding],
    min_confidence: TakeoverConfidence,
) -> Vec<&TakeoverFinding> {
    findings
        .iter()
        .filter(|f| f.confidence >= min_confidence)
        .collect()
}

/// Summary statistics for a batch scan.
#[derive(Debug, Clone, Default)]
pub struct TakeoverSummary {
    pub total_checked: usize,
    pub total_findings: usize,
    pub confirmed: usize,
    pub likely: usize,
    pub possible: usize,
    pub services_affected: Vec<CloudService>,
}

/// Generate a summary from a set of findings.
pub fn summarize_findings(total_checked: usize, findings: &[TakeoverFinding]) -> TakeoverSummary {
    let mut services = std::collections::HashSet::new();
    let mut confirmed = 0;
    let mut likely = 0;
    let mut possible = 0;

    for f in findings {
        services.insert(f.service.clone());
        match f.confidence {
            TakeoverConfidence::Confirmed => confirmed += 1,
            TakeoverConfidence::Likely => likely += 1,
            TakeoverConfidence::Possible => possible += 1,
        }
    }

    TakeoverSummary {
        total_checked,
        total_findings: findings.len(),
        confirmed,
        likely,
        possible,
        services_affected: services.into_iter().collect(),
    }
}

/// Validate that a subdomain string is well-formed.
pub fn validate_subdomain(subdomain: &str) -> bool {
    if subdomain.is_empty() || subdomain.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = subdomain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
    }
    true
}

/// Extract the registerable domain from a subdomain (e.g., "a.b.example.com" -> "example.com").
pub fn extract_base_domain(subdomain: &str) -> Option<String> {
    let parts: Vec<&str> = subdomain.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    Some(format!(
        "{}.{}",
        parts[parts.len() - 2],
        parts[parts.len() - 1]
    ))
}
