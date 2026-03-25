use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::IpAddr;

/// Commonly leaked / high-value subdomain prefixes.
const LEAKED_PREFIXES: &[&str] = &[
    "internal",
    "admin",
    "vpn",
    "mail",
    "dev",
    "staging",
    "uat",
    "prod",
    "api",
    "cdn",
    "static",
    "jenkins",
    "ci",
    "git",
    "jira",
    "grafana",
    "kibana",
    "prometheus",
    "vault",
    "portal",
    "dashboard",
    "monitor",
    "test",
    "beta",
    "demo",
    "sandbox",
    "preprod",
    "backup",
    "db",
    "redis",
    "elastic",
    "kafka",
    "rabbit",
    "queue",
    "worker",
    "cron",
    "scheduler",
];

/// Environment-like prefix groups for permutation generation.
const ENV_PREFIXES: &[&str] = &[
    "dev", "staging", "uat", "prod", "preprod", "sandbox", "test", "qa", "demo", "beta", "canary",
    "nightly", "release", "hotfix",
];

/// Service-like suffix groups for permutation generation.
const SERVICE_SUFFIXES: &[&str] = &[
    "api",
    "web",
    "app",
    "admin",
    "portal",
    "dashboard",
    "auth",
    "sso",
    "gateway",
    "proxy",
    "cdn",
    "static",
    "media",
    "assets",
    "docs",
    "ws",
    "grpc",
    "graphql",
    "rest",
    "rpc",
];

/// Cloud provider subdomain patterns. Each tuple: (provider, template with `{}` placeholder).
const CLOUD_PATTERNS: &[(&str, &str)] = &[
    ("aws-s3", "{}.s3.amazonaws.com"),
    ("aws-s3-region", "{}.s3.us-east-1.amazonaws.com"),
    ("aws-eb", "{}.elasticbeanstalk.com"),
    ("aws-cloudfront", "{}.cloudfront.net"),
    ("aws-api-gw", "{}.execute-api.us-east-1.amazonaws.com"),
    ("azure-blob", "{}.blob.core.windows.net"),
    ("azure-web", "{}.azurewebsites.net"),
    ("azure-cdn", "{}.azureedge.net"),
    ("gcp-storage", "{}.storage.googleapis.com"),
    ("gcp-appspot", "{}.appspot.com"),
    ("gcp-run", "{}.run.app"),
    ("firebase", "{}.firebaseapp.com"),
    ("heroku", "{}.herokuapp.com"),
    ("netlify", "{}.netlify.app"),
    ("vercel", "{}.vercel.app"),
];

/// A learned naming pattern from observed subdomains.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NamingPattern {
    /// env-service pattern (e.g., "dev-api" → prefix=dev, suffix=api)
    EnvService { separator: char },
    /// service-env pattern (e.g., "api-staging")
    ServiceEnv { separator: char },
    /// name + number suffix (e.g., "web1", "web2")
    NumberedSuffix { base: String },
    /// prefix + name (e.g., "v2-api")
    VersionedPrefix { base: String },
    /// Bare prefix that matches a known leaked prefix
    LeakedPrefix,
}

/// A candidate subdomain with an associated priority score.
#[derive(Debug, Clone)]
pub struct ScoredCandidate {
    pub subdomain: String,
    pub score: f64,
    pub source: CandidateSource,
}

impl PartialEq for ScoredCandidate {
    fn eq(&self, other: &Self) -> bool {
        self.subdomain == other.subdomain
    }
}

impl Eq for ScoredCandidate {}

impl PartialOrd for ScoredCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScoredCandidate {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score
            .partial_cmp(&other.score)
            .unwrap_or(Ordering::Equal)
    }
}

/// Where a candidate was generated from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CandidateSource {
    PatternPermutation,
    NumberIteration,
    CloudAware,
    LeakedPrefix,
    ZoneWalk,
}

/// Result of wildcard DNS detection.
#[derive(Debug, Clone, PartialEq)]
pub struct WildcardDetection {
    pub is_wildcard: bool,
    pub wildcard_ip: Option<IpAddr>,
    pub probe_results: Vec<(String, Option<IpAddr>)>,
}

/// Response signature for filtering wildcard false positives.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResponseSignature {
    pub status_code: u16,
    pub content_length_bucket: u64,
    pub server_header: Option<String>,
}

/// NSEC/NSEC3 zone walking result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneWalkResult {
    pub discovered_names: Vec<String>,
    pub nsec_type: NsecType,
    pub walked_records: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NsecType {
    Nsec,
    Nsec3,
    NotSupported,
}

/// Configuration for the smart brute-forcer.
#[derive(Debug, Clone)]
pub struct SmartBruteForceConfig {
    pub max_number_iteration: u32,
    pub cloud_check_enabled: bool,
    pub zone_walk_enabled: bool,
    pub wildcard_probe_count: usize,
    pub max_candidates: usize,
}

impl Default for SmartBruteForceConfig {
    fn default() -> Self {
        Self {
            max_number_iteration: 100,
            cloud_check_enabled: true,
            zone_walk_enabled: true,
            wildcard_probe_count: 3,
            max_candidates: 10_000,
        }
    }
}

/// The intelligent subdomain brute-force engine.
#[derive(Debug)]
pub struct SmartBruteForcer {
    config: SmartBruteForceConfig,
    known_subdomains: Vec<String>,
    learned_patterns: Vec<NamingPattern>,
    pattern_frequency: HashMap<String, usize>,
}

impl SmartBruteForcer {
    pub fn new(config: SmartBruteForceConfig) -> Self {
        Self {
            config,
            known_subdomains: Vec::new(),
            learned_patterns: Vec::new(),
            pattern_frequency: HashMap::new(),
        }
    }

    /// Feed discovered subdomains to learn naming patterns.
    pub fn learn_from(&mut self, subdomains: &[String]) {
        self.known_subdomains.extend_from_slice(subdomains);
        for sub in subdomains {
            self.analyze_subdomain(sub);
        }
    }

    fn analyze_subdomain(&mut self, subdomain: &str) {
        let name = extract_first_label(subdomain);

        for sep in ['-', '_', '.'] {
            if let Some((left, right)) = name.split_once(sep) {
                if ENV_PREFIXES.contains(&left) {
                    self.learned_patterns
                        .push(NamingPattern::EnvService { separator: sep });
                    *self
                        .pattern_frequency
                        .entry(format!("env{sep}service"))
                        .or_insert(0) += 1;
                    *self
                        .pattern_frequency
                        .entry(format!("suffix:{right}"))
                        .or_insert(0) += 1;
                }
                if ENV_PREFIXES.contains(&right) {
                    self.learned_patterns
                        .push(NamingPattern::ServiceEnv { separator: sep });
                    *self
                        .pattern_frequency
                        .entry(format!("service{sep}env"))
                        .or_insert(0) += 1;
                    *self
                        .pattern_frequency
                        .entry(format!("prefix:{left}"))
                        .or_insert(0) += 1;
                }
                if SERVICE_SUFFIXES.contains(&right) {
                    *self
                        .pattern_frequency
                        .entry(format!("suffix:{right}"))
                        .or_insert(0) += 1;
                }
                if SERVICE_SUFFIXES.contains(&left) {
                    *self
                        .pattern_frequency
                        .entry(format!("prefix:{left}"))
                        .or_insert(0) += 1;
                }
            }
        }

        if let Some(base) = extract_number_base(&name) {
            self.learned_patterns.push(NamingPattern::NumberedSuffix {
                base: base.to_string(),
            });
            *self
                .pattern_frequency
                .entry(format!("numbered:{base}"))
                .or_insert(0) += 1;
        }

        if let Some(base) = extract_version_prefix(&name) {
            self.learned_patterns.push(NamingPattern::VersionedPrefix {
                base: base.to_string(),
            });
            *self
                .pattern_frequency
                .entry(format!("versioned:{base}"))
                .or_insert(0) += 1;
        }

        if LEAKED_PREFIXES.contains(&name.as_str()) {
            self.learned_patterns.push(NamingPattern::LeakedPrefix);
        }
    }

    /// Generate all candidates, ranked by priority score.
    pub fn generate_candidates(&self, domain: &str) -> Vec<ScoredCandidate> {
        let mut seen = HashSet::new();
        let mut heap: BinaryHeap<ScoredCandidate> = BinaryHeap::new();

        for candidate in self.generate_pattern_permutations(domain) {
            if seen.insert(candidate.subdomain.clone()) {
                heap.push(candidate);
            }
        }

        for candidate in self.generate_number_iterations(domain) {
            if seen.insert(candidate.subdomain.clone()) {
                heap.push(candidate);
            }
        }

        if self.config.cloud_check_enabled {
            for candidate in self.generate_cloud_candidates(domain) {
                if seen.insert(candidate.subdomain.clone()) {
                    heap.push(candidate);
                }
            }
        }

        for candidate in self.generate_leaked_prefix_candidates(domain) {
            if seen.insert(candidate.subdomain.clone()) {
                heap.push(candidate);
            }
        }

        let mut results = Vec::with_capacity(self.config.max_candidates.min(heap.len()));
        while let Some(candidate) = heap.pop() {
            results.push(candidate);
            if results.len() >= self.config.max_candidates {
                break;
            }
        }
        results
    }

    fn generate_pattern_permutations(&self, domain: &str) -> Vec<ScoredCandidate> {
        let mut candidates = Vec::new();
        let known_labels: HashSet<String> = self
            .known_subdomains
            .iter()
            .map(|s| extract_first_label(s))
            .collect();

        let observed_suffixes: Vec<&str> = self
            .pattern_frequency
            .keys()
            .filter_map(|k| k.strip_prefix("suffix:"))
            .collect();

        let observed_prefixes: Vec<&str> = self
            .pattern_frequency
            .keys()
            .filter_map(|k| k.strip_prefix("prefix:"))
            .collect();

        for sep in ['-', '_'] {
            let has_env_service = self
                .learned_patterns
                .iter()
                .any(|p| matches!(p, NamingPattern::EnvService { separator } if *separator == sep));

            if has_env_service {
                for env in ENV_PREFIXES {
                    for suffix in &observed_suffixes {
                        let label = format!("{env}{sep}{suffix}");
                        if !known_labels.contains(&label) {
                            let score = self.score_candidate(&label);
                            candidates.push(ScoredCandidate {
                                subdomain: format!("{label}.{domain}"),
                                score,
                                source: CandidateSource::PatternPermutation,
                            });
                        }
                    }
                    for svc in SERVICE_SUFFIXES {
                        let label = format!("{env}{sep}{svc}");
                        if !known_labels.contains(&label) {
                            let score = self.score_candidate(&label) * 0.8;
                            candidates.push(ScoredCandidate {
                                subdomain: format!("{label}.{domain}"),
                                score,
                                source: CandidateSource::PatternPermutation,
                            });
                        }
                    }
                }
            }

            let has_service_env = self
                .learned_patterns
                .iter()
                .any(|p| matches!(p, NamingPattern::ServiceEnv { separator } if *separator == sep));

            if has_service_env {
                for prefix in &observed_prefixes {
                    for env in ENV_PREFIXES {
                        let label = format!("{prefix}{sep}{env}");
                        if !known_labels.contains(&label) {
                            let score = self.score_candidate(&label);
                            candidates.push(ScoredCandidate {
                                subdomain: format!("{label}.{domain}"),
                                score,
                                source: CandidateSource::PatternPermutation,
                            });
                        }
                    }
                }
            }
        }

        candidates
    }

    fn generate_number_iterations(&self, domain: &str) -> Vec<ScoredCandidate> {
        let mut candidates = Vec::new();
        let mut seen_bases: HashMap<String, u32> = HashMap::new();

        for sub in &self.known_subdomains {
            let label = extract_first_label(sub);
            if let Some(base) = extract_number_base(&label)
                && let Some(num) = extract_trailing_number(&label)
            {
                let max_seen = seen_bases.entry(base.to_string()).or_insert(0);
                *max_seen = (*max_seen).max(num);
            }
        }

        for (base, max_seen) in &seen_bases {
            let start = max_seen + 1;
            let end = (start + self.config.max_number_iteration).min(start + 100);
            for n in 1..=end {
                let label = format!("{base}{n}");
                let distance_from_known = if n > *max_seen { n - max_seen } else { 0 };
                let score = 8.0 / (1.0 + distance_from_known as f64);
                candidates.push(ScoredCandidate {
                    subdomain: format!("{label}.{domain}"),
                    score,
                    source: CandidateSource::NumberIteration,
                });
            }
        }

        candidates
    }

    fn generate_cloud_candidates(&self, domain: &str) -> Vec<ScoredCandidate> {
        let mut candidates = Vec::new();
        let org_name = domain.split('.').next().unwrap_or(domain);

        let name_variants = vec![
            org_name.to_string(),
            format!("{org_name}-assets"),
            format!("{org_name}-backup"),
            format!("{org_name}-data"),
            format!("{org_name}-media"),
            format!("{org_name}-static"),
            format!("{org_name}-dev"),
            format!("{org_name}-staging"),
            format!("{org_name}-prod"),
            format!("{org_name}-logs"),
            format!("{org_name}-internal"),
        ];

        for (provider, template) in CLOUD_PATTERNS {
            for variant in &name_variants {
                let fqdn = template.replace("{}", variant);
                let score = match *provider {
                    "aws-s3" | "azure-blob" | "gcp-storage" => 6.0,
                    _ => 4.0,
                };
                candidates.push(ScoredCandidate {
                    subdomain: fqdn,
                    score,
                    source: CandidateSource::CloudAware,
                });
            }
        }

        candidates
    }

    fn generate_leaked_prefix_candidates(&self, domain: &str) -> Vec<ScoredCandidate> {
        let known_labels: HashSet<String> = self
            .known_subdomains
            .iter()
            .map(|s| extract_first_label(s))
            .collect();

        LEAKED_PREFIXES
            .iter()
            .filter(|p| !known_labels.contains(**p))
            .map(|prefix| ScoredCandidate {
                subdomain: format!("{prefix}.{domain}"),
                score: 5.0,
                source: CandidateSource::LeakedPrefix,
            })
            .collect()
    }

    fn score_candidate(&self, label: &str) -> f64 {
        let mut score = 1.0;

        if let Some((left, _)) = label.split_once('-') {
            let freq = self
                .pattern_frequency
                .get(&format!(
                    "suffix:{}",
                    label.split_once('-').map(|(_, r)| r).unwrap_or("")
                ))
                .copied()
                .unwrap_or(0);
            score += freq as f64 * 2.0;

            if ENV_PREFIXES.contains(&left) {
                score += 3.0;
            }
        }

        if let Some((_, right)) = label.split_once('-')
            && SERVICE_SUFFIXES.contains(&right)
        {
            score += 2.0;
        }

        score
    }

    /// Detect wildcard DNS by probing random subdomains.
    pub fn detect_wildcard(domain: &str, probe_count: usize) -> WildcardDetection {
        detect_wildcard_dns(domain, probe_count)
    }

    /// Filter out wildcard false positives from a set of resolved subdomains.
    pub fn filter_wildcard_responses(
        responses: &[(String, ResponseSignature)],
        wildcard_sig: &ResponseSignature,
    ) -> Vec<String> {
        responses
            .iter()
            .filter(|(_, sig)| !signatures_match(sig, wildcard_sig))
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Simulate NSEC zone walking (returns discovered names for DNSSEC-enabled domains).
    pub fn zone_walk(domain: &str) -> ZoneWalkResult {
        simulate_zone_walk(domain)
    }

    /// Get the learned patterns.
    pub fn patterns(&self) -> &[NamingPattern] {
        &self.learned_patterns
    }

    /// Get the pattern frequency map.
    pub fn pattern_frequencies(&self) -> &HashMap<String, usize> {
        &self.pattern_frequency
    }

    /// Get the list of cloud patterns supported.
    pub fn cloud_patterns() -> &'static [(&'static str, &'static str)] {
        CLOUD_PATTERNS
    }
}

fn extract_first_label(subdomain: &str) -> String {
    subdomain.split('.').next().unwrap_or(subdomain).to_string()
}

fn extract_number_base(label: &str) -> Option<&str> {
    let end = label.trim_end_matches(|c: char| c.is_ascii_digit());
    let num_part = &label[end.len()..];
    if !num_part.is_empty() && !end.is_empty() {
        Some(end)
    } else {
        None
    }
}

fn extract_trailing_number(label: &str) -> Option<u32> {
    let end = label.trim_end_matches(|c: char| c.is_ascii_digit());
    let num_part = &label[end.len()..];
    num_part.parse::<u32>().ok()
}

fn extract_version_prefix(label: &str) -> Option<&str> {
    if let Some(rest) = label.strip_prefix('v')
        && let Some(idx) = rest.find(|c: char| !c.is_ascii_digit())
    {
        let version_digits = &rest[..idx];
        if !version_digits.is_empty() && rest[idx..].starts_with('-') {
            return Some(&rest[idx + 1..]);
        }
    }
    None
}

/// Detect wildcard DNS for a domain by resolving random subdomain labels.
fn detect_wildcard_dns(domain: &str, probe_count: usize) -> WildcardDetection {
    let probes: Vec<String> = (0..probe_count.max(1))
        .map(|i| format!("aegis-wildcard-probe-{i}-xz9q7w.{domain}"))
        .collect();

    let mut resolved_ips: Vec<(String, Option<IpAddr>)> = Vec::new();
    let mut ip_counts: HashMap<IpAddr, usize> = HashMap::new();

    for probe in &probes {
        let ip = resolve_subdomain(probe);
        if let Some(addr) = ip {
            *ip_counts.entry(addr).or_insert(0) += 1;
        }
        resolved_ips.push((probe.clone(), ip));
    }

    let total_resolved = ip_counts.values().sum::<usize>();
    let is_wildcard = total_resolved == probe_count && probe_count > 0;

    let wildcard_ip = if is_wildcard {
        ip_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(ip, _)| ip)
    } else {
        None
    };

    WildcardDetection {
        is_wildcard,
        wildcard_ip,
        probe_results: resolved_ips,
    }
}

fn resolve_subdomain(_subdomain: &str) -> Option<IpAddr> {
    // In production this would do actual DNS resolution.
    // Returning None for non-test usage; tests inject behavior via detect_wildcard_dns_with_resolver.
    None
}

/// Compare two response signatures for wildcard filtering.
fn signatures_match(a: &ResponseSignature, b: &ResponseSignature) -> bool {
    a.status_code == b.status_code
        && a.server_header == b.server_header
        && content_length_similar(a.content_length_bucket, b.content_length_bucket)
}

fn content_length_similar(a: u64, b: u64) -> bool {
    let diff = a.abs_diff(b);
    let max_val = a.max(b).max(1);
    (diff as f64 / max_val as f64) < 0.05
}

/// Simulate NSEC zone walking. Real implementation would send DNS queries
/// and follow NSEC next-name chains.
fn simulate_zone_walk(domain: &str) -> ZoneWalkResult {
    // NSEC zone walking: query for a name, get NSEC record pointing to next name,
    // follow the chain. For NSEC3 the names are hashed so walking is blocked.
    // This provides the structural framework; actual DNS wire protocol is out of scope.
    let _ = domain;
    ZoneWalkResult {
        discovered_names: Vec::new(),
        nsec_type: NsecType::NotSupported,
        walked_records: 0,
    }
}

/// Testable wildcard detection with injectable resolver.
pub fn detect_wildcard_with_resolver<F>(
    domain: &str,
    probe_count: usize,
    resolver: F,
) -> WildcardDetection
where
    F: Fn(&str) -> Option<IpAddr>,
{
    let probes: Vec<String> = (0..probe_count.max(1))
        .map(|i| format!("aegis-wildcard-probe-{i}-xz9q7w.{domain}"))
        .collect();

    let mut resolved_ips: Vec<(String, Option<IpAddr>)> = Vec::new();
    let mut ip_counts: HashMap<IpAddr, usize> = HashMap::new();

    for probe in &probes {
        let ip = resolver(probe);
        if let Some(addr) = ip {
            *ip_counts.entry(addr).or_insert(0) += 1;
        }
        resolved_ips.push((probe.clone(), ip));
    }

    let total_resolved = ip_counts.values().sum::<usize>();
    let is_wildcard = total_resolved == probe_count && probe_count > 0;

    let wildcard_ip = if is_wildcard {
        ip_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(ip, _)| ip)
    } else {
        None
    };

    WildcardDetection {
        is_wildcard,
        wildcard_ip,
        probe_results: resolved_ips,
    }
}

/// Zone walk with injectable DNS query function for testing.
pub fn zone_walk_with_query<F>(domain: &str, query_fn: F) -> ZoneWalkResult
where
    F: Fn(&str) -> Option<(NsecType, Vec<String>)>,
{
    match query_fn(domain) {
        Some((nsec_type, names)) => {
            let walked = names.len();
            ZoneWalkResult {
                discovered_names: names,
                nsec_type,
                walked_records: walked,
            }
        }
        None => ZoneWalkResult {
            discovered_names: Vec::new(),
            nsec_type: NsecType::NotSupported,
            walked_records: 0,
        },
    }
}
