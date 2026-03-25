use std::collections::HashSet;

/// Raw IP range input: (cidr, asn, org, country).
pub type IpRangeEntry<'a> = (&'a str, Option<u32>, Option<&'a str>, Option<&'a str>);
/// Raw domain input: (domain, type, ips, first_seen, source).
pub type DomainEntry<'a> = (&'a str, &'a str, &'a [&'a str], Option<&'a str>, &'a str);
/// Raw service input: (ip, port, protocol, name, version, banner, tls).
pub type ServiceEntry<'a> = (
    &'a str,
    u16,
    &'a str,
    Option<&'a str>,
    Option<&'a str>,
    Option<&'a str>,
    bool,
);
/// Raw web app input: (url, title, technologies, status, server).
pub type WebAppEntry<'a> = (
    &'a str,
    Option<&'a str>,
    &'a [&'a str],
    u16,
    Option<&'a str>,
);
/// Raw API input: (url, type, authenticated, docs_url, methods).
pub type ApiEntry<'a> = (&'a str, &'a str, bool, Option<&'a str>, &'a [&'a str]);

/// Classification of a discovered domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DomainType {
    Primary,
    Subdomain,
    Alias,
    Wildcard,
}

/// How a domain was discovered.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DiscoverySource {
    DnsEnum,
    CertTransparency,
    WebCrawl,
    BruteForce,
    PassiveDns,
    SearchEngine,
    Shodan,
    Censys,
}

/// Transport-layer protocol for an exposed service.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServiceProtocol {
    Http,
    Https,
    Ssh,
    Ftp,
    Smtp,
    Dns,
    Rdp,
    Smb,
    Mysql,
    Postgres,
    Redis,
    Mongodb,
    Elasticsearch,
    Grpc,
    Custom(String),
}

/// Classification of a discovered API.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ApiType {
    Rest,
    GraphQL,
    Grpc,
    Soap,
    WebSocket,
}

/// Cloud infrastructure provider.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
    DigitalOcean,
    Cloudflare,
    Other(String),
}

/// Type of cloud-hosted asset.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CloudAssetType {
    S3Bucket,
    AzureBlob,
    GcpStorage,
    StaticSite,
    CdnEndpoint,
    FunctionEndpoint,
    ContainerRegistry,
    Database,
}

/// Risk severity for shadow IT findings.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ShadowItRisk {
    Critical,
    High,
    Medium,
    Low,
}

/// An IP address range with optional ASN metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct IpRange {
    pub cidr: String,
    pub asn: Option<u32>,
    pub org_name: Option<String>,
    pub country: Option<String>,
    pub ip_count: u32,
}

/// A domain discovered during attack surface enumeration.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredDomain {
    pub domain: String,
    pub domain_type: DomainType,
    pub ip_addresses: Vec<String>,
    pub first_seen: Option<String>,
    pub source: DiscoverySource,
}

/// A network service exposed on a host.
#[derive(Debug, Clone, PartialEq)]
pub struct ExposedService {
    pub ip: String,
    pub port: u16,
    pub protocol: ServiceProtocol,
    pub service_name: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub tls_enabled: bool,
}

/// A web application discovered at a URL.
#[derive(Debug, Clone, PartialEq)]
pub struct WebApplication {
    pub url: String,
    pub title: Option<String>,
    pub technologies: Vec<String>,
    pub status_code: u16,
    pub server_header: Option<String>,
    pub content_type: Option<String>,
}

/// An API endpoint discovered during enumeration.
#[derive(Debug, Clone, PartialEq)]
pub struct ApiEndpoint {
    pub url: String,
    pub api_type: ApiType,
    pub authenticated: bool,
    pub documentation_url: Option<String>,
    pub methods: Vec<String>,
}

/// A cloud-hosted asset detected via domain patterns or DNS records.
#[derive(Debug, Clone, PartialEq)]
pub struct CloudAsset {
    pub provider: CloudProvider,
    pub asset_type: CloudAssetType,
    pub identifier: String,
    pub url: Option<String>,
    pub publicly_accessible: bool,
    pub region: Option<String>,
}

/// An asset found outside the official inventory.
#[derive(Debug, Clone, PartialEq)]
pub struct ShadowItAsset {
    pub asset_type: String,
    pub identifier: String,
    pub evidence: String,
    pub risk: ShadowItRisk,
}

/// Aggregate counts for the attack surface.
#[derive(Debug, Clone, PartialEq)]
pub struct AttackSurfaceSummary {
    pub total_ips: usize,
    pub total_domains: usize,
    pub total_services: usize,
    pub total_web_apps: usize,
    pub total_apis: usize,
    pub total_cloud_assets: usize,
    pub high_risk_count: usize,
}

/// Full attack surface report for a target domain.
#[derive(Debug, Clone, PartialEq)]
pub struct AttackSurfaceReport {
    pub domain: String,
    pub ip_ranges: Vec<IpRange>,
    pub domains: Vec<DiscoveredDomain>,
    pub services: Vec<ExposedService>,
    pub web_apps: Vec<WebApplication>,
    pub apis: Vec<ApiEndpoint>,
    pub cloud_assets: Vec<CloudAsset>,
    pub shadow_it: Vec<ShadowItAsset>,
    pub total_attack_surface_score: f64,
    pub summary: AttackSurfaceSummary,
}

// ---------------------------------------------------------------------------
// IP range mapping
// ---------------------------------------------------------------------------

/// Calculate the number of IP addresses in a CIDR block.
pub fn calculate_ip_count(cidr: &str) -> u32 {
    let prefix_len = cidr
        .rsplit('/')
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(32);
    if prefix_len > 32 {
        return 1;
    }
    1u32.checked_shl(32 - prefix_len).unwrap_or(1)
}

/// Parse raw IP range tuples into typed `IpRange` values.
pub fn map_ip_ranges(ranges: &[IpRangeEntry<'_>]) -> Vec<IpRange> {
    ranges
        .iter()
        .map(|(cidr, asn, org, country)| IpRange {
            cidr: (*cidr).to_string(),
            asn: *asn,
            org_name: org.map(|s| s.to_string()),
            country: country.map(|s| s.to_string()),
            ip_count: calculate_ip_count(cidr),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Domain mapping
// ---------------------------------------------------------------------------

fn parse_domain_type(s: &str) -> DomainType {
    match s.to_lowercase().as_str() {
        "primary" => DomainType::Primary,
        "subdomain" => DomainType::Subdomain,
        "alias" => DomainType::Alias,
        "wildcard" => DomainType::Wildcard,
        _ => DomainType::Subdomain,
    }
}

fn parse_discovery_source(s: &str) -> DiscoverySource {
    match s.to_lowercase().as_str() {
        "dns_enum" | "dnsenum" => DiscoverySource::DnsEnum,
        "cert_transparency" | "certtransparency" => DiscoverySource::CertTransparency,
        "web_crawl" | "webcrawl" => DiscoverySource::WebCrawl,
        "brute_force" | "bruteforce" => DiscoverySource::BruteForce,
        "passive_dns" | "passivedns" => DiscoverySource::PassiveDns,
        "search_engine" | "searchengine" => DiscoverySource::SearchEngine,
        "shodan" => DiscoverySource::Shodan,
        "censys" => DiscoverySource::Censys,
        _ => DiscoverySource::PassiveDns,
    }
}

/// Map raw domain tuples into typed `DiscoveredDomain` values.
pub fn map_domains(domains: &[DomainEntry<'_>]) -> Vec<DiscoveredDomain> {
    domains
        .iter()
        .map(
            |(domain, type_str, ips, first_seen, source_str)| DiscoveredDomain {
                domain: (*domain).to_string(),
                domain_type: parse_domain_type(type_str),
                ip_addresses: ips.iter().map(|s| (*s).to_string()).collect(),
                first_seen: first_seen.map(|s| s.to_string()),
                source: parse_discovery_source(source_str),
            },
        )
        .collect()
}

// ---------------------------------------------------------------------------
// Service mapping
// ---------------------------------------------------------------------------

fn parse_service_protocol(s: &str) -> ServiceProtocol {
    match s.to_lowercase().as_str() {
        "http" => ServiceProtocol::Http,
        "https" => ServiceProtocol::Https,
        "ssh" => ServiceProtocol::Ssh,
        "ftp" => ServiceProtocol::Ftp,
        "smtp" => ServiceProtocol::Smtp,
        "dns" => ServiceProtocol::Dns,
        "rdp" => ServiceProtocol::Rdp,
        "smb" => ServiceProtocol::Smb,
        "mysql" => ServiceProtocol::Mysql,
        "postgres" => ServiceProtocol::Postgres,
        "redis" => ServiceProtocol::Redis,
        "mongodb" => ServiceProtocol::Mongodb,
        "elasticsearch" => ServiceProtocol::Elasticsearch,
        "grpc" => ServiceProtocol::Grpc,
        other => ServiceProtocol::Custom(other.to_string()),
    }
}

/// Map raw service tuples into typed `ExposedService` values.
pub fn map_services(services: &[ServiceEntry<'_>]) -> Vec<ExposedService> {
    services
        .iter()
        .map(|(ip, port, proto, name, ver, banner, tls)| ExposedService {
            ip: (*ip).to_string(),
            port: *port,
            protocol: parse_service_protocol(proto),
            service_name: name.map(|s| s.to_string()),
            version: ver.map(|s| s.to_string()),
            banner: banner.map(|s| s.to_string()),
            tls_enabled: *tls,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Web application mapping
// ---------------------------------------------------------------------------

/// Map raw web application tuples into typed `WebApplication` values.
pub fn map_web_apps(apps: &[WebAppEntry<'_>]) -> Vec<WebApplication> {
    apps.iter()
        .map(|(url, title, techs, status, server)| WebApplication {
            url: (*url).to_string(),
            title: title.map(|s| s.to_string()),
            technologies: techs.iter().map(|s| (*s).to_string()).collect(),
            status_code: *status,
            server_header: server.map(|s| s.to_string()),
            content_type: None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// API mapping
// ---------------------------------------------------------------------------

fn parse_api_type(s: &str) -> ApiType {
    match s.to_lowercase().as_str() {
        "rest" => ApiType::Rest,
        "graphql" => ApiType::GraphQL,
        "grpc" => ApiType::Grpc,
        "soap" => ApiType::Soap,
        "websocket" | "ws" => ApiType::WebSocket,
        _ => ApiType::Rest,
    }
}

/// Map raw API tuples into typed `ApiEndpoint` values.
pub fn map_apis(apis: &[ApiEntry<'_>]) -> Vec<ApiEndpoint> {
    apis.iter()
        .map(|(url, type_str, auth, docs, methods)| ApiEndpoint {
            url: (*url).to_string(),
            api_type: parse_api_type(type_str),
            authenticated: *auth,
            documentation_url: docs.map(|s| s.to_string()),
            methods: methods.iter().map(|s| (*s).to_string()).collect(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Cloud asset detection
// ---------------------------------------------------------------------------

struct CloudPattern {
    suffix: &'static str,
    provider_tag: &'static str,
    asset_tag: &'static str,
}

fn resolve_provider(tag: &str) -> CloudProvider {
    match tag {
        "aws" => CloudProvider::Aws,
        "azure" => CloudProvider::Azure,
        "gcp" => CloudProvider::Gcp,
        "digitalocean" => CloudProvider::DigitalOcean,
        "cloudflare" => CloudProvider::Cloudflare,
        other => CloudProvider::Other(other.to_string()),
    }
}

fn resolve_asset_type(tag: &str) -> CloudAssetType {
    match tag {
        "s3" => CloudAssetType::S3Bucket,
        "azure_blob" => CloudAssetType::AzureBlob,
        "gcp_storage" => CloudAssetType::GcpStorage,
        "static_site" => CloudAssetType::StaticSite,
        "cdn" => CloudAssetType::CdnEndpoint,
        "function" => CloudAssetType::FunctionEndpoint,
        "container_registry" => CloudAssetType::ContainerRegistry,
        _ => CloudAssetType::Database,
    }
}

const CLOUD_DOMAIN_PATTERNS: &[CloudPattern] = &[
    CloudPattern {
        suffix: ".s3.amazonaws.com",
        provider_tag: "aws",
        asset_tag: "s3",
    },
    CloudPattern {
        suffix: ".s3-",
        provider_tag: "aws",
        asset_tag: "s3",
    },
    CloudPattern {
        suffix: ".blob.core.windows.net",
        provider_tag: "azure",
        asset_tag: "azure_blob",
    },
    CloudPattern {
        suffix: ".storage.googleapis.com",
        provider_tag: "gcp",
        asset_tag: "gcp_storage",
    },
    CloudPattern {
        suffix: ".cloudfront.net",
        provider_tag: "aws",
        asset_tag: "cdn",
    },
    CloudPattern {
        suffix: ".azureedge.net",
        provider_tag: "azure",
        asset_tag: "cdn",
    },
    CloudPattern {
        suffix: ".r2.cloudflarestorage.com",
        provider_tag: "cloudflare",
        asset_tag: "s3",
    },
    CloudPattern {
        suffix: ".azurewebsites.net",
        provider_tag: "azure",
        asset_tag: "function",
    },
    CloudPattern {
        suffix: ".lambda-url.",
        provider_tag: "aws",
        asset_tag: "function",
    },
    CloudPattern {
        suffix: ".cloudfunctions.net",
        provider_tag: "gcp",
        asset_tag: "function",
    },
    CloudPattern {
        suffix: ".run.app",
        provider_tag: "gcp",
        asset_tag: "function",
    },
    CloudPattern {
        suffix: ".azurecr.io",
        provider_tag: "azure",
        asset_tag: "container_registry",
    },
    CloudPattern {
        suffix: ".dkr.ecr.",
        provider_tag: "aws",
        asset_tag: "container_registry",
    },
    CloudPattern {
        suffix: ".netlify.app",
        provider_tag: "Netlify",
        asset_tag: "static_site",
    },
    CloudPattern {
        suffix: ".vercel.app",
        provider_tag: "Vercel",
        asset_tag: "static_site",
    },
    CloudPattern {
        suffix: ".pages.dev",
        provider_tag: "cloudflare",
        asset_tag: "static_site",
    },
];

fn extract_identifier_from_domain(domain: &str, suffix: &str) -> String {
    let lower = domain.to_lowercase();
    lower
        .strip_suffix(&suffix.to_lowercase())
        .or_else(|| lower.find(&suffix.to_lowercase()).map(|pos| &lower[..pos]))
        .unwrap_or(&lower)
        .to_string()
}

fn match_domain_to_cloud(domain: &str) -> Option<CloudAsset> {
    let lower = domain.to_lowercase();
    for pattern in CLOUD_DOMAIN_PATTERNS {
        if lower.contains(pattern.suffix) || lower.ends_with(pattern.suffix) {
            return Some(CloudAsset {
                provider: resolve_provider(pattern.provider_tag),
                asset_type: resolve_asset_type(pattern.asset_tag),
                identifier: extract_identifier_from_domain(domain, pattern.suffix),
                url: Some(domain.to_string()),
                publicly_accessible: true,
                region: None,
            });
        }
    }
    None
}

fn match_dns_cname_to_cloud(record_value: &str) -> Option<CloudAsset> {
    match_domain_to_cloud(record_value)
}

/// Detect cloud assets from discovered domains and DNS CNAME records.
pub fn detect_cloud_assets(
    domains: &[DiscoveredDomain],
    services: &[ExposedService],
    dns_records: &[(&str, &str)],
) -> Vec<CloudAsset> {
    let mut assets = Vec::new();
    let mut seen_identifiers: HashSet<String> = HashSet::new();

    for domain in domains {
        if let Some(asset) = match_domain_to_cloud(&domain.domain)
            && seen_identifiers.insert(asset.identifier.clone())
        {
            assets.push(asset);
        }
    }

    for (_, cname_target) in dns_records {
        if let Some(asset) = match_dns_cname_to_cloud(cname_target)
            && seen_identifiers.insert(asset.identifier.clone())
        {
            assets.push(asset);
        }
    }

    let cloud_service_ports: HashSet<u16> =
        [5432, 3306, 27017, 6379, 9200].iter().copied().collect();
    for svc in services {
        if cloud_service_ports.contains(&svc.port) && svc.banner.is_some() {
            let banner_lower = svc.banner.as_deref().unwrap_or_default().to_lowercase();
            let detected = detect_cloud_provider_from_banner(&banner_lower);
            if let Some((provider, region)) = detected {
                let id = format!("{}:{}", svc.ip, svc.port);
                if seen_identifiers.insert(id.clone()) {
                    assets.push(CloudAsset {
                        provider,
                        asset_type: CloudAssetType::Database,
                        identifier: id,
                        url: None,
                        publicly_accessible: true,
                        region: Some(region),
                    });
                }
            }
        }
    }

    assets
}

fn detect_cloud_provider_from_banner(banner: &str) -> Option<(CloudProvider, String)> {
    if banner.contains("rds") || banner.contains("amazonaws") {
        return Some((CloudProvider::Aws, "unknown".to_string()));
    }
    if banner.contains("azure") || banner.contains("windows.net") {
        return Some((CloudProvider::Azure, "unknown".to_string()));
    }
    if banner.contains("cloud-sql") || banner.contains("googleapis") {
        return Some((CloudProvider::Gcp, "unknown".to_string()));
    }
    None
}

// ---------------------------------------------------------------------------
// Shadow IT detection
// ---------------------------------------------------------------------------

/// Identify discovered assets that fall outside the official domain inventory.
pub fn detect_shadow_it(
    official_domains: &[&str],
    all_domains: &[DiscoveredDomain],
    cloud_assets: &[CloudAsset],
) -> Vec<ShadowItAsset> {
    let official_set: HashSet<String> = official_domains.iter().map(|d| d.to_lowercase()).collect();

    let mut shadow_assets = Vec::new();

    for domain in all_domains {
        let lower = domain.domain.to_lowercase();
        if is_shadow_domain(&lower, &official_set) {
            let risk = classify_shadow_domain_risk(&domain.domain_type);
            shadow_assets.push(ShadowItAsset {
                asset_type: "domain".to_string(),
                identifier: domain.domain.clone(),
                evidence: format!(
                    "Discovered via {:?} but not in official inventory",
                    domain.source
                ),
                risk,
            });
        }
    }

    for asset in cloud_assets {
        let id_lower = asset.identifier.to_lowercase();
        let matches_official = official_set
            .iter()
            .any(|off| id_lower.contains(off) || off.contains(&id_lower));
        if !matches_official {
            shadow_assets.push(ShadowItAsset {
                asset_type: format!("{:?}", asset.asset_type),
                identifier: asset.identifier.clone(),
                evidence: format!(
                    "{:?} asset not associated with official domains",
                    asset.provider
                ),
                risk: if asset.publicly_accessible {
                    ShadowItRisk::High
                } else {
                    ShadowItRisk::Medium
                },
            });
        }
    }

    shadow_assets
}

fn is_shadow_domain(lower: &str, official_set: &HashSet<String>) -> bool {
    if official_set.contains(lower) {
        return false;
    }
    let is_subdomain_of_official = official_set
        .iter()
        .any(|off| lower.ends_with(&format!(".{off}")));
    !is_subdomain_of_official
}

fn classify_shadow_domain_risk(domain_type: &DomainType) -> ShadowItRisk {
    match domain_type {
        DomainType::Wildcard => ShadowItRisk::Critical,
        DomainType::Primary => ShadowItRisk::High,
        DomainType::Alias => ShadowItRisk::Medium,
        DomainType::Subdomain => ShadowItRisk::Medium,
    }
}

// ---------------------------------------------------------------------------
// Attack surface scoring
// ---------------------------------------------------------------------------

const HIGH_RISK_PORTS: &[u16] = &[
    21, 22, 23, 25, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 27017,
];

/// Compute a normalized score (0.0–1.0) representing attack surface breadth.
pub fn calculate_attack_surface_score(report: &AttackSurfaceReport) -> f64 {
    let service_score = (report.services.len() as f64 / 50.0).min(1.0) * 0.25;

    let high_risk_port_count = report
        .services
        .iter()
        .filter(|s| HIGH_RISK_PORTS.contains(&s.port))
        .count();
    let high_risk_score = (high_risk_port_count as f64 / 10.0).min(1.0) * 0.25;

    let public_cloud_count = report
        .cloud_assets
        .iter()
        .filter(|a| a.publicly_accessible)
        .count();
    let cloud_score = (public_cloud_count as f64 / 10.0).min(1.0) * 0.25;

    let shadow_score = (report.shadow_it.len() as f64 / 5.0).min(1.0) * 0.25;

    let raw = service_score + high_risk_score + cloud_score + shadow_score;
    (raw * 100.0).round() / 100.0
}

// ---------------------------------------------------------------------------
// Summary builder
// ---------------------------------------------------------------------------

fn build_summary(report: &AttackSurfaceReport) -> AttackSurfaceSummary {
    let total_ips: usize = report.ip_ranges.iter().map(|r| r.ip_count as usize).sum();

    let high_risk_count = report
        .services
        .iter()
        .filter(|s| HIGH_RISK_PORTS.contains(&s.port))
        .count()
        + report
            .shadow_it
            .iter()
            .filter(|s| matches!(s.risk, ShadowItRisk::Critical | ShadowItRisk::High))
            .count();

    AttackSurfaceSummary {
        total_ips,
        total_domains: report.domains.len(),
        total_services: report.services.len(),
        total_web_apps: report.web_apps.len(),
        total_apis: report.apis.len(),
        total_cloud_assets: report.cloud_assets.len(),
        high_risk_count,
    }
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Assemble a complete `AttackSurfaceReport` from raw enumeration data.
#[allow(clippy::too_many_arguments)]
pub fn map_attack_surface(
    domain: &str,
    ip_data: &[IpRangeEntry<'_>],
    domain_data: &[DomainEntry<'_>],
    service_data: &[ServiceEntry<'_>],
    web_apps: &[WebAppEntry<'_>],
    api_data: &[ApiEntry<'_>],
    dns_records: &[(&str, &str)],
    official_domains: &[&str],
) -> AttackSurfaceReport {
    let ip_ranges = map_ip_ranges(ip_data);
    let domains = map_domains(domain_data);
    let services = map_services(service_data);
    let mapped_web_apps = map_web_apps(web_apps);
    let apis = map_apis(api_data);
    let cloud_assets = detect_cloud_assets(&domains, &services, dns_records);
    let shadow_it = detect_shadow_it(official_domains, &domains, &cloud_assets);

    let mut report = AttackSurfaceReport {
        domain: domain.to_string(),
        ip_ranges,
        domains,
        services,
        web_apps: mapped_web_apps,
        apis,
        cloud_assets,
        shadow_it,
        total_attack_surface_score: 0.0,
        summary: AttackSurfaceSummary {
            total_ips: 0,
            total_domains: 0,
            total_services: 0,
            total_web_apps: 0,
            total_apis: 0,
            total_cloud_assets: 0,
            high_risk_count: 0,
        },
    };

    report.total_attack_surface_score = calculate_attack_surface_score(&report);
    report.summary = build_summary(&report);
    report
}
