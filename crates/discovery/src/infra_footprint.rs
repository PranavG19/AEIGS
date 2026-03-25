use std::collections::HashMap;

use regex::Regex;

/// Shodan/Censys query for infrastructure discovery.
#[derive(Debug, Clone, PartialEq)]
pub struct InfraQuery {
    pub engine: SearchEngine,
    pub query: String,
    pub description: String,
    pub expected_results: QueryResultType,
}

/// Search engine for internet-facing infrastructure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchEngine {
    Shodan,
    Censys,
    ZoomEye,
    BinaryEdge,
    Fofa,
}

impl std::fmt::Display for SearchEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shodan => write!(f, "Shodan"),
            Self::Censys => write!(f, "Censys"),
            Self::ZoomEye => write!(f, "ZoomEye"),
            Self::BinaryEdge => write!(f, "BinaryEdge"),
            Self::Fofa => write!(f, "FOFA"),
        }
    }
}

/// Expected type of query result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueryResultType {
    WebServers,
    Databases,
    MailServers,
    DnsServers,
    SshServers,
    RdpServers,
    IndustrialControl,
    IoTDevices,
    VpnGateways,
    LoadBalancers,
    General,
}

impl std::fmt::Display for QueryResultType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WebServers => write!(f, "Web Servers"),
            Self::Databases => write!(f, "Databases"),
            Self::MailServers => write!(f, "Mail Servers"),
            Self::DnsServers => write!(f, "DNS Servers"),
            Self::SshServers => write!(f, "SSH Servers"),
            Self::RdpServers => write!(f, "RDP Servers"),
            Self::IndustrialControl => write!(f, "Industrial Control"),
            Self::IoTDevices => write!(f, "IoT Devices"),
            Self::VpnGateways => write!(f, "VPN Gateways"),
            Self::LoadBalancers => write!(f, "Load Balancers"),
            Self::General => write!(f, "General"),
        }
    }
}

/// Parsed service from nmap XML output.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedService {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub service_name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub state: PortState,
    pub cpe: Option<String>,
}

/// State of a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
    Unfiltered,
}

impl std::fmt::Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Closed => write!(f, "closed"),
            Self::Filtered => write!(f, "filtered"),
            Self::OpenFiltered => write!(f, "open|filtered"),
            Self::Unfiltered => write!(f, "unfiltered"),
        }
    }
}

/// Certificate transparency log entry.
#[derive(Debug, Clone, PartialEq)]
pub struct CtLogEntry {
    pub domain: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub serial_number: Option<String>,
    pub is_wildcard: bool,
    pub san_domains: Vec<String>,
}

/// Discovered cloud storage asset.
#[derive(Debug, Clone, PartialEq)]
pub struct CloudAsset {
    pub asset_type: CloudAssetType,
    pub name: String,
    pub url: String,
    pub is_public: Option<bool>,
    pub provider: CloudProvider,
    pub confidence: f64,
}

/// Type of cloud storage asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloudAssetType {
    S3Bucket,
    AzureBlob,
    GcpStorage,
    DigitalOceanSpaces,
    MinioInstance,
}

impl std::fmt::Display for CloudAssetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::S3Bucket => write!(f, "S3 Bucket"),
            Self::AzureBlob => write!(f, "Azure Blob"),
            Self::GcpStorage => write!(f, "GCP Storage"),
            Self::DigitalOceanSpaces => write!(f, "DigitalOcean Spaces"),
            Self::MinioInstance => write!(f, "MinIO Instance"),
        }
    }
}

/// Cloud provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
    DigitalOcean,
    Other,
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aws => write!(f, "AWS"),
            Self::Azure => write!(f, "Azure"),
            Self::Gcp => write!(f, "GCP"),
            Self::DigitalOcean => write!(f, "DigitalOcean"),
            Self::Other => write!(f, "Other"),
        }
    }
}

/// CDN mapping entry.
#[derive(Debug, Clone, PartialEq)]
pub struct CdnMapping {
    pub endpoint: String,
    pub cdn_provider: String,
    pub edge_domain: Option<String>,
    pub origin_hint: Option<String>,
    pub detection_method: String,
}

/// Email infrastructure information.
#[derive(Debug, Clone, PartialEq)]
pub struct EmailInfrastructure {
    pub mx_records: Vec<MxRecord>,
    pub spf_record: Option<String>,
    pub spf_includes: Vec<String>,
    pub dmarc_policy: Option<DmarcPolicy>,
    pub dkim_selectors: Vec<String>,
    pub email_provider: Option<String>,
}

/// MX record with priority.
#[derive(Debug, Clone, PartialEq)]
pub struct MxRecord {
    pub priority: u16,
    pub host: String,
}

/// DMARC policy settings.
#[derive(Debug, Clone, PartialEq)]
pub struct DmarcPolicy {
    pub policy: DmarcAction,
    pub subdomain_policy: Option<DmarcAction>,
    pub pct: u8,
    pub rua: Option<String>,
    pub ruf: Option<String>,
}

/// DMARC action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DmarcAction {
    None,
    Quarantine,
    Reject,
}

impl std::fmt::Display for DmarcAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Quarantine => write!(f, "quarantine"),
            Self::Reject => write!(f, "reject"),
        }
    }
}

/// DNS infrastructure information.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsInfrastructure {
    pub nameservers: Vec<String>,
    pub has_dnssec: bool,
    pub zone_transfer_possible: bool,
    pub registrar: Option<String>,
    pub dns_provider: Option<String>,
}

/// Historical infrastructure record.
#[derive(Debug, Clone, PartialEq)]
pub struct HistoricalRecord {
    pub record_type: HistoricalRecordType,
    pub value: String,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub is_current: bool,
}

/// Type of historical record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HistoricalRecordType {
    ARecord,
    CnameRecord,
    MxRecord,
    NsRecord,
    TxtRecord,
    WaybackUrl,
    DecommissionedSubdomain,
}

impl std::fmt::Display for HistoricalRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ARecord => write!(f, "A Record"),
            Self::CnameRecord => write!(f, "CNAME Record"),
            Self::MxRecord => write!(f, "MX Record"),
            Self::NsRecord => write!(f, "NS Record"),
            Self::TxtRecord => write!(f, "TXT Record"),
            Self::WaybackUrl => write!(f, "Wayback URL"),
            Self::DecommissionedSubdomain => write!(f, "Decommissioned Subdomain"),
        }
    }
}

/// Full infrastructure footprint.
#[derive(Debug, Clone)]
pub struct InfraFootprint {
    pub target_domain: String,
    pub queries: Vec<InfraQuery>,
    pub services: Vec<ParsedService>,
    pub ct_entries: Vec<CtLogEntry>,
    pub cloud_assets: Vec<CloudAsset>,
    pub cdn_mappings: Vec<CdnMapping>,
    pub email_infra: EmailInfrastructure,
    pub dns_infra: DnsInfrastructure,
    pub historical_records: Vec<HistoricalRecord>,
    pub total_services: usize,
    pub total_open_ports: usize,
    pub exposure_score: f64,
}

/// Generate Shodan/Censys queries for a target.
pub fn generate_infra_queries(
    domains: &[&str],
    ip_ranges: &[&str],
    org_name: Option<&str>,
) -> Vec<InfraQuery> {
    let mut queries = Vec::new();

    for domain in domains {
        queries.push(InfraQuery {
            engine: SearchEngine::Shodan,
            query: format!("hostname:{domain}"),
            description: format!("All services on {domain}"),
            expected_results: QueryResultType::General,
        });

        queries.push(InfraQuery {
            engine: SearchEngine::Shodan,
            query: format!("ssl.cert.subject.cn:{domain}"),
            description: format!("SSL certificates for {domain}"),
            expected_results: QueryResultType::WebServers,
        });

        queries.push(InfraQuery {
            engine: SearchEngine::Shodan,
            query: format!("hostname:{domain} port:3306,5432,27017,6379,9200"),
            description: format!("Database services on {domain}"),
            expected_results: QueryResultType::Databases,
        });

        queries.push(InfraQuery {
            engine: SearchEngine::Shodan,
            query: format!("hostname:{domain} port:22"),
            description: format!("SSH servers on {domain}"),
            expected_results: QueryResultType::SshServers,
        });

        queries.push(InfraQuery {
            engine: SearchEngine::Shodan,
            query: format!("hostname:{domain} port:3389"),
            description: format!("RDP servers on {domain}"),
            expected_results: QueryResultType::RdpServers,
        });

        queries.push(InfraQuery {
            engine: SearchEngine::Censys,
            query: format!("parsed.names: {domain}"),
            description: format!("Censys certificate search for {domain}"),
            expected_results: QueryResultType::WebServers,
        });

        queries.push(InfraQuery {
            engine: SearchEngine::Shodan,
            query: format!(
                "hostname:{domain} \"OpenVPN\" OR \"Cisco AnyConnect\" OR \"FortiGate\""
            ),
            description: format!("VPN gateways on {domain}"),
            expected_results: QueryResultType::VpnGateways,
        });
    }

    for ip_range in ip_ranges {
        queries.push(InfraQuery {
            engine: SearchEngine::Shodan,
            query: format!("net:{ip_range}"),
            description: format!("All services in {ip_range}"),
            expected_results: QueryResultType::General,
        });

        queries.push(InfraQuery {
            engine: SearchEngine::Shodan,
            query: format!("net:{ip_range} port:80,443,8080,8443"),
            description: format!("Web servers in {ip_range}"),
            expected_results: QueryResultType::WebServers,
        });
    }

    if let Some(org) = org_name {
        queries.push(InfraQuery {
            engine: SearchEngine::Shodan,
            query: format!("org:\"{org}\""),
            description: format!("All infrastructure belonging to {org}"),
            expected_results: QueryResultType::General,
        });
    }

    queries
}

/// Parse nmap XML output into structured services.
pub fn parse_nmap_xml(xml_content: &str) -> Vec<ParsedService> {
    let mut services = Vec::new();

    let host_re = Regex::new(r#"<address addr="([^"]+)""#).unwrap();
    let port_re = Regex::new(
        r#"<port protocol="([^"]+)" portid="(\d+)">\s*<state state="([^"]+)"[^/]*/>\s*(?:<service name="([^"]*)"(?:\s+product="([^"]*)")?(?:\s+version="([^"]*)")?[^/]*/>\s*)?(?:<cpe>([^<]*)</cpe>)?"#
    ).unwrap();

    let mut current_host = String::new();

    for line in xml_content.lines() {
        if let Some(cap) = host_re.captures(line) {
            current_host = cap[1].to_string();
        }

        if let Some(cap) = port_re.captures(line) {
            let protocol = cap[1].to_string();
            let port: u16 = cap[2].parse().unwrap_or(0);
            let state = match &cap[3] {
                "open" => PortState::Open,
                "closed" => PortState::Closed,
                "filtered" => PortState::Filtered,
                "open|filtered" => PortState::OpenFiltered,
                _ => PortState::Unfiltered,
            };

            services.push(ParsedService {
                host: current_host.clone(),
                port,
                protocol,
                service_name: cap.get(4).map(|m| m.as_str().to_string()),
                product: cap.get(5).map(|m| m.as_str().to_string()),
                version: cap.get(6).map(|m| m.as_str().to_string()),
                state,
                cpe: cap.get(7).map(|m| m.as_str().to_string()),
            });
        }
    }

    services
}

/// Parse simplified nmap-like service entries (host:port:state:service:product:version).
pub fn parse_service_inventory(
    entries: &[(&str, u16, &str, &str, Option<&str>, Option<&str>)],
) -> Vec<ParsedService> {
    entries
        .iter()
        .map(|&(host, port, state, service, product, version)| {
            let port_state = match state {
                "open" => PortState::Open,
                "closed" => PortState::Closed,
                "filtered" => PortState::Filtered,
                _ => PortState::Unfiltered,
            };
            ParsedService {
                host: host.to_string(),
                port,
                protocol: "tcp".to_string(),
                service_name: Some(service.to_string()),
                product: product.map(String::from),
                version: version.map(String::from),
                state: port_state,
                cpe: None,
            }
        })
        .collect()
}

/// Generate cloud asset name candidates from naming patterns.
pub fn generate_cloud_asset_candidates(org_name: &str, domains: &[&str]) -> Vec<CloudAsset> {
    let name_variants: Vec<String> = {
        let base = org_name.to_lowercase().replace(' ', "-");
        let base_underscore = org_name.to_lowercase().replace(' ', "_");
        let base_no_sep = org_name.to_lowercase().replace(' ', "");
        vec![
            base.clone(),
            base_underscore.clone(),
            base_no_sep.clone(),
            format!("{base}-prod"),
            format!("{base}-staging"),
            format!("{base}-dev"),
            format!("{base}-backup"),
            format!("{base}-assets"),
            format!("{base}-static"),
            format!("{base}-media"),
            format!("{base}-uploads"),
            format!("{base}-logs"),
            format!("{base}-data"),
            format!("{base}-config"),
            format!("{base}-internal"),
            format!("{base}-public"),
        ]
    };

    let domain_variants: Vec<String> = domains
        .iter()
        .flat_map(|d| {
            let base = d.split('.').next().unwrap_or(d).to_string();
            vec![
                base.clone(),
                format!("{base}-assets"),
                format!("{base}-static"),
                format!("{base}-cdn"),
                format!("{base}-backup"),
            ]
        })
        .collect();

    let all_names: Vec<String> = name_variants.into_iter().chain(domain_variants).collect();

    let mut assets = Vec::new();

    for name in &all_names {
        assets.push(CloudAsset {
            asset_type: CloudAssetType::S3Bucket,
            name: name.clone(),
            url: format!("https://{name}.s3.amazonaws.com"),
            is_public: None,
            provider: CloudProvider::Aws,
            confidence: 0.40,
        });
        assets.push(CloudAsset {
            asset_type: CloudAssetType::AzureBlob,
            name: name.replace('-', ""),
            url: format!("https://{}.blob.core.windows.net", name.replace('-', "")),
            is_public: None,
            provider: CloudProvider::Azure,
            confidence: 0.35,
        });
        assets.push(CloudAsset {
            asset_type: CloudAssetType::GcpStorage,
            name: name.clone(),
            url: format!("https://storage.googleapis.com/{name}"),
            is_public: None,
            provider: CloudProvider::Gcp,
            confidence: 0.35,
        });
    }

    assets
}

/// Detect CDN from HTTP response headers and CNAME records.
pub fn detect_cdn(headers: &[(&str, &str)], cname_records: &[(&str, &str)]) -> Vec<CdnMapping> {
    let mut mappings = Vec::new();

    let header_cdn_patterns: Vec<(&str, &str, &str)> = vec![
        ("server", "cloudflare", "Cloudflare"),
        ("server", "cloudfront", "AWS CloudFront"),
        ("x-served-by", "cache-", "Fastly"),
        ("x-cdn", "akamai", "Akamai"),
        ("x-amz-cf-id", "", "AWS CloudFront"),
        ("x-azure-ref", "", "Azure CDN"),
        ("cf-ray", "", "Cloudflare"),
        ("x-fastly-request-id", "", "Fastly"),
        ("x-cache", "bunnycdn", "BunnyCDN"),
        ("server", "bunnycdn", "BunnyCDN"),
        ("x-cdn-provider", "keycdn", "KeyCDN"),
    ];

    let mut seen_endpoints: std::collections::HashSet<String> = std::collections::HashSet::new();

    for &(header_name, header_value) in headers {
        let name_lower = header_name.to_lowercase();
        let value_lower = header_value.to_lowercase();

        for &(pattern_header, pattern_value, cdn_name) in &header_cdn_patterns {
            if name_lower == pattern_header
                && (pattern_value.is_empty() || value_lower.contains(pattern_value))
            {
                let key = cdn_name.to_string();
                if seen_endpoints.insert(key) {
                    mappings.push(CdnMapping {
                        endpoint: header_value.to_string(),
                        cdn_provider: cdn_name.to_string(),
                        edge_domain: None,
                        origin_hint: None,
                        detection_method: format!("HTTP header: {header_name}: {header_value}"),
                    });
                }
            }
        }
    }

    let cname_cdn_patterns: Vec<(&str, &str)> = vec![
        ("cloudfront.net", "AWS CloudFront"),
        ("cloudflare", "Cloudflare"),
        ("akamaiedge.net", "Akamai"),
        ("akamai.net", "Akamai"),
        ("fastly.net", "Fastly"),
        ("azureedge.net", "Azure CDN"),
        ("edgecastcdn.net", "Edgecast"),
        ("stackpathdns.com", "StackPath"),
        ("cdn77.org", "CDN77"),
        ("b-cdn.net", "BunnyCDN"),
        ("kxcdn.com", "KeyCDN"),
    ];

    for &(subdomain, target) in cname_records {
        let target_lower = target.to_lowercase();
        for &(pattern, cdn_name) in &cname_cdn_patterns {
            if target_lower.contains(pattern) {
                mappings.push(CdnMapping {
                    endpoint: subdomain.to_string(),
                    cdn_provider: cdn_name.to_string(),
                    edge_domain: Some(target.to_string()),
                    origin_hint: None,
                    detection_method: format!("CNAME: {subdomain} -> {target}"),
                });
            }
        }
    }

    mappings
}

/// Parse SPF record to extract included services.
pub fn parse_spf_includes(spf_record: &str) -> Vec<String> {
    let include_re = Regex::new(r"include:([^\s]+)").unwrap();
    include_re
        .captures_iter(spf_record)
        .map(|cap| cap[1].to_string())
        .collect()
}

/// Parse DMARC record into structured policy.
pub fn parse_dmarc_record(dmarc_txt: &str) -> Option<DmarcPolicy> {
    if !dmarc_txt.starts_with("v=DMARC1") {
        return None;
    }

    let policy_re = Regex::new(r";\s*p=(\w+)").unwrap();
    let policy = if let Some(cap) = policy_re.captures(dmarc_txt) {
        match &cap[1] {
            "reject" => DmarcAction::Reject,
            "quarantine" => DmarcAction::Quarantine,
            _ => DmarcAction::None,
        }
    } else {
        DmarcAction::None
    };

    let sp_re = Regex::new(r";\s*sp=(\w+)").unwrap();
    let subdomain_policy = sp_re.captures(dmarc_txt).map(|cap| match &cap[1] {
        "reject" => DmarcAction::Reject,
        "quarantine" => DmarcAction::Quarantine,
        _ => DmarcAction::None,
    });

    let pct_re = Regex::new(r"pct=(\d+)").unwrap();
    let pct = pct_re
        .captures(dmarc_txt)
        .and_then(|c| c[1].parse().ok())
        .unwrap_or(100);

    let rua_re = Regex::new(r"rua=mailto:([^\s;]+)").unwrap();
    let rua = rua_re.captures(dmarc_txt).map(|c| c[1].to_string());

    let ruf_re = Regex::new(r"ruf=mailto:([^\s;]+)").unwrap();
    let ruf = ruf_re.captures(dmarc_txt).map(|c| c[1].to_string());

    Some(DmarcPolicy {
        policy,
        subdomain_policy,
        pct,
        rua,
        ruf,
    })
}

/// Identify email provider from MX records.
pub fn identify_email_provider(mx_records: &[&str]) -> Option<String> {
    let providers: Vec<(&str, &str)> = vec![
        ("google", "Google Workspace"),
        ("outlook", "Microsoft 365"),
        ("protonmail", "ProtonMail"),
        ("zoho", "Zoho Mail"),
        ("mimecast", "Mimecast"),
        ("barracuda", "Barracuda"),
        ("pphosted", "Proofpoint"),
        ("messagelabs", "Symantec"),
        ("mailgun", "Mailgun"),
        ("sendgrid", "SendGrid"),
        ("postmarkapp", "Postmark"),
        ("amazonaws", "Amazon SES"),
        ("yahoodns", "Yahoo Mail"),
        ("icloud", "iCloud Mail"),
        ("fastmail", "Fastmail"),
        ("migadu", "Migadu"),
    ];

    for mx in mx_records {
        let lower = mx.to_lowercase();
        for &(pattern, provider) in &providers {
            if lower.contains(pattern) {
                return Some(provider.to_string());
            }
        }
    }

    None
}

/// Identify DNS provider from nameserver records.
pub fn identify_dns_provider(nameservers: &[&str]) -> Option<String> {
    let providers: Vec<(&str, &str)> = vec![
        ("cloudflare", "Cloudflare"),
        ("awsdns", "AWS Route 53"),
        ("azure-dns", "Azure DNS"),
        ("googledomains", "Google Domains"),
        ("cloud-dns", "Google Cloud DNS"),
        ("ns-cloud", "Google Cloud DNS"),
        ("dynect", "Dyn"),
        ("ultradns", "UltraDNS"),
        ("nsone", "NS1"),
        ("domaincontrol", "GoDaddy"),
        ("registrar-servers", "Namecheap"),
        ("dnsmadeeasy", "DNS Made Easy"),
        ("dnsimple", "DNSimple"),
        ("linode", "Linode"),
        ("digitalocean", "DigitalOcean"),
        ("vercel-dns", "Vercel"),
        ("netlify", "Netlify"),
    ];

    for ns in nameservers {
        let lower = ns.to_lowercase();
        for &(pattern, provider) in &providers {
            if lower.contains(pattern) {
                return Some(provider.to_string());
            }
        }
    }

    None
}

/// Build full infrastructure footprint.
pub fn build_infra_footprint(
    target_domain: &str,
    queries: Vec<InfraQuery>,
    services: Vec<ParsedService>,
    ct_entries: Vec<CtLogEntry>,
    cloud_assets: Vec<CloudAsset>,
    cdn_mappings: Vec<CdnMapping>,
    email_infra: EmailInfrastructure,
    dns_infra: DnsInfrastructure,
    historical_records: Vec<HistoricalRecord>,
) -> InfraFootprint {
    let total_services = services.len();
    let total_open = services
        .iter()
        .filter(|s| s.state == PortState::Open)
        .count();

    let service_score = (total_open as f64 / 20.0).min(1.0) * 25.0;
    let ct_score = (ct_entries.len() as f64 / 50.0).min(1.0) * 15.0;
    let cloud_score = (cloud_assets.len() as f64 / 10.0).min(1.0) * 20.0;
    let dns_score = if dns_infra.has_dnssec { 0.0 } else { 10.0 };
    let dmarc_score = match &email_infra.dmarc_policy {
        Some(p) if p.policy == DmarcAction::Reject => 0.0,
        Some(p) if p.policy == DmarcAction::Quarantine => 5.0,
        _ => 15.0,
    };
    let historical_score = (historical_records.len() as f64 / 20.0).min(1.0) * 15.0;

    let exposure =
        (service_score + ct_score + cloud_score + dns_score + dmarc_score + historical_score)
            .min(100.0);

    InfraFootprint {
        target_domain: target_domain.to_string(),
        queries,
        services,
        ct_entries,
        cloud_assets,
        cdn_mappings,
        email_infra,
        dns_infra,
        historical_records,
        total_services,
        total_open_ports: total_open,
        exposure_score: exposure,
    }
}
