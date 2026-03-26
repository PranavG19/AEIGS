use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Shodan service protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShodanProtocol {
    Http,
    Https,
    Ssh,
    Ftp,
    Telnet,
    Smtp,
    Dns,
    Rdp,
    Smb,
    Mqtt,
    Rtsp,
    Modbus,
    Sip,
    Snmp,
    Unknown,
}

impl fmt::Display for ShodanProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http => write!(f, "HTTP"),
            Self::Https => write!(f, "HTTPS"),
            Self::Ssh => write!(f, "SSH"),
            Self::Ftp => write!(f, "FTP"),
            Self::Telnet => write!(f, "Telnet"),
            Self::Smtp => write!(f, "SMTP"),
            Self::Dns => write!(f, "DNS"),
            Self::Rdp => write!(f, "RDP"),
            Self::Smb => write!(f, "SMB"),
            Self::Mqtt => write!(f, "MQTT"),
            Self::Rtsp => write!(f, "RTSP"),
            Self::Modbus => write!(f, "Modbus"),
            Self::Sip => write!(f, "SIP"),
            Self::Snmp => write!(f, "SNMP"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Risk level for Shodan findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ShodanRisk {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for ShodanRisk {
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

/// A single open port/service from Shodan.
#[derive(Debug, Clone, PartialEq)]
pub struct ShodanService {
    pub port: u16,
    pub protocol: ShodanProtocol,
    pub product: Option<String>,
    pub version: Option<String>,
    pub banner: String,
    pub cpe: Vec<String>,
    pub vulns: Vec<String>,
    pub ssl: Option<ShodanSslInfo>,
}

/// SSL/TLS info from Shodan.
#[derive(Debug, Clone, PartialEq)]
pub struct ShodanSslInfo {
    pub versions: Vec<String>,
    pub cert_subject: Option<String>,
    pub cert_issuer: Option<String>,
    pub cert_expires: Option<String>,
    pub cipher_suite: Option<String>,
    pub jarm: Option<String>,
}

/// Shodan host lookup result.
#[derive(Debug, Clone, PartialEq)]
pub struct ShodanHostResult {
    pub ip: String,
    pub hostnames: Vec<String>,
    pub org: Option<String>,
    pub asn: Option<String>,
    pub isp: Option<String>,
    pub os: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub services: Vec<ShodanService>,
    pub vulns: Vec<String>,
    pub last_update: Option<String>,
    pub tags: Vec<String>,
}

/// Shodan search query result.
#[derive(Debug, Clone, PartialEq)]
pub struct ShodanSearchResult {
    pub total: u64,
    pub matches: Vec<ShodanSearchMatch>,
    pub facets: HashMap<String, Vec<(String, u64)>>,
}

/// A single match from Shodan search.
#[derive(Debug, Clone, PartialEq)]
pub struct ShodanSearchMatch {
    pub ip_str: String,
    pub port: u16,
    pub org: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub banner_snippet: String,
    pub hostnames: Vec<String>,
    pub asn: Option<String>,
    pub country: Option<String>,
}

/// Parsed banner analysis result.
#[derive(Debug, Clone, PartialEq)]
pub struct BannerAnalysis {
    pub port: u16,
    pub protocol: ShodanProtocol,
    pub product_detected: Option<String>,
    pub version_detected: Option<String>,
    pub security_issues: Vec<String>,
    pub risk: ShodanRisk,
}

/// Full Shodan intelligence report.
#[derive(Debug, Clone, PartialEq)]
pub struct ShodanReport {
    pub target: String,
    pub hosts: Vec<ShodanHostResult>,
    pub search_results: Vec<ShodanSearchResult>,
    pub banner_analyses: Vec<BannerAnalysis>,
    pub exposed_services_count: usize,
    pub critical_vulns: Vec<String>,
    pub risk_summary: HashMap<ShodanRisk, usize>,
    pub overall_risk: ShodanRisk,
}

/// Builds the Shodan host lookup API URL.
pub fn build_host_url(ip: &str, api_key: &str) -> String {
    format!("https://api.shodan.io/shodan/host/{}?key={}", ip, api_key)
}

/// Builds the Shodan search API URL.
pub fn build_search_url(query: &str, api_key: &str, page: u32) -> String {
    let encoded = query.replace(' ', "+");
    format!(
        "https://api.shodan.io/shodan/host/search?key={}&query={}&page={}",
        api_key, encoded, page
    )
}

/// Builds common Shodan search queries for a target domain.
pub fn build_target_queries(domain: &str) -> Vec<String> {
    vec![
        format!("hostname:{}", domain),
        format!("ssl.cert.subject.cn:{}", domain),
        format!("org:\"{}\"", domain.split('.').next().unwrap_or(domain)),
        format!("hostname:{} port:22,3389,5900", domain),
        format!(
            "hostname:{} product:\"Apache\" || product:\"nginx\"",
            domain
        ),
        format!("hostname:{} vuln:*", domain),
    ]
}

/// Parses a Shodan host lookup JSON response.
pub fn parse_host_response(json_body: &str) -> Option<ShodanHostResult> {
    let val: serde_json::Value = serde_json::from_str(json_body).ok()?;

    let ip = val.get("ip_str")?.as_str()?.to_string();
    let hostnames = parse_string_array(&val, "hostnames");
    let org = val.get("org").and_then(|v| v.as_str()).map(String::from);
    let asn = val.get("asn").and_then(|v| v.as_str()).map(String::from);
    let isp = val.get("isp").and_then(|v| v.as_str()).map(String::from);
    let os = val.get("os").and_then(|v| v.as_str()).map(String::from);
    let country = val
        .get("country_code")
        .and_then(|v| v.as_str())
        .map(String::from);
    let city = val.get("city").and_then(|v| v.as_str()).map(String::from);
    let last_update = val
        .get("last_update")
        .and_then(|v| v.as_str())
        .map(String::from);
    let tags = parse_string_array(&val, "tags");
    let vulns_arr = parse_string_array(&val, "vulns");

    let services = val
        .get("data")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_service).collect())
        .unwrap_or_default();

    Some(ShodanHostResult {
        ip,
        hostnames,
        org,
        asn,
        isp,
        os,
        country,
        city,
        services,
        vulns: vulns_arr,
        last_update,
        tags,
    })
}

fn parse_string_array(val: &serde_json::Value, key: &str) -> Vec<String> {
    val.get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_service(val: &serde_json::Value) -> Option<ShodanService> {
    let port = val.get("port")?.as_u64()? as u16;
    let banner = val
        .get("data")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let product = val
        .get("product")
        .and_then(|v| v.as_str())
        .map(String::from);
    let version = val
        .get("version")
        .and_then(|v| v.as_str())
        .map(String::from);
    let transport = val.get("transport").and_then(|v| v.as_str()).unwrap_or("");

    let protocol = detect_protocol(port, transport, &banner);
    let cpe = parse_string_array(val, "cpe");
    let vulns = parse_string_array(val, "vulns");

    let ssl = val.get("ssl").map(|s| ShodanSslInfo {
        versions: parse_string_array(s, "versions"),
        cert_subject: s
            .get("cert")
            .and_then(|c| c.get("subject"))
            .and_then(|s| s.get("CN"))
            .and_then(|v| v.as_str())
            .map(String::from),
        cert_issuer: s
            .get("cert")
            .and_then(|c| c.get("issuer"))
            .and_then(|i| i.get("O"))
            .and_then(|v| v.as_str())
            .map(String::from),
        cert_expires: s
            .get("cert")
            .and_then(|c| c.get("expires"))
            .and_then(|v| v.as_str())
            .map(String::from),
        cipher_suite: s
            .get("cipher")
            .and_then(|c| c.get("name"))
            .and_then(|v| v.as_str())
            .map(String::from),
        jarm: s.get("jarm").and_then(|v| v.as_str()).map(String::from),
    });

    Some(ShodanService {
        port,
        protocol,
        product,
        version,
        banner,
        cpe,
        vulns,
        ssl,
    })
}

/// Detects protocol from port, transport, and banner.
pub fn detect_protocol(port: u16, transport: &str, banner: &str) -> ShodanProtocol {
    match port {
        80 => ShodanProtocol::Http,
        443 => ShodanProtocol::Https,
        22 => ShodanProtocol::Ssh,
        21 => ShodanProtocol::Ftp,
        23 => ShodanProtocol::Telnet,
        25 | 587 => ShodanProtocol::Smtp,
        53 => ShodanProtocol::Dns,
        3389 => ShodanProtocol::Rdp,
        445 => ShodanProtocol::Smb,
        1883 | 8883 => ShodanProtocol::Mqtt,
        554 => ShodanProtocol::Rtsp,
        502 => ShodanProtocol::Modbus,
        5060 | 5061 => ShodanProtocol::Sip,
        161 | 162 => ShodanProtocol::Snmp,
        _ => {
            let lower = banner.to_lowercase();
            if lower.contains("http") || lower.contains("html") {
                ShodanProtocol::Http
            } else if lower.contains("ssh") {
                ShodanProtocol::Ssh
            } else if lower.contains("ftp") {
                ShodanProtocol::Ftp
            } else {
                ShodanProtocol::Unknown
            }
        }
    }
}

/// Analyzes a service banner for security issues.
pub fn analyze_banner(service: &ShodanService) -> BannerAnalysis {
    let mut issues = Vec::new();
    let lower = service.banner.to_lowercase();

    if let Some(ref ver) = service.version {
        let old_versions = [
            ("apache", "2.2"),
            ("nginx", "1.14"),
            ("openssh", "7."),
            ("openssl", "1.0"),
            ("php", "5."),
            ("mysql", "5.5"),
        ];
        for (prod, old_ver) in &old_versions {
            if let Some(ref p) = service.product {
                if p.to_lowercase().contains(prod) && ver.starts_with(old_ver) {
                    issues.push(format!("Outdated {}: version {}", prod, ver));
                }
            }
        }
    }

    if lower.contains("default password") || lower.contains("admin:admin") {
        issues.push("Default credentials detected in banner".to_string());
    }
    if lower.contains("x-powered-by") {
        issues.push("Server reveals technology stack via X-Powered-By".to_string());
    }
    if lower.contains("directory listing") || lower.contains("index of /") {
        issues.push("Directory listing enabled".to_string());
    }

    if !service.vulns.is_empty() {
        issues.push(format!("{} known CVEs associated", service.vulns.len()));
    }

    let risk = if service.vulns.iter().any(|v| v.contains("CVE")) && service.vulns.len() > 3 {
        ShodanRisk::Critical
    } else if !issues.is_empty() && service.vulns.len() > 0 {
        ShodanRisk::High
    } else if !issues.is_empty() {
        ShodanRisk::Medium
    } else {
        match service.port {
            23 | 21 | 3389 | 5900 => ShodanRisk::Medium,
            _ => ShodanRisk::Info,
        }
    };

    BannerAnalysis {
        port: service.port,
        protocol: service.protocol,
        product_detected: service.product.clone(),
        version_detected: service.version.clone(),
        security_issues: issues,
        risk,
    }
}

/// Parses a Shodan search API JSON response.
pub fn parse_search_response(json_body: &str) -> Option<ShodanSearchResult> {
    let val: serde_json::Value = serde_json::from_str(json_body).ok()?;

    let total = val.get("total")?.as_u64()?;
    let matches_arr = val.get("matches")?.as_array()?;

    let matches: Vec<ShodanSearchMatch> = matches_arr
        .iter()
        .filter_map(|m| {
            let ip_str = m.get("ip_str")?.as_str()?.to_string();
            let port = m.get("port")?.as_u64()? as u16;
            let banner_snippet = m
                .get("data")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .chars()
                .take(200)
                .collect();

            Some(ShodanSearchMatch {
                ip_str,
                port,
                org: m.get("org").and_then(|v| v.as_str()).map(String::from),
                product: m.get("product").and_then(|v| v.as_str()).map(String::from),
                version: m.get("version").and_then(|v| v.as_str()).map(String::from),
                banner_snippet,
                hostnames: parse_string_array(m, "hostnames"),
                asn: m.get("asn").and_then(|v| v.as_str()).map(String::from),
                country: m
                    .get("location")
                    .and_then(|l| l.get("country_code"))
                    .and_then(|v| v.as_str())
                    .map(String::from),
            })
        })
        .collect();

    Some(ShodanSearchResult {
        total,
        matches,
        facets: HashMap::new(),
    })
}

/// Builds a comprehensive Shodan report.
pub fn build_shodan_report(
    target: &str,
    hosts: Vec<ShodanHostResult>,
    search_results: Vec<ShodanSearchResult>,
) -> ShodanReport {
    let mut banner_analyses = Vec::new();
    let mut critical_vulns = Vec::new();
    let mut risk_summary: HashMap<ShodanRisk, usize> = HashMap::new();

    for host in &hosts {
        for svc in &host.services {
            let analysis = analyze_banner(svc);
            *risk_summary.entry(analysis.risk).or_insert(0) += 1;
            banner_analyses.push(analysis);
        }
        for v in &host.vulns {
            if !critical_vulns.contains(v) {
                critical_vulns.push(v.clone());
            }
        }
    }

    let exposed_count: usize = hosts.iter().map(|h| h.services.len()).sum();

    let overall_risk = risk_summary
        .keys()
        .max()
        .copied()
        .unwrap_or(ShodanRisk::Info);

    ShodanReport {
        target: target.to_string(),
        hosts,
        search_results,
        banner_analyses,
        exposed_services_count: exposed_count,
        critical_vulns,
        risk_summary,
        overall_risk,
    }
}
