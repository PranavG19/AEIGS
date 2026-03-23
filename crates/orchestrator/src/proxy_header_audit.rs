use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ProxyHeaderIssue {
    ViaProxyLeak { value: String },
    AgePresent { seconds: String },
    XCacheHit { status: String },
    XForwardedFor { ips: String },
    XForwardedHost { host: String },
    XRealIp { ip: String },
    CdnIdentified { cdn: String },
    InternalIpLeak { ip: String },
    ProxyChainLength { count: usize },
    ServerTimingLeak { value: String },
}

impl std::fmt::Display for ProxyHeaderIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyHeaderIssue::ViaProxyLeak { value } => {
                write!(f, "via_proxy_leak:{value}")
            }
            ProxyHeaderIssue::AgePresent { seconds } => {
                write!(f, "age_present:{seconds}")
            }
            ProxyHeaderIssue::XCacheHit { status } => {
                write!(f, "x_cache_hit:{status}")
            }
            ProxyHeaderIssue::XForwardedFor { ips } => {
                write!(f, "x_forwarded_for:{ips}")
            }
            ProxyHeaderIssue::XForwardedHost { host } => {
                write!(f, "x_forwarded_host:{host}")
            }
            ProxyHeaderIssue::XRealIp { ip } => {
                write!(f, "x_real_ip:{ip}")
            }
            ProxyHeaderIssue::CdnIdentified { cdn } => {
                write!(f, "cdn_identified:{cdn}")
            }
            ProxyHeaderIssue::InternalIpLeak { ip } => {
                write!(f, "internal_ip_leak:{ip}")
            }
            ProxyHeaderIssue::ProxyChainLength { count } => {
                write!(f, "proxy_chain_length:{count}")
            }
            ProxyHeaderIssue::ServerTimingLeak { value } => {
                write!(f, "server_timing_leak:{value}")
            }
        }
    }
}

pub fn proxy_header_severity(issue: &ProxyHeaderIssue) -> f64 {
    match issue {
        ProxyHeaderIssue::ViaProxyLeak { .. } => 3.0,
        ProxyHeaderIssue::AgePresent { .. } => 1.5,
        ProxyHeaderIssue::XCacheHit { .. } => 2.0,
        ProxyHeaderIssue::XForwardedFor { .. } => 3.0,
        ProxyHeaderIssue::XForwardedHost { .. } => 3.5,
        ProxyHeaderIssue::XRealIp { .. } => 3.0,
        ProxyHeaderIssue::CdnIdentified { .. } => 2.0,
        ProxyHeaderIssue::InternalIpLeak { .. } => 5.0,
        ProxyHeaderIssue::ProxyChainLength { .. } => 2.5,
        ProxyHeaderIssue::ServerTimingLeak { .. } => 3.5,
    }
}

pub fn audit_proxy_headers(target: &str) -> Vec<ProxyHeaderIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let pairs: Vec<(&str, &str)> = resp
        .headers()
        .iter()
        .filter_map(|(name, value)| value.to_str().ok().map(|v| (name.as_str(), v)))
        .collect();

    analyze_proxy_headers(&pairs)
}

pub fn analyze_proxy_headers(headers: &[(&str, &str)]) -> Vec<ProxyHeaderIssue> {
    let mut issues = Vec::new();

    check_via(headers, &mut issues);
    check_age(headers, &mut issues);
    check_x_cache(headers, &mut issues);
    check_x_forwarded_for(headers, &mut issues);
    check_x_forwarded_host(headers, &mut issues);
    check_x_real_ip(headers, &mut issues);
    check_cdn(headers, &mut issues);
    check_server_timing(headers, &mut issues);

    issues
}

fn check_via(headers: &[(&str, &str)], issues: &mut Vec<ProxyHeaderIssue>) {
    let via_entries: Vec<&str> = headers
        .iter()
        .filter(|(name, _)| *name == "via")
        .map(|(_, value)| *value)
        .collect();

    for via in &via_entries {
        issues.push(ProxyHeaderIssue::ViaProxyLeak {
            value: via.to_string(),
        });
    }

    if via_entries.len() > 1 {
        issues.push(ProxyHeaderIssue::ProxyChainLength {
            count: via_entries.len(),
        });
    }

    check_cdn_in_via(&via_entries, issues);
}

fn check_cdn_in_via(via_entries: &[&str], issues: &mut Vec<ProxyHeaderIssue>) {
    let cdn_tokens = ["cloudflare", "akamai", "cloudfront", "fastly"];
    for via in via_entries {
        for token in &cdn_tokens {
            if via.contains(token) {
                issues.push(ProxyHeaderIssue::CdnIdentified {
                    cdn: token.to_string(),
                });
            }
        }
    }
}

fn check_age(headers: &[(&str, &str)], issues: &mut Vec<ProxyHeaderIssue>) {
    for (name, value) in headers {
        if *name == "age" {
            issues.push(ProxyHeaderIssue::AgePresent {
                seconds: value.to_string(),
            });
        }
    }
}

fn check_x_cache(headers: &[(&str, &str)], issues: &mut Vec<ProxyHeaderIssue>) {
    for (name, value) in headers {
        if *name == "x-cache" {
            issues.push(ProxyHeaderIssue::XCacheHit {
                status: value.to_string(),
            });
        }
    }
}

fn check_x_forwarded_for(headers: &[(&str, &str)], issues: &mut Vec<ProxyHeaderIssue>) {
    for (name, value) in headers {
        if *name == "x-forwarded-for" {
            issues.push(ProxyHeaderIssue::XForwardedFor {
                ips: value.to_string(),
            });
            check_internal_ips(value, issues);
        }
    }
}

fn check_internal_ips(forwarded_value: &str, issues: &mut Vec<ProxyHeaderIssue>) {
    for segment in forwarded_value.split(',') {
        let ip = segment.trim();
        if is_internal_ip(ip) {
            issues.push(ProxyHeaderIssue::InternalIpLeak { ip: ip.to_string() });
        }
    }
}

fn is_internal_ip(ip: &str) -> bool {
    if ip.starts_with("10.") {
        return true;
    }
    if ip.starts_with("192.168.") {
        return true;
    }
    if ip.starts_with("172.") {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() >= 2
            && let Ok(second_octet) = parts[1].parse::<u8>()
        {
            return (16..=31).contains(&second_octet);
        }
    }
    false
}

fn check_x_forwarded_host(headers: &[(&str, &str)], issues: &mut Vec<ProxyHeaderIssue>) {
    for (name, value) in headers {
        if *name == "x-forwarded-host" {
            issues.push(ProxyHeaderIssue::XForwardedHost {
                host: value.to_string(),
            });
        }
    }
}

fn check_x_real_ip(headers: &[(&str, &str)], issues: &mut Vec<ProxyHeaderIssue>) {
    for (name, value) in headers {
        if *name == "x-real-ip" {
            issues.push(ProxyHeaderIssue::XRealIp {
                ip: value.to_string(),
            });
        }
    }
}

fn check_cdn(headers: &[(&str, &str)], issues: &mut Vec<ProxyHeaderIssue>) {
    let cdn_tokens = ["cloudflare", "akamai", "cloudfront", "fastly"];
    for (name, value) in headers {
        if *name == "server" {
            for token in &cdn_tokens {
                if value.contains(token) {
                    issues.push(ProxyHeaderIssue::CdnIdentified {
                        cdn: token.to_string(),
                    });
                }
            }
        }
    }
}

fn check_server_timing(headers: &[(&str, &str)], issues: &mut Vec<ProxyHeaderIssue>) {
    for (name, value) in headers {
        if *name == "server-timing" {
            issues.push(ProxyHeaderIssue::ServerTimingLeak {
                value: value.to_string(),
            });
        }
    }
}

pub fn proxy_header_to_operations(
    issues: &[ProxyHeaderIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            let severity = proxy_header_severity(issue);
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                severity,
                0.5,
            )
        })
        .collect()
}
