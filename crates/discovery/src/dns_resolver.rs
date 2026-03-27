use std::net::IpAddr;
use std::time::Duration;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

/// DNS resolution errors.
#[derive(Debug)]
pub enum DnsError {
    ResolveFailed(String),
    NxDomain(String),
    Timeout(String),
    InvalidName(String),
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ResolveFailed(msg) => write!(f, "DNS resolve failed: {msg}"),
            Self::NxDomain(name) => write!(f, "NXDOMAIN: {name}"),
            Self::Timeout(msg) => write!(f, "DNS timeout: {msg}"),
            Self::InvalidName(name) => write!(f, "invalid DNS name: {name}"),
        }
    }
}

impl std::error::Error for DnsError {}

/// DNS record types for resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Ns,
}

/// A resolved DNS record.
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: DnsRecordType,
    pub value: String,
    pub ttl: u32,
}

/// MX record with priority.
#[derive(Debug, Clone)]
pub struct MxRecord {
    pub priority: u16,
    pub exchange: String,
}

/// CNAME chain resolution result.
#[derive(Debug, Clone)]
pub struct CnameChain {
    pub original: String,
    pub chain: Vec<String>,
    pub final_target: String,
    pub resolved_ips: Vec<IpAddr>,
}

/// Shared async DNS resolver for all discovery modules.
///
/// Wraps `hickory-resolver` (formerly trust-dns-resolver) with
/// convenience methods for common OSINT DNS operations.
pub struct SharedDnsResolver {
    resolver: TokioAsyncResolver,
}

impl SharedDnsResolver {
    /// Create a resolver using system DNS configuration.
    pub fn from_system_config() -> Result<Self, DnsError> {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );
        Ok(Self { resolver })
    }

    /// Create a resolver using specific nameservers (e.g. 8.8.8.8, 1.1.1.1).
    pub fn with_nameservers(config: ResolverConfig) -> Result<Self, DnsError> {
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(5);
        opts.attempts = 3;
        let resolver = TokioAsyncResolver::tokio(config, opts);
        Ok(Self { resolver })
    }

    /// Create a resolver using Google Public DNS.
    pub fn google_dns() -> Result<Self, DnsError> {
        Self::with_nameservers(ResolverConfig::google())
    }

    /// Create a resolver using Cloudflare DNS (1.1.1.1).
    pub fn cloudflare_dns() -> Result<Self, DnsError> {
        Self::with_nameservers(ResolverConfig::cloudflare())
    }

    /// Resolve A records for a hostname.
    pub async fn resolve_a(&self, name: &str) -> Result<Vec<IpAddr>, DnsError> {
        let response = self
            .resolver
            .lookup_ip(name)
            .await
            .map_err(|e| DnsError::ResolveFailed(e.to_string()))?;

        Ok(response.iter().collect())
    }

    /// Resolve MX records for a domain.
    pub async fn resolve_mx(&self, domain: &str) -> Result<Vec<MxRecord>, DnsError> {
        let response = self
            .resolver
            .mx_lookup(domain)
            .await
            .map_err(|e| DnsError::ResolveFailed(e.to_string()))?;

        let mut records: Vec<MxRecord> = response
            .iter()
            .map(|mx| MxRecord {
                priority: mx.preference(),
                exchange: mx.exchange().to_string().trim_end_matches('.').to_string(),
            })
            .collect();

        records.sort_by_key(|r| r.priority);
        Ok(records)
    }

    /// Resolve TXT records for a domain.
    pub async fn resolve_txt(&self, domain: &str) -> Result<Vec<String>, DnsError> {
        let response = self
            .resolver
            .txt_lookup(domain)
            .await
            .map_err(|e| DnsError::ResolveFailed(e.to_string()))?;

        Ok(response
            .iter()
            .map(|txt| txt.to_string())
            .collect())
    }

    /// Resolve NS records for a domain.
    pub async fn resolve_ns(&self, domain: &str) -> Result<Vec<String>, DnsError> {
        let response = self
            .resolver
            .ns_lookup(domain)
            .await
            .map_err(|e| DnsError::ResolveFailed(e.to_string()))?;

        Ok(response
            .iter()
            .map(|ns| ns.to_string().trim_end_matches('.').to_string())
            .collect())
    }

    /// Follow CNAME chain to its final target.
    pub async fn resolve_cname_chain(&self, name: &str) -> Result<CnameChain, DnsError> {
        let mut chain = Vec::new();
        let mut current = name.to_string();
        let max_depth = 20;

        for _ in 0..max_depth {
            match self.resolver.lookup(
                current.as_str(),
                hickory_resolver::proto::rr::RecordType::CNAME,
            ).await {
                Ok(response) => {
                    let cname = response
                        .iter()
                        .find_map(|r| {
                            if let Some(cname_data) = r.as_cname() {
                                Some(cname_data.to_string().trim_end_matches('.').to_string())
                            } else {
                                None
                            }
                        });
                    match cname {
                        Some(target) => {
                            chain.push(target.clone());
                            current = target;
                        }
                        None => break,
                    }
                }
                Err(_) => break,
            }
        }

        let final_target = chain.last().cloned().unwrap_or_else(|| name.to_string());
        let resolved_ips = self.resolve_a(&final_target).await.unwrap_or_default();

        Ok(CnameChain {
            original: name.to_string(),
            chain,
            final_target,
            resolved_ips,
        })
    }

    /// Check if a domain exists (has any DNS records).
    pub async fn domain_exists(&self, domain: &str) -> bool {
        self.resolve_a(domain).await.is_ok()
    }

    /// Resolve all common record types for a domain.
    pub async fn full_lookup(&self, domain: &str) -> Vec<DnsRecord> {
        let mut records = Vec::new();

        if let Ok(ips) = self.resolve_a(domain).await {
            for ip in ips {
                let rtype = match ip {
                    IpAddr::V4(_) => DnsRecordType::A,
                    IpAddr::V6(_) => DnsRecordType::Aaaa,
                };
                records.push(DnsRecord {
                    name: domain.to_string(),
                    record_type: rtype,
                    value: ip.to_string(),
                    ttl: 0,
                });
            }
        }

        if let Ok(mxs) = self.resolve_mx(domain).await {
            for mx in mxs {
                records.push(DnsRecord {
                    name: domain.to_string(),
                    record_type: DnsRecordType::Mx,
                    value: format!("{} {}", mx.priority, mx.exchange),
                    ttl: 0,
                });
            }
        }

        if let Ok(txts) = self.resolve_txt(domain).await {
            for txt in txts {
                records.push(DnsRecord {
                    name: domain.to_string(),
                    record_type: DnsRecordType::Txt,
                    value: txt,
                    ttl: 0,
                });
            }
        }

        if let Ok(nss) = self.resolve_ns(domain).await {
            for ns in nss {
                records.push(DnsRecord {
                    name: domain.to_string(),
                    record_type: DnsRecordType::Ns,
                    value: ns,
                    ttl: 0,
                });
            }
        }

        records
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_error_display() {
        let err = DnsError::NxDomain("test.invalid".to_string());
        assert_eq!(err.to_string(), "NXDOMAIN: test.invalid");
    }

    #[test]
    fn dns_error_resolve_display() {
        let err = DnsError::ResolveFailed("network unreachable".to_string());
        assert!(err.to_string().contains("network unreachable"));
    }

    #[test]
    fn dns_record_type_eq() {
        assert_eq!(DnsRecordType::A, DnsRecordType::A);
        assert_ne!(DnsRecordType::A, DnsRecordType::Aaaa);
    }

    #[test]
    fn mx_record_clone() {
        let mx = MxRecord {
            priority: 10,
            exchange: "mx.example.com".to_string(),
        };
        let cloned = mx.clone();
        assert_eq!(cloned.priority, 10);
        assert_eq!(cloned.exchange, "mx.example.com");
    }

    #[test]
    fn cname_chain_clone() {
        let chain = CnameChain {
            original: "www.example.com".to_string(),
            chain: vec!["cdn.example.com".to_string()],
            final_target: "cdn.example.com".to_string(),
            resolved_ips: Vec::new(),
        };
        let cloned = chain.clone();
        assert_eq!(cloned.original, "www.example.com");
        assert_eq!(cloned.chain.len(), 1);
    }

    #[test]
    fn resolver_creates_from_system() {
        let resolver = SharedDnsResolver::from_system_config();
        assert!(resolver.is_ok());
    }

    #[test]
    fn resolver_creates_google_dns() {
        let resolver = SharedDnsResolver::google_dns();
        assert!(resolver.is_ok());
    }

    #[test]
    fn resolver_creates_cloudflare_dns() {
        let resolver = SharedDnsResolver::cloudflare_dns();
        assert!(resolver.is_ok());
    }
}
