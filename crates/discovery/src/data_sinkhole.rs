use std::collections::HashMap;

/// Category of exposed data sinkhole service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SinkholeServiceType {
    Elasticsearch,
    Kibana,
    Grafana,
    JupyterNotebook,
    KubernetesDashboard,
    Redis,
    Memcached,
    Firebase,
    S3Bucket,
    GcsBucket,
    AzureBlob,
    MongoDb,
    CouchDb,
    Cassandra,
    InfluxDb,
    Prometheus,
    Jenkins,
    SonarQube,
    Minio,
    Etcd,
}

impl std::fmt::Display for SinkholeServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Elasticsearch => write!(f, "Elasticsearch"),
            Self::Kibana => write!(f, "Kibana"),
            Self::Grafana => write!(f, "Grafana"),
            Self::JupyterNotebook => write!(f, "Jupyter Notebook"),
            Self::KubernetesDashboard => write!(f, "Kubernetes Dashboard"),
            Self::Redis => write!(f, "Redis"),
            Self::Memcached => write!(f, "Memcached"),
            Self::Firebase => write!(f, "Firebase Realtime DB"),
            Self::S3Bucket => write!(f, "AWS S3 Bucket"),
            Self::GcsBucket => write!(f, "Google Cloud Storage"),
            Self::AzureBlob => write!(f, "Azure Blob Storage"),
            Self::MongoDb => write!(f, "MongoDB"),
            Self::CouchDb => write!(f, "CouchDB"),
            Self::Cassandra => write!(f, "Cassandra"),
            Self::InfluxDb => write!(f, "InfluxDB"),
            Self::Prometheus => write!(f, "Prometheus"),
            Self::Jenkins => write!(f, "Jenkins"),
            Self::SonarQube => write!(f, "SonarQube"),
            Self::Minio => write!(f, "MinIO"),
            Self::Etcd => write!(f, "etcd"),
        }
    }
}

/// Data sensitivity classification for exposed data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DataSensitivity {
    Public,
    Internal,
    Confidential,
    Restricted,
    Critical,
}

impl std::fmt::Display for DataSensitivity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public => write!(f, "Public"),
            Self::Internal => write!(f, "Internal"),
            Self::Confidential => write!(f, "Confidential"),
            Self::Restricted => write!(f, "Restricted"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// Authentication state of an exposed service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthState {
    NoAuth,
    DefaultCredentials,
    AnonymousAccess,
    WeakAuth,
    RequiresAuth,
}

impl std::fmt::Display for AuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAuth => write!(f, "No Authentication"),
            Self::DefaultCredentials => write!(f, "Default Credentials"),
            Self::AnonymousAccess => write!(f, "Anonymous Access Enabled"),
            Self::WeakAuth => write!(f, "Weak Authentication"),
            Self::RequiresAuth => write!(f, "Requires Authentication"),
        }
    }
}

/// Wire protocol used for probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WireProtocol {
    Http,
    Https,
    RedisResp,
    MemcachedAscii,
    MongoWire,
    CouchHttpApi,
    FirebaseRest,
    S3Api,
    EtcdGrpc,
    InfluxHttp,
}

impl std::fmt::Display for WireProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http => write!(f, "HTTP"),
            Self::Https => write!(f, "HTTPS"),
            Self::RedisResp => write!(f, "Redis RESP"),
            Self::MemcachedAscii => write!(f, "Memcached ASCII"),
            Self::MongoWire => write!(f, "MongoDB Wire"),
            Self::CouchHttpApi => write!(f, "CouchDB HTTP API"),
            Self::FirebaseRest => write!(f, "Firebase REST"),
            Self::S3Api => write!(f, "S3 API"),
            Self::EtcdGrpc => write!(f, "etcd gRPC"),
            Self::InfluxHttp => write!(f, "InfluxDB HTTP"),
        }
    }
}

/// A detected data sinkhole: an exposed service leaking data.
#[derive(Debug, Clone, PartialEq)]
pub struct SinkholeDetection {
    pub service_type: SinkholeServiceType,
    pub host: String,
    pub port: u16,
    pub protocol: WireProtocol,
    pub auth_state: AuthState,
    pub data_sensitivity: DataSensitivity,
    pub data_indicators: Vec<DataIndicator>,
    pub version: Option<String>,
    pub evidence: Vec<String>,
    pub remediation: String,
}

/// Indicator of what data is exposed through the sinkhole.
#[derive(Debug, Clone, PartialEq)]
pub struct DataIndicator {
    pub indicator_type: DataIndicatorType,
    pub description: String,
    pub sample_redacted: Option<String>,
    pub sensitivity: DataSensitivity,
}

/// Categories of data indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataIndicatorType {
    Credentials,
    PersonalInfo,
    SessionTokens,
    ApiKeys,
    DatabaseRecords,
    LogEntries,
    HealthMetrics,
    SourceCode,
    Configuration,
    FinancialData,
    InternalUrls,
}

impl std::fmt::Display for DataIndicatorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Credentials => write!(f, "Credentials"),
            Self::PersonalInfo => write!(f, "Personal Information"),
            Self::SessionTokens => write!(f, "Session Tokens"),
            Self::ApiKeys => write!(f, "API Keys"),
            Self::DatabaseRecords => write!(f, "Database Records"),
            Self::LogEntries => write!(f, "Log Entries"),
            Self::HealthMetrics => write!(f, "Health Metrics"),
            Self::SourceCode => write!(f, "Source Code"),
            Self::Configuration => write!(f, "Configuration"),
            Self::FinancialData => write!(f, "Financial Data"),
            Self::InternalUrls => write!(f, "Internal URLs"),
        }
    }
}

/// Probe definition: how to check a service for exposure.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceProbe {
    pub service_type: SinkholeServiceType,
    pub default_ports: Vec<u16>,
    pub protocol: WireProtocol,
    pub probe_paths: Vec<String>,
    pub success_indicators: Vec<String>,
    pub version_extraction: Option<String>,
}

/// Result of a full sinkhole detection scan.
#[derive(Debug, Clone)]
pub struct SinkholeDetectionResult {
    pub detections: Vec<SinkholeDetection>,
    pub probes_sent: usize,
    pub services_found: usize,
    pub critical_exposures: usize,
    pub summary: String,
}

/// Configuration for the sinkhole detector.
#[derive(Debug, Clone)]
pub struct SinkholeDetectorConfig {
    pub scan_databases: bool,
    pub scan_dashboards: bool,
    pub scan_caches: bool,
    pub scan_cloud_storage: bool,
    pub scan_ci_tools: bool,
    pub classify_sensitivity: bool,
    pub max_response_bytes: usize,
}

impl Default for SinkholeDetectorConfig {
    fn default() -> Self {
        Self {
            scan_databases: true,
            scan_dashboards: true,
            scan_caches: true,
            scan_cloud_storage: true,
            scan_ci_tools: true,
            classify_sensitivity: true,
            max_response_bytes: 1024 * 1024,
        }
    }
}

impl SinkholeDetectorConfig {
    pub fn with_scan_databases(mut self, enabled: bool) -> Self {
        self.scan_databases = enabled;
        self
    }

    pub fn with_scan_dashboards(mut self, enabled: bool) -> Self {
        self.scan_dashboards = enabled;
        self
    }

    pub fn with_scan_cloud_storage(mut self, enabled: bool) -> Self {
        self.scan_cloud_storage = enabled;
        self
    }

    pub fn with_max_response_bytes(mut self, bytes: usize) -> Self {
        self.max_response_bytes = bytes;
        self
    }
}

/// Discovers unintentional data exposure from misconfigured services.
/// Speaks native wire protocols and classifies sensitivity without exfiltrating.
pub struct DataSinkholeDetector {
    config: SinkholeDetectorConfig,
}

impl DataSinkholeDetector {
    pub fn new(config: SinkholeDetectorConfig) -> Self {
        Self { config }
    }

    /// Generate probe definitions for all supported service types.
    pub fn generate_probes(&self) -> Vec<ServiceProbe> {
        let mut probes = Vec::new();

        if self.config.scan_databases {
            probes.push(ServiceProbe {
                service_type: SinkholeServiceType::Elasticsearch,
                default_ports: vec![9200, 9300],
                protocol: WireProtocol::Http,
                probe_paths: vec![
                    "/".to_string(),
                    "/_cat/indices".to_string(),
                    "/_cluster/health".to_string(),
                    "/_nodes".to_string(),
                ],
                success_indicators: vec![
                    "cluster_name".to_string(),
                    "cluster_uuid".to_string(),
                    "tagline".to_string(),
                ],
                version_extraction: Some(r#""number"\s*:\s*"([^"]+)""#.to_string()),
            });

            probes.push(ServiceProbe {
                service_type: SinkholeServiceType::MongoDb,
                default_ports: vec![27017, 27018],
                protocol: WireProtocol::MongoWire,
                probe_paths: vec![],
                success_indicators: vec!["ismaster".to_string(), "maxBsonObjectSize".to_string()],
                version_extraction: Some(r#""version"\s*:\s*"([^"]+)""#.to_string()),
            });

            probes.push(ServiceProbe {
                service_type: SinkholeServiceType::CouchDb,
                default_ports: vec![5984],
                protocol: WireProtocol::CouchHttpApi,
                probe_paths: vec![
                    "/".to_string(),
                    "/_all_dbs".to_string(),
                    "/_utils/".to_string(),
                ],
                success_indicators: vec!["couchdb".to_string(), "Welcome".to_string()],
                version_extraction: Some(r#""version"\s*:\s*"([^"]+)""#.to_string()),
            });

            probes.push(ServiceProbe {
                service_type: SinkholeServiceType::InfluxDb,
                default_ports: vec![8086],
                protocol: WireProtocol::InfluxHttp,
                probe_paths: vec!["/ping".to_string(), "/query?q=SHOW+DATABASES".to_string()],
                success_indicators: vec!["InfluxDB".to_string(), "results".to_string()],
                version_extraction: Some(r#"X-Influxdb-Version:\s*([^\s]+)"#.to_string()),
            });

            probes.push(ServiceProbe {
                service_type: SinkholeServiceType::Etcd,
                default_ports: vec![2379, 2380],
                protocol: WireProtocol::Http,
                probe_paths: vec![
                    "/version".to_string(),
                    "/v2/keys/".to_string(),
                    "/v3/kv/range".to_string(),
                ],
                success_indicators: vec!["etcdserver".to_string(), "etcdcluster".to_string()],
                version_extraction: Some(r#""etcdserver"\s*:\s*"([^"]+)""#.to_string()),
            });
        }

        if self.config.scan_caches {
            probes.push(ServiceProbe {
                service_type: SinkholeServiceType::Redis,
                default_ports: vec![6379],
                protocol: WireProtocol::RedisResp,
                probe_paths: vec![],
                success_indicators: vec![
                    "redis_version".to_string(),
                    "connected_clients".to_string(),
                ],
                version_extraction: Some(r"redis_version:([^\s]+)".to_string()),
            });

            probes.push(ServiceProbe {
                service_type: SinkholeServiceType::Memcached,
                default_ports: vec![11211],
                protocol: WireProtocol::MemcachedAscii,
                probe_paths: vec![],
                success_indicators: vec!["STAT".to_string(), "curr_items".to_string()],
                version_extraction: Some(r"version\s+([^\s]+)".to_string()),
            });
        }

        if self.config.scan_dashboards {
            probes.push(ServiceProbe {
                service_type: SinkholeServiceType::Kibana,
                default_ports: vec![5601],
                protocol: WireProtocol::Http,
                probe_paths: vec!["/api/status".to_string(), "/app/kibana".to_string()],
                success_indicators: vec!["kibana".to_string(), "Looking good".to_string()],
                version_extraction: Some(
                    r#""version"\s*:\s*\{"number"\s*:\s*"([^"]+)""#.to_string(),
                ),
            });

            probes.push(ServiceProbe {
                service_type: SinkholeServiceType::Grafana,
                default_ports: vec![3000],
                protocol: WireProtocol::Http,
                probe_paths: vec![
                    "/api/health".to_string(),
                    "/api/org".to_string(),
                    "/api/dashboards/home".to_string(),
                ],
                success_indicators: vec!["Grafana".to_string(), "database".to_string()],
                version_extraction: Some(r#""version"\s*:\s*"([^"]+)""#.to_string()),
            });

            probes.push(ServiceProbe {
                service_type: SinkholeServiceType::JupyterNotebook,
                default_ports: vec![8888, 8889],
                protocol: WireProtocol::Http,
                probe_paths: vec![
                    "/api".to_string(),
                    "/api/contents".to_string(),
                    "/api/kernels".to_string(),
                ],
                success_indicators: vec!["jupyter".to_string(), "notebook".to_string()],
                version_extraction: Some(r#""version"\s*:\s*"([^"]+)""#.to_string()),
            });

            probes.push(ServiceProbe {
                service_type: SinkholeServiceType::KubernetesDashboard,
                default_ports: vec![8443, 443, 30000],
                protocol: WireProtocol::Https,
                probe_paths: vec!["/api/v1/namespaces".to_string(), "/api/v1/pods".to_string()],
                success_indicators: vec!["items".to_string(), "metadata".to_string()],
                version_extraction: None,
            });

            probes.push(ServiceProbe {
                service_type: SinkholeServiceType::Prometheus,
                default_ports: vec![9090],
                protocol: WireProtocol::Http,
                probe_paths: vec![
                    "/api/v1/targets".to_string(),
                    "/api/v1/label/__name__/values".to_string(),
                    "/metrics".to_string(),
                ],
                success_indicators: vec!["activeTargets".to_string(), "prometheus".to_string()],
                version_extraction: Some(r#""version"\s*:\s*"([^"]+)""#.to_string()),
            });
        }

        if self.config.scan_cloud_storage {
            probes.push(ServiceProbe {
                service_type: SinkholeServiceType::S3Bucket,
                default_ports: vec![443],
                protocol: WireProtocol::S3Api,
                probe_paths: vec!["/".to_string(), "/?list-type=2".to_string()],
                success_indicators: vec!["ListBucketResult".to_string(), "Contents".to_string()],
                version_extraction: None,
            });

            probes.push(ServiceProbe {
                service_type: SinkholeServiceType::Firebase,
                default_ports: vec![443],
                protocol: WireProtocol::FirebaseRest,
                probe_paths: vec!["/.json".to_string()],
                success_indicators: vec![],
                version_extraction: None,
            });

            probes.push(ServiceProbe {
                service_type: SinkholeServiceType::Minio,
                default_ports: vec![9000, 9001],
                protocol: WireProtocol::S3Api,
                probe_paths: vec![
                    "/minio/health/live".to_string(),
                    "/minio/health/cluster".to_string(),
                ],
                success_indicators: vec!["MinIO".to_string()],
                version_extraction: None,
            });
        }

        if self.config.scan_ci_tools {
            probes.push(ServiceProbe {
                service_type: SinkholeServiceType::Jenkins,
                default_ports: vec![8080, 8443],
                protocol: WireProtocol::Http,
                probe_paths: vec![
                    "/api/json".to_string(),
                    "/script".to_string(),
                    "/computer/api/json".to_string(),
                ],
                success_indicators: vec!["Jenkins".to_string(), "hudson".to_string()],
                version_extraction: Some(r"X-Jenkins:\s*([^\s]+)".to_string()),
            });

            probes.push(ServiceProbe {
                service_type: SinkholeServiceType::SonarQube,
                default_ports: vec![9000],
                protocol: WireProtocol::Http,
                probe_paths: vec![
                    "/api/system/status".to_string(),
                    "/api/projects/search".to_string(),
                ],
                success_indicators: vec!["SonarQube".to_string(), "UP".to_string()],
                version_extraction: Some(r#""version"\s*:\s*"([^"]+)""#.to_string()),
            });
        }

        probes
    }

    /// Classify sensitivity of data found in a service response WITHOUT exfiltrating.
    pub fn classify_response_sensitivity(&self, response_body: &str) -> Vec<DataIndicator> {
        if !self.config.classify_sensitivity {
            return Vec::new();
        }
        let mut indicators = Vec::new();

        let credential_patterns = [
            (
                "password",
                DataIndicatorType::Credentials,
                DataSensitivity::Critical,
            ),
            (
                "secret_key",
                DataIndicatorType::ApiKeys,
                DataSensitivity::Critical,
            ),
            (
                "aws_access_key",
                DataIndicatorType::ApiKeys,
                DataSensitivity::Critical,
            ),
            (
                "private_key",
                DataIndicatorType::Credentials,
                DataSensitivity::Critical,
            ),
            (
                "api_key",
                DataIndicatorType::ApiKeys,
                DataSensitivity::Restricted,
            ),
            (
                "token",
                DataIndicatorType::SessionTokens,
                DataSensitivity::Restricted,
            ),
            (
                "authorization",
                DataIndicatorType::SessionTokens,
                DataSensitivity::Restricted,
            ),
        ];

        let pii_patterns = [
            (
                "email",
                DataIndicatorType::PersonalInfo,
                DataSensitivity::Confidential,
            ),
            (
                "phone",
                DataIndicatorType::PersonalInfo,
                DataSensitivity::Confidential,
            ),
            (
                "ssn",
                DataIndicatorType::PersonalInfo,
                DataSensitivity::Critical,
            ),
            (
                "credit_card",
                DataIndicatorType::FinancialData,
                DataSensitivity::Critical,
            ),
            (
                "date_of_birth",
                DataIndicatorType::PersonalInfo,
                DataSensitivity::Restricted,
            ),
            (
                "address",
                DataIndicatorType::PersonalInfo,
                DataSensitivity::Confidential,
            ),
        ];

        let infra_patterns = [
            (
                "internal_url",
                DataIndicatorType::InternalUrls,
                DataSensitivity::Internal,
            ),
            (
                "10.0.",
                DataIndicatorType::InternalUrls,
                DataSensitivity::Internal,
            ),
            (
                "192.168.",
                DataIndicatorType::InternalUrls,
                DataSensitivity::Internal,
            ),
            (
                "172.16.",
                DataIndicatorType::InternalUrls,
                DataSensitivity::Internal,
            ),
            (
                "source_code",
                DataIndicatorType::SourceCode,
                DataSensitivity::Confidential,
            ),
            (
                "stack_trace",
                DataIndicatorType::LogEntries,
                DataSensitivity::Internal,
            ),
            (
                "database_url",
                DataIndicatorType::Configuration,
                DataSensitivity::Restricted,
            ),
        ];

        let lower = response_body.to_lowercase();

        for (pattern, ind_type, sensitivity) in &credential_patterns {
            if lower.contains(pattern) {
                indicators.push(DataIndicator {
                    indicator_type: *ind_type,
                    description: format!("Potential {} exposure detected", pattern),
                    sample_redacted: Some(format!("[REDACTED:{}]", pattern)),
                    sensitivity: *sensitivity,
                });
            }
        }

        for (pattern, ind_type, sensitivity) in &pii_patterns {
            if lower.contains(pattern) {
                indicators.push(DataIndicator {
                    indicator_type: *ind_type,
                    description: format!("PII indicator: {} field present", pattern),
                    sample_redacted: Some(format!("[REDACTED:{}]", pattern)),
                    sensitivity: *sensitivity,
                });
            }
        }

        for (pattern, ind_type, sensitivity) in &infra_patterns {
            if lower.contains(pattern) {
                indicators.push(DataIndicator {
                    indicator_type: *ind_type,
                    description: format!("Infrastructure detail: {} exposed", pattern),
                    sample_redacted: None,
                    sensitivity: *sensitivity,
                });
            }
        }

        indicators
    }

    /// Determine auth state from probe response characteristics.
    pub fn classify_auth_state(
        &self,
        status_code: u16,
        response_body: &str,
        headers: &HashMap<String, String>,
    ) -> AuthState {
        if status_code == 401 || status_code == 403 {
            return AuthState::RequiresAuth;
        }

        let auth_header = headers.get("www-authenticate");
        if auth_header.is_some() && status_code == 200 {
            return AuthState::WeakAuth;
        }

        let lower_body = response_body.to_lowercase();
        if lower_body.contains("anonymous") || lower_body.contains("guest") {
            return AuthState::AnonymousAccess;
        }

        let default_cred_indicators = [
            "admin:admin",
            "root:root",
            "default",
            "changeme",
            "admin:password",
            "elastic:changeme",
        ];
        for indicator in &default_cred_indicators {
            if lower_body.contains(indicator) {
                return AuthState::DefaultCredentials;
            }
        }

        if status_code == 200 {
            return AuthState::NoAuth;
        }

        AuthState::RequiresAuth
    }

    /// Generate remediation advice for a detected sinkhole.
    pub fn remediation_for(
        &self,
        service_type: SinkholeServiceType,
        auth_state: AuthState,
    ) -> String {
        let service_advice = match service_type {
            SinkholeServiceType::Elasticsearch => "Bind to localhost or internal network; enable X-Pack security; require TLS with client certs",
            SinkholeServiceType::Kibana => "Enable authentication; use Elasticsearch security; restrict to internal network",
            SinkholeServiceType::Grafana => "Disable anonymous access; require authentication; use HTTPS with SSO",
            SinkholeServiceType::JupyterNotebook => "Set token/password authentication; bind to localhost; use JupyterHub for multi-user",
            SinkholeServiceType::KubernetesDashboard => "Require RBAC authentication; never expose publicly; use kubectl proxy",
            SinkholeServiceType::Redis => "Set requirepass; bind to 127.0.0.1; disable dangerous commands; use TLS",
            SinkholeServiceType::Memcached => "Bind to localhost; use SASL authentication; firewall external access",
            SinkholeServiceType::Firebase => "Configure security rules; require authentication; disable .read: true at root",
            SinkholeServiceType::S3Bucket => "Remove public ACL; enable Block Public Access; use bucket policies with least privilege",
            SinkholeServiceType::GcsBucket => "Remove allUsers/allAuthenticatedUsers; use IAM with least privilege",
            SinkholeServiceType::AzureBlob => "Disable public access; use SAS tokens with expiration; enable Advanced Threat Protection",
            SinkholeServiceType::MongoDb => "Enable --auth flag; bind to 127.0.0.1; use TLS; create admin user",
            SinkholeServiceType::CouchDb => "Create admin user; disable admin party; bind to localhost",
            SinkholeServiceType::Cassandra => "Enable authentication; configure role-based access; use TLS for internode",
            SinkholeServiceType::InfluxDb => "Enable authentication; create admin user; use HTTPS",
            SinkholeServiceType::Prometheus => "Use reverse proxy with auth; never expose /api directly; restrict to internal network",
            SinkholeServiceType::Jenkins => "Disable anonymous read; require matrix-based security; remove script console access",
            SinkholeServiceType::SonarQube => "Disable anonymous analysis browsing; require authentication; rotate default admin password",
            SinkholeServiceType::Minio => "Set MINIO_ROOT_USER/PASSWORD; use TLS; configure bucket policies",
            SinkholeServiceType::Etcd => "Require client cert authentication; enable TLS; restrict to cluster network",
        };

        let auth_advice = match auth_state {
            AuthState::NoAuth => "URGENT: Service is completely unauthenticated",
            AuthState::DefaultCredentials => {
                "URGENT: Default credentials detected — change immediately"
            }
            AuthState::AnonymousAccess => {
                "HIGH: Anonymous access enabled — disable and require authentication"
            }
            AuthState::WeakAuth => {
                "MEDIUM: Authentication present but weak — upgrade to strong auth"
            }
            AuthState::RequiresAuth => "OK: Authentication is required",
        };

        format!("{}. {}", auth_advice, service_advice)
    }

    /// Analyze probe results and build detection report.
    pub fn analyze_responses(&self, responses: &[ProbeResponse]) -> SinkholeDetectionResult {
        let mut detections = Vec::new();
        let probes_sent = responses.len();

        for resp in responses {
            if resp.status_code == 0 || resp.status_code >= 500 {
                continue;
            }
            if resp.status_code == 401 || resp.status_code == 403 {
                continue;
            }

            let indicators = self.classify_response_sensitivity(&resp.body);
            let auth_state = self.classify_auth_state(resp.status_code, &resp.body, &resp.headers);

            if auth_state == AuthState::RequiresAuth {
                continue;
            }

            let max_sensitivity = indicators
                .iter()
                .map(|i| i.sensitivity)
                .max()
                .unwrap_or(DataSensitivity::Internal);

            let remediation = self.remediation_for(resp.service_type, auth_state);

            let mut evidence = vec![
                format!(
                    "Service: {} at {}:{}",
                    resp.service_type, resp.host, resp.port
                ),
                format!("Auth state: {}", auth_state),
                format!("HTTP {}", resp.status_code),
            ];
            if let Some(v) = &resp.detected_version {
                evidence.push(format!("Version: {}", v));
            }

            detections.push(SinkholeDetection {
                service_type: resp.service_type,
                host: resp.host.clone(),
                port: resp.port,
                protocol: resp.protocol,
                auth_state,
                data_sensitivity: max_sensitivity,
                data_indicators: indicators,
                version: resp.detected_version.clone(),
                evidence,
                remediation,
            });
        }

        let critical = detections
            .iter()
            .filter(|d| d.data_sensitivity >= DataSensitivity::Restricted)
            .count();

        let summary = format!(
            "Sinkhole scan: {} probes, {} exposed services, {} critical exposures",
            probes_sent,
            detections.len(),
            critical,
        );

        SinkholeDetectionResult {
            detections,
            probes_sent,
            services_found: probes_sent,
            critical_exposures: critical,
            summary,
        }
    }

    /// Build a Firebase probe URL for a given project.
    pub fn firebase_probe_url(project_id: &str) -> String {
        format!("https://{}-default-rtdb.firebaseio.com/.json", project_id)
    }

    /// Build an S3 probe URL for a bucket.
    pub fn s3_probe_url(bucket_name: &str, region: &str) -> String {
        format!("https://{}.s3.{}.amazonaws.com/", bucket_name, region)
    }

    /// Build a GCS probe URL.
    pub fn gcs_probe_url(bucket_name: &str) -> String {
        format!("https://storage.googleapis.com/{}/", bucket_name)
    }
}

/// A simulated probe response for analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeResponse {
    pub service_type: SinkholeServiceType,
    pub host: String,
    pub port: u16,
    pub protocol: WireProtocol,
    pub status_code: u16,
    pub body: String,
    pub headers: HashMap<String, String>,
    pub detected_version: Option<String>,
}
