#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcService {
    pub name: String,
    pub methods: Vec<GrpcMethod>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcMethod {
    pub name: String,
    pub full_path: String,
    pub client_streaming: bool,
    pub server_streaming: bool,
    pub input_type: String,
    pub output_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrpcStreamType {
    Unary,
    ServerStreaming,
    ClientStreaming,
    Bidirectional,
}

impl std::fmt::Display for GrpcStreamType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Unary => "unary",
            Self::ServerStreaming => "server_streaming",
            Self::ClientStreaming => "client_streaming",
            Self::Bidirectional => "bidirectional",
        };
        write!(f, "{label}")
    }
}

impl GrpcMethod {
    pub fn stream_type(&self) -> GrpcStreamType {
        match (self.client_streaming, self.server_streaming) {
            (false, false) => GrpcStreamType::Unary,
            (false, true) => GrpcStreamType::ServerStreaming,
            (true, false) => GrpcStreamType::ClientStreaming,
            (true, true) => GrpcStreamType::Bidirectional,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrpcAuthResult {
    Allowed,
    Denied,
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcAuthTestResult {
    pub method_path: String,
    pub token_description: String,
    pub result: GrpcAuthResult,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataInjectionPayload {
    pub key: String,
    pub value: String,
    pub attack_type: MetadataAttackType,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataAttackType {
    HeaderInjection,
    PathTraversal,
    SqlInjection,
    CommandInjection,
    SizeAbuse,
    NullByte,
}

impl std::fmt::Display for MetadataAttackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::HeaderInjection => "header_injection",
            Self::PathTraversal => "path_traversal",
            Self::SqlInjection => "sql_injection",
            Self::CommandInjection => "command_injection",
            Self::SizeAbuse => "size_abuse",
            Self::NullByte => "null_byte",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSizeTestCase {
    pub description: String,
    pub target_method: String,
    pub size_bytes: usize,
    pub nested_depth: usize,
    pub repeated_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamAbuseTestCase {
    pub description: String,
    pub target_method: String,
    pub stream_type: GrpcStreamType,
    pub abuse_type: StreamAbuseType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamAbuseType {
    RapidMessages,
    SlowLoris,
    InfiniteStream,
    OversizedMessage,
    HalfClose,
    CancelFlood,
}

impl std::fmt::Display for StreamAbuseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::RapidMessages => "rapid_messages",
            Self::SlowLoris => "slow_loris",
            Self::InfiniteStream => "infinite_stream",
            Self::OversizedMessage => "oversized_message",
            Self::HalfClose => "half_close",
            Self::CancelFlood => "cancel_flood",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorMessageFinding {
    pub method_path: String,
    pub grpc_status_code: i32,
    pub message: String,
    pub leaked_info: Vec<LeakedInfoType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeakedInfoType {
    StackTrace,
    InternalPath,
    DatabaseInfo,
    VersionInfo,
    InternalIp,
    ConfigDetail,
}

impl std::fmt::Display for LeakedInfoType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::StackTrace => "stack_trace",
            Self::InternalPath => "internal_path",
            Self::DatabaseInfo => "database_info",
            Self::VersionInfo => "version_info",
            Self::InternalIp => "internal_ip",
            Self::ConfigDetail => "config_detail",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone)]
pub struct GrpcSecurityReport {
    pub services: Vec<GrpcService>,
    pub reflection_enabled: bool,
    pub auth_test_results: Vec<GrpcAuthTestResult>,
    pub metadata_payloads: Vec<MetadataInjectionPayload>,
    pub message_size_tests: Vec<MessageSizeTestCase>,
    pub stream_abuse_tests: Vec<StreamAbuseTestCase>,
    pub error_findings: Vec<ErrorMessageFinding>,
}

pub struct GrpcSecurityTester {
    services: Vec<GrpcService>,
    reflection_enabled: bool,
}

impl GrpcSecurityTester {
    pub fn new() -> Self {
        Self {
            services: Vec::new(),
            reflection_enabled: false,
        }
    }

    pub fn set_reflection_enabled(&mut self, enabled: bool) {
        self.reflection_enabled = enabled;
    }

    pub fn add_service(&mut self, service: GrpcService) {
        self.services.push(service);
    }

    pub fn services(&self) -> &[GrpcService] {
        &self.services
    }

    pub fn generate_auth_test_plan(&self) -> Vec<GrpcAuthTestResult> {
        let token_scenarios = vec![
            ("no_token", "Request with no authentication token"),
            ("empty_token", "Request with empty bearer token"),
            (
                "malformed_token",
                "Request with malformed JWT (invalid base64)",
            ),
            ("expired_token", "Request with expired JWT"),
            ("null_token", "Request with null token value"),
            ("wrong_audience", "Request with JWT for wrong audience"),
        ];

        let mut results = Vec::new();
        for service in &self.services {
            for method in &service.methods {
                for (token_desc, _description) in &token_scenarios {
                    results.push(GrpcAuthTestResult {
                        method_path: method.full_path.clone(),
                        token_description: token_desc.to_string(),
                        result: GrpcAuthResult::Denied,
                    });
                }
            }
        }
        results
    }

    pub fn generate_metadata_injection_payloads(&self) -> Vec<MetadataInjectionPayload> {
        vec![
            MetadataInjectionPayload {
                key: "x-custom-header".to_string(),
                value: "value\r\nInjected-Header: malicious".to_string(),
                attack_type: MetadataAttackType::HeaderInjection,
                description: "CRLF injection in gRPC metadata value".to_string(),
            },
            MetadataInjectionPayload {
                key: "x-forwarded-for".to_string(),
                value: "127.0.0.1".to_string(),
                attack_type: MetadataAttackType::HeaderInjection,
                description: "IP spoofing via x-forwarded-for metadata".to_string(),
            },
            MetadataInjectionPayload {
                key: "x-file-path".to_string(),
                value: "../../../../etc/passwd".to_string(),
                attack_type: MetadataAttackType::PathTraversal,
                description: "Path traversal in metadata used for file operations".to_string(),
            },
            MetadataInjectionPayload {
                key: "x-request-id".to_string(),
                value: "' OR 1=1 --".to_string(),
                attack_type: MetadataAttackType::SqlInjection,
                description: "SQL injection in metadata logged to database".to_string(),
            },
            MetadataInjectionPayload {
                key: "x-trace-id".to_string(),
                value: "$(whoami)".to_string(),
                attack_type: MetadataAttackType::CommandInjection,
                description: "Command injection in metadata processed by shell".to_string(),
            },
            MetadataInjectionPayload {
                key: "x-data".to_string(),
                value: "A".repeat(1_048_576),
                attack_type: MetadataAttackType::SizeAbuse,
                description: "1MB metadata value to test size limits".to_string(),
            },
            MetadataInjectionPayload {
                key: "x-user-id".to_string(),
                value: "admin\x00ignored".to_string(),
                attack_type: MetadataAttackType::NullByte,
                description: "Null byte injection to truncate metadata processing".to_string(),
            },
        ]
    }

    pub fn generate_message_size_tests(&self) -> Vec<MessageSizeTestCase> {
        let mut tests = Vec::new();

        for service in &self.services {
            for method in &service.methods {
                tests.push(MessageSizeTestCase {
                    description: "Normal-sized message baseline".to_string(),
                    target_method: method.full_path.clone(),
                    size_bytes: 1024,
                    nested_depth: 1,
                    repeated_count: 1,
                });
                tests.push(MessageSizeTestCase {
                    description: "4MB message — default gRPC max".to_string(),
                    target_method: method.full_path.clone(),
                    size_bytes: 4 * 1024 * 1024,
                    nested_depth: 1,
                    repeated_count: 1,
                });
                tests.push(MessageSizeTestCase {
                    description: "16MB oversized message".to_string(),
                    target_method: method.full_path.clone(),
                    size_bytes: 16 * 1024 * 1024,
                    nested_depth: 1,
                    repeated_count: 1,
                });
                tests.push(MessageSizeTestCase {
                    description: "Deeply nested protobuf (100 levels)".to_string(),
                    target_method: method.full_path.clone(),
                    size_bytes: 4096,
                    nested_depth: 100,
                    repeated_count: 1,
                });
                tests.push(MessageSizeTestCase {
                    description: "Many repeated fields (100k entries)".to_string(),
                    target_method: method.full_path.clone(),
                    size_bytes: 8192,
                    nested_depth: 1,
                    repeated_count: 100_000,
                });
            }
        }

        tests
    }

    pub fn generate_stream_abuse_tests(&self) -> Vec<StreamAbuseTestCase> {
        let mut tests = Vec::new();

        for service in &self.services {
            for method in &service.methods {
                let stream_type = method.stream_type();
                match stream_type {
                    GrpcStreamType::Unary => {}
                    GrpcStreamType::ClientStreaming | GrpcStreamType::Bidirectional => {
                        tests.push(StreamAbuseTestCase {
                            description: "Rapid message flood on client stream".to_string(),
                            target_method: method.full_path.clone(),
                            stream_type: stream_type.clone(),
                            abuse_type: StreamAbuseType::RapidMessages,
                        });
                        tests.push(StreamAbuseTestCase {
                            description: "Slow-loris: send bytes very slowly to hold connection"
                                .to_string(),
                            target_method: method.full_path.clone(),
                            stream_type: stream_type.clone(),
                            abuse_type: StreamAbuseType::SlowLoris,
                        });
                        tests.push(StreamAbuseTestCase {
                            description: "Never-ending stream without half-close".to_string(),
                            target_method: method.full_path.clone(),
                            stream_type: stream_type.clone(),
                            abuse_type: StreamAbuseType::InfiniteStream,
                        });
                        tests.push(StreamAbuseTestCase {
                            description: "Oversized message in stream".to_string(),
                            target_method: method.full_path.clone(),
                            stream_type: stream_type.clone(),
                            abuse_type: StreamAbuseType::OversizedMessage,
                        });
                    }
                    GrpcStreamType::ServerStreaming => {
                        tests.push(StreamAbuseTestCase {
                            description: "Immediate half-close after opening server stream"
                                .to_string(),
                            target_method: method.full_path.clone(),
                            stream_type: stream_type.clone(),
                            abuse_type: StreamAbuseType::HalfClose,
                        });
                        tests.push(StreamAbuseTestCase {
                            description: "Rapid cancel and reconnect flood".to_string(),
                            target_method: method.full_path.clone(),
                            stream_type: stream_type.clone(),
                            abuse_type: StreamAbuseType::CancelFlood,
                        });
                    }
                }
            }
        }

        tests
    }

    pub fn analyze_error_message(
        &self,
        method_path: &str,
        status_code: i32,
        message: &str,
    ) -> Option<ErrorMessageFinding> {
        let mut leaked = Vec::new();

        let stack_patterns = [
            "at ",
            "Traceback",
            "goroutine",
            "panic:",
            "Exception in",
            "  File \"",
            "NullPointerException",
        ];
        if stack_patterns.iter().any(|p| message.contains(p)) {
            leaked.push(LeakedInfoType::StackTrace);
        }

        let path_patterns = [
            "/home/",
            "/var/",
            "/usr/",
            "/opt/",
            "/srv/",
            "C:\\",
            "\\Users\\",
        ];
        if path_patterns.iter().any(|p| message.contains(p)) {
            leaked.push(LeakedInfoType::InternalPath);
        }

        let db_patterns = [
            "SQLSTATE",
            "mysql",
            "postgres",
            "sqlite",
            "ORA-",
            "MongoDB",
            "redis://",
            "connection refused",
            "table ",
            "column ",
        ];
        if db_patterns
            .iter()
            .any(|p| message.to_lowercase().contains(&p.to_lowercase()))
        {
            leaked.push(LeakedInfoType::DatabaseInfo);
        }

        let version_re_patterns = [
            "v1.",
            "v2.",
            "version ",
            "grpc-go/",
            "grpc-node/",
            "grpc-python/",
        ];
        if version_re_patterns
            .iter()
            .any(|p| message.to_lowercase().contains(&p.to_lowercase()))
        {
            leaked.push(LeakedInfoType::VersionInfo);
        }

        let ip_pattern_fragments = ["10.", "172.", "192.168.", "fd", "fe80:"];
        if ip_pattern_fragments
            .iter()
            .any(|p| message.contains(p) && message.len() < 500)
        {
            leaked.push(LeakedInfoType::InternalIp);
        }

        let config_patterns = [
            "config",
            "secret",
            "password",
            "credential",
            "api_key",
            "token=",
        ];
        if config_patterns
            .iter()
            .any(|p| message.to_lowercase().contains(p))
        {
            leaked.push(LeakedInfoType::ConfigDetail);
        }

        if leaked.is_empty() {
            return None;
        }

        Some(ErrorMessageFinding {
            method_path: method_path.to_string(),
            grpc_status_code: status_code,
            message: message.to_string(),
            leaked_info: leaked,
        })
    }

    pub fn generate_report(&self) -> GrpcSecurityReport {
        GrpcSecurityReport {
            services: self.services.clone(),
            reflection_enabled: self.reflection_enabled,
            auth_test_results: self.generate_auth_test_plan(),
            metadata_payloads: self.generate_metadata_injection_payloads(),
            message_size_tests: self.generate_message_size_tests(),
            stream_abuse_tests: self.generate_stream_abuse_tests(),
            error_findings: Vec::new(),
        }
    }
}

impl Default for GrpcSecurityTester {
    fn default() -> Self {
        Self::new()
    }
}
