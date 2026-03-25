#[cfg(test)]
mod tests {
    use crate::grpc_security::{
        GrpcAuthResult, GrpcMethod, GrpcSecurityTester, GrpcService, GrpcStreamType,
        LeakedInfoType, MetadataAttackType, StreamAbuseType,
    };

    fn sample_service() -> GrpcService {
        GrpcService {
            name: "UserService".to_string(),
            methods: vec![
                GrpcMethod {
                    name: "GetUser".to_string(),
                    full_path: "/user.UserService/GetUser".to_string(),
                    client_streaming: false,
                    server_streaming: false,
                    input_type: "GetUserRequest".to_string(),
                    output_type: "GetUserResponse".to_string(),
                },
                GrpcMethod {
                    name: "StreamUpdates".to_string(),
                    full_path: "/user.UserService/StreamUpdates".to_string(),
                    client_streaming: false,
                    server_streaming: true,
                    input_type: "StreamRequest".to_string(),
                    output_type: "UpdateEvent".to_string(),
                },
                GrpcMethod {
                    name: "Upload".to_string(),
                    full_path: "/user.UserService/Upload".to_string(),
                    client_streaming: true,
                    server_streaming: false,
                    input_type: "UploadChunk".to_string(),
                    output_type: "UploadResult".to_string(),
                },
                GrpcMethod {
                    name: "Chat".to_string(),
                    full_path: "/user.UserService/Chat".to_string(),
                    client_streaming: true,
                    server_streaming: true,
                    input_type: "ChatMessage".to_string(),
                    output_type: "ChatMessage".to_string(),
                },
            ],
        }
    }

    fn build_tester() -> GrpcSecurityTester {
        let mut tester = GrpcSecurityTester::new();
        tester.set_reflection_enabled(true);
        tester.add_service(sample_service());
        tester
    }

    #[test]
    fn new_tester_is_empty() {
        let tester = GrpcSecurityTester::new();
        assert!(tester.services().is_empty());
        let report = tester.generate_report();
        assert!(!report.reflection_enabled);
        assert!(report.services.is_empty());
    }

    #[test]
    fn add_service_and_enumerate() {
        let tester = build_tester();
        assert_eq!(tester.services().len(), 1);
        assert_eq!(tester.services()[0].methods.len(), 4);
    }

    #[test]
    fn stream_type_classification() {
        let service = sample_service();

        let get_user = &service.methods[0];
        assert_eq!(get_user.stream_type(), GrpcStreamType::Unary);

        let stream = &service.methods[1];
        assert_eq!(stream.stream_type(), GrpcStreamType::ServerStreaming);

        let upload = &service.methods[2];
        assert_eq!(upload.stream_type(), GrpcStreamType::ClientStreaming);

        let chat = &service.methods[3];
        assert_eq!(chat.stream_type(), GrpcStreamType::Bidirectional);
    }

    #[test]
    fn auth_test_plan_covers_all_methods() {
        let tester = build_tester();
        let auth_tests = tester.generate_auth_test_plan();

        let method_count = 4;
        let token_scenario_count = 6;
        assert_eq!(auth_tests.len(), method_count * token_scenario_count);

        let get_user_tests: Vec<_> = auth_tests
            .iter()
            .filter(|t| t.method_path == "/user.UserService/GetUser")
            .collect();
        assert_eq!(get_user_tests.len(), token_scenario_count);

        let no_token = get_user_tests
            .iter()
            .find(|t| t.token_description == "no_token")
            .unwrap();
        assert_eq!(no_token.result, GrpcAuthResult::Denied);
    }

    #[test]
    fn metadata_injection_payloads_coverage() {
        let tester = build_tester();
        let payloads = tester.generate_metadata_injection_payloads();

        assert!(payloads.len() >= 7);

        let attack_types: Vec<_> = payloads.iter().map(|p| &p.attack_type).collect();
        assert!(attack_types.contains(&&MetadataAttackType::HeaderInjection));
        assert!(attack_types.contains(&&MetadataAttackType::PathTraversal));
        assert!(attack_types.contains(&&MetadataAttackType::SqlInjection));
        assert!(attack_types.contains(&&MetadataAttackType::CommandInjection));
        assert!(attack_types.contains(&&MetadataAttackType::SizeAbuse));
        assert!(attack_types.contains(&&MetadataAttackType::NullByte));

        let crlf = payloads
            .iter()
            .find(|p| {
                p.attack_type == MetadataAttackType::HeaderInjection && p.value.contains("\r\n")
            })
            .unwrap();
        assert!(crlf.value.contains("Injected-Header"));

        let size_payload = payloads
            .iter()
            .find(|p| p.attack_type == MetadataAttackType::SizeAbuse)
            .unwrap();
        assert!(size_payload.value.len() >= 1_000_000);
    }

    #[test]
    fn message_size_tests_per_method() {
        let tester = build_tester();
        let size_tests = tester.generate_message_size_tests();

        let per_method = 5;
        assert_eq!(size_tests.len(), 4 * per_method);

        let oversized: Vec<_> = size_tests
            .iter()
            .filter(|t| t.size_bytes > 4 * 1024 * 1024)
            .collect();
        assert_eq!(oversized.len(), 4);

        let deep_nested: Vec<_> = size_tests
            .iter()
            .filter(|t| t.nested_depth >= 100)
            .collect();
        assert_eq!(deep_nested.len(), 4);
    }

    #[test]
    fn stream_abuse_tests_only_for_streaming_methods() {
        let tester = build_tester();
        let abuse_tests = tester.generate_stream_abuse_tests();

        let unary_tests: Vec<_> = abuse_tests
            .iter()
            .filter(|t| t.target_method.contains("GetUser"))
            .collect();
        assert!(
            unary_tests.is_empty(),
            "Unary methods should have no stream abuse tests"
        );

        let server_stream_tests: Vec<_> = abuse_tests
            .iter()
            .filter(|t| t.target_method.contains("StreamUpdates"))
            .collect();
        assert!(server_stream_tests.len() >= 2);
        let server_types: Vec<_> = server_stream_tests.iter().map(|t| &t.abuse_type).collect();
        assert!(server_types.contains(&&StreamAbuseType::HalfClose));
        assert!(server_types.contains(&&StreamAbuseType::CancelFlood));

        let client_stream_tests: Vec<_> = abuse_tests
            .iter()
            .filter(|t| t.target_method.contains("Upload"))
            .collect();
        assert!(client_stream_tests.len() >= 4);
        let client_types: Vec<_> = client_stream_tests.iter().map(|t| &t.abuse_type).collect();
        assert!(client_types.contains(&&StreamAbuseType::RapidMessages));
        assert!(client_types.contains(&&StreamAbuseType::SlowLoris));

        let bidi_tests: Vec<_> = abuse_tests
            .iter()
            .filter(|t| t.target_method.contains("Chat"))
            .collect();
        assert!(bidi_tests.len() >= 4);
    }

    #[test]
    fn error_message_analysis_detects_stack_trace() {
        let tester = build_tester();
        let finding = tester
            .analyze_error_message(
                "/user.UserService/GetUser",
                13,
                "panic: runtime error: index out of range\ngoroutine 1 [running]:\nmain.main()",
            )
            .unwrap();

        assert!(finding.leaked_info.contains(&LeakedInfoType::StackTrace));
        assert_eq!(finding.grpc_status_code, 13);
    }

    #[test]
    fn error_message_analysis_detects_internal_path() {
        let tester = build_tester();
        let finding = tester
            .analyze_error_message(
                "/user.UserService/GetUser",
                2,
                "failed to open /var/data/config.yaml: permission denied",
            )
            .unwrap();

        assert!(finding.leaked_info.contains(&LeakedInfoType::InternalPath));
    }

    #[test]
    fn error_message_analysis_detects_database_info() {
        let tester = build_tester();
        let finding = tester
            .analyze_error_message(
                "/user.UserService/GetUser",
                13,
                "SQLSTATE[42S02]: table users not found in postgres",
            )
            .unwrap();

        assert!(finding.leaked_info.contains(&LeakedInfoType::DatabaseInfo));
    }

    #[test]
    fn error_message_analysis_detects_version_info() {
        let tester = build_tester();
        let finding = tester
            .analyze_error_message(
                "/user.UserService/GetUser",
                13,
                "grpc-go/v1.58.0: transport closing",
            )
            .unwrap();

        assert!(finding.leaked_info.contains(&LeakedInfoType::VersionInfo));
    }

    #[test]
    fn error_message_analysis_clean_message_returns_none() {
        let tester = build_tester();
        let result = tester.analyze_error_message("/user.UserService/GetUser", 5, "user not found");

        assert!(result.is_none());
    }

    #[test]
    fn error_message_detects_config_leak() {
        let tester = build_tester();
        let finding = tester
            .analyze_error_message(
                "/user.UserService/GetUser",
                13,
                "invalid credential for service account, check config",
            )
            .unwrap();

        assert!(finding.leaked_info.contains(&LeakedInfoType::ConfigDetail));
    }

    #[test]
    fn full_report_structure() {
        let tester = build_tester();
        let report = tester.generate_report();

        assert!(report.reflection_enabled);
        assert_eq!(report.services.len(), 1);
        assert!(!report.auth_test_results.is_empty());
        assert!(!report.metadata_payloads.is_empty());
        assert!(!report.message_size_tests.is_empty());
        assert!(!report.stream_abuse_tests.is_empty());
        assert!(report.error_findings.is_empty());
    }

    #[test]
    fn default_tester() {
        let tester = GrpcSecurityTester::default();
        assert!(tester.services().is_empty());
    }
}
