#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use aegis_protocol::finding::VulnerabilityClass;

    use crate::mutator::MutationOrigin;
    use crate::streaming_fuzzer::{
        MessageDirection, StreamAnomalyType, StreamFuzzError, StreamFuzzTarget, StreamMessage,
        StreamMessageType, StreamProtocol, analyze_stream_messages, build_stream_fuzz_result,
        generate_sse_probe_urls, generate_ws_payloads, score_stream_anomaly,
        validate_stream_target,
    };

    fn make_message(
        seq: u64,
        direction: MessageDirection,
        payload: &str,
        msg_type: StreamMessageType,
    ) -> StreamMessage {
        StreamMessage {
            sequence: seq,
            direction,
            payload: payload.to_string(),
            timestamp_ms: seq * 100,
            message_type: msg_type,
        }
    }

    fn make_target() -> StreamFuzzTarget {
        StreamFuzzTarget {
            endpoint: "ws://localhost:8080/ws".to_string(),
            protocol: StreamProtocol::WebSocket,
            vulnerability_class: VulnerabilityClass::CrossSiteScripting,
            priority_score: 5.0,
            handshake_headers: vec![],
        }
    }

    #[test]
    fn stream_protocol_display() {
        assert_eq!(StreamProtocol::WebSocket.to_string(), "WebSocket");
        assert_eq!(
            StreamProtocol::ServerSentEvents.to_string(),
            "Server-Sent Events"
        );
    }

    #[test]
    fn stream_protocol_equality() {
        assert_eq!(StreamProtocol::WebSocket, StreamProtocol::WebSocket);
        assert_ne!(StreamProtocol::WebSocket, StreamProtocol::ServerSentEvents);
    }

    #[test]
    fn stream_message_type_variants() {
        let types = [
            StreamMessageType::Text,
            StreamMessageType::Binary,
            StreamMessageType::Ping,
            StreamMessageType::Pong,
            StreamMessageType::Event,
        ];
        assert_eq!(types.len(), 5);
    }

    #[test]
    fn message_direction_variants() {
        assert_ne!(MessageDirection::Sent, MessageDirection::Received);
        assert_eq!(MessageDirection::Sent, MessageDirection::Sent);
    }

    #[test]
    fn validate_stream_target_ws_localhost() {
        let result = validate_stream_target("ws://localhost:8080/ws");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), StreamProtocol::WebSocket);
    }

    #[test]
    fn validate_stream_target_http_localhost_is_sse() {
        let result = validate_stream_target("http://localhost:3000/events");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), StreamProtocol::ServerSentEvents);
    }

    #[test]
    fn validate_stream_target_non_localhost_rejected() {
        let result = validate_stream_target("ws://example.com:8080/ws");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("not localhost"));
    }

    #[test]
    fn validate_stream_target_invalid_url_rejected() {
        let result = validate_stream_target("not a valid url at all");
        assert!(result.is_err());
    }

    #[test]
    fn validate_stream_target_wss_is_websocket() {
        let result = validate_stream_target("wss://localhost:443/secure");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), StreamProtocol::WebSocket);
    }

    #[test]
    fn validate_stream_target_https_is_sse() {
        let result = validate_stream_target("https://127.0.0.1:8443/stream");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), StreamProtocol::ServerSentEvents);
    }

    #[test]
    fn validate_stream_target_ipv6_localhost() {
        let result = validate_stream_target("ws://[::1]:8080/ws");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), StreamProtocol::WebSocket);
    }

    #[test]
    fn validate_stream_target_127_0_0_1() {
        let result = validate_stream_target("http://127.0.0.1:9000/sse");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), StreamProtocol::ServerSentEvents);
    }

    #[test]
    fn validate_stream_target_unsupported_scheme() {
        let result = validate_stream_target("ftp://localhost/files");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("unsupported scheme"));
    }

    #[test]
    fn generate_ws_payloads_xss_produces_payloads() {
        let payloads = generate_ws_payloads(VulnerabilityClass::CrossSiteScripting, 10);
        assert!(!payloads.is_empty());
        let has_script = payloads.iter().any(|p| p.payload.contains("script"));
        assert!(has_script);
    }

    #[test]
    fn generate_ws_payloads_sqli_produces_payloads() {
        let payloads = generate_ws_payloads(VulnerabilityClass::SqlInjection, 10);
        assert!(!payloads.is_empty());
        let has_sql = payloads.iter().any(|p| p.payload.contains("OR 1=1"));
        assert!(has_sql);
    }

    #[test]
    fn generate_ws_payloads_respects_count_limit() {
        let payloads = generate_ws_payloads(VulnerabilityClass::CrossSiteScripting, 2);
        assert_eq!(payloads.len(), 2);
    }

    #[test]
    fn generate_ws_payloads_tagged_with_template_origin() {
        let payloads = generate_ws_payloads(VulnerabilityClass::SqlInjection, 5);
        assert!(
            payloads
                .iter()
                .all(|p| p.origin == MutationOrigin::Template)
        );
    }

    #[test]
    fn generate_ws_payloads_includes_oversized_message() {
        let payloads = generate_ws_payloads(VulnerabilityClass::CrossSiteScripting, 20);
        let has_large = payloads.iter().any(|p| p.payload.len() > 64000);
        assert!(has_large);
    }

    #[test]
    fn generate_ws_payloads_command_injection() {
        let payloads = generate_ws_payloads(VulnerabilityClass::CommandInjection, 10);
        let has_whoami = payloads.iter().any(|p| p.payload.contains("whoami"));
        assert!(has_whoami);
    }

    #[test]
    fn generate_ws_payloads_zero_count_returns_empty() {
        let payloads = generate_ws_payloads(VulnerabilityClass::SqlInjection, 0);
        assert!(payloads.is_empty());
    }

    #[test]
    fn generate_sse_probe_urls_produces_path_variations() {
        let urls = generate_sse_probe_urls("http://localhost:3000");
        assert!(urls.iter().any(|u| u.ends_with("/events")));
        assert!(urls.iter().any(|u| u.ends_with("/stream")));
        assert!(urls.iter().any(|u| u.ends_with("/sse")));
        assert!(urls.iter().any(|u| u.ends_with("/subscribe")));
        assert!(urls.iter().any(|u| u.ends_with("/feed")));
    }

    #[test]
    fn generate_sse_probe_urls_includes_query_parameter_injection() {
        let urls = generate_sse_probe_urls("http://localhost:3000");
        let has_event_param = urls.iter().any(|u| u.contains("?event="));
        let has_channel_param = urls.iter().any(|u| u.contains("?channel="));
        assert!(has_event_param);
        assert!(has_channel_param);
    }

    #[test]
    fn generate_sse_probe_urls_preserves_base_url() {
        let urls = generate_sse_probe_urls("http://localhost:8080/api");
        assert!(
            urls.iter()
                .all(|u| u.starts_with("http://localhost:8080/api"))
        );
    }

    #[test]
    fn generate_sse_probe_urls_strips_trailing_slash() {
        let urls = generate_sse_probe_urls("http://localhost:3000/");
        assert!(urls.iter().any(|u| u.contains("localhost:3000/events")));
        assert!(!urls.iter().any(|u| u.contains("localhost:3000//events")));
    }

    #[test]
    fn analyze_stream_messages_detects_reflection() {
        let messages = vec![
            make_message(
                1,
                MessageDirection::Sent,
                "test_payload",
                StreamMessageType::Text,
            ),
            make_message(
                2,
                MessageDirection::Received,
                "echo: test_payload here",
                StreamMessageType::Text,
            ),
        ];
        let anomalies = analyze_stream_messages(&messages, "test_payload");
        assert!(anomalies.contains(&StreamAnomalyType::ReflectionDetected));
    }

    #[test]
    fn analyze_stream_messages_detects_error_message() {
        let messages = vec![make_message(
            1,
            MessageDirection::Received,
            "Internal Server Error occurred",
            StreamMessageType::Text,
        )];
        let anomalies = analyze_stream_messages(&messages, "payload");
        assert!(anomalies.contains(&StreamAnomalyType::ErrorMessage));
    }

    #[test]
    fn analyze_stream_messages_detects_information_leak() {
        let messages = vec![make_message(
            1,
            MessageDirection::Received,
            "file not found: /usr/local/app/config.yml",
            StreamMessageType::Text,
        )];
        let anomalies = analyze_stream_messages(&messages, "payload");
        assert!(anomalies.contains(&StreamAnomalyType::InformationLeak));
    }

    #[test]
    fn analyze_stream_messages_detects_unexpected_close() {
        let messages = vec![
            make_message(1, MessageDirection::Sent, "data", StreamMessageType::Text),
            make_message(2, MessageDirection::Sent, "ping", StreamMessageType::Ping),
        ];
        let anomalies = analyze_stream_messages(&messages, "data");
        assert!(anomalies.contains(&StreamAnomalyType::UnexpectedClose));
    }

    #[test]
    fn analyze_stream_messages_no_anomalies_for_clean_messages() {
        let messages = vec![
            make_message(1, MessageDirection::Sent, "hello", StreamMessageType::Text),
            make_message(
                2,
                MessageDirection::Received,
                "world",
                StreamMessageType::Text,
            ),
        ];
        let anomalies = analyze_stream_messages(&messages, "hello");
        assert!(anomalies.is_empty());
    }

    #[test]
    fn analyze_stream_messages_short_payload_no_reflection() {
        let messages = vec![make_message(
            1,
            MessageDirection::Received,
            "ab is here",
            StreamMessageType::Text,
        )];
        let anomalies = analyze_stream_messages(&messages, "ab");
        assert!(!anomalies.contains(&StreamAnomalyType::ReflectionDetected));
    }

    #[test]
    fn analyze_stream_messages_detects_protocol_violation() {
        let messages = vec![
            make_message(
                1,
                MessageDirection::Sent,
                "text data",
                StreamMessageType::Text,
            ),
            make_message(
                2,
                MessageDirection::Received,
                "binary response",
                StreamMessageType::Binary,
            ),
        ];
        let anomalies = analyze_stream_messages(&messages, "text data");
        assert!(anomalies.contains(&StreamAnomalyType::ProtocolViolation));
    }

    #[test]
    fn score_stream_anomaly_reflection() {
        assert!(
            (score_stream_anomaly(&StreamAnomalyType::ReflectionDetected) - 0.9).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn score_stream_anomaly_information_leak() {
        assert!(
            (score_stream_anomaly(&StreamAnomalyType::InformationLeak) - 0.85).abs() < f64::EPSILON
        );
    }

    #[test]
    fn score_stream_anomaly_error_message() {
        assert!(
            (score_stream_anomaly(&StreamAnomalyType::ErrorMessage) - 0.7).abs() < f64::EPSILON
        );
    }

    #[test]
    fn score_stream_anomaly_unexpected_close() {
        assert!(
            (score_stream_anomaly(&StreamAnomalyType::UnexpectedClose) - 0.6).abs() < f64::EPSILON
        );
    }

    #[test]
    fn score_stream_anomaly_timing() {
        assert!(
            (score_stream_anomaly(&StreamAnomalyType::TimingAnomaly) - 0.5).abs() < f64::EPSILON
        );
    }

    #[test]
    fn score_stream_anomaly_protocol_violation() {
        assert!(
            (score_stream_anomaly(&StreamAnomalyType::ProtocolViolation) - 0.4).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn build_stream_fuzz_result_counts_sent_received() {
        let target = make_target();
        let messages = vec![
            make_message(1, MessageDirection::Sent, "a", StreamMessageType::Text),
            make_message(2, MessageDirection::Sent, "b", StreamMessageType::Text),
            make_message(3, MessageDirection::Received, "c", StreamMessageType::Text),
        ];
        let result = build_stream_fuzz_result(&target, &messages, vec![], 1000);
        assert_eq!(result.messages_sent, 2);
        assert_eq!(result.messages_received, 1);
        assert_eq!(result.connection_duration_ms, 1000);
        assert_eq!(result.protocol, StreamProtocol::WebSocket);
    }

    #[test]
    fn build_stream_fuzz_result_empty_messages() {
        let target = make_target();
        let result = build_stream_fuzz_result(&target, &[], vec![], 500);
        assert_eq!(result.messages_sent, 0);
        assert_eq!(result.messages_received, 0);
    }

    #[test]
    fn stream_fuzz_error_display_connection_failed() {
        let err = StreamFuzzError::ConnectionFailed("refused".to_string());
        assert_eq!(err.to_string(), "connection failed: refused");
    }

    #[test]
    fn stream_fuzz_error_display_handshake_failed() {
        let err = StreamFuzzError::HandshakeFailed("401".to_string());
        assert_eq!(err.to_string(), "handshake failed: 401");
    }

    #[test]
    fn stream_fuzz_error_display_target_not_allowed() {
        let err = StreamFuzzError::TargetNotAllowed("remote host".to_string());
        assert_eq!(err.to_string(), "target not allowed: remote host");
    }

    #[test]
    fn stream_fuzz_error_display_timeout() {
        let err = StreamFuzzError::Timeout("30s exceeded".to_string());
        assert_eq!(err.to_string(), "timeout: 30s exceeded");
    }

    #[test]
    fn stream_fuzz_error_display_protocol_error() {
        let err = StreamFuzzError::ProtocolError("bad frame".to_string());
        assert_eq!(err.to_string(), "protocol error: bad frame");
    }

    #[test]
    fn stream_anomaly_type_equality_and_hash() {
        let a = StreamAnomalyType::ReflectionDetected;
        let b = StreamAnomalyType::ReflectionDetected;
        let c = StreamAnomalyType::ErrorMessage;
        assert_eq!(a, b);
        assert_ne!(a, c);

        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        set.insert(c);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn stream_anomaly_type_display() {
        assert_eq!(
            StreamAnomalyType::ReflectionDetected.to_string(),
            "Reflection Detected"
        );
        assert_eq!(
            StreamAnomalyType::UnexpectedClose.to_string(),
            "Unexpected Close"
        );
    }

    #[test]
    fn message_direction_display() {
        assert_eq!(MessageDirection::Sent.to_string(), "Sent");
        assert_eq!(MessageDirection::Received.to_string(), "Received");
    }

    #[test]
    fn stream_message_type_display() {
        assert_eq!(StreamMessageType::Text.to_string(), "Text");
        assert_eq!(StreamMessageType::Binary.to_string(), "Binary");
        assert_eq!(StreamMessageType::Event.to_string(), "Event");
    }

    #[test]
    fn analyze_stream_messages_java_stack_trace_leak() {
        let messages = vec![make_message(
            1,
            MessageDirection::Received,
            "at java.lang.NullPointerException",
            StreamMessageType::Text,
        )];
        let anomalies = analyze_stream_messages(&messages, "payload");
        assert!(anomalies.contains(&StreamAnomalyType::InformationLeak));
    }

    #[test]
    fn analyze_stream_messages_sqlstate_leak() {
        let messages = vec![make_message(
            1,
            MessageDirection::Received,
            "SQLSTATE[42000]: Syntax error",
            StreamMessageType::Text,
        )];
        let anomalies = analyze_stream_messages(&messages, "payload");
        assert!(anomalies.contains(&StreamAnomalyType::InformationLeak));
    }

    #[test]
    fn analyze_stream_messages_exception_keyword() {
        let messages = vec![make_message(
            1,
            MessageDirection::Received,
            "Unhandled Exception in handler",
            StreamMessageType::Text,
        )];
        let anomalies = analyze_stream_messages(&messages, "payload");
        assert!(anomalies.contains(&StreamAnomalyType::ErrorMessage));
    }

    #[test]
    fn generate_ws_payloads_includes_null_byte_payload() {
        let payloads = generate_ws_payloads(VulnerabilityClass::CrossSiteScripting, 20);
        let has_null = payloads.iter().any(|p| p.payload.contains('\0'));
        assert!(has_null);
    }
}
