use std::collections::HashMap;

use super::data_sinkhole::*;

#[test]
fn test_sinkhole_service_type_display() {
    assert_eq!(
        SinkholeServiceType::Elasticsearch.to_string(),
        "Elasticsearch"
    );
    assert_eq!(SinkholeServiceType::Redis.to_string(), "Redis");
    assert_eq!(
        SinkholeServiceType::Firebase.to_string(),
        "Firebase Realtime DB"
    );
    assert_eq!(SinkholeServiceType::S3Bucket.to_string(), "AWS S3 Bucket");
    assert_eq!(
        SinkholeServiceType::KubernetesDashboard.to_string(),
        "Kubernetes Dashboard"
    );
}

#[test]
fn test_data_sensitivity_ordering() {
    assert!(DataSensitivity::Public < DataSensitivity::Internal);
    assert!(DataSensitivity::Internal < DataSensitivity::Confidential);
    assert!(DataSensitivity::Confidential < DataSensitivity::Restricted);
    assert!(DataSensitivity::Restricted < DataSensitivity::Critical);
}

#[test]
fn test_auth_state_display() {
    assert_eq!(AuthState::NoAuth.to_string(), "No Authentication");
    assert_eq!(
        AuthState::DefaultCredentials.to_string(),
        "Default Credentials"
    );
    assert_eq!(
        AuthState::AnonymousAccess.to_string(),
        "Anonymous Access Enabled"
    );
}

#[test]
fn test_wire_protocol_display() {
    assert_eq!(WireProtocol::RedisResp.to_string(), "Redis RESP");
    assert_eq!(WireProtocol::MemcachedAscii.to_string(), "Memcached ASCII");
    assert_eq!(WireProtocol::MongoWire.to_string(), "MongoDB Wire");
}

#[test]
fn test_data_indicator_type_display() {
    assert_eq!(DataIndicatorType::Credentials.to_string(), "Credentials");
    assert_eq!(
        DataIndicatorType::PersonalInfo.to_string(),
        "Personal Information"
    );
    assert_eq!(
        DataIndicatorType::SessionTokens.to_string(),
        "Session Tokens"
    );
}

#[test]
fn test_default_config() {
    let config = SinkholeDetectorConfig::default();
    assert!(config.scan_databases);
    assert!(config.scan_dashboards);
    assert!(config.scan_caches);
    assert!(config.scan_cloud_storage);
    assert!(config.scan_ci_tools);
    assert!(config.classify_sensitivity);
}

#[test]
fn test_config_builder() {
    let config = SinkholeDetectorConfig::default()
        .with_scan_databases(false)
        .with_scan_dashboards(false)
        .with_max_response_bytes(512);
    assert!(!config.scan_databases);
    assert!(!config.scan_dashboards);
    assert_eq!(config.max_response_bytes, 512);
}

#[test]
fn test_generate_probes_all_enabled() {
    let detector = DataSinkholeDetector::new(SinkholeDetectorConfig::default());
    let probes = detector.generate_probes();
    assert!(
        probes.len() >= 10,
        "Should generate probes for many services"
    );

    let service_types: Vec<SinkholeServiceType> = probes.iter().map(|p| p.service_type).collect();
    assert!(service_types.contains(&SinkholeServiceType::Elasticsearch));
    assert!(service_types.contains(&SinkholeServiceType::Redis));
    assert!(service_types.contains(&SinkholeServiceType::Grafana));
    assert!(service_types.contains(&SinkholeServiceType::Jenkins));
    assert!(service_types.contains(&SinkholeServiceType::S3Bucket));
}

#[test]
fn test_generate_probes_databases_disabled() {
    let config = SinkholeDetectorConfig::default().with_scan_databases(false);
    let detector = DataSinkholeDetector::new(config);
    let probes = detector.generate_probes();
    let has_es = probes
        .iter()
        .any(|p| p.service_type == SinkholeServiceType::Elasticsearch);
    assert!(
        !has_es,
        "Should not include Elasticsearch when databases disabled"
    );
}

#[test]
fn test_classify_sensitivity_credentials() {
    let detector = DataSinkholeDetector::new(SinkholeDetectorConfig::default());
    let response = r#"{"config": {"password": "s3cret", "api_key": "abc123"}}"#;
    let indicators = detector.classify_response_sensitivity(response);
    assert!(indicators
        .iter()
        .any(|i| i.indicator_type == DataIndicatorType::Credentials));
    assert!(indicators
        .iter()
        .any(|i| i.indicator_type == DataIndicatorType::ApiKeys));
    let cred = indicators
        .iter()
        .find(|i| i.indicator_type == DataIndicatorType::Credentials)
        .unwrap();
    assert_eq!(cred.sensitivity, DataSensitivity::Critical);
}

#[test]
fn test_classify_sensitivity_pii() {
    let detector = DataSinkholeDetector::new(SinkholeDetectorConfig::default());
    let response = r#"{"user": {"email": "test@example.com", "phone": "555-1234"}}"#;
    let indicators = detector.classify_response_sensitivity(response);
    let pii: Vec<_> = indicators
        .iter()
        .filter(|i| i.indicator_type == DataIndicatorType::PersonalInfo)
        .collect();
    assert!(pii.len() >= 2);
}

#[test]
fn test_classify_sensitivity_internal_ips() {
    let detector = DataSinkholeDetector::new(SinkholeDetectorConfig::default());
    let response = r#"{"upstream": "http://10.0.1.50:8080/api", "redis": "192.168.1.10:6379"}"#;
    let indicators = detector.classify_response_sensitivity(response);
    let internal: Vec<_> = indicators
        .iter()
        .filter(|i| i.indicator_type == DataIndicatorType::InternalUrls)
        .collect();
    assert!(internal.len() >= 2);
}

#[test]
fn test_classify_sensitivity_clean_response() {
    let detector = DataSinkholeDetector::new(SinkholeDetectorConfig::default());
    let response = r#"{"status": "green", "cluster_name": "production"}"#;
    let indicators = detector.classify_response_sensitivity(response);
    assert!(indicators.is_empty());
}

#[test]
fn test_classify_auth_state_no_auth() {
    let detector = DataSinkholeDetector::new(SinkholeDetectorConfig::default());
    let state = detector.classify_auth_state(200, r#"{"data": "exposed"}"#, &HashMap::new());
    assert_eq!(state, AuthState::NoAuth);
}

#[test]
fn test_classify_auth_state_requires_auth() {
    let detector = DataSinkholeDetector::new(SinkholeDetectorConfig::default());
    let state = detector.classify_auth_state(401, "Unauthorized", &HashMap::new());
    assert_eq!(state, AuthState::RequiresAuth);
}

#[test]
fn test_classify_auth_state_anonymous() {
    let detector = DataSinkholeDetector::new(SinkholeDetectorConfig::default());
    let state = detector.classify_auth_state(
        200,
        r#"{"auth": "anonymous access enabled"}"#,
        &HashMap::new(),
    );
    assert_eq!(state, AuthState::AnonymousAccess);
}

#[test]
fn test_classify_auth_state_default_creds() {
    let detector = DataSinkholeDetector::new(SinkholeDetectorConfig::default());
    let state = detector.classify_auth_state(
        200,
        "elastic:changeme is the default credential",
        &HashMap::new(),
    );
    assert_eq!(state, AuthState::DefaultCredentials);
}

#[test]
fn test_remediation_elasticsearch_no_auth() {
    let detector = DataSinkholeDetector::new(SinkholeDetectorConfig::default());
    let remediation =
        detector.remediation_for(SinkholeServiceType::Elasticsearch, AuthState::NoAuth);
    assert!(remediation.contains("URGENT"));
    assert!(remediation.contains("X-Pack"));
}

#[test]
fn test_remediation_redis_default_creds() {
    let detector = DataSinkholeDetector::new(SinkholeDetectorConfig::default());
    let remediation =
        detector.remediation_for(SinkholeServiceType::Redis, AuthState::DefaultCredentials);
    assert!(remediation.contains("URGENT"));
    assert!(remediation.contains("requirepass"));
}

#[test]
fn test_remediation_authenticated_service() {
    let detector = DataSinkholeDetector::new(SinkholeDetectorConfig::default());
    let remediation =
        detector.remediation_for(SinkholeServiceType::Grafana, AuthState::RequiresAuth);
    assert!(remediation.contains("OK"));
}

#[test]
fn test_analyze_responses_exposed_elasticsearch() {
    let detector = DataSinkholeDetector::new(SinkholeDetectorConfig::default());
    let responses = vec![ProbeResponse {
        service_type: SinkholeServiceType::Elasticsearch,
        host: "elastic.example.com".to_string(),
        port: 9200,
        protocol: WireProtocol::Http,
        status_code: 200,
        body: r#"{
            "cluster_name": "production",
            "tagline": "You Know, for Search",
            "password": "leaked_password_hash",
            "api_key": "AKIAIOSFODNN7EXAMPLE"
        }"#
        .to_string(),
        headers: HashMap::new(),
        detected_version: Some("7.17.0".to_string()),
    }];

    let result = detector.analyze_responses(&responses);
    assert_eq!(result.detections.len(), 1);
    let det = &result.detections[0];
    assert_eq!(det.service_type, SinkholeServiceType::Elasticsearch);
    assert_eq!(det.auth_state, AuthState::NoAuth);
    assert!(det.data_sensitivity >= DataSensitivity::Restricted);
    assert!(!det.data_indicators.is_empty());
    assert!(!det.remediation.is_empty());
}

#[test]
fn test_analyze_responses_authenticated_skip() {
    let detector = DataSinkholeDetector::new(SinkholeDetectorConfig::default());
    let responses = vec![ProbeResponse {
        service_type: SinkholeServiceType::Grafana,
        host: "grafana.example.com".to_string(),
        port: 3000,
        protocol: WireProtocol::Http,
        status_code: 401,
        body: "Unauthorized".to_string(),
        headers: HashMap::new(),
        detected_version: None,
    }];
    let result = detector.analyze_responses(&responses);
    assert!(
        result.detections.is_empty(),
        "Authenticated services should not be flagged"
    );
}

#[test]
fn test_analyze_responses_multiple_services() {
    let detector = DataSinkholeDetector::new(SinkholeDetectorConfig::default());
    let responses = vec![
        ProbeResponse {
            service_type: SinkholeServiceType::Redis,
            host: "cache.example.com".to_string(),
            port: 6379,
            protocol: WireProtocol::RedisResp,
            status_code: 200,
            body: "redis_version:6.2.6\nconnected_clients:42\ntoken:abc123session".to_string(),
            headers: HashMap::new(),
            detected_version: Some("6.2.6".to_string()),
        },
        ProbeResponse {
            service_type: SinkholeServiceType::Kibana,
            host: "kibana.example.com".to_string(),
            port: 5601,
            protocol: WireProtocol::Http,
            status_code: 200,
            body: r#"{"status": {"overall": "green"}, "kibana": true}"#.to_string(),
            headers: HashMap::new(),
            detected_version: Some("7.17.0".to_string()),
        },
        ProbeResponse {
            service_type: SinkholeServiceType::MongoDb,
            host: "db.example.com".to_string(),
            port: 27017,
            protocol: WireProtocol::MongoWire,
            status_code: 403,
            body: "Forbidden".to_string(),
            headers: HashMap::new(),
            detected_version: None,
        },
    ];

    let result = detector.analyze_responses(&responses);
    assert_eq!(result.detections.len(), 2, "Two open, one denied");
    assert!(result.critical_exposures >= 0);
    assert!(!result.summary.is_empty());
}

#[test]
fn test_empty_responses() {
    let detector = DataSinkholeDetector::new(SinkholeDetectorConfig::default());
    let result = detector.analyze_responses(&[]);
    assert!(result.detections.is_empty());
    assert_eq!(result.probes_sent, 0);
}

#[test]
fn test_firebase_probe_url() {
    let url = DataSinkholeDetector::firebase_probe_url("my-project");
    assert_eq!(url, "https://my-project-default-rtdb.firebaseio.com/.json");
}

#[test]
fn test_s3_probe_url() {
    let url = DataSinkholeDetector::s3_probe_url("my-bucket", "us-east-1");
    assert_eq!(url, "https://my-bucket.s3.us-east-1.amazonaws.com/");
}

#[test]
fn test_gcs_probe_url() {
    let url = DataSinkholeDetector::gcs_probe_url("my-bucket");
    assert_eq!(url, "https://storage.googleapis.com/my-bucket/");
}

#[test]
fn test_probe_has_correct_ports() {
    let detector = DataSinkholeDetector::new(SinkholeDetectorConfig::default());
    let probes = detector.generate_probes();

    let es_probe = probes
        .iter()
        .find(|p| p.service_type == SinkholeServiceType::Elasticsearch)
        .unwrap();
    assert!(es_probe.default_ports.contains(&9200));

    let redis_probe = probes
        .iter()
        .find(|p| p.service_type == SinkholeServiceType::Redis)
        .unwrap();
    assert!(redis_probe.default_ports.contains(&6379));

    let grafana_probe = probes
        .iter()
        .find(|p| p.service_type == SinkholeServiceType::Grafana)
        .unwrap();
    assert!(grafana_probe.default_ports.contains(&3000));
}

#[test]
fn test_anonymous_grafana_exposure() {
    let detector = DataSinkholeDetector::new(SinkholeDetectorConfig::default());
    let responses = vec![ProbeResponse {
        service_type: SinkholeServiceType::Grafana,
        host: "grafana.internal".to_string(),
        port: 3000,
        protocol: WireProtocol::Http,
        status_code: 200,
        body: r#"{"id":1,"name":"Main Org.","anonymous":true,"database":"sqlite3"}"#.to_string(),
        headers: HashMap::new(),
        detected_version: Some("9.3.0".to_string()),
    }];
    let result = detector.analyze_responses(&responses);
    assert_eq!(result.detections.len(), 1);
    assert_eq!(result.detections[0].auth_state, AuthState::AnonymousAccess);
}
