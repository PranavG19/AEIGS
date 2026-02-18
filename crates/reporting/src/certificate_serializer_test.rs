#[cfg(test)]
mod tests {
    use crate::certificate_serializer::{
        certificate_hash, deserialize_certificate, serialize_certificate, Certificate,
        ChainCertificate, ChainStep, ConfigCertificate, DependencyCertificate,
        FuzzingCertificate, SourceSinkLocation, TaintCertificate, TaintPathStep,
    };

    fn sample_fuzzing_cert() -> Certificate {
        Certificate::Fuzzing(FuzzingCertificate {
            request_method: "POST".to_string(),
            request_url: "http://localhost:8080/api/login".to_string(),
            request_headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            request_body: b"{\"user\":\"admin' OR 1=1--\"}".to_vec(),
            response_status: 500,
            response_body: b"SQL syntax error near...".to_vec(),
            anomaly_type: "content".to_string(),
            statistical_significance: 0.001,
        })
    }

    fn sample_taint_cert() -> Certificate {
        Certificate::Taint(TaintCertificate {
            source_location: SourceSinkLocation {
                file: "src/handlers.rs".to_string(),
                line: 10,
                function: "handle_login".to_string(),
                variable: "username".to_string(),
            },
            sink_location: SourceSinkLocation {
                file: "src/db.rs".to_string(),
                line: 42,
                function: "query_user".to_string(),
                variable: "query_str".to_string(),
            },
            path_steps: vec![TaintPathStep {
                file: "src/handlers.rs".to_string(),
                line: 15,
                function: "handle_login".to_string(),
                variable: "query".to_string(),
                operation: "string_concat".to_string(),
            }],
        })
    }

    fn sample_chain_cert() -> Certificate {
        Certificate::Chain(ChainCertificate {
            steps: vec![
                ChainStep {
                    vulnerability_id: 1,
                    description: "SSRF in image proxy".to_string(),
                    transition_condition: "access internal network".to_string(),
                },
                ChainStep {
                    vulnerability_id: 2,
                    description: "unauth admin endpoint".to_string(),
                    transition_condition: "escalate to admin".to_string(),
                },
            ],
        })
    }

    fn sample_config_cert() -> Certificate {
        Certificate::Config(ConfigCertificate {
            config_key: "session.secure".to_string(),
            current_value: "false".to_string(),
            expected_value: "true".to_string(),
        })
    }

    fn sample_dependency_cert() -> Certificate {
        Certificate::Dependency(DependencyCertificate {
            package_name: "lodash".to_string(),
            installed_version: "4.17.20".to_string(),
            vulnerable_range: "<4.17.21".to_string(),
            cve_id: "CVE-2021-23337".to_string(),
        })
    }

    #[test]
    fn fuzzing_certificate_roundtrip() {
        let cert = sample_fuzzing_cert();
        let bytes = serialize_certificate(&cert).unwrap();
        let decoded = deserialize_certificate(&bytes).unwrap();

        if let Certificate::Fuzzing(f) = decoded {
            assert_eq!(f.request_method, "POST");
            assert_eq!(f.response_status, 500);
            assert!((f.statistical_significance - 0.001).abs() < 0.0001);
        } else {
            panic!("expected fuzzing certificate");
        }
    }

    #[test]
    fn taint_certificate_roundtrip() {
        let cert = sample_taint_cert();
        let bytes = serialize_certificate(&cert).unwrap();
        let decoded = deserialize_certificate(&bytes).unwrap();

        if let Certificate::Taint(t) = decoded {
            assert_eq!(t.source_location.file, "src/handlers.rs");
            assert_eq!(t.sink_location.function, "query_user");
            assert_eq!(t.path_steps.len(), 1);
        } else {
            panic!("expected taint certificate");
        }
    }

    #[test]
    fn chain_certificate_roundtrip() {
        let cert = sample_chain_cert();
        let bytes = serialize_certificate(&cert).unwrap();
        let decoded = deserialize_certificate(&bytes).unwrap();

        if let Certificate::Chain(c) = decoded {
            assert_eq!(c.steps.len(), 2);
            assert_eq!(c.steps[0].vulnerability_id, 1);
        } else {
            panic!("expected chain certificate");
        }
    }

    #[test]
    fn config_certificate_roundtrip() {
        let cert = sample_config_cert();
        let bytes = serialize_certificate(&cert).unwrap();
        let decoded = deserialize_certificate(&bytes).unwrap();

        if let Certificate::Config(c) = decoded {
            assert_eq!(c.config_key, "session.secure");
            assert_eq!(c.current_value, "false");
        } else {
            panic!("expected config certificate");
        }
    }

    #[test]
    fn dependency_certificate_roundtrip() {
        let cert = sample_dependency_cert();
        let bytes = serialize_certificate(&cert).unwrap();
        let decoded = deserialize_certificate(&bytes).unwrap();

        if let Certificate::Dependency(d) = decoded {
            assert_eq!(d.package_name, "lodash");
            assert_eq!(d.cve_id, "CVE-2021-23337");
        } else {
            panic!("expected dependency certificate");
        }
    }

    #[test]
    fn certificate_hash_deterministic() {
        let cert = sample_fuzzing_cert();
        let bytes = serialize_certificate(&cert).unwrap();
        let hash1 = certificate_hash(&bytes);
        let hash2 = certificate_hash(&bytes);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn certificate_hash_differs_for_different_data() {
        let cert1 = sample_fuzzing_cert();
        let cert2 = sample_config_cert();
        let bytes1 = serialize_certificate(&cert1).unwrap();
        let bytes2 = serialize_certificate(&cert2).unwrap();
        assert_ne!(certificate_hash(&bytes1), certificate_hash(&bytes2));
    }

    #[test]
    fn certificate_hash_is_32_bytes() {
        let hash = certificate_hash(b"test data");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn deserialize_invalid_data_returns_error() {
        let result = deserialize_certificate(b"not valid cbor");
        assert!(result.is_err());
    }

    #[test]
    fn empty_data_returns_error() {
        let result = deserialize_certificate(b"");
        assert!(result.is_err());
    }

    #[test]
    fn serialized_bytes_are_compact() {
        let cert = sample_config_cert();
        let cbor_bytes = serialize_certificate(&cert).unwrap();
        let json_bytes = serde_json::to_vec(&match cert {
            Certificate::Config(c) => c,
            _ => unreachable!(),
        })
        .unwrap();

        assert!(cbor_bytes.len() <= json_bytes.len());
    }
}
