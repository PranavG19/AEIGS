#[cfg(test)]
mod tests {
    use crate::certificate_serializer::{
        Certificate, CertificateType, ChainCertificate, ChainStep, ConfigCertificate,
        DependencyCertificate, EvasionCertificate, FuzzingCertificate, SourceSinkLocation,
        TaintCertificate, TaintPathStep, certificate_hash, deserialize_certificate,
        serialize_certificate,
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

    fn sample_evasion_cert() -> Certificate {
        Certificate::Evasion(EvasionCertificate {
            original_payload: "<script>alert(1)</script>".to_string(),
            evasion_payload: "<scr\x00ipt>alert(1)</scr\x00ipt>".to_string(),
            defense_vendor: "ModSecurity".to_string(),
            evasion_technique: "null_byte_insertion".to_string(),
            block_response_status: 403,
            bypass_response_status: 200,
            anomaly_detected: true,
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
        let cert = sample_fuzzing_cert();
        let cbor_bytes = serialize_certificate(&cert).unwrap();
        let json_bytes = serde_json::to_vec(&match cert {
            Certificate::Fuzzing(ref f) => f,
            _ => unreachable!(),
        })
        .unwrap();

        assert!(cbor_bytes.len() <= json_bytes.len() * 2);
    }

    #[test]
    fn evasion_certificate_roundtrip() {
        let cert = sample_evasion_cert();
        let bytes = serialize_certificate(&cert).unwrap();
        let decoded = deserialize_certificate(&bytes).unwrap();

        if let Certificate::Evasion(e) = decoded {
            assert_eq!(e.original_payload, "<script>alert(1)</script>");
            assert_eq!(e.evasion_payload, "<scr\x00ipt>alert(1)</scr\x00ipt>");
            assert_eq!(e.defense_vendor, "ModSecurity");
            assert_eq!(e.evasion_technique, "null_byte_insertion");
            assert_eq!(e.block_response_status, 403);
            assert_eq!(e.bypass_response_status, 200);
            assert!(e.anomaly_detected);
        } else {
            panic!("expected evasion certificate");
        }
    }

    #[test]
    fn evasion_certificate_hash_deterministic() {
        let cert = sample_evasion_cert();
        let bytes = serialize_certificate(&cert).unwrap();
        let hash1 = certificate_hash(&bytes);
        let hash2 = certificate_hash(&bytes);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn evasion_certificate_hash_differs_from_other_types() {
        let evasion_bytes = serialize_certificate(&sample_evasion_cert()).unwrap();
        let fuzzing_bytes = serialize_certificate(&sample_fuzzing_cert()).unwrap();
        let config_bytes = serialize_certificate(&sample_config_cert()).unwrap();
        let dependency_bytes = serialize_certificate(&sample_dependency_cert()).unwrap();

        let evasion_hash = certificate_hash(&evasion_bytes);
        assert_ne!(evasion_hash, certificate_hash(&fuzzing_bytes));
        assert_ne!(evasion_hash, certificate_hash(&config_bytes));
        assert_ne!(evasion_hash, certificate_hash(&dependency_bytes));
    }

    #[test]
    fn evasion_certificate_uses_version_2_envelope() {
        let cert = sample_evasion_cert();
        let bytes = serialize_certificate(&cert).unwrap();
        let envelope: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();

        if let ciborium::Value::Map(entries) = envelope {
            let version_entry = entries
                .iter()
                .find(|(k, _)| {
                    if let ciborium::Value::Text(s) = k {
                        s == "version"
                    } else {
                        false
                    }
                })
                .expect("envelope must have version field");
            if let ciborium::Value::Integer(v) = &version_entry.1 {
                let version: i128 = (*v).into();
                assert_eq!(version, 2);
            } else {
                panic!("version field must be an integer");
            }
        } else {
            panic!("envelope must be a CBOR map");
        }
    }

    #[test]
    fn certificate_type_evasion_variant_exists() {
        let evasion_type = CertificateType::Evasion;
        assert_eq!(evasion_type, CertificateType::Evasion);
        assert_ne!(evasion_type, CertificateType::Fuzzing);
        assert_ne!(evasion_type, CertificateType::Config);
    }

    #[test]
    fn certificate_error_display_serialize() {
        let err = crate::certificate_serializer::CertificateError::SerializeError(
            "payload too large".to_string(),
        );
        let msg = format!("{err}");
        assert_eq!(msg, "serialize error: payload too large");
    }

    #[test]
    fn certificate_error_display_deserialize() {
        let err = crate::certificate_serializer::CertificateError::DeserializeError(
            "unexpected tag".to_string(),
        );
        let msg = format!("{err}");
        assert_eq!(msg, "deserialize error: unexpected tag");
    }

    #[test]
    fn certificate_error_display_unsupported_version() {
        let err = crate::certificate_serializer::CertificateError::UnsupportedVersion(99);
        let msg = format!("{err}");
        assert_eq!(msg, "unsupported certificate version: 99");
    }

    #[test]
    fn certificate_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(
            crate::certificate_serializer::CertificateError::DeserializeError("test".to_string()),
        );
        assert!(err.to_string().contains("deserialize error"));
    }

    #[test]
    fn deserialize_unsupported_version_zero() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize)]
        struct FakeEnvelope {
            version: u16,
            payload: Vec<u8>,
        }

        let envelope = FakeEnvelope {
            version: 0,
            payload: vec![1, 2, 3],
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&envelope, &mut buf).unwrap();

        let result = deserialize_certificate(&buf);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("unsupported certificate version: 0"));
    }

    #[test]
    fn deserialize_unsupported_version_too_high() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize)]
        struct FakeEnvelope {
            version: u16,
            payload: Vec<u8>,
        }

        let envelope = FakeEnvelope {
            version: 255,
            payload: vec![1, 2, 3],
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&envelope, &mut buf).unwrap();

        let result = deserialize_certificate(&buf);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("unsupported certificate version: 255"));
    }

    #[test]
    fn deserialize_valid_envelope_corrupted_payload() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize)]
        struct FakeEnvelope {
            version: u16,
            payload: Vec<u8>,
        }

        let envelope = FakeEnvelope {
            version: 2,
            payload: vec![0xFF, 0xFF, 0xFF],
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&envelope, &mut buf).unwrap();

        let result = deserialize_certificate(&buf);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("deserialize error"));
    }
}
