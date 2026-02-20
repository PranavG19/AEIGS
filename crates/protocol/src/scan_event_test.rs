#[cfg(test)]
mod tests {
    use crate::finding::VulnerabilityClass;
    use crate::operation::ModuleIdentifier;
    use crate::scan_event::{ScanEvent, ScanEventEnvelope};

    #[test]
    fn test_scan_event_endpoint_discovered_serializes() {
        let event = ScanEvent::EndpointDiscovered {
            endpoint: "/api/users".to_string(),
            method: "GET".to_string(),
            source_module: ModuleIdentifier::Enumeration,
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ScanEvent = serde_json::from_str(&json).unwrap();
        if let ScanEvent::EndpointDiscovered {
            endpoint, method, ..
        } = deserialized
        {
            assert_eq!(endpoint, "/api/users");
            assert_eq!(method, "GET");
        } else {
            panic!("expected EndpointDiscovered variant");
        }
    }

    #[test]
    fn test_scan_event_hypothesis_generated_serializes() {
        let event = ScanEvent::HypothesisGenerated {
            vulnerability_class: VulnerabilityClass::SqlInjection,
            condition: "user input in query parameter".to_string(),
            confidence: 0.85,
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ScanEvent = serde_json::from_str(&json).unwrap();
        if let ScanEvent::HypothesisGenerated {
            vulnerability_class,
            condition,
            confidence,
        } = deserialized
        {
            assert_eq!(vulnerability_class, VulnerabilityClass::SqlInjection);
            assert_eq!(condition, "user input in query parameter");
            assert!((confidence - 0.85).abs() < f64::EPSILON);
        } else {
            panic!("expected HypothesisGenerated variant");
        }
    }

    #[test]
    fn test_scan_event_payload_tested_serializes() {
        let event = ScanEvent::PayloadTested {
            endpoint: "/api/login".to_string(),
            payload_hash: "abc123def456".to_string(),
            vulnerability_class: VulnerabilityClass::CrossSiteScripting,
            anomaly_score: 0.72,
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ScanEvent = serde_json::from_str(&json).unwrap();
        if let ScanEvent::PayloadTested {
            endpoint,
            payload_hash,
            vulnerability_class,
            anomaly_score,
        } = deserialized
        {
            assert_eq!(endpoint, "/api/login");
            assert_eq!(payload_hash, "abc123def456");
            assert_eq!(vulnerability_class, VulnerabilityClass::CrossSiteScripting);
            assert!((anomaly_score - 0.72).abs() < f64::EPSILON);
        } else {
            panic!("expected PayloadTested variant");
        }
    }

    #[test]
    fn test_scan_event_anomaly_detected_serializes() {
        let event = ScanEvent::AnomalyDetected {
            endpoint: "/api/admin".to_string(),
            vulnerability_class: VulnerabilityClass::BrokenAuthorization,
            anomaly_type: "status_code_divergence".to_string(),
            score: 0.95,
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ScanEvent = serde_json::from_str(&json).unwrap();
        if let ScanEvent::AnomalyDetected {
            endpoint,
            vulnerability_class,
            anomaly_type,
            score,
        } = deserialized
        {
            assert_eq!(endpoint, "/api/admin");
            assert_eq!(vulnerability_class, VulnerabilityClass::BrokenAuthorization);
            assert_eq!(anomaly_type, "status_code_divergence");
            assert!((score - 0.95).abs() < f64::EPSILON);
        } else {
            panic!("expected AnomalyDetected variant");
        }
    }

    #[test]
    fn test_scan_event_finding_confirmed_serializes() {
        let event = ScanEvent::FindingConfirmed {
            finding_id: 42,
            vulnerability_class: VulnerabilityClass::CommandInjection,
            severity: 9.5,
            confidence: 0.92,
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ScanEvent = serde_json::from_str(&json).unwrap();
        if let ScanEvent::FindingConfirmed {
            finding_id,
            vulnerability_class,
            severity,
            confidence,
        } = deserialized
        {
            assert_eq!(finding_id, 42);
            assert_eq!(vulnerability_class, VulnerabilityClass::CommandInjection);
            assert!((severity - 9.5).abs() < f64::EPSILON);
            assert!((confidence - 0.92).abs() < f64::EPSILON);
        } else {
            panic!("expected FindingConfirmed variant");
        }
    }

    #[test]
    fn test_scan_event_phase_completed_serializes() {
        let event = ScanEvent::PhaseCompleted {
            phase_name: "fuzzing".to_string(),
            operations_applied: 150,
            findings_count: 3,
            duration_ms: 12500,
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ScanEvent = serde_json::from_str(&json).unwrap();
        if let ScanEvent::PhaseCompleted {
            phase_name,
            operations_applied,
            findings_count,
            duration_ms,
        } = deserialized
        {
            assert_eq!(phase_name, "fuzzing");
            assert_eq!(operations_applied, 150);
            assert_eq!(findings_count, 3);
            assert_eq!(duration_ms, 12500);
        } else {
            panic!("expected PhaseCompleted variant");
        }
    }

    #[test]
    fn test_scan_event_envelope_new_sets_timestamp() {
        let event = ScanEvent::PhaseCompleted {
            phase_name: "recon".to_string(),
            operations_applied: 10,
            findings_count: 0,
            duration_ms: 500,
        };
        let envelope = ScanEventEnvelope::new(1, ModuleIdentifier::PassiveRecon, event);
        assert!(envelope.timestamp_unix_ms > 0);
        assert_eq!(envelope.event_id, 1);
    }

    #[test]
    fn test_scan_event_envelope_serializes() {
        let event = ScanEvent::EndpointDiscovered {
            endpoint: "/health".to_string(),
            method: "GET".to_string(),
            source_module: ModuleIdentifier::Enumeration,
        };
        let envelope = ScanEventEnvelope::new(99, ModuleIdentifier::Enumeration, event);
        let json = serde_json::to_string(&envelope).unwrap();
        let deserialized: ScanEventEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.event_id, 99);
        assert_eq!(deserialized.source_module, ModuleIdentifier::Enumeration);
        assert!(deserialized.timestamp_unix_ms > 0);
    }

    #[test]
    fn test_all_event_variants_have_serde() {
        let variants: Vec<ScanEvent> = vec![
            ScanEvent::EndpointDiscovered {
                endpoint: "/a".to_string(),
                method: "POST".to_string(),
                source_module: ModuleIdentifier::PassiveRecon,
            },
            ScanEvent::HypothesisGenerated {
                vulnerability_class: VulnerabilityClass::PathTraversal,
                condition: "test".to_string(),
                confidence: 0.5,
            },
            ScanEvent::PayloadTested {
                endpoint: "/b".to_string(),
                payload_hash: "hash".to_string(),
                vulnerability_class: VulnerabilityClass::HeaderInjection,
                anomaly_score: 0.1,
            },
            ScanEvent::AnomalyDetected {
                endpoint: "/c".to_string(),
                vulnerability_class: VulnerabilityClass::OpenRedirect,
                anomaly_type: "body_divergence".to_string(),
                score: 0.6,
            },
            ScanEvent::FindingConfirmed {
                finding_id: 1,
                vulnerability_class: VulnerabilityClass::CrlfInjection,
                severity: 5.0,
                confidence: 0.8,
            },
            ScanEvent::PhaseCompleted {
                phase_name: "analyze".to_string(),
                operations_applied: 0,
                findings_count: 0,
                duration_ms: 100,
            },
        ];

        for event in variants {
            let json = serde_json::to_string(&event).unwrap();
            let _roundtrip: ScanEvent = serde_json::from_str(&json).unwrap();
        }
    }
}
