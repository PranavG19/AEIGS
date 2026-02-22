#[cfg(test)]
mod tests {
    use crate::finding::{
        Confidence, EvidenceLevel, FindingConfidence, FindingData, FindingId, VulnerabilityClass,
    };
    use crate::operation::ModuleIdentifier;

    #[test]
    fn finding_id_same_inputs_are_equal() {
        let id1 = FindingId::from_parts("/api/users", VulnerabilityClass::SqlInjection, "username");
        let id2 = FindingId::from_parts("/api/users", VulnerabilityClass::SqlInjection, "username");
        assert_eq!(id1, id2);
    }

    #[test]
    fn finding_id_different_endpoint_are_different() {
        let id1 = FindingId::from_parts("/api/users", VulnerabilityClass::SqlInjection, "username");
        let id2 = FindingId::from_parts("/api/admin", VulnerabilityClass::SqlInjection, "username");
        assert_ne!(id1, id2);
    }

    #[test]
    fn finding_id_different_parameter_are_different() {
        let id1 = FindingId::from_parts("/api/users", VulnerabilityClass::SqlInjection, "username");
        let id2 = FindingId::from_parts("/api/users", VulnerabilityClass::SqlInjection, "password");
        assert_ne!(id1, id2);
    }

    #[test]
    fn finding_id_different_vuln_class_are_different() {
        let id1 = FindingId::from_parts("/api/users", VulnerabilityClass::SqlInjection, "username");
        let id2 = FindingId::from_parts(
            "/api/users",
            VulnerabilityClass::CrossSiteScripting,
            "username",
        );
        assert_ne!(id1, id2);
    }

    #[test]
    fn finding_id_is_stable_across_severity_changes() {
        let finding1 = FindingData::new(
            1,
            VulnerabilityClass::SqlInjection,
            9.5,
            0.95,
            ModuleIdentifier::Fuzzing,
            1700000000000,
        )
        .with_stable_id("/api/users", "username");

        let finding2 = FindingData::new(
            2,
            VulnerabilityClass::SqlInjection,
            3.0,
            0.5,
            ModuleIdentifier::Fuzzing,
            1700000001000,
        )
        .with_stable_id("/api/users", "username");

        assert_eq!(finding1.stable_id, finding2.stable_id);
    }

    #[test]
    fn finding_with_stable_id_roundtrips_serde() {
        let finding = FindingData::new(
            1,
            VulnerabilityClass::PathTraversal,
            7.0,
            0.8,
            ModuleIdentifier::Fuzzing,
            1700000000000,
        )
        .with_stable_id("/api/files", "path");

        let json = serde_json::to_string(&finding).unwrap();
        let deserialized: FindingData = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.stable_id, finding.stable_id);
        assert!(deserialized.stable_id.is_some());
    }

    #[test]
    fn finding_without_stable_id_deserializes_as_none() {
        let finding = FindingData::new(
            1,
            VulnerabilityClass::SqlInjection,
            9.0,
            0.9,
            ModuleIdentifier::Fuzzing,
            1700000000000,
        );

        let json = serde_json::to_string(&finding).unwrap();
        let deserialized: FindingData = serde_json::from_str(&json).unwrap();
        assert!(deserialized.stable_id.is_none());
    }

    #[test]
    fn finding_id_hash_is_nonzero_and_stable() {
        let id1 =
            FindingId::from_parts("/api/endpoint", VulnerabilityClass::CommandInjection, "cmd");
        let id2 =
            FindingId::from_parts("/api/endpoint", VulnerabilityClass::CommandInjection, "cmd");
        let zero_id =
            FindingId::from_parts("/api/endpoint", VulnerabilityClass::CommandInjection, "");
        assert_eq!(id1, id2);
        assert_ne!(id1, zero_id);
    }

    #[test]
    fn with_stable_id_uses_finding_vulnerability_class() {
        let finding = FindingData::new(
            1,
            VulnerabilityClass::CrossSiteScripting,
            5.0,
            0.7,
            ModuleIdentifier::Fuzzing,
            1700000000000,
        )
        .with_stable_id("/api/search", "q");

        let expected =
            FindingId::from_parts("/api/search", VulnerabilityClass::CrossSiteScripting, "q");
        assert_eq!(finding.stable_id.unwrap(), expected);
    }

    #[test]
    fn old_json_without_stable_id_field_deserializes_backward_compat() {
        let old_json = r#"{
            "id": 1,
            "linked_node_ids": [],
            "vulnerability_class": "SqlInjection",
            "severity": 9.0,
            "confidence": 0.9,
            "certificate": [],
            "provenance_module": "Fuzzing",
            "timestamp_unix_ms": 1700000000000,
            "evidence_level": "Statistical"
        }"#;
        let deserialized: FindingData = serde_json::from_str(old_json).unwrap();
        assert!(deserialized.stable_id.is_none());
        assert_eq!(deserialized.evidence_level, EvidenceLevel::Statistical);
    }

    #[test]
    fn finding_confidence_compute_clamps_to_unit_range() {
        let fc = FindingConfidence::compute(0.5, 3.0, 1.0);
        assert!((fc.composite.value() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn finding_confidence_compute_normal_values() {
        let fc = FindingConfidence::compute(0.5, 1.0, 0.8);
        assert!((fc.composite.value() - 0.4).abs() < f64::EPSILON);
        assert!((fc.prior - 0.5).abs() < f64::EPSILON);
        assert!((fc.likelihood_ratio - 1.0).abs() < f64::EPSILON);
        assert!((fc.methodology_reliability - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn finding_confidence_from_simple_preserves_composite() {
        let c = Confidence::new(0.7).unwrap();
        let fc = FindingConfidence::from_simple(c);
        assert!((fc.composite.value() - 0.7).abs() < f64::EPSILON);
        assert!((fc.prior - 0.5).abs() < f64::EPSILON);
        assert!((fc.likelihood_ratio - 1.4).abs() < f64::EPSILON);
        assert!((fc.methodology_reliability - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn finding_confidence_display_shows_composite() {
        let fc = FindingConfidence::compute(0.5, 1.0, 0.8);
        let display = format!("{fc}");
        assert_eq!(display, "0.40");
    }

    #[test]
    fn finding_confidence_roundtrips_serde() {
        let fc = FindingConfidence::compute(0.3, 2.0, 0.7);
        let json = serde_json::to_string(&fc).unwrap();
        let deserialized: FindingConfidence = serde_json::from_str(&json).unwrap();
        assert!((deserialized.prior - 0.3).abs() < f64::EPSILON);
        assert!((deserialized.likelihood_ratio - 2.0).abs() < f64::EPSILON);
        assert!((deserialized.methodology_reliability - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn finding_data_with_finding_confidence_uses_provenance() {
        let fc = FindingConfidence::compute(0.3, 2.0, 0.9);
        let finding = FindingData::new(
            1,
            VulnerabilityClass::SqlInjection,
            9.0,
            0.5,
            ModuleIdentifier::Fuzzing,
            1700000000000,
        )
        .with_finding_confidence(fc);
        assert!((finding.confidence.prior - 0.3).abs() < f64::EPSILON);
        assert!((finding.confidence.composite.value() - 0.54).abs() < f64::EPSILON);
    }

    #[test]
    fn legacy_scalar_confidence_deserializes_into_finding_confidence() {
        let old_json = r#"{
            "id": 1,
            "linked_node_ids": [],
            "vulnerability_class": "SqlInjection",
            "severity": 9.0,
            "confidence": 0.85,
            "certificate": [],
            "provenance_module": "Fuzzing",
            "timestamp_unix_ms": 1700000000000,
            "evidence_level": "Statistical"
        }"#;
        let deserialized: FindingData = serde_json::from_str(old_json).unwrap();
        assert!((deserialized.confidence.composite.value() - 0.85).abs() < f64::EPSILON);
        assert!((deserialized.confidence.prior - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn provenance_json_deserializes_into_finding_confidence() {
        let json = r#"{
            "id": 1,
            "linked_node_ids": [],
            "vulnerability_class": "SqlInjection",
            "severity": 9.0,
            "confidence": {"prior": 0.3, "likelihood_ratio": 2.0, "methodology_reliability": 0.8, "composite": 0.48},
            "certificate": [],
            "provenance_module": "Fuzzing",
            "timestamp_unix_ms": 1700000000000,
            "evidence_level": "Statistical"
        }"#;
        let deserialized: FindingData = serde_json::from_str(json).unwrap();
        assert!((deserialized.confidence.prior - 0.3).abs() < f64::EPSILON);
        assert!((deserialized.confidence.likelihood_ratio - 2.0).abs() < f64::EPSILON);
        assert!((deserialized.confidence.methodology_reliability - 0.8).abs() < f64::EPSILON);
        assert!((deserialized.confidence.composite.value() - 0.48).abs() < f64::EPSILON);
    }

    #[test]
    fn counterfactual_alias_deserializes_as_controlled() {
        let json = r#""Counterfactual""#;
        let level: EvidenceLevel = serde_json::from_str(json).unwrap();
        assert_eq!(level, EvidenceLevel::Controlled);
    }

    #[test]
    fn controlled_evidence_level_display() {
        assert_eq!(format!("{}", EvidenceLevel::Controlled), "Controlled");
    }

    #[test]
    fn confidence_from_evidence_controlled() {
        let c = Confidence::from_evidence(EvidenceLevel::Controlled);
        assert!((c.value() - 0.7).abs() < f64::EPSILON);
    }
}
