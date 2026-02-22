#[cfg(test)]
mod tests {
    use crate::finding::{Confidence, EvidenceLevel, FindingData, FindingId, VulnerabilityClass};
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
}
