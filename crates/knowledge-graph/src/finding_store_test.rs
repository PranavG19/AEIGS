#[cfg(test)]
mod tests {
    use crate::finding_store::FindingStore;
    use aegis_protocol::finding::VulnerabilityClass;
    use aegis_protocol::operation::ModuleIdentifier;

    #[test]
    fn insert_and_retrieve_finding() {
        let mut store = FindingStore::new();
        let id = store.insert(
            vec![1, 2],
            VulnerabilityClass::SqlInjection,
            9.0,
            0.95,
            b"proof".to_vec(),
            ModuleIdentifier::Fuzzing,
            1700000000000,
        );

        let finding = store.get(id).unwrap();
        assert_eq!(finding.id, 0);
        assert_eq!(finding.linked_node_ids, vec![1, 2]);
        assert_eq!(
            finding.vulnerability_class,
            VulnerabilityClass::SqlInjection
        );
        assert!((finding.severity - 9.0).abs() < f64::EPSILON);
        assert!((finding.confidence - 0.95).abs() < f64::EPSILON);
        assert_eq!(finding.certificate, b"proof");
    }

    #[test]
    fn findings_for_node_returns_linked_findings() {
        let mut store = FindingStore::new();
        store.insert(
            vec![10],
            VulnerabilityClass::SqlInjection,
            9.0,
            0.95,
            vec![],
            ModuleIdentifier::Fuzzing,
            1700000000000,
        );
        store.insert(
            vec![10, 20],
            VulnerabilityClass::CrossSiteScripting,
            7.0,
            0.90,
            vec![],
            ModuleIdentifier::Fuzzing,
            1700000000001,
        );
        store.insert(
            vec![20],
            VulnerabilityClass::PathTraversal,
            5.0,
            0.80,
            vec![],
            ModuleIdentifier::Fuzzing,
            1700000000002,
        );

        let findings_for_10 = store.findings_for_node(10);
        assert_eq!(findings_for_10, &[0, 1]);

        let findings_for_20 = store.findings_for_node(20);
        assert_eq!(findings_for_20, &[1, 2]);
    }

    #[test]
    fn findings_by_class_filters_correctly() {
        let mut store = FindingStore::new();
        store.insert(
            vec![1],
            VulnerabilityClass::SqlInjection,
            9.0,
            0.95,
            vec![],
            ModuleIdentifier::Fuzzing,
            1700000000000,
        );
        store.insert(
            vec![2],
            VulnerabilityClass::SqlInjection,
            8.0,
            0.90,
            vec![],
            ModuleIdentifier::Fuzzing,
            1700000000001,
        );
        store.insert(
            vec![3],
            VulnerabilityClass::CrossSiteScripting,
            7.0,
            0.85,
            vec![],
            ModuleIdentifier::Fuzzing,
            1700000000002,
        );

        let sqli = store.findings_by_class(VulnerabilityClass::SqlInjection);
        assert_eq!(sqli, &[0, 1]);

        let xss = store.findings_by_class(VulnerabilityClass::CrossSiteScripting);
        assert_eq!(xss, &[2]);

        let ssrf = store.findings_by_class(VulnerabilityClass::ServerSideRequestForgery);
        assert!(ssrf.is_empty());
    }

    #[test]
    fn count_tracks_insertions() {
        let mut store = FindingStore::new();
        assert_eq!(store.count(), 0);

        store.insert(
            vec![1],
            VulnerabilityClass::SqlInjection,
            9.0,
            0.95,
            vec![],
            ModuleIdentifier::Fuzzing,
            1700000000000,
        );
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let store = FindingStore::new();
        assert!(store.get(0).is_none());
        assert!(store.get(999).is_none());
    }

    #[test]
    fn findings_for_nonexistent_node_returns_empty() {
        let store = FindingStore::new();
        assert!(store.findings_for_node(999).is_empty());
    }

    #[test]
    fn multiple_findings_per_node() {
        let mut store = FindingStore::new();
        for i in 0..5 {
            store.insert(
                vec![42],
                VulnerabilityClass::SqlInjection,
                9.0 - i as f64,
                0.95,
                vec![],
                ModuleIdentifier::Fuzzing,
                1700000000000 + i,
            );
        }

        let findings = store.findings_for_node(42);
        assert_eq!(findings.len(), 5);
    }

    #[test]
    fn iter_yields_all_findings() {
        let mut store = FindingStore::new();
        store.insert(
            vec![1],
            VulnerabilityClass::SqlInjection,
            9.0,
            0.95,
            vec![],
            ModuleIdentifier::Fuzzing,
            1700000000000,
        );
        store.insert(
            vec![2],
            VulnerabilityClass::CrossSiteScripting,
            7.0,
            0.90,
            vec![],
            ModuleIdentifier::Fuzzing,
            1700000000001,
        );

        let ids: Vec<u64> = store.iter().map(|f| f.id).collect();
        assert_eq!(ids, vec![0, 1]);
    }

    #[test]
    fn default_creates_empty_store() {
        let store = FindingStore::default();
        assert_eq!(store.count(), 0);
    }
}
