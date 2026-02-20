#[cfg(test)]
mod tests {
    use crate::graph_persistence::{load_or_create_graph, save_graph_if_configured};
    use aegis_knowledge_graph::GraphMetadata;

    #[test]
    fn load_or_create_returns_empty_when_no_path() {
        let (graph, count) = load_or_create_graph(None);
        assert_eq!(count, 0);
        assert_eq!(graph.node_count().unwrap(), 0);
        assert_eq!(graph.finding_count().unwrap(), 0);
    }

    #[test]
    fn load_or_create_returns_empty_for_missing_file() {
        let path = std::path::Path::new("/tmp/aegis_nonexistent_graph_test_xyz.json");
        let (graph, count) = load_or_create_graph(Some(path));
        assert_eq!(count, 0);
        assert_eq!(graph.node_count().unwrap(), 0);
    }

    #[test]
    fn load_or_create_returns_empty_for_corrupted_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt.json");
        std::fs::write(&path, b"not json {{{{ at all").unwrap();
        let (graph, count) = load_or_create_graph(Some(&path));
        assert_eq!(count, 0);
        assert_eq!(graph.node_count().unwrap(), 0);
    }

    #[test]
    fn save_and_load_roundtrip_preserves_scan_count() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("graph.json");

        let graph = aegis_knowledge_graph::KnowledgeGraph::new();
        save_graph_if_configured(&graph, Some(&path), "http://127.0.0.1:8080", 1);

        assert!(path.exists());

        let (_, count) = load_or_create_graph(Some(&path));
        assert_eq!(count, 1);
    }

    #[test]
    fn save_graph_if_configured_noop_when_path_none() {
        let graph = aegis_knowledge_graph::KnowledgeGraph::new();
        save_graph_if_configured(&graph, None, "http://127.0.0.1:8080", 0);
    }

    #[test]
    fn save_and_load_increments_scan_count() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scan_count_test.json");

        let graph = aegis_knowledge_graph::KnowledgeGraph::new();

        save_graph_if_configured(&graph, Some(&path), "http://127.0.0.1:9090", 0);
        let (_, count0) = load_or_create_graph(Some(&path));
        assert_eq!(count0, 0);

        save_graph_if_configured(&graph, Some(&path), "http://127.0.0.1:9090", 1);
        let (_, count1) = load_or_create_graph(Some(&path));
        assert_eq!(count1, 1);

        save_graph_if_configured(&graph, Some(&path), "http://127.0.0.1:9090", 2);
        let (_, count2) = load_or_create_graph(Some(&path));
        assert_eq!(count2, 2);
    }

    #[test]
    fn save_graph_stores_metadata_target_url() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta_test.json");
        let graph = aegis_knowledge_graph::KnowledgeGraph::new();

        save_graph_if_configured(&graph, Some(&path), "http://127.0.0.1:3000", 5);

        let (_, meta) = aegis_knowledge_graph::KnowledgeGraph::load_from_file(&path).unwrap();
        let meta = meta.unwrap();
        assert_eq!(meta.target_url, "http://127.0.0.1:3000");
        assert_eq!(meta.scan_count, 5);
    }

    #[test]
    fn load_or_create_extracts_scan_count_from_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("count_check.json");
        let graph = aegis_knowledge_graph::KnowledgeGraph::new();
        let meta = GraphMetadata {
            scan_timestamp_unix_ms: 1700000000000,
            target_url: "http://127.0.0.1:8080".into(),
            aegis_version: "0.1.0".into(),
            scan_count: 7,
        };
        graph.save_to_file(&path, &meta).unwrap();

        let (_, count) = load_or_create_graph(Some(&path));
        assert_eq!(count, 7);
    }
}
