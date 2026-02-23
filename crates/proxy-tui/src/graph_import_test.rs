#[cfg(test)]
mod tests {
    use crate::graph_import::{GraphImportResult, ImportError, import_from_graph};
    use aegis_knowledge_graph::{GraphMetadata, KnowledgeGraph};
    use aegis_proxy::ScopeEngine;
    use std::path::Path;
    use tempfile::NamedTempFile;

    #[test]
    fn import_from_nonexistent_path_returns_error() {
        let mut scope = ScopeEngine::new();
        let result = import_from_graph(Path::new("/nonexistent/no_such_file.json"), &mut scope);
        assert!(matches!(result, Err(ImportError::GraphLoad(_))));
    }

    #[test]
    fn empty_graph_returns_zero_counts() {
        let graph = KnowledgeGraph::new();
        let tmp = NamedTempFile::new().expect("tempfile");
        let metadata = GraphMetadata {
            scan_timestamp_unix_ms: 0,
            target_url: "http://localhost".to_string(),
            aegis_version: "test".to_string(),
            scan_count: 0,
        };
        graph
            .save_to_file(tmp.path(), &metadata)
            .expect("save graph");

        let mut scope = ScopeEngine::new();
        let result = import_from_graph(tmp.path(), &mut scope).expect("import");

        assert_eq!(result.endpoints_found, 0);
        assert_eq!(result.scope_rules_added, 0);
        assert_eq!(result.saved_requests_created, 0);
    }

    #[test]
    fn import_result_fields_accessible() {
        let result = GraphImportResult {
            scope_rules_added: 3,
            saved_requests_created: 0,
            endpoints_found: 5,
        };
        let cloned = result.clone();
        assert_eq!(cloned.scope_rules_added, 3);
        assert_eq!(cloned.saved_requests_created, 0);
        assert_eq!(cloned.endpoints_found, 5);
        let _ = format!("{cloned:?}");
    }
}
