use aegis_knowledge_graph::KnowledgeGraph;
use aegis_protocol::node::NodeType;
use aegis_proxy::ScopeEngine;
use std::collections::HashSet;
use std::path::Path;

/// Summary of what was imported from a knowledge graph file.
#[derive(Debug, Clone)]
pub struct GraphImportResult {
    pub scope_rules_added: usize,
    pub saved_requests_created: usize,
    pub endpoints_found: usize,
}

/// Error returned when graph import fails.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ImportError {
    #[error("failed to load graph: {0}")]
    GraphLoad(String),
}

/// Load endpoints from a knowledge graph DB file and add include scope rules.
///
/// Reads all `Endpoint` nodes from the persisted graph, extracts their `path`
/// property, and registers one include rule per unique path prefix on `scope`.
/// `saved_requests_created` is always 0 — saved request creation requires an
/// HTTP session context not available at import time.
pub fn import_from_graph(
    db_path: &Path,
    scope: &mut ScopeEngine,
) -> Result<GraphImportResult, ImportError> {
    let (graph, _metadata) = KnowledgeGraph::load_from_file(db_path)
        .map_err(|e| ImportError::GraphLoad(e.to_string()))?;

    let node_ids = graph
        .nodes_by_type(NodeType::Endpoint)
        .map_err(|e| ImportError::GraphLoad(e.to_string()))?;

    let endpoints_found = node_ids.len();
    let mut seen_paths: HashSet<String> = HashSet::new();

    for id in node_ids {
        let node = graph
            .get_node(id)
            .map_err(|e| ImportError::GraphLoad(e.to_string()))?;

        if let Some(node_data) = node
            && let Some(path) = node_data.properties.get("path")
            && seen_paths.insert(path.clone())
        {
            let pattern = format!(".*{}.*", regex::escape(path));
            let _ = scope.add_rule(&pattern, true);
        }
    }

    Ok(GraphImportResult {
        scope_rules_added: seen_paths.len(),
        saved_requests_created: 0,
        endpoints_found,
    })
}

#[cfg(test)]
#[path = "graph_import_test.rs"]
mod graph_import_test;
