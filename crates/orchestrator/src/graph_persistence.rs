use aegis_knowledge_graph::{GraphMetadata, GraphStore, KnowledgeGraph};
use std::path::Path;

/// Loads a `KnowledgeGraph` from `path` if the file exists.
///
/// Returns a fresh empty graph if `path` is `None` or does not exist.
/// On load failure (corrupted file, schema error), falls back to an empty graph
/// rather than aborting the scan — persistence failures are non-fatal.
///
/// Returns the graph and the `scan_count` from the loaded metadata (0 if new).
pub fn load_or_create_graph(path: Option<&Path>) -> (KnowledgeGraph, u64) {
    let Some(p) = path else {
        return (KnowledgeGraph::new(), 0);
    };
    if !p.exists() {
        return (KnowledgeGraph::new(), 0);
    }
    match KnowledgeGraph::load_from_file(p) {
        Ok((graph, meta)) => {
            let count = meta.map(|m| m.scan_count).unwrap_or(0);
            (graph, count)
        }
        Err(_) => (KnowledgeGraph::new(), 0),
    }
}

/// Saves the graph to `path` with updated metadata.
///
/// No-op if `path` is `None`. Save failures are printed as warnings to stderr
/// but do not invalidate the scan result.
///
/// Accepts `&dyn GraphStore` so the pipeline can call this directly on
/// `ScanContext.graph` without downcasting. The `GraphStore::save_to_file`
/// default implementation is a no-op for test fakes; `KnowledgeGraph` writes
/// a JSON bundle.
pub fn save_graph_if_configured(
    graph: &dyn GraphStore,
    path: Option<&Path>,
    target_url: &str,
    scan_count: u64,
) {
    let Some(p) = path else {
        return;
    };
    let metadata = GraphMetadata {
        scan_timestamp_unix_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        target_url: target_url.to_string(),
        aegis_version: env!("CARGO_PKG_VERSION").to_string(),
        scan_count,
    };
    if let Err(e) = graph.save_to_file(p, &metadata) {
        eprintln!(
            "aegis: warning: failed to save graph to {}: {e}",
            p.display()
        );
    }
}
