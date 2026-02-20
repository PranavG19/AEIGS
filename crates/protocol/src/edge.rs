use crate::node::NodeType;
use crate::operation::ModuleIdentifier;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeLabel {
    Calls,
    Trusts,
    Authenticates,
    Reads,
    Writes,
    DependsOn,
    Exposes,
    ProtectedBy,
}

impl fmt::Display for EdgeLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EdgeLabel::Calls => write!(f, "Calls"),
            EdgeLabel::Trusts => write!(f, "Trusts"),
            EdgeLabel::Authenticates => write!(f, "Authenticates"),
            EdgeLabel::Reads => write!(f, "Reads"),
            EdgeLabel::Writes => write!(f, "Writes"),
            EdgeLabel::DependsOn => write!(f, "Depends On"),
            EdgeLabel::Exposes => write!(f, "Exposes"),
            EdgeLabel::ProtectedBy => write!(f, "Protected By"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeData {
    pub id: u64,
    pub source_node_id: u64,
    pub target_node_id: u64,
    pub label: EdgeLabel,
    pub weight: f64,
    pub provenance_module: ModuleIdentifier,
    pub provenance_sequence: u64,
}

impl EdgeData {
    pub fn new(
        id: u64,
        source_node_id: u64,
        target_node_id: u64,
        label: EdgeLabel,
        weight: f64,
        provenance_module: ModuleIdentifier,
        provenance_sequence: u64,
    ) -> Self {
        Self {
            id,
            source_node_id,
            target_node_id,
            label,
            weight,
            provenance_module,
            provenance_sequence,
        }
    }
}

/// The 28 valid (`NodeType`, `EdgeLabel`, `NodeType`) triples that the AEGIS security model
/// permits. This array is the single source of truth — [`is_valid_edge`] iterates it for
/// membership checks, and [`valid_edge_count`] exposes its length.
///
/// # Warning
///
/// Adding a new [`NodeType`] or [`EdgeLabel`] variant **requires** updating this
/// array and the exhaustive coverage test in `protocol_test.rs`.
pub const EDGE_WHITELIST: &[(NodeType, EdgeLabel, NodeType)] = {
    use EdgeLabel::*;
    use NodeType::*;

    &[
        // Execution flow
        (Endpoint, Calls, Function),
        (Function, Calls, Function),
        (Service, Calls, Service),
        (Service, Calls, Function),
        // Trust relationships
        (Role, Trusts, Role),
        (Service, Trusts, Service),
        (User, Trusts, Service),
        // Authentication
        (Role, Authenticates, Endpoint),
        (User, Authenticates, Endpoint),
        (Service, Authenticates, Endpoint),
        // Data access — reads
        (Function, Reads, DataStore),
        (Endpoint, Reads, DataStore),
        (Service, Reads, DataStore),
        // Data access — writes
        (Function, Writes, DataStore),
        (Endpoint, Writes, DataStore),
        (Service, Writes, DataStore),
        // Dependencies
        (Service, DependsOn, Dependency),
        (Service, DependsOn, Service),
        (Function, DependsOn, Dependency),
        (Endpoint, DependsOn, Dependency),
        // Data exposure
        (Endpoint, Exposes, DataStore),
        (Function, Exposes, DataStore),
        (Service, Exposes, DataStore),
        (Config, Exposes, DataStore),
        // Protection
        (Endpoint, ProtectedBy, Defense),
        (DataStore, ProtectedBy, Defense),
        (Service, ProtectedBy, Defense),
        (Function, ProtectedBy, Defense),
    ]
};

/// Validates whether a (`source_type`, `label`, `target_type`) triple is semantically
/// meaningful in the AEGIS security model.
///
/// The knowledge graph only permits edges that represent real security relationships.
/// This function encodes the 28 valid triples, grouped into seven categories:
///
/// **Execution flow** — `Calls` edges model invocation relationships:
/// - `Endpoint → Function`, `Function → Function`, `Service → Service`, `Service → Function`
///
/// **Trust relationships** — `Trusts` edges model delegation of authority:
/// - `Role → Role`, `Service → Service`, `User → Service`
///
/// **Authentication** — `Authenticates` edges model identity verification:
/// - `Role → Endpoint`, `User → Endpoint`, `Service → Endpoint`
///
/// **Data access** — `Reads` and `Writes` edges model data flow:
/// - `Function → DataStore`, `Endpoint → DataStore`, `Service → DataStore`
///
/// **Dependencies** — `DependsOn` edges model supply-chain relationships:
/// - `Service → Dependency`, `Service → Service`, `Function → Dependency`, `Endpoint → Dependency`
///
/// **Data exposure** — `Exposes` edges model information leakage paths:
/// - `Endpoint → DataStore`, `Function → DataStore`, `Service → DataStore`, `Config → DataStore`
///
/// **Protection** — `ProtectedBy` edges model defensive controls:
/// - `Endpoint → Defense`, `DataStore → Defense`, `Service → Defense`, `Function → Defense`
pub fn is_valid_edge(source: NodeType, label: EdgeLabel, target: NodeType) -> bool {
    EDGE_WHITELIST
        .iter()
        .any(|&(s, l, t)| s == source && l == label && t == target)
}

/// Returns the number of valid edge triples in [`EDGE_WHITELIST`].
pub fn valid_edge_count() -> usize {
    EDGE_WHITELIST.len()
}
