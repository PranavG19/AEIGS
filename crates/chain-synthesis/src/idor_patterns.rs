use petgraph::Direction;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// Pattern categories for Insecure Direct Object Reference exploitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdorPatternType {
    HorizontalEscalation,
    VerticalEscalation,
    BulkEnumeration,
    CrossObjectReference,
    IndirectReferenceMapping,
    UuidPrediction,
    GraphQlIdor,
    ParameterTampering,
}

impl std::fmt::Display for IdorPatternType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::HorizontalEscalation => "horizontal-escalation",
            Self::VerticalEscalation => "vertical-escalation",
            Self::BulkEnumeration => "bulk-enumeration",
            Self::CrossObjectReference => "cross-object-reference",
            Self::IndirectReferenceMapping => "indirect-reference-mapping",
            Self::UuidPrediction => "uuid-prediction",
            Self::GraphQlIdor => "graphql-idor",
            Self::ParameterTampering => "parameter-tampering",
        };
        write!(f, "{label}")
    }
}

/// Privilege level associated with a resource or user context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PrivilegeLevel {
    Anonymous,
    User,
    Moderator,
    Admin,
    SuperAdmin,
}

impl std::fmt::Display for PrivilegeLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Anonymous => "anonymous",
            Self::User => "user",
            Self::Moderator => "moderator",
            Self::Admin => "admin",
            Self::SuperAdmin => "super-admin",
        };
        write!(f, "{label}")
    }
}

/// An HTTP method relevant to IDOR testing (superset of base HttpMethod with Patch/Delete).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdorHttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl std::fmt::Display for IdorHttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        };
        write!(f, "{label}")
    }
}

/// Confirmed IDOR finding that seeds exploitation chain generation.
#[derive(Debug, Clone, PartialEq)]
pub struct IdorFinding {
    pub endpoint: String,
    pub method: IdorHttpMethod,
    pub vulnerable_parameter: String,
    pub observed_id: String,
    pub resource_type: String,
    pub privilege_level: PrivilegeLevel,
}

/// A single step within an exploitation chain.
#[derive(Debug, Clone, PartialEq)]
pub struct ExploitationStep {
    pub step_number: u32,
    pub description: String,
    pub endpoint: String,
    pub method: IdorHttpMethod,
    pub parameter: String,
    pub payload: String,
    pub expected_outcome: String,
}

/// Full exploitation chain produced for a confirmed IDOR.
#[derive(Debug, Clone, PartialEq)]
pub struct ExploitationChain {
    pub pattern_type: IdorPatternType,
    pub finding: IdorFinding,
    pub steps: Vec<ExploitationStep>,
    pub impact_description: String,
    pub risk_score: f64,
}

/// Result of UUID v1 analysis: extracted temporal and hardware components.
#[derive(Debug, Clone, PartialEq)]
pub struct UuidV1Analysis {
    pub raw_uuid: String,
    pub timestamp_100ns: u64,
    pub clock_sequence: u16,
    pub mac_address: [u8; 6],
    pub predicted_next: Vec<String>,
}

/// A node in the cross-object reference graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectNode {
    pub object_type: String,
    pub example_id: String,
    pub endpoint: String,
}

/// An edge in the cross-object reference graph representing a traversal.
#[derive(Debug, Clone, PartialEq)]
pub struct ObjectEdge {
    pub source_field: String,
    pub target_field: String,
    pub traversal_method: String,
    pub requires_auth: bool,
}

/// Cross-object reference graph built with petgraph DiGraph.
pub struct CrossObjectGraph {
    graph: DiGraph<ObjectNode, ObjectEdge>,
    index_map: HashMap<String, NodeIndex>,
}

impl CrossObjectGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            index_map: HashMap::new(),
        }
    }

    /// Add an object type as a node, returning its index. Deduplicates by object_type.
    pub fn add_object(&mut self, node: ObjectNode) -> NodeIndex {
        if let Some(&idx) = self.index_map.get(&node.object_type) {
            return idx;
        }
        let key = node.object_type.clone();
        let idx = self.graph.add_node(node);
        self.index_map.insert(key, idx);
        idx
    }

    /// Add a directed reference edge between two object types.
    pub fn add_reference(
        &mut self,
        source_type: &str,
        target_type: &str,
        edge: ObjectEdge,
    ) -> bool {
        let source = self.index_map.get(source_type).copied();
        let target = self.index_map.get(target_type).copied();
        match (source, target) {
            (Some(s), Some(t)) => {
                self.graph.add_edge(s, t, edge);
                true
            }
            _ => false,
        }
    }

    /// Find all exploitation chains from a starting object type to any reachable target.
    pub fn find_chains(&self, start_type: &str, max_depth: usize) -> Vec<Vec<String>> {
        let start = match self.index_map.get(start_type).copied() {
            Some(idx) => idx,
            None => return Vec::new(),
        };

        let mut result = Vec::new();
        let mut queue: VecDeque<(NodeIndex, Vec<String>)> = VecDeque::new();
        queue.push_back((start, vec![start_type.to_string()]));

        while let Some((current, path)) = queue.pop_front() {
            if path.len() > 1 {
                result.push(path.clone());
            }
            if path.len() > max_depth {
                continue;
            }
            for edge_ref in self.graph.edges_directed(current, Direction::Outgoing) {
                let target = edge_ref.target();
                let target_type = &self.graph[target].object_type;
                if !path.contains(target_type) {
                    let mut new_path = path.clone();
                    new_path.push(target_type.clone());
                    queue.push_back((target, new_path));
                }
            }
        }

        result
    }

    /// Return all edges for a given source type (for inspection/reporting).
    pub fn outgoing_references(&self, object_type: &str) -> Vec<(&ObjectNode, &ObjectEdge)> {
        let idx = match self.index_map.get(object_type).copied() {
            Some(i) => i,
            None => return Vec::new(),
        };
        self.graph
            .edges_directed(idx, Direction::Outgoing)
            .map(|e| (&self.graph[e.target()], e.weight()))
            .collect()
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Export the graph in DOT format for visualization.
    pub fn to_dot(&self) -> String {
        let mut lines = vec!["digraph CrossObjectIDOR {".to_string()];
        lines.push("  rankdir=LR;".to_string());
        for idx in self.graph.node_indices() {
            let node = &self.graph[idx];
            lines.push(format!(
                "  \"{}\" [label=\"{}\\n({})\"];",
                node.object_type, node.object_type, node.endpoint
            ));
        }
        for edge_ref in self.graph.edge_references() {
            let source = &self.graph[edge_ref.source()].object_type;
            let target = &self.graph[edge_ref.target()].object_type;
            let weight = edge_ref.weight();
            lines.push(format!(
                "  \"{}\" -> \"{}\" [label=\"{} → {}\"];",
                source, target, weight.source_field, weight.target_field
            ));
        }
        lines.push("}".to_string());
        lines.join("\n")
    }
}

impl Default for CrossObjectGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Vulnerability in a parameter per endpoint for the tampering matrix.
#[derive(Debug, Clone, PartialEq)]
pub struct ParameterVulnerability {
    pub parameter: String,
    pub methods: Vec<IdorHttpMethod>,
    pub id_type: IdType,
    pub confirmed: bool,
}

/// Classification of an identifier's format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdType {
    Sequential,
    UuidV1,
    UuidV4,
    HashBased,
    Encoded,
    Composite,
}

impl std::fmt::Display for IdType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Sequential => "sequential",
            Self::UuidV1 => "uuid-v1",
            Self::UuidV4 => "uuid-v4",
            Self::HashBased => "hash-based",
            Self::Encoded => "encoded",
            Self::Composite => "composite",
        };
        write!(f, "{label}")
    }
}

/// Per-endpoint tampering matrix entry.
#[derive(Debug, Clone, PartialEq)]
pub struct TamperingMatrixEntry {
    pub endpoint: String,
    pub vulnerabilities: Vec<ParameterVulnerability>,
}

/// GraphQL-specific IDOR traversal path through nested objects.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphQlTraversalPath {
    pub query_path: Vec<String>,
    pub target_field: String,
    pub requires_variables: Vec<(String, String)>,
}

/// Indirect reference mapping: observed encoded ID → decoded components.
#[derive(Debug, Clone, PartialEq)]
pub struct IndirectReferenceMap {
    pub encoded_value: String,
    pub encoding: IndirectEncoding,
    pub decoded_components: Vec<String>,
    pub predicted_pattern: String,
}

/// Encoding scheme used for indirect references.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IndirectEncoding {
    Base64,
    Hex,
    Sha256Truncated,
    Hmac,
    RotatingNumeric,
    Jwt,
}

impl std::fmt::Display for IndirectEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Base64 => "base64",
            Self::Hex => "hex",
            Self::Sha256Truncated => "sha256-truncated",
            Self::Hmac => "hmac",
            Self::RotatingNumeric => "rotating-numeric",
            Self::Jwt => "jwt",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Core generation functions
// ---------------------------------------------------------------------------

/// Generate a horizontal escalation chain: access other users' data via predictable IDs.
pub fn generate_horizontal_escalation(finding: &IdorFinding) -> ExploitationChain {
    let id_numeric: Option<u64> = finding.observed_id.parse().ok();

    let mut steps = vec![
        ExploitationStep {
            step_number: 1,
            description: "Authenticate as attacker user and capture session token".to_string(),
            endpoint: finding.endpoint.clone(),
            method: finding.method,
            parameter: "Authorization".to_string(),
            payload: "Bearer <attacker_token>".to_string(),
            expected_outcome: "Valid authenticated session for attacker user".to_string(),
        },
        ExploitationStep {
            step_number: 2,
            description: format!(
                "Request target resource with observed ID '{}'",
                finding.observed_id
            ),
            endpoint: finding.endpoint.clone(),
            method: finding.method,
            parameter: finding.vulnerable_parameter.clone(),
            payload: finding.observed_id.clone(),
            expected_outcome: "Baseline response for attacker-owned resource".to_string(),
        },
    ];

    if let Some(base) = id_numeric {
        for (i, offset) in [1u64, 2, 10].iter().enumerate() {
            let target_id = base.wrapping_add(*offset);
            steps.push(ExploitationStep {
                step_number: (3 + i) as u32,
                description: format!(
                    "Substitute {} with victim ID {} (offset +{})",
                    finding.vulnerable_parameter, target_id, offset
                ),
                endpoint: finding.endpoint.clone(),
                method: finding.method,
                parameter: finding.vulnerable_parameter.clone(),
                payload: target_id.to_string(),
                expected_outcome: format!(
                    "Unauthorized access to {} belonging to user {}",
                    finding.resource_type, target_id
                ),
            });
        }
    } else {
        steps.push(ExploitationStep {
            step_number: 3,
            description: "Substitute with enumerated or guessed victim identifier".to_string(),
            endpoint: finding.endpoint.clone(),
            method: finding.method,
            parameter: finding.vulnerable_parameter.clone(),
            payload: format!("{}_victim", finding.observed_id),
            expected_outcome: format!(
                "Unauthorized access to {} belonging to another user",
                finding.resource_type
            ),
        });
    }

    ExploitationChain {
        pattern_type: IdorPatternType::HorizontalEscalation,
        finding: finding.clone(),
        steps,
        impact_description: format!(
            "Attacker can access any user's {} by manipulating {}",
            finding.resource_type, finding.vulnerable_parameter
        ),
        risk_score: 7.5,
    }
}

/// Generate a vertical escalation chain: access admin resources via privilege confusion.
pub fn generate_vertical_escalation(
    finding: &IdorFinding,
    target_privilege: PrivilegeLevel,
) -> ExploitationChain {
    let steps = vec![
        ExploitationStep {
            step_number: 1,
            description: format!("Authenticate as {} user", finding.privilege_level),
            endpoint: "/api/auth/login".to_string(),
            method: IdorHttpMethod::Post,
            parameter: "credentials".to_string(),
            payload: format!("role={}", finding.privilege_level),
            expected_outcome: "Session token with limited privileges".to_string(),
        },
        ExploitationStep {
            step_number: 2,
            description: format!("Identify {} resource identifier pattern", target_privilege),
            endpoint: finding.endpoint.clone(),
            method: finding.method,
            parameter: finding.vulnerable_parameter.clone(),
            payload: finding.observed_id.clone(),
            expected_outcome: "Response reveals admin resource ID format".to_string(),
        },
        ExploitationStep {
            step_number: 3,
            description: format!(
                "Replace {} with {} resource ID",
                finding.vulnerable_parameter, target_privilege
            ),
            endpoint: finding.endpoint.clone(),
            method: finding.method,
            parameter: finding.vulnerable_parameter.clone(),
            payload: "admin_resource_1".to_string(),
            expected_outcome: format!(
                "Access to {}-level {} without authorization",
                target_privilege, finding.resource_type
            ),
        },
        ExploitationStep {
            step_number: 4,
            description: "Attempt write operation on escalated resource".to_string(),
            endpoint: finding.endpoint.clone(),
            method: IdorHttpMethod::Put,
            parameter: finding.vulnerable_parameter.clone(),
            payload: "admin_resource_1".to_string(),
            expected_outcome: format!(
                "Modify {}-level resource from {} context",
                target_privilege, finding.privilege_level
            ),
        },
    ];

    ExploitationChain {
        pattern_type: IdorPatternType::VerticalEscalation,
        finding: finding.clone(),
        steps,
        impact_description: format!(
            "Privilege escalation from {} to {} via {} manipulation on {}",
            finding.privilege_level,
            target_privilege,
            finding.vulnerable_parameter,
            finding.endpoint
        ),
        risk_score: 9.0,
    }
}

/// Generate a bulk enumeration chain: iterate through the entire ID space.
pub fn generate_bulk_enumeration(
    finding: &IdorFinding,
    range_start: u64,
    range_end: u64,
    step_size: u64,
) -> ExploitationChain {
    let count = if range_end > range_start && step_size > 0 {
        (range_end - range_start) / step_size
    } else {
        0
    };

    let steps = vec![
        ExploitationStep {
            step_number: 1,
            description: "Establish authenticated session and confirm base access".to_string(),
            endpoint: finding.endpoint.clone(),
            method: finding.method,
            parameter: finding.vulnerable_parameter.clone(),
            payload: finding.observed_id.clone(),
            expected_outcome: "Confirmed access to own resource; baseline response captured"
                .to_string(),
        },
        ExploitationStep {
            step_number: 2,
            description: format!(
                "Enumerate {} from {} to {} (step {})",
                finding.vulnerable_parameter, range_start, range_end, step_size
            ),
            endpoint: finding.endpoint.clone(),
            method: finding.method,
            parameter: finding.vulnerable_parameter.clone(),
            payload: format!("{}..{}", range_start, range_end),
            expected_outcome: format!(
                "Up to {} {} records exfiltrated",
                count, finding.resource_type
            ),
        },
        ExploitationStep {
            step_number: 3,
            description: "Differentiate valid from invalid IDs by response status/body size"
                .to_string(),
            endpoint: finding.endpoint.clone(),
            method: finding.method,
            parameter: finding.vulnerable_parameter.clone(),
            payload: "compare_responses".to_string(),
            expected_outcome: "Map of valid IDs with response fingerprints".to_string(),
        },
        ExploitationStep {
            step_number: 4,
            description: "Extract and aggregate collected data".to_string(),
            endpoint: finding.endpoint.clone(),
            method: finding.method,
            parameter: finding.vulnerable_parameter.clone(),
            payload: "batch_export".to_string(),
            expected_outcome: format!(
                "Complete dump of accessible {} records",
                finding.resource_type
            ),
        },
    ];

    ExploitationChain {
        pattern_type: IdorPatternType::BulkEnumeration,
        finding: finding.clone(),
        steps,
        impact_description: format!(
            "Mass data exfiltration of {} records via sequential {} enumeration ({} to {})",
            finding.resource_type, finding.vulnerable_parameter, range_start, range_end
        ),
        risk_score: 8.5,
    }
}

/// Generate a cross-object reference chain using a pre-built CrossObjectGraph.
pub fn generate_cross_object_chain(
    finding: &IdorFinding,
    graph: &CrossObjectGraph,
    max_depth: usize,
) -> Vec<ExploitationChain> {
    let chains = graph.find_chains(&finding.resource_type, max_depth);
    chains
        .into_iter()
        .map(|chain_path| {
            let mut steps = Vec::new();
            steps.push(ExploitationStep {
                step_number: 1,
                description: format!("Obtain {} ID via {}", chain_path[0], finding.endpoint),
                endpoint: finding.endpoint.clone(),
                method: finding.method,
                parameter: finding.vulnerable_parameter.clone(),
                payload: finding.observed_id.clone(),
                expected_outcome: format!("Confirmed {} identifier", chain_path[0]),
            });

            for (i, window) in chain_path.windows(2).enumerate() {
                let source = &window[0];
                let target = &window[1];
                steps.push(ExploitationStep {
                    step_number: (2 + i) as u32,
                    description: format!(
                        "Traverse from {} to {} via object reference",
                        source, target
                    ),
                    endpoint: format!("/api/{}s/{{id}}", target.to_lowercase()),
                    method: IdorHttpMethod::Get,
                    parameter: format!("{}_id", source.to_lowercase()),
                    payload: format!("{{extracted_{}_id}}", source.to_lowercase()),
                    expected_outcome: format!("Access to {} linked from {}", target, source),
                });
            }

            let chain_description = chain_path.join(" → ");
            ExploitationChain {
                pattern_type: IdorPatternType::CrossObjectReference,
                finding: finding.clone(),
                steps,
                impact_description: format!(
                    "Cross-object IDOR chain: {}; starting from {}",
                    chain_description, finding.endpoint
                ),
                risk_score: 8.0 + (chain_path.len() as f64 - 2.0) * 0.5,
            }
        })
        .collect()
}

/// Analyze a UUID v1 string: extract timestamp, clock sequence, MAC, and predict next UUIDs.
pub fn analyze_uuid_v1(uuid_str: &str) -> Option<UuidV1Analysis> {
    let hex: String = uuid_str.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }

    let version_nibble = u8::from_str_radix(&hex[12..13], 16).ok()?;
    if version_nibble != 1 {
        return None;
    }

    let time_low = u32::from_str_radix(&hex[0..8], 16).ok()? as u64;
    let time_mid = u16::from_str_radix(&hex[8..12], 16).ok()? as u64;
    let time_hi = u16::from_str_radix(&hex[13..16], 16).ok()? as u64;

    let timestamp = time_low | (time_mid << 32) | (time_hi << 48);

    let clk_hi = u8::from_str_radix(&hex[16..18], 16).ok()?;
    let clk_lo = u8::from_str_radix(&hex[18..20], 16).ok()?;
    let clock_sequence = (((clk_hi & 0x3F) as u16) << 8) | (clk_lo as u16);

    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[i] = u8::from_str_radix(&hex[20 + i * 2..22 + i * 2], 16).ok()?;
    }

    let mut predicted = Vec::new();
    for offset in 1..=3u64 {
        let next_ts = timestamp.wrapping_add(offset * 1000);
        predicted.push(format_uuid_v1(next_ts, clock_sequence, &mac));
    }

    Some(UuidV1Analysis {
        raw_uuid: uuid_str.to_string(),
        timestamp_100ns: timestamp,
        clock_sequence,
        mac_address: mac,
        predicted_next: predicted,
    })
}

/// Reconstruct a UUID v1 from timestamp, clock sequence, and MAC.
fn format_uuid_v1(timestamp: u64, clock_seq: u16, mac: &[u8; 6]) -> String {
    let time_low = (timestamp & 0xFFFF_FFFF) as u32;
    let time_mid = ((timestamp >> 32) & 0xFFFF) as u16;
    let time_hi = ((timestamp >> 48) & 0x0FFF) as u16;
    let time_hi_version = time_hi | 0x1000;
    let clk_hi = ((clock_seq >> 8) & 0x3F) as u8 | 0x80;
    let clk_lo = (clock_seq & 0xFF) as u8;

    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        time_low,
        time_mid,
        time_hi_version,
        clk_hi,
        clk_lo,
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    )
}

/// Generate a UUID prediction exploitation chain.
pub fn generate_uuid_prediction_chain(
    finding: &IdorFinding,
    analysis: &UuidV1Analysis,
) -> ExploitationChain {
    let mut steps = vec![
        ExploitationStep {
            step_number: 1,
            description: "Capture UUID v1 from legitimate resource creation".to_string(),
            endpoint: finding.endpoint.clone(),
            method: IdorHttpMethod::Post,
            parameter: finding.vulnerable_parameter.clone(),
            payload: analysis.raw_uuid.clone(),
            expected_outcome: "UUID v1 captured with embedded timestamp and MAC".to_string(),
        },
        ExploitationStep {
            step_number: 2,
            description: format!(
                "Extract timestamp ({}), clock_seq ({}), MAC ({:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
                analysis.timestamp_100ns,
                analysis.clock_sequence,
                analysis.mac_address[0],
                analysis.mac_address[1],
                analysis.mac_address[2],
                analysis.mac_address[3],
                analysis.mac_address[4],
                analysis.mac_address[5],
            ),
            endpoint: finding.endpoint.clone(),
            method: finding.method,
            parameter: "analysis".to_string(),
            payload: "uuid_v1_decompose".to_string(),
            expected_outcome: "Temporal and hardware components extracted".to_string(),
        },
    ];

    for (i, predicted_uuid) in analysis.predicted_next.iter().enumerate() {
        steps.push(ExploitationStep {
            step_number: (3 + i) as u32,
            description: format!("Probe predicted UUID #{}", i + 1),
            endpoint: finding.endpoint.clone(),
            method: finding.method,
            parameter: finding.vulnerable_parameter.clone(),
            payload: predicted_uuid.clone(),
            expected_outcome: format!(
                "Access to {} created near the observed UUID's timestamp",
                finding.resource_type
            ),
        });
    }

    ExploitationChain {
        pattern_type: IdorPatternType::UuidPrediction,
        finding: finding.clone(),
        steps,
        impact_description: format!(
            "UUID v1 prediction on {} enables enumeration of {} via timestamp+MAC analysis",
            finding.endpoint, finding.resource_type
        ),
        risk_score: 7.0,
    }
}

/// Generate GraphQL IDOR traversal chains through nested object fields.
pub fn generate_graphql_idor_chain(
    finding: &IdorFinding,
    traversal_paths: &[GraphQlTraversalPath],
) -> ExploitationChain {
    let mut steps = vec![ExploitationStep {
        step_number: 1,
        description: "Introspect GraphQL schema to map object relationships".to_string(),
        endpoint: finding.endpoint.clone(),
        method: IdorHttpMethod::Post,
        parameter: "query".to_string(),
        payload: "{ __schema { types { name fields { name type { name } } } } }".to_string(),
        expected_outcome: "Full schema map with nested object types exposed".to_string(),
    }];

    for (i, path) in traversal_paths.iter().enumerate() {
        let nested_query = build_graphql_nested_query(path);
        let vars: Vec<String> = path
            .requires_variables
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        let var_desc = if vars.is_empty() {
            "none".to_string()
        } else {
            vars.join(", ")
        };

        steps.push(ExploitationStep {
            step_number: (2 + i) as u32,
            description: format!(
                "Traverse nested path: {} → {}",
                path.query_path.join("."),
                path.target_field
            ),
            endpoint: finding.endpoint.clone(),
            method: IdorHttpMethod::Post,
            parameter: "query".to_string(),
            payload: nested_query,
            expected_outcome: format!(
                "Unauthorized access to {} (variables: {})",
                path.target_field, var_desc
            ),
        });
    }

    ExploitationChain {
        pattern_type: IdorPatternType::GraphQlIdor,
        finding: finding.clone(),
        steps,
        impact_description: format!(
            "GraphQL nested traversal IDOR on {} exposes {} paths to unauthorized data",
            finding.endpoint,
            traversal_paths.len()
        ),
        risk_score: 8.0,
    }
}

fn build_graphql_nested_query(path: &GraphQlTraversalPath) -> String {
    if path.query_path.is_empty() {
        return format!("{{ {} }}", path.target_field);
    }

    let mut query = format!("{{ {} }}", path.target_field);
    for segment in path.query_path.iter().rev() {
        query = format!("{{ {} {} }}", segment, query);
    }
    query
}

/// Build a parameter tampering matrix for a set of endpoints.
pub fn build_tampering_matrix(entries: Vec<TamperingMatrixEntry>) -> ParameterTamperingMatrix {
    ParameterTamperingMatrix { entries }
}

/// Matrix of which parameters are IDOR-vulnerable per endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct ParameterTamperingMatrix {
    pub entries: Vec<TamperingMatrixEntry>,
}

impl ParameterTamperingMatrix {
    /// Return all confirmed-vulnerable endpoints.
    pub fn confirmed_vulnerabilities(&self) -> Vec<(&str, &str)> {
        let mut result = Vec::new();
        for entry in &self.entries {
            for vuln in &entry.vulnerabilities {
                if vuln.confirmed {
                    result.push((entry.endpoint.as_str(), vuln.parameter.as_str()));
                }
            }
        }
        result
    }

    /// Return endpoints vulnerable to a specific ID type.
    pub fn by_id_type(&self, target_type: IdType) -> Vec<(&str, &str)> {
        let mut result = Vec::new();
        for entry in &self.entries {
            for vuln in &entry.vulnerabilities {
                if vuln.id_type == target_type {
                    result.push((entry.endpoint.as_str(), vuln.parameter.as_str()));
                }
            }
        }
        result
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn total_vulnerabilities(&self) -> usize {
        self.entries.iter().map(|e| e.vulnerabilities.len()).sum()
    }
}

/// Generate a parameter tampering exploitation chain from the matrix.
pub fn generate_parameter_tampering_chain(
    finding: &IdorFinding,
    matrix: &ParameterTamperingMatrix,
) -> ExploitationChain {
    let mut steps = vec![ExploitationStep {
        step_number: 1,
        description: "Map all endpoints with ID parameters in request".to_string(),
        endpoint: finding.endpoint.clone(),
        method: finding.method,
        parameter: finding.vulnerable_parameter.clone(),
        payload: "parameter_discovery".to_string(),
        expected_outcome: format!(
            "Identified {} endpoints with {} total ID parameters",
            matrix.entry_count(),
            matrix.total_vulnerabilities()
        ),
    }];

    let confirmed = matrix.confirmed_vulnerabilities();
    for (i, (endpoint, param)) in confirmed.iter().enumerate().take(5) {
        steps.push(ExploitationStep {
            step_number: (2 + i) as u32,
            description: format!("Tamper {} on {}", param, endpoint),
            endpoint: endpoint.to_string(),
            method: finding.method,
            parameter: param.to_string(),
            payload: "substituted_id".to_string(),
            expected_outcome: format!("Unauthorized access via {} manipulation", param),
        });
    }

    ExploitationChain {
        pattern_type: IdorPatternType::ParameterTampering,
        finding: finding.clone(),
        steps,
        impact_description: format!(
            "Parameter tampering across {} endpoints; {} confirmed IDOR-vulnerable parameters",
            matrix.entry_count(),
            confirmed.len()
        ),
        risk_score: 7.0,
    }
}

/// Detect the encoding scheme of an indirect reference value.
pub fn detect_indirect_encoding(value: &str) -> Option<IndirectEncoding> {
    if value.contains('.') && value.split('.').count() == 3 {
        let parts: Vec<&str> = value.split('.').collect();
        let all_b64 = parts.iter().all(|p| {
            p.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        });
        if all_b64 {
            return Some(IndirectEncoding::Jwt);
        }
    }

    if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(IndirectEncoding::Sha256Truncated);
    }

    if value.len() >= 40 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(IndirectEncoding::Hmac);
    }

    if value.chars().all(|c| c.is_ascii_digit()) && value.len() >= 4 {
        return Some(IndirectEncoding::RotatingNumeric);
    }

    if value.len() > 4 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(IndirectEncoding::Hex);
    }

    if value.ends_with('=') || (value.len() > 4 && is_base64_chars(value)) {
        return Some(IndirectEncoding::Base64);
    }

    None
}

fn is_base64_chars(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

/// Generate an indirect reference mapping exploitation chain.
pub fn generate_indirect_reference_chain(
    finding: &IdorFinding,
    mappings: &[IndirectReferenceMap],
) -> ExploitationChain {
    let mut steps = vec![ExploitationStep {
        step_number: 1,
        description: "Collect multiple encoded reference values from API responses".to_string(),
        endpoint: finding.endpoint.clone(),
        method: finding.method,
        parameter: finding.vulnerable_parameter.clone(),
        payload: finding.observed_id.clone(),
        expected_outcome: "Corpus of encoded identifiers for pattern analysis".to_string(),
    }];

    for (i, mapping) in mappings.iter().enumerate() {
        steps.push(ExploitationStep {
            step_number: (2 + i) as u32,
            description: format!(
                "Decode {} reference: {} → [{}]",
                mapping.encoding,
                mapping.encoded_value,
                mapping.decoded_components.join(", ")
            ),
            endpoint: finding.endpoint.clone(),
            method: finding.method,
            parameter: finding.vulnerable_parameter.clone(),
            payload: format!("pattern: {}", mapping.predicted_pattern),
            expected_outcome: format!(
                "Generate valid encoded IDs matching {} pattern",
                mapping.encoding
            ),
        });
    }

    ExploitationChain {
        pattern_type: IdorPatternType::IndirectReferenceMapping,
        finding: finding.clone(),
        steps,
        impact_description: format!(
            "Indirect reference cracking on {} via {} mappings analyzed",
            finding.endpoint,
            mappings.len()
        ),
        risk_score: 6.5,
    }
}

/// Generate all applicable exploitation chains for a given finding.
pub fn generate_all_chains(
    finding: &IdorFinding,
    graph: Option<&CrossObjectGraph>,
    uuid_analysis: Option<&UuidV1Analysis>,
    graphql_paths: Option<&[GraphQlTraversalPath]>,
    matrix: Option<&ParameterTamperingMatrix>,
    indirect_maps: Option<&[IndirectReferenceMap]>,
) -> Vec<ExploitationChain> {
    let mut chains = Vec::new();

    chains.push(generate_horizontal_escalation(finding));
    chains.push(generate_vertical_escalation(finding, PrivilegeLevel::Admin));
    chains.push(generate_bulk_enumeration(finding, 1, 10000, 1));

    if let Some(g) = graph {
        chains.extend(generate_cross_object_chain(finding, g, 4));
    }

    if let Some(analysis) = uuid_analysis {
        chains.push(generate_uuid_prediction_chain(finding, analysis));
    }

    if let Some(paths) = graphql_paths
        && !paths.is_empty()
    {
        chains.push(generate_graphql_idor_chain(finding, paths));
    }

    if let Some(m) = matrix {
        chains.push(generate_parameter_tampering_chain(finding, m));
    }

    if let Some(maps) = indirect_maps
        && !maps.is_empty()
    {
        chains.push(generate_indirect_reference_chain(finding, maps));
    }

    chains
}
