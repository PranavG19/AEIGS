use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeType {
    Endpoint,
    Function,
    DataStore,
    Role,
    Dependency,
    Config,
    User,
    Service,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeData {
    pub id: u64,
    pub node_type: NodeType,
    pub properties: HashMap<String, String>,
}

impl NodeData {
    pub fn new(id: u64, node_type: NodeType) -> Self {
        Self {
            id,
            node_type,
            properties: HashMap::new(),
        }
    }

    pub fn with_property(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.properties.insert(key.into(), value.into());
        self
    }
}
