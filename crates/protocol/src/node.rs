use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

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
    Defense,
}

impl fmt::Display for NodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeType::Endpoint => write!(f, "Endpoint"),
            NodeType::Function => write!(f, "Function"),
            NodeType::DataStore => write!(f, "Data Store"),
            NodeType::Role => write!(f, "Role"),
            NodeType::Dependency => write!(f, "Dependency"),
            NodeType::Config => write!(f, "Configuration"),
            NodeType::User => write!(f, "User"),
            NodeType::Service => write!(f, "Service"),
            NodeType::Defense => write!(f, "Defense"),
        }
    }
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
