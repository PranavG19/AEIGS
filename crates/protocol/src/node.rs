use serde::{Deserialize, Serialize};

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
