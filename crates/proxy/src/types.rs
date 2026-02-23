use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// A recorded HTTP request/response pair captured by the proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedExchange {
    pub id: u64,
    pub request_method: String,
    pub request_url: String,
    pub request_headers: Vec<(String, String)>,
    pub request_body: Vec<u8>,
    pub response_status: u16,
    pub response_headers: Vec<(String, String)>,
    pub response_body: Vec<u8>,
    pub timestamp_ms: u64,
    pub duration_ms: u64,
    #[serde(default = "default_in_scope")]
    pub in_scope: bool,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_in_scope() -> bool {
    true
}

/// Configuration for the recording proxy.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub listen_addr: SocketAddr,
    pub max_log_size: usize,
    pub db_path: Option<std::path::PathBuf>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: ([127, 0, 0, 1], 8080).into(),
            max_log_size: 10_000,
            db_path: None,
        }
    }
}

impl ProxyConfig {
    pub fn with_listen_addr(mut self, addr: SocketAddr) -> Self {
        self.listen_addr = addr;
        self
    }

    pub fn with_max_log_size(mut self, max: usize) -> Self {
        self.max_log_size = max;
        self
    }

    pub fn with_db_path(mut self, path: std::path::PathBuf) -> Self {
        self.db_path = Some(path);
        self
    }
}

#[cfg(test)]
#[path = "types_test.rs"]
mod types_test;
