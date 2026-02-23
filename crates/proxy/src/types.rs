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
}

/// Configuration for the recording proxy.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub listen_addr: SocketAddr,
    pub max_log_size: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: ([127, 0, 0, 1], 8080).into(),
            max_log_size: 10_000,
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
}

#[cfg(test)]
#[path = "types_test.rs"]
mod types_test;
