use std::time::Duration;

#[derive(Debug, Clone)]
pub struct FuzzRequest {
    pub request_id: u64,
    pub endpoint: String,
    pub method: String,
    pub parameter_name: String,
    pub payload: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct FuzzResponse {
    pub request_id: u64,
    pub status_code: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
    pub response_time: Duration,
    pub body_size_bytes: usize,
}
