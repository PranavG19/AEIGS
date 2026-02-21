use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::request::{FuzzRequest, FuzzResponse};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A configured response pattern for the mock transport.
#[derive(Debug, Clone)]
struct ResponseRule {
    endpoint_pattern: String,
    status: u16,
    body: String,
    headers: Vec<(String, String)>,
}

/// Simulated WAF blocking configuration.
#[derive(Debug, Clone)]
struct WafBlockConfig {
    vendor: String,
    blocked_classes: Vec<VulnerabilityClass>,
}

/// Simulated rate limit configuration.
#[derive(Debug, Clone)]
struct RateLimitConfig {
    max_rps: u32,
    status_code: u16,
}

/// A mock HTTP transport that records requests and returns configured responses.
///
/// Does not implement the async `FuzzTransport` trait — instead provides a
/// simpler synchronous interface for unit/integration test assertions.
pub struct MockFuzzTransport {
    rules: Vec<ResponseRule>,
    waf: Option<WafBlockConfig>,
    rate_limit: Option<RateLimitConfig>,
    requests: Arc<Mutex<Vec<FuzzRequest>>>,
}

impl MockFuzzTransport {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            waf: None,
            rate_limit: None,
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Configures a canned response for requests matching `endpoint_pattern`
    /// (substring match).
    pub fn with_response(
        mut self,
        endpoint_pattern: &str,
        status: u16,
        body: &str,
        headers: Vec<(String, String)>,
    ) -> Self {
        self.rules.push(ResponseRule {
            endpoint_pattern: endpoint_pattern.to_string(),
            status,
            body: body.to_string(),
            headers,
        });
        self
    }

    /// Simulates a WAF that blocks payloads targeting the given vuln classes.
    pub fn with_waf_block(
        mut self,
        vendor: &str,
        blocked_classes: Vec<VulnerabilityClass>,
    ) -> Self {
        self.waf = Some(WafBlockConfig {
            vendor: vendor.to_string(),
            blocked_classes,
        });
        self
    }

    /// Simulates rate limiting: after `rps` requests, subsequent calls return
    /// `status_code` (typically 429).
    pub fn with_rate_limit(mut self, rps: u32, status_code: u16) -> Self {
        self.rate_limit = Some(RateLimitConfig {
            max_rps: rps,
            status_code,
        });
        self
    }

    /// Returns all requests that have been sent through this transport.
    pub fn requests(&self) -> Vec<FuzzRequest> {
        self.requests.lock().unwrap().clone()
    }

    /// Returns the number of requests sent.
    pub fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    /// Simulates sending a fuzz request and returns a configured response.
    pub fn send(&self, request: FuzzRequest) -> FuzzResponse {
        let mut reqs = self.requests.lock().unwrap();
        reqs.push(request.clone());

        if let Some(ref rl) = self.rate_limit
            && reqs.len() > rl.max_rps as usize
        {
            return FuzzResponse {
                request_id: request.request_id,
                status_code: rl.status_code,
                body: "Rate limit exceeded".to_string(),
                headers: vec![("Retry-After".to_string(), "60".to_string())],
                response_time: Duration::from_millis(1),
                body_size_bytes: 19,
            };
        }

        if let Some(ref waf) = self.waf {
            let payload_lower = request.payload.to_lowercase();
            let is_blocked = waf.blocked_classes.iter().any(|class| {
                matches!(
                    class,
                    VulnerabilityClass::SqlInjection
                        if payload_lower.contains("select")
                            || payload_lower.contains("union")
                            || payload_lower.contains("'")
                ) || matches!(
                    class,
                    VulnerabilityClass::CrossSiteScripting
                        if payload_lower.contains("<script")
                            || payload_lower.contains("onerror")
                ) || matches!(
                    class,
                    VulnerabilityClass::CommandInjection
                        if payload_lower.contains(";")
                            || payload_lower.contains("|")
                )
            });

            if is_blocked {
                return FuzzResponse {
                    request_id: request.request_id,
                    status_code: 403,
                    body: format!("Blocked by {} WAF", waf.vendor),
                    headers: vec![("X-WAF-Block".to_string(), waf.vendor.clone())],
                    response_time: Duration::from_millis(2),
                    body_size_bytes: 20 + waf.vendor.len(),
                };
            }
        }

        for rule in &self.rules {
            if request.endpoint.contains(&rule.endpoint_pattern) {
                return FuzzResponse {
                    request_id: request.request_id,
                    status_code: rule.status,
                    body: rule.body.clone(),
                    headers: rule.headers.clone(),
                    response_time: Duration::from_millis(5),
                    body_size_bytes: rule.body.len(),
                };
            }
        }

        FuzzResponse {
            request_id: request.request_id,
            status_code: 200,
            body: "OK".to_string(),
            headers: vec![],
            response_time: Duration::from_millis(1),
            body_size_bytes: 2,
        }
    }
}

impl Default for MockFuzzTransport {
    fn default() -> Self {
        Self::new()
    }
}
