use std::time::Instant;

use crate::types::RecordedExchange;

/// A request with optionally modified fields for replay.
#[derive(Debug, Clone)]
pub struct ModifiedRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ModifiedRequest {
    pub fn from_exchange(exchange: &RecordedExchange) -> Self {
        Self {
            method: exchange.request_method.clone(),
            url: exchange.request_url.clone(),
            headers: exchange.request_headers.clone(),
            body: exchange.request_body.clone(),
        }
    }
}

/// Result of replaying a request, bundled with the original exchange for comparison.
#[derive(Debug, Clone)]
pub struct RepeaterResult {
    pub original: RecordedExchange,
    pub modified_request: ModifiedRequest,
    pub response_status: u16,
    pub response_headers: Vec<(String, String)>,
    pub response_body: Vec<u8>,
    pub duration_ms: u64,
}

/// Sends individual HTTP requests, optionally with modifications, for manual replay.
pub struct Repeater {
    client: reqwest::Client,
}

impl Repeater {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build reqwest client");
        Self { client }
    }

    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }

    pub async fn repeat(
        &self,
        exchange: &RecordedExchange,
        modifications: Option<ModifiedRequest>,
    ) -> Result<RepeaterResult, reqwest::Error> {
        let req = modifications.unwrap_or_else(|| ModifiedRequest::from_exchange(exchange));
        let (status, headers, body, duration_ms) = self.send_request(&req).await?;
        Ok(RepeaterResult {
            original: exchange.clone(),
            modified_request: req,
            response_status: status,
            response_headers: headers,
            response_body: body,
            duration_ms,
        })
    }

    async fn send_request(
        &self,
        req: &ModifiedRequest,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>, u64), reqwest::Error> {
        let method =
            reqwest::Method::from_bytes(req.method.as_bytes()).unwrap_or(reqwest::Method::GET);
        let start = Instant::now();
        let mut builder = self.client.request(method, &req.url);
        for (name, value) in &req.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        if !req.body.is_empty() {
            builder = builder.body(req.body.clone());
        }
        let resp = builder.send().await?;
        let elapsed = start.elapsed().as_millis() as u64;
        let status = resp.status().as_u16();
        let resp_headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = resp.bytes().await?.to_vec();
        Ok((status, resp_headers, body, elapsed))
    }
}

impl Default for Repeater {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "repeater_test.rs"]
mod repeater_test;
