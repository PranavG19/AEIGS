use std::time::Duration;

/// HTTP response from a discovery request.
#[derive(Debug, Clone)]
pub struct DiscoveryResponse {
    pub status_code: u16,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
    pub headers: Vec<(String, String)>,
}

/// Trait for HTTP clients used by discovery modules.
///
/// Abstracts the HTTP layer so modules can work with either bare reqwest
/// (default) or an evasion-aware transport from aegis-evasion-engine.
/// The blocking interface matches the existing synchronous discovery modules.
pub trait DiscoveryHttpClient: Send + Sync {
    fn get(&self, url: &str) -> Result<DiscoveryResponse, String>;
    fn head(&self, url: &str) -> Result<DiscoveryResponse, String>;
    fn get_with_headers(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<DiscoveryResponse, String>;
}

/// Default blocking HTTP client wrapping `reqwest::blocking::Client`.
pub struct DefaultDiscoveryClient {
    client: reqwest::blocking::Client,
}

impl DefaultDiscoveryClient {
    pub fn new() -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build HTTP client");
        Self { client }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build HTTP client");
        Self { client }
    }

    pub fn with_accept_invalid_certs(timeout: Duration) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(true)
            .build()
            .expect("failed to build HTTP client");
        Self { client }
    }
}

impl Default for DefaultDiscoveryClient {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscoveryHttpClient for DefaultDiscoveryClient {
    fn get(&self, url: &str) -> Result<DiscoveryResponse, String> {
        let resp = self.client.get(url).send().map_err(|e| e.to_string())?;
        map_blocking_response(resp)
    }

    fn head(&self, url: &str) -> Result<DiscoveryResponse, String> {
        let resp = self.client.head(url).send().map_err(|e| e.to_string())?;
        map_blocking_response(resp)
    }

    fn get_with_headers(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<DiscoveryResponse, String> {
        let mut builder = self.client.get(url);
        for (key, value) in headers {
            builder = builder.header(key.as_str(), value.as_str());
        }
        let resp = builder.send().map_err(|e| e.to_string())?;
        map_blocking_response(resp)
    }
}

fn map_blocking_response(resp: reqwest::blocking::Response) -> Result<DiscoveryResponse, String> {
    let status_code = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|val| (k.as_str().to_string(), val.to_string()))
        })
        .collect();
    let body = resp.bytes().map_err(|e| e.to_string())?.to_vec();
    Ok(DiscoveryResponse {
        status_code,
        body,
        content_type,
        headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_client_creates_successfully() {
        let client = DefaultDiscoveryClient::new();
        let _ = client;
    }

    #[test]
    fn with_timeout_creates_successfully() {
        let client = DefaultDiscoveryClient::with_timeout(Duration::from_secs(5));
        let _ = client;
    }

    #[test]
    fn with_accept_invalid_certs_creates_successfully() {
        let client = DefaultDiscoveryClient::with_accept_invalid_certs(Duration::from_secs(5));
        let _ = client;
    }
}
