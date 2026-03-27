use std::collections::HashMap;
use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;

/// Errors from live API calls.
#[derive(Debug)]
pub enum LiveApiError {
    Http(String),
    Timeout(String),
    RateLimited,
    Unauthorized(String),
    ParseError(String),
}

impl std::fmt::Display for LiveApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(msg) => write!(f, "HTTP error: {msg}"),
            Self::Timeout(msg) => write!(f, "timeout: {msg}"),
            Self::RateLimited => write!(f, "rate limited"),
            Self::Unauthorized(msg) => write!(f, "unauthorized: {msg}"),
            Self::ParseError(msg) => write!(f, "parse error: {msg}"),
        }
    }
}

impl std::error::Error for LiveApiError {}

/// Live Shodan API client.
pub struct ShodanLiveClient {
    client: Client,
    api_key: String,
}

impl ShodanLiveClient {
    pub fn new(api_key: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");
        Self {
            client,
            api_key: api_key.to_string(),
        }
    }

    /// GET https://api.shodan.io/shodan/host/{ip}?key={api_key}
    pub async fn host_info(&self, ip: &str) -> Result<String, LiveApiError> {
        let url = format!(
            "https://api.shodan.io/shodan/host/{}?key={}",
            ip, self.api_key
        );
        self.get(&url).await
    }

    /// GET https://api.shodan.io/shodan/host/search?query={query}&key={api_key}
    pub async fn search(&self, query: &str) -> Result<String, LiveApiError> {
        let url = format!(
            "https://api.shodan.io/shodan/host/search?query={}&key={}",
            urlencoding::encode(query),
            self.api_key
        );
        self.get(&url).await
    }

    async fn get(&self, url: &str) -> Result<String, LiveApiError> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    LiveApiError::Timeout(e.to_string())
                } else {
                    LiveApiError::Http(e.to_string())
                }
            })?;

        match resp.status().as_u16() {
            401 => return Err(LiveApiError::Unauthorized("invalid API key".to_string())),
            429 => return Err(LiveApiError::RateLimited),
            _ => {}
        }

        resp.text()
            .await
            .map_err(|e| LiveApiError::Http(e.to_string()))
    }
}

/// Live crt.sh Certificate Transparency client.
pub struct CrtShLiveClient {
    client: Client,
}

impl CrtShLiveClient {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");
        Self { client }
    }

    /// GET https://crt.sh/?q={domain}&output=json
    pub async fn query_domain(&self, domain: &str) -> Result<String, LiveApiError> {
        let url = format!(
            "https://crt.sh/?q={}&output=json",
            urlencoding::encode(domain)
        );
        let resp = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| LiveApiError::Http(e.to_string()))?;

        resp.text()
            .await
            .map_err(|e| LiveApiError::Http(e.to_string()))
    }
}

impl Default for CrtShLiveClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Live Have I Been Pwned / k-anonymity client.
pub struct BreachCorrelatorClient {
    client: Client,
}

impl BreachCorrelatorClient {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("failed to build HTTP client");
        Self { client }
    }

    /// GET https://api.pwnedpasswords.com/range/{prefix}
    /// Uses k-anonymity: only send first 5 chars of SHA1 hash.
    pub async fn check_password_prefix(&self, sha1_prefix: &str) -> Result<String, LiveApiError> {
        let prefix = &sha1_prefix[..5.min(sha1_prefix.len())];
        let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
        let resp = self
            .client
            .get(&url)
            .header("Add-Padding", "true")
            .send()
            .await
            .map_err(|e| LiveApiError::Http(e.to_string()))?;

        if resp.status().as_u16() == 429 {
            return Err(LiveApiError::RateLimited);
        }

        resp.text()
            .await
            .map_err(|e| LiveApiError::Http(e.to_string()))
    }
}

impl Default for BreachCorrelatorClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Live GitHub API client for code/secret scanning.
pub struct GitHubLiveClient {
    client: Client,
    token: Option<String>,
}

impl GitHubLiveClient {
    pub fn new(token: Option<&str>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");
        Self {
            client,
            token: token.map(String::from),
        }
    }

    /// Search code: GET https://api.github.com/search/code?q={query}
    pub async fn search_code(&self, query: &str) -> Result<String, LiveApiError> {
        let url = format!(
            "https://api.github.com/search/code?q={}",
            urlencoding::encode(query)
        );
        self.get_github(&url).await
    }

    /// Search repos: GET https://api.github.com/search/repositories?q={query}
    pub async fn search_repos(&self, query: &str) -> Result<String, LiveApiError> {
        let url = format!(
            "https://api.github.com/search/repositories?q={}",
            urlencoding::encode(query)
        );
        self.get_github(&url).await
    }

    /// Get user info: GET https://api.github.com/users/{username}
    pub async fn user_info(&self, username: &str) -> Result<String, LiveApiError> {
        let url = format!("https://api.github.com/users/{}", username);
        self.get_github(&url).await
    }

    async fn get_github(&self, url: &str) -> Result<String, LiveApiError> {
        let mut builder = self
            .client
            .get(url)
            .header("Accept", "application/vnd.github.v3+json")
            .header("User-Agent", "aegis-scanner/1.0");

        if let Some(ref token) = self.token {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }

        let resp = builder.send().await.map_err(|e| {
            if e.is_timeout() {
                LiveApiError::Timeout(e.to_string())
            } else {
                LiveApiError::Http(e.to_string())
            }
        })?;

        match resp.status().as_u16() {
            401 => return Err(LiveApiError::Unauthorized("invalid token".to_string())),
            403 | 429 => return Err(LiveApiError::RateLimited),
            _ => {}
        }

        resp.text()
            .await
            .map_err(|e| LiveApiError::Http(e.to_string()))
    }
}

/// Live cloud bucket enumeration via HEAD requests.
pub struct CloudEnumLiveClient {
    client: Client,
}

impl CloudEnumLiveClient {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build HTTP client");
        Self { client }
    }

    /// HEAD check for S3 bucket: https://{bucket}.s3.amazonaws.com/
    pub async fn check_s3_bucket(&self, bucket: &str) -> Result<(u16, Option<String>), LiveApiError> {
        let url = format!("https://{}.s3.amazonaws.com/", bucket);
        self.head_check(&url).await
    }

    /// HEAD check for GCS bucket: https://storage.googleapis.com/{bucket}/
    pub async fn check_gcs_bucket(&self, bucket: &str) -> Result<(u16, Option<String>), LiveApiError> {
        let url = format!("https://storage.googleapis.com/{}/", bucket);
        self.head_check(&url).await
    }

    /// HEAD check for Azure blob: https://{account}.blob.core.windows.net/{container}
    pub async fn check_azure_blob(
        &self,
        account: &str,
        container: &str,
    ) -> Result<(u16, Option<String>), LiveApiError> {
        let url = format!(
            "https://{}.blob.core.windows.net/{}/",
            account, container
        );
        self.head_check(&url).await
    }

    async fn head_check(&self, url: &str) -> Result<(u16, Option<String>), LiveApiError> {
        let resp = self
            .client
            .head(url)
            .send()
            .await
            .map_err(|e| LiveApiError::Http(e.to_string()))?;

        let status = resp.status().as_u16();
        let server = resp
            .headers()
            .get("server")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        Ok((status, server))
    }
}

impl Default for CloudEnumLiveClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Live SMTP email validator using tokio TCP.
pub struct EmailValidatorLiveClient {
    timeout: Duration,
}

impl EmailValidatorLiveClient {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Validate an email by connecting to the MX server and issuing SMTP RCPT TO.
    /// Returns (accepted, smtp_code, smtp_response).
    pub async fn validate_email(
        &self,
        email: &str,
        mx_host: &str,
    ) -> Result<(bool, u16, String), LiveApiError> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpStream;

        let addr = format!("{mx_host}:25");
        let stream = tokio::time::timeout(self.timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| LiveApiError::Timeout(format!("connecting to {addr}")))?
            .map_err(|e| LiveApiError::Http(e.to_string()))?;

        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        reader
            .read_line(&mut line)
            .await
            .map_err(|e| LiveApiError::Http(e.to_string()))?;

        writer
            .write_all(b"EHLO aegis.local\r\n")
            .await
            .map_err(|e| LiveApiError::Http(e.to_string()))?;
        line.clear();
        loop {
            reader
                .read_line(&mut line)
                .await
                .map_err(|e| LiveApiError::Http(e.to_string()))?;
            if line.chars().nth(3) == Some(' ') {
                break;
            }
            line.clear();
        }

        writer
            .write_all(format!("MAIL FROM:<verify@aegis.local>\r\n").as_bytes())
            .await
            .map_err(|e| LiveApiError::Http(e.to_string()))?;
        line.clear();
        reader
            .read_line(&mut line)
            .await
            .map_err(|e| LiveApiError::Http(e.to_string()))?;

        writer
            .write_all(format!("RCPT TO:<{email}>\r\n").as_bytes())
            .await
            .map_err(|e| LiveApiError::Http(e.to_string()))?;
        line.clear();
        reader
            .read_line(&mut line)
            .await
            .map_err(|e| LiveApiError::Http(e.to_string()))?;

        let code = line
            .get(..3)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        let accepted = code == 250;

        let _ = writer.write_all(b"QUIT\r\n").await;

        Ok((accepted, code, line.trim().to_string()))
    }
}

impl Default for EmailValidatorLiveClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Live platform checker for person profiling (concurrent HEAD/GET to 530+ platforms).
pub struct PersonProfilerLiveClient {
    client: Client,
    concurrency: usize,
}

impl PersonProfilerLiveClient {
    pub fn new(concurrency: usize) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .expect("failed to build HTTP client");
        Self { client, concurrency }
    }

    /// Check if a username exists on a platform by status code.
    pub async fn check_platform(
        &self,
        url: &str,
        expected_status: u16,
    ) -> Result<bool, LiveApiError> {
        let resp = self
            .client
            .get(url)
            .header(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            )
            .send()
            .await
            .map_err(|e| LiveApiError::Http(e.to_string()))?;

        Ok(resp.status().as_u16() == expected_status)
    }

    /// Batch check multiple platforms concurrently.
    pub async fn batch_check(
        &self,
        checks: Vec<(String, u16)>,
    ) -> Vec<(String, Result<bool, LiveApiError>)> {
        use tokio::sync::Semaphore;
        use std::sync::Arc;

        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let mut handles = Vec::with_capacity(checks.len());

        for (url, expected) in checks {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let client = self.client.clone();
            handles.push(tokio::spawn(async move {
                let result = async {
                    let resp = client
                        .get(&url)
                        .header(
                            "User-Agent",
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        )
                        .send()
                        .await
                        .map_err(|e| LiveApiError::Http(e.to_string()))?;
                    Ok(resp.status().as_u16() == expected)
                }
                .await;
                drop(permit);
                (url, result)
            }));
        }

        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            if let Ok(result) = handle.await {
                results.push(result);
            }
        }
        results
    }
}

/// Passive DNS live client (SecurityTrails API).
pub struct PassiveDnsLiveClient {
    client: Client,
    api_key: String,
}

impl PassiveDnsLiveClient {
    pub fn new(api_key: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");
        Self {
            client,
            api_key: api_key.to_string(),
        }
    }

    /// GET https://api.securitytrails.com/v1/domain/{domain}
    pub async fn domain_info(&self, domain: &str) -> Result<String, LiveApiError> {
        let url = format!("https://api.securitytrails.com/v1/domain/{}", domain);
        let resp = self
            .client
            .get(&url)
            .header("APIKEY", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| LiveApiError::Http(e.to_string()))?;

        match resp.status().as_u16() {
            401 | 403 => return Err(LiveApiError::Unauthorized("invalid API key".to_string())),
            429 => return Err(LiveApiError::RateLimited),
            _ => {}
        }

        resp.text()
            .await
            .map_err(|e| LiveApiError::Http(e.to_string()))
    }

    /// GET https://api.securitytrails.com/v1/history/{domain}/dns/a
    pub async fn dns_history(&self, domain: &str) -> Result<String, LiveApiError> {
        let url = format!(
            "https://api.securitytrails.com/v1/history/{}/dns/a",
            domain
        );
        let resp = self
            .client
            .get(&url)
            .header("APIKEY", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| LiveApiError::Http(e.to_string()))?;

        resp.text()
            .await
            .map_err(|e| LiveApiError::Http(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shodan_client_creates() {
        let client = ShodanLiveClient::new("test-key");
        let _ = client;
    }

    #[test]
    fn crtsh_client_creates() {
        let client = CrtShLiveClient::new();
        let _ = client;
    }

    #[test]
    fn breach_client_creates() {
        let client = BreachCorrelatorClient::new();
        let _ = client;
    }

    #[test]
    fn github_client_creates_without_token() {
        let client = GitHubLiveClient::new(None);
        let _ = client;
    }

    #[test]
    fn github_client_creates_with_token() {
        let client = GitHubLiveClient::new(Some("ghp_test"));
        let _ = client;
    }

    #[test]
    fn cloud_enum_client_creates() {
        let client = CloudEnumLiveClient::new();
        let _ = client;
    }

    #[test]
    fn email_validator_creates() {
        let client = EmailValidatorLiveClient::new();
        let _ = client;
    }

    #[test]
    fn person_profiler_creates() {
        let client = PersonProfilerLiveClient::new(50);
        let _ = client;
    }

    #[test]
    fn passive_dns_creates() {
        let client = PassiveDnsLiveClient::new("test-key");
        let _ = client;
    }

    #[test]
    fn live_api_error_display() {
        assert_eq!(
            LiveApiError::Http("test".to_string()).to_string(),
            "HTTP error: test"
        );
        assert_eq!(LiveApiError::RateLimited.to_string(), "rate limited");
        assert_eq!(
            LiveApiError::Timeout("connect".to_string()).to_string(),
            "timeout: connect"
        );
    }
}
