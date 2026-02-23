use reqwest::blocking::Client;

use aegis_protocol::target_validation::validate_target_is_localhost;

pub const COMMON_PARAMS: &[&str] = &[
    "id", "user", "username", "name", "email", "page", "limit", "offset", "sort", "order",
    "search", "q", "query", "filter", "type", "format", "callback", "redirect", "url", "next",
    "return", "ref", "source", "token", "key", "api_key", "apikey", "secret", "password", "pass",
    "file", "path", "dir", "folder", "template", "include", "lang", "locale", "debug", "test",
    "verbose", "admin", "role", "action", "cmd", "command", "exec", "run", "mode", "method",
    "version", "v", "output", "input", "data", "json", "xml", "html", "text", "csv", "download",
    "upload", "export", "import", "delete", "update", "create",
];

const BODY_SIZE_DIFF_THRESHOLD: f64 = 0.10;
const PROBE_VALUE: &str = "test123";

#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredParam {
    pub endpoint: String,
    pub param_name: String,
    pub evidence: ParamEvidence,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ParamEvidence {
    StatusCodeChange(u16, u16),
    BodySizeChange(usize, usize),
    ContentChange,
}

#[derive(Debug)]
pub enum ParamDiscoverError {
    InvalidUrl(String),
    NonLocalhostTarget(String),
    HttpError(String),
}

impl std::fmt::Display for ParamDiscoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(url) => write!(f, "invalid URL: {url}"),
            Self::NonLocalhostTarget(url) => write!(f, "non-localhost target: {url}"),
            Self::HttpError(msg) => write!(f, "HTTP error: {msg}"),
        }
    }
}

impl std::error::Error for ParamDiscoverError {}

pub struct ParamDiscoverer {
    client: Client,
}

impl std::fmt::Debug for ParamDiscoverer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParamDiscoverer").finish()
    }
}

struct BaselineResponse {
    status_code: u16,
    body: Vec<u8>,
}

impl ParamDiscoverer {
    pub fn new() -> Result<Self, ParamDiscoverError> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ParamDiscoverError::HttpError(e.to_string()))?;

        Ok(Self { client })
    }

    pub fn discover_params(
        &self,
        endpoint: &str,
    ) -> Result<Vec<DiscoveredParam>, ParamDiscoverError> {
        let base = validate_and_normalize(endpoint)?;
        let baseline = match self.fetch_baseline(&base) {
            Ok(b) => b,
            Err(_) => return Ok(Vec::new()),
        };

        let mut discovered = Vec::new();
        for param in COMMON_PARAMS {
            if let Some(evidence) = self.probe_param(&base, param, &baseline) {
                discovered.push(DiscoveredParam {
                    endpoint: base.clone(),
                    param_name: param.to_string(),
                    evidence,
                });
            }
        }
        Ok(discovered)
    }

    fn fetch_baseline(&self, url: &str) -> Result<BaselineResponse, ParamDiscoverError> {
        let resp = self
            .client
            .get(url)
            .send()
            .map_err(|e| ParamDiscoverError::HttpError(e.to_string()))?;

        let status_code = resp.status().as_u16();
        let body = resp
            .bytes()
            .map_err(|e| ParamDiscoverError::HttpError(e.to_string()))?
            .to_vec();

        Ok(BaselineResponse { status_code, body })
    }

    fn probe_param(
        &self,
        base_url: &str,
        param: &str,
        baseline: &BaselineResponse,
    ) -> Option<ParamEvidence> {
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let probe_url = format!("{base_url}{separator}{param}={PROBE_VALUE}");

        let resp = self.client.get(&probe_url).send().ok()?;
        let status = resp.status().as_u16();
        let body = resp.bytes().ok()?.to_vec();

        detect_evidence(baseline.status_code, &baseline.body, status, &body)
    }
}

pub(crate) fn detect_evidence(
    baseline_status: u16,
    baseline_body: &[u8],
    probe_status: u16,
    probe_body: &[u8],
) -> Option<ParamEvidence> {
    if baseline_status != probe_status {
        return Some(ParamEvidence::StatusCodeChange(
            baseline_status,
            probe_status,
        ));
    }

    if body_size_differs_significantly(baseline_body.len(), probe_body.len()) {
        return Some(ParamEvidence::BodySizeChange(
            baseline_body.len(),
            probe_body.len(),
        ));
    }

    if baseline_body != probe_body {
        return Some(ParamEvidence::ContentChange);
    }

    None
}

pub(crate) fn body_size_differs_significantly(baseline: usize, probe: usize) -> bool {
    if baseline == 0 && probe == 0 {
        return false;
    }
    let max = baseline.max(probe) as f64;
    let diff = (baseline as f64 - probe as f64).abs();
    diff / max > BODY_SIZE_DIFF_THRESHOLD
}

fn validate_and_normalize(url: &str) -> Result<String, ParamDiscoverError> {
    if url.is_empty() {
        return Err(ParamDiscoverError::InvalidUrl(url.to_string()));
    }
    validate_target_is_localhost(url)
        .map_err(|_| ParamDiscoverError::NonLocalhostTarget(url.to_string()))?;
    Ok(url.trim_end_matches('/').to_string())
}
