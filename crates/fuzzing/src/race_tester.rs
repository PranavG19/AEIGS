use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use aegis_protocol::target_validation::validate_target_is_localhost;

const DEFAULT_CONCURRENCY: usize = 10;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

const SENSITIVE_PATH_SEGMENTS: &[&str] = &[
    "transfer", "payment", "purchase", "withdraw", "deposit", "send", "checkout",
];

const RACE_CANDIDATE_SEGMENTS: &[&str] = &[
    "transfer", "purchase", "payment", "order", "redeem", "coupon", "vote", "apply", "withdraw",
    "deposit", "send", "submit", "checkout", "book", "reserve", "claim", "activate",
];

const STATE_CHANGING_METHODS: &[&str] = &["POST", "PUT", "DELETE", "PATCH"];

const SUCCESS_CODES: &[u16] = &[200, 201, 204];

const HIGH_SEVERITY: f64 = 7.5;
const MEDIUM_SEVERITY: f64 = 5.5;

#[derive(Debug, Clone)]
pub struct RaceTestResult {
    pub endpoint: String,
    pub method: String,
    pub concurrent_successes: usize,
    pub total_sent: usize,
    pub severity: f64,
    pub evidence: String,
}

pub struct RaceTester {
    concurrency: usize,
    client: reqwest::blocking::Client,
}

impl RaceTester {
    pub fn new() -> Self {
        Self {
            concurrency: DEFAULT_CONCURRENCY,
            client: reqwest::blocking::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("failed to build HTTP client"),
        }
    }

    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency.max(1);
        self
    }

    pub fn concurrency(&self) -> usize {
        self.concurrency
    }

    pub fn test_race_condition(
        &self,
        endpoint: &str,
        method: &str,
        body: Option<&str>,
        headers: &[(String, String)],
    ) -> Option<RaceTestResult> {
        if !is_race_candidate(endpoint, method) {
            return None;
        }

        if validate_target_is_localhost(endpoint).is_err() {
            return None;
        }

        let responses = send_concurrent(
            &self.client,
            endpoint,
            method,
            body,
            headers,
            self.concurrency,
        );

        interpret_results(endpoint, method, &responses, self.concurrency)
    }
}

impl Default for RaceTester {
    fn default() -> Self {
        Self::new()
    }
}

pub fn is_race_candidate(endpoint: &str, method: &str) -> bool {
    let method_upper = method.to_uppercase();
    if !STATE_CHANGING_METHODS.contains(&method_upper.as_str()) {
        return false;
    }

    let path = extract_path(endpoint);
    let path_lower = path.to_lowercase();

    RACE_CANDIDATE_SEGMENTS
        .iter()
        .any(|segment| path_lower.contains(segment))
}

fn extract_path(endpoint: &str) -> &str {
    if let Some(scheme_end) = endpoint.find("://") {
        let after_scheme = &endpoint[scheme_end + 3..];
        after_scheme.find('/').map_or("", |i| &after_scheme[i..])
    } else {
        endpoint
    }
}

pub fn send_concurrent(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    method: &str,
    body: Option<&str>,
    headers: &[(String, String)],
    concurrency: usize,
) -> Vec<(u16, usize)> {
    let (tx, rx) = mpsc::channel();

    let endpoint = endpoint.to_string();
    let method = method.to_uppercase();
    let body = body.map(|b| b.to_string());
    let headers: Vec<(String, String)> = headers.to_vec();

    let handles: Vec<_> = (0..concurrency)
        .map(|_| {
            let tx = tx.clone();
            let client = client.clone();
            let endpoint = endpoint.clone();
            let method = method.clone();
            let body = body.clone();
            let headers = headers.clone();

            thread::spawn(move || {
                let result =
                    execute_single_request(&client, &endpoint, &method, body.as_deref(), &headers);
                let _ = tx.send(result);
            })
        })
        .collect();

    drop(tx);

    for handle in handles {
        let _ = handle.join();
    }

    rx.iter().collect()
}

fn execute_single_request(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    method: &str,
    body: Option<&str>,
    headers: &[(String, String)],
) -> (u16, usize) {
    let mut builder = match method {
        "POST" => client.post(endpoint),
        "PUT" => client.put(endpoint),
        "DELETE" => client.delete(endpoint),
        "PATCH" => client.patch(endpoint),
        _ => client.get(endpoint),
    };

    for (key, value) in headers {
        builder = builder.header(key.as_str(), value.as_str());
    }

    if let Some(b) = body {
        builder = builder.body(b.to_string());
    }

    match builder.send() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body_len = resp.text().map_or(0, |t| t.len());
            (status, body_len)
        }
        Err(_) => (0, 0),
    }
}

pub(crate) fn interpret_results(
    endpoint: &str,
    method: &str,
    responses: &[(u16, usize)],
    total_sent: usize,
) -> Option<RaceTestResult> {
    let successes = responses
        .iter()
        .filter(|(code, _)| SUCCESS_CODES.contains(code))
        .count();

    if successes <= 1 {
        return None;
    }

    let severity = if is_sensitive_path(endpoint) {
        HIGH_SEVERITY
    } else {
        MEDIUM_SEVERITY
    };

    let evidence = format!(
        "{successes}/{total_sent} concurrent {method} requests to {endpoint} \
         returned success — expected at most 1 for an idempotent state-changing operation"
    );

    Some(RaceTestResult {
        endpoint: endpoint.to_string(),
        method: method.to_uppercase(),
        concurrent_successes: successes,
        total_sent,
        severity,
        evidence,
    })
}

fn is_sensitive_path(endpoint: &str) -> bool {
    let path = extract_path(endpoint);
    let path_lower = path.to_lowercase();

    SENSITIVE_PATH_SEGMENTS
        .iter()
        .any(|segment| path_lower.contains(segment))
}
