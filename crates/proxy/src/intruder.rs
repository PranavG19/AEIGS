use std::time::Instant;

use crate::repeater::ModifiedRequest;

/// How payload lists are combined across positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackMode {
    /// One position at a time; others keep their original marker text.
    Sniper,
    /// Same payload inserted into all positions simultaneously.
    BatteringRam,
    /// Parallel iteration (zip) through payload lists.
    Pitchfork,
    /// Cartesian product of all payload lists.
    ClusterBomb,
}

/// Configuration for an intruder attack run.
#[derive(Debug, Clone)]
pub struct IntruderConfig {
    pub template: ModifiedRequest,
    pub positions: Vec<String>,
    pub payload_lists: Vec<Vec<String>>,
    pub mode: AttackMode,
    pub concurrency: usize,
}

/// Result of a single intruder request.
#[derive(Debug, Clone)]
pub struct IntruderResult {
    pub payload: Vec<String>,
    pub status_code: u16,
    pub body_length: usize,
    pub duration_ms: u64,
}

/// Generate all (payload-vector, request) pairs for the given attack configuration.
pub fn generate_attack_requests(config: &IntruderConfig) -> Vec<(Vec<String>, ModifiedRequest)> {
    let combos = generate_payload_combinations(config);
    combos
        .into_iter()
        .map(|payloads| {
            let req = substitute_positions(&config.template, &config.positions, &payloads);
            (payloads, req)
        })
        .collect()
}

fn generate_payload_combinations(config: &IntruderConfig) -> Vec<Vec<String>> {
    match config.mode {
        AttackMode::Sniper => sniper_combinations(config),
        AttackMode::BatteringRam => battering_ram_combinations(config),
        AttackMode::Pitchfork => pitchfork_combinations(config),
        AttackMode::ClusterBomb => cluster_bomb_combinations(config),
    }
}

fn sniper_combinations(config: &IntruderConfig) -> Vec<Vec<String>> {
    let mut results = Vec::new();
    for (pos_idx, marker) in config.positions.iter().enumerate() {
        let payloads = config.payload_lists.first().unwrap_or(&Vec::new()).clone();
        for payload in payloads {
            let mut combo: Vec<String> = config.positions.clone();
            combo[pos_idx] = payload;
            for (j, m) in config.positions.iter().enumerate() {
                if j != pos_idx {
                    combo[j] = m.clone();
                }
            }
            results.push(combo);
        }
        let _ = marker;
    }
    results
}

fn battering_ram_combinations(config: &IntruderConfig) -> Vec<Vec<String>> {
    let payloads = config.payload_lists.first().unwrap_or(&Vec::new()).clone();
    payloads
        .into_iter()
        .map(|p| vec![p; config.positions.len()])
        .collect()
}

fn pitchfork_combinations(config: &IntruderConfig) -> Vec<Vec<String>> {
    if config.payload_lists.is_empty() {
        return Vec::new();
    }
    let min_len = config
        .payload_lists
        .iter()
        .map(|l| l.len())
        .min()
        .unwrap_or(0);
    (0..min_len)
        .map(|i| {
            config
                .payload_lists
                .iter()
                .map(|list| list[i].clone())
                .collect()
        })
        .collect()
}

fn cluster_bomb_combinations(config: &IntruderConfig) -> Vec<Vec<String>> {
    if config.payload_lists.is_empty() {
        return Vec::new();
    }
    let mut results: Vec<Vec<String>> = vec![vec![]];
    for list in &config.payload_lists {
        let mut next = Vec::new();
        for existing in &results {
            for item in list {
                let mut combo = existing.clone();
                combo.push(item.clone());
                next.push(combo);
            }
        }
        results = next;
    }
    results
}

fn substitute_positions(
    template: &ModifiedRequest,
    positions: &[String],
    payloads: &[String],
) -> ModifiedRequest {
    let mut url = template.url.clone();
    let mut body = String::from_utf8_lossy(&template.body).to_string();
    let mut headers = template.headers.clone();
    for (marker, payload) in positions.iter().zip(payloads.iter()) {
        url = url.replace(marker, payload);
        body = body.replace(marker, payload);
        for (_, val) in &mut headers {
            *val = val.replace(marker, payload);
        }
    }
    ModifiedRequest {
        method: template.method.clone(),
        url,
        headers,
        body: body.into_bytes(),
    }
}

/// Execute the full intruder run: generate requests, send concurrently, return sorted results.
pub async fn run_intruder(config: IntruderConfig) -> Vec<IntruderResult> {
    let requests = generate_attack_requests(&config);
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to build reqwest client");
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(config.concurrency));
    let mut handles = Vec::new();
    for (payloads, req) in requests {
        let client = client.clone();
        let permit = semaphore.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit.acquire().await.expect("semaphore closed");
            send_intruder_request(&client, payloads, &req).await
        }));
    }
    let mut results = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }
    results.sort_by(|a, b| {
        let a_anomalous = a.status_code != 200;
        let b_anomalous = b.status_code != 200;
        b_anomalous
            .cmp(&a_anomalous)
            .then(b.body_length.cmp(&a.body_length))
    });
    results
}

async fn send_intruder_request(
    client: &reqwest::Client,
    payloads: Vec<String>,
    req: &ModifiedRequest,
) -> IntruderResult {
    let method = reqwest::Method::from_bytes(req.method.as_bytes()).unwrap_or(reqwest::Method::GET);
    let start = Instant::now();
    let mut builder = client.request(method, &req.url);
    for (name, value) in &req.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    if !req.body.is_empty() {
        builder = builder.body(req.body.clone());
    }
    match builder.send().await {
        Ok(resp) => {
            let status_code = resp.status().as_u16();
            let body = resp.bytes().await.unwrap_or_default();
            IntruderResult {
                payload: payloads,
                status_code,
                body_length: body.len(),
                duration_ms: start.elapsed().as_millis() as u64,
            }
        }
        Err(_) => IntruderResult {
            payload: payloads,
            status_code: 0,
            body_length: 0,
            duration_ms: start.elapsed().as_millis() as u64,
        },
    }
}

#[cfg(test)]
#[path = "intruder_test.rs"]
mod intruder_test;
