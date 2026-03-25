use serde::{Deserialize, Serialize};

pub const MAX_BATCH_SIZE: usize = 64;
pub const DEFAULT_INTER_BATCH_DELAY_MS: u64 = 500;

pub const COMMON_SUBRESOURCES: &[&str] = &[
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
    "/style.css",
    "/app.js",
    "/manifest.json",
];

/// How a batch of requests should be dispatched to mimic browsing behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BrowsingPattern {
    Sequential,
    BurstThenPause,
    ParallelResources,
    NavigationChain,
}

impl std::fmt::Display for BrowsingPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sequential => write!(f, "Sequential"),
            Self::BurstThenPause => write!(f, "Burst Then Pause"),
            Self::ParallelResources => write!(f, "Parallel Resources"),
            Self::NavigationChain => write!(f, "Navigation Chain"),
        }
    }
}

/// A single planned request within a batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedRequest {
    pub endpoint: String,
    pub method: String,
    pub delay_before_ms: u64,
    pub is_cover_traffic: bool,
    pub referer: Option<String>,
    pub priority: u32,
}

/// A batch of requests with a dispatch pattern and inter-batch pause.
#[derive(Debug, Clone)]
pub struct RequestBatch {
    pub requests: Vec<PlannedRequest>,
    pub pattern: BrowsingPattern,
    pub inter_batch_delay_ms: u64,
}

/// Configuration for injecting decoy requests to mask real payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverTrafficConfig {
    pub enabled: bool,
    pub cover_endpoints: Vec<String>,
    pub cover_ratio: f64,
    pub randomize_order: bool,
}

/// A navigation step describing a page load and its subresource fetches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavigationStep {
    pub page_url: String,
    pub subresources: Vec<String>,
    pub api_calls: Vec<String>,
}

/// Errors when constructing request batches: empty input, invalid cover ratio,
/// or exceeding `MAX_BATCH_SIZE` (64).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternError {
    EmptyBatch,
    InvalidCoverRatio(String),
    TooManyRequests(usize),
}

impl std::fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyBatch => write!(f, "batch has no requests"),
            Self::InvalidCoverRatio(val) => write!(f, "invalid cover ratio: {val}"),
            Self::TooManyRequests(count) => {
                write!(f, "batch exceeds maximum of {MAX_BATCH_SIZE}: {count}")
            }
        }
    }
}

impl std::error::Error for PatternError {}

/// Build a sequential batch where each request fires one at a time with a fixed delay.
pub fn build_sequential_batch(
    endpoints: &[&str],
    method: &str,
    base_delay_ms: u64,
) -> Result<RequestBatch, PatternError> {
    validate_batch_size(endpoints.len())?;
    let requests = endpoints
        .iter()
        .enumerate()
        .map(|(i, ep)| PlannedRequest {
            endpoint: (*ep).to_string(),
            method: method.to_string(),
            delay_before_ms: base_delay_ms,
            is_cover_traffic: false,
            referer: None,
            priority: i as u32,
        })
        .collect();
    Ok(RequestBatch {
        requests,
        pattern: BrowsingPattern::Sequential,
        inter_batch_delay_ms: DEFAULT_INTER_BATCH_DELAY_MS,
    })
}

/// Build a burst batch: all requests fire with a short delay, then a long pause follows.
pub fn build_burst_batch(
    endpoints: &[&str],
    method: &str,
    burst_delay_ms: u64,
    pause_ms: u64,
) -> Result<RequestBatch, PatternError> {
    validate_batch_size(endpoints.len())?;
    let requests = endpoints
        .iter()
        .enumerate()
        .map(|(i, ep)| PlannedRequest {
            endpoint: (*ep).to_string(),
            method: method.to_string(),
            delay_before_ms: burst_delay_ms,
            is_cover_traffic: false,
            referer: None,
            priority: i as u32,
        })
        .collect();
    Ok(RequestBatch {
        requests,
        pattern: BrowsingPattern::BurstThenPause,
        inter_batch_delay_ms: pause_ms,
    })
}

/// Build a parallel-resources batch simulating a browser loading a page and its assets.
pub fn build_parallel_resources_batch(
    page_url: &str,
    subresources: &[&str],
) -> Result<RequestBatch, PatternError> {
    let total = 1 + subresources.len();
    validate_batch_size(total)?;
    let mut requests = Vec::with_capacity(total);
    requests.push(PlannedRequest {
        endpoint: page_url.to_string(),
        method: "GET".to_string(),
        delay_before_ms: 0,
        is_cover_traffic: false,
        referer: None,
        priority: 0,
    });
    for (i, sub) in subresources.iter().enumerate() {
        let jitter = 10 + ((i as u64 * 17) % 41);
        requests.push(PlannedRequest {
            endpoint: (*sub).to_string(),
            method: "GET".to_string(),
            delay_before_ms: jitter,
            is_cover_traffic: false,
            referer: Some(page_url.to_string()),
            priority: 1,
        });
    }
    Ok(RequestBatch {
        requests,
        pattern: BrowsingPattern::ParallelResources,
        inter_batch_delay_ms: DEFAULT_INTER_BATCH_DELAY_MS,
    })
}

/// Convert navigation steps into a series of batches simulating real browsing.
pub fn build_navigation_chain(steps: &[NavigationStep]) -> Result<Vec<RequestBatch>, PatternError> {
    if steps.is_empty() {
        return Err(PatternError::EmptyBatch);
    }
    let mut batches = Vec::with_capacity(steps.len());
    for step in steps {
        let total = 1 + step.subresources.len() + step.api_calls.len();
        if total > MAX_BATCH_SIZE {
            return Err(PatternError::TooManyRequests(total));
        }
        let mut requests = Vec::with_capacity(total);
        requests.push(PlannedRequest {
            endpoint: step.page_url.clone(),
            method: "GET".to_string(),
            delay_before_ms: 0,
            is_cover_traffic: false,
            referer: None,
            priority: 0,
        });
        for (i, sub) in step.subresources.iter().enumerate() {
            let jitter = 10 + ((i as u64 * 17) % 41);
            requests.push(PlannedRequest {
                endpoint: sub.clone(),
                method: "GET".to_string(),
                delay_before_ms: jitter,
                is_cover_traffic: false,
                referer: Some(step.page_url.clone()),
                priority: 1,
            });
        }
        for (i, api) in step.api_calls.iter().enumerate() {
            requests.push(PlannedRequest {
                endpoint: api.clone(),
                method: "GET".to_string(),
                delay_before_ms: 50 + (i as u64 * 10),
                is_cover_traffic: false,
                referer: Some(step.page_url.clone()),
                priority: 2,
            });
        }
        batches.push(RequestBatch {
            requests,
            pattern: BrowsingPattern::NavigationChain,
            inter_batch_delay_ms: 1000,
        });
    }
    Ok(batches)
}

/// Inject cover traffic into an existing batch to disguise real payloads.
pub fn inject_cover_traffic(
    batch: &RequestBatch,
    config: &CoverTrafficConfig,
) -> Result<RequestBatch, PatternError> {
    if !config.cover_ratio.is_finite() || config.cover_ratio < 0.0 {
        return Err(PatternError::InvalidCoverRatio(
            config.cover_ratio.to_string(),
        ));
    }
    if !config.enabled || config.cover_endpoints.is_empty() {
        return Ok(batch.clone());
    }
    let cover_count = (batch.requests.len() as f64 * config.cover_ratio).round() as usize;
    let total = batch.requests.len() + cover_count;
    if total > MAX_BATCH_SIZE {
        return Err(PatternError::TooManyRequests(total));
    }
    let mut requests = batch.requests.clone();
    for i in 0..cover_count {
        let ep = &config.cover_endpoints[i % config.cover_endpoints.len()];
        requests.push(PlannedRequest {
            endpoint: ep.clone(),
            method: "GET".to_string(),
            delay_before_ms: 10,
            is_cover_traffic: true,
            referer: None,
            priority: requests.len() as u32,
        });
    }
    if config.randomize_order {
        let seed = batch.requests.len();
        deterministic_shuffle(&mut requests, seed);
    }
    Ok(RequestBatch {
        requests,
        pattern: batch.pattern,
        inter_batch_delay_ms: batch.inter_batch_delay_ms,
    })
}

/// Plan execution timing for a batch, returning (request_index, absolute_offset_ms) pairs
/// sorted by priority then original order.
pub fn plan_timing(batch: &RequestBatch, jitter_ms: u64) -> Vec<(usize, u64)> {
    let mut indexed: Vec<(usize, u32, u64)> = batch
        .requests
        .iter()
        .enumerate()
        .map(|(i, r)| (i, r.priority, r.delay_before_ms))
        .collect();
    indexed.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
    let mut result = Vec::with_capacity(indexed.len());
    let mut offset = 0u64;
    for (idx, (original_index, _priority, delay)) in indexed.iter().enumerate() {
        offset += delay;
        if jitter_ms > 0 {
            offset += (idx as u64) % jitter_ms;
        }
        result.push((*original_index, offset));
    }
    result
}

/// Estimate the total wall-clock duration of a batch including all delays and jitter.
pub fn estimate_batch_duration_ms(batch: &RequestBatch, jitter_ms: u64) -> u64 {
    let timing = plan_timing(batch, jitter_ms);
    let last_offset = timing.last().map(|(_, t)| *t).unwrap_or(0);
    last_offset + batch.inter_batch_delay_ms
}

fn validate_batch_size(count: usize) -> Result<(), PatternError> {
    if count == 0 {
        return Err(PatternError::EmptyBatch);
    }
    if count > MAX_BATCH_SIZE {
        return Err(PatternError::TooManyRequests(count));
    }
    Ok(())
}

fn deterministic_shuffle(items: &mut [PlannedRequest], seed: usize) {
    let len = items.len();
    if len <= 1 {
        return;
    }
    let mut state = seed.wrapping_add(0x9E37_79B9);
    for i in (1..len).rev() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let j = state % (i + 1);
        items.swap(i, j);
    }
}
