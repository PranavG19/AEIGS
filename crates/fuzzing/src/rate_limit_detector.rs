use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::defense_profile::RateLimitProfile;

/// Result of a sustained-rate probe: how many requests were sent at a given rate
/// and how many were throttled. Used to detect the rate-limit threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitProbeResult {
    pub request_rate: f64,
    pub total_sent: u32,
    pub limited_count: u32,
    pub limit_status_code: Option<u16>,
}

/// Result of a burst probe that sends rapid sequential requests to find the burst
/// allowance — the request count at which rate limiting first activates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurstProbeResult {
    pub total_sent: u32,
    pub first_limited_at: Option<u32>,
    pub limit_status_code: Option<u16>,
}

/// Result of a window-recovery probe that waits a given duration after being
/// rate-limited and checks whether the limit has reset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowProbeResult {
    pub wait_seconds: u32,
    pub recovered: bool,
}

pub fn detect_rate_limit(probes: &[RateLimitProbeResult]) -> Option<f64> {
    probes
        .iter()
        .filter(|p| p.total_sent > 0 && p.limited_count * 2 > p.total_sent)
        .map(|p| p.request_rate)
        .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
}

pub fn detect_burst_allowance(probe: &BurstProbeResult) -> Option<u32> {
    probe.first_limited_at
}

pub fn detect_limit_window(probes: &[WindowProbeResult]) -> Option<u32> {
    probes
        .iter()
        .filter(|p| p.recovered)
        .map(|p| p.wait_seconds)
        .min()
}

pub fn detect_limit_response_code(probes: &[RateLimitProbeResult]) -> u16 {
    let mut counts: HashMap<u16, usize> = HashMap::new();
    for probe in probes {
        if let Some(code) = probe.limit_status_code {
            *counts.entry(code).or_insert(0) += 1;
        }
    }
    counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(code, _)| code)
        .unwrap_or(429)
}

pub fn build_rate_limit_profile(
    probes: &[RateLimitProbeResult],
    burst: Option<&BurstProbeResult>,
    window_probes: &[WindowProbeResult],
) -> Option<RateLimitProfile> {
    let requests_per_second = detect_rate_limit(probes);
    requests_per_second?;

    Some(RateLimitProfile {
        requests_per_second,
        burst_allowance: burst.and_then(detect_burst_allowance),
        limit_response_code: detect_limit_response_code(probes),
        limit_window_seconds: detect_limit_window(window_probes),
    })
}

#[cfg(test)]
#[path = "rate_limit_detector_test.rs"]
mod rate_limit_detector_test;
