use aegis_protocol::finding::VulnerabilityClass;
use regex::RegexBuilder;

use crate::defense_profile::{WafProfile, WafVendor};

#[derive(Debug, Clone)]
pub struct WafProbeResult {
    pub probe_payload: String,
    pub response_status: u16,
    pub response_headers: Vec<(String, String)>,
    pub response_body_snippet: String,
}

pub struct WafFingerprinter {
    pub target_url: String,
    pub baseline_status: Option<u16>,
}

impl WafFingerprinter {
    pub fn new(target_url: String) -> Self {
        Self {
            target_url,
            baseline_status: None,
        }
    }
}

const BLOCKED_STATUS_CODES: [u16; 4] = [403, 406, 419, 451];

pub fn identify_vendor(responses: &[WafProbeResult]) -> WafVendor {
    for response in responses {
        let vendor = detect_vendor_from_response(response);
        if vendor != WafVendor::Unknown {
            return vendor;
        }
    }
    WafVendor::Unknown
}

fn detect_vendor_from_response(response: &WafProbeResult) -> WafVendor {
    if has_cloudflare_signature(response) {
        return WafVendor::Cloudflare;
    }
    if has_modsecurity_signature(response) {
        return WafVendor::ModSecurity;
    }
    if has_aws_waf_signature(response) {
        return WafVendor::AwsWaf;
    }
    if has_imperva_signature(response) {
        return WafVendor::Imperva;
    }
    if has_akamai_signature(response) {
        return WafVendor::Akamai;
    }
    WafVendor::Unknown
}

fn has_cloudflare_signature(response: &WafProbeResult) -> bool {
    for (name, value) in &response.response_headers {
        let lower_name = name.to_lowercase();
        if lower_name == "server" && value.to_lowercase().contains("cloudflare") {
            return true;
        }
        if lower_name == "cf-ray" {
            return true;
        }
    }
    false
}

fn has_modsecurity_signature(response: &WafProbeResult) -> bool {
    for (name, value) in &response.response_headers {
        if name.to_lowercase() == "x-powered-by" && value.to_lowercase().contains("modsecurity") {
            return true;
        }
    }
    body_matches_pattern(&response.response_body_snippet, r"Mod_Security")
}

fn has_aws_waf_signature(response: &WafProbeResult) -> bool {
    for (name, _) in &response.response_headers {
        if name.to_lowercase().starts_with("x-amzn-waf-") {
            return true;
        }
    }
    false
}

fn has_imperva_signature(response: &WafProbeResult) -> bool {
    let body_lower = response.response_body_snippet.to_lowercase();
    body_lower.contains("powered by imperva") || body_lower.contains("incapsula")
}

fn has_akamai_signature(response: &WafProbeResult) -> bool {
    for (name, _) in &response.response_headers {
        let lower_name = name.to_lowercase();
        if lower_name == "x-akamai-transformed" || lower_name == "akamai-grn" {
            return true;
        }
    }
    body_matches_pattern(&response.response_body_snippet, r"(?i)akamai")
}

fn body_matches_pattern(body: &str, pattern: &str) -> bool {
    RegexBuilder::new(pattern)
        .build()
        .map(|re| re.is_match(body))
        .unwrap_or(false)
}

pub fn identify_blocked_categories(
    baseline_status: u16,
    probe_results: &[(VulnerabilityClass, WafProbeResult)],
) -> Vec<VulnerabilityClass> {
    probe_results
        .iter()
        .filter(|(_, probe)| {
            probe.response_status != baseline_status
                && BLOCKED_STATUS_CODES.contains(&probe.response_status)
        })
        .map(|(class, _)| *class)
        .collect()
}

pub fn estimate_paranoia_level(probe_results: &[(u8, WafProbeResult)]) -> Option<u8> {
    let mut max_blocked_level: Option<u8> = None;
    for (subtlety_level, probe) in probe_results {
        if BLOCKED_STATUS_CODES.contains(&probe.response_status) {
            max_blocked_level = Some(
                max_blocked_level.map_or(*subtlety_level, |current| current.max(*subtlety_level)),
            );
        }
    }
    max_blocked_level
}

pub fn build_waf_profile(
    vendor: WafVendor,
    blocked_categories: Vec<VulnerabilityClass>,
    paranoia_level: Option<u8>,
    blocked_response_code: u16,
) -> WafProfile {
    WafProfile {
        vendor,
        paranoia_level,
        blocked_response_code,
        blocked_categories,
    }
}

#[cfg(test)]
#[path = "waf_fingerprinter_test.rs"]
mod waf_fingerprinter_test;
