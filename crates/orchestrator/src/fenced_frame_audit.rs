use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum FencedFrameIssue {
    ApiDetected,
    AdAuctionAbuse,
    DataExfiltration,
    OpaqueUrlBypass,
    SharedStorageLeak,
}

impl std::fmt::Display for FencedFrameIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::AdAuctionAbuse => write!(f, "ad_auction_abuse"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::OpaqueUrlBypass => write!(f, "opaque_url_bypass"),
            Self::SharedStorageLeak => write!(f, "shared_storage_leak"),
        }
    }
}

pub fn audit_fenced_frame(target: &str) -> Vec<FencedFrameIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send() {
        Ok(r) => r.text().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    analyze_fenced_frame(&body)
}

pub fn analyze_fenced_frame(body: &str) -> Vec<FencedFrameIssue> {
    let has_element = body.contains("fencedframe") || body.contains("FencedFrame");
    let has_config = body.contains("FencedFrameConfig");
    let has_auction = body.contains("runAdAuction") || body.contains("joinAdInterestGroup");

    if !has_element && !has_config && !has_auction {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(FencedFrameIssue::ApiDetected);

    if has_auction
        && (body.contains("decisionLogicUrl") || body.contains("biddingLogicUrl"))
        && !body.contains("trustedScoringSignalsUrl")
    {
        issues.push(FencedFrameIssue::AdAuctionAbuse);
    }

    if (has_element || has_config)
        && (body.contains("reportEvent") || body.contains("fence.reportEvent"))
        && (body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest"))
    {
        issues.push(FencedFrameIssue::DataExfiltration);
    }

    if has_config
        && (body.contains("window.location") || body.contains("document.referrer") || body.contains("top.location"))
    {
        issues.push(FencedFrameIssue::OpaqueUrlBypass);
    }

    if (has_element || has_auction)
        && body.contains("sharedStorage")
        && (body.contains(".get(") || body.contains(".entries(") || body.contains(".keys("))
    {
        issues.push(FencedFrameIssue::SharedStorageLeak);
    }

    issues
}

pub fn fenced_frame_severity(issue: &FencedFrameIssue) -> f64 {
    match issue {
        FencedFrameIssue::DataExfiltration => 7.5,
        FencedFrameIssue::SharedStorageLeak => 7.0,
        FencedFrameIssue::OpaqueUrlBypass => 6.0,
        FencedFrameIssue::AdAuctionAbuse => 5.5,
        FencedFrameIssue::ApiDetected => 2.0,
    }
}

pub fn fenced_frame_to_operations(
    issues: &[FencedFrameIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                fenced_frame_severity(issue),
                0.5,
            )
        })
        .collect()
}
