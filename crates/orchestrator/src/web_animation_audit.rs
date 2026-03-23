use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebAnimationIssue {
    ApiDetected,
    UiRedressing,
    ResourceExhaustion,
    TimingSideChannel,
    ClickjackingViaAnimation,
}

impl std::fmt::Display for WebAnimationIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::UiRedressing => write!(f, "ui_redressing"),
            Self::ResourceExhaustion => write!(f, "resource_exhaustion"),
            Self::TimingSideChannel => write!(f, "timing_side_channel"),
            Self::ClickjackingViaAnimation => write!(f, "clickjacking_via_animation"),
        }
    }
}

pub fn audit_web_animation(target: &str) -> Vec<WebAnimationIssue> {
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
    analyze_web_animation(&body)
}

pub fn analyze_web_animation(body: &str) -> Vec<WebAnimationIssue> {
    let has_api = body.contains("element.animate(")
        || body.contains("Animation(")
        || body.contains("KeyframeEffect")
        || body.contains("getAnimations");

    if !has_api {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(WebAnimationIssue::ApiDetected);

    let has_positioning = body.contains("transform")
        || body.contains("opacity")
        || body.contains("z-index")
        || body.contains("zIndex");
    let has_fixed_absolute = body.contains("position: fixed")
        || body.contains("position: absolute")
        || body.contains("position:fixed")
        || body.contains("position:absolute");
    if has_positioning && has_fixed_absolute {
        issues.push(WebAnimationIssue::UiRedressing);
    }

    let has_infinite = body.contains("iterations: Infinity")
        || body.contains("iterations:Infinity")
        || body.contains("repeat(")
        || body.contains("infinite");
    let has_cancel = body.contains("cancel(");
    let has_pause = body.contains("pause(");
    if has_infinite && !has_cancel && !has_pause {
        issues.push(WebAnimationIssue::ResourceExhaustion);
    }

    let has_finish = body.contains("finished") || body.contains("onfinish");
    let has_timing = body.contains("performance.now") || body.contains("Date.now");
    if has_finish && has_timing {
        issues.push(WebAnimationIssue::TimingSideChannel);
    }

    let has_visibility = body.contains("opacity") || body.contains("visibility");
    let has_click =
        body.contains("click") || body.contains("onclick") || body.contains("addEventListener");
    let has_pointer = body.contains("pointer-events") || body.contains("pointerEvents");
    if has_visibility && has_click && has_pointer {
        issues.push(WebAnimationIssue::ClickjackingViaAnimation);
    }

    issues
}

pub fn web_animation_severity(issue: &WebAnimationIssue) -> f64 {
    match issue {
        WebAnimationIssue::ClickjackingViaAnimation => 7.0,
        WebAnimationIssue::UiRedressing => 6.5,
        WebAnimationIssue::ResourceExhaustion => 6.0,
        WebAnimationIssue::TimingSideChannel => 5.5,
        WebAnimationIssue::ApiDetected => 2.0,
    }
}

pub fn web_animation_to_operations(
    issues: &[WebAnimationIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                web_animation_severity(issue),
                0.5,
            )
        })
        .collect()
}
