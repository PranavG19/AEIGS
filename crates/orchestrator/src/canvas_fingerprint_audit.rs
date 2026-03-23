use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum CanvasFingerprintIssue {
    CanvasToDataUrl,
    CanvasGetImageData,
    WebGlRendererInfo,
    CanvasTextMeasurement,
    AudioContextFingerprint,
    FontEnumeration,
    CanvasDataSent,
}

impl std::fmt::Display for CanvasFingerprintIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CanvasToDataUrl => write!(f, "canvas_to_data_url"),
            Self::CanvasGetImageData => write!(f, "canvas_get_image_data"),
            Self::WebGlRendererInfo => write!(f, "webgl_renderer_info"),
            Self::CanvasTextMeasurement => write!(f, "canvas_text_measurement"),
            Self::AudioContextFingerprint => write!(f, "audio_fingerprint"),
            Self::FontEnumeration => write!(f, "font_enumeration"),
            Self::CanvasDataSent => write!(f, "canvas_data_sent"),
        }
    }
}

pub fn audit_canvas_fingerprint(target: &str) -> Vec<CanvasFingerprintIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    analyze_canvas_fingerprint(&body)
}

pub fn analyze_canvas_fingerprint(body: &str) -> Vec<CanvasFingerprintIssue> {
    if !has_fingerprint_indicators(body) {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("toDataURL") {
        issues.push(CanvasFingerprintIssue::CanvasToDataUrl);
    }

    if body.contains("getImageData") {
        issues.push(CanvasFingerprintIssue::CanvasGetImageData);
    }

    if body.contains("WEBGL_debug_renderer_info")
        || body.contains("UNMASKED_RENDERER_WEBGL")
        || body.contains("UNMASKED_VENDOR_WEBGL")
    {
        issues.push(CanvasFingerprintIssue::WebGlRendererInfo);
    }

    if body.contains("measureText") && body.contains("toDataURL") {
        issues.push(CanvasFingerprintIssue::CanvasTextMeasurement);
    }

    if (body.contains("AudioContext") || body.contains("OfflineAudioContext"))
        && (body.contains("createOscillator") || body.contains("createDynamicsCompressor"))
    {
        issues.push(CanvasFingerprintIssue::AudioContextFingerprint);
    }

    if (body.contains("document.fonts") || body.contains("FontFace"))
        && (body.contains("check(") || body.contains("load(") || body.contains("forEach"))
    {
        issues.push(CanvasFingerprintIssue::FontEnumeration);
    }

    let has_canvas_data = body.contains("toDataURL") || body.contains("getImageData");
    let sends_data = body.contains("fetch(")
        || body.contains("XMLHttpRequest")
        || body.contains("sendBeacon")
        || body.contains(".send(")
        || body.contains("$.ajax");
    if has_canvas_data && sends_data {
        issues.push(CanvasFingerprintIssue::CanvasDataSent);
    }

    issues
}

fn has_fingerprint_indicators(body: &str) -> bool {
    body.contains("toDataURL")
        || body.contains("getImageData")
        || body.contains("WEBGL_debug_renderer_info")
        || body.contains("UNMASKED_RENDERER_WEBGL")
        || body.contains("UNMASKED_VENDOR_WEBGL")
        || body.contains("AudioContext")
        || body.contains("OfflineAudioContext")
        || body.contains("document.fonts")
}

pub fn canvas_fingerprint_severity(issue: &CanvasFingerprintIssue) -> f64 {
    match issue {
        CanvasFingerprintIssue::CanvasDataSent => 7.0,
        CanvasFingerprintIssue::AudioContextFingerprint => 6.5,
        CanvasFingerprintIssue::WebGlRendererInfo => 6.0,
        CanvasFingerprintIssue::CanvasTextMeasurement => 5.5,
        CanvasFingerprintIssue::FontEnumeration => 5.0,
        CanvasFingerprintIssue::CanvasToDataUrl => 4.5,
        CanvasFingerprintIssue::CanvasGetImageData => 4.0,
    }
}

pub fn canvas_fingerprint_to_operations(
    issues: &[CanvasFingerprintIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                canvas_fingerprint_severity(issue),
                0.7,
            )
        })
        .collect()
}
