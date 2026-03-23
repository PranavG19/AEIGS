use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum DeprecatedHeaderIssue {
    ExpectCt,
    FeaturePolicy,
    PublicKeyPins,
    PublicKeyPinsReportOnly,
    XxssProtection,
    XFrameOptions,
    XContentTypeOptions { value: String },
    PragmaHttp2,
    P3p,
    XWebkitCsp,
    XContentSecurityPolicy,
}

impl std::fmt::Display for DeprecatedHeaderIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExpectCt => write!(f, "expect_ct"),
            Self::FeaturePolicy => write!(f, "feature_policy"),
            Self::PublicKeyPins => write!(f, "public_key_pins"),
            Self::PublicKeyPinsReportOnly => write!(f, "public_key_pins_report_only"),
            Self::XxssProtection => write!(f, "xxss_protection"),
            Self::XFrameOptions => write!(f, "x_frame_options"),
            Self::XContentTypeOptions { value } => {
                write!(f, "x_content_type_options:{value}")
            }
            Self::PragmaHttp2 => write!(f, "pragma_http2"),
            Self::P3p => write!(f, "p3p"),
            Self::XWebkitCsp => write!(f, "x_webkit_csp"),
            Self::XContentSecurityPolicy => write!(f, "x_content_security_policy"),
        }
    }
}

pub fn deprecated_header_severity(issue: &DeprecatedHeaderIssue) -> f64 {
    match issue {
        DeprecatedHeaderIssue::ExpectCt => 1.5,
        DeprecatedHeaderIssue::FeaturePolicy => 2.0,
        DeprecatedHeaderIssue::PublicKeyPins => 3.0,
        DeprecatedHeaderIssue::PublicKeyPinsReportOnly => 2.0,
        DeprecatedHeaderIssue::XxssProtection => 2.5,
        DeprecatedHeaderIssue::XFrameOptions => 1.5,
        DeprecatedHeaderIssue::XContentTypeOptions { .. } => 2.0,
        DeprecatedHeaderIssue::PragmaHttp2 => 1.0,
        DeprecatedHeaderIssue::P3p => 1.5,
        DeprecatedHeaderIssue::XWebkitCsp => 2.5,
        DeprecatedHeaderIssue::XContentSecurityPolicy => 2.5,
    }
}

fn find_header<'a>(headers: &[(&str, &'a str)], target: &str) -> Option<&'a str> {
    let target_lower = target.to_ascii_lowercase();
    headers
        .iter()
        .find(|(name, _)| name.to_ascii_lowercase() == target_lower)
        .map(|(_, value)| *value)
}

pub fn analyze_deprecated_headers(headers: &[(&str, &str)]) -> Vec<DeprecatedHeaderIssue> {
    let mut issues = Vec::new();

    if find_header(headers, "expect-ct").is_some() {
        issues.push(DeprecatedHeaderIssue::ExpectCt);
    }
    if find_header(headers, "feature-policy").is_some() {
        issues.push(DeprecatedHeaderIssue::FeaturePolicy);
    }
    if find_header(headers, "public-key-pins").is_some() {
        issues.push(DeprecatedHeaderIssue::PublicKeyPins);
    }
    if find_header(headers, "public-key-pins-report-only").is_some() {
        issues.push(DeprecatedHeaderIssue::PublicKeyPinsReportOnly);
    }
    if find_header(headers, "x-xss-protection").is_some() {
        issues.push(DeprecatedHeaderIssue::XxssProtection);
    }
    if find_header(headers, "x-frame-options").is_some() {
        issues.push(DeprecatedHeaderIssue::XFrameOptions);
    }
    if let Some(value) = find_header(headers, "x-content-type-options")
        && !value.trim().eq_ignore_ascii_case("nosniff")
    {
        issues.push(DeprecatedHeaderIssue::XContentTypeOptions {
            value: value.to_string(),
        });
    }
    if find_header(headers, "pragma").is_some() {
        issues.push(DeprecatedHeaderIssue::PragmaHttp2);
    }
    if find_header(headers, "p3p").is_some() {
        issues.push(DeprecatedHeaderIssue::P3p);
    }
    if find_header(headers, "x-webkit-csp").is_some() {
        issues.push(DeprecatedHeaderIssue::XWebkitCsp);
    }
    if find_header(headers, "x-content-security-policy").is_some() {
        issues.push(DeprecatedHeaderIssue::XContentSecurityPolicy);
    }

    issues
}

pub fn audit_deprecated_headers(target: &str) -> Vec<DeprecatedHeaderIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let raw_headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_string(), v.to_string()))
        })
        .collect();

    let header_refs: Vec<(&str, &str)> = raw_headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    analyze_deprecated_headers(&header_refs)
}

pub fn deprecated_header_to_operations(
    issues: &[DeprecatedHeaderIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                deprecated_header_severity(issue),
                0.5,
            )
        })
        .collect()
}
