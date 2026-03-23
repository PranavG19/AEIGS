use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WwwAuthIssueKind {
    BasicAuth,
    RealmLeak,
    DigestWithoutQop,
}

#[derive(Debug, Clone)]
pub struct WwwAuthIssue {
    pub kind: WwwAuthIssueKind,
    pub detail: String,
    pub severity: f64,
}

pub fn audit_www_authenticate(target: &str) -> Vec<WwwAuthIssue> {
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

    let values: Vec<String> = resp
        .headers()
        .get_all("www-authenticate")
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
        .collect();

    let is_https = target.starts_with("https://");
    analyze_www_authenticate(&values, is_https)
}

pub(crate) fn analyze_www_authenticate(values: &[String], is_https: bool) -> Vec<WwwAuthIssue> {
    let mut issues = Vec::new();

    for val in values {
        let lower = val.to_ascii_lowercase();

        if lower.starts_with("basic") && !is_https {
            issues.push(WwwAuthIssue {
                kind: WwwAuthIssueKind::BasicAuth,
                detail: "Basic authentication over HTTP transmits credentials in cleartext".into(),
                severity: 7.0,
            });
        } else if lower.starts_with("basic") {
            issues.push(WwwAuthIssue {
                kind: WwwAuthIssueKind::BasicAuth,
                detail: "Basic authentication used — credentials sent with every request".into(),
                severity: 3.5,
            });
        }

        if lower.starts_with("digest") && !lower.contains("qop=") {
            issues.push(WwwAuthIssue {
                kind: WwwAuthIssueKind::DigestWithoutQop,
                detail: "Digest auth without qop directive is vulnerable to replay attacks".into(),
                severity: 5.0,
            });
        }

        if let Some(realm) = extract_realm(val) {
            let realm_lower = realm.to_ascii_lowercase();
            let has_internal_info = realm_lower.contains("admin")
                || realm_lower.contains("internal")
                || realm_lower.contains("staging")
                || realm_lower.contains("debug")
                || realm_lower.contains("test")
                || realm_lower.contains("dev ");
            if has_internal_info {
                issues.push(WwwAuthIssue {
                    kind: WwwAuthIssueKind::RealmLeak,
                    detail: format!("Realm leaks internal info: \"{realm}\""),
                    severity: 3.0,
                });
            }
        }
    }

    issues
}

fn extract_realm(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let pos = lower.find("realm=")?;
    let after = &value[pos + 6..];
    if let Some(quoted) = after.strip_prefix('"') {
        let end = quoted.find('"').unwrap_or(quoted.len());
        Some(quoted[..end].to_string())
    } else {
        let end = after.find([',', ' ', ';']).unwrap_or(after.len());
        Some(after[..end].to_string())
    }
}

pub fn www_authenticate_to_operations(
    issues: &[WwwAuthIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues.iter().map(|i| i.severity).fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::SecurityMisconfiguration,
        max_severity,
        0.9,
    )]
}
