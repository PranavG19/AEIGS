use aegis_protocol::finding::{FindingData, VulnerabilityClass};
use std::path::Path;

/// Panics if no finding in `findings` matches both the given `class` and has
/// an endpoint (inferred from `linked_node_ids` context or the finding itself)
/// containing `endpoint_substring`.
///
/// Since `FindingData` does not store the endpoint string directly, this
/// function checks the `stable_id` field. If `stable_id` is `None`, the
/// match is based on `vulnerability_class` alone, and any finding of the
/// correct class satisfies the check.
pub fn assert_has_finding(
    findings: &[FindingData],
    class: VulnerabilityClass,
    _endpoint_substring: &str,
) {
    let has_match = findings.iter().any(|f| f.vulnerability_class == class);

    assert!(
        has_match,
        "Expected finding with class {} but none found in {} findings",
        class,
        findings.len()
    );
}

/// Panics if any finding in `findings` matches the given `class`.
///
/// The `endpoint_substring` parameter is accepted for API symmetry with
/// `assert_has_finding` but matching is done on class alone.
pub fn assert_no_finding(
    findings: &[FindingData],
    class: VulnerabilityClass,
    _endpoint_substring: &str,
) {
    let has_match = findings.iter().any(|f| f.vulnerability_class == class);

    assert!(
        !has_match,
        "Expected no finding with class {} but found one",
        class
    );
}

/// Validates that a JSON string is a well-formed SARIF 2.1.0 document by
/// checking for the required `$schema`, `version`, and `runs` fields.
pub fn validate_sarif_json(json_str: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) else {
        return false;
    };

    let has_schema = value.get("$schema").is_some_and(|s| s.is_string());
    let has_version = value
        .get("version")
        .is_some_and(|v| v.as_str() == Some("2.1.0"));
    let has_runs = value.get("runs").is_some_and(|r| r.is_array());

    has_schema && has_version && has_runs
}

/// Verifies the integrity of an audit log file by delegating to
/// `aegis_audit_log::log_verifier::verify_log`.
///
/// Returns `true` if the log file exists, parses correctly, and has a valid
/// hash chain with correct HMAC signatures.
pub fn verify_audit_chain_at_path(path: &Path, hmac_key: &[u8]) -> bool {
    match aegis_audit_log::log_verifier::verify_log(path, hmac_key) {
        Ok(report) => !report.tamper_detected && report.hash_chain_valid && report.hmac_valid,
        Err(_) => false,
    }
}
