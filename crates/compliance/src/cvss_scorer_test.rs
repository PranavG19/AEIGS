use crate::cvss_scorer::*;

fn metrics(
    av: AttackVector,
    ac: AttackComplexity,
    pr: PrivilegesRequired,
    ui: UserInteraction,
    s: Scope,
    c: Impact,
    i: Impact,
    a: Impact,
) -> CvssMetrics {
    CvssMetrics {
        attack_vector: av,
        attack_complexity: ac,
        privileges_required: pr,
        user_interaction: ui,
        scope: s,
        confidentiality: c,
        integrity: i,
        availability: a,
    }
}

#[test]
fn critical_all_high_unchanged() {
    let m = metrics(
        AttackVector::Network,
        AttackComplexity::Low,
        PrivilegesRequired::None,
        UserInteraction::None,
        Scope::Unchanged,
        Impact::High,
        Impact::High,
        Impact::High,
    );
    let result = compute_cvss(&m);
    assert_eq!(result.score, 9.8);
    assert_eq!(result.severity_label, CvssSeverity::Critical);
    assert_eq!(
        result.vector_string,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    );
}

#[test]
fn xss_reflected_typical() {
    let m = metrics(
        AttackVector::Network,
        AttackComplexity::Low,
        PrivilegesRequired::None,
        UserInteraction::Required,
        Scope::Changed,
        Impact::Low,
        Impact::Low,
        Impact::None,
    );
    let result = compute_cvss(&m);
    assert_eq!(result.score, 6.1);
    assert_eq!(result.severity_label, CvssSeverity::Medium);
    assert_eq!(
        result.vector_string,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    );
}

#[test]
fn sqli_no_availability() {
    let m = metrics(
        AttackVector::Network,
        AttackComplexity::Low,
        PrivilegesRequired::None,
        UserInteraction::None,
        Scope::Unchanged,
        Impact::High,
        Impact::High,
        Impact::None,
    );
    let result = compute_cvss(&m);
    assert_eq!(result.score, 9.1);
    assert_eq!(result.severity_label, CvssSeverity::Critical);
}

#[test]
fn path_traversal_read_only() {
    let m = metrics(
        AttackVector::Network,
        AttackComplexity::Low,
        PrivilegesRequired::None,
        UserInteraction::None,
        Scope::Unchanged,
        Impact::High,
        Impact::None,
        Impact::None,
    );
    let result = compute_cvss(&m);
    assert_eq!(result.score, 7.5);
    assert_eq!(result.severity_label, CvssSeverity::High);
}

#[test]
fn ssrf_scope_changed() {
    let m = metrics(
        AttackVector::Network,
        AttackComplexity::Low,
        PrivilegesRequired::None,
        UserInteraction::None,
        Scope::Changed,
        Impact::High,
        Impact::None,
        Impact::None,
    );
    let result = compute_cvss(&m);
    assert_eq!(result.score, 8.6);
    assert_eq!(result.severity_label, CvssSeverity::High);
}

#[test]
fn zero_impact_returns_zero() {
    let m = metrics(
        AttackVector::Network,
        AttackComplexity::Low,
        PrivilegesRequired::None,
        UserInteraction::None,
        Scope::Unchanged,
        Impact::None,
        Impact::None,
        Impact::None,
    );
    let result = compute_cvss(&m);
    assert_eq!(result.score, 0.0);
    assert_eq!(result.severity_label, CvssSeverity::None);
}

#[test]
fn physical_high_complexity_high_priv() {
    let m = metrics(
        AttackVector::Physical,
        AttackComplexity::High,
        PrivilegesRequired::High,
        UserInteraction::Required,
        Scope::Unchanged,
        Impact::Low,
        Impact::Low,
        Impact::None,
    );
    let result = compute_cvss(&m);
    assert!(result.score > 0.0 && result.score < 3.0);
    assert_eq!(result.severity_label, CvssSeverity::Low);
    assert_eq!(
        result.vector_string,
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N"
    );
}

#[test]
fn local_attack_low_privilege_changed_scope() {
    let m = metrics(
        AttackVector::Local,
        AttackComplexity::Low,
        PrivilegesRequired::Low,
        UserInteraction::None,
        Scope::Changed,
        Impact::High,
        Impact::High,
        Impact::High,
    );
    let result = compute_cvss(&m);
    assert_eq!(result.score, 8.8);
    assert_eq!(result.severity_label, CvssSeverity::High);
}

#[test]
fn adjacent_network_medium_severity() {
    let m = metrics(
        AttackVector::Adjacent,
        AttackComplexity::Low,
        PrivilegesRequired::None,
        UserInteraction::None,
        Scope::Unchanged,
        Impact::Low,
        Impact::Low,
        Impact::None,
    );
    let result = compute_cvss(&m);
    assert_eq!(result.score, 5.4);
    assert_eq!(result.severity_label, CvssSeverity::Medium);
}

#[test]
fn privileges_required_scope_changed_weight() {
    let m_low = metrics(
        AttackVector::Network,
        AttackComplexity::Low,
        PrivilegesRequired::Low,
        UserInteraction::None,
        Scope::Changed,
        Impact::High,
        Impact::High,
        Impact::None,
    );
    let m_high = metrics(
        AttackVector::Network,
        AttackComplexity::Low,
        PrivilegesRequired::High,
        UserInteraction::None,
        Scope::Changed,
        Impact::High,
        Impact::High,
        Impact::None,
    );
    let result_low = compute_cvss(&m_low);
    let result_high = compute_cvss(&m_high);
    assert!(result_low.score > result_high.score);
}

#[test]
fn score_never_exceeds_ten() {
    let m = metrics(
        AttackVector::Network,
        AttackComplexity::Low,
        PrivilegesRequired::None,
        UserInteraction::None,
        Scope::Changed,
        Impact::High,
        Impact::High,
        Impact::High,
    );
    let result = compute_cvss(&m);
    assert!(result.score <= 10.0);
    assert_eq!(result.score, 10.0);
    assert_eq!(result.severity_label, CvssSeverity::Critical);
}

#[test]
fn severity_boundary_none() {
    assert_eq!(severity_from_score(0.0), CvssSeverity::None);
}

#[test]
fn severity_boundary_low() {
    assert_eq!(severity_from_score(0.1), CvssSeverity::Low);
    assert_eq!(severity_from_score(3.9), CvssSeverity::Low);
}

#[test]
fn severity_boundary_medium() {
    assert_eq!(severity_from_score(4.0), CvssSeverity::Medium);
    assert_eq!(severity_from_score(6.9), CvssSeverity::Medium);
}

#[test]
fn severity_boundary_high() {
    assert_eq!(severity_from_score(7.0), CvssSeverity::High);
    assert_eq!(severity_from_score(8.9), CvssSeverity::High);
}

#[test]
fn severity_boundary_critical() {
    assert_eq!(severity_from_score(9.0), CvssSeverity::Critical);
    assert_eq!(severity_from_score(10.0), CvssSeverity::Critical);
}

#[test]
fn vector_string_all_abbreviations() {
    let m = metrics(
        AttackVector::Adjacent,
        AttackComplexity::High,
        PrivilegesRequired::High,
        UserInteraction::Required,
        Scope::Changed,
        Impact::None,
        Impact::Low,
        Impact::High,
    );
    let result = compute_cvss(&m);
    assert_eq!(
        result.vector_string,
        "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:C/C:N/I:L/A:H"
    );
}

#[test]
fn serde_roundtrip_metrics() {
    let m = metrics(
        AttackVector::Network,
        AttackComplexity::Low,
        PrivilegesRequired::None,
        UserInteraction::None,
        Scope::Unchanged,
        Impact::High,
        Impact::High,
        Impact::High,
    );
    let json = serde_json::to_string(&m).unwrap();
    let deserialized: CvssMetrics = serde_json::from_str(&json).unwrap();
    let result = compute_cvss(&deserialized);
    assert_eq!(result.score, 9.8);
}

#[test]
fn serde_roundtrip_result() {
    let m = metrics(
        AttackVector::Network,
        AttackComplexity::Low,
        PrivilegesRequired::None,
        UserInteraction::None,
        Scope::Unchanged,
        Impact::High,
        Impact::None,
        Impact::None,
    );
    let result = compute_cvss(&m);
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: CvssResult = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.score, 7.5);
    assert_eq!(deserialized.severity_label, CvssSeverity::High);
}

#[test]
fn cve_2021_44228_log4shell() {
    let m = metrics(
        AttackVector::Network,
        AttackComplexity::Low,
        PrivilegesRequired::None,
        UserInteraction::None,
        Scope::Changed,
        Impact::High,
        Impact::High,
        Impact::High,
    );
    let result = compute_cvss(&m);
    assert_eq!(result.score, 10.0);
}

#[test]
fn cve_2017_5638_struts_rce() {
    let m = metrics(
        AttackVector::Network,
        AttackComplexity::Low,
        PrivilegesRequired::None,
        UserInteraction::None,
        Scope::Changed,
        Impact::High,
        Impact::High,
        Impact::High,
    );
    let result = compute_cvss(&m);
    assert_eq!(result.score, 10.0);
}

#[test]
fn cve_2019_0708_bluekeep() {
    let m = metrics(
        AttackVector::Network,
        AttackComplexity::Low,
        PrivilegesRequired::None,
        UserInteraction::None,
        Scope::Unchanged,
        Impact::High,
        Impact::High,
        Impact::High,
    );
    let result = compute_cvss(&m);
    assert_eq!(result.score, 9.8);
    assert_eq!(
        result.vector_string,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    );
}

#[test]
fn low_impact_single_metric() {
    let m = metrics(
        AttackVector::Network,
        AttackComplexity::Low,
        PrivilegesRequired::None,
        UserInteraction::None,
        Scope::Unchanged,
        Impact::Low,
        Impact::None,
        Impact::None,
    );
    let result = compute_cvss(&m);
    assert_eq!(result.score, 5.3);
    assert_eq!(result.severity_label, CvssSeverity::Medium);
}

#[test]
fn misconfig_typical() {
    let m = metrics(
        AttackVector::Network,
        AttackComplexity::Low,
        PrivilegesRequired::None,
        UserInteraction::None,
        Scope::Unchanged,
        Impact::Low,
        Impact::Low,
        Impact::None,
    );
    let result = compute_cvss(&m);
    assert_eq!(result.score, 6.5);
    assert_eq!(result.severity_label, CvssSeverity::Medium);
}
