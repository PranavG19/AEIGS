use super::command_injection_gen::*;
use std::collections::HashSet;

#[test]
fn total_payload_count_exceeds_100() {
    assert!(
        total_payload_count() >= 100,
        "expected >=100 payloads, got {}",
        total_payload_count()
    );
}

#[test]
fn category_count_at_least_10() {
    assert!(
        category_count() >= 10,
        "expected >=10 categories, got {}",
        category_count()
    );
}

#[test]
fn all_categories_represented() {
    let payloads = all_payloads();
    let categories: HashSet<_> = payloads.iter().map(|p| p.category).collect();
    for cat in InjectionCategory::all() {
        assert!(
            categories.contains(cat),
            "category {:?} has no payloads",
            cat
        );
    }
}

#[test]
fn inline_payloads_nonempty() {
    let results = payloads_for_category(InjectionCategory::Inline);
    assert!(!results.is_empty());
    assert!(results.len() >= 10);
}

#[test]
fn newline_payloads_nonempty() {
    let results = payloads_for_category(InjectionCategory::Newline);
    assert!(!results.is_empty());
}

#[test]
fn time_based_blind_payloads_nonempty() {
    let results = payloads_for_category(InjectionCategory::TimeBasedBlind);
    assert!(results.len() >= 5);
}

#[test]
fn dns_oob_payloads_nonempty() {
    let results = payloads_for_category(InjectionCategory::DnsBasedOob);
    assert!(results.len() >= 5);
}

#[test]
fn backtick_subshell_payloads_nonempty() {
    let results = payloads_for_category(InjectionCategory::BacktickSubshell);
    assert!(results.len() >= 5);
}

#[test]
fn waf_bypass_at_least_10_techniques() {
    let results = waf_bypass_techniques();
    assert!(
        results.len() >= 10,
        "expected >=10 WAF bypass techniques, got {}",
        results.len()
    );
}

#[test]
fn chained_operator_payloads_nonempty() {
    let results = payloads_for_category(InjectionCategory::ChainedOperator);
    assert!(!results.is_empty());
}

#[test]
fn windows_specific_payloads_exist() {
    let results = payloads_for_category(InjectionCategory::WindowsSpecific);
    assert!(results.len() >= 10);
    for p in &results {
        assert_eq!(p.target_os, TargetOs::Windows);
    }
}

#[test]
fn argument_injection_payloads_exist() {
    let results = payloads_for_category(InjectionCategory::ArgumentInjection);
    assert!(!results.is_empty());
}

#[test]
fn environment_variable_payloads_exist() {
    let results = payloads_for_category(InjectionCategory::EnvironmentVariable);
    assert!(!results.is_empty());
}

#[test]
fn filter_bypass_payloads_exist() {
    let results = payloads_for_category(InjectionCategory::FilterBypass);
    assert!(!results.is_empty());
}

#[test]
fn truncation_comment_payloads_exist() {
    let results = payloads_for_category(InjectionCategory::TruncationComment);
    assert!(!results.is_empty());
}

#[test]
fn linux_payloads_nonempty() {
    let results = payloads_for_os(TargetOs::Linux);
    assert!(
        results.len() >= 50,
        "expected >=50 Linux payloads, got {}",
        results.len()
    );
}

#[test]
fn windows_payloads_nonempty() {
    let results = payloads_for_os(TargetOs::Windows);
    assert!(
        results.len() >= 15,
        "expected >=15 Windows payloads, got {}",
        results.len()
    );
}

#[test]
fn os_and_category_filter_works() {
    let results = payloads_for_os_and_category(TargetOs::Linux, InjectionCategory::TimeBasedBlind);
    assert!(!results.is_empty());
    for p in &results {
        assert!(p.target_os == TargetOs::Linux || p.target_os == TargetOs::Both);
        assert_eq!(p.category, InjectionCategory::TimeBasedBlind);
    }
}

#[test]
fn windows_time_based_blind_payloads() {
    let results =
        payloads_for_os_and_category(TargetOs::Windows, InjectionCategory::TimeBasedBlind);
    assert!(!results.is_empty());
    for p in &results {
        assert!(p.target_os == TargetOs::Windows || p.target_os == TargetOs::Both);
    }
}

#[test]
fn blind_detection_includes_both_categories() {
    let results = blind_detection_payloads();
    let categories: HashSet<_> = results.iter().map(|p| p.category).collect();
    assert!(categories.contains(&InjectionCategory::TimeBasedBlind));
    assert!(categories.contains(&InjectionCategory::DnsBasedOob));
}

#[test]
fn all_payloads_have_nonempty_fields() {
    for p in all_payloads() {
        assert!(!p.payload.is_empty(), "payload text must not be empty");
        assert!(!p.description.is_empty(), "description must not be empty");
    }
}

#[test]
fn no_duplicate_payloads() {
    let all = all_payloads();
    let unique: HashSet<&str> = all.iter().map(|p| p.payload).collect();
    assert_eq!(
        all.len(),
        unique.len(),
        "found {} duplicates",
        all.len() - unique.len()
    );
}

#[test]
fn waf_bypass_category_has_10_plus() {
    let results = payloads_for_category(InjectionCategory::WafBypass);
    assert!(
        results.len() >= 10,
        "WafBypass category alone needs >=10, got {}",
        results.len()
    );
}

#[test]
fn time_based_has_linux_and_windows() {
    let linux = payloads_for_os_and_category(TargetOs::Linux, InjectionCategory::TimeBasedBlind);
    let win = payloads_for_os_and_category(TargetOs::Windows, InjectionCategory::TimeBasedBlind);
    assert!(!linux.is_empty(), "need Linux time-based payloads");
    assert!(!win.is_empty(), "need Windows time-based payloads");
}

#[test]
fn dns_oob_has_linux_and_windows() {
    let linux = payloads_for_os_and_category(TargetOs::Linux, InjectionCategory::DnsBasedOob);
    let win = payloads_for_os_and_category(TargetOs::Windows, InjectionCategory::DnsBasedOob);
    assert!(!linux.is_empty(), "need Linux DNS OOB payloads");
    assert!(!win.is_empty(), "need Windows DNS OOB payloads");
}

#[test]
fn inline_payloads_contain_separators() {
    let results = payloads_for_category(InjectionCategory::Inline);
    let has_semicolon = results.iter().any(|p| p.payload.contains(';'));
    let has_pipe = results.iter().any(|p| p.payload.starts_with('|'));
    let has_and = results.iter().any(|p| p.payload.contains("&&"));
    let has_or = results.iter().any(|p| p.payload.contains("||"));
    assert!(has_semicolon, "inline should have semicolon payloads");
    assert!(has_pipe, "inline should have pipe payloads");
    assert!(has_and, "inline should have AND payloads");
    assert!(has_or, "inline should have OR payloads");
}

#[test]
fn waf_bypass_has_ifs_technique() {
    let results = payloads_for_category(InjectionCategory::WafBypass);
    let has_ifs = results.iter().any(|p| p.payload.contains("IFS"));
    assert!(has_ifs, "WAF bypass should include IFS technique");
}

#[test]
fn waf_bypass_has_glob_technique() {
    let results = payloads_for_category(InjectionCategory::WafBypass);
    let has_glob = results
        .iter()
        .any(|p| p.payload.contains('?') || p.payload.contains('*'));
    assert!(
        has_glob,
        "WAF bypass should include glob wildcard technique"
    );
}
