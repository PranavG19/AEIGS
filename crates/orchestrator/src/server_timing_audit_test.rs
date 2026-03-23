use crate::server_timing_audit::{analyze_server_timing, server_timing_to_operations};

#[test]
fn detects_database_metric() {
    let values = vec!["db;dur=53.2".to_string()];
    let leaks = analyze_server_timing(&values);
    assert_eq!(leaks.len(), 1);
    assert_eq!(leaks[0].metric_name, "db");
}

#[test]
fn detects_mysql_metric() {
    let values = vec!["mysql-query;dur=12.5".to_string()];
    let leaks = analyze_server_timing(&values);
    assert_eq!(leaks.len(), 1);
}

#[test]
fn detects_redis_metric() {
    let values = vec!["redis;dur=0.8, app;dur=45".to_string()];
    let leaks = analyze_server_timing(&values);
    assert!(leaks.iter().any(|l| l.metric_name == "redis"));
}

#[test]
fn detects_cache_metric() {
    let values = vec!["cache;desc=\"HIT\"".to_string()];
    let leaks = analyze_server_timing(&values);
    assert_eq!(leaks.len(), 1);
}

#[test]
fn detects_internal_metric() {
    let values = vec!["internal-api;dur=100".to_string()];
    let leaks = analyze_server_timing(&values);
    assert!(leaks.iter().any(|l| l.metric_name == "internal-api"));
}

#[test]
fn ignores_safe_metric() {
    let values = vec!["total;dur=200".to_string()];
    let leaks = analyze_server_timing(&values);
    assert!(leaks.is_empty());
}

#[test]
fn multiple_metrics_comma_separated() {
    let values = vec!["db;dur=10, cache;dur=2, render;dur=50".to_string()];
    let leaks = analyze_server_timing(&values);
    assert_eq!(leaks.len(), 2);
}

#[test]
fn multiple_header_values() {
    let values = vec!["db;dur=10".to_string(), "redis;dur=1".to_string()];
    let leaks = analyze_server_timing(&values);
    assert_eq!(leaks.len(), 2);
}

#[test]
fn deduplicates_same_metric() {
    let values = vec!["db;dur=10".to_string(), "db;dur=15".to_string()];
    let leaks = analyze_server_timing(&values);
    assert_eq!(leaks.len(), 1);
}

#[test]
fn case_insensitive() {
    let values = vec!["DB;dur=10".to_string()];
    let leaks = analyze_server_timing(&values);
    assert_eq!(leaks.len(), 1);
}

#[test]
fn empty_values() {
    let leaks = analyze_server_timing(&[]);
    assert!(leaks.is_empty());
}

#[test]
fn operations_empty_when_no_leaks() {
    let mut seq = 0;
    let ops = server_timing_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_leaks() {
    let values = vec!["db;dur=10".to_string()];
    let leaks = analyze_server_timing(&values);
    let mut seq = 0;
    let ops = server_timing_to_operations(&leaks, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}
