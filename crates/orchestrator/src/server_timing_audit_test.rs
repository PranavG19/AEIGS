use crate::server_timing_audit::*;

// ========== Existing 13 tests ==========

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

// ========== New tests for ServerTimingIssue ==========

#[test]
fn analyze_detects_database_timing() {
    let values = vec!["db;dur=53.2".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::DatabaseTiming { .. }))
    );
}

#[test]
fn analyze_detects_mysql_timing() {
    let values = vec!["mysql-query;dur=12.5".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::DatabaseTiming { .. }))
    );
}

#[test]
fn analyze_detects_postgres_timing() {
    let values = vec!["postgres-pool;dur=8.3".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::DatabaseTiming { .. }))
    );
}

#[test]
fn analyze_detects_mongo_timing() {
    let values = vec!["mongo-query;dur=25.1".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::DatabaseTiming { .. }))
    );
}

#[test]
fn analyze_detects_sqlite_timing() {
    let values = vec!["sqlite;dur=5.0".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::DatabaseTiming { .. }))
    );
}

#[test]
fn analyze_detects_generic_sql_timing() {
    let values = vec!["sql-exec;dur=100.5".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::DatabaseTiming { .. }))
    );
}

#[test]
fn analyze_detects_slow_query() {
    let values = vec!["db;dur=1500.0".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::SlowQuery { .. }))
    );
}

#[test]
fn analyze_slow_query_threshold() {
    let values = vec!["db;dur=999.0".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::SlowQuery { .. }))
    );
}

#[test]
fn analyze_slow_query_exactly_at_threshold() {
    let values = vec!["mysql;dur=1000.0".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::SlowQuery { .. }))
    );
}

#[test]
fn analyze_slow_query_above_threshold() {
    let values = vec!["postgres;dur=1000.1".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::SlowQuery { .. }))
    );
}

#[test]
fn analyze_detects_cache_timing() {
    let values = vec!["cache;desc=\"HIT\"".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::CacheTiming { .. }))
    );
}

#[test]
fn analyze_cache_hit_detected() {
    let values = vec!["cache;desc=\"HIT\"".to_string()];
    let issues = analyze_timing_metrics(&values);
    let cache_issue = issues
        .iter()
        .find(|i| matches!(i, ServerTimingIssue::CacheTiming { .. }));
    match cache_issue {
        Some(ServerTimingIssue::CacheTiming { hit, .. }) => assert!(hit),
        _ => panic!("Expected cache timing issue"),
    }
}

#[test]
fn analyze_cache_miss_detected() {
    let values = vec!["cache;desc=\"MISS\"".to_string()];
    let issues = analyze_timing_metrics(&values);
    let cache_issue = issues
        .iter()
        .find(|i| matches!(i, ServerTimingIssue::CacheTiming { .. }));
    match cache_issue {
        Some(ServerTimingIssue::CacheTiming { hit, .. }) => assert!(!hit),
        _ => panic!("Expected cache timing issue"),
    }
}

#[test]
fn analyze_cache_no_desc_is_miss() {
    let values = vec!["cache;dur=10".to_string()];
    let issues = analyze_timing_metrics(&values);
    let cache_issue = issues
        .iter()
        .find(|i| matches!(i, ServerTimingIssue::CacheTiming { .. }));
    match cache_issue {
        Some(ServerTimingIssue::CacheTiming { hit, .. }) => assert!(!hit),
        _ => panic!("Expected cache timing issue"),
    }
}

#[test]
fn analyze_detects_memcache() {
    let values = vec!["memcache;dur=2.5".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::CacheTiming { .. }))
    );
}

#[test]
fn analyze_detects_redis_as_cache() {
    let values = vec!["redis;dur=1.2".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::CacheTiming { .. }))
    );
}

#[test]
fn analyze_detects_varnish() {
    let values = vec!["varnish;desc=\"hit\"".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::CacheTiming { .. }))
    );
}

#[test]
fn analyze_detects_auth_timing() {
    let values = vec!["auth;dur=35.0".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::AuthTiming { .. }))
    );
}

#[test]
fn analyze_detects_token_timing() {
    let values = vec!["token-validation;dur=12.0".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::AuthTiming { .. }))
    );
}

#[test]
fn analyze_detects_session_timing() {
    let values = vec!["session-lookup;dur=8.5".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::AuthTiming { .. }))
    );
}

#[test]
fn analyze_detects_internal_service() {
    let values = vec!["internal-api;dur=100.0".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::InternalServiceTiming { .. }))
    );
}

#[test]
fn analyze_detects_backend_service() {
    let values = vec!["backend-call;dur=250.0".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::InternalServiceTiming { .. }))
    );
}

#[test]
fn analyze_detects_upstream_service() {
    let values = vec!["upstream;dur=75.0".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::InternalServiceTiming { .. }))
    );
}

#[test]
fn analyze_detects_queue_timing() {
    let values = vec!["queue;dur=15.0".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::QueueTiming { .. }))
    );
}

#[test]
fn analyze_detects_worker_timing() {
    let values = vec!["worker-process;dur=500.0".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::QueueTiming { .. }))
    );
}

#[test]
fn analyze_detects_job_timing() {
    let values = vec!["job-execution;dur=1200.0".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::QueueTiming { .. }))
    );
}

#[test]
fn analyze_detects_cdn_timing() {
    let values = vec!["cdn;dur=50.0".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::CdnTiming { .. }))
    );
}

#[test]
fn analyze_detects_edge_timing() {
    let values = vec!["edge-server;dur=20.0".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::CdnTiming { .. }))
    );
}

#[test]
fn analyze_detects_pop_timing() {
    let values = vec!["pop-location;dur=30.0".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::CdnTiming { .. }))
    );
}

#[test]
fn analyze_detects_k8s_leak() {
    let values = vec!["k8s-pod;dur=10.0".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::BackendInfraLeak { .. }))
    );
}

#[test]
fn analyze_detects_docker_leak() {
    let values = vec!["docker-container;dur=5.0".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::BackendInfraLeak { .. }))
    );
}

#[test]
fn analyze_detects_lambda_leak() {
    let values = vec!["lambda-invoke;dur=150.0".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::BackendInfraLeak { .. }))
    );
}

#[test]
fn analyze_detects_fargate_leak() {
    let values = vec!["fargate-task;dur=80.0".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::BackendInfraLeak { .. }))
    );
}

#[test]
fn analyze_detects_high_precision_timing() {
    let values = vec!["api-call;dur=0.5".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::HighPrecisionTiming { .. }))
    );
}

#[test]
fn analyze_high_precision_at_boundary() {
    let values = vec!["api-call;dur=0.9".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::HighPrecisionTiming { .. }))
    );
}

#[test]
fn analyze_high_precision_not_at_one_ms() {
    let values = vec!["api-call;dur=1.0".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::HighPrecisionTiming { .. }))
    );
}

#[test]
fn analyze_high_precision_zero_not_detected() {
    let values = vec!["api-call;dur=0.0".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::HighPrecisionTiming { .. }))
    );
}

#[test]
fn analyze_detects_excessive_metrics() {
    let metrics: Vec<String> = (0..11).map(|i| format!("metric{};dur=10", i)).collect();
    let values = vec![metrics.join(", ")];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::ExcessiveMetrics { .. }))
    );
}

#[test]
fn analyze_excessive_metrics_exactly_at_threshold() {
    let metrics: Vec<String> = (0..10).map(|i| format!("metric{};dur=10", i)).collect();
    let values = vec![metrics.join(", ")];
    let issues = analyze_timing_metrics(&values);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::ExcessiveMetrics { .. }))
    );
}

#[test]
fn analyze_excessive_metrics_count_correct() {
    let metrics: Vec<String> = (0..15).map(|i| format!("metric{};dur=10", i)).collect();
    let values = vec![metrics.join(", ")];
    let issues = analyze_timing_metrics(&values);
    let excessive = issues
        .iter()
        .find(|i| matches!(i, ServerTimingIssue::ExcessiveMetrics { .. }));
    match excessive {
        Some(ServerTimingIssue::ExcessiveMetrics { count }) => assert_eq!(*count, 15),
        _ => panic!("Expected excessive metrics issue"),
    }
}

#[test]
fn analyze_empty_values_no_issues() {
    let issues = analyze_timing_metrics(&[]);
    assert!(issues.is_empty());
}

#[test]
fn analyze_safe_metrics_no_issues() {
    let values = vec!["total;dur=200, render;dur=50".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(issues.is_empty());
}

#[test]
fn analyze_multiple_issue_types() {
    let values = vec!["db;dur=1500.0, cache;desc=\"HIT\", auth;dur=10".to_string()];
    let issues = analyze_timing_metrics(&values);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::DatabaseTiming { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::SlowQuery { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::CacheTiming { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServerTimingIssue::AuthTiming { .. }))
    );
}

#[test]
fn severity_slow_query_is_highest() {
    let issue = ServerTimingIssue::SlowQuery {
        metric: "db".to_string(),
        duration_ms: 2000.0,
    };
    assert_eq!(server_timing_issue_severity(&issue), 6.0);
}

#[test]
fn severity_database_timing() {
    let issue = ServerTimingIssue::DatabaseTiming {
        metric: "db".to_string(),
        duration_ms: Some(50.0),
    };
    assert_eq!(server_timing_issue_severity(&issue), 5.0);
}

#[test]
fn severity_auth_timing() {
    let issue = ServerTimingIssue::AuthTiming {
        metric: "auth".to_string(),
    };
    assert_eq!(server_timing_issue_severity(&issue), 4.5);
}

#[test]
fn severity_internal_service() {
    let issue = ServerTimingIssue::InternalServiceTiming {
        metric: "internal".to_string(),
        duration_ms: Some(100.0),
    };
    assert_eq!(server_timing_issue_severity(&issue), 4.0);
}

#[test]
fn severity_backend_infra_leak() {
    let issue = ServerTimingIssue::BackendInfraLeak {
        metric: "k8s".to_string(),
    };
    assert_eq!(server_timing_issue_severity(&issue), 4.0);
}

#[test]
fn severity_high_precision_timing() {
    let issue = ServerTimingIssue::HighPrecisionTiming {
        metric: "api".to_string(),
    };
    assert_eq!(server_timing_issue_severity(&issue), 3.5);
}

#[test]
fn severity_cache_timing() {
    let issue = ServerTimingIssue::CacheTiming {
        metric: "cache".to_string(),
        hit: true,
    };
    assert_eq!(server_timing_issue_severity(&issue), 3.0);
}

#[test]
fn severity_queue_timing() {
    let issue = ServerTimingIssue::QueueTiming {
        metric: "queue".to_string(),
    };
    assert_eq!(server_timing_issue_severity(&issue), 3.0);
}

#[test]
fn severity_excessive_metrics() {
    let issue = ServerTimingIssue::ExcessiveMetrics { count: 15 };
    assert_eq!(server_timing_issue_severity(&issue), 3.0);
}

#[test]
fn severity_cdn_timing_is_lowest() {
    let issue = ServerTimingIssue::CdnTiming {
        metric: "cdn".to_string(),
    };
    assert_eq!(server_timing_issue_severity(&issue), 2.0);
}

#[test]
fn issues_to_operations_empty() {
    let mut seq = 0;
    let ops = server_timing_issues_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn issues_to_operations_single_issue() {
    let issues = vec![ServerTimingIssue::DatabaseTiming {
        metric: "db".to_string(),
        duration_ms: Some(50.0),
    }];
    let mut seq = 0;
    let ops = server_timing_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn issues_to_operations_multiple_issues() {
    let issues = vec![
        ServerTimingIssue::DatabaseTiming {
            metric: "db".to_string(),
            duration_ms: Some(50.0),
        },
        ServerTimingIssue::CacheTiming {
            metric: "cache".to_string(),
            hit: true,
        },
        ServerTimingIssue::AuthTiming {
            metric: "auth".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = server_timing_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn display_database_timing_with_duration() {
    let issue = ServerTimingIssue::DatabaseTiming {
        metric: "db".to_string(),
        duration_ms: Some(50.0),
    };
    let display = format!("{}", issue);
    assert!(display.contains("Database timing leak"));
    assert!(display.contains("db"));
}

#[test]
fn display_cache_timing_hit() {
    let issue = ServerTimingIssue::CacheTiming {
        metric: "cache".to_string(),
        hit: true,
    };
    let display = format!("{}", issue);
    assert!(display.contains("Cache timing leak"));
    assert!(display.contains("hit: true"));
}

#[test]
fn display_slow_query() {
    let issue = ServerTimingIssue::SlowQuery {
        metric: "mysql".to_string(),
        duration_ms: 1500.0,
    };
    let display = format!("{}", issue);
    assert!(display.contains("Slow query leak"));
    assert!(display.contains("1500"));
}

#[test]
fn display_excessive_metrics() {
    let issue = ServerTimingIssue::ExcessiveMetrics { count: 15 };
    let display = format!("{}", issue);
    assert!(display.contains("Excessive metrics"));
    assert!(display.contains("15"));
}
