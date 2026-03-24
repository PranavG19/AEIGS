use std::collections::HashMap;

use crate::multi_bot_coordinator::*;

#[tokio::test]
async fn register_bot_assigns_unique_ids() {
    let coord = MultiBotCoordinator::new(CoordinatorConfig::default());
    let bot1 = coord.register_bot().await;
    let bot2 = coord.register_bot().await;
    let bot3 = coord.register_bot().await;
    assert_ne!(bot1, bot2);
    assert_ne!(bot2, bot3);
}

#[tokio::test]
async fn initialize_pool_creates_correct_count() {
    let config = CoordinatorConfig::default().with_initial_bot_count(6);
    let coord = MultiBotCoordinator::new(config);
    let bots = coord.initialize_pool().await;
    assert_eq!(bots.len(), 6);

    let statuses = coord.bot_status_summary().await;
    assert_eq!(statuses.len(), 6);
    assert!(statuses.values().all(|s| *s == BotStatus::Idle));
}

#[tokio::test]
async fn enqueue_and_assign_tasks() {
    let coord = MultiBotCoordinator::new(CoordinatorConfig::default());
    let bot = coord.register_bot().await;

    coord
        .enqueue_task("http://localhost:8080/api", "GET", ScanTaskType::Crawl, 5)
        .await;
    coord
        .enqueue_task("http://localhost:8080/login", "POST", ScanTaskType::Fuzz, 10)
        .await;

    let task = coord.assign_task(bot).await;
    assert!(task.is_some());
    let task = task.unwrap();
    assert_eq!(task.priority, 10);
    assert_eq!(task.url, "http://localhost:8080/login");
    assert_eq!(task.assigned_bot, Some(bot));

    let statuses = coord.bot_status_summary().await;
    assert_eq!(statuses[&bot], BotStatus::Scanning);
}

#[tokio::test]
async fn no_task_returns_none() {
    let coord = MultiBotCoordinator::new(CoordinatorConfig::default());
    let bot = coord.register_bot().await;

    let task = coord.assign_task(bot).await;
    assert!(task.is_none());

    let statuses = coord.bot_status_summary().await;
    assert_eq!(statuses[&bot], BotStatus::WaitingForTask);
}

#[tokio::test]
async fn complete_task_updates_stats() {
    let coord = MultiBotCoordinator::new(CoordinatorConfig::default());
    let bot = coord.register_bot().await;

    coord
        .enqueue_task("http://localhost:8080/test", "GET", ScanTaskType::Crawl, 5)
        .await;

    let task = coord.assign_task(bot).await.unwrap();
    coord.complete_task(bot, &task, 150).await;

    let stats = coord.bot_stats_summary().await;
    assert_eq!(stats[&bot].tasks_completed, 1);
    assert!((stats[&bot].avg_response_ms - 150.0).abs() < 0.01);
    assert!(coord.is_url_completed("http://localhost:8080/test").await);
}

#[tokio::test]
async fn fail_task_requeues_within_retry_limit() {
    let config = CoordinatorConfig::default().with_max_retries(3);
    let coord = MultiBotCoordinator::new(config);
    let bot = coord.register_bot().await;

    coord
        .enqueue_task("http://localhost:8080/flaky", "GET", ScanTaskType::Fuzz, 5)
        .await;

    let task = coord.assign_task(bot).await.unwrap();
    assert_eq!(task.retries, 0);
    coord.fail_task(bot, task).await;

    assert_eq!(coord.pending_task_count().await, 1);

    let stats = coord.bot_stats_summary().await;
    assert_eq!(stats[&bot].tasks_failed, 1);
}

#[tokio::test]
async fn fail_task_drops_at_max_retries() {
    let config = CoordinatorConfig::default().with_max_retries(0);
    let coord = MultiBotCoordinator::new(config);
    let bot = coord.register_bot().await;

    coord
        .enqueue_task("http://localhost:8080/broken", "GET", ScanTaskType::Crawl, 5)
        .await;

    let task = coord.assign_task(bot).await.unwrap();
    coord.fail_task(bot, task).await;

    assert_eq!(coord.pending_task_count().await, 0);
}

#[tokio::test]
async fn share_finding_across_bots() {
    let coord = MultiBotCoordinator::new(CoordinatorConfig::default());
    let bot1 = coord.register_bot().await;
    let _bot2 = coord.register_bot().await;

    let finding = SharedFinding {
        url: "http://localhost:8080/vuln".to_string(),
        finding_type: "XSS".to_string(),
        severity: FindingSeverity::High,
        discovered_by: bot1,
        timestamp_ms: 1700000000000,
        details: "Reflected XSS in search param".to_string(),
    };

    coord.share_finding(finding).await;

    let findings = coord.get_findings().await;
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].finding_type, "XSS");
    assert_eq!(findings[0].discovered_by, bot1);

    let stats = coord.bot_stats_summary().await;
    assert_eq!(stats[&bot1].findings_count, 1);
}

#[tokio::test]
async fn share_session_and_retrieve_by_role() {
    let coord = MultiBotCoordinator::new(CoordinatorConfig::default());

    let admin_session = SharedSession {
        session_id: "sess_admin_1".to_string(),
        cookies: HashMap::from([("sid".to_string(), "admin123".to_string())]),
        headers: HashMap::new(),
        token: Some("jwt_admin_token".to_string()),
        expires_at_ms: Some(1700000100000),
        role: "admin".to_string(),
    };

    let user_session = SharedSession {
        session_id: "sess_user_1".to_string(),
        cookies: HashMap::from([("sid".to_string(), "user456".to_string())]),
        headers: HashMap::new(),
        token: Some("jwt_user_token".to_string()),
        expires_at_ms: None,
        role: "user".to_string(),
    };

    coord.share_session(admin_session).await;
    coord.share_session(user_session).await;

    let sessions = coord.get_sessions().await;
    assert_eq!(sessions.len(), 2);

    let admin = coord.get_session_for_role("admin").await;
    assert!(admin.is_some());
    assert_eq!(admin.unwrap().token.as_deref(), Some("jwt_admin_token"));

    let guest = coord.get_session_for_role("guest").await;
    assert!(guest.is_none());
}

#[tokio::test]
async fn rate_limit_reporting() {
    let coord = MultiBotCoordinator::new(CoordinatorConfig::default());
    let bot = coord.register_bot().await;

    coord.report_rate_limit(bot).await;

    let statuses = coord.bot_status_summary().await;
    assert_eq!(statuses[&bot], BotStatus::RateLimited);

    let stats = coord.bot_stats_summary().await;
    assert_eq!(stats[&bot].rate_limit_hits, 1);
}

#[tokio::test]
async fn race_condition_test_enqueues_multiple() {
    let coord = MultiBotCoordinator::new(CoordinatorConfig::default());

    let ids = coord
        .enqueue_race_condition_test("http://localhost:8080/transfer", "POST", 5)
        .await;
    assert_eq!(ids.len(), 5);
    assert_eq!(coord.pending_task_count().await, 5);

    let unique_ids: std::collections::HashSet<_> = ids.into_iter().collect();
    assert_eq!(unique_ids.len(), 5);
}

#[tokio::test]
async fn priority_ordering_in_queue() {
    let coord = MultiBotCoordinator::new(CoordinatorConfig::default());
    let bot = coord.register_bot().await;

    coord
        .enqueue_task("http://localhost/low", "GET", ScanTaskType::Crawl, 1)
        .await;
    coord
        .enqueue_task("http://localhost/high", "GET", ScanTaskType::Fuzz, 100)
        .await;
    coord
        .enqueue_task("http://localhost/mid", "GET", ScanTaskType::Crawl, 50)
        .await;

    let first = coord.assign_task(bot).await.unwrap();
    assert_eq!(first.url, "http://localhost/high");
    assert_eq!(first.priority, 100);
}

#[tokio::test]
async fn shutdown_bot_marks_status() {
    let coord = MultiBotCoordinator::new(CoordinatorConfig::default());
    let bot = coord.register_bot().await;

    coord.shutdown_bot(bot).await;

    let statuses = coord.bot_status_summary().await;
    assert_eq!(statuses[&bot], BotStatus::Shutdown);
}

#[tokio::test]
async fn scaling_no_change_default() {
    let coord = MultiBotCoordinator::new(CoordinatorConfig::default());
    let _ = coord.initialize_pool().await;

    let decision = coord.evaluate_scaling().await;
    assert_eq!(decision, ScaleDecision::NoChange);
}

#[tokio::test]
async fn scaling_down_when_rate_limited() {
    let config = CoordinatorConfig::default().with_initial_bot_count(4);
    let coord = MultiBotCoordinator::new(config);
    let bots = coord.initialize_pool().await;

    for bot in &bots[..3] {
        coord.report_rate_limit(*bot).await;
    }

    let decision = coord.evaluate_scaling().await;
    match decision {
        ScaleDecision::ScaleDown(n) => assert!(n > 0),
        _ => panic!("expected ScaleDown, got {:?}", decision),
    }
}

#[test]
fn coordinator_config_builder() {
    let config = CoordinatorConfig::default()
        .with_initial_bot_count(8)
        .with_max_bot_count(32)
        .with_task_timeout(std::time::Duration::from_secs(60))
        .with_max_retries(5);
    assert_eq!(config.initial_bot_count, 8);
    assert_eq!(config.max_bot_count, 32);
    assert_eq!(config.task_timeout, std::time::Duration::from_secs(60));
    assert_eq!(config.max_retries_per_task, 5);
}

#[test]
fn finding_severity_ordering() {
    assert!(FindingSeverity::Critical > FindingSeverity::High);
    assert!(FindingSeverity::High > FindingSeverity::Medium);
    assert!(FindingSeverity::Medium > FindingSeverity::Low);
    assert!(FindingSeverity::Low > FindingSeverity::Info);
}
