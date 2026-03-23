use crate::scheduler_api_audit::*;

#[test]
fn no_scheduler_no_issues() {
    assert!(analyze_scheduler_api("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_post_task() {
    let body = r#"<script>scheduler.postTask(() => doWork());</script>"#;
    let issues = analyze_scheduler_api(body);
    assert!(issues.contains(&SchedulerApiIssue::ApiDetected));
}

#[test]
fn detects_scheduler_yield() {
    let body = r#"<script>await scheduler.yield();</script>"#;
    let issues = analyze_scheduler_api(body);
    assert!(issues.contains(&SchedulerApiIssue::ApiDetected));
}

#[test]
fn detects_task_controller() {
    let body = r#"<script>const tc = new TaskController({priority: "background"});</script>"#;
    let issues = analyze_scheduler_api(body);
    assert!(issues.contains(&SchedulerApiIssue::ApiDetected));
}

#[test]
fn detects_priority_manipulation() {
    let body = r#"<script>
        while (true) {
            scheduler.postTask(() => mineData(), {priority: "user-blocking"});
        }
    </script>"#;
    let issues = analyze_scheduler_api(body);
    assert!(issues.contains(&SchedulerApiIssue::PriorityManipulation));
}

#[test]
fn no_priority_manipulation_without_loop() {
    let body = r#"<script>
        scheduler.postTask(() => doWork(), {priority: "user-blocking"});
    </script>"#;
    let issues = analyze_scheduler_api(body);
    assert!(!issues.contains(&SchedulerApiIssue::PriorityManipulation));
}

#[test]
fn detects_task_starvation() {
    let body = r#"<script>
        scheduler.postTask(() => heavyWork(), {priority: "background", delay: 0});
    </script>"#;
    let issues = analyze_scheduler_api(body);
    assert!(issues.contains(&SchedulerApiIssue::TaskStarvation));
}

#[test]
fn no_starvation_without_delay() {
    let body = r#"<script>
        scheduler.postTask(() => work(), {priority: "background"});
    </script>"#;
    let issues = analyze_scheduler_api(body);
    assert!(!issues.contains(&SchedulerApiIssue::TaskStarvation));
}

#[test]
fn detects_timing_attack() {
    let body = r#"<script>
        const t0 = performance.now();
        scheduler.postTask(() => {
            const elapsed = performance.now() - t0;
        });
    </script>"#;
    let issues = analyze_scheduler_api(body);
    assert!(issues.contains(&SchedulerApiIssue::TimingAttack));
}

#[test]
fn no_timing_without_perf() {
    let body = r#"<script>scheduler.postTask(() => doWork());</script>"#;
    let issues = analyze_scheduler_api(body);
    assert!(!issues.contains(&SchedulerApiIssue::TimingAttack));
}

#[test]
fn detects_unbounded_tasks() {
    let body = r#"<script>
        while (hasWork) {
            scheduler.postTask(() => process(item));
        }
    </script>"#;
    let issues = analyze_scheduler_api(body);
    assert!(issues.contains(&SchedulerApiIssue::UnboundedTasks));
}

#[test]
fn no_unbounded_with_abort() {
    let body = r#"<script>
        const ac = new AbortController();
        while (hasWork) {
            scheduler.postTask(() => process(item), {signal: ac.signal});
        }
    </script>"#;
    let issues = analyze_scheduler_api(body);
    assert!(!issues.contains(&SchedulerApiIssue::UnboundedTasks));
}

#[test]
fn severity_priority_highest() {
    assert_eq!(
        scheduler_api_severity(&SchedulerApiIssue::PriorityManipulation),
        6.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(scheduler_api_severity(&SchedulerApiIssue::ApiDetected), 2.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        SchedulerApiIssue::ApiDetected,
        SchedulerApiIssue::TimingAttack,
    ];
    let mut seq = 0;
    let ops = scheduler_api_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(SchedulerApiIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        SchedulerApiIssue::PriorityManipulation.to_string(),
        "priority_manipulation"
    );
    assert_eq!(
        SchedulerApiIssue::TaskStarvation.to_string(),
        "task_starvation"
    );
    assert_eq!(SchedulerApiIssue::TimingAttack.to_string(), "timing_attack");
    assert_eq!(
        SchedulerApiIssue::UnboundedTasks.to_string(),
        "unbounded_tasks"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_scheduler_api("").is_empty());
}
