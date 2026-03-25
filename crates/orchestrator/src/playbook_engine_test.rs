use super::playbook_engine::*;
use aegis_protocol::finding::VulnerabilityClass;

#[test]
fn create_basic_playbook() {
    let pb = Playbook::new(
        "web-pentest-1",
        "Standard Web Pentest",
        "Full OWASP workflow",
    )
    .with_step(PlaybookStep::new(
        "recon",
        "Reconnaissance",
        PlaybookAction::Recon,
    ))
    .with_step(
        PlaybookStep::new("crawl", "Crawl Target", PlaybookAction::Crawl).with_dependency("recon"),
    )
    .with_step(
        PlaybookStep::new("fuzz", "Fuzz Endpoints", PlaybookAction::Fuzz)
            .with_dependency("crawl")
            .with_target_class(VulnerabilityClass::SqlInjection)
            .with_target_class(VulnerabilityClass::CrossSiteScripting),
    );

    assert_eq!(pb.steps.len(), 3);
    assert_eq!(pb.name, "Standard Web Pentest");
    assert!(pb.validate().is_ok());
}

#[test]
fn validate_detects_missing_dependency() {
    let pb = Playbook::new("bad", "Bad Playbook", "Has broken deps").with_step(
        PlaybookStep::new("step1", "First", PlaybookAction::Recon).with_dependency("nonexistent"),
    );

    let errors = pb.validate().unwrap_err();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("nonexistent"));
}

#[test]
fn validate_detects_duplicate_ids() {
    let pb = Playbook::new("dup", "Dup IDs", "Two steps same id")
        .with_step(PlaybookStep::new("step1", "First", PlaybookAction::Recon))
        .with_step(PlaybookStep::new("step1", "Second", PlaybookAction::Crawl));

    let errors = pb.validate().unwrap_err();
    assert!(errors.iter().any(|e| e.contains("duplicate step id")));
}

#[test]
fn validate_detects_bad_branch_target() {
    let pb = Playbook::new("bad-branch", "Bad Branch", "Branch to nowhere").with_step(
        PlaybookStep::new("step1", "First", PlaybookAction::Recon).with_branch(ConditionalBranch {
            condition: BranchCondition::Always,
            target_step_id: "ghost".to_string(),
            description: "goes nowhere".to_string(),
        }),
    );

    let errors = pb.validate().unwrap_err();
    assert!(errors.iter().any(|e| e.contains("ghost")));
}

#[test]
fn execution_basic_linear_flow() {
    let pb = Playbook::new("linear", "Linear", "A→B→C")
        .with_step(PlaybookStep::new("a", "Step A", PlaybookAction::Recon))
        .with_step(PlaybookStep::new("b", "Step B", PlaybookAction::Crawl).with_dependency("a"))
        .with_step(PlaybookStep::new("c", "Step C", PlaybookAction::Fuzz).with_dependency("b"));

    let mut exec = PlaybookExecution::start(pb);
    assert!(!exec.is_finished);

    let ready = exec.ready_steps();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].id, "a");

    let adv = exec
        .advance_step(
            "a",
            true,
            Some(StepOutput {
                findings_discovered: vec![],
                endpoints_found: vec!["/api".to_string()],
                notes: "found endpoints".to_string(),
                duration_ms: 1200,
            }),
        )
        .unwrap();

    assert_eq!(adv.executed_step_id, "a");
    assert_eq!(adv.status, StepStatus::Succeeded);
    assert!(adv.next_steps.contains(&"b".to_string()));

    let adv = exec.advance_step("b", true, None).unwrap();
    assert!(adv.next_steps.contains(&"c".to_string()));

    exec.advance_step("c", true, None);
    assert!(exec.is_finished);
}

#[test]
fn execution_conditional_branch_on_vuln_found() {
    let pb = Playbook::new("branch-test", "Branch", "XSS triggers cookie theft")
        .with_step(
            PlaybookStep::new("fuzz", "Fuzz", PlaybookAction::Fuzz).with_branch(
                ConditionalBranch {
                    condition: BranchCondition::VulnFound(VulnerabilityClass::CrossSiteScripting),
                    target_step_id: "cookie-theft".to_string(),
                    description: "XSS found → steal cookies".to_string(),
                },
            ),
        )
        .with_step(PlaybookStep::new(
            "cookie-theft",
            "Cookie Theft Exploit",
            PlaybookAction::Exploit,
        ))
        .with_step(PlaybookStep::new(
            "report",
            "Generate Report",
            PlaybookAction::Report,
        ));

    let mut exec = PlaybookExecution::start(pb);

    let adv = exec
        .advance_step(
            "fuzz",
            true,
            Some(StepOutput {
                findings_discovered: vec![VulnerabilityClass::CrossSiteScripting],
                endpoints_found: vec![],
                notes: "reflected XSS in search param".to_string(),
                duration_ms: 3400,
            }),
        )
        .unwrap();

    assert!(adv.branches_taken.contains(&"cookie-theft".to_string()));
    assert!(adv.next_steps.contains(&"cookie-theft".to_string()));
}

#[test]
fn execution_branch_not_taken_when_vuln_not_found() {
    let pb = Playbook::new("no-branch", "NoBranch", "SQLi branch not taken")
        .with_step(
            PlaybookStep::new("fuzz", "Fuzz", PlaybookAction::Fuzz).with_branch(
                ConditionalBranch {
                    condition: BranchCondition::VulnFound(VulnerabilityClass::SqlInjection),
                    target_step_id: "sqli-exploit".to_string(),
                    description: "SQLi found → exploit".to_string(),
                },
            ),
        )
        .with_step(PlaybookStep::new(
            "sqli-exploit",
            "SQLi Exploit",
            PlaybookAction::Exploit,
        ));

    let mut exec = PlaybookExecution::start(pb);

    let adv = exec
        .advance_step(
            "fuzz",
            true,
            Some(StepOutput {
                findings_discovered: vec![VulnerabilityClass::CrossSiteScripting],
                endpoints_found: vec![],
                notes: "only XSS found".to_string(),
                duration_ms: 2000,
            }),
        )
        .unwrap();

    assert!(adv.branches_taken.is_empty());
}

#[test]
fn parallel_groups() {
    let pb = Playbook::new("parallel", "Parallel", "Two tracks")
        .with_step(
            PlaybookStep::new("sqli-fuzz", "SQLi Fuzz", PlaybookAction::Fuzz)
                .with_parallel_group("fuzz-track"),
        )
        .with_step(
            PlaybookStep::new("xss-fuzz", "XSS Fuzz", PlaybookAction::Fuzz)
                .with_parallel_group("fuzz-track"),
        )
        .with_step(
            PlaybookStep::new("report", "Report", PlaybookAction::Report)
                .with_dependency("sqli-fuzz")
                .with_dependency("xss-fuzz"),
        );

    let exec = PlaybookExecution::start(pb);
    let groups = exec.ready_parallel_groups();
    assert_eq!(groups, vec!["fuzz-track"]);

    let ready = exec.ready_steps();
    assert_eq!(ready.len(), 2);
}

#[test]
fn status_summary() {
    let pb = Playbook::new("sum", "Summary", "Track counts")
        .with_step(PlaybookStep::new("a", "A", PlaybookAction::Recon))
        .with_step(PlaybookStep::new("b", "B", PlaybookAction::Crawl))
        .with_step(PlaybookStep::new("c", "C", PlaybookAction::Fuzz));

    let mut exec = PlaybookExecution::start(pb);
    exec.advance_step("a", true, None);
    exec.advance_step("b", false, None);

    let summary = exec.status_summary();
    assert_eq!(summary.get("succeeded"), Some(&1));
    assert_eq!(summary.get("failed"), Some(&1));
    assert_eq!(summary.get("pending"), Some(&1));
}

#[test]
fn json_round_trip() {
    let pb = Playbook::new("rt", "Round Trip", "Serialize test").with_step(PlaybookStep::new(
        "recon",
        "Recon",
        PlaybookAction::Recon,
    ));

    let json = pb.to_json().unwrap();
    let restored = Playbook::from_yaml_str(&json).unwrap();

    assert_eq!(restored.id, "rt");
    assert_eq!(restored.steps.len(), 1);
    assert_eq!(restored.steps[0].id, "recon");
}

#[test]
fn step_builder_methods() {
    let step = PlaybookStep::new(
        "s1",
        "Step One",
        PlaybookAction::Custom("nmap-scan".to_string()),
    )
    .with_description("Run nmap against target")
    .with_target_class(VulnerabilityClass::SecurityMisconfiguration)
    .with_parallel_group("recon-track");

    assert_eq!(step.description, "Run nmap against target");
    assert_eq!(step.target_classes.len(), 1);
    assert_eq!(step.parallel_group, Some("recon-track".to_string()));
    assert_eq!(step.action, PlaybookAction::Custom("nmap-scan".to_string()));
}

#[test]
fn step_failed_branch_condition() {
    let pb = Playbook::new("fail-branch", "Fail Branch", "Retry on failure")
        .with_step(
            PlaybookStep::new("scan", "Scan", PlaybookAction::Fuzz).with_branch(
                ConditionalBranch {
                    condition: BranchCondition::StepFailed("scan".to_string()),
                    target_step_id: "retry".to_string(),
                    description: "retry on failure".to_string(),
                },
            ),
        )
        .with_step(PlaybookStep::new(
            "retry",
            "Retry Scan",
            PlaybookAction::Fuzz,
        ));

    let mut exec = PlaybookExecution::start(pb);
    let adv = exec.advance_step("scan", false, None).unwrap();

    assert!(adv.branches_taken.contains(&"retry".to_string()));
    assert!(matches!(adv.status, StepStatus::Failed(_)));
}
