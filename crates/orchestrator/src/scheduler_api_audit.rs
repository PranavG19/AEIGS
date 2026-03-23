use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum SchedulerApiIssue {
    ApiDetected,
    PriorityManipulation,
    TaskStarvation,
    TimingAttack,
    UnboundedTasks,
}

impl std::fmt::Display for SchedulerApiIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::PriorityManipulation => write!(f, "priority_manipulation"),
            Self::TaskStarvation => write!(f, "task_starvation"),
            Self::TimingAttack => write!(f, "timing_attack"),
            Self::UnboundedTasks => write!(f, "unbounded_tasks"),
        }
    }
}

pub fn audit_scheduler_api(target: &str) -> Vec<SchedulerApiIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send() {
        Ok(r) => r.text().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    analyze_scheduler_api(&body)
}

pub fn analyze_scheduler_api(body: &str) -> Vec<SchedulerApiIssue> {
    let has_api = body.contains("scheduler.postTask")
        || body.contains("scheduler.yield")
        || body.contains("TaskController");

    if !has_api {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(SchedulerApiIssue::ApiDetected);

    if body.contains("priority")
        && (body.contains("\"user-blocking\"") || body.contains("'user-blocking'"))
        && (body.contains("while") || body.contains("setInterval") || body.contains("for(") || body.contains("for ("))
    {
        issues.push(SchedulerApiIssue::PriorityManipulation);
    }

    if body.contains("postTask")
        && body.contains("\"background\"")
        && (body.contains("delay") || body.contains("setTimeout"))
    {
        issues.push(SchedulerApiIssue::TaskStarvation);
    }

    if has_api
        && (body.contains("performance.now") || body.contains("Date.now"))
        && body.contains("postTask")
    {
        issues.push(SchedulerApiIssue::TimingAttack);
    }

    if body.contains("postTask")
        && (body.contains("while") || body.contains("for(") || body.contains("for ("))
        && !body.contains("abort") && !body.contains("AbortController") && !body.contains("limit")
    {
        issues.push(SchedulerApiIssue::UnboundedTasks);
    }

    issues
}

pub fn scheduler_api_severity(issue: &SchedulerApiIssue) -> f64 {
    match issue {
        SchedulerApiIssue::PriorityManipulation => 6.5,
        SchedulerApiIssue::UnboundedTasks => 6.0,
        SchedulerApiIssue::TaskStarvation => 5.5,
        SchedulerApiIssue::TimingAttack => 5.0,
        SchedulerApiIssue::ApiDetected => 2.0,
    }
}

pub fn scheduler_api_to_operations(
    issues: &[SchedulerApiIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                scheduler_api_severity(issue),
                0.5,
            )
        })
        .collect()
}
