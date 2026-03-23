use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WindowNameIssue {
    WindowNameRead,
    WindowNameWrite,
    WindowNameInConditional,
    WindowNameDataParsing,
    WindowNameCrossOriginLeak,
}

impl std::fmt::Display for WindowNameIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WindowNameRead => write!(f, "window_name_read"),
            Self::WindowNameWrite => write!(f, "window_name_write"),
            Self::WindowNameInConditional => write!(f, "window_name_conditional"),
            Self::WindowNameDataParsing => write!(f, "window_name_data_parsing"),
            Self::WindowNameCrossOriginLeak => write!(f, "window_name_cross_origin"),
        }
    }
}

pub fn audit_window_name(target: &str) -> Vec<WindowNameIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    analyze_window_name(&body)
}

pub fn analyze_window_name(body: &str) -> Vec<WindowNameIssue> {
    if !body.contains("window.name") && !body.contains("self.name") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if has_window_name_read(body) {
        issues.push(WindowNameIssue::WindowNameRead);
    }

    if has_window_name_write(body) {
        issues.push(WindowNameIssue::WindowNameWrite);
    }

    if has_conditional_check(body) {
        issues.push(WindowNameIssue::WindowNameInConditional);
    }

    if has_data_parsing(body) {
        issues.push(WindowNameIssue::WindowNameDataParsing);
    }

    if has_cross_origin_pattern(body) {
        issues.push(WindowNameIssue::WindowNameCrossOriginLeak);
    }

    issues
}

fn has_window_name_read(body: &str) -> bool {
    let read_patterns = [
        "= window.name",
        "=window.name",
        "(window.name)",
        "= self.name",
        "=self.name",
        "(self.name)",
        "console.log(window.name",
    ];
    read_patterns.iter().any(|p| body.contains(p))
}

fn has_window_name_write(body: &str) -> bool {
    let write_patterns = ["window.name =", "window.name=", "self.name =", "self.name="];
    write_patterns.iter().any(|p| body.contains(p))
}

fn has_conditional_check(body: &str) -> bool {
    let cond_patterns = [
        "if(window.name",
        "if (window.name",
        "if(self.name",
        "if (self.name",
        "window.name ?",
        "window.name?",
        "window.name &&",
        "window.name ||",
    ];
    cond_patterns.iter().any(|p| body.contains(p))
}

fn has_data_parsing(body: &str) -> bool {
    let parse_patterns = [
        "JSON.parse(window.name",
        "JSON.parse(self.name",
        "atob(window.name",
        "decodeURIComponent(window.name",
        "window.name.split",
        "self.name.split",
        "window.name.substring",
        "window.name.slice",
    ];
    parse_patterns.iter().any(|p| body.contains(p))
}

fn has_cross_origin_pattern(body: &str) -> bool {
    let has_name_usage = body.contains("window.name") || body.contains("self.name");
    let has_navigation = body.contains("location.href")
        || body.contains("location.replace")
        || body.contains("window.open")
        || body.contains("location =");
    has_name_usage && has_navigation
}

pub fn window_name_severity(issue: &WindowNameIssue) -> f64 {
    match issue {
        WindowNameIssue::WindowNameCrossOriginLeak => 7.0,
        WindowNameIssue::WindowNameDataParsing => 6.5,
        WindowNameIssue::WindowNameInConditional => 5.0,
        WindowNameIssue::WindowNameWrite => 4.5,
        WindowNameIssue::WindowNameRead => 4.0,
    }
}

pub fn window_name_to_operations(
    issues: &[WindowNameIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                window_name_severity(issue),
                0.7,
            )
        })
        .collect()
}
