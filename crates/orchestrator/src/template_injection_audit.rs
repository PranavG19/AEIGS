use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum TemplateInjectionIssue {
    AngularExpression,
    VueInterpolation,
    HandlebarsExpression,
    EjsExpression,
    JinjaExpression,
    PugExpression,
    TemplateStringEval,
}

impl std::fmt::Display for TemplateInjectionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AngularExpression => write!(f, "angular_template_injection"),
            Self::VueInterpolation => write!(f, "vue_template_injection"),
            Self::HandlebarsExpression => write!(f, "handlebars_template_injection"),
            Self::EjsExpression => write!(f, "ejs_template_injection"),
            Self::JinjaExpression => write!(f, "jinja_template_injection"),
            Self::PugExpression => write!(f, "pug_template_injection"),
            Self::TemplateStringEval => write!(f, "template_string_eval"),
        }
    }
}

const ANGULAR_SINKS: &[&str] = &[
    "ng-bind-html",
    "ng-bind-template",
    "[innerHTML]",
    "bypassSecurityTrustHtml",
    "bypassSecurityTrustScript",
    "bypassSecurityTrustUrl",
    "bypassSecurityTrustResourceUrl",
];

const VUE_SINKS: &[&str] = &["v-html", "v-bind:innerHTML", "$compile"];

const TEMPLATE_EVAL_PATTERNS: &[&str] = &[
    "new Function(",
    "eval(",
    "setTimeout(\"",
    "setTimeout('",
    "setInterval(\"",
    "setInterval('",
];

pub fn audit_template_injection(target: &str) -> Vec<TemplateInjectionIssue> {
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
    analyze_template_injection(&body)
}

pub fn analyze_template_injection(body: &str) -> Vec<TemplateInjectionIssue> {
    let mut issues = Vec::new();

    if ANGULAR_SINKS.iter().any(|s| body.contains(s)) {
        issues.push(TemplateInjectionIssue::AngularExpression);
    }

    if VUE_SINKS.iter().any(|s| body.contains(s)) {
        issues.push(TemplateInjectionIssue::VueInterpolation);
    }

    if has_handlebars_injection_risk(body) {
        issues.push(TemplateInjectionIssue::HandlebarsExpression);
    }

    if body.contains("<%=") || body.contains("<%-") {
        issues.push(TemplateInjectionIssue::EjsExpression);
    }

    if has_jinja_risk(body) {
        issues.push(TemplateInjectionIssue::JinjaExpression);
    }

    if body.contains("!= ") && body.contains("extends ") && body.contains("block ") {
        issues.push(TemplateInjectionIssue::PugExpression);
    }

    if TEMPLATE_EVAL_PATTERNS.iter().any(|p| body.contains(p)) {
        issues.push(TemplateInjectionIssue::TemplateStringEval);
    }

    issues
}

fn has_handlebars_injection_risk(body: &str) -> bool {
    let has_triple = body.contains("{{{");
    let has_helper_missing = body.contains("helperMissing") || body.contains("blockHelperMissing");
    let has_lookup = body.contains("{{lookup") || body.contains("{{#with");
    has_triple || has_helper_missing || has_lookup
}

fn has_jinja_risk(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    (lower.contains("{{") && lower.contains("__class__"))
        || (lower.contains("{{") && lower.contains("__mro__"))
        || (lower.contains("{{") && lower.contains("__subclasses__"))
        || (lower.contains("{%") && lower.contains("import"))
}

pub fn template_injection_severity(issue: &TemplateInjectionIssue) -> f64 {
    match issue {
        TemplateInjectionIssue::AngularExpression => 7.5,
        TemplateInjectionIssue::JinjaExpression => 7.0,
        TemplateInjectionIssue::EjsExpression => 6.5,
        TemplateInjectionIssue::VueInterpolation => 6.5,
        TemplateInjectionIssue::HandlebarsExpression => 6.0,
        TemplateInjectionIssue::PugExpression => 6.0,
        TemplateInjectionIssue::TemplateStringEval => 5.5,
    }
}

pub fn template_injection_to_operations(
    issues: &[TemplateInjectionIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::CrossSiteScripting,
                template_injection_severity(issue),
                0.7,
            )
        })
        .collect()
}
