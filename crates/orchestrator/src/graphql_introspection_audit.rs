use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum GraphqlIntroIssue {
    IntrospectionEnabled { endpoint: String },
    SuggestionsEnabled { endpoint: String },
    DebugModeEnabled { endpoint: String },
    SensitiveTypesExposed { type_name: String },
}

impl std::fmt::Display for GraphqlIntroIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IntrospectionEnabled { endpoint } => {
                write!(f, "graphql_introspection_enabled:{endpoint}")
            }
            Self::SuggestionsEnabled { endpoint } => {
                write!(f, "graphql_suggestions_enabled:{endpoint}")
            }
            Self::DebugModeEnabled { endpoint } => {
                write!(f, "graphql_debug_mode:{endpoint}")
            }
            Self::SensitiveTypesExposed { type_name } => {
                write!(f, "graphql_sensitive_type:{type_name}")
            }
        }
    }
}

const GRAPHQL_PATHS: &[&str] = &["/graphql", "/graphiql", "/api/graphql", "/v1/graphql"];

const INTROSPECTION_QUERY: &str = r#"{"query":"{ __schema { types { name } } }"}"#;

const SUGGESTION_QUERY: &str = r#"{"query":"{ __typo_deliberately_wrong }"}"#;

const SENSITIVE_TYPE_PATTERNS: &[&str] = &[
    "admin",
    "internal",
    "debug",
    "secret",
    "private",
    "password",
    "credential",
    "token",
    "session",
];

pub fn audit_graphql_introspection(target: &str) -> Vec<GraphqlIntroIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };

    let base = target.trim_end_matches('/');
    let mut issues = Vec::new();

    for path in GRAPHQL_PATHS {
        let url = format!("{base}{path}");

        if let Ok(resp) = client
            .post(&url)
            .header("content-type", "application/json")
            .body(INTROSPECTION_QUERY)
            .send()
            && resp.status().is_success()
            && let Ok(body) = resp.text()
        {
            let body_lower = body.to_ascii_lowercase();
            if body_lower.contains("__schema") && body_lower.contains("types") {
                issues.push(GraphqlIntroIssue::IntrospectionEnabled {
                    endpoint: path.to_string(),
                });
                check_sensitive_types(&body_lower, &mut issues);
            }
        }

        if let Ok(resp) = client
            .post(&url)
            .header("content-type", "application/json")
            .body(SUGGESTION_QUERY)
            .send()
            && let Ok(body) = resp.text()
        {
            let body_lower = body.to_ascii_lowercase();
            if body_lower.contains("did you mean") {
                issues.push(GraphqlIntroIssue::SuggestionsEnabled {
                    endpoint: path.to_string(),
                });
            }
            if body_lower.contains("\"debug\"")
                || (body_lower.contains("\"extensions\"") && body_lower.contains("\"stack\""))
            {
                issues.push(GraphqlIntroIssue::DebugModeEnabled {
                    endpoint: path.to_string(),
                });
            }
        }
    }

    issues
}

pub fn analyze_graphql_response(
    endpoint: &str,
    introspection_body: &str,
    error_body: &str,
) -> Vec<GraphqlIntroIssue> {
    let mut issues = Vec::new();
    let intro_lower = introspection_body.to_ascii_lowercase();
    let err_lower = error_body.to_ascii_lowercase();

    if intro_lower.contains("__schema") && intro_lower.contains("types") {
        issues.push(GraphqlIntroIssue::IntrospectionEnabled {
            endpoint: endpoint.to_string(),
        });
        check_sensitive_types(&intro_lower, &mut issues);
    }

    if err_lower.contains("did you mean") {
        issues.push(GraphqlIntroIssue::SuggestionsEnabled {
            endpoint: endpoint.to_string(),
        });
    }

    if err_lower.contains("\"debug\"")
        || (err_lower.contains("\"extensions\"") && err_lower.contains("\"stack\""))
    {
        issues.push(GraphqlIntroIssue::DebugModeEnabled {
            endpoint: endpoint.to_string(),
        });
    }

    issues
}

fn check_sensitive_types(body_lower: &str, issues: &mut Vec<GraphqlIntroIssue>) {
    for pattern in SENSITIVE_TYPE_PATTERNS {
        let quoted = format!("\"{pattern}");
        if body_lower.contains(&quoted) {
            issues.push(GraphqlIntroIssue::SensitiveTypesExposed {
                type_name: pattern.to_string(),
            });
        }
    }
}

pub(crate) fn graphql_intro_severity(issue: &GraphqlIntroIssue) -> f64 {
    match issue {
        GraphqlIntroIssue::SensitiveTypesExposed { .. } => 7.0,
        GraphqlIntroIssue::IntrospectionEnabled { .. } => 6.0,
        GraphqlIntroIssue::DebugModeEnabled { .. } => 5.5,
        GraphqlIntroIssue::SuggestionsEnabled { .. } => 3.0,
    }
}

pub fn graphql_intro_to_operations(
    issues: &[GraphqlIntroIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                graphql_intro_severity(issue),
                0.9,
            )
        })
        .collect()
}
