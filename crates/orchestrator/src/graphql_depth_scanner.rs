use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum GraphqlDepthIssue {
    UnlimitedQueryDepth,
    BatchingEnabled,
    IntrospectionEnabled,
    FieldSuggestionsEnabled,
    NoComplexityLimit,
    DebugModeEnabled,
    NoRateLimit,
    PlaygroundExposed,
}

impl std::fmt::Display for GraphqlDepthIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnlimitedQueryDepth => write!(f, "unlimited_query_depth"),
            Self::BatchingEnabled => write!(f, "batching_enabled"),
            Self::IntrospectionEnabled => write!(f, "introspection_enabled"),
            Self::FieldSuggestionsEnabled => write!(f, "field_suggestions_enabled"),
            Self::NoComplexityLimit => write!(f, "no_complexity_limit"),
            Self::DebugModeEnabled => write!(f, "debug_mode_enabled"),
            Self::NoRateLimit => write!(f, "no_rate_limit"),
            Self::PlaygroundExposed => write!(f, "playground_exposed"),
        }
    }
}

pub fn scan_graphql_depth(target: &str) -> Vec<GraphqlDepthIssue> {
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
    analyze_graphql_depth(&body)
}

pub fn analyze_graphql_depth(body: &str) -> Vec<GraphqlDepthIssue> {
    let lower = body.to_ascii_lowercase();
    let has_graphql = lower.contains("graphql")
        || lower.contains("/graphql")
        || lower.contains("query {")
        || lower.contains("mutation {");

    if !has_graphql {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if !lower.contains("depthlimit") && !lower.contains("maxdepth") && !lower.contains("max_depth")
    {
        issues.push(GraphqlDepthIssue::UnlimitedQueryDepth);
    }

    if lower.contains("[{") || lower.contains("batch") || lower.contains("queries\":[") {
        issues.push(GraphqlDepthIssue::BatchingEnabled);
    }

    if lower.contains("__schema") || lower.contains("__type") || lower.contains("introspection") {
        issues.push(GraphqlDepthIssue::IntrospectionEnabled);
    }

    if lower.contains("did you mean") || lower.contains("suggestions") {
        issues.push(GraphqlDepthIssue::FieldSuggestionsEnabled);
    }

    if !lower.contains("complexity") && !lower.contains("cost") {
        issues.push(GraphqlDepthIssue::NoComplexityLimit);
    }

    if lower.contains("stacktrace")
        || lower.contains("\"debug\"")
        || lower.contains("internal server error")
    {
        issues.push(GraphqlDepthIssue::DebugModeEnabled);
    }

    if !lower.contains("x-ratelimit")
        && !lower.contains("ratelimit")
        && !lower.contains("rate-limit")
    {
        issues.push(GraphqlDepthIssue::NoRateLimit);
    }

    if lower.contains("graphiql") || lower.contains("playground") || lower.contains("altair") {
        issues.push(GraphqlDepthIssue::PlaygroundExposed);
    }

    issues
}

pub fn graphql_depth_severity(issue: &GraphqlDepthIssue) -> f64 {
    match issue {
        GraphqlDepthIssue::IntrospectionEnabled => 7.5,
        GraphqlDepthIssue::UnlimitedQueryDepth => 7.0,
        GraphqlDepthIssue::NoComplexityLimit => 6.5,
        GraphqlDepthIssue::BatchingEnabled => 6.5,
        GraphqlDepthIssue::DebugModeEnabled => 6.0,
        GraphqlDepthIssue::FieldSuggestionsEnabled => 5.5,
        GraphqlDepthIssue::PlaygroundExposed => 5.0,
        GraphqlDepthIssue::NoRateLimit => 5.0,
    }
}

pub fn graphql_depth_to_operations(
    issues: &[GraphqlDepthIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                graphql_depth_severity(issue),
                0.6,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum GraphqlSecurityIssue {
    GraphqlInjection,
    GraphqlExfiltration,
    GraphqlDos,
    GraphqlAuthBypass,
    SubscriptionAbuse,
    FragmentSpread,
    AliasAbuse,
    DirectiveOverload,
    PersistedQueryBypass,
    SchemaStitchingLeak,
}

impl std::fmt::Display for GraphqlSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GraphqlInjection => write!(f, "graphql_injection"),
            Self::GraphqlExfiltration => write!(f, "graphql_exfiltration"),
            Self::GraphqlDos => write!(f, "graphql_dos"),
            Self::GraphqlAuthBypass => write!(f, "graphql_auth_bypass"),
            Self::SubscriptionAbuse => write!(f, "subscription_abuse"),
            Self::FragmentSpread => write!(f, "fragment_spread"),
            Self::AliasAbuse => write!(f, "alias_abuse"),
            Self::DirectiveOverload => write!(f, "directive_overload"),
            Self::PersistedQueryBypass => write!(f, "persisted_query_bypass"),
            Self::SchemaStitchingLeak => write!(f, "schema_stitching_leak"),
        }
    }
}

pub fn analyze_graphql_security(body: &str) -> Vec<GraphqlSecurityIssue> {
    let lower = body.to_ascii_lowercase();
    if !lower.contains("graphql")
        && !lower.contains("query {")
        && !lower.contains("mutation {")
        && !lower.contains("subscription {")
    {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if (lower.contains("query") || lower.contains("graphql"))
        && (lower.contains("\" +")
            || lower.contains("` +")
            || lower.contains("${")
            || lower.contains("concat"))
    {
        issues.push(GraphqlSecurityIssue::GraphqlInjection);
    }

    if lower.contains("query {")
        && (lower.contains("edges {") || lower.contains("node {"))
        && (lower.contains("edges {") && lower.contains("node {"))
    {
        issues.push(GraphqlSecurityIssue::GraphqlExfiltration);
    }

    if (lower.contains("query {") || lower.contains("graphql"))
        && (lower.contains("... on") || lower.contains("recursive"))
        && (lower.contains("depth") || lower.contains("nested"))
    {
        issues.push(GraphqlSecurityIssue::GraphqlDos);
    }

    if lower.contains("mutation {")
        && !lower.contains("authorization")
        && !lower.contains("bearer")
        && !lower.contains("authenticate")
    {
        issues.push(GraphqlSecurityIssue::GraphqlAuthBypass);
    }

    if lower.contains("subscription") && lower.contains("ws://") && !lower.contains("authorization")
    {
        issues.push(GraphqlSecurityIssue::SubscriptionAbuse);
    }

    if lower.contains("...") && lower.contains("fragment") && lower.contains("on ") {
        issues.push(GraphqlSecurityIssue::FragmentSpread);
    }

    if (lower.contains("alias") || has_multiple_aliases(&lower))
        && (lower.contains("query") || lower.contains("graphql"))
    {
        issues.push(GraphqlSecurityIssue::AliasAbuse);
    }

    if lower.contains("@")
        && lower.contains("directive")
        && (lower.contains("query") || lower.contains("graphql"))
    {
        issues.push(GraphqlSecurityIssue::DirectiveOverload);
    }

    if lower.contains("persistedquery") || lower.contains("extensions") && lower.contains("query") {
        issues.push(GraphqlSecurityIssue::PersistedQueryBypass);
    }

    if lower.contains("_service") || lower.contains("_entities") {
        issues.push(GraphqlSecurityIssue::SchemaStitchingLeak);
    }

    issues
}

fn has_multiple_aliases(lower: &str) -> bool {
    let count = lower.matches(": ").count();
    let field_pattern = lower.contains("a1:") || lower.contains("a2:") || lower.contains("alias1:");
    count >= 3 && field_pattern
}

pub fn graphql_security_severity(issue: &GraphqlSecurityIssue) -> f64 {
    match issue {
        GraphqlSecurityIssue::GraphqlInjection => 8.5,
        GraphqlSecurityIssue::GraphqlAuthBypass => 8.0,
        GraphqlSecurityIssue::GraphqlExfiltration => 7.5,
        GraphqlSecurityIssue::SchemaStitchingLeak => 7.0,
        GraphqlSecurityIssue::GraphqlDos => 7.0,
        GraphqlSecurityIssue::SubscriptionAbuse => 6.5,
        GraphqlSecurityIssue::AliasAbuse => 6.0,
        GraphqlSecurityIssue::FragmentSpread => 6.0,
        GraphqlSecurityIssue::DirectiveOverload => 5.5,
        GraphqlSecurityIssue::PersistedQueryBypass => 5.5,
    }
}

pub fn graphql_security_to_operations(
    issues: &[GraphqlSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::GraphQlAbuse,
                graphql_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
