/// Initial access selector: rank and attempt initial access vectors.
///
/// Scores discovered vulnerabilities by exploit reliability and impact,
/// then attempts exploitation in priority order. Produces an InitialAccessResult
/// describing the method used, credentials obtained, and whether shell access
/// was established.
use serde::{Deserialize, Serialize};
use std::fmt;

/// Category of initial access technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InitialAccessCategory {
    RemoteCodeExecution,
    AuthBypass,
    FileUpload,
    DeserializationRce,
    CredentialStuffing,
    DefaultCredentials,
    SqlInjectionToShell,
    SsrfToMetadata,
    SstiToExec,
}

impl fmt::Display for InitialAccessCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RemoteCodeExecution => write!(f, "RCE"),
            Self::AuthBypass => write!(f, "Auth Bypass"),
            Self::FileUpload => write!(f, "File Upload → Web Shell"),
            Self::DeserializationRce => write!(f, "Deserialization RCE"),
            Self::CredentialStuffing => write!(f, "Credential Stuffing"),
            Self::DefaultCredentials => write!(f, "Default Credentials"),
            Self::SqlInjectionToShell => write!(f, "SQLi → Shell"),
            Self::SsrfToMetadata => write!(f, "SSRF → Metadata"),
            Self::SstiToExec => write!(f, "SSTI → Exec"),
        }
    }
}

/// A discovered vulnerability candidate for initial access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessCandidate {
    pub vulnerability_id: String,
    pub category: InitialAccessCategory,
    pub endpoint: String,
    pub parameter: Option<String>,
    pub exploit_reliability: f64,
    pub impact_score: f64,
    pub description: String,
}

/// Composite score for ranking access candidates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredCandidate {
    pub candidate: AccessCandidate,
    pub composite_score: f64,
    pub rank: usize,
}

/// Result of an individual exploitation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExploitOutcome {
    Success,
    Failure,
    Partial,
    Blocked,
    TimedOut,
}

/// Record of a single exploitation attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitAttempt {
    pub candidate: AccessCandidate,
    pub outcome: ExploitOutcome,
    pub details: String,
    pub credentials_obtained: Vec<ObtainedCred>,
    pub shell_access: bool,
    pub duration_ms: u64,
}

/// A credential obtained during initial access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObtainedCred {
    pub username: String,
    pub credential_value: String,
    pub credential_type: String,
}

/// Final result of the initial access selection process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialAccessResult {
    pub method: Option<InitialAccessCategory>,
    pub successful_endpoint: Option<String>,
    pub credentials_obtained: Vec<ObtainedCred>,
    pub shell_access: bool,
    pub attempts: Vec<ExploitAttempt>,
    pub total_candidates: usize,
    pub success: bool,
}

/// Configuration for initial access selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialAccessConfig {
    pub max_attempts: usize,
    pub timeout_per_attempt_ms: u64,
    pub allow_credential_stuffing: bool,
    pub allow_default_credentials: bool,
    pub discovered_emails: Vec<String>,
}

impl Default for InitialAccessConfig {
    fn default() -> Self {
        Self {
            max_attempts: 10,
            timeout_per_attempt_ms: 30_000,
            allow_credential_stuffing: true,
            allow_default_credentials: true,
            discovered_emails: Vec::new(),
        }
    }
}

/// Base reliability scores for each access category.
fn category_base_reliability(category: InitialAccessCategory) -> f64 {
    match category {
        InitialAccessCategory::RemoteCodeExecution => 0.95,
        InitialAccessCategory::SqlInjectionToShell => 0.85,
        InitialAccessCategory::SstiToExec => 0.80,
        InitialAccessCategory::SsrfToMetadata => 0.75,
        InitialAccessCategory::DeserializationRce => 0.70,
        InitialAccessCategory::FileUpload => 0.65,
        InitialAccessCategory::AuthBypass => 0.60,
        InitialAccessCategory::DefaultCredentials => 0.50,
        InitialAccessCategory::CredentialStuffing => 0.30,
    }
}

/// Base impact scores for each access category.
fn category_base_impact(category: InitialAccessCategory) -> f64 {
    match category {
        InitialAccessCategory::RemoteCodeExecution => 10.0,
        InitialAccessCategory::SqlInjectionToShell => 9.5,
        InitialAccessCategory::SstiToExec => 9.0,
        InitialAccessCategory::DeserializationRce => 9.5,
        InitialAccessCategory::SsrfToMetadata => 8.5,
        InitialAccessCategory::FileUpload => 8.0,
        InitialAccessCategory::AuthBypass => 7.0,
        InitialAccessCategory::DefaultCredentials => 7.5,
        InitialAccessCategory::CredentialStuffing => 6.0,
    }
}

/// Score a single candidate: composite = reliability × impact (normalized).
pub fn score_candidate(candidate: &AccessCandidate) -> f64 {
    let base_rel = category_base_reliability(candidate.category);
    let base_imp = category_base_impact(candidate.category);
    let effective_rel = (candidate.exploit_reliability + base_rel) / 2.0;
    let effective_imp = (candidate.impact_score + base_imp) / 2.0;
    (effective_rel * effective_imp).clamp(0.0, 10.0)
}

/// Rank all candidates by composite score, highest first.
pub fn rank_candidates(candidates: &[AccessCandidate]) -> Vec<ScoredCandidate> {
    let mut scored: Vec<ScoredCandidate> = candidates
        .iter()
        .map(|c| ScoredCandidate {
            composite_score: score_candidate(c),
            candidate: c.clone(),
            rank: 0,
        })
        .collect();

    scored.sort_by(|a, b| {
        b.composite_score
            .partial_cmp(&a.composite_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for (i, s) in scored.iter_mut().enumerate() {
        s.rank = i + 1;
    }

    scored
}

/// Execute initial access selection: rank candidates, attempt in order,
/// return first success or exhaust all options.
///
/// `exploit_fn` is injected for testability. In production it would call
/// into the actual exploit modules.
pub fn select_and_execute<F>(
    candidates: &[AccessCandidate],
    config: &InitialAccessConfig,
    mut exploit_fn: F,
) -> InitialAccessResult
where
    F: FnMut(&AccessCandidate) -> ExploitAttempt,
{
    let ranked = rank_candidates(candidates);
    let total_candidates = ranked.len();
    let mut attempts = Vec::new();

    let limit = config.max_attempts.min(ranked.len());
    for scored in ranked.iter().take(limit) {
        let attempt = exploit_fn(&scored.candidate);
        let success = attempt.outcome == ExploitOutcome::Success;
        let shell = attempt.shell_access;
        let creds = attempt.credentials_obtained.clone();
        let method = scored.candidate.category;
        let endpoint = scored.candidate.endpoint.clone();
        attempts.push(attempt);

        if success {
            return InitialAccessResult {
                method: Some(method),
                successful_endpoint: Some(endpoint),
                credentials_obtained: creds,
                shell_access: shell,
                attempts,
                total_candidates,
                success: true,
            };
        }
    }

    if config.allow_credential_stuffing && !config.discovered_emails.is_empty() {
        let stuffing_candidate = AccessCandidate {
            vulnerability_id: "credential-stuffing-fallback".to_string(),
            category: InitialAccessCategory::CredentialStuffing,
            endpoint: "/api/login".to_string(),
            parameter: Some("email".to_string()),
            exploit_reliability: 0.3,
            impact_score: 6.0,
            description: format!(
                "Credential stuffing with {} discovered emails",
                config.discovered_emails.len()
            ),
        };

        let attempt = exploit_fn(&stuffing_candidate);
        let success = attempt.outcome == ExploitOutcome::Success;
        let creds = attempt.credentials_obtained.clone();
        attempts.push(attempt);

        if success {
            return InitialAccessResult {
                method: Some(InitialAccessCategory::CredentialStuffing),
                successful_endpoint: Some("/api/login".to_string()),
                credentials_obtained: creds,
                shell_access: false,
                attempts,
                total_candidates,
                success: true,
            };
        }
    }

    InitialAccessResult {
        method: None,
        successful_endpoint: None,
        credentials_obtained: vec![],
        shell_access: false,
        attempts,
        total_candidates,
        success: false,
    }
}

/// Generate default credential stuffing candidates from email list.
pub fn generate_credential_stuffing_candidates(emails: &[String]) -> Vec<AccessCandidate> {
    emails
        .iter()
        .map(|email| AccessCandidate {
            vulnerability_id: format!("cred-stuff-{}", email.replace('@', "_at_")),
            category: InitialAccessCategory::CredentialStuffing,
            endpoint: "/api/login".to_string(),
            parameter: Some("email".to_string()),
            exploit_reliability: 0.2,
            impact_score: 5.0,
            description: format!("Credential stuffing attempt with {email}"),
        })
        .collect()
}

/// Generate default credential candidates for common services.
pub fn generate_default_credential_candidates(services: &[String]) -> Vec<AccessCandidate> {
    services
        .iter()
        .map(|svc| AccessCandidate {
            vulnerability_id: format!("default-cred-{svc}"),
            category: InitialAccessCategory::DefaultCredentials,
            endpoint: format!("/{svc}/login"),
            parameter: None,
            exploit_reliability: 0.5,
            impact_score: 7.5,
            description: format!("Default credentials for {svc}"),
        })
        .collect()
}
