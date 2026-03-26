/// Autonomous lateral movement: move through the network from initial foothold.
///
/// Maps reachable hosts from the current position, attempts credential reuse,
/// Kerberoasting, pass-the-hash, and shared admin credential checks. Tracks
/// the full pivot path for reporting.
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

/// Method used for lateral movement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LateralMethod {
    CredentialReuse,
    Kerberoast,
    PassTheHash,
    SharedAdminCreds,
    SshKeyReuse,
    TokenImpersonation,
    ServiceExploit,
}

impl fmt::Display for LateralMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CredentialReuse => write!(f, "Credential Reuse"),
            Self::Kerberoast => write!(f, "Kerberoast"),
            Self::PassTheHash => write!(f, "Pass-the-Hash"),
            Self::SharedAdminCreds => write!(f, "Shared Admin Credentials"),
            Self::SshKeyReuse => write!(f, "SSH Key Reuse"),
            Self::TokenImpersonation => write!(f, "Token Impersonation"),
            Self::ServiceExploit => write!(f, "Service Exploit"),
        }
    }
}

/// A host discovered on the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHost {
    pub address: String,
    pub hostname: Option<String>,
    pub open_ports: Vec<u16>,
    pub services: Vec<String>,
    pub os_fingerprint: Option<String>,
    pub reachable: bool,
}

/// A credential available for lateral movement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralCredential {
    pub username: String,
    pub credential_type: LateralCredentialType,
    pub credential_value: String,
    pub source_host: String,
    pub domain: Option<String>,
}

/// Type of credential for lateral movement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LateralCredentialType {
    Password,
    NtlmHash,
    KerberosTicket,
    SshKey,
    Token,
}

/// A single pivot step in the lateral movement path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PivotStep {
    pub from_host: String,
    pub to_host: String,
    pub method: LateralMethod,
    pub credential_used: Option<String>,
    pub ports_used: Vec<u16>,
    pub success: bool,
    pub details: String,
}

/// Result of an attempt to move to a single host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostAccessResult {
    pub host: String,
    pub accessed: bool,
    pub method: Option<LateralMethod>,
    pub credential_used: Option<String>,
    pub new_credentials_found: Vec<LateralCredential>,
    pub attempts: Vec<PivotStep>,
}

/// Full result of the lateral movement phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralMovementResult {
    pub pivot_path: Vec<PivotStep>,
    pub hosts_compromised: Vec<String>,
    pub hosts_attempted: Vec<String>,
    pub credentials_used: Vec<String>,
    pub new_credentials_discovered: Vec<LateralCredential>,
    pub domain_admin_obtained: bool,
    pub objective_host_reached: bool,
    pub total_pivots: u32,
}

/// Configuration for lateral movement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralMovementConfig {
    pub max_pivots: u32,
    pub max_hosts: usize,
    pub objective_host: Option<String>,
    pub try_credential_reuse: bool,
    pub try_kerberoast: bool,
    pub try_pass_the_hash: bool,
    pub try_shared_admin: bool,
    pub stealth_mode: bool,
}

impl Default for LateralMovementConfig {
    fn default() -> Self {
        Self {
            max_pivots: 10,
            max_hosts: 50,
            objective_host: None,
            try_credential_reuse: true,
            try_kerberoast: true,
            try_pass_the_hash: true,
            try_shared_admin: true,
            stealth_mode: false,
        }
    }
}

/// Current lateral movement state tracking.
#[derive(Debug, Clone)]
pub struct LateralState {
    pub current_host: String,
    pub compromised_hosts: HashSet<String>,
    pub available_credentials: Vec<LateralCredential>,
    pub pivot_path: Vec<PivotStep>,
    pub pivot_count: u32,
}

/// Build the ordered list of methods to attempt per host.
pub fn build_method_priority(config: &LateralMovementConfig) -> Vec<LateralMethod> {
    let mut methods = Vec::new();
    if config.try_credential_reuse {
        methods.push(LateralMethod::CredentialReuse);
    }
    if config.try_pass_the_hash {
        methods.push(LateralMethod::PassTheHash);
    }
    if config.try_kerberoast {
        methods.push(LateralMethod::Kerberoast);
    }
    if config.try_shared_admin {
        methods.push(LateralMethod::SharedAdminCreds);
    }
    methods
}

/// Score a host for targeting priority. Higher = more desirable target.
pub fn score_host(host: &NetworkHost, objective_host: Option<&str>) -> f64 {
    let mut score = 0.0;

    if let Some(obj) = objective_host {
        if host.address == obj || host.hostname.as_deref() == Some(obj) {
            score += 100.0;
        }
    }

    if host.open_ports.contains(&445) {
        score += 20.0;
    }
    if host.open_ports.contains(&22) {
        score += 15.0;
    }
    if host.open_ports.contains(&3389) {
        score += 15.0;
    }
    if host.open_ports.contains(&88) {
        score += 25.0;
    }

    if host
        .services
        .iter()
        .any(|s| s.contains("domain controller") || s.contains("DC"))
    {
        score += 50.0;
    }

    score += host.open_ports.len() as f64 * 2.0;

    score
}

/// Prioritize hosts by score, returning them in order.
pub fn prioritize_hosts(
    hosts: &[NetworkHost],
    already_compromised: &HashSet<String>,
    objective_host: Option<&str>,
) -> Vec<(NetworkHost, f64)> {
    let mut scored: Vec<(NetworkHost, f64)> = hosts
        .iter()
        .filter(|h| h.reachable && !already_compromised.contains(&h.address))
        .map(|h| (h.clone(), score_host(h, objective_host)))
        .collect();

    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    scored
}

/// Execute lateral movement across the network.
///
/// `host_scanner` discovers reachable hosts from current position.
/// `pivot_executor` attempts a single pivot using a given method.
pub fn execute_lateral_movement<S, P>(
    initial_host: &str,
    initial_credentials: &[LateralCredential],
    config: &LateralMovementConfig,
    mut host_scanner: S,
    mut pivot_executor: P,
) -> LateralMovementResult
where
    S: FnMut(&str) -> Vec<NetworkHost>,
    P: FnMut(&str, &str, LateralMethod, &[LateralCredential]) -> HostAccessResult,
{
    let mut state = LateralState {
        current_host: initial_host.to_string(),
        compromised_hosts: {
            let mut s = HashSet::new();
            s.insert(initial_host.to_string());
            s
        },
        available_credentials: initial_credentials.to_vec(),
        pivot_path: Vec::new(),
        pivot_count: 0,
    };

    let methods = build_method_priority(config);
    let mut all_attempted = Vec::new();
    let mut da_obtained = false;
    let mut objective_reached = false;

    loop {
        if state.pivot_count >= config.max_pivots {
            break;
        }
        if state.compromised_hosts.len() >= config.max_hosts {
            break;
        }

        let reachable = host_scanner(&state.current_host);
        let prioritized = prioritize_hosts(
            &reachable,
            &state.compromised_hosts,
            config.objective_host.as_deref(),
        );

        if prioritized.is_empty() {
            break;
        }

        let mut pivoted = false;
        for (host, _score) in &prioritized {
            if state.pivot_count >= config.max_pivots {
                break;
            }

            all_attempted.push(host.address.clone());

            for method in &methods {
                let result = pivot_executor(
                    &state.current_host,
                    &host.address,
                    *method,
                    &state.available_credentials,
                );

                if result.accessed {
                    let step = PivotStep {
                        from_host: state.current_host.clone(),
                        to_host: host.address.clone(),
                        method: result.method.unwrap_or(*method),
                        credential_used: result.credential_used.clone(),
                        ports_used: host.open_ports.clone(),
                        success: true,
                        details: format!("Pivoted via {method}"),
                    };

                    state.pivot_path.push(step);
                    state.compromised_hosts.insert(host.address.clone());
                    state.current_host = host.address.clone();
                    state.pivot_count += 1;

                    for cred in &result.new_credentials_found {
                        if cred.credential_type == LateralCredentialType::KerberosTicket
                            && cred.username.to_lowercase().contains("admin")
                        {
                            da_obtained = true;
                        }
                        state.available_credentials.push(cred.clone());
                    }

                    if let Some(ref obj) = config.objective_host {
                        if &host.address == obj || host.hostname.as_deref() == Some(obj.as_str()) {
                            objective_reached = true;
                        }
                    }

                    pivoted = true;
                    break;
                }
            }

            if pivoted {
                break;
            }
        }

        if !pivoted {
            break;
        }

        if da_obtained || objective_reached {
            break;
        }
    }

    let credentials_used: Vec<String> = state
        .pivot_path
        .iter()
        .filter_map(|p| p.credential_used.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    let new_creds: Vec<LateralCredential> = state
        .available_credentials
        .iter()
        .filter(|c| c.source_host != initial_host)
        .cloned()
        .collect();

    LateralMovementResult {
        pivot_path: state.pivot_path,
        hosts_compromised: state.compromised_hosts.into_iter().collect(),
        hosts_attempted: all_attempted,
        credentials_used,
        new_credentials_discovered: new_creds,
        domain_admin_obtained: da_obtained,
        objective_host_reached: objective_reached,
        total_pivots: state.pivot_count,
    }
}
