/// Persistent access manager: post-exploitation persistence lifecycle.
///
/// After exploitation succeeds, reasons about the target environment to
/// select and deploy persistence mechanisms: polymorphic web shells, scheduled
/// task backdoors, modified app routes, injected middleware. Monitors for
/// detection indicators, triggers migration/cleanup.
///
/// Lifecycle: deploy → verify → monitor → rotate → clean.
use aegis_protocol::finding::VulnerabilityClass;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The target environment context for persistence planning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetEnvironment {
    pub os: OsFamily,
    pub web_server: Option<String>,
    pub framework: Option<String>,
    pub language: String,
    pub writable_paths: Vec<String>,
    pub has_cron: bool,
    pub has_scheduled_tasks: bool,
    pub has_middleware_support: bool,
    pub has_route_injection: bool,
    pub detection_capabilities: Vec<DetectionCapability>,
}

/// Operating system family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OsFamily {
    Linux,
    Windows,
    MacOs,
    Unknown,
}

/// Detection capabilities the target has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectionCapability {
    FileIntegrityMonitor,
    ProcessMonitor,
    NetworkMonitor,
    LogAggregation,
    Edr,
    Av,
    Siem,
    WebApplicationFirewall,
}

/// Type of persistence mechanism.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PersistenceType {
    WebShell,
    ScheduledTask,
    ModifiedRoute,
    InjectedMiddleware,
    CronJob,
    StartupScript,
    DatabaseTrigger,
    ModifiedConfig,
}

/// A persistence mechanism to deploy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceMechanism {
    pub id: String,
    pub mechanism_type: PersistenceType,
    pub name: String,
    pub description: String,
    pub deployment_steps: Vec<String>,
    pub verification_check: String,
    pub detection_indicators: Vec<String>,
    pub stealth_score: f64,
    pub reliability_score: f64,
    pub cleanup_procedure: Vec<String>,
    pub polymorphic: bool,
    pub rotation_interval_secs: Option<u64>,
}

/// Lifecycle state of a deployed persistence mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersistenceState {
    Planned,
    Deploying,
    Deployed,
    Verified,
    Monitoring,
    DetectionWarning,
    Rotating,
    Cleaning,
    Cleaned,
    Failed,
}

/// A deployed persistence instance with lifecycle tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceInstance {
    pub mechanism: PersistenceMechanism,
    pub state: PersistenceState,
    pub deployed_at_ms: Option<u64>,
    pub last_verified_at_ms: Option<u64>,
    pub rotation_count: u32,
    pub detection_events: Vec<DetectionEvent>,
    pub deployment_path: Option<String>,
}

/// A detection indicator that was triggered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvent {
    pub timestamp_ms: u64,
    pub indicator: String,
    pub severity: DetectionSeverity,
    pub source: String,
}

/// Severity of a detection event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Result of persistence planning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistencePlan {
    pub primary: PersistenceMechanism,
    pub fallbacks: Vec<PersistenceMechanism>,
    pub reasoning: Vec<String>,
    pub total_candidates: usize,
    pub filtered_by_detection: usize,
}

/// The persistence manager state.
pub struct PersistenceManager {
    environment: TargetEnvironment,
    instances: Vec<PersistenceInstance>,
    mechanism_counter: u32,
}

impl PersistenceManager {
    pub fn new(environment: TargetEnvironment) -> Self {
        Self {
            environment,
            instances: Vec::new(),
            mechanism_counter: 0,
        }
    }

    pub fn active_instances(&self) -> Vec<&PersistenceInstance> {
        self.instances
            .iter()
            .filter(|i| {
                matches!(
                    i.state,
                    PersistenceState::Deployed
                        | PersistenceState::Verified
                        | PersistenceState::Monitoring
                )
            })
            .collect()
    }

    pub fn all_instances(&self) -> &[PersistenceInstance] {
        &self.instances
    }

    /// Plan persistence mechanisms for the target environment.
    pub fn plan(&mut self) -> PersistencePlan {
        let mut candidates = generate_candidates(&self.environment, &mut self.mechanism_counter);
        let mut reasoning = Vec::new();

        reasoning.push(format!(
            "Target: {:?} OS, language={}, {} writable paths",
            self.environment.os,
            self.environment.language,
            self.environment.writable_paths.len()
        ));

        let total_candidates = candidates.len();
        reasoning.push(format!(
            "Generated {} persistence candidates",
            total_candidates
        ));

        let detection_caps = &self.environment.detection_capabilities;
        let mut filtered = 0usize;
        candidates.retain(|c| {
            let detected = would_be_detected(c, detection_caps);
            if detected {
                filtered += 1;
            }
            !detected
        });

        if filtered > 0 {
            reasoning.push(format!(
                "Filtered {} candidates due to active detection capabilities",
                filtered
            ));
        }

        candidates.sort_by(|a, b| {
            let score_a = a.stealth_score * 0.6 + a.reliability_score * 0.4;
            let score_b = b.stealth_score * 0.6 + b.reliability_score * 0.4;
            score_b
                .partial_cmp(&score_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let primary = candidates
            .first()
            .cloned()
            .unwrap_or_else(|| fallback_mechanism(&mut self.mechanism_counter));
        let fallbacks: Vec<PersistenceMechanism> = candidates.into_iter().skip(1).take(3).collect();

        reasoning.push(format!(
            "Selected primary: {} (stealth={:.2}, reliability={:.2})",
            primary.name, primary.stealth_score, primary.reliability_score
        ));

        PersistencePlan {
            primary,
            fallbacks,
            reasoning,
            total_candidates,
            filtered_by_detection: filtered,
        }
    }

    /// Deploy a persistence mechanism (simulated).
    pub fn deploy(&mut self, mechanism: PersistenceMechanism, timestamp_ms: u64) -> usize {
        let path = self.environment.writable_paths.first().cloned();
        let instance = PersistenceInstance {
            mechanism,
            state: PersistenceState::Deployed,
            deployed_at_ms: Some(timestamp_ms),
            last_verified_at_ms: None,
            rotation_count: 0,
            detection_events: Vec::new(),
            deployment_path: path,
        };
        self.instances.push(instance);
        self.instances.len() - 1
    }

    /// Verify a deployed instance is still active.
    pub fn verify(&mut self, index: usize, timestamp_ms: u64) -> bool {
        if let Some(instance) = self.instances.get_mut(index) {
            if instance.state == PersistenceState::Deployed
                || instance.state == PersistenceState::Monitoring
            {
                instance.state = PersistenceState::Verified;
                instance.last_verified_at_ms = Some(timestamp_ms);
                return true;
            }
        }
        false
    }

    /// Transition a verified instance to monitoring state.
    pub fn start_monitoring(&mut self, index: usize) -> bool {
        if let Some(instance) = self.instances.get_mut(index) {
            if instance.state == PersistenceState::Verified {
                instance.state = PersistenceState::Monitoring;
                return true;
            }
        }
        false
    }

    /// Report a detection event on an instance.
    pub fn report_detection(
        &mut self,
        index: usize,
        event: DetectionEvent,
    ) -> Option<PersistenceAction> {
        if let Some(instance) = self.instances.get_mut(index) {
            let severity = event.severity;
            instance.detection_events.push(event);

            match severity {
                DetectionSeverity::Critical => {
                    instance.state = PersistenceState::Cleaning;
                    Some(PersistenceAction::ImmediateCleanup)
                }
                DetectionSeverity::High => {
                    instance.state = PersistenceState::Rotating;
                    Some(PersistenceAction::RotateNow)
                }
                DetectionSeverity::Medium => {
                    instance.state = PersistenceState::DetectionWarning;
                    Some(PersistenceAction::IncreaseMonitoring)
                }
                DetectionSeverity::Low => Some(PersistenceAction::Continue),
            }
        } else {
            None
        }
    }

    /// Rotate a persistence mechanism (redeploy with mutation).
    pub fn rotate(&mut self, index: usize, timestamp_ms: u64) -> bool {
        if let Some(instance) = self.instances.get_mut(index) {
            if instance.state == PersistenceState::Rotating
                || instance.state == PersistenceState::DetectionWarning
                || instance.state == PersistenceState::Monitoring
            {
                instance.rotation_count += 1;
                instance.state = PersistenceState::Deployed;
                instance.deployed_at_ms = Some(timestamp_ms);
                instance.detection_events.clear();
                return true;
            }
        }
        false
    }

    /// Clean up a persistence instance.
    pub fn cleanup(&mut self, index: usize) -> bool {
        if let Some(instance) = self.instances.get_mut(index) {
            instance.state = PersistenceState::Cleaned;
            return true;
        }
        false
    }

    /// Emergency cleanup of all instances.
    pub fn emergency_cleanup(&mut self) -> usize {
        let mut cleaned = 0;
        for instance in &mut self.instances {
            if instance.state != PersistenceState::Cleaned
                && instance.state != PersistenceState::Failed
            {
                instance.state = PersistenceState::Cleaned;
                cleaned += 1;
            }
        }
        cleaned
    }
}

/// Action recommended after a detection event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceAction {
    Continue,
    IncreaseMonitoring,
    RotateNow,
    ImmediateCleanup,
}

fn generate_candidates(env: &TargetEnvironment, counter: &mut u32) -> Vec<PersistenceMechanism> {
    let mut candidates = Vec::new();

    if !env.writable_paths.is_empty() {
        *counter += 1;
        let shell_ext = match env.language.as_str() {
            l if l.contains("php") => ".php",
            l if l.contains("python") => ".py",
            l if l.contains("java") => ".jsp",
            l if l.contains("csharp") || l.contains("c#") || l.contains("aspnet") => ".aspx",
            _ => ".php",
        };

        candidates.push(PersistenceMechanism {
            id: format!("persist-{counter:03}"),
            mechanism_type: PersistenceType::WebShell,
            name: format!("Polymorphic web shell ({})", shell_ext),
            description: format!(
                "Randomized variable names, encoded payload, disguised as static asset in {}",
                env.writable_paths.first().unwrap_or(&String::new())
            ),
            deployment_steps: vec![
                "Generate polymorphic shell with randomized variable names".to_string(),
                format!("Write shell as innocuous filename{}", shell_ext),
                "Set file timestamp to match adjacent files".to_string(),
                "Verify shell responds to authentication probe".to_string(),
            ],
            verification_check: "Send GET with auth token, expect command execution capability"
                .to_string(),
            detection_indicators: vec![
                "New file in web-accessible directory".to_string(),
                "File contains eval/exec/system calls".to_string(),
                "Unusual file access patterns".to_string(),
            ],
            stealth_score: 0.65,
            reliability_score: 0.85,
            cleanup_procedure: vec![
                "Delete web shell file".to_string(),
                "Clear web server access logs for shell path".to_string(),
            ],
            polymorphic: true,
            rotation_interval_secs: Some(3600),
        });
    }

    if env.has_cron && env.os == OsFamily::Linux {
        *counter += 1;
        candidates.push(PersistenceMechanism {
            id: format!("persist-{counter:03}"),
            mechanism_type: PersistenceType::CronJob,
            name: "Cron-based callback".to_string(),
            description: "Periodic reverse shell callback disguised as log rotation job"
                .to_string(),
            deployment_steps: vec![
                "Write cron entry to /var/spool/cron/ or /etc/cron.d/".to_string(),
                "Name job to mimic system maintenance (logrotate, tmpclean)".to_string(),
                "Set execution to low-traffic hours".to_string(),
            ],
            verification_check: "Verify crontab -l shows entry; wait for callback".to_string(),
            detection_indicators: vec![
                "New cron entry for non-standard user".to_string(),
                "Cron job contacts external host".to_string(),
            ],
            stealth_score: 0.55,
            reliability_score: 0.90,
            cleanup_procedure: vec![
                "Remove cron entry".to_string(),
                "Kill any spawned processes".to_string(),
                "Remove downloaded artifacts".to_string(),
            ],
            polymorphic: false,
            rotation_interval_secs: Some(86400),
        });
    }

    if env.has_scheduled_tasks && env.os == OsFamily::Windows {
        *counter += 1;
        candidates.push(PersistenceMechanism {
            id: format!("persist-{counter:03}"),
            mechanism_type: PersistenceType::ScheduledTask,
            name: "Windows scheduled task backdoor".to_string(),
            description: "Scheduled task disguised as Windows Update helper".to_string(),
            deployment_steps: vec![
                "Create scheduled task via schtasks.exe".to_string(),
                "Name task as 'WindowsUpdateHelper' or similar".to_string(),
                "Set trigger to system startup + hourly repeat".to_string(),
                "Point action to payload in System32 or ProgramData".to_string(),
            ],
            verification_check: "schtasks /query /tn TaskName shows enabled".to_string(),
            detection_indicators: vec![
                "New scheduled task created by non-admin process".to_string(),
                "Task references unusual binary path".to_string(),
            ],
            stealth_score: 0.50,
            reliability_score: 0.88,
            cleanup_procedure: vec![
                "Delete scheduled task".to_string(),
                "Remove payload binary".to_string(),
                "Clear event logs for task creation".to_string(),
            ],
            polymorphic: false,
            rotation_interval_secs: Some(43200),
        });
    }

    if env.has_route_injection {
        *counter += 1;
        candidates.push(PersistenceMechanism {
            id: format!("persist-{counter:03}"),
            mechanism_type: PersistenceType::ModifiedRoute,
            name: "Injected application route".to_string(),
            description: "Hidden route added to application router that provides command execution"
                .to_string(),
            deployment_steps: vec![
                "Identify route registration file".to_string(),
                "Inject new route with innocuous path (e.g. /health-check-v2)".to_string(),
                "Route handler provides authenticated command execution".to_string(),
            ],
            verification_check: "Send authenticated request to injected route path".to_string(),
            detection_indicators: vec![
                "Modified route configuration file".to_string(),
                "New endpoint not in original API specification".to_string(),
            ],
            stealth_score: 0.75,
            reliability_score: 0.80,
            cleanup_procedure: vec![
                "Remove injected route from configuration".to_string(),
                "Restart application to clear cached routes".to_string(),
            ],
            polymorphic: false,
            rotation_interval_secs: None,
        });
    }

    if env.has_middleware_support {
        *counter += 1;
        candidates.push(PersistenceMechanism {
            id: format!("persist-{counter:03}"),
            mechanism_type: PersistenceType::InjectedMiddleware,
            name: "Injected middleware interceptor".to_string(),
            description: "Middleware that intercepts all requests, executes commands when secret header present".to_string(),
            deployment_steps: vec![
                "Identify middleware registration point".to_string(),
                "Inject middleware that checks for X-Debug-Token header".to_string(),
                "When token matches, execute command from X-Debug-Cmd header".to_string(),
                "Pass through all other requests transparently".to_string(),
            ],
            verification_check: "Send request with X-Debug-Token header, verify command output".to_string(),
            detection_indicators: vec![
                "Modified middleware chain".to_string(),
                "Middleware processes unusual headers".to_string(),
                "Application restart shows new middleware registration".to_string(),
            ],
            stealth_score: 0.80,
            reliability_score: 0.85,
            cleanup_procedure: vec![
                "Remove injected middleware".to_string(),
                "Restart application".to_string(),
                "Verify middleware chain matches expected configuration".to_string(),
            ],
            polymorphic: false,
            rotation_interval_secs: None,
        });
    }

    *counter += 1;
    candidates.push(PersistenceMechanism {
        id: format!("persist-{counter:03}"),
        mechanism_type: PersistenceType::DatabaseTrigger,
        name: "Database trigger backdoor".to_string(),
        description:
            "Database trigger on high-traffic table that executes payload on specific input pattern"
                .to_string(),
        deployment_steps: vec![
            "Create database trigger on frequently-accessed table".to_string(),
            "Trigger fires when specific magic value appears in a column".to_string(),
            "Trigger body executes xp_cmdshell / COPY TO PROGRAM / sys_exec".to_string(),
        ],
        verification_check: "Insert row with magic value, verify command execution".to_string(),
        detection_indicators: vec![
            "New database trigger on production table".to_string(),
            "Trigger references system command execution".to_string(),
        ],
        stealth_score: 0.70,
        reliability_score: 0.75,
        cleanup_procedure: vec![
            "Drop the trigger".to_string(),
            "Remove any UDFs or extensions installed for command execution".to_string(),
        ],
        polymorphic: false,
        rotation_interval_secs: None,
    });

    candidates
}

fn would_be_detected(
    mechanism: &PersistenceMechanism,
    capabilities: &[DetectionCapability],
) -> bool {
    for cap in capabilities {
        match (cap, &mechanism.mechanism_type) {
            (DetectionCapability::FileIntegrityMonitor, PersistenceType::WebShell) => {
                if mechanism.stealth_score < 0.7 {
                    return true;
                }
            }
            (DetectionCapability::FileIntegrityMonitor, PersistenceType::ModifiedConfig) => {
                return true;
            }
            (DetectionCapability::Edr, PersistenceType::ScheduledTask) => {
                return true;
            }
            (DetectionCapability::Edr, PersistenceType::CronJob) => {
                if mechanism.stealth_score < 0.6 {
                    return true;
                }
            }
            (DetectionCapability::Av, PersistenceType::WebShell) => {
                if !mechanism.polymorphic {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn fallback_mechanism(counter: &mut u32) -> PersistenceMechanism {
    *counter += 1;
    PersistenceMechanism {
        id: format!("persist-{counter:03}"),
        mechanism_type: PersistenceType::ModifiedConfig,
        name: "Modified application config".to_string(),
        description: "Add debug mode or hidden admin credentials to application configuration"
            .to_string(),
        deployment_steps: vec![
            "Modify application config file to add backdoor credentials".to_string()
        ],
        verification_check: "Login with backdoor credentials".to_string(),
        detection_indicators: vec!["Modified configuration file".to_string()],
        stealth_score: 0.30,
        reliability_score: 0.60,
        cleanup_procedure: vec!["Restore original configuration".to_string()],
        polymorphic: false,
        rotation_interval_secs: None,
    }
}
