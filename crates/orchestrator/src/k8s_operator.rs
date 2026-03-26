use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Notification channels for scan completion, failures, and critical findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub slack_webhook: Option<String>,
    pub email: Option<String>,
    pub pagerduty_key: Option<String>,
}

/// Desired state for an AegisScan custom resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AegisScanSpec {
    pub target_url: String,
    pub scan_preset: String,
    pub schedule: Option<String>,
    pub max_duration_secs: u64,
    pub use_llm: bool,
    pub stealth_mode: bool,
    pub scope_domains: Vec<String>,
    pub notifications: NotificationConfig,
}

/// Lifecycle phase of an AegisScan resource.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScanPhase {
    Pending,
    Provisioning,
    Running,
    Analyzing,
    Reporting,
    Completed,
    Failed,
    Cancelled,
}

/// Observed state written back to the CRD status subresource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AegisScanStatus {
    pub phase: ScanPhase,
    pub start_time: Option<u64>,
    pub completion_time: Option<u64>,
    pub findings_count: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub report_path: Option<String>,
    pub error_message: Option<String>,
    pub last_reconciled: u64,
}

/// Minimal CRD metadata mirroring the Kubernetes ObjectMeta subset we care about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrdMetadata {
    pub name: String,
    pub namespace: String,
    pub uid: String,
    pub labels: HashMap<String, String>,
    pub creation_timestamp: u64,
}

/// Full AegisScan custom resource definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AegisScanCrd {
    pub api_version: String,
    pub kind: String,
    pub metadata: CrdMetadata,
    pub spec: AegisScanSpec,
    pub status: Option<AegisScanStatus>,
}

impl Default for AegisScanCrd {
    fn default() -> Self {
        Self {
            api_version: "aegis.io/v1".to_string(),
            kind: "AegisScan".to_string(),
            metadata: CrdMetadata {
                name: String::new(),
                namespace: "default".to_string(),
                uid: String::new(),
                labels: HashMap::new(),
                creation_timestamp: 0,
            },
            spec: AegisScanSpec {
                target_url: String::new(),
                scan_preset: "quick".to_string(),
                schedule: None,
                max_duration_secs: 3600,
                use_llm: false,
                stealth_mode: false,
                scope_domains: Vec::new(),
                notifications: NotificationConfig {
                    slack_webhook: None,
                    email: None,
                    pagerduty_key: None,
                },
            },
            status: None,
        }
    }
}

/// Action the reconciler decides to take after inspecting a CRD.
#[derive(Debug, Clone, PartialEq)]
pub enum ReconcileAction {
    Create,
    Update,
    Delete,
    Requeue(u64),
    NoOp,
}

/// Outcome of a single reconciliation pass.
#[derive(Debug, Clone)]
pub struct ReconcileResult {
    pub action: ReconcileAction,
    pub message: String,
    pub requeue_after_secs: Option<u64>,
}

/// Timestamped event emitted during operator reconciliation loops.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorEvent {
    pub timestamp_ms: u64,
    pub crd_name: String,
    pub event_type: String,
    pub message: String,
}

/// Errors surfaced by operator operations.
#[derive(Debug, Clone, PartialEq)]
pub enum OperatorError {
    CrdNotFound(String),
    CrdAlreadyExists(String),
    InvalidSpec(String),
    ReconcileFailed(String),
    HelmGenerationFailed(String),
}

impl std::fmt::Display for OperatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CrdNotFound(n) => write!(f, "CRD not found: {n}"),
            Self::CrdAlreadyExists(n) => write!(f, "CRD already exists: {n}"),
            Self::InvalidSpec(m) => write!(f, "invalid spec: {m}"),
            Self::ReconcileFailed(m) => write!(f, "reconcile failed: {m}"),
            Self::HelmGenerationFailed(m) => write!(f, "helm generation failed: {m}"),
        }
    }
}

impl std::error::Error for OperatorError {}

/// Container image coordinates for the Helm chart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelmImage {
    pub repository: String,
    pub tag: String,
    pub pull_policy: String,
}

/// CPU/memory resource requests and limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelmResources {
    pub cpu_request: String,
    pub memory_request: String,
    pub cpu_limit: String,
    pub memory_limit: String,
}

/// Top-level Helm values rendered from an AegisScan CRD.
#[derive(Debug, Clone, Serialize)]
pub struct HelmValues {
    pub image: HelmImage,
    pub replicas: u32,
    pub resources: HelmResources,
    pub scan_config: serde_json::Value,
    pub service_account: String,
    pub namespace: String,
}

/// PersistentVolume configuration derived from scan requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentVolumeConfig {
    pub storage_class: String,
    pub size: String,
    pub access_mode: String,
    pub mount_path: String,
}

/// In-process Kubernetes operator that manages AegisScan CRDs as a pure state machine.
///
/// No k8s client library required — this struct owns the CRD registry, reconciliation
/// logic, and event log. An external controller loop feeds it watch events and drains
/// the resulting actions.
#[derive(Debug)]
pub struct K8sOperator {
    pub crds: HashMap<String, AegisScanCrd>,
    pub reconcile_count: u64,
    pub event_log: Vec<OperatorEvent>,
}

impl K8sOperator {
    pub fn new() -> Self {
        Self {
            crds: HashMap::new(),
            reconcile_count: 0,
            event_log: Vec::new(),
        }
    }

    /// Register a new CRD. Rejects duplicates by metadata.name.
    pub fn register_crd(&mut self, crd: AegisScanCrd) -> Result<(), OperatorError> {
        let name = crd.metadata.name.clone();
        if self.crds.contains_key(&name) {
            return Err(OperatorError::CrdAlreadyExists(name));
        }
        self.push_event(&name, "Registered", "CRD registered with operator");
        self.crds.insert(name, crd);
        Ok(())
    }

    /// Remove a CRD from the registry and return it for finalizer processing.
    pub fn unregister_crd(&mut self, name: &str) -> Result<AegisScanCrd, OperatorError> {
        let crd = self
            .crds
            .remove(name)
            .ok_or_else(|| OperatorError::CrdNotFound(name.to_string()))?;
        self.push_event(name, "Unregistered", "CRD removed from operator");
        Ok(crd)
    }

    /// Run one reconciliation pass for the named CRD.
    ///
    /// State machine transitions:
    /// - No status → Pending (create)
    /// - Pending → Provisioning (requeue 5 s)
    /// - Provisioning → Running (requeue 10 s)
    /// - Running → Analyzing (requeue 10 s)
    /// - Analyzing → Reporting (requeue 5 s)
    /// - Reporting → Completed (done)
    /// - Failed / Completed / Cancelled → NoOp
    pub fn reconcile(&mut self, crd_name: &str) -> Result<ReconcileResult, OperatorError> {
        let crd = self
            .crds
            .get(crd_name)
            .ok_or_else(|| OperatorError::CrdNotFound(crd_name.to_string()))?;

        if crd.spec.target_url.is_empty() {
            return Err(OperatorError::InvalidSpec(
                "target_url must not be empty".to_string(),
            ));
        }

        let valid_presets = ["quick", "thorough", "paranoid"];
        if !valid_presets.contains(&crd.spec.scan_preset.as_str()) {
            return Err(OperatorError::InvalidSpec(format!(
                "unknown scan_preset: {}",
                crd.spec.scan_preset
            )));
        }

        let phase_snapshot = crd.status.as_ref().map(|s| s.phase.clone());
        // Drop the immutable borrow of self.crds before mutating self.
        drop(crd);

        self.reconcile_count += 1;

        let result = match &phase_snapshot {
            None => {
                self.push_event(
                    crd_name,
                    "Reconcile",
                    "Initial reconciliation — creating scan",
                );
                ReconcileResult {
                    action: ReconcileAction::Create,
                    message: "scan resource created, transitioning to Pending".to_string(),
                    requeue_after_secs: Some(0),
                }
            }
            Some(phase) => match phase {
                ScanPhase::Pending => {
                    self.push_event(crd_name, "Reconcile", "Provisioning scan infrastructure");
                    ReconcileResult {
                        action: ReconcileAction::Update,
                        message: "transitioning Pending → Provisioning".to_string(),
                        requeue_after_secs: Some(5),
                    }
                }
                ScanPhase::Provisioning => {
                    self.push_event(crd_name, "Reconcile", "Starting scan execution");
                    ReconcileResult {
                        action: ReconcileAction::Update,
                        message: "transitioning Provisioning → Running".to_string(),
                        requeue_after_secs: Some(10),
                    }
                }
                ScanPhase::Running => {
                    self.push_event(crd_name, "Reconcile", "Scan active, moving to analysis");
                    ReconcileResult {
                        action: ReconcileAction::Update,
                        message: "transitioning Running → Analyzing".to_string(),
                        requeue_after_secs: Some(10),
                    }
                }
                ScanPhase::Analyzing => {
                    self.push_event(crd_name, "Reconcile", "Analysis done, generating report");
                    ReconcileResult {
                        action: ReconcileAction::Update,
                        message: "transitioning Analyzing → Reporting".to_string(),
                        requeue_after_secs: Some(5),
                    }
                }
                ScanPhase::Reporting => {
                    self.push_event(crd_name, "Reconcile", "Report ready, scan completed");
                    ReconcileResult {
                        action: ReconcileAction::Update,
                        message: "transitioning Reporting → Completed".to_string(),
                        requeue_after_secs: None,
                    }
                }
                ScanPhase::Completed | ScanPhase::Failed | ScanPhase::Cancelled => {
                    self.push_event(crd_name, "Reconcile", "Terminal state — no action");
                    ReconcileResult {
                        action: ReconcileAction::NoOp,
                        message: format!("scan in terminal phase {:?}", phase),
                        requeue_after_secs: None,
                    }
                }
            },
        };

        Ok(result)
    }

    /// Replace the status subresource on a registered CRD.
    pub fn update_status(
        &mut self,
        crd_name: &str,
        status: AegisScanStatus,
    ) -> Result<(), OperatorError> {
        let crd = self
            .crds
            .get_mut(crd_name)
            .ok_or_else(|| OperatorError::CrdNotFound(crd_name.to_string()))?;
        self.event_log.push(OperatorEvent {
            timestamp_ms: status.last_reconciled,
            crd_name: crd_name.to_string(),
            event_type: "StatusUpdate".to_string(),
            message: format!("phase → {:?}", status.phase),
        });
        crd.status = Some(status);
        Ok(())
    }

    /// Look up a CRD by name.
    pub fn get_crd(&self, name: &str) -> Option<&AegisScanCrd> {
        self.crds.get(name)
    }

    /// Return all registered CRDs (unordered).
    pub fn list_crds(&self) -> Vec<&AegisScanCrd> {
        self.crds.values().collect()
    }

    /// Render a YAML-like Helm values document from the named CRD's spec.
    pub fn generate_helm_chart(&self, crd_name: &str) -> Result<String, OperatorError> {
        let crd = self
            .crds
            .get(crd_name)
            .ok_or_else(|| OperatorError::CrdNotFound(crd_name.to_string()))?;

        let (cpu_req, mem_req, cpu_lim, mem_lim) = match crd.spec.scan_preset.as_str() {
            "quick" => ("500m", "512Mi", "1000m", "1Gi"),
            "thorough" => ("1000m", "1Gi", "2000m", "2Gi"),
            "paranoid" => ("2000m", "2Gi", "4000m", "4Gi"),
            other => {
                return Err(OperatorError::HelmGenerationFailed(format!(
                    "unsupported preset: {other}"
                )))
            }
        };

        let replicas: u32 = if crd.spec.scan_preset == "paranoid" {
            3
        } else {
            1
        };

        let scan_config = serde_json::json!({
            "target_url": crd.spec.target_url,
            "scan_preset": crd.spec.scan_preset,
            "use_llm": crd.spec.use_llm,
            "stealth_mode": crd.spec.stealth_mode,
            "max_duration_secs": crd.spec.max_duration_secs,
            "scope_domains": crd.spec.scope_domains,
        });

        let values = HelmValues {
            image: HelmImage {
                repository: "ghcr.io/aegis/scanner".to_string(),
                tag: "latest".to_string(),
                pull_policy: "IfNotPresent".to_string(),
            },
            replicas,
            resources: HelmResources {
                cpu_request: cpu_req.to_string(),
                memory_request: mem_req.to_string(),
                cpu_limit: cpu_lim.to_string(),
                memory_limit: mem_lim.to_string(),
            },
            scan_config,
            service_account: format!("aegis-scanner-{}", crd.metadata.namespace),
            namespace: crd.metadata.namespace.clone(),
        };

        serde_json::to_string_pretty(&values)
            .map_err(|e| OperatorError::HelmGenerationFailed(e.to_string()))
    }

    /// Derive a PersistentVolume config sized to the scan preset.
    pub fn generate_pv_config(
        &self,
        crd_name: &str,
    ) -> Result<PersistentVolumeConfig, OperatorError> {
        let crd = self
            .crds
            .get(crd_name)
            .ok_or_else(|| OperatorError::CrdNotFound(crd_name.to_string()))?;

        let size = match crd.spec.scan_preset.as_str() {
            "quick" => "5Gi",
            "thorough" => "10Gi",
            "paranoid" => "20Gi",
            other => {
                return Err(OperatorError::HelmGenerationFailed(format!(
                    "unsupported preset for PV sizing: {other}"
                )))
            }
        };

        Ok(PersistentVolumeConfig {
            storage_class: "standard".to_string(),
            size: size.to_string(),
            access_mode: "ReadWriteOnce".to_string(),
            mount_path: "/data/aegis-scans".to_string(),
        })
    }

    /// Total number of events recorded since operator creation.
    pub fn event_count(&self) -> usize {
        self.event_log.len()
    }

    fn push_event(&mut self, crd_name: &str, event_type: &str, message: &str) {
        self.event_log.push(OperatorEvent {
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            crd_name: crd_name.to_string(),
            event_type: event_type.to_string(),
            message: message.to_string(),
        });
    }
}
