use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ComputePressureIssue {
    ApiDetected,
    StateExfiltration,
    CpuFingerprinting,
    CrossOriginLeak,
    ContinuousObserving,
}

impl std::fmt::Display for ComputePressureIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::StateExfiltration => write!(f, "state_exfiltration"),
            Self::CpuFingerprinting => write!(f, "cpu_fingerprinting"),
            Self::CrossOriginLeak => write!(f, "cross_origin_leak"),
            Self::ContinuousObserving => write!(f, "continuous_observing"),
        }
    }
}

pub fn audit_compute_pressure(target: &str) -> Vec<ComputePressureIssue> {
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
    analyze_compute_pressure(&body)
}

pub fn analyze_compute_pressure(body: &str) -> Vec<ComputePressureIssue> {
    if !body.contains("PressureObserver") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(ComputePressureIssue::ApiDetected);

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_exfil {
        issues.push(ComputePressureIssue::StateExfiltration);
    }

    if body.contains("hardwareConcurrency") || body.contains("deviceMemory") {
        issues.push(ComputePressureIssue::CpuFingerprinting);
    }

    if body.contains("iframe") || body.contains("postMessage") || body.contains("SharedWorker") {
        issues.push(ComputePressureIssue::CrossOriginLeak);
    }

    if body.contains(".observe(") && !body.contains(".unobserve(") && !body.contains("disconnect") {
        issues.push(ComputePressureIssue::ContinuousObserving);
    }

    issues
}

pub fn compute_pressure_severity(issue: &ComputePressureIssue) -> f64 {
    match issue {
        ComputePressureIssue::StateExfiltration => 6.5,
        ComputePressureIssue::CpuFingerprinting => 6.0,
        ComputePressureIssue::CrossOriginLeak => 5.5,
        ComputePressureIssue::ContinuousObserving => 5.0,
        ComputePressureIssue::ApiDetected => 3.0,
    }
}

pub fn compute_pressure_to_operations(
    issues: &[ComputePressureIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                compute_pressure_severity(issue),
                0.6,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum ComputePressureSecurityIssue {
    ObserverWithoutFeaturePolicy,
    DataCollectionWithoutConsent,
    TimingCorrelation,
    CrossOriginPressureLeak,
    WorkerBasedCollection,
    PersistentStorage,
    HighFrequencyPolling,
    MultiSourceCorrelation,
    BatteryCorrelation,
    UnencryptedTransmission,
}

impl std::fmt::Display for ComputePressureSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ObserverWithoutFeaturePolicy => write!(f, "observer_without_feature_policy"),
            Self::DataCollectionWithoutConsent => write!(f, "data_collection_without_consent"),
            Self::TimingCorrelation => write!(f, "timing_correlation"),
            Self::CrossOriginPressureLeak => write!(f, "cross_origin_pressure_leak"),
            Self::WorkerBasedCollection => write!(f, "worker_based_collection"),
            Self::PersistentStorage => write!(f, "persistent_storage"),
            Self::HighFrequencyPolling => write!(f, "high_frequency_polling"),
            Self::MultiSourceCorrelation => write!(f, "multi_source_correlation"),
            Self::BatteryCorrelation => write!(f, "battery_correlation"),
            Self::UnencryptedTransmission => write!(f, "unencrypted_transmission"),
        }
    }
}

pub fn analyze_compute_pressure_security(body: &str) -> Vec<ComputePressureSecurityIssue> {
    let mut issues = Vec::new();

    let has_observer = body.contains("PressureObserver");
    if !has_observer {
        return issues;
    }

    if has_observer && !body.contains("Permissions-Policy") && !body.contains("Feature-Policy") {
        issues.push(ComputePressureSecurityIssue::ObserverWithoutFeaturePolicy);
    }

    if body.contains("PressureObserver")
        && (body.contains("localStorage") || body.contains("sessionStorage"))
        && !body.contains("consent")
        && !body.contains("permission")
        && !body.contains("Consent")
    {
        issues.push(ComputePressureSecurityIssue::DataCollectionWithoutConsent);
    }

    if body.contains("PressureObserver")
        && (body.contains("Date.now()") || body.contains("performance.now()"))
        && (body.contains("state") || body.contains("records"))
    {
        issues.push(ComputePressureSecurityIssue::TimingCorrelation);
    }

    if body.contains("PressureObserver") && body.contains("postMessage") {
        issues.push(ComputePressureSecurityIssue::CrossOriginPressureLeak);
    }

    if body.contains("PressureObserver")
        && (body.contains("new Worker(") || body.contains("serviceWorker.register"))
    {
        issues.push(ComputePressureSecurityIssue::WorkerBasedCollection);
    }

    if body.contains("PressureObserver")
        && (body.contains("localStorage.setItem")
            || body.contains("indexedDB")
            || body.contains("IDBDatabase"))
    {
        issues.push(ComputePressureSecurityIssue::PersistentStorage);
    }

    if body.contains("PressureObserver") && body.contains("sampleInterval") {
        let has_high_freq = body.contains("sampleInterval: 100")
            || body.contains("sampleInterval: 50")
            || body.contains("sampleInterval:100")
            || body.contains("sampleInterval:50");
        let has_normal_freq = body.contains("sampleInterval: 1000")
            || body.contains("sampleInterval:1000")
            || body.contains("sampleInterval: 500")
            || body.contains("sampleInterval:500");

        if has_high_freq && !has_normal_freq {
            issues.push(ComputePressureSecurityIssue::HighFrequencyPolling);
        }
    }

    if body.contains("PressureObserver") {
        let cpu_sources = body.matches(r#""cpu""#).count() + body.matches(r#"'cpu'"#).count();
        let thermal_sources =
            body.matches(r#""thermals""#).count() + body.matches(r#"'thermals'"#).count();
        if cpu_sources > 0 && thermal_sources > 0 {
            issues.push(ComputePressureSecurityIssue::MultiSourceCorrelation);
        }
    }

    if body.contains("PressureObserver")
        && (body.contains("getBattery") || body.contains("battery.level"))
    {
        issues.push(ComputePressureSecurityIssue::BatteryCorrelation);
    }

    if body.contains("PressureObserver")
        && (body.contains(r#"fetch("http://"#)
            || body.contains(r#"fetch('http://"#)
            || body.contains(r#"url: "http://"#)
            || body.contains(r#"url: 'http://"#))
    {
        issues.push(ComputePressureSecurityIssue::UnencryptedTransmission);
    }

    issues
}

pub fn compute_pressure_security_severity(issue: &ComputePressureSecurityIssue) -> f64 {
    match issue {
        ComputePressureSecurityIssue::UnencryptedTransmission => 8.0,
        ComputePressureSecurityIssue::DataCollectionWithoutConsent => 7.5,
        ComputePressureSecurityIssue::CrossOriginPressureLeak => 7.0,
        ComputePressureSecurityIssue::PersistentStorage => 6.5,
        ComputePressureSecurityIssue::BatteryCorrelation => 6.0,
        ComputePressureSecurityIssue::TimingCorrelation => 5.5,
        ComputePressureSecurityIssue::WorkerBasedCollection => 5.0,
        ComputePressureSecurityIssue::MultiSourceCorrelation => 4.5,
        ComputePressureSecurityIssue::HighFrequencyPolling => 4.0,
        ComputePressureSecurityIssue::ObserverWithoutFeaturePolicy => 3.5,
    }
}

pub fn compute_pressure_security_to_operations(
    issues: &[ComputePressureSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                compute_pressure_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
