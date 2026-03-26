use super::sandbox_detector::*;
use std::collections::HashMap;

fn bare_env() -> SystemEnvironment {
    SystemEnvironment::default()
}

#[test]
fn clean_environment_scores_zero() {
    let detector = SandboxDetector::with_defaults();
    let env = bare_env();
    let result = detector.analyze(&env);
    assert_eq!(result.score, 0);
    assert_eq!(result.recommendation, SandboxRecommendation::Proceed);
    assert!(result.indicators.is_empty());
}

#[test]
fn cpuid_vmware_detected() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.cpuid_vendor_string = Some("VMwareVMware".to_string());
    let result = detector.analyze(&env);
    assert!(result.score > 0);
    assert_eq!(result.detected_hypervisor, Some(HypervisorVendor::VMware));
    assert!(result
        .indicators
        .iter()
        .any(|i| i.description.contains("CPUID")));
}

#[test]
fn cpuid_virtualbox_detected() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.cpuid_vendor_string = Some("VBoxVBoxVBox".to_string());
    let result = detector.analyze(&env);
    assert_eq!(
        result.detected_hypervisor,
        Some(HypervisorVendor::VirtualBox)
    );
}

#[test]
fn cpuid_hyperv_detected() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.cpuid_vendor_string = Some("Microsoft Hv".to_string());
    let result = detector.analyze(&env);
    assert_eq!(result.detected_hypervisor, Some(HypervisorVendor::HyperV));
}

#[test]
fn cpuid_kvm_detected() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.cpuid_vendor_string = Some("KVMKVMKVM".to_string());
    let result = detector.analyze(&env);
    assert_eq!(result.detected_hypervisor, Some(HypervisorVendor::Kvm));
}

#[test]
fn dmi_string_detection() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.dmi_strings = vec!["System Manufacturer: VMware".to_string()];
    let result = detector.analyze(&env);
    assert!(result.score > 0);
    assert!(result
        .indicators
        .iter()
        .any(|i| i.category == DetectionCategory::VmHypervisor));
}

#[test]
fn mac_oui_vmware_detected() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.mac_addresses = vec!["00:50:56:AB:CD:EF".to_string()];
    let result = detector.analyze(&env);
    assert!(result.score > 0);
    assert!(result
        .indicators
        .iter()
        .any(|i| i.description.contains("MAC OUI")));
}

#[test]
fn mac_oui_virtualbox_detected() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.mac_addresses = vec!["08:00:27:11:22:33".to_string()];
    let result = detector.analyze(&env);
    assert!(result
        .indicators
        .iter()
        .any(|i| i.evidence.contains("VirtualBox")));
}

#[test]
fn low_resource_indicators() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.cpu_core_count = Some(1);
    env.total_ram_mb = Some(512);
    env.disk_size_gb = Some(20);
    env.screen_resolution = Some((800, 600));
    let result = detector.analyze(&env);
    assert!(result.score > 0);
    let vm_cats: Vec<_> = result
        .indicators
        .iter()
        .filter(|i| i.category == DetectionCategory::VmHypervisor)
        .collect();
    assert!(vm_cats.len() >= 3);
}

#[test]
fn sandbox_path_cuckoo_detected() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.filesystem_paths = vec!["/opt/cuckoo".to_string()];
    let result = detector.analyze(&env);
    assert!(result.score > 0);
    assert_eq!(result.detected_sandbox, Some(SandboxProduct::Cuckoo));
}

#[test]
fn sandbox_path_anyrun_detected() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.filesystem_paths = vec!["C:\\Users\\anyrun".to_string()];
    let result = detector.analyze(&env);
    assert_eq!(result.detected_sandbox, Some(SandboxProduct::AnyRun));
}

#[test]
fn sandbox_env_var_detected() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.environment_variables
        .insert("CUCKOO_ROOT".to_string(), "/opt/cuckoo".to_string());
    let result = detector.analyze(&env);
    assert!(result.score > 0);
    assert!(result
        .indicators
        .iter()
        .any(|i| i.description.contains("env var")));
}

#[test]
fn sandbox_registry_key_detected() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.registry_keys = vec![(
        "HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools".to_string(),
        "installed".to_string(),
    )];
    let result = detector.analyze(&env);
    assert!(result.score > 0);
}

#[test]
fn suspicious_username_detected() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.username = Some("sandbox".to_string());
    let result = detector.analyze(&env);
    assert!(result
        .indicators
        .iter()
        .any(|i| i.description.contains("username")));
}

#[test]
fn suspicious_hostname_detected() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.hostname = Some("maltest-lab-01".to_string());
    let result = detector.analyze(&env);
    assert!(result
        .indicators
        .iter()
        .any(|i| i.description.contains("hostname")));
}

#[test]
fn low_uptime_flagged() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.uptime_seconds = Some(30);
    let result = detector.analyze(&env);
    assert!(result
        .indicators
        .iter()
        .any(|i| i.description.contains("uptime")));
}

#[test]
fn debugger_tracer_pid_detected() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.tracer_pid = Some(1234);
    let result = detector.analyze(&env);
    assert!(result.score > 0);
    assert!(result
        .indicators
        .iter()
        .any(|i| i.category == DetectionCategory::DebuggerPresence));
}

#[test]
fn tracer_pid_zero_is_clean() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.tracer_pid = Some(0);
    let result = detector.analyze(&env);
    assert!(!result
        .indicators
        .iter()
        .any(|i| i.category == DetectionCategory::DebuggerPresence));
}

#[test]
fn debugger_process_detected() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.running_processes = vec!["gdb".to_string()];
    let result = detector.analyze(&env);
    assert!(result
        .indicators
        .iter()
        .any(|i| i.category == DetectionCategory::DebuggerPresence));
}

#[test]
fn analysis_tool_wireshark_detected() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.running_processes = vec!["wireshark".to_string()];
    let result = detector.analyze(&env);
    assert!(result
        .indicators
        .iter()
        .any(|i| i.category == DetectionCategory::AnalysisTool));
}

#[test]
fn multiple_analysis_tools_detected() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.running_processes = vec![
        "wireshark".to_string(),
        "fiddler".to_string(),
        "procmon".to_string(),
    ];
    let result = detector.analyze(&env);
    let tool_count = result
        .indicators
        .iter()
        .filter(|i| i.category == DetectionCategory::AnalysisTool)
        .count();
    assert!(tool_count >= 3);
}

#[test]
fn rdtsc_anomaly_detected() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.rdtsc_delta_ns = Some(1_000_000);
    let result = detector.analyze(&env);
    assert!(result
        .indicators
        .iter()
        .any(|i| i.category == DetectionCategory::TimingAnomaly));
}

#[test]
fn rdtsc_normal_not_flagged() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.rdtsc_delta_ns = Some(100);
    let result = detector.analyze(&env);
    assert!(!result
        .indicators
        .iter()
        .any(|i| i.evidence.contains("rdtsc")));
}

#[test]
fn sleep_acceleration_detected() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.sleep_requested_ms = Some(10_000);
    env.sleep_actual_ms = Some(100);
    let result = detector.analyze(&env);
    assert!(result
        .indicators
        .iter()
        .any(|i| i.description.contains("Sleep acceleration")));
}

#[test]
fn sleep_normal_not_flagged() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.sleep_requested_ms = Some(1000);
    env.sleep_actual_ms = Some(950);
    let result = detector.analyze(&env);
    assert!(!result
        .indicators
        .iter()
        .any(|i| i.description.contains("Sleep acceleration")));
}

#[test]
fn mouse_static_positions_flagged() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.mouse_positions = vec![(100, 100); 15];
    let result = detector.analyze(&env);
    assert!(result
        .indicators
        .iter()
        .any(|i| i.evidence == "mouse_static"));
}

#[test]
fn mouse_linear_movement_flagged() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.mouse_positions = (0..15).map(|i| (i * 10, i * 10)).collect();
    let result = detector.analyze(&env);
    assert!(result
        .indicators
        .iter()
        .any(|i| i.evidence == "mouse_linear"));
}

#[test]
fn mouse_human_like_not_flagged() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.mouse_positions = vec![
        (100, 200),
        (115, 193),
        (140, 210),
        (135, 250),
        (170, 230),
        (200, 215),
        (180, 260),
        (220, 300),
        (250, 280),
        (210, 320),
        (270, 310),
        (300, 340),
    ];
    let result = detector.analyze(&env);
    assert!(!result
        .indicators
        .iter()
        .any(|i| i.evidence == "mouse_static" || i.evidence == "mouse_linear"));
}

#[test]
fn insufficient_mouse_samples() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.mouse_positions = vec![(10, 20), (30, 40)];
    let result = detector.analyze(&env);
    assert!(result
        .indicators
        .iter()
        .any(|i| i.evidence == "low_samples"));
}

#[test]
fn combined_high_score_recommends_abort() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.cpuid_vendor_string = Some("VMwareVMware".to_string());
    env.filesystem_paths = vec!["/opt/cuckoo".to_string()];
    env.tracer_pid = Some(999);
    env.running_processes = vec!["wireshark".to_string(), "gdb".to_string()];
    env.rdtsc_delta_ns = Some(2_000_000);
    env.mouse_positions = vec![(100, 100); 15];
    let result = detector.analyze(&env);
    assert!(result.score >= 70);
    assert_eq!(result.recommendation, SandboxRecommendation::Abort);
}

#[test]
fn medium_score_recommends_deceive() {
    let config = SandboxDetectorConfig {
        abort_threshold: 70,
        deceive_threshold: 20,
        ..Default::default()
    };
    let detector = SandboxDetector::new(config);
    let mut env = bare_env();
    env.cpuid_vendor_string = Some("VMwareVMware".to_string());
    let result = detector.analyze(&env);
    assert!(result.score >= 20);
    assert!(result.score < 70);
    assert_eq!(result.recommendation, SandboxRecommendation::Deceive);
}

#[test]
fn custom_thresholds_respected() {
    let config = SandboxDetectorConfig {
        abort_threshold: 90,
        deceive_threshold: 80,
        ..Default::default()
    };
    let detector = SandboxDetector::new(config);
    let mut env = bare_env();
    env.cpuid_vendor_string = Some("VMwareVMware".to_string());
    let result = detector.analyze(&env);
    assert!(result.score < 90);
    assert_eq!(result.recommendation, SandboxRecommendation::Proceed);
}

#[test]
fn timing_checks_disabled() {
    let config = SandboxDetectorConfig {
        enable_timing_checks: false,
        ..Default::default()
    };
    let detector = SandboxDetector::new(config);
    let mut env = bare_env();
    env.rdtsc_delta_ns = Some(10_000_000);
    let result = detector.analyze(&env);
    assert!(!result
        .indicators
        .iter()
        .any(|i| i.category == DetectionCategory::TimingAnomaly));
}

#[test]
fn mouse_entropy_disabled() {
    let config = SandboxDetectorConfig {
        enable_mouse_entropy: false,
        ..Default::default()
    };
    let detector = SandboxDetector::new(config);
    let mut env = bare_env();
    env.mouse_positions = vec![(100, 100); 15];
    let result = detector.analyze(&env);
    assert!(!result
        .indicators
        .iter()
        .any(|i| i.category == DetectionCategory::MouseEntropy));
}

#[test]
fn category_scores_populated() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.cpuid_vendor_string = Some("VMwareVMware".to_string());
    env.tracer_pid = Some(42);
    let result = detector.analyze(&env);
    assert!(result
        .category_scores
        .contains_key(&DetectionCategory::VmHypervisor));
    assert!(result
        .category_scores
        .contains_key(&DetectionCategory::DebuggerPresence));
}

#[test]
fn cpuid_check_payload_not_empty() {
    let payload = SandboxDetector::cpuid_check_payload();
    assert!(payload.contains("cpuid"));
    assert!(payload.contains("0x40000000"));
}

#[test]
fn rdtsc_timing_pattern_not_empty() {
    let pattern = SandboxDetector::rdtsc_timing_check_pattern();
    assert!(pattern.contains("rdtsc"));
    assert!(pattern.contains("500000"));
}

#[test]
fn display_impls_consistent() {
    assert_eq!(format!("{}", SandboxRecommendation::Proceed), "proceed");
    assert_eq!(format!("{}", SandboxRecommendation::Abort), "abort");
    assert_eq!(format!("{}", SandboxRecommendation::Deceive), "deceive");
    assert_eq!(
        format!("{}", DetectionCategory::VmHypervisor),
        "vm-hypervisor"
    );
    assert_eq!(format!("{}", HypervisorVendor::VMware), "VMware");
    assert_eq!(format!("{}", SandboxProduct::Cuckoo), "Cuckoo");
}

#[test]
fn score_clamped_to_100() {
    let detector = SandboxDetector::with_defaults();
    let mut env = bare_env();
    env.cpuid_vendor_string = Some("VMwareVMware".to_string());
    env.dmi_strings = vec!["VMware Virtual".to_string()];
    env.mac_addresses = vec!["00:50:56:AA:BB:CC".to_string()];
    env.filesystem_paths = vec!["/opt/cuckoo".to_string()];
    env.registry_keys = vec![(
        "HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools".to_string(),
        "1".to_string(),
    )];
    env.tracer_pid = Some(9999);
    env.running_processes = vec![
        "wireshark".to_string(),
        "gdb".to_string(),
        "ida64".to_string(),
    ];
    env.rdtsc_delta_ns = Some(50_000_000);
    env.sleep_requested_ms = Some(10_000);
    env.sleep_actual_ms = Some(10);
    env.mouse_positions = vec![(0, 0); 20];
    env.cpu_core_count = Some(1);
    env.total_ram_mb = Some(256);
    env.disk_size_gb = Some(10);
    env.uptime_seconds = Some(5);
    env.username = Some("sandbox".to_string());
    env.hostname = Some("analysis-lab".to_string());
    env.environment_variables
        .insert("CUCKOO".to_string(), "1".to_string());
    let result = detector.analyze(&env);
    assert!(result.score <= 100);
    assert_eq!(result.recommendation, SandboxRecommendation::Abort);
}
