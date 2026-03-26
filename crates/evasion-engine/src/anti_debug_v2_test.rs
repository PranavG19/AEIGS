use super::anti_debug_v2::*;

#[test]
fn clean_environment_returns_clean() {
    let detector = AntiDebugDetector::with_defaults();
    let env = DebugEnvironment {
        tracer_pid: Some(0),
        ptrace_self_result: Some(PtraceResult::Success),
        timing_delta_ns: Some(1000),
        parent_process_name: Some("bash".to_string()),
        ..Default::default()
    };
    let result = detector.analyze(&env);
    assert_eq!(result.verdict, DebugVerdict::Clean);
    assert_eq!(result.detected_count, 0);
}

#[test]
fn tracer_pid_nonzero_detected() {
    let detector = AntiDebugDetector::with_defaults();
    let env = DebugEnvironment {
        tracer_pid: Some(1234),
        ptrace_self_result: Some(PtraceResult::Success),
        ..Default::default()
    };
    let result = detector.analyze(&env);
    assert_eq!(result.verdict, DebugVerdict::TracerDetected);
    assert!(result.detected_count >= 1);
}

#[test]
fn ptrace_already_traced_detected() {
    let detector = AntiDebugDetector::with_defaults();
    let env = DebugEnvironment {
        tracer_pid: Some(0),
        ptrace_self_result: Some(PtraceResult::AlreadyTraced),
        ..Default::default()
    };
    let result = detector.analyze(&env);
    assert_eq!(result.verdict, DebugVerdict::DebuggerAttached);
}

#[test]
fn timing_anomaly_detected() {
    let detector = AntiDebugDetector::with_defaults();
    let env = DebugEnvironment {
        tracer_pid: Some(0),
        ptrace_self_result: Some(PtraceResult::Success),
        timing_delta_ns: Some(1_000_000),
        parent_process_name: Some("bash".to_string()),
        ..Default::default()
    };
    let result = detector.analyze(&env);
    assert_eq!(result.verdict, DebugVerdict::TimingAnomaly);
}

#[test]
fn gdb_parent_detected() {
    let detector = AntiDebugDetector::with_defaults();
    let env = DebugEnvironment {
        tracer_pid: Some(0),
        ptrace_self_result: Some(PtraceResult::Success),
        parent_process_name: Some("gdb".to_string()),
        ..Default::default()
    };
    let result = detector.analyze(&env);
    assert_eq!(result.verdict, DebugVerdict::SuspiciousParent);
}

#[test]
fn strace_parent_detected() {
    let detector = AntiDebugDetector::with_defaults();
    let env = DebugEnvironment {
        tracer_pid: Some(0),
        ptrace_self_result: Some(PtraceResult::Success),
        parent_process_name: Some("strace".to_string()),
        ..Default::default()
    };
    let result = detector.analyze(&env);
    assert_eq!(result.verdict, DebugVerdict::SuspiciousParent);
}

#[test]
fn frida_grandparent_detected() {
    let detector = AntiDebugDetector::with_defaults();
    let env = DebugEnvironment {
        tracer_pid: Some(0),
        ptrace_self_result: Some(PtraceResult::Success),
        parent_process_name: Some("bash".to_string()),
        grandparent_process_name: Some("frida".to_string()),
        ..Default::default()
    };
    let result = detector.analyze(&env);
    assert_eq!(result.verdict, DebugVerdict::SuspiciousParent);
}

#[test]
fn multiple_indicators_verdict() {
    let detector = AntiDebugDetector::with_defaults();
    let env = DebugEnvironment {
        tracer_pid: Some(999),
        ptrace_self_result: Some(PtraceResult::AlreadyTraced),
        timing_delta_ns: Some(5_000_000),
        parent_process_name: Some("gdb".to_string()),
        ..Default::default()
    };
    let result = detector.analyze(&env);
    assert_eq!(result.verdict, DebugVerdict::MultipleIndicators);
    assert!(result.detected_count >= 3);
}

#[test]
fn debug_env_var_detected() {
    let detector = AntiDebugDetector::with_defaults();
    let env = DebugEnvironment {
        tracer_pid: Some(0),
        ptrace_self_result: Some(PtraceResult::Success),
        parent_process_name: Some("bash".to_string()),
        environment_variables: vec![("LD_PRELOAD".to_string(), "/tmp/hook.so".to_string())],
        ..Default::default()
    };
    let result = detector.analyze(&env);
    assert!(result.detected_count >= 1);
}

#[test]
fn is_debugger_present_api_detected() {
    let detector = AntiDebugDetector::with_defaults();
    let env = DebugEnvironment {
        tracer_pid: Some(0),
        ptrace_self_result: Some(PtraceResult::Success),
        is_debugger_present_api: Some(true),
        ..Default::default()
    };
    let result = detector.analyze(&env);
    assert!(result.detected_count >= 1);
}

#[test]
fn int3_breakpoint_detected() {
    let detector = AntiDebugDetector::with_defaults();
    let env = DebugEnvironment {
        tracer_pid: Some(0),
        ptrace_self_result: Some(PtraceResult::Success),
        int3_trap_triggered: Some(true),
        ..Default::default()
    };
    let result = detector.analyze(&env);
    assert!(result.detected_count >= 1);
}

#[test]
fn overall_confidence_reflects_max_detected() {
    let detector = AntiDebugDetector::with_defaults();
    let env = DebugEnvironment {
        tracer_pid: Some(1234),
        ..Default::default()
    };
    let result = detector.analyze(&env);
    assert!(result.overall_confidence >= 0.9);
}

#[test]
fn verdict_display_formatting() {
    assert_eq!(format!("{}", DebugVerdict::Clean), "clean");
    assert_eq!(
        format!("{}", DebugVerdict::DebuggerAttached),
        "debugger-attached"
    );
    assert_eq!(
        format!("{}", DebugVerdict::MultipleIndicators),
        "multiple-indicators"
    );
}

#[test]
fn ptrace_permission_denied_not_flagged_as_debug() {
    let detector = AntiDebugDetector::with_defaults();
    let env = DebugEnvironment {
        tracer_pid: Some(0),
        ptrace_self_result: Some(PtraceResult::PermissionDenied),
        parent_process_name: Some("bash".to_string()),
        ..Default::default()
    };
    let result = detector.analyze(&env);
    assert_eq!(result.verdict, DebugVerdict::Clean);
}

#[test]
fn empty_environment_is_clean() {
    let detector = AntiDebugDetector::with_defaults();
    let env = DebugEnvironment::default();
    let result = detector.analyze(&env);
    assert_eq!(result.verdict, DebugVerdict::Clean);
}
