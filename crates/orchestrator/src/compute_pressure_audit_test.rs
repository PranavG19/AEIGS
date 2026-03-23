use crate::compute_pressure_audit::*;

#[test]
fn no_pressure_no_issues() {
    assert!(analyze_compute_pressure("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api() {
    let body = r#"<script>const observer = new PressureObserver(callback);</script>"#;
    let issues = analyze_compute_pressure(body);
    assert!(issues.contains(&ComputePressureIssue::ApiDetected));
}

#[test]
fn detects_state_exfiltration() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            fetch("/track?state=" + records[0].state);
        });
    </script>"#;
    let issues = analyze_compute_pressure(body);
    assert!(issues.contains(&ComputePressureIssue::StateExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            console.log(records[0].state);
        });
    </script>"#;
    let issues = analyze_compute_pressure(body);
    assert!(!issues.contains(&ComputePressureIssue::StateExfiltration));
}

#[test]
fn detects_cpu_fingerprinting() {
    let body = r#"<script>
        const observer = new PressureObserver(callback);
        const cores = navigator.hardwareConcurrency;
    </script>"#;
    let issues = analyze_compute_pressure(body);
    assert!(issues.contains(&ComputePressureIssue::CpuFingerprinting));
}

#[test]
fn detects_cross_origin_leak() {
    let body = r#"<script>
        const observer = new PressureObserver(records => {
            parent.postMessage(records[0].state, "*");
        });
    </script>"#;
    let issues = analyze_compute_pressure(body);
    assert!(issues.contains(&ComputePressureIssue::CrossOriginLeak));
}

#[test]
fn detects_continuous_observing() {
    let body = r#"<script>
        const observer = new PressureObserver(callback);
        observer.observe("cpu");
    </script>"#;
    let issues = analyze_compute_pressure(body);
    assert!(issues.contains(&ComputePressureIssue::ContinuousObserving));
}

#[test]
fn no_continuous_with_disconnect() {
    let body = r#"<script>
        const observer = new PressureObserver(callback);
        observer.observe("cpu");
        setTimeout(() => observer.disconnect(), 5000);
    </script>"#;
    let issues = analyze_compute_pressure(body);
    assert!(!issues.contains(&ComputePressureIssue::ContinuousObserving));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        compute_pressure_severity(&ComputePressureIssue::StateExfiltration),
        6.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(
        compute_pressure_severity(&ComputePressureIssue::ApiDetected),
        3.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        ComputePressureIssue::ApiDetected,
        ComputePressureIssue::CpuFingerprinting,
    ];
    let mut seq = 0;
    let ops = compute_pressure_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        ComputePressureIssue::ApiDetected.to_string(),
        "api_detected"
    );
    assert_eq!(
        ComputePressureIssue::StateExfiltration.to_string(),
        "state_exfiltration"
    );
    assert_eq!(
        ComputePressureIssue::CpuFingerprinting.to_string(),
        "cpu_fingerprinting"
    );
    assert_eq!(
        ComputePressureIssue::CrossOriginLeak.to_string(),
        "cross_origin_leak"
    );
    assert_eq!(
        ComputePressureIssue::ContinuousObserving.to_string(),
        "continuous_observing"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_compute_pressure("").is_empty());
}
