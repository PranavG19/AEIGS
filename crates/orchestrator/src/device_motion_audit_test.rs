use crate::device_motion_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_device_motion("");
    assert!(issues.is_empty());
}

#[test]
fn no_motion_api_no_issues() {
    let body = "<html><body>Hello</body></html>";
    let issues = analyze_device_motion(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_orientation_event() {
    let body = "window.addEventListener('deviceorientation', handler);";
    let issues = analyze_device_motion(body);
    assert!(issues.contains(&DeviceMotionIssue::OrientationEventListener));
}

#[test]
fn detects_motion_event() {
    let body = "window.addEventListener('devicemotion', handler);";
    let issues = analyze_device_motion(body);
    assert!(issues.contains(&DeviceMotionIssue::MotionEventListener));
}

#[test]
fn detects_accelerometer_api() {
    let body = "var sensor = new Accelerometer({frequency: 60});";
    let issues = analyze_device_motion(body);
    assert!(issues.contains(&DeviceMotionIssue::AccelerometerApi));
}

#[test]
fn detects_gyroscope_api() {
    let body = "var gyro = new Gyroscope({frequency: 30});";
    let issues = analyze_device_motion(body);
    assert!(issues.contains(&DeviceMotionIssue::GyroscopeApi));
}

#[test]
fn detects_sensor_exfiltration() {
    let body = r#"
        window.addEventListener('devicemotion', function(e) {
            fetch('/track', {method:'POST', body: JSON.stringify(e)});
        });
    "#;
    let issues = analyze_device_motion(body);
    assert!(issues.contains(&DeviceMotionIssue::SensorDataExfiltration));
}

#[test]
fn detects_high_frequency_sampling() {
    let body = r#"
        window.addEventListener('devicemotion', handler);
        setInterval(function() { readSensor(); }, 10);
    "#;
    let issues = analyze_device_motion(body);
    assert!(issues.contains(&DeviceMotionIssue::HighFrequencySampling));
}

#[test]
fn detects_high_frequency_via_frequency_option() {
    let body = "var sensor = new Accelerometer({frequency: 120});";
    let issues = analyze_device_motion(body);
    assert!(issues.contains(&DeviceMotionIssue::HighFrequencySampling));
}

#[test]
fn detects_absolute_orientation_sensor() {
    let body = "var sensor = new AbsoluteOrientationSensor();";
    let issues = analyze_device_motion(body);
    assert!(issues.contains(&DeviceMotionIssue::AbsoluteOrientationSensor));
}

#[test]
fn detects_relative_orientation_sensor() {
    let body = "var sensor = new RelativeOrientationSensor();";
    let issues = analyze_device_motion(body);
    assert!(issues.contains(&DeviceMotionIssue::AbsoluteOrientationSensor));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        device_motion_severity(&DeviceMotionIssue::SensorDataExfiltration),
        7.0
    );
}

#[test]
fn severity_orientation_lowest() {
    assert_eq!(
        device_motion_severity(&DeviceMotionIssue::OrientationEventListener),
        4.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        DeviceMotionIssue::MotionEventListener,
        DeviceMotionIssue::AccelerometerApi,
    ];
    let mut seq = 0;
    let ops = device_motion_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        DeviceMotionIssue::OrientationEventListener.to_string(),
        "orientation_event_listener"
    );
    assert_eq!(
        DeviceMotionIssue::MotionEventListener.to_string(),
        "motion_event_listener"
    );
    assert_eq!(
        DeviceMotionIssue::SensorDataExfiltration.to_string(),
        "sensor_data_exfiltration"
    );
    assert_eq!(
        DeviceMotionIssue::AbsoluteOrientationSensor.to_string(),
        "absolute_orientation_sensor"
    );
}
