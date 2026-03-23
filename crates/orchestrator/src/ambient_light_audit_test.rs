use crate::ambient_light_audit::*;

#[test]
fn no_ambient_no_issues() {
    assert!(analyze_ambient_light("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_sensor() {
    let body = r#"<script>const sensor = new AmbientLightSensor();</script>"#;
    let issues = analyze_ambient_light(body);
    assert!(issues.contains(&AmbientLightIssue::ApiDetected));
}

#[test]
fn detects_api_devicelight() {
    let body = r#"<script>window.addEventListener("devicelight", handler);</script>"#;
    let issues = analyze_ambient_light(body);
    assert!(issues.contains(&AmbientLightIssue::ApiDetected));
}

#[test]
fn detects_light_exfiltration() {
    let body = r#"<script>
        const sensor = new AmbientLightSensor();
        fetch("/track?lux=" + sensor.illuminance);
    </script>"#;
    let issues = analyze_ambient_light(body);
    assert!(issues.contains(&AmbientLightIssue::LightExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const sensor = new AmbientLightSensor();
        console.log(sensor.illuminance);
    </script>"#;
    let issues = analyze_ambient_light(body);
    assert!(!issues.contains(&AmbientLightIssue::LightExfiltration));
}

#[test]
fn detects_high_frequency_reading() {
    let body = r#"<script>
        const sensor = new AmbientLightSensor({frequency: 60});
        sensor.start();
    </script>"#;
    let issues = analyze_ambient_light(body);
    assert!(issues.contains(&AmbientLightIssue::HighFrequencyReading));
}

#[test]
fn detects_cross_origin_leak() {
    let body = r#"<script>
        const sensor = new AmbientLightSensor();
        parent.postMessage(sensor.illuminance, "*");
    </script>"#;
    let issues = analyze_ambient_light(body);
    assert!(issues.contains(&AmbientLightIssue::CrossOriginLeak));
}

#[test]
fn detects_screen_content_inference() {
    let body = r#"<script>
        const sensor = new AmbientLightSensor();
        const history = [];
        sensor.onreading = () => {
            if (sensor.illuminance > threshold) {
                history.push(sensor.illuminance);
            }
        };
    </script>"#;
    let issues = analyze_ambient_light(body);
    assert!(issues.contains(&AmbientLightIssue::ScreenContentInference));
}

#[test]
fn severity_inference_highest() {
    assert_eq!(
        ambient_light_severity(&AmbientLightIssue::ScreenContentInference),
        7.0
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(ambient_light_severity(&AmbientLightIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        AmbientLightIssue::ApiDetected,
        AmbientLightIssue::CrossOriginLeak,
    ];
    let mut seq = 0;
    let ops = ambient_light_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(AmbientLightIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        AmbientLightIssue::LightExfiltration.to_string(),
        "light_exfiltration"
    );
    assert_eq!(
        AmbientLightIssue::HighFrequencyReading.to_string(),
        "high_frequency_reading"
    );
    assert_eq!(
        AmbientLightIssue::CrossOriginLeak.to_string(),
        "cross_origin_leak"
    );
    assert_eq!(
        AmbientLightIssue::ScreenContentInference.to_string(),
        "screen_content_inference"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_ambient_light("").is_empty());
}
