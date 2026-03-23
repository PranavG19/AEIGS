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

// DeviceMotionSecurityIssue tests

#[test]
fn security_empty_body_no_issues() {
    let issues = analyze_device_motion_security("");
    assert!(issues.is_empty());
}

#[test]
fn security_no_motion_api_no_issues() {
    let body = "<html><body>Hello World</body></html>";
    let issues = analyze_device_motion_security(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_motion_fingerprinting_with_canvas() {
    let body = r#"
        window.addEventListener('devicemotion', function(e) {
            var canvas = document.createElement('canvas');
            var hash = computeHash(e.acceleration);
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionFingerprinting));
}

#[test]
fn detects_motion_fingerprinting_with_device_id() {
    let body = r#"
        var sensor = new Accelerometer();
        sensor.addEventListener('reading', () => {
            var deviceId = generateId(sensor.x, sensor.y);
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionFingerprinting));
}

#[test]
fn detects_motion_fingerprinting_with_unique_id() {
    let body = r#"
        window.addEventListener('deviceorientation', function(e) {
            var uniqueId = createFingerprint(e.alpha, e.beta);
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionFingerprinting));
}

#[test]
fn detects_motion_fingerprinting_accelerometer_hash() {
    let body = r#"
        var accel = new Accelerometer({frequency: 60});
        accel.addEventListener('reading', () => {
            var hash = SHA256(accel.x + accel.y + accel.z);
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionFingerprinting));
}

#[test]
fn detects_motion_keylogging_with_keypress() {
    let body = r#"
        window.addEventListener('devicemotion', recordMotion);
        document.addEventListener('keypress', correlateWithMotion);
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionKeylogging));
}

#[test]
fn detects_motion_keylogging_with_input() {
    let body = r#"
        var gyro = new Gyroscope();
        document.querySelector('input').addEventListener('input', function() {
            inferKeyFromMotion(gyro.x, gyro.y);
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionKeylogging));
}

#[test]
fn detects_motion_keylogging_with_typing() {
    let body = r#"
        window.addEventListener('deviceorientation', function(e) {
            if (isTyping) {
                analyzeTypingPattern(e.alpha, e.beta);
            }
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionKeylogging));
}

#[test]
fn detects_motion_keylogging_with_keyboard() {
    let body = r#"
        var sensor = new Accelerometer();
        sensor.addEventListener('reading', () => {
            correlateWithKeyboard(sensor.x, sensor.y);
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionKeylogging));
}

#[test]
fn detects_motion_without_permission_devicemotion() {
    let body = r#"
        window.addEventListener('devicemotion', function(e) {
            console.log(e.acceleration);
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionWithoutPermission));
}

#[test]
fn detects_motion_without_permission_accelerometer() {
    let body = r#"
        var sensor = new Accelerometer({frequency: 60});
        sensor.start();
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionWithoutPermission));
}

#[test]
fn no_motion_without_permission_when_permission_checked() {
    let body = r#"
        DeviceMotionEvent.requestPermission().then(permission => {
            if (permission === 'granted') {
                window.addEventListener('devicemotion', handler);
            }
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(!issues.contains(&DeviceMotionSecurityIssue::MotionWithoutPermission));
}

#[test]
fn no_motion_without_permission_with_permissions_query() {
    let body = r#"
        navigator.permissions.query({name: 'accelerometer'}).then(result => {
            var sensor = new Accelerometer();
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(!issues.contains(&DeviceMotionSecurityIssue::MotionWithoutPermission));
}

#[test]
fn detects_motion_cross_origin_with_postmessage() {
    let body = r#"
        window.addEventListener('deviceorientation', function(e) {
            parent.postMessage({orientation: e}, '*');
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionCrossOrigin));
}

#[test]
fn detects_motion_cross_origin_with_cors() {
    let body = r#"
        var gyro = new Gyroscope();
        gyro.addEventListener('reading', () => {
            fetch('https://api.example.com', {
                mode: 'cors',
                body: JSON.stringify(gyro)
            });
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionCrossOrigin));
}

#[test]
fn detects_motion_cross_origin_with_origin_check() {
    let body = r#"
        window.addEventListener('devicemotion', function(e) {
            if (window.origin !== 'https://trusted.com') {
                sendData(e);
            }
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionCrossOrigin));
}

#[test]
fn detects_motion_in_background_without_visibility_check() {
    let body = r#"
        window.addEventListener('devicemotion', function(e) {
            setInterval(() => logMotion(e), 1000);
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionInBackground));
}

#[test]
fn detects_motion_in_background_with_animation_frame() {
    let body = r#"
        var accel = new Accelerometer();
        function collect() {
            logData(accel.x);
            requestAnimationFrame(collect);
        }
        requestAnimationFrame(collect);
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionInBackground));
}

#[test]
fn no_motion_in_background_with_visibility_check() {
    let body = r#"
        window.addEventListener('devicemotion', function(e) {
            if (!document.hidden) {
                setInterval(() => logMotion(e), 1000);
            }
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(!issues.contains(&DeviceMotionSecurityIssue::MotionInBackground));
}

#[test]
fn no_motion_in_background_with_visibility_state() {
    let body = r#"
        var gyro = new Gyroscope();
        if (document.visibilityState === 'visible') {
            requestAnimationFrame(collect);
        }
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(!issues.contains(&DeviceMotionSecurityIssue::MotionInBackground));
}

#[test]
fn detects_motion_high_frequency_120hz() {
    let body = r#"
        var sensor = new Accelerometer({frequency: 120});
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionHighFrequency));
}

#[test]
fn detects_motion_high_frequency_100hz() {
    let body = r#"
        var gyro = new Gyroscope({frequency: 100});
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionHighFrequency));
}

#[test]
fn detects_motion_high_frequency_200hz() {
    let body = r#"
        window.addEventListener('deviceorientation', handler);
        // Sample at 200 Hz
        var config = {frequency: 200};
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionHighFrequency));
}

#[test]
fn detects_motion_high_frequency_fast_interval_5ms() {
    let body = r#"
        window.addEventListener('devicemotion', function(e) {
            setInterval(readSensor, 5);
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionHighFrequency));
}

#[test]
fn detects_motion_high_frequency_fast_interval_10ms() {
    let body = r#"
        var accel = new Accelerometer();
        setInterval(() => read(accel), 10);
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionHighFrequency));
}

#[test]
fn detects_motion_with_geolocation_get_position() {
    let body = r#"
        window.addEventListener('devicemotion', motionHandler);
        navigator.geolocation.getCurrentPosition(positionHandler);
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionWithGeolocation));
}

#[test]
fn detects_motion_with_geolocation_watch_position() {
    let body = r#"
        var gyro = new Gyroscope();
        navigator.geolocation.watchPosition(function(pos) {
            correlate(gyro, pos);
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionWithGeolocation));
}

#[test]
fn detects_motion_with_geolocation_coords() {
    let body = r#"
        window.addEventListener('deviceorientation', function(e) {
            var coords = {lat: position.coords.latitude};
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionWithGeolocation));
}

#[test]
fn detects_motion_with_geolocation_latitude() {
    let body = r#"
        var accel = new Accelerometer();
        var latitude = getCurrentLatitude();
        combineSensorData(accel, latitude);
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionWithGeolocation));
}

#[test]
fn detects_motion_data_exfiltration_fetch_https() {
    let body = r#"
        window.addEventListener('devicemotion', function(e) {
            fetch('https://analytics.example.com/track', {
                method: 'POST',
                body: JSON.stringify(e)
            });
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionDataExfiltration));
}

#[test]
fn detects_motion_data_exfiltration_xhr_http() {
    let body = r#"
        var gyro = new Gyroscope();
        var xhr = new XMLHttpRequest();
        xhr.open('POST', 'http://tracking.com/api');
        xhr.send(JSON.stringify(gyro));
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionDataExfiltration));
}

#[test]
fn detects_motion_data_exfiltration_sendbeacon_analytics() {
    let body = r#"
        window.addEventListener('deviceorientation', function(e) {
            navigator.sendBeacon('//analytics.tracker.io/events', JSON.stringify(e));
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionDataExfiltration));
}

#[test]
fn detects_motion_data_exfiltration_websocket() {
    let body = r#"
        var accel = new Accelerometer();
        var ws = new WebSocket('https://realtime.example.com');
        accel.addEventListener('reading', () => {
            ws.send(JSON.stringify(accel));
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionDataExfiltration));
}

#[test]
fn detects_motion_in_iframe_with_iframe_tag() {
    let body = r#"
        <iframe src="sensor-collector.html"></iframe>
        <script>
            window.addEventListener('devicemotion', handler);
        </script>
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionInIframe));
}

#[test]
fn detects_motion_in_iframe_with_content_window() {
    let body = r#"
        var gyro = new Gyroscope();
        var frame = document.querySelector('iframe');
        frame.contentWindow.postMessage(gyro, '*');
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionInIframe));
}

#[test]
fn detects_motion_in_iframe_with_parent_postmessage() {
    let body = r#"
        window.addEventListener('deviceorientation', function(e) {
            parent.postMessage(e, '*');
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionInIframe));
}

#[test]
fn detects_motion_in_iframe_with_window_parent() {
    let body = r#"
        var accel = new Accelerometer();
        if (window.parent !== window) {
            sendToParent(accel);
        }
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionInIframe));
}

#[test]
fn detects_motion_persistent_collection_localstorage() {
    let body = r#"
        window.addEventListener('devicemotion', function(e) {
            localStorage.setItem('motion_data', JSON.stringify(e));
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionPersistentCollection));
}

#[test]
fn detects_motion_persistent_collection_sessionstorage() {
    let body = r#"
        var gyro = new Gyroscope();
        gyro.addEventListener('reading', () => {
            sessionStorage.setItem('gyro', JSON.stringify(gyro));
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionPersistentCollection));
}

#[test]
fn detects_motion_persistent_collection_indexeddb() {
    let body = r#"
        window.addEventListener('deviceorientation', function(e) {
            var request = indexedDB.open('SensorDB');
            request.onsuccess = function() {
                saveOrientation(e);
            };
        });
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionPersistentCollection));
}

#[test]
fn detects_motion_persistent_collection_indexeddb_uppercase() {
    let body = r#"
        var accel = new Accelerometer();
        var db = IndexedDB.open('Sensors');
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionPersistentCollection));
}

#[test]
fn detects_motion_persistent_collection_opendatabase() {
    let body = r#"
        var gyro = new Gyroscope();
        var db = openDatabase('MotionData', '1.0', 'Sensor data', 2 * 1024 * 1024);
    "#;
    let issues = analyze_device_motion_security(body);
    assert!(issues.contains(&DeviceMotionSecurityIssue::MotionPersistentCollection));
}

#[test]
fn security_severity_keylogging_highest() {
    assert_eq!(
        device_motion_security_severity(&DeviceMotionSecurityIssue::MotionKeylogging),
        9.0
    );
}

#[test]
fn security_severity_exfiltration_high() {
    assert_eq!(
        device_motion_security_severity(&DeviceMotionSecurityIssue::MotionDataExfiltration),
        8.5
    );
}

#[test]
fn security_severity_fingerprinting() {
    assert_eq!(
        device_motion_security_severity(&DeviceMotionSecurityIssue::MotionFingerprinting),
        8.0
    );
}

#[test]
fn security_severity_without_permission_lowest() {
    assert_eq!(
        device_motion_security_severity(&DeviceMotionSecurityIssue::MotionWithoutPermission),
        4.5
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        DeviceMotionSecurityIssue::MotionKeylogging,
        DeviceMotionSecurityIssue::MotionFingerprinting,
        DeviceMotionSecurityIssue::MotionDataExfiltration,
    ];
    let mut seq = 0;
    let ops = device_motion_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn security_to_operations_empty_vec() {
    let issues = vec![];
    let mut seq = 0;
    let ops = device_motion_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 0);
}

#[test]
fn security_display_fingerprinting() {
    assert_eq!(
        DeviceMotionSecurityIssue::MotionFingerprinting.to_string(),
        "motion_fingerprinting"
    );
}

#[test]
fn security_display_keylogging() {
    assert_eq!(
        DeviceMotionSecurityIssue::MotionKeylogging.to_string(),
        "motion_keylogging"
    );
}

#[test]
fn security_display_without_permission() {
    assert_eq!(
        DeviceMotionSecurityIssue::MotionWithoutPermission.to_string(),
        "motion_without_permission"
    );
}

#[test]
fn security_display_cross_origin() {
    assert_eq!(
        DeviceMotionSecurityIssue::MotionCrossOrigin.to_string(),
        "motion_cross_origin"
    );
}

#[test]
fn security_display_in_background() {
    assert_eq!(
        DeviceMotionSecurityIssue::MotionInBackground.to_string(),
        "motion_in_background"
    );
}

#[test]
fn security_display_high_frequency() {
    assert_eq!(
        DeviceMotionSecurityIssue::MotionHighFrequency.to_string(),
        "motion_high_frequency"
    );
}

#[test]
fn security_display_with_geolocation() {
    assert_eq!(
        DeviceMotionSecurityIssue::MotionWithGeolocation.to_string(),
        "motion_with_geolocation"
    );
}

#[test]
fn security_display_data_exfiltration() {
    assert_eq!(
        DeviceMotionSecurityIssue::MotionDataExfiltration.to_string(),
        "motion_data_exfiltration"
    );
}

#[test]
fn security_display_in_iframe() {
    assert_eq!(
        DeviceMotionSecurityIssue::MotionInIframe.to_string(),
        "motion_in_iframe"
    );
}

#[test]
fn security_display_persistent_collection() {
    assert_eq!(
        DeviceMotionSecurityIssue::MotionPersistentCollection.to_string(),
        "motion_persistent_collection"
    );
}
