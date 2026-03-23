use crate::geolocation_audit::*;

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
    assert_eq!(
        geolocation_severity(&GeolocationIssue::NoErrorHandler),
        2.5
    );
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
    assert_eq!(GeolocationIssue::GeolocationApiUsed.to_string(), "geolocation_used");
    assert_eq!(GeolocationIssue::WatchPositionUsed.to_string(), "watch_position");
    assert_eq!(GeolocationIssue::HighAccuracyEnabled.to_string(), "high_accuracy");
    assert_eq!(GeolocationIssue::PositionDataSent.to_string(), "position_data_sent");
    assert_eq!(
        GeolocationIssue::GeolocationOverHttp.to_string(),
        "geolocation_over_http"
    );
    assert_eq!(GeolocationIssue::NoErrorHandler.to_string(), "no_error_handler");
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
