use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum GeolocationIssue {
    GeolocationApiUsed,
    WatchPositionUsed,
    HighAccuracyEnabled,
    PositionDataSent,
    GeolocationOverHttp,
    NoErrorHandler,
}

impl std::fmt::Display for GeolocationIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GeolocationApiUsed => write!(f, "geolocation_used"),
            Self::WatchPositionUsed => write!(f, "watch_position"),
            Self::HighAccuracyEnabled => write!(f, "high_accuracy"),
            Self::PositionDataSent => write!(f, "position_data_sent"),
            Self::GeolocationOverHttp => write!(f, "geolocation_over_http"),
            Self::NoErrorHandler => write!(f, "no_error_handler"),
        }
    }
}

pub fn audit_geolocation(target: &str) -> Vec<GeolocationIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    analyze_geolocation(&body, target.starts_with("https://"))
}

pub fn analyze_geolocation(body: &str, is_https: bool) -> Vec<GeolocationIssue> {
    if !body.contains("geolocation") && !body.contains("getCurrentPosition") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("getCurrentPosition") {
        issues.push(GeolocationIssue::GeolocationApiUsed);

        if !is_https {
            issues.push(GeolocationIssue::GeolocationOverHttp);
        }
    }

    if body.contains("watchPosition") {
        issues.push(GeolocationIssue::WatchPositionUsed);
    }

    if body.contains("enableHighAccuracy") && body.contains("true") {
        issues.push(GeolocationIssue::HighAccuracyEnabled);
    }

    if has_position_exfiltration(body) {
        issues.push(GeolocationIssue::PositionDataSent);
    }

    if body.contains("getCurrentPosition")
        && !body.contains("PositionError")
        && !body.contains("GeolocationPositionError")
    {
        let has_error_cb = body.contains("getCurrentPosition(")
            && (body.contains(", function") || body.contains(", (") || body.contains(",null"));
        if !has_error_cb {
            issues.push(GeolocationIssue::NoErrorHandler);
        }
    }

    issues
}

fn has_position_exfiltration(body: &str) -> bool {
    let has_coords = body.contains("coords.latitude")
        || body.contains("coords.longitude")
        || body.contains("coords.accuracy");

    let sends_data = body.contains("fetch(")
        || body.contains("XMLHttpRequest")
        || body.contains("sendBeacon")
        || body.contains(".send(")
        || body.contains("$.ajax")
        || body.contains("$.post");

    has_coords && sends_data
}

pub fn geolocation_severity(issue: &GeolocationIssue) -> f64 {
    match issue {
        GeolocationIssue::PositionDataSent => 7.0,
        GeolocationIssue::GeolocationOverHttp => 6.5,
        GeolocationIssue::WatchPositionUsed => 5.0,
        GeolocationIssue::HighAccuracyEnabled => 4.5,
        GeolocationIssue::GeolocationApiUsed => 3.0,
        GeolocationIssue::NoErrorHandler => 2.5,
    }
}

pub fn geolocation_to_operations(
    issues: &[GeolocationIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                geolocation_severity(issue),
                0.7,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum GeolocationSecurityIssue {
    LocationExfiltration,
    ContinuousTracking,
    LocationWithoutConsent,
    HighAccuracyTracking,
    LocationCrossOrigin,
    LocationPersistence,
    LocationFingerprinting,
    LocationInBackground,
    LocationWithSensitiveData,
    GeofencingAbuse,
}

impl std::fmt::Display for GeolocationSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LocationExfiltration => write!(f, "location_exfiltration"),
            Self::ContinuousTracking => write!(f, "continuous_tracking"),
            Self::LocationWithoutConsent => write!(f, "location_without_consent"),
            Self::HighAccuracyTracking => write!(f, "high_accuracy_tracking"),
            Self::LocationCrossOrigin => write!(f, "location_cross_origin"),
            Self::LocationPersistence => write!(f, "location_persistence"),
            Self::LocationFingerprinting => write!(f, "location_fingerprinting"),
            Self::LocationInBackground => write!(f, "location_in_background"),
            Self::LocationWithSensitiveData => write!(f, "location_with_sensitive_data"),
            Self::GeofencingAbuse => write!(f, "geofencing_abuse"),
        }
    }
}

pub fn analyze_geolocation_security(body: &str) -> Vec<GeolocationSecurityIssue> {
    if !body.contains("geolocation") && !body.contains("getCurrentPosition") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if has_location_exfiltration(body) {
        issues.push(GeolocationSecurityIssue::LocationExfiltration);
    }

    if body.contains("watchPosition") {
        issues.push(GeolocationSecurityIssue::ContinuousTracking);
    }

    if has_location_without_consent(body) {
        issues.push(GeolocationSecurityIssue::LocationWithoutConsent);
    }

    if body.contains("enableHighAccuracy") && body.contains("true") {
        issues.push(GeolocationSecurityIssue::HighAccuracyTracking);
    }

    if has_location_cross_origin(body) {
        issues.push(GeolocationSecurityIssue::LocationCrossOrigin);
    }

    if has_location_persistence(body) {
        issues.push(GeolocationSecurityIssue::LocationPersistence);
    }

    if has_location_fingerprinting(body) {
        issues.push(GeolocationSecurityIssue::LocationFingerprinting);
    }

    if has_location_in_background(body) {
        issues.push(GeolocationSecurityIssue::LocationInBackground);
    }

    if has_location_with_sensitive_data(body) {
        issues.push(GeolocationSecurityIssue::LocationWithSensitiveData);
    }

    if has_geofencing_abuse(body) {
        issues.push(GeolocationSecurityIssue::GeofencingAbuse);
    }

    issues
}

fn has_location_exfiltration(body: &str) -> bool {
    let has_location = body.contains("getCurrentPosition") || body.contains("watchPosition");
    let has_coords = body.contains("coords.latitude")
        || body.contains("coords.longitude")
        || body.contains("coords");
    let sends_external = body.contains("fetch(")
        || body.contains("XMLHttpRequest")
        || body.contains("sendBeacon")
        || body.contains(".send(");
    has_location && has_coords && sends_external
}

fn has_location_without_consent(body: &str) -> bool {
    let has_geolocation = body.contains("getCurrentPosition") || body.contains("watchPosition");
    let no_consent_ui = !body.contains("confirm(")
        && !body.contains("permission")
        && !body.contains("consent")
        && !body.contains("allow");
    has_geolocation && no_consent_ui
}

fn has_location_cross_origin(body: &str) -> bool {
    let has_coords = body.contains("coords.latitude")
        || body.contains("coords.longitude")
        || body.contains("coords");
    let posts_message = body.contains("postMessage");
    has_coords && posts_message
}

fn has_location_persistence(body: &str) -> bool {
    let has_coords = body.contains("coords.latitude")
        || body.contains("coords.longitude")
        || body.contains("coords");
    let stores_data = body.contains("localStorage")
        || body.contains("sessionStorage")
        || body.contains("indexedDB");
    has_coords && stores_data
}

fn has_location_fingerprinting(body: &str) -> bool {
    let has_location = body.contains("getCurrentPosition") || body.contains("coords");
    let has_fingerprint_indicators = (body.contains("userAgent") || body.contains("navigator."))
        && (body.contains("screen") || body.contains("fingerprint") || body.contains("deviceId"));
    has_location && has_fingerprint_indicators
}

fn has_location_in_background(body: &str) -> bool {
    let has_location = body.contains("watchPosition") || body.contains("getCurrentPosition");
    let tracks_visibility = body.contains("visibilitychange")
        || body.contains("document.hidden")
        || body.contains("pageVisibility");
    has_location && tracks_visibility
}

fn has_location_with_sensitive_data(body: &str) -> bool {
    let has_coords = body.contains("coords.latitude")
        || body.contains("coords.longitude")
        || body.contains("coords");
    let has_pii = body.contains("email")
        || body.contains("phone")
        || body.contains("name")
        || body.contains("ssn")
        || body.contains("creditCard");
    has_coords && has_pii
}

fn has_geofencing_abuse(body: &str) -> bool {
    let has_location = body.contains("coords.latitude") || body.contains("coords.longitude");
    let has_geofence = body.contains("distance")
        || body.contains("radius")
        || body.contains("boundary")
        || body.contains("zone")
        || body.contains("perimeter");
    has_location && has_geofence
}

pub fn geolocation_security_severity(issue: &GeolocationSecurityIssue) -> f64 {
    match issue {
        GeolocationSecurityIssue::LocationExfiltration => 9.0,
        GeolocationSecurityIssue::LocationWithSensitiveData => 8.5,
        GeolocationSecurityIssue::LocationFingerprinting => 7.5,
        GeolocationSecurityIssue::ContinuousTracking => 7.0,
        GeolocationSecurityIssue::LocationInBackground => 6.5,
        GeolocationSecurityIssue::GeofencingAbuse => 6.0,
        GeolocationSecurityIssue::HighAccuracyTracking => 5.5,
        GeolocationSecurityIssue::LocationCrossOrigin => 5.0,
        GeolocationSecurityIssue::LocationPersistence => 4.5,
        GeolocationSecurityIssue::LocationWithoutConsent => 3.0,
    }
}

pub fn geolocation_security_to_operations(
    issues: &[GeolocationSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                geolocation_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
