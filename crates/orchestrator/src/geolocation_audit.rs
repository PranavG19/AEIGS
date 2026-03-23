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
