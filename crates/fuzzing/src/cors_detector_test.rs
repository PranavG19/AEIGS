#[cfg(test)]
mod tests {
    use std::net::TcpListener as StdTcpListener;

    use axum::Router;
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use tokio::net::TcpListener;

    use crate::cors_detector::{CorsDetector, CorsIssue};

    fn start_server_background(app: Router) -> String {
        let std_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let port = std_listener.local_addr().unwrap().port();
        std_listener.set_nonblocking(true).unwrap();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = TcpListener::from_std(std_listener).unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });

        std::thread::sleep(std::time::Duration::from_millis(50));
        format!("http://127.0.0.1:{port}")
    }

    async fn reflected_origin_handler(headers: HeaderMap) -> impl IntoResponse {
        let mut resp_headers = HeaderMap::new();
        if let Some(origin) = headers.get("origin") {
            resp_headers.insert("access-control-allow-origin", origin.clone());
        }
        (StatusCode::OK, resp_headers, "ok")
    }

    async fn null_origin_handler(headers: HeaderMap) -> impl IntoResponse {
        let mut resp_headers = HeaderMap::new();
        if let Some(origin) = headers.get("origin") {
            if origin.to_str().unwrap_or("") == "null" {
                resp_headers.insert(
                    "access-control-allow-origin",
                    HeaderValue::from_static("null"),
                );
            }
        }
        (StatusCode::OK, resp_headers, "ok")
    }

    async fn wildcard_with_credentials_handler() -> impl IntoResponse {
        let mut headers = HeaderMap::new();
        headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
        headers.insert(
            "access-control-allow-credentials",
            HeaderValue::from_static("true"),
        );
        (StatusCode::OK, headers, "ok")
    }

    async fn subdomain_trust_handler(headers: HeaderMap) -> impl IntoResponse {
        let mut resp_headers = HeaderMap::new();
        if let Some(origin) = headers.get("origin") {
            let origin_str = origin.to_str().unwrap_or("");
            if origin_str.ends_with(".localhost") || origin_str.ends_with(".127.0.0.1") {
                resp_headers.insert("access-control-allow-origin", origin.clone());
            }
        }
        (StatusCode::OK, resp_headers, "ok")
    }

    async fn wildcard_no_credentials_handler() -> impl IntoResponse {
        let mut headers = HeaderMap::new();
        headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
        (StatusCode::OK, headers, "ok")
    }

    async fn no_cors_handler() -> impl IntoResponse {
        (StatusCode::OK, "ok")
    }

    async fn specific_origin_handler() -> impl IntoResponse {
        let mut headers = HeaderMap::new();
        headers.insert(
            "access-control-allow-origin",
            HeaderValue::from_static("https://trusted.example.com"),
        );
        (StatusCode::OK, headers, "ok")
    }

    #[test]
    fn issue_severity_reflected_origin() {
        assert!((CorsIssue::ReflectedOrigin.severity() - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn issue_severity_null_origin() {
        assert!((CorsIssue::NullOriginAccepted.severity() - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn issue_severity_wildcard_with_credentials() {
        assert!((CorsIssue::WildcardWithCredentials.severity() - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn issue_severity_subdomain_trust() {
        assert!((CorsIssue::SubdomainTrust.severity() - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn issue_severity_wildcard_origin() {
        assert!((CorsIssue::WildcardOrigin.severity() - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn issue_display_reflected_origin() {
        assert_eq!(CorsIssue::ReflectedOrigin.to_string(), "reflected-origin");
    }

    #[test]
    fn issue_display_null_origin() {
        assert_eq!(
            CorsIssue::NullOriginAccepted.to_string(),
            "null-origin-accepted"
        );
    }

    #[test]
    fn issue_display_wildcard_with_credentials() {
        assert_eq!(
            CorsIssue::WildcardWithCredentials.to_string(),
            "wildcard-with-credentials"
        );
    }

    #[test]
    fn issue_display_subdomain_trust() {
        assert_eq!(CorsIssue::SubdomainTrust.to_string(), "subdomain-trust");
    }

    #[test]
    fn issue_display_wildcard_origin() {
        assert_eq!(CorsIssue::WildcardOrigin.to_string(), "wildcard-origin");
    }

    #[test]
    fn detects_reflected_origin() {
        let app = Router::new().route("/api", get(reflected_origin_handler));
        let base = start_server_background(app);

        let detector = CorsDetector::new();
        let findings = detector.test_cors(&format!("{base}/api"));

        let reflected = findings
            .iter()
            .find(|f| f.issue == CorsIssue::ReflectedOrigin);
        assert!(reflected.is_some());
        let f = reflected.unwrap();
        assert!((f.severity - 7.0).abs() < f64::EPSILON);
        assert_eq!(f.evidence, "https://evil.com");
    }

    #[test]
    fn detects_null_origin_accepted() {
        let app = Router::new().route("/api", get(null_origin_handler));
        let base = start_server_background(app);

        let detector = CorsDetector::new();
        let findings = detector.test_cors(&format!("{base}/api"));

        let null_finding = findings
            .iter()
            .find(|f| f.issue == CorsIssue::NullOriginAccepted);
        assert!(null_finding.is_some());
        let f = null_finding.unwrap();
        assert!((f.severity - 5.0).abs() < f64::EPSILON);
        assert_eq!(f.evidence, "null");
    }

    #[test]
    fn detects_wildcard_with_credentials() {
        let app = Router::new().route("/api", get(wildcard_with_credentials_handler));
        let base = start_server_background(app);

        let detector = CorsDetector::new();
        let findings = detector.test_cors(&format!("{base}/api"));

        let wc_finding = findings
            .iter()
            .find(|f| f.issue == CorsIssue::WildcardWithCredentials);
        assert!(wc_finding.is_some());
        let f = wc_finding.unwrap();
        assert!((f.severity - 7.0).abs() < f64::EPSILON);
        assert!(f.evidence.contains("ACAO: *"));
        assert!(f.evidence.contains("ACAC: true"));
    }

    #[test]
    fn detects_subdomain_trust() {
        let app = Router::new().route("/api", get(subdomain_trust_handler));
        let base = start_server_background(app);

        let detector = CorsDetector::new();
        let endpoint = format!("{base}/api");
        let findings = detector.test_cors(&endpoint);

        let sub_finding = findings
            .iter()
            .find(|f| f.issue == CorsIssue::SubdomainTrust);
        assert!(sub_finding.is_some());
        let f = sub_finding.unwrap();
        assert!((f.severity - 5.0).abs() < f64::EPSILON);
        assert!(f.evidence.contains("evil."));
    }

    #[test]
    fn detects_wildcard_origin_low_severity() {
        let app = Router::new().route("/api", get(wildcard_no_credentials_handler));
        let base = start_server_background(app);

        let detector = CorsDetector::new();
        let findings = detector.test_cors(&format!("{base}/api"));

        let wc_finding = findings
            .iter()
            .find(|f| f.issue == CorsIssue::WildcardOrigin);
        assert!(wc_finding.is_some());
        let f = wc_finding.unwrap();
        assert!((f.severity - 3.0).abs() < f64::EPSILON);
        assert_eq!(f.evidence, "*");
    }

    #[test]
    fn no_findings_on_compliant_cors() {
        let app = Router::new().route("/api", get(specific_origin_handler));
        let base = start_server_background(app);

        let detector = CorsDetector::new();
        let findings = detector.test_cors(&format!("{base}/api"));
        assert!(findings.is_empty());
    }

    #[test]
    fn no_findings_when_no_cors_headers() {
        let app = Router::new().route("/api", get(no_cors_handler));
        let base = start_server_background(app);

        let detector = CorsDetector::new();
        let findings = detector.test_cors(&format!("{base}/api"));
        assert!(findings.is_empty());
    }

    #[test]
    fn rejects_non_localhost_target() {
        let detector = CorsDetector::new();
        let findings = detector.test_cors("https://example.com/api");
        assert!(findings.is_empty());
    }

    #[test]
    fn rejects_empty_endpoint() {
        let detector = CorsDetector::new();
        let findings = detector.test_cors("");
        assert!(findings.is_empty());
    }

    #[test]
    fn wildcard_with_credentials_not_flagged_as_plain_wildcard() {
        let app = Router::new().route("/api", get(wildcard_with_credentials_handler));
        let base = start_server_background(app);

        let detector = CorsDetector::new();
        let findings = detector.test_cors(&format!("{base}/api"));

        let plain_wildcard = findings
            .iter()
            .find(|f| f.issue == CorsIssue::WildcardOrigin);
        assert!(
            plain_wildcard.is_none(),
            "wildcard+credentials should not also flag plain wildcard"
        );
    }

    #[test]
    fn finding_endpoint_matches_input() {
        let app = Router::new().route("/specific/path", get(reflected_origin_handler));
        let base = start_server_background(app);

        let detector = CorsDetector::new();
        let endpoint = format!("{base}/specific/path");
        let findings = detector.test_cors(&endpoint);

        assert!(!findings.is_empty());
        for f in &findings {
            assert_eq!(f.endpoint, endpoint);
        }
    }

    #[test]
    fn with_client_constructor_works() {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let detector = CorsDetector::with_client(client);

        let app = Router::new().route("/api", get(no_cors_handler));
        let base = start_server_background(app);

        let findings = detector.test_cors(&format!("{base}/api"));
        assert!(findings.is_empty());
    }

    #[test]
    fn extract_domain_returns_none_for_invalid_url() {
        let detector = CorsDetector::new();
        let findings = detector.test_cors("not-a-url");
        assert!(findings.is_empty());
    }
}
