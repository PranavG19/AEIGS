#[cfg(test)]
mod tests {
    use std::net::TcpListener as StdTcpListener;

    use axum::Router;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use tokio::net::TcpListener;

    use crate::subdomain_takeover::{SubdomainTakeoverDetector, is_potential_takeover_target};

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
        format!("127.0.0.1:{port}")
    }

    #[test]
    fn signature_match_s3() {
        let result = is_potential_takeover_target("<Error><Code>NoSuchBucket</Code></Error>");
        assert!(result.is_some());
        let (service, sig, sev) = result.unwrap();
        assert_eq!(service, "s3.amazonaws.com");
        assert_eq!(sig, "NoSuchBucket");
        assert!((sev - 8.0).abs() < f64::EPSILON);
    }

    #[test]
    fn signature_match_heroku() {
        let result = is_potential_takeover_target("No such app");
        assert!(result.is_some());
        let (service, _, sev) = result.unwrap();
        assert_eq!(service, "herokuapp.com");
        assert!((sev - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn signature_match_github_pages() {
        let result = is_potential_takeover_target("<p>There isn't a GitHub Pages site here.</p>");
        assert!(result.is_some());
        let (service, _, sev) = result.unwrap();
        assert_eq!(service, "github.io");
        assert!((sev - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn signature_match_azure() {
        let result = is_potential_takeover_target("404 Web Site not found");
        assert!(result.is_some());
        let (service, _, sev) = result.unwrap();
        assert_eq!(service, "azurewebsites.net");
        assert!((sev - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn signature_match_cloudfront() {
        let result = is_potential_takeover_target("Bad request - CloudFront");
        assert!(result.is_some());
        let (service, _, sev) = result.unwrap();
        assert_eq!(service, "cloudfront.net");
        assert!((sev - 6.0).abs() < f64::EPSILON);
    }

    #[test]
    fn signature_match_pantheon() {
        let result = is_potential_takeover_target("404 Unknown Site");
        assert!(result.is_some());
        let (service, _, _) = result.unwrap();
        assert_eq!(service, "pantheon.io");
    }

    #[test]
    fn signature_match_shopify() {
        let result = is_potential_takeover_target("Sorry, this shop is currently unavailable");
        assert!(result.is_some());
        let (service, _, _) = result.unwrap();
        assert_eq!(service, "shopify.com");
    }

    #[test]
    fn signature_match_tumblr() {
        let body = "Whatever you were looking for doesn't currently exist at this address.";
        let result = is_potential_takeover_target(body);
        assert!(result.is_some());
        let (service, _, sev) = result.unwrap();
        assert_eq!(service, "tumblr.com");
        assert!((sev - 6.0).abs() < f64::EPSILON);
    }

    #[test]
    fn signature_match_wordpress() {
        let result = is_potential_takeover_target("Do you want to register this domain?");
        assert!(result.is_some());
        let (service, _, _) = result.unwrap();
        assert_eq!(service, "wordpress.com");
    }

    #[test]
    fn signature_match_ghost() {
        let result = is_potential_takeover_target(
            "The thing you were looking for is no longer here, or never was",
        );
        assert!(result.is_some());
        let (service, _, _) = result.unwrap();
        assert_eq!(service, "ghost.io");
    }

    #[test]
    fn signature_match_surge() {
        let result = is_potential_takeover_target("project not found");
        assert!(result.is_some());
        let (service, _, _) = result.unwrap();
        assert_eq!(service, "surge.sh");
    }

    #[test]
    fn signature_match_bitbucket() {
        let result = is_potential_takeover_target("Repository not found");
        assert!(result.is_some());
        let (service, _, _) = result.unwrap();
        assert_eq!(service, "bitbucket.io");
    }

    #[test]
    fn signature_match_zendesk() {
        let result = is_potential_takeover_target("Help Center Closed");
        assert!(result.is_some());
        let (service, _, sev) = result.unwrap();
        assert_eq!(service, "zendesk.com");
        assert!((sev - 6.0).abs() < f64::EPSILON);
    }

    #[test]
    fn signature_match_fastly() {
        let result = is_potential_takeover_target("Fastly error: unknown domain: foo.example.com");
        assert!(result.is_some());
        let (service, _, sev) = result.unwrap();
        assert_eq!(service, "fastly.net");
        assert!((sev - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn no_match_on_clean_response() {
        let result = is_potential_takeover_target("Welcome to our website!");
        assert!(result.is_none());
    }

    #[test]
    fn no_match_on_empty_body() {
        let result = is_potential_takeover_target("");
        assert!(result.is_none());
    }

    #[test]
    fn no_match_on_generic_404() {
        let result = is_potential_takeover_target("404 Not Found");
        assert!(result.is_none());
    }

    #[test]
    fn first_matching_signature_wins() {
        let body = "NoSuchBucket and also No such app";
        let result = is_potential_takeover_target(body);
        assert!(result.is_some());
        let (service, _, _) = result.unwrap();
        assert_eq!(service, "s3.amazonaws.com");
    }

    #[test]
    fn finding_fields_populated_correctly() {
        async fn s3_handler() -> impl IntoResponse {
            (StatusCode::OK, "<Error><Code>NoSuchBucket</Code></Error>")
        }

        let app = Router::new().route("/", get(s3_handler));
        let addr = start_server_background(app);

        let detector = SubdomainTakeoverDetector::new();
        let finding = detector.test_subdomain(&addr);

        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.subdomain, addr);
        assert_eq!(f.service, "s3.amazonaws.com");
        assert_eq!(f.signature, "NoSuchBucket");
        assert!((f.severity - 8.0).abs() < f64::EPSILON);
        assert!(f.cname_target.is_none());
    }

    #[test]
    fn test_subdomain_returns_none_on_clean_server() {
        async fn ok_handler() -> impl IntoResponse {
            (StatusCode::OK, "Everything is fine")
        }

        let app = Router::new().route("/", get(ok_handler));
        let addr = start_server_background(app);

        let detector = SubdomainTakeoverDetector::new();
        let finding = detector.test_subdomain(&addr);
        assert!(finding.is_none());
    }

    #[test]
    fn test_subdomain_returns_none_on_unreachable_host() {
        let detector = SubdomainTakeoverDetector::new();
        let finding = detector.test_subdomain("192.0.2.1:1");
        assert!(finding.is_none());
    }

    #[test]
    fn test_subdomains_multiple() {
        async fn heroku_handler() -> impl IntoResponse {
            (StatusCode::OK, "No such app")
        }

        async fn ok_handler() -> impl IntoResponse {
            (StatusCode::OK, "ok")
        }

        let app1 = Router::new().route("/", get(heroku_handler));
        let addr1 = start_server_background(app1);

        let app2 = Router::new().route("/", get(ok_handler));
        let addr2 = start_server_background(app2);

        let app3 = Router::new().route("/", get(heroku_handler));
        let addr3 = start_server_background(app3);

        let detector = SubdomainTakeoverDetector::new();
        let subs = vec![addr1.clone(), addr2, addr3.clone()];
        let findings = detector.test_subdomains(&subs);

        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.service == "herokuapp.com"));
        let found_subs: Vec<&str> = findings.iter().map(|f| f.subdomain.as_str()).collect();
        assert!(found_subs.contains(&addr1.as_str()));
        assert!(found_subs.contains(&addr3.as_str()));
    }

    #[test]
    fn test_subdomains_empty_input() {
        let detector = SubdomainTakeoverDetector::new();
        let findings = detector.test_subdomains(&[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn with_client_constructor_works() {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let detector = SubdomainTakeoverDetector::with_client(client);

        async fn ok_handler() -> impl IntoResponse {
            (StatusCode::OK, "safe page")
        }

        let app = Router::new().route("/", get(ok_handler));
        let addr = start_server_background(app);

        let finding = detector.test_subdomain(&addr);
        assert!(finding.is_none());
    }

    #[test]
    fn severity_values_are_in_expected_range() {
        let bodies = [
            ("NoSuchBucket", 8.0),
            ("No such app", 7.0),
            ("Bad request", 6.0),
            ("Help Center Closed", 6.0),
            ("project not found", 7.0),
        ];

        for (body, expected_sev) in bodies {
            let result = is_potential_takeover_target(body);
            assert!(result.is_some(), "expected match for: {body}");
            let (_, _, sev) = result.unwrap();
            assert!(
                (sev - expected_sev).abs() < f64::EPSILON,
                "wrong severity for {body}: got {sev}, expected {expected_sev}"
            );
        }
    }
}
