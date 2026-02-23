#[cfg(test)]
mod tests {
    use std::net::TcpListener as StdTcpListener;

    use axum::Router;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use tokio::net::TcpListener;

    use crate::cloud_detector::{
        CloudDetector, CloudIssue, CloudResource, extract_cloud_references,
    };

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

    #[test]
    fn extract_s3_subdomain_style() {
        let body = r#"<img src="https://my-bucket.s3.amazonaws.com/image.png">"#;
        let refs = extract_cloud_references(body);

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, CloudResource::AwsS3Bucket);
        assert_eq!(refs[0].1, "https://my-bucket.s3.amazonaws.com");
    }

    #[test]
    fn extract_s3_path_style() {
        let body = r#"<a href="https://s3.amazonaws.com/company-assets/file.pdf">"#;
        let refs = extract_cloud_references(body);

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, CloudResource::AwsS3Bucket);
        assert_eq!(refs[0].1, "https://s3.amazonaws.com/company-assets");
    }

    #[test]
    fn extract_azure_blob() {
        let body = r#"{"url": "https://storageaccount.blob.core.windows.net/container/blob"}"#;
        let refs = extract_cloud_references(body);

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, CloudResource::AzureBlobStorage);
        assert_eq!(refs[0].1, "https://storageaccount.blob.core.windows.net");
    }

    #[test]
    fn extract_gcp_storage() {
        let body = r#"<script src="https://storage.googleapis.com/my-project/app.js"></script>"#;
        let refs = extract_cloud_references(body);

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, CloudResource::GcpStorageBucket);
        assert_eq!(refs[0].1, "https://storage.googleapis.com/my-project");
    }

    #[test]
    fn extract_firebase() {
        let body = r#"var ref = new Firebase("https://my-app.firebaseio.com/data");"#;
        let refs = extract_cloud_references(body);

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, CloudResource::FirebaseDatabase);
        assert_eq!(refs[0].1, "https://my-app.firebaseio.com");
    }

    #[test]
    fn extract_multiple_providers_in_one_body() {
        let body = concat!(
            r#"<img src="https://assets.s3.amazonaws.com/logo.png"> "#,
            r#"<link href="https://cdn.blob.core.windows.net/styles.css"> "#,
            r#"<script src="https://storage.googleapis.com/static-files/app.js"></script> "#,
            r#"firebase.initializeApp({databaseURL: "https://test-project.firebaseio.com"});"#,
        );
        let refs = extract_cloud_references(body);

        assert_eq!(refs.len(), 4);

        let types: Vec<CloudResource> = refs.iter().map(|(r, _)| *r).collect();
        assert!(types.contains(&CloudResource::AwsS3Bucket));
        assert!(types.contains(&CloudResource::AzureBlobStorage));
        assert!(types.contains(&CloudResource::GcpStorageBucket));
        assert!(types.contains(&CloudResource::FirebaseDatabase));
    }

    #[test]
    fn no_matches_on_clean_html() {
        let body = r#"
            <html>
            <head><title>Test</title></head>
            <body>
                <p>Hello world</p>
                <a href="https://example.com/page">Link</a>
                <img src="/images/logo.png">
            </body>
            </html>
        "#;
        let refs = extract_cloud_references(body);
        assert!(refs.is_empty());
    }

    #[test]
    fn no_matches_on_empty_body() {
        let refs = extract_cloud_references("");
        assert!(refs.is_empty());
    }

    #[test]
    fn extract_s3_bucket_with_dots_in_name() {
        let body = r#"https://my.company.assets.s3.amazonaws.com/file"#;
        let refs = extract_cloud_references(body);

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, CloudResource::AwsS3Bucket);
        assert!(refs[0].1.contains("my.company.assets"));
    }

    #[test]
    fn extract_firebase_with_hyphens() {
        let body = r#"https://my-cool-project-123.firebaseio.com/users"#;
        let refs = extract_cloud_references(body);

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, CloudResource::FirebaseDatabase);
        assert_eq!(refs[0].1, "https://my-cool-project-123.firebaseio.com");
    }

    #[test]
    fn issue_severity_public_listing() {
        assert!((CloudIssue::PublicListing.severity() - 8.0).abs() < f64::EPSILON);
    }

    #[test]
    fn issue_severity_public_read_access() {
        assert!((CloudIssue::PublicReadAccess.severity() - 7.5).abs() < f64::EPSILON);
    }

    #[test]
    fn issue_severity_open_firebase() {
        assert!((CloudIssue::OpenFirebase.severity() - 9.0).abs() < f64::EPSILON);
    }

    #[test]
    fn cloud_resource_display() {
        assert_eq!(CloudResource::AwsS3Bucket.to_string(), "aws-s3-bucket");
        assert_eq!(
            CloudResource::AzureBlobStorage.to_string(),
            "azure-blob-storage"
        );
        assert_eq!(
            CloudResource::GcpStorageBucket.to_string(),
            "gcp-storage-bucket"
        );
        assert_eq!(
            CloudResource::FirebaseDatabase.to_string(),
            "firebase-database"
        );
    }

    #[test]
    fn cloud_issue_display() {
        assert_eq!(CloudIssue::PublicListing.to_string(), "public-listing");
        assert_eq!(
            CloudIssue::PublicReadAccess.to_string(),
            "public-read-access"
        );
        assert_eq!(CloudIssue::OpenFirebase.to_string(), "open-firebase");
    }

    async fn s3_listing_handler() -> impl IntoResponse {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
    <Contents>
        <Key>secret.txt</Key>
        <Size>1024</Size>
    </Contents>
</ListBucketResult>"#;
        (StatusCode::OK, xml)
    }

    async fn s3_access_denied_handler() -> impl IntoResponse {
        (StatusCode::FORBIDDEN, "AccessDenied")
    }

    async fn firebase_open_handler() -> impl IntoResponse {
        (
            StatusCode::OK,
            r#"{"users":{"admin":{"password":"secret"}}}"#,
        )
    }

    async fn firebase_null_handler() -> impl IntoResponse {
        (StatusCode::OK, "null")
    }

    async fn firebase_quoted_null_handler() -> impl IntoResponse {
        (StatusCode::OK, "\"null\"")
    }

    async fn azure_listing_handler() -> impl IntoResponse {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<EnumerationResults>
    <Blobs>
        <Blob>
            <Name>data.csv</Name>
        </Blob>
    </Blobs>
</EnumerationResults>"#;
        (StatusCode::OK, xml)
    }

    async fn azure_private_handler() -> impl IntoResponse {
        (StatusCode::FORBIDDEN, "AuthorizationFailure")
    }

    #[test]
    fn detects_s3_public_listing() {
        let app = Router::new().fallback(get(s3_listing_handler));
        let base = start_server_background(app);

        let detector = CloudDetector::new();
        let finding = detector.test_s3_bucket(&base);

        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.resource_type, CloudResource::AwsS3Bucket);
        assert_eq!(f.issue, CloudIssue::PublicListing);
        assert!((f.severity - 8.0).abs() < f64::EPSILON);
        assert!(f.evidence.contains("S3 bucket listing enabled"));
    }

    #[test]
    fn no_finding_on_s3_access_denied() {
        let app = Router::new().fallback(get(s3_access_denied_handler));
        let base = start_server_background(app);

        let detector = CloudDetector::new();
        let finding = detector.test_s3_bucket(&base);

        assert!(finding.is_none());
    }

    #[test]
    fn detects_open_firebase() {
        let app = Router::new().route("/.json", get(firebase_open_handler));
        let base = start_server_background(app);

        let detector = CloudDetector::new();
        let finding = detector.test_firebase(&base);

        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.resource_type, CloudResource::FirebaseDatabase);
        assert_eq!(f.issue, CloudIssue::OpenFirebase);
        assert!((f.severity - 9.0).abs() < f64::EPSILON);
        assert!(f.evidence.contains("Firebase database openly readable"));
    }

    #[test]
    fn no_finding_on_firebase_null_response() {
        let app = Router::new().route("/.json", get(firebase_null_handler));
        let base = start_server_background(app);

        let detector = CloudDetector::new();
        let finding = detector.test_firebase(&base);

        assert!(finding.is_none());
    }

    #[test]
    fn no_finding_on_firebase_quoted_null_response() {
        let app = Router::new().route("/.json", get(firebase_quoted_null_handler));
        let base = start_server_background(app);

        let detector = CloudDetector::new();
        let finding = detector.test_firebase(&base);

        assert!(finding.is_none());
    }

    #[test]
    fn detects_azure_public_listing() {
        let app = Router::new().fallback(get(azure_listing_handler));
        let base = start_server_background(app);

        let detector = CloudDetector::new();
        let finding = detector.test_azure_blob(&base);

        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.resource_type, CloudResource::AzureBlobStorage);
        assert_eq!(f.issue, CloudIssue::PublicListing);
        assert!((f.severity - 8.0).abs() < f64::EPSILON);
        assert!(f.evidence.contains("Azure blob container listing enabled"));
    }

    #[test]
    fn no_finding_on_azure_private_container() {
        let app = Router::new().fallback(get(azure_private_handler));
        let base = start_server_background(app);

        let detector = CloudDetector::new();
        let finding = detector.test_azure_blob(&base);

        assert!(finding.is_none());
    }

    #[test]
    fn scan_responses_with_no_cloud_references() {
        let detector = CloudDetector::new();
        let responses = vec![(
            "http://127.0.0.1/page".to_string(),
            "<html><body>Hello</body></html>".to_string(),
        )];

        let findings = detector.scan_responses(&responses);
        assert!(findings.is_empty());
    }

    #[test]
    fn with_client_constructor_works() {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let detector = CloudDetector::with_client(client);

        let responses: Vec<(String, String)> = vec![];
        let findings = detector.scan_responses(&responses);
        assert!(findings.is_empty());
    }

    #[test]
    fn finding_fields_populated_correctly() {
        let app = Router::new().fallback(get(s3_listing_handler));
        let base = start_server_background(app);

        let detector = CloudDetector::new();
        let finding = detector.test_s3_bucket(&base).unwrap();

        assert_eq!(finding.resource_url, base);
        assert!(!finding.evidence.is_empty());
    }

    #[test]
    fn extract_both_s3_styles_in_same_body() {
        let body = concat!(
            "https://my-bucket.s3.amazonaws.com/a ",
            "https://s3.amazonaws.com/other-bucket/b",
        );
        let refs = extract_cloud_references(body);

        assert_eq!(refs.len(), 2);
        assert!(refs.iter().all(|(r, _)| *r == CloudResource::AwsS3Bucket));
    }

    #[test]
    fn subdomain_s3_url_does_not_produce_path_style_duplicate() {
        let body = r#"https://only-subdomain.s3.amazonaws.com/some/path"#;
        let refs = extract_cloud_references(body);

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, CloudResource::AwsS3Bucket);
        assert_eq!(refs[0].1, "https://only-subdomain.s3.amazonaws.com");
    }
}
