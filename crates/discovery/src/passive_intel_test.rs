use super::passive_intel::*;

fn make_response(headers: Vec<(&str, &str)>, body: &str) -> ResponseData {
    ResponseData {
        url: "http://localhost:8080/test".to_string(),
        status: 200,
        headers: headers
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        body: body.to_string(),
    }
}

fn make_body_response(body: &str) -> ResponseData {
    make_response(vec![], body)
}

fn make_header_response(headers: Vec<(&str, &str)>) -> ResponseData {
    make_response(headers, "")
}

// ---------------------------------------------------------------------------
// Version string extraction
// ---------------------------------------------------------------------------

#[test]
fn test_server_header_version() {
    let resp = make_header_response(vec![("Server", "Apache/2.4.51 (Ubuntu)")]);
    let report = extract_intel(&resp);
    let versions = report.items_by_category(IntelCategory::VersionString);
    assert!(
        !versions.is_empty(),
        "should extract version from Server header"
    );
    assert!(versions.iter().any(|v| v.value.contains("Apache/2.4.51")));
}

#[test]
fn test_x_powered_by_version() {
    let resp = make_header_response(vec![("X-Powered-By", "PHP/7.4.33")]);
    let report = extract_intel(&resp);
    let versions = report.items_by_category(IntelCategory::VersionString);
    assert!(versions.iter().any(|v| v.value.contains("PHP/7.4.33")));
}

#[test]
fn test_aspnet_version_header() {
    let resp = make_header_response(vec![("X-AspNet-Version", "4.0.30319")]);
    let report = extract_intel(&resp);
    let versions = report.items_by_category(IntelCategory::VersionString);
    assert!(!versions.is_empty());
}

#[test]
fn test_nginx_version_extraction() {
    let resp = make_header_response(vec![("Server", "nginx/1.21.6")]);
    let report = extract_intel(&resp);
    let versions = report.items_by_category(IntelCategory::VersionString);
    assert!(versions.iter().any(|v| v.value.contains("nginx/1.21.6")));
}

// ---------------------------------------------------------------------------
// Framework signatures from headers
// ---------------------------------------------------------------------------

#[test]
fn test_phpsessid_cookie() {
    let resp = make_header_response(vec![("Set-Cookie", "PHPSESSID=abc123; path=/")]);
    let report = extract_intel(&resp);
    let sigs = report.items_by_category(IntelCategory::FrameworkSignature);
    assert!(sigs.iter().any(|s| s.value.contains("PHP")));
}

#[test]
fn test_jsessionid_cookie() {
    let resp = make_header_response(vec![("Set-Cookie", "JSESSIONID=node0abc; path=/")]);
    let report = extract_intel(&resp);
    let sigs = report.items_by_category(IntelCategory::FrameworkSignature);
    assert!(sigs.iter().any(|s| s.value.contains("Java")));
}

#[test]
fn test_django_csrf_cookie() {
    let resp = make_header_response(vec![("Set-Cookie", "csrftoken=abc123def456; path=/")]);
    let report = extract_intel(&resp);
    let sigs = report.items_by_category(IntelCategory::FrameworkSignature);
    assert!(sigs.iter().any(|s| s.value.contains("Django")));
}

#[test]
fn test_rails_session_cookie() {
    let resp = make_header_response(vec![("Set-Cookie", "_rails_session=encrypted; path=/")]);
    let report = extract_intel(&resp);
    let sigs = report.items_by_category(IntelCategory::FrameworkSignature);
    assert!(sigs.iter().any(|s| s.value.contains("Ruby on Rails")));
}

#[test]
fn test_express_powered_by_header() {
    let resp = make_header_response(vec![("X-Powered-By", "Express")]);
    let report = extract_intel(&resp);
    let sigs = report.items_by_category(IntelCategory::FrameworkSignature);
    assert!(sigs.iter().any(|s| s.value.contains("Express")));
}

// ---------------------------------------------------------------------------
// Framework signatures from body
// ---------------------------------------------------------------------------

#[test]
fn test_wordpress_body_pattern() {
    let resp =
        make_body_response(r#"<link rel="stylesheet" href="/wp-content/themes/flavor/style.css">"#);
    let report = extract_intel(&resp);
    let sigs = report.items_by_category(IntelCategory::FrameworkSignature);
    assert!(sigs.iter().any(|s| s.value == "WordPress"));
}

#[test]
fn test_nextjs_body_pattern() {
    let resp = make_body_response(
        r#"<script id="__NEXT_DATA__" type="application/json">{"props":{}}</script>"#,
    );
    let report = extract_intel(&resp);
    let sigs = report.items_by_category(IntelCategory::FrameworkSignature);
    assert!(sigs.iter().any(|s| s.value == "Next.js"));
}

#[test]
fn test_react_body_pattern() {
    let resp = make_body_response(r#"<div id="root" data-reactroot="">Loading</div>"#);
    let report = extract_intel(&resp);
    let sigs = report.items_by_category(IntelCategory::FrameworkSignature);
    assert!(sigs.iter().any(|s| s.value == "React"));
}

#[test]
fn test_meta_generator_tag() {
    let resp = make_body_response(r#"<meta name="generator" content="WordPress 6.3.1">"#);
    let report = extract_intel(&resp);
    let sigs = report.items_by_category(IntelCategory::FrameworkSignature);
    assert!(sigs.iter().any(|s| s.value.contains("WordPress")));
}

// ---------------------------------------------------------------------------
// Leaked IPs
// ---------------------------------------------------------------------------

#[test]
fn test_leaked_private_ip_10_range() {
    let resp = make_body_response("Forwarded to backend at 10.0.5.23:8080 for processing");
    let report = extract_intel(&resp);
    let ips = report.items_by_category(IntelCategory::LeakedIp);
    assert!(ips.iter().any(|i| i.value == "10.0.5.23"));
}

#[test]
fn test_leaked_private_ip_172_range() {
    let resp = make_body_response("Proxy: 172.16.0.42 upstream timeout");
    let report = extract_intel(&resp);
    let ips = report.items_by_category(IntelCategory::LeakedIp);
    assert!(ips.iter().any(|i| i.value == "172.16.0.42"));
}

#[test]
fn test_leaked_private_ip_192_range() {
    let resp = make_body_response("Connection refused: 192.168.1.100 port 5432");
    let report = extract_intel(&resp);
    let ips = report.items_by_category(IntelCategory::LeakedIp);
    assert!(ips.iter().any(|i| i.value == "192.168.1.100"));
}

#[test]
fn test_leaked_ip_in_header() {
    let resp = make_header_response(vec![("X-Backend-Server", "10.0.1.55")]);
    let report = extract_intel(&resp);
    let ips = report.items_by_category(IntelCategory::LeakedIp);
    assert!(ips.iter().any(|i| i.value == "10.0.1.55"));
}

// ---------------------------------------------------------------------------
// Hostnames
// ---------------------------------------------------------------------------

#[test]
fn test_internal_hostname() {
    let resp = make_body_response("Resolved via db-master.internal on port 3306");
    let report = extract_intel(&resp);
    let hosts = report.items_by_category(IntelCategory::Hostname);
    assert!(hosts.iter().any(|h| h.value == "db-master.internal"));
}

#[test]
fn test_corp_hostname() {
    let resp = make_body_response("auth handled by sso-gateway.corp");
    let report = extract_intel(&resp);
    let hosts = report.items_by_category(IntelCategory::Hostname);
    assert!(hosts.iter().any(|h| h.value == "sso-gateway.corp"));
}

// ---------------------------------------------------------------------------
// API keys and tokens
// ---------------------------------------------------------------------------

#[test]
fn test_aws_access_key() {
    let resp = make_body_response(r#"var config = { key: "AKIAIOSFODNN7EXAMPLE" };"#);
    let report = extract_intel(&resp);
    let keys = report.items_by_category(IntelCategory::ApiKey);
    assert!(keys.iter().any(|k| k.value.starts_with("AKIA")));
}

#[test]
fn test_generic_api_key() {
    let resp = make_body_response(r#"api_key: "abcdefghij1234567890KLMNOP""#);
    let report = extract_intel(&resp);
    let keys = report.items_by_category(IntelCategory::ApiKey);
    assert!(!keys.is_empty(), "should detect generic api_key pattern");
}

#[test]
fn test_github_pat_token() {
    let resp = make_body_response(r#"const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";"#);
    let report = extract_intel(&resp);
    let keys = report.items_by_category(IntelCategory::ApiKey);
    assert!(keys.iter().any(|k| k.value.starts_with("ghp_")));
}

#[test]
fn test_jwt_in_body() {
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    let resp = make_body_response(&format!(r#"token: "{jwt}""#));
    let report = extract_intel(&resp);
    let keys = report.items_by_category(IntelCategory::ApiKey);
    assert!(keys.iter().any(|k| k.value.starts_with("eyJ")));
}

#[test]
fn test_slack_token() {
    let resp = make_body_response(r#"slack_token = "xoxb-1234567890-abcdefghij""#);
    let report = extract_intel(&resp);
    let keys = report.items_by_category(IntelCategory::ApiKey);
    assert!(keys.iter().any(|k| k.value.starts_with("xoxb-")));
}

#[test]
fn test_google_api_key() {
    let resp = make_body_response(r#"AIzaSyA1234567890abcdefghijklmnopqrstuvw"#);
    let report = extract_intel(&resp);
    let keys = report.items_by_category(IntelCategory::ApiKey);
    assert!(keys.iter().any(|k| k.value.starts_with("AIza")));
}

// ---------------------------------------------------------------------------
// Emails
// ---------------------------------------------------------------------------

#[test]
fn test_email_extraction() {
    let resp = make_body_response("Contact admin@acmecorp.io for support");
    let report = extract_intel(&resp);
    let emails = report.items_by_category(IntelCategory::Email);
    assert!(emails.iter().any(|e| e.value == "admin@acmecorp.io"));
}

#[test]
fn test_email_ignores_example_domain() {
    let resp = make_body_response("user@example.com should be ignored");
    let report = extract_intel(&resp);
    let emails = report.items_by_category(IntelCategory::Email);
    assert!(emails.is_empty(), "should ignore @example.com addresses");
}

#[test]
fn test_email_ignores_asset_extensions() {
    let resp = make_body_response("hash@file.png and stuff@file.css");
    let report = extract_intel(&resp);
    let emails = report.items_by_category(IntelCategory::Email);
    assert!(emails.is_empty());
}

// ---------------------------------------------------------------------------
// S3 buckets
// ---------------------------------------------------------------------------

#[test]
fn test_s3_virtual_hosted_style() {
    let resp = make_body_response("https://my-secret-bucket.s3.amazonaws.com/assets/logo.png");
    let report = extract_intel(&resp);
    let buckets = report.items_by_category(IntelCategory::S3Bucket);
    assert!(
        buckets.iter().any(|b| b.value == "my-secret-bucket"),
        "got: {:?}",
        buckets
    );
}

#[test]
fn test_s3_uri_scheme() {
    let resp = make_body_response("uploaded to s3://company-backups/db-dump.sql.gz");
    let report = extract_intel(&resp);
    let buckets = report.items_by_category(IntelCategory::S3Bucket);
    assert!(buckets.iter().any(|b| b.value == "company-backups"));
}

#[test]
fn test_s3_path_style() {
    let resp = make_body_response("https://s3.us-east-1.amazonaws.com/data-lake-prod/export.csv");
    let report = extract_intel(&resp);
    let buckets = report.items_by_category(IntelCategory::S3Bucket);
    assert!(buckets.iter().any(|b| b.value == "data-lake-prod"));
}

#[test]
fn test_s3_arn() {
    let resp = make_body_response(r#""Resource": "arn:aws:s3:::internal-logs""#);
    let report = extract_intel(&resp);
    let buckets = report.items_by_category(IntelCategory::S3Bucket);
    assert!(buckets.iter().any(|b| b.value == "internal-logs"));
}

// ---------------------------------------------------------------------------
// Internal paths
// ---------------------------------------------------------------------------

#[test]
fn test_linux_path_disclosure() {
    let resp = make_body_response("Error at /home/deploy/app/server/routes/auth.js:42");
    let report = extract_intel(&resp);
    let paths = report.items_by_category(IntelCategory::InternalPath);
    assert!(!paths.is_empty(), "should detect Linux path disclosure");
    assert!(paths.iter().any(|p| p.value.contains("/home/deploy")));
}

#[test]
fn test_python_traceback_path() {
    let resp =
        make_body_response(r#"File "/opt/webapp/app/views.py", line 128, in handle_request"#);
    let report = extract_intel(&resp);
    let paths = report.items_by_category(IntelCategory::InternalPath);
    assert!(paths.iter().any(|p| p.value.contains("/opt/webapp")));
}

#[test]
fn test_php_error_path() {
    let resp = make_body_response("Fatal error in /var/www/html/includes/db.php on line 45");
    let report = extract_intel(&resp);
    let paths = report.items_by_category(IntelCategory::InternalPath);
    assert!(paths.iter().any(|p| p.value.contains("/var/www")));
}

#[test]
fn test_windows_path_disclosure() {
    let resp =
        make_body_response(r"Exception at C:\inetpub\wwwroot\api\Controllers\UserController.cs:88");
    let report = extract_intel(&resp);
    let paths = report.items_by_category(IntelCategory::InternalPath);
    assert!(!paths.is_empty(), "should detect Windows path disclosure");
}

// ---------------------------------------------------------------------------
// Developer comments
// ---------------------------------------------------------------------------

#[test]
fn test_todo_comment() {
    let resp = make_body_response("<!-- TODO: remove hardcoded admin password before deploy -->");
    let report = extract_intel(&resp);
    let comments = report.items_by_category(IntelCategory::DeveloperComment);
    assert!(!comments.is_empty());
    assert!(comments.iter().any(|c| c.value.contains("TODO")));
}

#[test]
fn test_fixme_comment() {
    let resp = make_body_response("<!-- FIXME: this endpoint has no auth check, very insecure -->");
    let report = extract_intel(&resp);
    let comments = report.items_by_category(IntelCategory::DeveloperComment);
    assert!(!comments.is_empty());
}

#[test]
fn test_debug_comment() {
    let resp = make_body_response("<!-- debug: admin password is hunter2 -->");
    let report = extract_intel(&resp);
    let comments = report.items_by_category(IntelCategory::DeveloperComment);
    assert!(comments.iter().any(|c| c.value.contains("debug")));
}

#[test]
fn test_ignores_boring_comments() {
    let resp = make_body_response("<!-- [if IE 9]><link href='ie.css'><![endif] -->");
    let report = extract_intel(&resp);
    let comments = report.items_by_category(IntelCategory::DeveloperComment);
    assert!(comments.is_empty(), "should ignore IE conditional comments");
}

// ---------------------------------------------------------------------------
// Batch extraction and report merging
// ---------------------------------------------------------------------------

#[test]
fn test_batch_extraction() {
    let responses = vec![
        make_body_response("leaked IP: 10.0.1.5"),
        make_body_response("admin@acmecorp.io is the contact"),
        make_header_response(vec![("Server", "nginx/1.19.0")]),
    ];
    let report = extract_intel_batch(&responses);
    assert!(report.items.len() >= 3);
    assert!(!report.items_by_category(IntelCategory::LeakedIp).is_empty());
    assert!(!report.items_by_category(IntelCategory::Email).is_empty());
    assert!(!report
        .items_by_category(IntelCategory::VersionString)
        .is_empty());
}

#[test]
fn test_report_merge() {
    let mut r1 = extract_intel(&make_body_response("IP: 10.0.0.1"));
    let r2 = extract_intel(&make_body_response("admin@corp.io"));
    r1.merge(r2);
    assert!(!r1.items_by_category(IntelCategory::LeakedIp).is_empty());
    assert!(!r1.items_by_category(IntelCategory::Email).is_empty());
}

#[test]
fn test_deduplication() {
    let resp = make_body_response("IP 10.0.0.1 and again 10.0.0.1 appears");
    let report = extract_intel(&resp);
    let ips = report.items_by_category(IntelCategory::LeakedIp);
    assert_eq!(ips.len(), 1, "duplicate IPs should be deduplicated");
}

// ---------------------------------------------------------------------------
// Rich fixture: multiple intel types in one response
// ---------------------------------------------------------------------------

#[test]
fn test_rich_fixture_response() {
    let body = r#"
<!DOCTYPE html>
<html>
<head>
    <meta name="generator" content="WordPress 6.3.1">
    <!-- TODO: remove debug endpoint before production -->
</head>
<body>
    <div data-reactroot="">
        <script>
            var config = {
                api_key: "AKIAIOSFODNN7EXAMPLE",
                bucket: "https://assets-prod.s3.amazonaws.com/uploads/img.png",
                backend: "10.0.2.15",
                contact: "devops@acmecorp.io"
            };
        </script>
        <p>Powered by api-gateway.internal on port 443</p>
    </div>
</body>
</html>"#;

    let resp = make_response(
        vec![
            ("Server", "nginx/1.21.3"),
            ("X-Powered-By", "Express"),
            ("Set-Cookie", "connect.sid=s%3Aabc; path=/"),
        ],
        body,
    );
    let report = extract_intel(&resp);

    assert!(
        !report
            .items_by_category(IntelCategory::VersionString)
            .is_empty(),
        "should find nginx version"
    );
    assert!(
        !report
            .items_by_category(IntelCategory::FrameworkSignature)
            .is_empty(),
        "should find framework signatures"
    );
    assert!(
        !report.items_by_category(IntelCategory::ApiKey).is_empty(),
        "should find AWS key"
    );
    assert!(
        !report.items_by_category(IntelCategory::S3Bucket).is_empty(),
        "should find S3 bucket"
    );
    assert!(
        !report.items_by_category(IntelCategory::LeakedIp).is_empty(),
        "should find leaked IP"
    );
    assert!(
        !report.items_by_category(IntelCategory::Email).is_empty(),
        "should find email"
    );
    assert!(
        !report.items_by_category(IntelCategory::Hostname).is_empty(),
        "should find internal hostname"
    );
    assert!(
        !report
            .items_by_category(IntelCategory::DeveloperComment)
            .is_empty(),
        "should find dev comment"
    );

    let total_categories_found: usize = [
        IntelCategory::VersionString,
        IntelCategory::FrameworkSignature,
        IntelCategory::ApiKey,
        IntelCategory::S3Bucket,
        IntelCategory::LeakedIp,
        IntelCategory::Email,
        IntelCategory::Hostname,
        IntelCategory::DeveloperComment,
    ]
    .iter()
    .filter(|cat| !report.items_by_category(**cat).is_empty())
    .count();

    assert!(
        total_categories_found >= 7,
        "rich fixture should cover ≥7 categories, found {total_categories_found}"
    );
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_empty_response() {
    let resp = make_response(vec![], "");
    let report = extract_intel(&resp);
    assert!(report.items.is_empty());
}

#[test]
fn test_display_impl_for_category() {
    assert_eq!(format!("{}", IntelCategory::LeakedIp), "Leaked IP");
    assert_eq!(format!("{}", IntelCategory::S3Bucket), "S3 Bucket");
    assert_eq!(format!("{}", IntelCategory::ApiKey), "API Key");
}

#[test]
fn test_items_by_category_filters_correctly() {
    let report = IntelReport {
        items: vec![
            IntelItem {
                category: IntelCategory::Email,
                value: "a@b.com".to_string(),
                source: "test".to_string(),
                confidence: 0.9,
            },
            IntelItem {
                category: IntelCategory::LeakedIp,
                value: "10.0.0.1".to_string(),
                source: "test".to_string(),
                confidence: 0.9,
            },
        ],
    };
    assert_eq!(report.items_by_category(IntelCategory::Email).len(), 1);
    assert_eq!(report.items_by_category(IntelCategory::LeakedIp).len(), 1);
    assert_eq!(report.items_by_category(IntelCategory::S3Bucket).len(), 0);
}

// ---------------------------------------------------------------------------
// Acceptance criterion: ≥90% extraction from rich fixture
// ---------------------------------------------------------------------------

#[test]
fn test_acceptance_90_percent_extraction() {
    let body = r#"
    Error: connection refused to 10.0.5.99:3306
    Trace: File "/srv/app/handlers/user.py", line 42, in get_user
    Also: C:\Users\dev\projects\backend\api.cs was involved
    Found: AKIAIOSFODNN7EXAMPLA aws key
    Token: ghp_0123456789abcdefghijABCDEFGHIJKLMN
    Mail: security@company.io and ops@internal-tools.io
    Bucket ref: s3://prod-data-exports and https://backup-db.s3.amazonaws.com/dump.sql
    Host: redis-master.internal
    <!-- FIXME: SQL injection possible in search param -->
    <!-- hack: disabled auth temporarily for testing -->
    <div data-v-abc123>Vue app</div>
    "#;

    let resp = make_response(
        vec![
            ("Server", "Apache/2.4.52"),
            ("Set-Cookie", "PHPSESSID=test123; path=/"),
            ("X-Backend-Server", "192.168.10.5"),
        ],
        body,
    );
    let report = extract_intel(&resp);

    let planted_items = 15;
    let extracted = report.items.len();
    let ratio = extracted as f64 / planted_items as f64;

    assert!(
        ratio >= 0.9,
        "extraction ratio {extracted}/{planted_items} = {ratio:.2} < 0.90"
    );
}
