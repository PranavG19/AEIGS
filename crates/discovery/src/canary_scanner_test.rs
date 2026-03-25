use crate::canary_scanner::*;

#[test]
fn new_scanner_builds_without_panic() {
    let _scanner = CanaryScanner::new();
}

#[test]
fn scan_rejects_non_localhost() {
    let scanner = CanaryScanner::new();
    let result = scanner.scan("http://example.com");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CanaryScanError::NonLocalhostTarget(_)
    ));
}

#[test]
fn scan_rejects_invalid_url() {
    let scanner = CanaryScanner::new();
    let result = scanner.scan("not-a-url");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CanaryScanError::InvalidUrl(_)
    ));
}

#[test]
fn detect_aws_canary_key_known_example() {
    let content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE1";
    let tokens = scan_content_for_canaries(content, "/.env");
    assert!(!tokens.is_empty(), "should detect AWS example key");
    let token = &tokens[0];
    assert_eq!(token.token_type, CanaryTokenType::AwsCredential);
    assert_eq!(token.risk_level, CanaryRisk::Critical);
    assert!(token.should_avoid);
}

#[test]
fn detect_aws_canary_key_generic() {
    let content = "aws_access_key_id = AKIAZ7TQFAKEKEY12345";
    let tokens = scan_content_for_canaries(content, "/.env");
    let aws_tokens: Vec<_> = tokens
        .iter()
        .filter(|t| t.token_type == CanaryTokenType::AwsCredential)
        .collect();
    assert!(!aws_tokens.is_empty(), "should detect generic AKIA key");
    assert_eq!(aws_tokens[0].risk_level, CanaryRisk::High);
}

#[test]
fn detect_aws_secret_key() {
    let content = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1";
    let tokens = scan_content_for_canaries(content, "/.env");
    let secret_tokens: Vec<_> = tokens
        .iter()
        .filter(|t| t.description.contains("secret"))
        .collect();
    assert!(
        !secret_tokens.is_empty(),
        "should detect AWS secret access key"
    );
}

#[test]
fn detect_canary_service_url() {
    let content = "callback_url=https://canarytokens.com/about/abc123/post.jsp";
    let tokens = scan_content_for_canaries(content, "/config.json");
    let service_tokens: Vec<_> = tokens
        .iter()
        .filter(|t| t.token_type == CanaryTokenType::CanaryServiceUrl)
        .collect();
    assert!(!service_tokens.is_empty(), "should detect canarytokens.com");
    assert_eq!(service_tokens[0].risk_level, CanaryRisk::Critical);
}

#[test]
fn detect_honeydb_url() {
    let content = "# threat intel feed\nurl = https://honeydb.io/api/v2/feed";
    let tokens = scan_content_for_canaries(content, "/config.yml");
    assert!(
        tokens.iter().any(|t| t.value.contains("honeydb.io")),
        "should detect honeydb.io"
    );
}

#[test]
fn detect_dns_canary_domain() {
    let content = "nslookup abc1234567890abcdef.canarytokens.com";
    let tokens = scan_content_for_canaries(content, "/script.sh");
    let dns_tokens: Vec<_> = tokens
        .iter()
        .filter(|t| t.token_type == CanaryTokenType::DnsCanary)
        .collect();
    assert!(!dns_tokens.is_empty(), "should detect DNS canary domain");
}

#[test]
fn detect_honeydoc_marker() {
    let content = "var honeydoc = true; /* marker for document tracking */";
    let tokens = scan_content_for_canaries(content, "/doc.html");
    let doc_tokens: Vec<_> = tokens
        .iter()
        .filter(|t| t.token_type == CanaryTokenType::HoneydocMarker)
        .collect();
    assert!(!doc_tokens.is_empty(), "should detect honeydoc marker");
}

#[test]
fn detect_tokenized_email() {
    let content = "contact: admin-token123@canarytokens.com";
    let tokens = scan_content_for_canaries(content, "/.env");
    let email_tokens: Vec<_> = tokens
        .iter()
        .filter(|t| t.token_type == CanaryTokenType::TokenizedEmail)
        .collect();
    assert!(
        !email_tokens.is_empty(),
        "should detect tokenized canary email"
    );
}

#[test]
fn detect_web_bug_image_beacon() {
    let content = r#"<script>new Image().src="https://evil.com/track?id=123";</script>"#;
    let tokens = scan_content_for_canaries(content, "/page.html");
    let bug_tokens: Vec<_> = tokens
        .iter()
        .filter(|t| t.token_type == CanaryTokenType::WebBug)
        .collect();
    assert!(!bug_tokens.is_empty(), "should detect Image beacon");
}

#[test]
fn detect_web_bug_send_beacon() {
    let content = r#"navigator.sendBeacon("https://track.example.com/hit", data);"#;
    let tokens = scan_content_for_canaries(content, "/page.html");
    let bug_tokens: Vec<_> = tokens
        .iter()
        .filter(|t| t.token_type == CanaryTokenType::WebBug)
        .collect();
    assert!(!bug_tokens.is_empty(), "should detect sendBeacon call");
}

#[test]
fn clean_content_returns_no_tokens() {
    let content = "DATABASE_URL=postgresql://localhost:5432/mydb\nPORT=3000\nDEBUG=true";
    let tokens = scan_content_for_canaries(content, "/.env");
    assert!(tokens.is_empty(), "clean content should have no canaries");
}

#[test]
fn multiple_canaries_in_single_document() {
    let content = r#"
        AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE1
        CALLBACK=https://canarytokens.com/test
        ALERT_EMAIL=notify@canary.tools
        honeydoc = true
    "#;
    let tokens = scan_content_for_canaries(content, "/.env");
    assert!(
        tokens.len() >= 3,
        "should find multiple canaries, found {}",
        tokens.len()
    );
}

#[test]
fn canary_token_type_display() {
    assert_eq!(
        format!("{}", CanaryTokenType::AwsCredential),
        "AWS Canary Credential"
    );
    assert_eq!(
        format!("{}", CanaryTokenType::TrackingPixel),
        "Tracking Pixel"
    );
    assert_eq!(
        format!("{}", CanaryTokenType::DnsCanary),
        "DNS Canary Domain"
    );
    assert_eq!(format!("{}", CanaryTokenType::WebBug), "Web Bug / Beacon");
}

#[test]
fn canary_risk_display() {
    assert_eq!(format!("{}", CanaryRisk::Low), "Low");
    assert_eq!(format!("{}", CanaryRisk::Critical), "Critical");
}

#[test]
fn canary_risk_ordering() {
    assert!(CanaryRisk::Low < CanaryRisk::Medium);
    assert!(CanaryRisk::Medium < CanaryRisk::High);
    assert!(CanaryRisk::High < CanaryRisk::Critical);
}

#[test]
fn error_display_variants() {
    let e1 = CanaryScanError::InvalidUrl("bad".into());
    assert!(format!("{e1}").contains("bad"));

    let e2 = CanaryScanError::NonLocalhostTarget("remote".into());
    assert!(format!("{e2}").contains("remote"));

    let e3 = CanaryScanError::HttpError("timeout".into());
    assert!(format!("{e3}").contains("timeout"));
}

#[test]
fn scan_content_method_works() {
    let scanner = CanaryScanner::new();
    let content = "AKIAIOSFODNN7EXAMPLE1 is a canary key";
    let tokens = scanner.scan_content(content, "manual-input");
    assert!(!tokens.is_empty());
}

#[test]
fn scan_result_fields() {
    let result = CanaryScanResult {
        canaries_found: vec![CanaryToken {
            token_type: CanaryTokenType::AwsCredential,
            location: "/.env".to_string(),
            value: "AKIA...".to_string(),
            risk_level: CanaryRisk::Critical,
            description: "test".to_string(),
            should_avoid: true,
        }],
        total_paths_scanned: 18,
        safe_paths: vec!["/robots.txt".to_string()],
        dangerous_paths: vec!["/.env".to_string()],
    };
    assert_eq!(result.canaries_found.len(), 1);
    assert_eq!(result.total_paths_scanned, 18);
    assert_eq!(result.dangerous_paths.len(), 1);
}
