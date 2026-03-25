use crate::api_secret_exposure::{
    check_docker_layer_history, check_swagger_content, compile_patterns, dockerhub_search_url,
    finding_from_match, github_search_queries, github_search_url, gitlab_snippet_search_url,
    npm_search_url, postman_search_url, scan_text_for_secrets, severity_for_secret,
    ApiSecretExposureScanner, ExposureSource, SecretSeverity, SecretType, DOCKER_LEAK_PATTERNS,
    SECRET_PATTERNS, SWAGGER_ENDPOINTS,
};

#[test]
fn all_sources_listed() {
    let all = ExposureSource::all();
    assert_eq!(all.len(), 6);
    assert!(all.contains(&ExposureSource::GitHubCodeSearch));
    assert!(all.contains(&ExposureSource::GitLabSnippets));
    assert!(all.contains(&ExposureSource::NpmPackageContents));
    assert!(all.contains(&ExposureSource::DockerHubImageLayers));
    assert!(all.contains(&ExposureSource::PostmanPublicWorkspaces));
    assert!(all.contains(&ExposureSource::SwaggerUiEmbeddedTokens));
}

#[test]
fn source_display_names() {
    assert_eq!(
        format!("{}", ExposureSource::GitHubCodeSearch),
        "GitHub Code Search"
    );
    assert_eq!(
        format!("{}", ExposureSource::DockerHubImageLayers),
        "Docker Hub Image Layers"
    );
}

#[test]
fn secret_type_display() {
    assert_eq!(format!("{}", SecretType::AwsAccessKey), "AWS Access Key");
    assert_eq!(
        format!("{}", SecretType::StripeSecretKey),
        "Stripe Secret Key"
    );
    assert_eq!(format!("{}", SecretType::JwtToken), "JWT Token");
}

#[test]
fn severity_for_aws_keys_is_critical() {
    assert_eq!(
        severity_for_secret(SecretType::AwsAccessKey),
        SecretSeverity::Critical
    );
    assert_eq!(
        severity_for_secret(SecretType::AwsSecretKey),
        SecretSeverity::Critical
    );
}

#[test]
fn severity_for_private_key_is_critical() {
    assert_eq!(
        severity_for_secret(SecretType::PrivateKey),
        SecretSeverity::Critical
    );
}

#[test]
fn severity_for_database_url_is_critical() {
    assert_eq!(
        severity_for_secret(SecretType::DatabaseUrl),
        SecretSeverity::Critical
    );
}

#[test]
fn severity_for_github_token_is_high() {
    assert_eq!(
        severity_for_secret(SecretType::GitHubToken),
        SecretSeverity::High
    );
}

#[test]
fn severity_for_stripe_publishable_is_low() {
    assert_eq!(
        severity_for_secret(SecretType::StripePublishableKey),
        SecretSeverity::Low
    );
}

#[test]
fn severity_for_firebase_is_medium() {
    assert_eq!(
        severity_for_secret(SecretType::FirebaseKey),
        SecretSeverity::Medium
    );
}

#[test]
fn severity_scores_ordered() {
    assert!(SecretSeverity::Informational.score() < SecretSeverity::Low.score());
    assert!(SecretSeverity::Low.score() < SecretSeverity::Medium.score());
    assert!(SecretSeverity::Medium.score() < SecretSeverity::High.score());
    assert!(SecretSeverity::High.score() < SecretSeverity::Critical.score());
}

#[test]
fn secret_patterns_non_empty() {
    assert!(SECRET_PATTERNS.len() >= 20);
}

#[test]
fn all_patterns_compile() {
    let compiled = compile_patterns();
    assert_eq!(compiled.len(), SECRET_PATTERNS.len());
}

#[test]
fn scan_detects_aws_access_key() {
    let text = "config: AKIAIOSFODNN7EXAMPLE more text";
    let matches = scan_text_for_secrets(text);
    assert!(matches
        .iter()
        .any(|m| m.secret_type == SecretType::AwsAccessKey));
}

#[test]
fn scan_detects_github_token() {
    let text = "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
    let matches = scan_text_for_secrets(text);
    assert!(matches
        .iter()
        .any(|m| m.secret_type == SecretType::GitHubToken));
}

#[test]
fn scan_detects_gitlab_token() {
    let text = "GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx";
    let matches = scan_text_for_secrets(text);
    assert!(matches
        .iter()
        .any(|m| m.secret_type == SecretType::GitLabToken));
}

#[test]
fn scan_detects_slack_token() {
    let text = "SLACK_BOT_TOKEN=xoxb-1234567890-abcdefghijklmn";
    let matches = scan_text_for_secrets(text);
    assert!(matches
        .iter()
        .any(|m| m.secret_type == SecretType::SlackToken));
}

#[test]
fn scan_detects_stripe_secret() {
    let text = "STRIPE_KEY=sk_live_abcdefghijklmnopqrstuvwx";
    let matches = scan_text_for_secrets(text);
    assert!(matches
        .iter()
        .any(|m| m.secret_type == SecretType::StripeSecretKey));
}

#[test]
fn scan_detects_private_key() {
    let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----";
    let matches = scan_text_for_secrets(text);
    assert!(matches
        .iter()
        .any(|m| m.secret_type == SecretType::PrivateKey));
}

#[test]
fn scan_detects_jwt_token() {
    let text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    let matches = scan_text_for_secrets(text);
    assert!(matches
        .iter()
        .any(|m| m.secret_type == SecretType::JwtToken));
}

#[test]
fn scan_detects_sendgrid_key() {
    let text = "SG.xxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    let matches = scan_text_for_secrets(text);
    assert!(matches
        .iter()
        .any(|m| m.secret_type == SecretType::SendGridApiKey));
}

#[test]
fn scan_detects_database_url() {
    let text = "DATABASE_URL=postgres://user:pass@host:5432/db";
    let matches = scan_text_for_secrets(text);
    assert!(matches
        .iter()
        .any(|m| m.secret_type == SecretType::DatabaseUrl));
}

#[test]
fn scan_detects_firebase_key() {
    let text = "FIREBASE_API_KEY=AIzaSyC_abcdefghijklmnopqrstuvwxyz12345";
    let matches = scan_text_for_secrets(text);
    assert!(matches
        .iter()
        .any(|m| m.secret_type == SecretType::FirebaseKey));
}

#[test]
fn scan_detects_digitalocean_token() {
    let text = "DO_TOKEN=dop_v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let matches = scan_text_for_secrets(text);
    assert!(matches
        .iter()
        .any(|m| m.secret_type == SecretType::DigitalOceanToken));
}

#[test]
fn scan_detects_generic_api_key() {
    let text = r#"api_key = "abcdefghijklmnopqrstuvwxyz123456""#;
    let matches = scan_text_for_secrets(text);
    assert!(matches
        .iter()
        .any(|m| m.secret_type == SecretType::GenericApiKey));
}

#[test]
fn scan_no_false_positives_on_clean_text() {
    let text = "This is a normal paragraph without any secrets or keys.";
    let matches = scan_text_for_secrets(text);
    assert!(matches.is_empty());
}

#[test]
fn scan_match_has_correct_span() {
    let prefix = "prefix ";
    let key = "AKIAIOSFODNN7EXAMPLE";
    let text = format!("{}{} suffix", prefix, key);
    let matches = scan_text_for_secrets(&text);
    let aws = matches
        .iter()
        .find(|m| m.secret_type == SecretType::AwsAccessKey)
        .unwrap();
    assert_eq!(aws.start, prefix.len());
    assert_eq!(aws.end, prefix.len() + key.len());
}

#[test]
fn github_search_queries_contain_domain() {
    let queries = github_search_queries("example.com");
    assert!(queries.len() >= 10);
    for q in &queries {
        assert!(q.contains("example.com"));
    }
}

#[test]
fn github_search_queries_cover_key_terms() {
    let queries = github_search_queries("test.io");
    let joined = queries.join(" ");
    assert!(joined.contains("password"));
    assert!(joined.contains("secret"));
    assert!(joined.contains("api_key"));
    assert!(joined.contains("token"));
    assert!(joined.contains("PRIVATE KEY"));
}

#[test]
fn github_search_url_format() {
    let url = github_search_url("\"example.com\" password");
    assert!(url.starts_with("https://github.com/search?q="));
    assert!(url.contains("type=code"));
}

#[test]
fn gitlab_snippet_search_url_format() {
    let url = gitlab_snippet_search_url("example.com");
    assert!(url.starts_with("https://gitlab.com/search"));
    assert!(url.contains("example.com"));
    assert!(url.contains("scope=snippet_titles"));
}

#[test]
fn npm_search_url_format() {
    let url = npm_search_url("example.com");
    assert!(url.starts_with("https://www.npmjs.com/search"));
    assert!(url.contains("example.com"));
}

#[test]
fn dockerhub_search_url_format() {
    let url = dockerhub_search_url("myorg");
    assert!(url.starts_with("https://hub.docker.com"));
    assert!(url.contains("myorg"));
}

#[test]
fn postman_search_url_format() {
    let url = postman_search_url("example.com");
    assert!(url.starts_with("https://www.postman.com/search"));
    assert!(url.contains("example.com"));
}

#[test]
fn swagger_endpoints_non_empty() {
    assert!(SWAGGER_ENDPOINTS.len() >= 10);
    assert!(SWAGGER_ENDPOINTS.contains(&"/swagger-ui.html"));
    assert!(SWAGGER_ENDPOINTS.contains(&"/openapi.json"));
    assert!(SWAGGER_ENDPOINTS.contains(&"/api-docs"));
}

#[test]
fn check_swagger_content_finds_secrets() {
    let swagger_json = r#"{"securityDefinitions":{"api_key":{"type":"apiKey"}},"host":"api.example.com","token":"AKIAIOSFODNN7EXAMPLE"}"#;
    let matches = check_swagger_content(swagger_json);
    assert!(!matches.is_empty());
}

#[test]
fn docker_leak_patterns_non_empty() {
    assert!(DOCKER_LEAK_PATTERNS.len() >= 10);
    assert!(DOCKER_LEAK_PATTERNS.contains(&"ENV AWS_ACCESS_KEY_ID"));
    assert!(DOCKER_LEAK_PATTERNS.contains(&"COPY .env"));
    assert!(DOCKER_LEAK_PATTERNS.contains(&"COPY id_rsa"));
}

#[test]
fn check_docker_layer_history_detects_leaks() {
    let layers = vec![
        "RUN apt-get install -y curl",
        "ENV AWS_ACCESS_KEY_ID=AKIAEXAMPLE",
        "COPY . /app",
        "COPY .env /app/.env",
    ];
    let leaks = check_docker_layer_history(&layers);
    assert_eq!(leaks.len(), 2);
    assert!(leaks.iter().any(|l| l.contains("AWS_ACCESS_KEY_ID")));
    assert!(leaks.iter().any(|l| l.contains("COPY .env")));
}

#[test]
fn check_docker_layer_history_clean() {
    let layers = vec!["RUN npm install", "COPY dist /app", "CMD node app.js"];
    let leaks = check_docker_layer_history(&layers);
    assert!(leaks.is_empty());
}

#[test]
fn finding_from_match_populates_fields() {
    let text = "key=AKIAIOSFODNN7EXAMPLE";
    let matches = scan_text_for_secrets(text);
    let aws_match = matches
        .iter()
        .find(|m| m.secret_type == SecretType::AwsAccessKey)
        .unwrap();
    let finding = finding_from_match(
        ExposureSource::GitHubCodeSearch,
        aws_match,
        "https://github.com/org/repo/blob/main/config.py",
    );
    assert_eq!(finding.source, ExposureSource::GitHubCodeSearch);
    assert_eq!(finding.secret_type, SecretType::AwsAccessKey);
    assert_eq!(finding.severity, SecretSeverity::Critical);
    assert!(finding.location.contains("github.com"));
    assert!(finding.detail.contains("AWS Access Key"));
    assert!(finding.matched_text.is_some());
}

#[test]
fn scanner_new_default_all_sources() {
    let scanner = ApiSecretExposureScanner::new("example.com");
    assert_eq!(scanner.domain, "example.com");
    assert_eq!(scanner.sources.len(), 6);
}

#[test]
fn scanner_with_sources() {
    let scanner = ApiSecretExposureScanner::new("example.com")
        .with_sources(vec![ExposureSource::GitHubCodeSearch]);
    assert_eq!(scanner.sources.len(), 1);
}

#[test]
fn scanner_github_queries() {
    let scanner = ApiSecretExposureScanner::new("target.io");
    let queries = scanner.github_queries();
    assert!(queries.len() >= 10);
    for q in &queries {
        assert!(q.contains("target.io"));
    }
}

#[test]
fn scanner_search_urls_non_empty() {
    let scanner = ApiSecretExposureScanner::new("test.com");
    let urls = scanner.search_urls();
    assert!(!urls.is_empty());
    assert!(urls.len() > 20);
}

#[test]
fn scanner_search_urls_single_source() {
    let scanner = ApiSecretExposureScanner::new("test.com")
        .with_sources(vec![ExposureSource::GitLabSnippets]);
    let urls = scanner.search_urls();
    assert_eq!(urls.len(), 1);
    assert_eq!(urls[0].0, ExposureSource::GitLabSnippets);
}

#[test]
fn scanner_swagger_urls() {
    let scanner = ApiSecretExposureScanner::new("api.example.com");
    let urls = scanner.swagger_urls();
    assert_eq!(urls.len(), SWAGGER_ENDPOINTS.len());
    for url in &urls {
        assert!(url.starts_with("https://api.example.com/"));
    }
}

#[test]
fn gcp_service_account_detection() {
    let json = r#"{"type": "service_account", "project_id": "my-project"}"#;
    let matches = scan_text_for_secrets(json);
    assert!(matches
        .iter()
        .any(|m| m.secret_type == SecretType::GcpServiceAccountKey));
}

#[test]
fn slack_webhook_detection() {
    let text = "WEBHOOK=https://hooks.slack.com/services/T01234567/B01234567/abcdefghijklmnop";
    let matches = scan_text_for_secrets(text);
    assert!(matches
        .iter()
        .any(|m| m.secret_type == SecretType::SlackWebhook));
}

#[test]
fn generic_secret_detection() {
    let text = r#"password = "super_secret_password_123""#;
    let matches = scan_text_for_secrets(text);
    assert!(matches
        .iter()
        .any(|m| m.secret_type == SecretType::GenericSecret));
}

#[test]
fn oauth_client_secret_detection() {
    let text = r#"client_secret = "abcdefghijklmnopqrstuvwx""#;
    let matches = scan_text_for_secrets(text);
    assert!(matches
        .iter()
        .any(|m| m.secret_type == SecretType::OAuthClientSecret));
}

#[test]
fn scan_deduplicates_overlapping_matches() {
    let text = "AIzaSyC_abcdefghijklmnopqrstuvwxyz12345";
    let matches = scan_text_for_secrets(text);
    let firebase_count = matches
        .iter()
        .filter(|m| m.start == 0 && m.end == text.len())
        .count();
    assert_eq!(firebase_count, 1);
}
