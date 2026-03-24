use super::secret_scanner::*;

fn scanner() -> SecretScanner {
    SecretScanner::new()
}

// ── Pattern count ────────────────────────────────────────────

#[test]
fn has_at_least_30_patterns() {
    assert!(
        scanner().pattern_count() >= 30,
        "expected ≥30 patterns, got {}",
        scanner().pattern_count()
    );
}

// ── Shannon entropy ──────────────────────────────────────────

#[test]
fn entropy_empty_string_is_zero() {
    assert!((shannon_entropy("") - 0.0).abs() < f64::EPSILON);
}

#[test]
fn entropy_single_char_repeated_is_zero() {
    assert!((shannon_entropy("aaaaaaa") - 0.0).abs() < f64::EPSILON);
}

#[test]
fn entropy_high_for_random_hex() {
    let high_entropy = "a3f8b2c1d9e7045638bf1c2d4a9e0f73";
    assert!(shannon_entropy(high_entropy) > 3.5);
}

#[test]
fn entropy_very_high_for_uuid() {
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    assert!(shannon_entropy(uuid) > 3.0);
}

// ── AWS Access Key ───────────────────────────────────────────

#[test]
fn detects_aws_access_key_id() {
    let content = r#"config.aws_key = "AKIAIOSFODNN7REALKEY""#;
    let findings = scanner().scan(content);
    assert!(
        findings
            .iter()
            .any(|f| f.pattern_name == "AWS Access Key ID"),
        "should detect AWS key: {findings:?}"
    );
}

#[test]
fn does_not_flag_aws_example_key() {
    let content = r#"config.aws_key = "AKIAIOSFODNN7EXAMPLE""#;
    let findings = scanner().scan(content);
    assert!(
        !findings
            .iter()
            .any(|f| f.pattern_name == "AWS Access Key ID"),
        "should filter AWS example key"
    );
}

// ── AWS Secret Access Key ────────────────────────────────────

#[test]
fn detects_aws_secret_access_key() {
    let content = r#"aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY1234567890""#;
    let findings = scanner().scan(content);
    assert!(
        findings
            .iter()
            .any(|f| f.pattern_name == "AWS Secret Access Key"),
        "should detect AWS secret: {findings:?}"
    );
}

#[test]
fn does_not_flag_aws_example_secret() {
    let content = r#"aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY""#;
    let findings = scanner().scan(content);
    assert!(
        !findings
            .iter()
            .any(|f| f.pattern_name == "AWS Secret Access Key"),
        "should filter AWS example secret"
    );
}

// ── GCP API Key ──────────────────────────────────────────────

#[test]
fn detects_gcp_api_key() {
    let content = r#"const apiKey = "AIzaSyA1bcDeFgHiJkLmNopQrStUvWxYz0123456";"#;
    let findings = scanner().scan(content);
    assert!(
        findings.iter().any(|f| f.pattern_name == "GCP API Key"),
        "should detect GCP key: {findings:?}"
    );
}

// ── GCP Service Account ─────────────────────────────────────

#[test]
fn detects_gcp_service_account_json() {
    let content = r#"{"type": "service_account", "project_id": "my-project"}"#;
    let findings = scanner().scan(content);
    assert!(
        findings
            .iter()
            .any(|f| f.pattern_name == "GCP Service Account JSON"),
        "should detect GCP SA: {findings:?}"
    );
}

// ── Stripe ───────────────────────────────────────────────────

#[test]
fn detects_stripe_secret_key() {
    let content = "const key = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc123456';";
    let findings = scanner().scan(content);
    assert!(
        findings
            .iter()
            .any(|f| f.pattern_name == "Stripe Secret Key"),
        "should detect Stripe sk_live: {findings:?}"
    );
}

#[test]
fn detects_stripe_publishable_key() {
    let content = "const pk = 'pk_live_4eC39HqLyjWDarjtT1zdp7dc123456';";
    let findings = scanner().scan(content);
    assert!(
        findings
            .iter()
            .any(|f| f.pattern_name == "Stripe Publishable Key"),
        "should detect Stripe pk_live: {findings:?}"
    );
}

// ── SendGrid ─────────────────────────────────────────────────

#[test]
fn detects_sendgrid_api_key() {
    let content =
        "SENDGRID_KEY=SG.abcdefghij12345678901w.abcdefghij1234567890abcdefghij1234567890abc";
    let findings = scanner().scan(content);
    assert!(
        findings
            .iter()
            .any(|f| f.pattern_name == "SendGrid API Key"),
        "should detect SendGrid: {findings:?}"
    );
}

// ── Slack ────────────────────────────────────────────────────

#[test]
fn detects_slack_token() {
    let content = "token: xoxb-1234567890123-abcdefGHIJKLmnop123456";
    let findings = scanner().scan(content);
    assert!(
        findings.iter().any(|f| f.pattern_name == "Slack Token"),
        "should detect Slack token: {findings:?}"
    );
}

#[test]
fn detects_slack_webhook() {
    let content = "https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx";
    let findings = scanner().scan(content);
    assert!(
        findings
            .iter()
            .any(|f| f.pattern_name == "Slack Webhook URL"),
        "should detect Slack webhook: {findings:?}"
    );
}

// ── GitHub ───────────────────────────────────────────────────

#[test]
fn detects_github_pat() {
    let content = "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";
    let findings = scanner().scan(content);
    assert!(
        findings
            .iter()
            .any(|f| f.pattern_name == "GitHub Personal Access Token"),
        "should detect GitHub PAT: {findings:?}"
    );
}

#[test]
fn detects_github_oauth_token() {
    let content = "auth = gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";
    let findings = scanner().scan(content);
    assert!(
        findings
            .iter()
            .any(|f| f.pattern_name == "GitHub OAuth Token"),
        "should detect GitHub OAuth: {findings:?}"
    );
}

// ── JWT ──────────────────────────────────────────────────────

#[test]
fn detects_jwt_token() {
    let content = r#"{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}"#;
    let findings = scanner().scan(content);
    assert!(
        findings.iter().any(|f| f.pattern_name == "JWT Token"),
        "should detect JWT: {findings:?}"
    );
}

// ── Database Connection Strings ──────────────────────────────

#[test]
fn detects_postgres_connection_string() {
    let content = r#"DATABASE_URL=postgres://admin:s3cr3tP4ss@db.internal:5432/mydb"#;
    let findings = scanner().scan(content);
    assert!(
        findings
            .iter()
            .any(|f| f.pattern_name == "PostgreSQL Connection String"),
        "should detect postgres: {findings:?}"
    );
}

#[test]
fn detects_mongodb_connection_string() {
    let content = "MONGO_URI=mongodb+srv://user:pass123word@cluster0.abc12.mongodb.net/mydb";
    let findings = scanner().scan(content);
    assert!(
        findings
            .iter()
            .any(|f| f.pattern_name == "MongoDB Connection String"),
        "should detect mongodb: {findings:?}"
    );
}

#[test]
fn detects_mysql_connection_string() {
    let content = "MYSQL_DSN=mysql://root:password@localhost:3306/mydb";
    let findings = scanner().scan(content);
    assert!(
        findings
            .iter()
            .any(|f| f.pattern_name == "MySQL Connection String"),
        "should detect mysql: {findings:?}"
    );
}

#[test]
fn detects_redis_connection_string() {
    let content = "REDIS_URL=redis://default:redisPass@redis.cloud:6379/0";
    let findings = scanner().scan(content);
    assert!(
        findings
            .iter()
            .any(|f| f.pattern_name == "Redis Connection String"),
        "should detect redis: {findings:?}"
    );
}

// ── Private Keys ─────────────────────────────────────────────

#[test]
fn detects_rsa_private_key() {
    let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRi...";
    let findings = scanner().scan(content);
    assert!(
        findings.iter().any(|f| f.pattern_name == "RSA Private Key"),
        "should detect RSA key: {findings:?}"
    );
}

#[test]
fn detects_ec_private_key() {
    let content = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...";
    let findings = scanner().scan(content);
    assert!(
        findings.iter().any(|f| f.pattern_name == "EC Private Key"),
        "should detect EC key: {findings:?}"
    );
}

#[test]
fn detects_pgp_private_key() {
    let content = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG";
    let findings = scanner().scan(content);
    assert!(
        findings.iter().any(|f| f.pattern_name == "PGP Private Key"),
        "should detect PGP key: {findings:?}"
    );
}

// ── Internal URLs ────────────────────────────────────────────

#[test]
fn detects_internal_url() {
    let content = r#"<script src="http://api.corp/v1/config.js"></script>"#;
    let findings = scanner().scan(content);
    assert!(
        findings
            .iter()
            .any(|f| f.pattern_name == "Internal URL Leak"),
        "should detect .corp URL: {findings:?}"
    );
}

#[test]
fn detects_internal_ip_reference() {
    let content = r#"proxy_pass http://10.0.1.54:8080/api/v2;"#;
    let findings = scanner().scan(content);
    assert!(
        findings
            .iter()
            .any(|f| f.pattern_name == "Internal IP Reference"),
        "should detect RFC1918 IP: {findings:?}"
    );
}

// ── Debug/Admin Endpoints ────────────────────────────────────

#[test]
fn detects_admin_endpoint() {
    let content = r#"<a href="/admin/dashboard">Admin Panel</a>"#;
    let findings = scanner().scan(content);
    assert!(
        findings
            .iter()
            .any(|f| f.pattern_name == "Admin Endpoint Exposed"),
        "should detect /admin: {findings:?}"
    );
}

#[test]
fn detects_debug_endpoint() {
    let content = r#"<a href="/phpinfo.php">Server Info</a>"#;
    let findings = scanner().scan(content);
    assert!(
        findings
            .iter()
            .any(|f| f.pattern_name == "Debug Endpoint Exposed"),
        "should detect /phpinfo: {findings:?}"
    );
}

// ── Password Patterns ────────────────────────────────────────

#[test]
fn detects_password_in_url() {
    let content = "https://app.example.net/login?username=admin&password=SuperSecr3t!";
    let findings = scanner().scan(content);
    assert!(
        findings.iter().any(|f| f.pattern_name == "Password in URL"),
        "should detect password param: {findings:?}"
    );
}

#[test]
fn detects_hardcoded_password_in_js() {
    let content = r#"const config = { password: "xK9#mP2$vL5nQ8wR" };"#;
    let findings = scanner().scan(content);
    assert!(
        findings
            .iter()
            .any(|f| f.pattern_name == "Hardcoded Password"),
        "should detect hardcoded pw: {findings:?}"
    );
}

// ── False-Positive Filtering ─────────────────────────────────

#[test]
fn filters_placeholder_values() {
    let content = r#"secret: "your_api_key_here""#;
    let findings = scanner().scan(content);
    assert!(
        findings.is_empty(),
        "should filter placeholder: {findings:?}"
    );
}

#[test]
fn filters_test_key_values() {
    let content = r#"api_key = "test_key_not_real""#;
    let findings = scanner().scan(content);
    assert!(findings.is_empty(), "should filter test_key: {findings:?}");
}

#[test]
fn filters_dummy_tokens() {
    let content = r#"token: "dummy_token_for_tests""#;
    let findings = scanner().scan(content);
    assert!(findings.is_empty(), "should filter dummy: {findings:?}");
}

// ── Twilio ───────────────────────────────────────────────────

#[test]
fn detects_twilio_api_key() {
    let content = "TWILIO_KEY=SK0123456789abcdef0123456789abcdef";
    let findings = scanner().scan(content);
    assert!(
        findings.iter().any(|f| f.pattern_name == "Twilio API Key"),
        "should detect Twilio key: {findings:?}"
    );
}

// ── Line Number Accuracy ─────────────────────────────────────

#[test]
fn reports_correct_line_number() {
    let content = "nothing here\nstill nothing\nsk_live_4eC39HqLyjWDarjtT1zdp7dc123456\nend";
    let findings = scanner().scan(content);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].line_number, 3);
}

// ── Confidence Scoring ───────────────────────────────────────

#[test]
fn critical_finding_has_high_confidence() {
    let content = "-----BEGIN RSA PRIVATE KEY-----";
    let findings = scanner().scan(content);
    assert!(!findings.is_empty());
    assert!(findings[0].confidence >= 0.9);
}

// ── Multi-Finding in Single Response ─────────────────────────

#[test]
fn finds_multiple_secrets_in_single_response() {
    let content = r#"
<!-- debug config dump -->
AWS_KEY=AKIAIOSFODNN7REALKEY
DATABASE_URL=postgres://admin:hunter2@db.internal:5432/prod
-----BEGIN RSA PRIVATE KEY-----
MIIBogIBAAJBALRi...
-----END RSA PRIVATE KEY-----
"#;
    let findings = scanner().scan(content);
    let names: Vec<&str> = findings.iter().map(|f| f.pattern_name.as_str()).collect();
    assert!(
        names.contains(&"AWS Access Key ID"),
        "missing AWS key in multi: {names:?}"
    );
    assert!(
        names.contains(&"PostgreSQL Connection String"),
        "missing postgres in multi: {names:?}"
    );
    assert!(
        names.contains(&"RSA Private Key"),
        "missing RSA in multi: {names:?}"
    );
}

// ── Azure ────────────────────────────────────────────────────

#[test]
fn detects_azure_subscription_key() {
    let content = r#"subscription_key = "0123456789abcdef0123456789abcdef""#;
    let findings = scanner().scan(content);
    assert!(
        findings
            .iter()
            .any(|f| f.pattern_name == "Azure Subscription Key"),
        "should detect Azure sub key: {findings:?}"
    );
}

// ── Mailgun ──────────────────────────────────────────────────

#[test]
fn detects_mailgun_api_key() {
    let content = "MAILGUN_KEY=key-0123456789abcdef0123456789abcdef";
    let findings = scanner().scan(content);
    assert!(
        findings.iter().any(|f| f.pattern_name == "Mailgun API Key"),
        "should detect Mailgun key: {findings:?}"
    );
}
