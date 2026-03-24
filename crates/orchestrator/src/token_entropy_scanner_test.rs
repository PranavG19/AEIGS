use crate::token_entropy_scanner::*;

#[test]
fn shannon_entropy_empty_string() {
    assert_eq!(shannon_entropy(""), 0.0);
}

#[test]
fn shannon_entropy_single_char() {
    assert_eq!(shannon_entropy("aaaa"), 0.0);
}

#[test]
fn shannon_entropy_two_equal_chars() {
    let e = shannon_entropy("ab");
    assert!((e - 1.0).abs() < 0.001);
}

#[test]
fn shannon_entropy_high_entropy_string() {
    let e = shannon_entropy("a8Kz3pQ!xW9mRt");
    assert!(e > 3.0);
}

#[test]
fn shannon_entropy_low_entropy_string() {
    let e = shannon_entropy("aaaaabbb");
    assert!(e < 1.5);
}

#[test]
fn extract_tokens_finds_token_eq() {
    let body = "some text token=abc123def456 more text";
    let tokens = extract_tokens(body);
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].0, "token");
    assert_eq!(tokens[0].1, "abc123def456");
}

#[test]
fn extract_tokens_finds_session_id() {
    let body = r#"session_id="mySessionValue""#;
    let tokens = extract_tokens(body);
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].0, "session_id");
    assert_eq!(tokens[0].1, "mySessionValue");
}

#[test]
fn extract_tokens_finds_multiple() {
    let body = "token=abc123 api_key=xyz789 secret=s3cret";
    let tokens = extract_tokens(body);
    assert_eq!(tokens.len(), 3);
}

#[test]
fn extract_tokens_empty_body() {
    let tokens = extract_tokens("");
    assert!(tokens.is_empty());
}

#[test]
fn detects_weak_session_token() {
    let body = "token=short123";
    let issues = analyze_token_entropy(body);
    assert!(issues.contains(&TokenEntropyIssue::WeakSessionToken));
}

#[test]
fn no_weak_session_token_for_long_value() {
    let body = "token=a8Kz3pQ1xW9mRt0BcDeFg";
    let issues = analyze_token_entropy(body);
    assert!(!issues.contains(&TokenEntropyIssue::WeakSessionToken));
}

#[test]
fn detects_numeric_only_token() {
    let body = "token=99887766554433221100";
    let issues = analyze_token_entropy(body);
    assert!(issues.contains(&TokenEntropyIssue::NumericOnlyToken));
}

#[test]
fn no_numeric_only_for_alphanumeric() {
    let body = "token=abc123def456ghi789jkl";
    let issues = analyze_token_entropy(body);
    assert!(!issues.contains(&TokenEntropyIssue::NumericOnlyToken));
}

#[test]
fn detects_sequential_token() {
    let body = "token=abcdefghijklmnop";
    let issues = analyze_token_entropy(body);
    assert!(issues.contains(&TokenEntropyIssue::SequentialToken));
}

#[test]
fn detects_timestamp_based_token() {
    let body = "token=1700000000";
    let issues = analyze_token_entropy(body);
    assert!(issues.contains(&TokenEntropyIssue::TimestampBasedToken));
}

#[test]
fn detects_timestamp_millis() {
    let body = "token=1700000000000";
    let issues = analyze_token_entropy(body);
    assert!(issues.contains(&TokenEntropyIssue::TimestampBasedToken));
}

#[test]
fn no_timestamp_for_non_epoch() {
    let body = "token=abc123def456ghi789jkl";
    let issues = analyze_token_entropy(body);
    assert!(!issues.contains(&TokenEntropyIssue::TimestampBasedToken));
}

#[test]
fn detects_base64_weak_secret() {
    let body = "secret=QUFBQUFBQUFBQQ==";
    let issues = analyze_token_entropy(body);
    assert!(issues.contains(&TokenEntropyIssue::Base64WeakSecret));
}

#[test]
fn detects_hardcoded_token() {
    let body = r#"<script>const token = "abc123";</script>"#;
    let issues = analyze_token_entropy(body);
    assert!(issues.contains(&TokenEntropyIssue::HardcodedToken));
}

#[test]
fn detects_hardcoded_var_token() {
    let body = r#"<script>var token = "secretvalue";</script>"#;
    let issues = analyze_token_entropy(body);
    assert!(issues.contains(&TokenEntropyIssue::HardcodedToken));
}

#[test]
fn detects_hardcoded_let_api_key() {
    let body = r#"<script>let api_key = "key_12345";</script>"#;
    let issues = analyze_token_entropy(body);
    assert!(issues.contains(&TokenEntropyIssue::HardcodedToken));
}

#[test]
fn no_hardcoded_for_unrelated_js() {
    let body = r#"<script>const width = 100;</script>"#;
    let issues = analyze_token_entropy(body);
    assert!(!issues.contains(&TokenEntropyIssue::HardcodedToken));
}

#[test]
fn detects_short_api_key() {
    let body = "api_key=shortkey123";
    let issues = analyze_token_entropy(body);
    assert!(issues.contains(&TokenEntropyIssue::ShortApiKey));
}

#[test]
fn no_short_api_key_for_long_value() {
    let body = "api_key=a8Kz3pQ1xW9mRt0BcDeFgHiJk";
    let issues = analyze_token_entropy(body);
    assert!(!issues.contains(&TokenEntropyIssue::ShortApiKey));
}

#[test]
fn detects_predictable_csrf_token() {
    let body = "csrf_token=12345";
    let issues = analyze_token_entropy(body);
    assert!(issues.contains(&TokenEntropyIssue::PredictableCsrfToken));
}

#[test]
fn empty_body_no_entropy_issues() {
    let issues = analyze_token_entropy("");
    assert!(issues.is_empty());
}

#[test]
fn severity_hardcoded_token_highest() {
    assert_eq!(
        token_entropy_severity(&TokenEntropyIssue::HardcodedToken),
        8.0
    );
}

#[test]
fn severity_base64_weak_secret_lowest() {
    assert_eq!(
        token_entropy_severity(&TokenEntropyIssue::Base64WeakSecret),
        5.5
    );
}

#[test]
fn severity_weak_session_token() {
    assert_eq!(
        token_entropy_severity(&TokenEntropyIssue::WeakSessionToken),
        7.5
    );
}

#[test]
fn severity_predictable_csrf_token() {
    assert_eq!(
        token_entropy_severity(&TokenEntropyIssue::PredictableCsrfToken),
        7.0
    );
}

#[test]
fn severity_numeric_only_token() {
    assert_eq!(
        token_entropy_severity(&TokenEntropyIssue::NumericOnlyToken),
        7.0
    );
}

#[test]
fn severity_sequential_token() {
    assert_eq!(
        token_entropy_severity(&TokenEntropyIssue::SequentialToken),
        6.5
    );
}

#[test]
fn severity_short_api_key() {
    assert_eq!(token_entropy_severity(&TokenEntropyIssue::ShortApiKey), 6.5);
}

#[test]
fn severity_timestamp_based_token() {
    assert_eq!(
        token_entropy_severity(&TokenEntropyIssue::TimestampBasedToken),
        6.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        TokenEntropyIssue::WeakSessionToken,
        TokenEntropyIssue::HardcodedToken,
    ];
    let mut seq = 0;
    let ops = token_entropy_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn to_operations_empty_vec() {
    let issues: Vec<TokenEntropyIssue> = vec![];
    let mut seq = 0;
    let ops = token_entropy_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn display_variants() {
    assert_eq!(
        TokenEntropyIssue::WeakSessionToken.to_string(),
        "weak_session_token"
    );
    assert_eq!(
        TokenEntropyIssue::PredictableCsrfToken.to_string(),
        "predictable_csrf_token"
    );
    assert_eq!(TokenEntropyIssue::ShortApiKey.to_string(), "short_api_key");
    assert_eq!(
        TokenEntropyIssue::NumericOnlyToken.to_string(),
        "numeric_only_token"
    );
    assert_eq!(
        TokenEntropyIssue::SequentialToken.to_string(),
        "sequential_token"
    );
    assert_eq!(
        TokenEntropyIssue::TimestampBasedToken.to_string(),
        "timestamp_based_token"
    );
    assert_eq!(
        TokenEntropyIssue::Base64WeakSecret.to_string(),
        "base64_weak_secret"
    );
    assert_eq!(
        TokenEntropyIssue::HardcodedToken.to_string(),
        "hardcoded_token"
    );
}

#[test]
fn security_detects_token_exfiltration() {
    let body = r#"
        <script>
        const token = getToken();
        fetch('/collect', { method: 'POST', body: token });
        </script>
    "#;
    let issues = analyze_token_security(body);
    assert!(issues.contains(&TokenSecurityIssue::TokenExfiltration));
}

#[test]
fn security_detects_token_exfiltration_xmlhttprequest() {
    let body = r#"
        <script>
        var token = getCsrf();
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/exfil');
        xhr.send(token);
        </script>
    "#;
    let issues = analyze_token_security(body);
    assert!(issues.contains(&TokenSecurityIssue::TokenExfiltration));
}

#[test]
fn security_detects_token_in_url() {
    let body = r#"<a href="/page?token=abc123">Link</a>"#;
    let issues = analyze_token_security(body);
    assert!(issues.contains(&TokenSecurityIssue::TokenInUrl));
}

#[test]
fn security_detects_token_no_expiry() {
    let body = r#"<script>const token = "abc";</script>"#;
    let issues = analyze_token_security(body);
    assert!(issues.contains(&TokenSecurityIssue::TokenNoExpiry));
}

#[test]
fn security_no_expiry_absent_when_expires_present() {
    let body = r#"<script>const token = "abc"; expires=3600;</script>"#;
    let issues = analyze_token_security(body);
    assert!(!issues.contains(&TokenSecurityIssue::TokenNoExpiry));
}

#[test]
fn security_detects_cross_origin_leak() {
    let body = r#"
        <script>
        const token = getToken();
        parent.postMessage({ token: token }, '*');
        </script>
    "#;
    let issues = analyze_token_security(body);
    assert!(issues.contains(&TokenSecurityIssue::TokenCrossOriginLeak));
}

#[test]
fn security_detects_weak_token_generation() {
    let body = r#"
        <script>
        const token = Math.random().toString(36).substring(2);
        </script>
    "#;
    let issues = analyze_token_security(body);
    assert!(issues.contains(&TokenSecurityIssue::WeakTokenGeneration));
}

#[test]
fn security_detects_token_in_local_storage() {
    let body = r#"
        <script>
        localStorage.setItem('token', sessionToken);
        </script>
    "#;
    let issues = analyze_token_security(body);
    assert!(issues.contains(&TokenSecurityIssue::TokenInLocalStorage));
}

#[test]
fn security_detects_token_in_comment() {
    let body = r#"
        <html>
        <!-- token=abc123secret -->
        <body>Hello</body>
        </html>
    "#;
    let issues = analyze_token_security(body);
    assert!(issues.contains(&TokenSecurityIssue::TokenInComment));
}

#[test]
fn security_no_token_in_comment_without_keyword() {
    let body = r#"
        <html>
        <!-- this is a normal comment -->
        <body>token here</body>
        </html>
    "#;
    let issues = analyze_token_security(body);
    assert!(!issues.contains(&TokenSecurityIssue::TokenInComment));
}

#[test]
fn security_detects_jwt_alg_none() {
    let body = r#"{"alg":"none","typ":"JWT"}"#;
    let issues = analyze_token_security(body);
    assert!(issues.contains(&TokenSecurityIssue::JwtWeakAlgorithm));
}

#[test]
fn security_detects_jwt_alg_hs256() {
    let body = r#"{"alg":"HS256","typ":"JWT"} token"#;
    let issues = analyze_token_security(body);
    assert!(issues.contains(&TokenSecurityIssue::JwtWeakAlgorithm));
}

#[test]
fn security_detects_token_padding_oracle() {
    let body = "token=AAAAAAAAAAAAAAAA";
    let issues = analyze_token_security(body);
    assert!(issues.contains(&TokenSecurityIssue::TokenPaddingOracle));
}

#[test]
fn security_empty_body() {
    let issues = analyze_token_security("");
    assert!(issues.is_empty());
}

#[test]
fn security_no_token_keyword() {
    let body = "<html><head><title>Hello World</title></head></html>";
    let issues = analyze_token_security(body);
    assert!(issues.is_empty());
}

#[test]
fn security_severity_token_exfiltration() {
    assert_eq!(
        token_security_severity(&TokenSecurityIssue::TokenExfiltration),
        8.5
    );
}

#[test]
fn security_severity_jwt_weak_algorithm() {
    assert_eq!(
        token_security_severity(&TokenSecurityIssue::JwtWeakAlgorithm),
        8.0
    );
}

#[test]
fn security_severity_weak_token_generation() {
    assert_eq!(
        token_security_severity(&TokenSecurityIssue::WeakTokenGeneration),
        8.0
    );
}

#[test]
fn security_severity_token_in_url() {
    assert_eq!(
        token_security_severity(&TokenSecurityIssue::TokenInUrl),
        7.5
    );
}

#[test]
fn security_severity_token_cross_origin_leak() {
    assert_eq!(
        token_security_severity(&TokenSecurityIssue::TokenCrossOriginLeak),
        7.0
    );
}

#[test]
fn security_severity_token_replay_vulnerable() {
    assert_eq!(
        token_security_severity(&TokenSecurityIssue::TokenReplayVulnerable),
        7.0
    );
}

#[test]
fn security_severity_token_in_local_storage() {
    assert_eq!(
        token_security_severity(&TokenSecurityIssue::TokenInLocalStorage),
        6.5
    );
}

#[test]
fn security_severity_token_in_comment() {
    assert_eq!(
        token_security_severity(&TokenSecurityIssue::TokenInComment),
        6.5
    );
}

#[test]
fn security_severity_token_no_expiry() {
    assert_eq!(
        token_security_severity(&TokenSecurityIssue::TokenNoExpiry),
        6.0
    );
}

#[test]
fn security_severity_token_padding_oracle() {
    assert_eq!(
        token_security_severity(&TokenSecurityIssue::TokenPaddingOracle),
        5.5
    );
}

#[test]
fn security_operations_creates_entries() {
    let issues = vec![
        TokenSecurityIssue::TokenExfiltration,
        TokenSecurityIssue::JwtWeakAlgorithm,
    ];
    let mut seq = 0;
    let ops = token_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_operations_empty_vec() {
    let issues: Vec<TokenSecurityIssue> = vec![];
    let mut seq = 0;
    let ops = token_security_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn security_display_variants() {
    assert_eq!(
        TokenSecurityIssue::TokenExfiltration.to_string(),
        "token_exfiltration"
    );
    assert_eq!(TokenSecurityIssue::TokenInUrl.to_string(), "token_in_url");
    assert_eq!(
        TokenSecurityIssue::TokenNoExpiry.to_string(),
        "token_no_expiry"
    );
    assert_eq!(
        TokenSecurityIssue::TokenCrossOriginLeak.to_string(),
        "token_cross_origin_leak"
    );
    assert_eq!(
        TokenSecurityIssue::TokenReplayVulnerable.to_string(),
        "token_replay_vulnerable"
    );
    assert_eq!(
        TokenSecurityIssue::WeakTokenGeneration.to_string(),
        "weak_token_generation"
    );
    assert_eq!(
        TokenSecurityIssue::TokenInLocalStorage.to_string(),
        "token_in_local_storage"
    );
    assert_eq!(
        TokenSecurityIssue::TokenInComment.to_string(),
        "token_in_comment"
    );
    assert_eq!(
        TokenSecurityIssue::JwtWeakAlgorithm.to_string(),
        "jwt_weak_algorithm"
    );
    assert_eq!(
        TokenSecurityIssue::TokenPaddingOracle.to_string(),
        "token_padding_oracle"
    );
}

#[test]
fn security_combined_multiple_issues() {
    let body = r#"
        <script>
        const token = Math.random().toString(36);
        fetch('/exfil', { method: 'POST', body: token });
        localStorage.setItem('token', token);
        parent.postMessage({ token }, '*');
        </script>
    "#;
    let issues = analyze_token_security(body);
    assert!(issues.contains(&TokenSecurityIssue::TokenExfiltration));
    assert!(issues.contains(&TokenSecurityIssue::WeakTokenGeneration));
    assert!(issues.contains(&TokenSecurityIssue::TokenInLocalStorage));
    assert!(issues.contains(&TokenSecurityIssue::TokenCrossOriginLeak));
}
