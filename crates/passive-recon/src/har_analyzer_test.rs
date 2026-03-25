use super::har_analyzer::*;

fn minimal_har(entries_json: &str) -> String {
    format!(r#"{{"log":{{"entries":[{}]}}}}"#, entries_json)
}

fn make_entry(
    method: &str,
    url: &str,
    req_headers: &str,
    resp_headers: &str,
    resp_body: &str,
) -> String {
    format!(
        r#"{{
            "request": {{
                "method": "{}",
                "url": "{}",
                "headers": [{}],
                "cookies": [],
                "queryString": []
            }},
            "response": {{
                "status": 200,
                "headers": [{}],
                "content": {{
                    "size": {},
                    "mimeType": "text/html",
                    "text": {}
                }},
                "cookies": []
            }}
        }}"#,
        method,
        url,
        req_headers,
        resp_headers,
        resp_body.len(),
        serde_json::to_string(resp_body).unwrap()
    )
}

fn header_json(name: &str, value: &str) -> String {
    format!(r#"{{"name":"{}","value":"{}"}}"#, name, value)
}

#[test]
fn test_parse_valid_har() {
    let json = minimal_har(&make_entry(
        "GET",
        "https://example.com/",
        "",
        "",
        "<html></html>",
    ));
    let har = HarAnalyzer::parse(&json);
    assert!(har.is_ok());
    assert_eq!(har.unwrap().log.entries.len(), 1);
}

#[test]
fn test_parse_invalid_har() {
    assert!(HarAnalyzer::parse("invalid json").is_err());
    assert!(HarAnalyzer::parse("{}").is_err());
}

#[test]
fn test_insecure_http_detection() {
    let entry = make_entry("GET", "http://example.com/login", "", "", "");
    let json = minimal_har(&entry);
    let har = HarAnalyzer::parse(&json).unwrap();
    let analyzer = HarAnalyzer::new();
    let result = analyzer.analyze(&har);
    assert!(
        result
            .findings
            .iter()
            .any(|f| matches!(f.category, HarFindingCategory::InsecureTransmission))
    );
}

#[test]
fn test_auth_token_detection() {
    let headers = header_json("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.test.sig");
    let entry = make_entry("GET", "https://api.example.com/users", &headers, "", "");
    let json = minimal_har(&entry);
    let har = HarAnalyzer::parse(&json).unwrap();
    let analyzer = HarAnalyzer::new();
    let result = analyzer.analyze(&har);
    let auth_finding = result
        .findings
        .iter()
        .find(|f| matches!(f.category, HarFindingCategory::AuthTokenExposed));
    assert!(auth_finding.is_some());
    assert_eq!(auth_finding.unwrap().severity, HarFindingSeverity::Critical);
}

#[test]
fn test_sensitive_query_param_detection() {
    let json = r#"{"log":{"entries":[{
        "request": {
            "method": "GET",
            "url": "https://example.com/login",
            "headers": [],
            "cookies": [],
            "queryString": [{"name":"password","value":"s3cret123"}]
        },
        "response": {
            "status": 200,
            "headers": [],
            "content": null,
            "cookies": []
        }
    }]}}"#;
    let har = HarAnalyzer::parse(json).unwrap();
    let analyzer = HarAnalyzer::new();
    let result = analyzer.analyze(&har);
    assert!(
        result
            .findings
            .iter()
            .any(|f| matches!(f.category, HarFindingCategory::SensitiveDataInRequest))
    );
}

#[test]
fn test_request_body_secret_detection() {
    let json = r#"{"log":{"entries":[{
        "request": {
            "method": "POST",
            "url": "https://example.com/api/login",
            "headers": [],
            "cookies": [],
            "queryString": [],
            "postData": {
                "mimeType": "application/json",
                "text": "{\"username\":\"admin\",\"password\":\"s3cret123\"}"
            }
        },
        "response": {
            "status": 200,
            "headers": [],
            "content": null,
            "cookies": []
        }
    }]}}"#;
    let har = HarAnalyzer::parse(json).unwrap();
    let analyzer = HarAnalyzer::new();
    let result = analyzer.analyze(&har);
    assert!(result.findings.iter().any(|f| matches!(
        f.category,
        HarFindingCategory::SensitiveDataInRequest
    ) && f.description.contains("Password")));
}

#[test]
fn test_response_body_secret_detection() {
    let entry = make_entry(
        "GET",
        "https://example.com/api/config",
        "",
        "",
        r#"{"aws_key": "AKIAIOSFODNN7EXAMPLE"}"#,
    );
    let json = minimal_har(&entry);
    let har = HarAnalyzer::parse(&json).unwrap();
    let analyzer = HarAnalyzer::new();
    let result = analyzer.analyze(&har);
    assert!(
        result
            .findings
            .iter()
            .any(|f| matches!(f.category, HarFindingCategory::SensitiveDataInResponse))
    );
}

#[test]
fn test_missing_security_headers() {
    let entry = make_entry("GET", "https://example.com/", "", "", "<html>Hello</html>");
    let json = minimal_har(&entry);
    let har = HarAnalyzer::parse(&json).unwrap();
    let analyzer = HarAnalyzer::new();
    let result = analyzer.analyze(&har);
    let missing: Vec<_> = result
        .findings
        .iter()
        .filter(|f| matches!(f.category, HarFindingCategory::MissingSecurityHeader))
        .collect();
    assert!(missing.len() >= 3);
}

#[test]
fn test_cookie_security_missing_secure() {
    let json = r#"{"log":{"entries":[{
        "request": {
            "method": "GET",
            "url": "https://example.com/",
            "headers": [],
            "cookies": [],
            "queryString": []
        },
        "response": {
            "status": 200,
            "headers": [],
            "content": null,
            "cookies": [{"name":"session_token","value":"abc123","secure":false,"httpOnly":true}]
        }
    }]}}"#;
    let har = HarAnalyzer::parse(json).unwrap();
    let analyzer = HarAnalyzer::new();
    let result = analyzer.analyze(&har);
    assert!(result.findings.iter().any(|f| {
        matches!(f.category, HarFindingCategory::CookieSecurity) && f.description.contains("Secure")
    }));
}

#[test]
fn test_cookie_security_missing_httponly() {
    let json = r#"{"log":{"entries":[{
        "request": {
            "method": "GET",
            "url": "https://example.com/",
            "headers": [],
            "cookies": [],
            "queryString": []
        },
        "response": {
            "status": 200,
            "headers": [],
            "content": null,
            "cookies": [{"name":"auth_token","value":"xyz","secure":true,"httpOnly":false}]
        }
    }]}}"#;
    let har = HarAnalyzer::parse(json).unwrap();
    let analyzer = HarAnalyzer::new();
    let result = analyzer.analyze(&har);
    assert!(result.findings.iter().any(|f| {
        matches!(f.category, HarFindingCategory::CookieSecurity)
            && f.description.contains("HttpOnly")
    }));
}

#[test]
fn test_information_leak_server_header() {
    let resp_headers = header_json("Server", "Apache/2.4.54");
    let entry = make_entry("GET", "https://example.com/", "", &resp_headers, "");
    let json = minimal_har(&entry);
    let har = HarAnalyzer::parse(&json).unwrap();
    let analyzer = HarAnalyzer::new();
    let result = analyzer.analyze(&har);
    assert!(
        result
            .findings
            .iter()
            .any(|f| matches!(f.category, HarFindingCategory::InformationLeak))
    );
}

#[test]
fn test_api_pattern_extraction() {
    let headers = header_json("Authorization", "Bearer token123");
    let entry = make_entry(
        "GET",
        "https://api.example.com/api/v2/users/42",
        &headers,
        "",
        r#"{"users":[]}"#,
    );
    let json = minimal_har(&entry);
    let har = HarAnalyzer::parse(&json).unwrap();
    let analyzer = HarAnalyzer::new();
    let result = analyzer.analyze(&har);
    assert!(!result.api_patterns.is_empty());
    let pattern = &result.api_patterns[0];
    assert!(pattern.path_pattern.contains(":id"));
    assert!(pattern.requires_auth);
}

#[test]
fn test_third_party_tracking() {
    let entry1 = make_entry(
        "GET",
        "https://www.google-analytics.com/collect",
        "",
        "",
        "",
    );
    let entry2 = make_entry("GET", "https://js.stripe.com/v3/", "", "", "");
    let json = minimal_har(&format!("{},{}", entry1, entry2));
    let har = HarAnalyzer::parse(&json).unwrap();
    let analyzer = HarAnalyzer::new();
    let result = analyzer.analyze(&har);
    assert!(
        result
            .third_party_integrations
            .iter()
            .any(|t| t.service_name == "Google Analytics")
    );
    assert!(
        result
            .third_party_integrations
            .iter()
            .any(|t| t.service_name == "Stripe")
    );
}

#[test]
fn test_domain_extraction() {
    let entry1 = make_entry("GET", "https://api.example.com/v1/data", "", "", "");
    let entry2 = make_entry("GET", "https://cdn.example.com/assets/app.js", "", "", "");
    let json = minimal_har(&format!("{},{}", entry1, entry2));
    let har = HarAnalyzer::parse(&json).unwrap();
    let analyzer = HarAnalyzer::new();
    let result = analyzer.analyze(&har);
    assert!(
        result
            .domains_contacted
            .contains(&"api.example.com".to_string())
    );
    assert!(
        result
            .domains_contacted
            .contains(&"cdn.example.com".to_string())
    );
}

#[test]
fn test_unique_url_count() {
    let entry1 = make_entry("GET", "https://example.com/page1", "", "", "");
    let entry2 = make_entry("GET", "https://example.com/page1", "", "", "");
    let entry3 = make_entry("GET", "https://example.com/page2", "", "", "");
    let json = minimal_har(&format!("{},{},{}", entry1, entry2, entry3));
    let har = HarAnalyzer::parse(&json).unwrap();
    let analyzer = HarAnalyzer::new();
    let result = analyzer.analyze(&har);
    assert_eq!(result.total_entries, 3);
    assert_eq!(result.unique_urls, 2);
}

#[test]
fn test_severity_display() {
    assert_eq!(HarFindingSeverity::Critical.to_string(), "critical");
    assert_eq!(HarFindingSeverity::High.to_string(), "high");
    assert_eq!(HarFindingSeverity::Medium.to_string(), "medium");
    assert_eq!(HarFindingSeverity::Low.to_string(), "low");
    assert_eq!(HarFindingSeverity::Info.to_string(), "info");
}

#[test]
fn test_category_display() {
    assert_eq!(
        HarFindingCategory::AuthTokenExposed.to_string(),
        "Auth Token Exposed"
    );
    assert_eq!(
        HarFindingCategory::CookieSecurity.to_string(),
        "Cookie Security Issue"
    );
    assert_eq!(
        HarFindingCategory::ThirdPartyRisk.to_string(),
        "Third-Party Risk"
    );
}

#[test]
fn test_empty_har() {
    let json = r#"{"log":{"entries":[]}}"#;
    let har = HarAnalyzer::parse(json).unwrap();
    let analyzer = HarAnalyzer::new();
    let result = analyzer.analyze(&har);
    assert_eq!(result.total_entries, 0);
    assert!(result.findings.is_empty());
}

#[test]
fn test_default_impl() {
    let analyzer = HarAnalyzer::default();
    let json = r#"{"log":{"entries":[]}}"#;
    let har = HarAnalyzer::parse(json).unwrap();
    let result = analyzer.analyze(&har);
    assert!(result.findings.is_empty());
}

#[test]
fn test_path_normalization() {
    let entry = make_entry(
        "GET",
        "https://example.com/api/v1/users/12345/posts/67890",
        "",
        "",
        "{}",
    );
    let json = minimal_har(&entry);
    let har = HarAnalyzer::parse(&json).unwrap();
    let analyzer = HarAnalyzer::new();
    let result = analyzer.analyze(&har);
    if let Some(pattern) = result.api_patterns.first() {
        assert!(pattern.path_pattern.contains(":id"));
        assert!(!pattern.path_pattern.contains("12345"));
    }
}
