use crate::jwt_header_audit::*;

#[test]
fn is_jwt_format_valid_token() {
    let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    assert!(is_jwt_format(token));
}

#[test]
fn is_jwt_format_rejects_short_parts() {
    assert!(!is_jwt_format("ab.cd.ef"));
}

#[test]
fn is_jwt_format_rejects_two_parts() {
    assert!(!is_jwt_format("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"));
}

#[test]
fn is_jwt_format_rejects_invalid_chars() {
    assert!(!is_jwt_format("eyJh!gc.eyJz@WI.dozj#Nry"));
}

#[test]
fn analyze_alg_none() {
    // {"alg":"none"}  base64url = eyJhbGciOiJub25lIn0
    // {"sub":"1234567890"} base64url = eyJzdWIiOiIxMjM0NTY3ODkwIn0
    let token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.";
    let issues = analyze_jwt_token(token);
    assert!(issues.iter().any(|i| *i == JwtIssue::AlgNone));
    assert!(issues.iter().any(|i| *i == JwtIssue::MissingExpClaim));
}

#[test]
fn analyze_weak_hmac_hs256() {
    // {"alg":"HS256","typ":"JWT"} base64url = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    let issues = analyze_jwt_token(token);
    assert!(issues.iter().any(|i| matches!(i, JwtIssue::WeakHmac { algorithm } if algorithm == "HS256")));
}

#[test]
fn analyze_missing_exp() {
    // payload: {"sub":"user"} = eyJzdWIiOiJ1c2VyIn0
    let token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig";
    let issues = analyze_jwt_token(token);
    assert!(issues.iter().any(|i| *i == JwtIssue::MissingExpClaim));
}

#[test]
fn analyze_has_exp_no_issue() {
    // payload: {"sub":"user","exp":1700000000} = eyJzdWIiOiJ1c2VyIiwiZXhwIjoxNzAwMDAwMDAwfQ
    let token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiZXhwIjoxNzAwMDAwMDAwfQ.sig";
    let issues = analyze_jwt_token(token);
    assert!(!issues.iter().any(|i| *i == JwtIssue::MissingExpClaim));
}

#[test]
fn analyze_sensitive_field_password() {
    // payload: {"password":"secret123"} = eyJwYXNzd29yZCI6InNlY3JldDEyMyJ9
    let token = "eyJhbGciOiJSUzI1NiJ9.eyJwYXNzd29yZCI6InNlY3JldDEyMyJ9.sig";
    let issues = analyze_jwt_token(token);
    assert!(issues.iter().any(|i| matches!(i, JwtIssue::SensitivePayloadData { field } if field == "password")));
}

#[test]
fn analyze_not_jwt_returns_empty() {
    let issues = analyze_jwt_token("not-a-jwt");
    assert!(issues.is_empty());
}

#[test]
fn extract_jwt_from_cookie_found() {
    let sc = "session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U; Path=/; HttpOnly";
    let result = extract_jwt_from_cookie(sc);
    assert!(result.is_some());
    let (name, _token) = result.unwrap();
    assert_eq!(name, "session");
}

#[test]
fn extract_jwt_from_cookie_not_jwt() {
    let sc = "session=abc123; Path=/; HttpOnly";
    assert!(extract_jwt_from_cookie(sc).is_none());
}

#[test]
fn severity_ordering() {
    assert!(jwt_severity(&JwtIssue::AlgNone) > jwt_severity(&JwtIssue::WeakHmac { algorithm: "HS256".to_string() }));
    assert!(jwt_severity(&JwtIssue::WeakHmac { algorithm: "HS256".to_string() }) > jwt_severity(&JwtIssue::ExposedInUrl));
    assert!(jwt_severity(&JwtIssue::ExposedInUrl) > jwt_severity(&JwtIssue::MissingExpClaim));
    assert!(jwt_severity(&JwtIssue::MissingExpClaim) > jwt_severity(&JwtIssue::ExposedInCookie { cookie_name: "x".to_string() }));
}

#[test]
fn operations_generated() {
    let issues = vec![JwtIssue::AlgNone, JwtIssue::MissingExpClaim];
    let mut seq = 0;
    let ops = jwt_header_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn operations_empty_for_no_issues() {
    let mut seq = 0;
    let ops = jwt_header_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn display_variants() {
    assert_eq!(JwtIssue::AlgNone.to_string(), "jwt_alg_none");
    assert_eq!(
        JwtIssue::WeakHmac { algorithm: "HS256".to_string() }.to_string(),
        "jwt_weak_hmac:HS256"
    );
    assert_eq!(JwtIssue::MissingExpClaim.to_string(), "jwt_missing_exp");
    assert_eq!(JwtIssue::ExposedInUrl.to_string(), "jwt_exposed_in_url");
    assert_eq!(
        JwtIssue::ExposedInCookie { cookie_name: "tok".to_string() }.to_string(),
        "jwt_in_cookie:tok"
    );
    assert_eq!(
        JwtIssue::SensitivePayloadData { field: "ssn".to_string() }.to_string(),
        "jwt_sensitive_data:ssn"
    );
}

#[test]
fn audit_skips_localhost() {
    let issues = audit_jwt_headers("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn audit_skips_loopback() {
    let issues = audit_jwt_headers("http://127.0.0.1");
    assert!(issues.is_empty());
}
