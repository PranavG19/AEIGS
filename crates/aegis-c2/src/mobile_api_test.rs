use std::collections::HashMap;

use super::mobile_api::*;

fn make_router() -> MobileApiRouter {
    let mut router = MobileApiRouter::new(b"test-secret-key-32bytes!12345678");
    router.register_default_routes();
    router
}

fn sample_implant(id: &str, hostname: &str) -> ImplantData {
    ImplantData {
        id: id.to_string(),
        hostname: hostname.to_string(),
        username: "root".to_string(),
        os: "Linux 6.8".to_string(),
        ip: "10.0.0.5".to_string(),
        last_seen_ms: 1_700_000_000_000,
        sleep_secs: 60,
        status: "active".to_string(),
    }
}

fn get_request(path: &str) -> ApiRequest {
    ApiRequest {
        method: HttpMethod::GET,
        path: path.to_string(),
        headers: HashMap::new(),
        body: None,
        query_params: HashMap::new(),
    }
}

fn post_request(path: &str, body: &str) -> ApiRequest {
    ApiRequest {
        method: HttpMethod::POST,
        path: path.to_string(),
        headers: HashMap::new(),
        body: Some(body.to_string()),
        query_params: HashMap::new(),
    }
}

#[test]
fn test_route_registration() {
    let router = make_router();
    let matched = router.match_route(&HttpMethod::GET, "/api/v1/implants");
    assert!(matched.is_some());
    let (endpoint, params) = matched.unwrap();
    assert_eq!(endpoint, ApiEndpoint::ListImplants);
    assert!(params.is_empty());

    let matched_post = router.match_route(&HttpMethod::POST, "/api/v1/auth");
    assert!(matched_post.is_some());
    assert_eq!(matched_post.unwrap().0, ApiEndpoint::Authenticate);

    let unmatched = router.match_route(&HttpMethod::DELETE, "/api/v1/implants");
    assert!(unmatched.is_none());
}

#[test]
fn test_route_with_path_param() {
    let router = make_router();

    let matched = router.match_route(&HttpMethod::GET, "/api/v1/implants/imp-007");
    assert!(matched.is_some());
    let (endpoint, params) = matched.unwrap();
    assert_eq!(endpoint, ApiEndpoint::GetImplant);
    assert_eq!(params.get("id").unwrap(), "imp-007");

    let cmd_match = router.match_route(&HttpMethod::POST, "/api/v1/implants/imp-007/command");
    assert!(cmd_match.is_some());
    let (ep2, p2) = cmd_match.unwrap();
    assert_eq!(ep2, ApiEndpoint::SendCommand);
    assert_eq!(p2.get("id").unwrap(), "imp-007");
}

#[test]
fn test_list_implants_empty() {
    let router = make_router();
    let resp = router.handle_list_implants();
    assert_eq!(resp.status_code, 200);
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&resp.body).unwrap();
    assert!(parsed.is_empty());
}

#[test]
fn test_list_implants_populated() {
    let mut router = make_router();
    router.add_implant(sample_implant("imp-001", "kali-box"));
    router.add_implant(sample_implant("imp-002", "win-dc"));

    let resp = router.handle_list_implants();
    assert_eq!(resp.status_code, 200);
    let parsed: Vec<ImplantData> = serde_json::from_str(&resp.body).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].id, "imp-001");
    assert_eq!(parsed[1].hostname, "win-dc");
}

#[test]
fn test_get_implant_found() {
    let mut router = make_router();
    router.add_implant(sample_implant("imp-042", "target-box"));

    let resp = router.handle_get_implant("imp-042");
    assert_eq!(resp.status_code, 200);
    let parsed: ImplantData = serde_json::from_str(&resp.body).unwrap();
    assert_eq!(parsed.id, "imp-042");
    assert_eq!(parsed.hostname, "target-box");
}

#[test]
fn test_get_implant_not_found() {
    let router = make_router();
    let resp = router.handle_get_implant("nonexistent");
    assert_eq!(resp.status_code, 404);
    assert!(resp.body.contains("not found"));
}

#[test]
fn test_send_command() {
    let mut router = make_router();
    router.add_implant(sample_implant("imp-001", "kali-box"));

    let body = r#"{"command_type":"shell","args":["whoami"]}"#;
    let resp = router.handle_send_command("imp-001", body);
    assert_eq!(resp.status_code, 201);

    let parsed: CommandResponse = serde_json::from_str(&resp.body).unwrap();
    assert_eq!(parsed.status, "queued");
    assert!(parsed.command_id.starts_with("cmd-"));
    assert!(!parsed.queued_at.is_empty());
}

#[test]
fn test_send_command_implant_not_found() {
    let mut router = make_router();
    let body = r#"{"command_type":"shell","args":["id"]}"#;
    let resp = router.handle_send_command("ghost", body);
    assert_eq!(resp.status_code, 404);
}

#[test]
fn test_send_command_bad_body() {
    let mut router = make_router();
    router.add_implant(sample_implant("imp-001", "kali-box"));

    let resp = router.handle_send_command("imp-001", "not json at all");
    assert_eq!(resp.status_code, 400);
    assert!(resp.body.contains("error"));
}

#[test]
fn test_authenticate_valid() {
    let router = make_router();
    let body = r#"{"operator_id":"op-alpha","password":"supersecretpassword","role":"admin"}"#;
    let resp = router.handle_authenticate(body);
    assert_eq!(resp.status_code, 200);

    let parsed: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
    let token = parsed["token"].as_str().unwrap();
    assert!(token.contains('.'));
}

#[test]
fn test_authenticate_invalid() {
    let router = make_router();
    let body = r#"{"operator_id":"op-alpha","password":"short"}"#;
    let resp = router.handle_authenticate(body);
    assert_eq!(resp.status_code, 401);
    assert!(resp.body.contains("Invalid credentials"));
}

#[test]
fn test_jwt_create_and_validate() {
    let validator = JwtValidator::new(b"my-secret-key-for-testing-32byte");
    let token = validator.create_token("operator-9", "admin");

    let claims = validator.validate_token(&token).unwrap();
    assert_eq!(claims.sub, "operator-9");
    assert_eq!(claims.role, "admin");
    assert!(claims.exp > claims.iat);
}

#[test]
fn test_jwt_invalid_token() {
    let validator = JwtValidator::new(b"secret-aaa");
    let result = validator.validate_token("garbage.token");
    assert!(result.is_err());
}

#[test]
fn test_jwt_wrong_secret() {
    let v1 = JwtValidator::new(b"secret-one-32-bytes-padding!!!!!");
    let v2 = JwtValidator::new(b"secret-two-32-bytes-padding!!!!!");

    let token = v1.create_token("op-1", "operator");
    let result = v2.validate_token(&token);
    assert!(result.is_err());
}

#[test]
fn test_handle_request_routes_correctly() {
    let mut router = make_router();
    router.add_implant(sample_implant("imp-001", "kali-box"));

    let list_resp = router.handle_request(&get_request("/api/v1/implants"));
    assert_eq!(list_resp.status_code, 200);
    let parsed: Vec<ImplantData> = serde_json::from_str(&list_resp.body).unwrap();
    assert_eq!(parsed.len(), 1);

    let get_resp = router.handle_request(&get_request("/api/v1/implants/imp-001"));
    assert_eq!(get_resp.status_code, 200);
    assert!(get_resp.body.contains("kali-box"));

    let cmd_body = r#"{"command_type":"screenshot","args":[]}"#;
    let cmd_resp =
        router.handle_request(&post_request("/api/v1/implants/imp-001/command", cmd_body));
    assert_eq!(cmd_resp.status_code, 201);

    let auth_body = r#"{"operator_id":"op-1","password":"longpassword123"}"#;
    let auth_resp = router.handle_request(&post_request("/api/v1/auth", auth_body));
    assert_eq!(auth_resp.status_code, 200);

    let missing = router.handle_request(&get_request("/api/v1/nonexistent"));
    assert_eq!(missing.status_code, 404);
}
