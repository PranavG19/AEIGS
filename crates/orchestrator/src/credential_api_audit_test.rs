use crate::credential_api_audit::*;

#[test]
fn no_credential_api_no_issues() {
    assert!(analyze_credential_api("<html></html>").is_empty());
}

#[test]
fn detects_get() {
    let body = r#"<script>navigator.credentials.get({password: true})</script>"#;
    let issues = analyze_credential_api(body);
    assert!(issues.contains(&CredentialApiIssue::GetDetected));
}

#[test]
fn detects_store() {
    let body = r#"<script>navigator.credentials.store(cred)</script>"#;
    let issues = analyze_credential_api(body);
    assert!(issues.contains(&CredentialApiIssue::StoreDetected));
}

#[test]
fn detects_create() {
    let body = r#"<script>navigator.credentials.create({publicKey: opts})</script>"#;
    let issues = analyze_credential_api(body);
    assert!(issues.contains(&CredentialApiIssue::CreateDetected));
}

#[test]
fn detects_mediation_silent() {
    let body = r#"<script>navigator.credentials.get({mediation: "silent"})</script>"#;
    let issues = analyze_credential_api(body);
    assert!(issues.contains(&CredentialApiIssue::MediationSilent));
}

#[test]
fn detects_mediation_silent_single_quotes() {
    let body = r#"<script>navigator.credentials.get({mediation: 'silent'})</script>"#;
    let issues = analyze_credential_api(body);
    assert!(issues.contains(&CredentialApiIssue::MediationSilent));
}

#[test]
fn no_mediation_silent_without_marker() {
    let body = r#"<script>navigator.credentials.get({password: true})</script>"#;
    let issues = analyze_credential_api(body);
    assert!(!issues.contains(&CredentialApiIssue::MediationSilent));
}

#[test]
fn detects_password_credential() {
    let body = r#"<script>new PasswordCredential({id: "u", password: "p"})</script>"#;
    let issues = analyze_credential_api(body);
    assert!(issues.contains(&CredentialApiIssue::PasswordCredential));
}

#[test]
fn detects_federated_credential() {
    let body =
        r#"<script>new FederatedCredential({id: "u", provider: "https://idp.com"})</script>"#;
    let issues = analyze_credential_api(body);
    assert!(issues.contains(&CredentialApiIssue::FederatedCredential));
}

#[test]
fn detects_no_prevent_silent_access() {
    let body = r#"<script>navigator.credentials.get({password: true})</script>"#;
    let issues = analyze_credential_api(body);
    assert!(issues.contains(&CredentialApiIssue::NoPreventSilentAccess));
}

#[test]
fn no_prevent_issue_when_present() {
    let body = r#"<script>
        navigator.credentials.get({password: true});
        navigator.credentials.preventSilentAccess();
    </script>"#;
    let issues = analyze_credential_api(body);
    assert!(!issues.contains(&CredentialApiIssue::NoPreventSilentAccess));
}

#[test]
fn severity_silent_highest() {
    assert_eq!(
        credential_api_severity(&CredentialApiIssue::MediationSilent),
        6.5
    );
}

#[test]
fn severity_get_lowest() {
    assert_eq!(
        credential_api_severity(&CredentialApiIssue::GetDetected),
        3.5
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        CredentialApiIssue::GetDetected,
        CredentialApiIssue::MediationSilent,
    ];
    let mut seq = 0;
    let ops = credential_api_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(CredentialApiIssue::GetDetected.to_string(), "get_detected");
    assert_eq!(
        CredentialApiIssue::StoreDetected.to_string(),
        "store_detected"
    );
    assert_eq!(
        CredentialApiIssue::CreateDetected.to_string(),
        "create_detected"
    );
    assert_eq!(
        CredentialApiIssue::MediationSilent.to_string(),
        "mediation_silent"
    );
    assert_eq!(
        CredentialApiIssue::NoPreventSilentAccess.to_string(),
        "no_prevent_silent_access"
    );
    assert_eq!(
        CredentialApiIssue::FederatedCredential.to_string(),
        "federated_credential"
    );
    assert_eq!(
        CredentialApiIssue::PasswordCredential.to_string(),
        "password_credential"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_credential_api("").is_empty());
}
