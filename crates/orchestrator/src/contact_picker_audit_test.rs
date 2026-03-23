use crate::contact_picker_audit::*;

#[test]
fn no_contacts_no_issues() {
    assert!(analyze_contact_picker("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_contacts_manager() {
    let body = r#"<script>const cm = new ContactsManager();</script>"#;
    let issues = analyze_contact_picker(body);
    assert!(issues.contains(&ContactPickerIssue::ApiDetected));
}

#[test]
fn detects_api_navigator() {
    let body = r#"<script>const c = navigator.contacts.select(["name"]);</script>"#;
    let issues = analyze_contact_picker(body);
    assert!(issues.contains(&ContactPickerIssue::ApiDetected));
}

#[test]
fn detects_exfiltration() {
    let body = r#"<script>
        const c = navigator.contacts.select(["name"]);
        fetch("/api/contacts", {body: JSON.stringify(c)});
    </script>"#;
    let issues = analyze_contact_picker(body);
    assert!(issues.contains(&ContactPickerIssue::ContactExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const c = navigator.contacts.select(["name"]);
        console.log(c);
    </script>"#;
    let issues = analyze_contact_picker(body);
    assert!(!issues.contains(&ContactPickerIssue::ContactExfiltration));
}

#[test]
fn detects_excessive_properties() {
    let body = r#"<script>
        navigator.contacts.select(["name", "email", "tel"]);
    </script>"#;
    let issues = analyze_contact_picker(body);
    assert!(issues.contains(&ContactPickerIssue::ExcessiveProperties));
}

#[test]
fn no_excessive_with_few_props() {
    let body = r#"<script>
        navigator.contacts.select(["name"]);
    </script>"#;
    let issues = analyze_contact_picker(body);
    assert!(!issues.contains(&ContactPickerIssue::ExcessiveProperties));
}

#[test]
fn detects_no_user_activation() {
    let body = r#"<script>navigator.contacts.select(["name"]);</script>"#;
    let issues = analyze_contact_picker(body);
    assert!(issues.contains(&ContactPickerIssue::NoUserActivation));
}

#[test]
fn no_activation_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", () => navigator.contacts.select(["name"]));
    </script>"#;
    let issues = analyze_contact_picker(body);
    assert!(!issues.contains(&ContactPickerIssue::NoUserActivation));
}

#[test]
fn detects_multiple_select() {
    let body = r#"<script>
        navigator.contacts.select(["name"], {multiple: true});
    </script>"#;
    let issues = analyze_contact_picker(body);
    assert!(issues.contains(&ContactPickerIssue::MultipleSelect));
}

#[test]
fn detects_email_harvesting() {
    let body = r#"<script>
        navigator.contacts.select(["email"]);
    </script>"#;
    let issues = analyze_contact_picker(body);
    assert!(issues.contains(&ContactPickerIssue::EmailHarvesting));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        contact_picker_severity(&ContactPickerIssue::ContactExfiltration),
        7.0
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(
        contact_picker_severity(&ContactPickerIssue::ApiDetected),
        3.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        ContactPickerIssue::ApiDetected,
        ContactPickerIssue::EmailHarvesting,
    ];
    let mut seq = 0;
    let ops = contact_picker_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(ContactPickerIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        ContactPickerIssue::ContactExfiltration.to_string(),
        "contact_exfiltration"
    );
    assert_eq!(
        ContactPickerIssue::ExcessiveProperties.to_string(),
        "excessive_properties"
    );
    assert_eq!(
        ContactPickerIssue::NoUserActivation.to_string(),
        "no_user_activation"
    );
    assert_eq!(
        ContactPickerIssue::MultipleSelect.to_string(),
        "multiple_select"
    );
    assert_eq!(
        ContactPickerIssue::EmailHarvesting.to_string(),
        "email_harvesting"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_contact_picker("").is_empty());
}
