use crate::clipboard_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_clipboard("");
    assert!(issues.is_empty());
}

#[test]
fn no_clipboard_no_issues() {
    let body = "var x = document.title;";
    let issues = analyze_clipboard(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_api_navigator_clipboard() {
    let body = "navigator.clipboard.readText().then(text => console.log(text));";
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::ApiDetected));
}

#[test]
fn detects_api_clipboard_write() {
    let body = "clipboard.writeText('hello world');";
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::ApiDetected));
}

#[test]
fn detects_api_exec_command_copy() {
    let body = "document.execCommand('copy');";
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::ApiDetected));
}

#[test]
fn detects_api_exec_command_paste() {
    let body = "document.execCommand(\"paste\");";
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::ApiDetected));
}

#[test]
fn detects_silent_read_no_gesture() {
    let body = r#"
        async function stealClipboard() {
            const text = await navigator.clipboard.readText();
            return text;
        }
    "#;
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::SilentClipboardRead));
}

#[test]
fn no_silent_read_with_click() {
    let body = r#"
        button.addEventListener('click', async () => {
            const text = await navigator.clipboard.readText();
        });
    "#;
    let issues = analyze_clipboard(body);
    assert!(!issues.contains(&ClipboardIssue::SilentClipboardRead));
}

#[test]
fn no_silent_read_with_permission() {
    let body = r#"
        const permission = await navigator.permissions.query({name: 'clipboard-read'});
        if (permission.state === 'granted') {
            const text = await navigator.clipboard.readText();
        }
    "#;
    let issues = analyze_clipboard(body);
    assert!(!issues.contains(&ClipboardIssue::SilentClipboardRead));
}

#[test]
fn detects_hijacking_bitcoin() {
    let body = r#"
        document.addEventListener('copy', (e) => {
            e.preventDefault();
            e.clipboardData.setData('text/plain', 'bc1qmaliciousaddress');
        });
    "#;
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::ClipboardHijacking));
}

#[test]
fn detects_hijacking_crypto_wallet() {
    let body = r#"
        function replaceWallet() {
            const text = '0xMaliciousEthereumAddress';
            navigator.clipboard.writeText(text);
        }
    "#;
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::ClipboardHijacking));
}

#[test]
fn detects_hijacking_oncopy() {
    let body = r#"
        <div oncopy="modifyClipboard(event)">Select me</div>
        <script>
        function modifyClipboard(e) {
            navigator.clipboard.writeText('malicious');
        }
        </script>
    "#;
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::ClipboardHijacking));
}

#[test]
fn no_hijacking_normal_write() {
    let body = r#"
        button.onclick = () => {
            navigator.clipboard.writeText('normal text');
        };
    "#;
    let issues = analyze_clipboard(body);
    assert!(!issues.contains(&ClipboardIssue::ClipboardHijacking));
}

#[test]
fn detects_sensitive_password() {
    let body = r#"
        const password = document.getElementById('pwd').value;
        navigator.clipboard.writeText(password);
    "#;
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::SensitiveDataClipboard));
}

#[test]
fn detects_sensitive_token() {
    let body = r#"
        clipboard.readText().then(token => {
            localStorage.setItem('authToken', token);
        });
    "#;
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::SensitiveDataClipboard));
}

#[test]
fn detects_sensitive_api_key() {
    let body = r#"
        const apiKey = getApiKey();
        clipboard.writeText(apiKey);
    "#;
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::SensitiveDataClipboard));
}

#[test]
fn detects_sensitive_private_key() {
    let body = r#"
        e.clipboardData.setData('text', privateKey);
    "#;
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::SensitiveDataClipboard));
}

#[test]
fn detects_missing_permission_check() {
    let body = r#"
        async function read() {
            const text = await clipboard.readText();
            return text;
        }
    "#;
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::MissingPermissionCheck));
}

#[test]
fn no_missing_permission_with_query() {
    let body = r#"
        const result = await navigator.permissions.query({name: 'clipboard-read'});
        if (result.state === 'granted') {
            clipboard.readText();
        }
    "#;
    let issues = analyze_clipboard(body);
    assert!(!issues.contains(&ClipboardIssue::MissingPermissionCheck));
}

#[test]
fn detects_cross_origin_iframe() {
    let body = r#"
        <iframe src="https://evil.com"></iframe>
        <script>
        clipboard.readText().then(text => console.log(text));
        </script>
    "#;
    let issues = analyze_clipboard(body);
    assert!(issues.contains(&ClipboardIssue::CrossOriginClipboardAccess));
}

#[test]
fn no_cross_origin_with_allow() {
    let body = r#"
        <iframe src="https://trusted.com" allow="clipboard-read clipboard-write"></iframe>
        <script>
        clipboard.writeText('data');
        </script>
    "#;
    let issues = analyze_clipboard(body);
    assert!(!issues.contains(&ClipboardIssue::CrossOriginClipboardAccess));
}

#[test]
fn no_cross_origin_without_iframe() {
    let body = r#"
        clipboard.readText().then(text => console.log(text));
    "#;
    let issues = analyze_clipboard(body);
    assert!(!issues.contains(&ClipboardIssue::CrossOriginClipboardAccess));
}

#[test]
fn severity_silent_read_highest() {
    assert_eq!(
        clipboard_severity(&ClipboardIssue::SilentClipboardRead),
        8.5
    );
}

#[test]
fn severity_hijacking_high() {
    assert_eq!(clipboard_severity(&ClipboardIssue::ClipboardHijacking), 8.0);
}

#[test]
fn severity_sensitive_data_high() {
    assert_eq!(
        clipboard_severity(&ClipboardIssue::SensitiveDataClipboard),
        7.5
    );
}

#[test]
fn severity_cross_origin_medium() {
    assert_eq!(
        clipboard_severity(&ClipboardIssue::CrossOriginClipboardAccess),
        6.5
    );
}

#[test]
fn severity_missing_permission_medium() {
    assert_eq!(
        clipboard_severity(&ClipboardIssue::MissingPermissionCheck),
        5.5
    );
}

#[test]
fn severity_api_detected_low() {
    assert_eq!(clipboard_severity(&ClipboardIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        ClipboardIssue::ApiDetected,
        ClipboardIssue::SilentClipboardRead,
    ];
    let mut seq = 0u64;
    let ops = clipboard_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn to_operations_empty_input() {
    let issues = vec![];
    let mut seq = 0u64;
    let ops = clipboard_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn display_api_detected() {
    assert_eq!(
        ClipboardIssue::ApiDetected.to_string(),
        "clipboard_api_detected"
    );
}

#[test]
fn display_silent_read() {
    assert_eq!(
        ClipboardIssue::SilentClipboardRead.to_string(),
        "silent_clipboard_read"
    );
}

#[test]
fn display_hijacking() {
    assert_eq!(
        ClipboardIssue::ClipboardHijacking.to_string(),
        "clipboard_hijacking"
    );
}

#[test]
fn display_sensitive_data() {
    assert_eq!(
        ClipboardIssue::SensitiveDataClipboard.to_string(),
        "sensitive_data_clipboard"
    );
}

#[test]
fn display_missing_permission() {
    assert_eq!(
        ClipboardIssue::MissingPermissionCheck.to_string(),
        "missing_permission_check"
    );
}

#[test]
fn display_cross_origin() {
    assert_eq!(
        ClipboardIssue::CrossOriginClipboardAccess.to_string(),
        "cross_origin_clipboard_access"
    );
}

#[test]
fn multiple_issues_detected() {
    let body = r#"
        <iframe src="https://evil.com"></iframe>
        <script>
        async function steal() {
            const password = await clipboard.readText();
            fetch('/exfil', { method: 'POST', body: password });
        }
        steal();
        </script>
    "#;
    let issues = analyze_clipboard(body);
    assert!(issues.len() >= 3);
    assert!(issues.contains(&ClipboardIssue::ApiDetected));
    assert!(issues.contains(&ClipboardIssue::SilentClipboardRead));
    assert!(issues.contains(&ClipboardIssue::SensitiveDataClipboard));
}
