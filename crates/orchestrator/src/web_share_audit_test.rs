use crate::web_share_audit::*;

#[test]
fn no_share_no_issues() {
    assert!(analyze_web_share("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_navigator_share() {
    let body = r#"<script>navigator.share({title: "test"});</script>"#;
    let issues = analyze_web_share(body);
    assert!(issues.contains(&WebShareIssue::ApiDetected));
}

#[test]
fn detects_api_can_share() {
    let body = r#"<script>if (navigator.canShare(data)) {}</script>"#;
    let issues = analyze_web_share(body);
    assert!(issues.contains(&WebShareIssue::ApiDetected));
}

#[test]
fn detects_no_user_activation() {
    let body = r#"<script>navigator.share({title: "test"});</script>"#;
    let issues = analyze_web_share(body);
    assert!(issues.contains(&WebShareIssue::NoUserActivation));
}

#[test]
fn no_activation_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", () => navigator.share({title: "t"}));
    </script>"#;
    let issues = analyze_web_share(body);
    assert!(!issues.contains(&WebShareIssue::NoUserActivation));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            await navigator.share({title: "t"});
            fetch("/log", {body: "shared"});
        });
    </script>"#;
    let issues = analyze_web_share(body);
    assert!(issues.contains(&WebShareIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        btn.addEventListener("click", () => navigator.share({title: "t"}));
    </script>"#;
    let issues = analyze_web_share(body);
    assert!(!issues.contains(&WebShareIssue::DataExfiltration));
}

#[test]
fn detects_file_sharing() {
    let body = r#"<script>
        btn.addEventListener("click", () => {
            const f = new File(["data"], "test.txt");
            navigator.share({files: [f]});
        });
    </script>"#;
    let issues = analyze_web_share(body);
    assert!(issues.contains(&WebShareIssue::FileSharing));
}

#[test]
fn detects_sensitive_content() {
    let body = r#"<script>
        btn.addEventListener("click", () => {
            navigator.share({text: localStorage.getItem("token")});
        });
    </script>"#;
    let issues = analyze_web_share(body);
    assert!(issues.contains(&WebShareIssue::SensitiveContent));
}

#[test]
fn no_sensitive_without_keywords() {
    let body = r#"<script>
        btn.addEventListener("click", () => {
            navigator.share({title: "hello"});
        });
    </script>"#;
    let issues = analyze_web_share(body);
    assert!(!issues.contains(&WebShareIssue::SensitiveContent));
}

#[test]
fn detects_unvalidated_url() {
    let body = r#"<script>
        btn.addEventListener("click", () => {
            navigator.share({url: userInput, text: "check this"});
        });
    </script>"#;
    let issues = analyze_web_share(body);
    assert!(issues.contains(&WebShareIssue::UnvalidatedUrl));
}

#[test]
fn no_unvalidated_with_encode() {
    let body = r#"<script>
        btn.addEventListener("click", () => {
            navigator.share({url: encodeURI(input), text: "safe"});
        });
    </script>"#;
    let issues = analyze_web_share(body);
    assert!(!issues.contains(&WebShareIssue::UnvalidatedUrl));
}

#[test]
fn severity_exfil_highest() {
    assert_eq!(web_share_severity(&WebShareIssue::DataExfiltration), 7.0);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(web_share_severity(&WebShareIssue::ApiDetected), 2.5);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![WebShareIssue::ApiDetected, WebShareIssue::FileSharing];
    let mut seq = 0;
    let ops = web_share_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(WebShareIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(WebShareIssue::DataExfiltration.to_string(), "data_exfiltration");
    assert_eq!(WebShareIssue::NoUserActivation.to_string(), "no_user_activation");
    assert_eq!(WebShareIssue::FileSharing.to_string(), "file_sharing");
    assert_eq!(WebShareIssue::SensitiveContent.to_string(), "sensitive_content");
    assert_eq!(WebShareIssue::UnvalidatedUrl.to_string(), "unvalidated_url");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_web_share("").is_empty());
}
