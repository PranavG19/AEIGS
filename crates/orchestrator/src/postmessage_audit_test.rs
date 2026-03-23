use crate::postmessage_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_postmessage_usage("");
    assert!(issues.is_empty());
}

#[test]
fn no_postmessage_no_issues() {
    let body = "<script>var x = 1;</script>";
    let issues = analyze_postmessage_usage(body);
    assert!(issues.is_empty());
}

#[test]
fn wildcard_target_origin_double_quotes() {
    let body = r#"<script>parent.postMessage(data, "*");</script>"#;
    let issues = analyze_postmessage_usage(body);
    assert!(issues
        .iter()
        .any(|i| *i == PostMessageIssue::WildcardTargetOrigin));
}

#[test]
fn wildcard_target_origin_single_quotes() {
    let body = "<script>parent.postMessage(data, '*');</script>";
    let issues = analyze_postmessage_usage(body);
    assert!(issues
        .iter()
        .any(|i| *i == PostMessageIssue::WildcardTargetOrigin));
}

#[test]
fn specific_origin_not_flagged() {
    let body = r#"<script>parent.postMessage(data, "https://example.com");</script>"#;
    let issues = analyze_postmessage_usage(body);
    assert!(!issues
        .iter()
        .any(|i| *i == PostMessageIssue::WildcardTargetOrigin));
}

#[test]
fn message_handler_no_origin_check() {
    let body = r#"<script>
        window.addEventListener("message", function(event) {
            processData(event.data);
        });
    </script>"#;
    let issues = analyze_postmessage_usage(body);
    assert!(issues
        .iter()
        .any(|i| *i == PostMessageIssue::MessageHandlerNoOriginCheck));
}

#[test]
fn message_handler_with_origin_check_ok() {
    let body = r#"<script>
        window.addEventListener("message", function(event) {
            if (event.origin !== "https://trusted.com") return;
            processData(event.data);
        });
    </script>"#;
    let issues = analyze_postmessage_usage(body);
    assert!(!issues
        .iter()
        .any(|i| *i == PostMessageIssue::MessageHandlerNoOriginCheck));
}

#[test]
fn message_handler_with_eval_flagged() {
    let body = r#"<script>
        window.addEventListener("message", function(event) {
            if (event.origin === "https://example.com") {
                eval(event.data);
            }
        });
    </script>"#;
    let issues = analyze_postmessage_usage(body);
    assert!(issues
        .iter()
        .any(|i| *i == PostMessageIssue::MessageHandlerUsesEval));
}

#[test]
fn message_handler_with_innerhtml_flagged() {
    let body = r#"<script>
        window.addEventListener("message", function(event) {
            if (event.origin === "https://example.com") {
                document.getElementById("out").innerHTML = event.data;
            }
        });
    </script>"#;
    let issues = analyze_postmessage_usage(body);
    assert!(issues
        .iter()
        .any(|i| *i == PostMessageIssue::MessageHandlerUsesInnerHtml));
}

#[test]
fn onmessage_handler_detected() {
    let body = r#"<script>
        window.onmessage = function(e) {
            doStuff(e.data);
        };
    </script>"#;
    let issues = analyze_postmessage_usage(body);
    assert!(issues
        .iter()
        .any(|i| *i == PostMessageIssue::MessageHandlerNoOriginCheck));
}

#[test]
fn onmessage_with_origin_check() {
    let body = r#"<script>
        window.onmessage = function(e) {
            if (e.origin !== "https://safe.com") return;
            doStuff(e.data);
        };
    </script>"#;
    let issues = analyze_postmessage_usage(body);
    assert!(!issues
        .iter()
        .any(|i| *i == PostMessageIssue::MessageHandlerNoOriginCheck));
}

#[test]
fn severity_ordering() {
    assert!(
        postmessage_severity(&PostMessageIssue::MessageHandlerUsesEval)
            > postmessage_severity(&PostMessageIssue::MessageHandlerUsesInnerHtml)
    );
    assert!(
        postmessage_severity(&PostMessageIssue::MessageHandlerNoOriginCheck)
            > postmessage_severity(&PostMessageIssue::WildcardTargetOrigin)
    );
}

#[test]
fn to_operations_produces_entries() {
    let issues = vec![
        PostMessageIssue::WildcardTargetOrigin,
        PostMessageIssue::MessageHandlerNoOriginCheck,
    ];
    let mut seq = 60;
    let ops = postmessage_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 62);
}

#[test]
fn display_variants() {
    assert_eq!(
        PostMessageIssue::WildcardTargetOrigin.to_string(),
        "postmessage_wildcard_origin"
    );
    assert_eq!(
        PostMessageIssue::MessageHandlerNoOriginCheck.to_string(),
        "message_handler_no_origin"
    );
    assert_eq!(
        PostMessageIssue::MessageHandlerUsesEval.to_string(),
        "message_handler_eval"
    );
}

#[test]
fn no_duplicate_wildcard_issues() {
    let body = r#"<script>
        parent.postMessage(a, "*");
        parent.postMessage(b, '*');
    </script>"#;
    let issues = analyze_postmessage_usage(body);
    let wildcard_count = issues
        .iter()
        .filter(|i| **i == PostMessageIssue::WildcardTargetOrigin)
        .count();
    assert_eq!(wildcard_count, 1);
}
