use crate::content_type_confusion_audit::*;

#[test]
fn both_success_detects_xml_acceptance() {
    let issues = analyze_content_type_confusion(200, 200, "<root/>", "/api/data");
    assert!(issues.iter().any(|i| matches!(
        i,
        ContentTypeConfusionIssue::AcceptsXmlWhenExpectingJson { .. }
    )));
}

#[test]
fn json_ok_xml_rejected_no_issue() {
    let issues = analyze_content_type_confusion(200, 415, "", "/api/data");
    assert!(issues.is_empty());
}

#[test]
fn both_rejected_no_issue() {
    let issues = analyze_content_type_confusion(405, 405, "", "/api/data");
    assert!(issues.is_empty());
}

#[test]
fn xxe_file_content_detected() {
    let issues = analyze_content_type_confusion(
        200,
        200,
        "<response>root:x:0:0:root:/root:/bin/bash</response>",
        "/api/data",
    );
    assert!(issues.iter().any(|i| matches!(
        i,
        ContentTypeConfusionIssue::XxeIndicator { indicator, .. } if indicator == "file_content_leak"
    )));
}

#[test]
fn xxe_metadata_detected() {
    let issues = analyze_content_type_confusion(
        200,
        200,
        "<response>169.254.169.254 metadata</response>",
        "/api/data",
    );
    assert!(issues.iter().any(|i| matches!(
        i,
        ContentTypeConfusionIssue::XxeIndicator { indicator, .. } if indicator == "ssrf_metadata_leak"
    )));
}

#[test]
fn no_xxe_in_normal_xml_response() {
    let issues =
        analyze_content_type_confusion(200, 200, "<response>ok</response>", "/api/data");
    assert!(!issues.iter().any(|i| matches!(
        i,
        ContentTypeConfusionIssue::XxeIndicator { .. }
    )));
}

#[test]
fn xxe_not_checked_when_xml_rejected() {
    let issues = analyze_content_type_confusion(
        200,
        415,
        "root:x:0:0:root:/root:/bin/bash",
        "/api/data",
    );
    assert!(!issues.iter().any(|i| matches!(
        i,
        ContentTypeConfusionIssue::XxeIndicator { .. }
    )));
}

#[test]
fn json_to_xml_response_mismatch() {
    let result =
        analyze_response_type_mismatch("application/json", "application/xml");
    assert!(result.is_some());
    assert!(matches!(
        result.unwrap(),
        ContentTypeConfusionIssue::MismatchedResponseType { .. }
    ));
}

#[test]
fn xml_to_json_response_mismatch() {
    let result =
        analyze_response_type_mismatch("text/xml", "application/json; charset=utf-8");
    assert!(result.is_some());
}

#[test]
fn same_type_no_mismatch() {
    let result =
        analyze_response_type_mismatch("application/json", "application/json");
    assert!(result.is_none());
}

#[test]
fn html_to_html_no_mismatch() {
    let result = analyze_response_type_mismatch("text/html", "text/html");
    assert!(result.is_none());
}

#[test]
fn severity_ordering() {
    assert!(
        content_type_confusion_severity(&ContentTypeConfusionIssue::XxeIndicator {
            endpoint: "/api".into(),
            indicator: "file_read".into()
        }) > content_type_confusion_severity(
            &ContentTypeConfusionIssue::AcceptsXmlWhenExpectingJson {
                endpoint: "/api".into()
            }
        )
    );
    assert!(
        content_type_confusion_severity(
            &ContentTypeConfusionIssue::AcceptsXmlWhenExpectingJson {
                endpoint: "/api".into()
            }
        ) > content_type_confusion_severity(
            &ContentTypeConfusionIssue::MismatchedResponseType {
                request_ct: "json".into(),
                response_ct: "xml".into()
            }
        )
    );
}

#[test]
fn to_operations_produces_entries() {
    let issues = vec![
        ContentTypeConfusionIssue::AcceptsXmlWhenExpectingJson {
            endpoint: "/api".into(),
        },
        ContentTypeConfusionIssue::XxeIndicator {
            endpoint: "/api".into(),
            indicator: "file_read".into(),
        },
    ];
    let mut seq = 20;
    let ops = content_type_confusion_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 22);
}

#[test]
fn display_variants() {
    let issue = ContentTypeConfusionIssue::AcceptsXmlWhenExpectingJson {
        endpoint: "/api".into(),
    };
    assert_eq!(issue.to_string(), "accepts_xml_for_json:/api");

    let issue = ContentTypeConfusionIssue::XxeIndicator {
        endpoint: "/api".into(),
        indicator: "file_read".into(),
    };
    assert_eq!(issue.to_string(), "xxe_indicator:/api:file_read");

    let issue = ContentTypeConfusionIssue::MismatchedResponseType {
        request_ct: "json".into(),
        response_ct: "xml".into(),
    };
    assert_eq!(issue.to_string(), "ct_mismatch:json->xml");
}
