use crate::postmessage_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_postmessage("");
    assert!(issues.is_empty());
}

#[test]
fn no_postmessage_no_issues() {
    let body = "<script>var x = 1; console.log('test');</script>";
    let issues = analyze_postmessage(body);
    assert!(issues.is_empty());
}

#[test]
fn api_detected_basic() {
    let body = r#"<script>window.postMessage('test', '*');</script>"#;
    let issues = analyze_postmessage(body);
    assert!(issues.contains(&PostMessageIssue::ApiDetected));
}

#[test]
fn api_detected_listener() {
    let body = r#"<script>window.addEventListener('message', handler);</script>"#;
    let issues = analyze_postmessage(body);
    assert!(issues.contains(&PostMessageIssue::ApiDetected));
}

#[test]
fn api_detected_onmessage() {
    let body = r#"<script>window.onmessage = function(e) {};</script>"#;
    let issues = analyze_postmessage(body);
    assert!(issues.contains(&PostMessageIssue::ApiDetected));
}

#[test]
fn wildcard_target_origin_double_quotes() {
    let body = r#"<script>parent.postMessage(data, "*");</script>"#;
    let issues = analyze_postmessage(body);
    assert!(issues.contains(&PostMessageIssue::WildcardTargetOrigin));
}

#[test]
fn wildcard_target_origin_single_quotes() {
    let body = "<script>parent.postMessage(data, '*');</script>";
    let issues = analyze_postmessage(body);
    assert!(issues.contains(&PostMessageIssue::WildcardTargetOrigin));
}

#[test]
fn specific_origin_not_wildcard() {
    let body = r#"<script>parent.postMessage(data, "https://example.com");</script>"#;
    let issues = analyze_postmessage(body);
    assert!(!issues.contains(&PostMessageIssue::WildcardTargetOrigin));
}

#[test]
fn message_handler_no_origin_check() {
    let body = r#"<script>
        window.addEventListener("message", function(event) {
            processData(event.data);
        });
    </script>"#;
    let issues = analyze_postmessage(body);
    assert!(issues.contains(&PostMessageIssue::MessageHandlerNoOriginCheck));
}

#[test]
fn message_handler_with_origin_check_strict_equality() {
    let body = r#"<script>
        window.addEventListener("message", function(event) {
            if (event.origin !== "https://trusted.com") return;
            processData(event.data);
        });
    </script>"#;
    let issues = analyze_postmessage(body);
    assert!(!issues.contains(&PostMessageIssue::MessageHandlerNoOriginCheck));
}

#[test]
fn message_handler_with_origin_check_equality() {
    let body = r#"<script>
        window.addEventListener('message', function(e) {
            if (e.origin == "https://ok.com") processData(e.data);
        });
    </script>"#;
    let issues = analyze_postmessage(body);
    assert!(!issues.contains(&PostMessageIssue::MessageHandlerNoOriginCheck));
}

#[test]
fn dom_injection_innerhtml() {
    let body = r#"<script>
        window.addEventListener("message", function(event) {
            document.getElementById("output").innerHTML = event.data;
        });
    </script>"#;
    let issues = analyze_postmessage(body);
    assert!(issues.contains(&PostMessageIssue::DomInjectionViaMessage));
}

#[test]
fn dom_injection_eval() {
    let body = r#"<script>
        window.addEventListener("message", function(event) {
            if (event.origin === "https://example.com") {
                eval(event.data);
            }
        });
    </script>"#;
    let issues = analyze_postmessage(body);
    assert!(issues.contains(&PostMessageIssue::DomInjectionViaMessage));
}

#[test]
fn dom_injection_document_write() {
    let body = r#"<script>
        window.onmessage = function(e) {
            document.write(e.data);
        };
    </script>"#;
    let issues = analyze_postmessage(body);
    assert!(issues.contains(&PostMessageIssue::DomInjectionViaMessage));
}

#[test]
fn sensitive_data_password() {
    let body = r#"<script>
        var password = document.getElementById("pwd").value;
        parent.postMessage({password: password}, "*");
    </script>"#;
    let issues = analyze_postmessage(body);
    assert!(issues.contains(&PostMessageIssue::SensitiveDataInMessage));
}

#[test]
fn sensitive_data_token() {
    let body = r#"<script>
        const token = getAuthToken();
        window.postMessage({auth: token}, origin);
    </script>"#;
    let issues = analyze_postmessage(body);
    assert!(issues.contains(&PostMessageIssue::SensitiveDataInMessage));
}

#[test]
fn cross_frame_parent_no_validation() {
    let body = r#"<script>
        parent.postMessage(data, targetOrigin);
    </script>"#;
    let issues = analyze_postmessage(body);
    assert!(issues.contains(&PostMessageIssue::CrossFrameNoValidation));
}

#[test]
fn cross_frame_frames_array() {
    let body = r#"<script>
        frames[0].postMessage(msg, "*");
    </script>"#;
    let issues = analyze_postmessage(body);
    assert!(issues.contains(&PostMessageIssue::CrossFrameNoValidation));
}

#[test]
fn prototype_pollution_proto() {
    let body = r#"<script>
        window.addEventListener("message", function(event) {
            const obj = {};
            obj[event.data.key] = event.data.value;
            if (event.data.__proto__) obj.__proto__ = event.data.__proto__;
        });
    </script>"#;
    let issues = analyze_postmessage(body);
    assert!(issues.contains(&PostMessageIssue::PrototypePollutionRisk));
}

#[test]
fn prototype_pollution_constructor() {
    let body = r#"<script>
        window.onmessage = function(e) {
            const target = {};
            merge(target, e.data);
            if (e.data.constructor.prototype) apply(e.data.constructor.prototype);
        };
    </script>"#;
    let issues = analyze_postmessage(body);
    assert!(issues.contains(&PostMessageIssue::PrototypePollutionRisk));
}

#[test]
fn severity_ordering() {
    assert!(
        postmessage_severity(&PostMessageIssue::DomInjectionViaMessage)
            > postmessage_severity(&PostMessageIssue::PrototypePollutionRisk)
    );
    assert!(
        postmessage_severity(&PostMessageIssue::PrototypePollutionRisk)
            > postmessage_severity(&PostMessageIssue::SensitiveDataInMessage)
    );
    assert!(
        postmessage_severity(&PostMessageIssue::SensitiveDataInMessage)
            > postmessage_severity(&PostMessageIssue::MessageHandlerNoOriginCheck)
    );
    assert!(
        postmessage_severity(&PostMessageIssue::MessageHandlerNoOriginCheck)
            > postmessage_severity(&PostMessageIssue::CrossFrameNoValidation)
    );
    assert!(
        postmessage_severity(&PostMessageIssue::CrossFrameNoValidation)
            > postmessage_severity(&PostMessageIssue::WildcardTargetOrigin)
    );
    assert!(
        postmessage_severity(&PostMessageIssue::WildcardTargetOrigin)
            > postmessage_severity(&PostMessageIssue::ApiDetected)
    );
}

#[test]
fn to_operations_produces_entries() {
    let issues = vec![
        PostMessageIssue::ApiDetected,
        PostMessageIssue::WildcardTargetOrigin,
        PostMessageIssue::MessageHandlerNoOriginCheck,
    ];
    let mut seq = 0u64;
    let ops = postmessage_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn to_operations_empty_input() {
    let issues = vec![];
    let mut seq = 42u64;
    let ops = postmessage_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 42);
}

#[test]
fn display_api_detected() {
    assert_eq!(
        PostMessageIssue::ApiDetected.to_string(),
        "postmessage_api_detected"
    );
}

#[test]
fn display_wildcard_origin() {
    assert_eq!(
        PostMessageIssue::WildcardTargetOrigin.to_string(),
        "postmessage_wildcard_origin"
    );
}

#[test]
fn display_no_origin_check() {
    assert_eq!(
        PostMessageIssue::MessageHandlerNoOriginCheck.to_string(),
        "message_handler_no_origin"
    );
}

#[test]
fn display_dom_injection() {
    assert_eq!(
        PostMessageIssue::DomInjectionViaMessage.to_string(),
        "dom_injection_via_message"
    );
}

#[test]
fn display_sensitive_data() {
    assert_eq!(
        PostMessageIssue::SensitiveDataInMessage.to_string(),
        "sensitive_data_in_message"
    );
}

#[test]
fn display_cross_frame() {
    assert_eq!(
        PostMessageIssue::CrossFrameNoValidation.to_string(),
        "cross_frame_no_validation"
    );
}

#[test]
fn display_prototype_pollution() {
    assert_eq!(
        PostMessageIssue::PrototypePollutionRisk.to_string(),
        "prototype_pollution_risk"
    );
}

#[test]
fn onmessage_assignment_with_space() {
    let body = r#"<script>window.onmessage = function(e) { process(e.data); };</script>"#;
    let issues = analyze_postmessage(body);
    assert!(issues.contains(&PostMessageIssue::MessageHandlerNoOriginCheck));
}

#[test]
fn onmessage_assignment_without_space() {
    let body = r#"<script>window.onmessage=function(e) { process(e.data); };</script>"#;
    let issues = analyze_postmessage(body);
    assert!(issues.contains(&PostMessageIssue::MessageHandlerNoOriginCheck));
}

#[test]
fn evt_param_name_origin_check() {
    let body = r#"<script>
        window.addEventListener("message", function(evt) {
            if (evt.origin !== "https://safe.com") return;
            process(evt.data);
        });
    </script>"#;
    let issues = analyze_postmessage(body);
    assert!(!issues.contains(&PostMessageIssue::MessageHandlerNoOriginCheck));
}
