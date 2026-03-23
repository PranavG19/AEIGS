use crate::selection_audit::*;

#[test]
fn no_selection_no_issues() {
    assert!(analyze_selection("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api() {
    let body = r#"<script>const sel = window.getSelection();</script>"#;
    let issues = analyze_selection(body);
    assert!(issues.contains(&SelectionIssue::ApiDetected));
}

#[test]
fn detects_exfiltration() {
    let body = r#"<script>
        const sel = window.getSelection();
        fetch("/track?text=" + sel.toString());
    </script>"#;
    let issues = analyze_selection(body);
    assert!(issues.contains(&SelectionIssue::SelectionExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const sel = window.getSelection();
        console.log(sel.toString());
    </script>"#;
    let issues = analyze_selection(body);
    assert!(!issues.contains(&SelectionIssue::SelectionExfiltration));
}

#[test]
fn detects_clipboard_hijack() {
    let body = r#"<script>
        window.getSelection();
        document.execCommand("copy");
    </script>"#;
    let issues = analyze_selection(body);
    assert!(issues.contains(&SelectionIssue::ClipboardHijack));
}

#[test]
fn detects_clipboard_write_text() {
    let body = r#"<script>
        const sel = window.getSelection();
        navigator.clipboard.writeText(sel.toString());
    </script>"#;
    let issues = analyze_selection(body);
    assert!(issues.contains(&SelectionIssue::ClipboardHijack));
}

#[test]
fn detects_hidden_text() {
    let body = r#"<div style="visibility:hidden">secret</div>
    <script>window.getSelection();</script>"#;
    let issues = analyze_selection(body);
    assert!(issues.contains(&SelectionIssue::HiddenTextSelection));
}

#[test]
fn detects_continuous_monitoring() {
    let body = r#"<script>
        document.addEventListener("selectionchange", () => {
            const sel = window.getSelection();
        });
    </script>"#;
    let issues = analyze_selection(body);
    assert!(issues.contains(&SelectionIssue::ContinuousMonitoring));
}

#[test]
fn detects_range_manipulation() {
    let body = r#"<script>
        const sel = window.getSelection();
        const range = document.createRange();
        sel.addRange(range);
    </script>"#;
    let issues = analyze_selection(body);
    assert!(issues.contains(&SelectionIssue::RangeManipulation));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        selection_severity(&SelectionIssue::SelectionExfiltration),
        6.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(selection_severity(&SelectionIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![SelectionIssue::ApiDetected, SelectionIssue::ClipboardHijack];
    let mut seq = 0;
    let ops = selection_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(SelectionIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        SelectionIssue::SelectionExfiltration.to_string(),
        "selection_exfiltration"
    );
    assert_eq!(
        SelectionIssue::ClipboardHijack.to_string(),
        "clipboard_hijack"
    );
    assert_eq!(
        SelectionIssue::HiddenTextSelection.to_string(),
        "hidden_text_selection"
    );
    assert_eq!(
        SelectionIssue::ContinuousMonitoring.to_string(),
        "continuous_monitoring"
    );
    assert_eq!(
        SelectionIssue::RangeManipulation.to_string(),
        "range_manipulation"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_selection("").is_empty());
}

#[test]
fn analyze_security_no_selection_api() {
    let body = r#"<script>navigator.clipboard.writeText("test");</script>"#;
    assert!(analyze_selection_security(body).is_empty());
}

#[test]
fn analyze_security_selection_to_clipboard() {
    let body = r#"<script>
        const sel = window.getSelection();
        navigator.clipboard.writeText(sel.toString());
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionToClipboard));
}

#[test]
fn analyze_security_clipboard_data() {
    let body = r#"<script>
        const sel = document.selection;
        clipboardData.setData("text", sel);
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionToClipboard));
}

#[test]
fn analyze_security_selection_in_iframe() {
    let body = r#"<script>
        const iframe = document.getElementById("frame");
        const sel = iframe.contentDocument.getSelection();
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionInIframe));
}

#[test]
fn analyze_security_iframe_content_window() {
    let body = r#"<script>
        const sel = window.getSelection();
        const iframeSel = iframe.contentWindow.getSelection();
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionInIframe));
}

#[test]
fn analyze_security_drag_drop_dragstart() {
    let body = r#"<script>
        element.addEventListener("dragstart", (e) => {
            const sel = window.getSelection();
            e.dataTransfer.setData("text", sel.toString());
        });
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionWithDragDrop));
}

#[test]
fn analyze_security_drag_drop_dragover() {
    let body = r#"<script>
        const sel = getSelection();
        element.addEventListener("dragover", handler);
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionWithDragDrop));
}

#[test]
fn analyze_security_drag_drop_drop() {
    let body = r#"<script>
        document.addEventListener("drop", (e) => {
            const sel = window.getSelection();
        });
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionWithDragDrop));
}

#[test]
fn analyze_security_drag_drop_data_transfer() {
    let body = r#"<script>
        const sel = window.getSelection();
        const data = dataTransfer.getData("text");
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionWithDragDrop));
}

#[test]
fn analyze_security_payload_injection_inner_html() {
    let body = r#"<script>
        const sel = window.getSelection();
        element.innerHTML = sel.toString();
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionPayloadInjection));
}

#[test]
fn analyze_security_payload_injection_insert_adjacent() {
    let body = r#"<script>
        const sel = window.getSelection();
        element.insertAdjacentHTML("beforeend", sel.toString());
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionPayloadInjection));
}

#[test]
fn analyze_security_payload_injection_doc_write() {
    let body = r#"<script>
        const sel = window.getSelection();
        document.write(sel.toString());
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionPayloadInjection));
}

#[test]
fn analyze_security_timing_attack_performance_now() {
    let body = r#"<script>
        const start = performance.now();
        const sel = window.getSelection();
        const end = performance.now();
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionTimingAttack));
}

#[test]
fn analyze_security_timing_attack_date_now() {
    let body = r#"<script>
        const start = Date.now();
        const sel = window.getSelection();
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionTimingAttack));
}

#[test]
fn analyze_security_timing_attack_performance_mark() {
    let body = r#"<script>
        performance.mark("sel-start");
        const sel = window.getSelection();
        performance.mark("sel-end");
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionTimingAttack));
}

#[test]
fn analyze_security_cross_origin_post_message() {
    let body = r#"<script>
        const sel = window.getSelection();
        window.parent.postMessage(sel.toString(), "*");
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionCrossOrigin));
}

#[test]
fn analyze_security_cross_origin_keyword() {
    let body = r#"<script>
        // cross-origin access
        const sel = window.getSelection();
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionCrossOrigin));
}

#[test]
fn analyze_security_cross_origin_iframe() {
    let body = r#"<script>
        const sel = window.getSelection();
        const iframe = document.createElement("iframe");
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionCrossOrigin));
}

#[test]
fn analyze_security_password_fields_double_quotes() {
    let body = r#"<input type="password" id="pass">
    <script>
        const sel = window.getSelection();
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionOfPasswordFields));
}

#[test]
fn analyze_security_password_fields_single_quotes() {
    let body = r#"<input type='password' id='pass'>
    <script>
        const sel = window.getSelection();
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionOfPasswordFields));
}

#[test]
fn analyze_security_password_fields_keyword() {
    let body = r#"<script>
        const sel = window.getSelection();
        const password = document.getElementById("pwd");
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionOfPasswordFields));
}

#[test]
fn analyze_security_mutation_observer() {
    let body = r#"<script>
        const sel = window.getSelection();
        const observer = new MutationObserver((mutations) => {
            console.log(mutations);
        });
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionWithMutationObserver));
}

#[test]
fn analyze_security_to_worker_worker() {
    let body = r#"<script>
        const sel = window.getSelection();
        const worker = new Worker("worker.js");
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionToWorker));
}

#[test]
fn analyze_security_to_worker_shared_worker() {
    let body = r#"<script>
        const sel = window.getSelection();
        const worker = new SharedWorker("worker.js");
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionToWorker));
}

#[test]
fn analyze_security_to_worker_post_message() {
    let body = r#"<script>
        const sel = window.getSelection();
        worker.postMessage(sel.toString());
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionToWorker));
}

#[test]
fn analyze_security_screenshot_html2canvas() {
    let body = r#"<script>
        const sel = window.getSelection();
        html2canvas(document.body);
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionScreenshot));
}

#[test]
fn analyze_security_screenshot_to_data_url() {
    let body = r#"<script>
        const sel = window.getSelection();
        canvas.toDataURL();
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionScreenshot));
}

#[test]
fn analyze_security_screenshot_to_blob() {
    let body = r#"<script>
        const sel = window.getSelection();
        canvas.toBlob((blob) => {});
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionScreenshot));
}

#[test]
fn analyze_security_screenshot_capture_stream() {
    let body = r#"<script>
        const sel = window.getSelection();
        const stream = canvas.captureStream();
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionScreenshot));
}

#[test]
fn analyze_security_empty_body() {
    assert!(analyze_selection_security("").is_empty());
}

#[test]
fn analyze_security_multiple_issues() {
    let body = r#"<script>
        const sel = window.getSelection();
        navigator.clipboard.writeText(sel.toString());
        element.innerHTML = sel.toString();
        worker.postMessage(sel.toString());
    </script>"#;
    let issues = analyze_selection_security(body);
    assert!(issues.contains(&SelectionIssue::SelectionToClipboard));
    assert!(issues.contains(&SelectionIssue::SelectionPayloadInjection));
    assert!(issues.contains(&SelectionIssue::SelectionToWorker));
}

#[test]
fn selection_security_to_operations_creates_entries() {
    let issues = vec![
        SelectionIssue::SelectionToClipboard,
        SelectionIssue::SelectionInIframe,
    ];
    let mut seq = 0;
    let ops = selection_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn selection_security_to_operations_empty() {
    let issues = vec![];
    let mut seq = 0;
    let ops = selection_security_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn display_new_variants() {
    assert_eq!(
        SelectionIssue::SelectionToClipboard.to_string(),
        "selection_to_clipboard"
    );
    assert_eq!(
        SelectionIssue::SelectionInIframe.to_string(),
        "selection_in_iframe"
    );
    assert_eq!(
        SelectionIssue::SelectionWithDragDrop.to_string(),
        "selection_with_drag_drop"
    );
    assert_eq!(
        SelectionIssue::SelectionPayloadInjection.to_string(),
        "selection_payload_injection"
    );
    assert_eq!(
        SelectionIssue::SelectionTimingAttack.to_string(),
        "selection_timing_attack"
    );
    assert_eq!(
        SelectionIssue::SelectionCrossOrigin.to_string(),
        "selection_cross_origin"
    );
    assert_eq!(
        SelectionIssue::SelectionOfPasswordFields.to_string(),
        "selection_of_password_fields"
    );
    assert_eq!(
        SelectionIssue::SelectionWithMutationObserver.to_string(),
        "selection_with_mutation_observer"
    );
    assert_eq!(
        SelectionIssue::SelectionToWorker.to_string(),
        "selection_to_worker"
    );
    assert_eq!(
        SelectionIssue::SelectionScreenshot.to_string(),
        "selection_screenshot"
    );
}

#[test]
fn severity_new_variants() {
    assert_eq!(
        selection_severity(&SelectionIssue::SelectionToClipboard),
        6.0
    );
    assert_eq!(selection_severity(&SelectionIssue::SelectionInIframe), 7.5);
    assert_eq!(
        selection_severity(&SelectionIssue::SelectionWithDragDrop),
        5.5
    );
    assert_eq!(
        selection_severity(&SelectionIssue::SelectionPayloadInjection),
        8.0
    );
    assert_eq!(
        selection_severity(&SelectionIssue::SelectionTimingAttack),
        6.0
    );
    assert_eq!(
        selection_severity(&SelectionIssue::SelectionCrossOrigin),
        7.0
    );
    assert_eq!(
        selection_severity(&SelectionIssue::SelectionOfPasswordFields),
        9.0
    );
    assert_eq!(
        selection_severity(&SelectionIssue::SelectionWithMutationObserver),
        5.0
    );
    assert_eq!(selection_severity(&SelectionIssue::SelectionToWorker), 6.5);
    assert_eq!(
        selection_severity(&SelectionIssue::SelectionScreenshot),
        7.5
    );
}

#[test]
fn severity_password_fields_highest() {
    assert_eq!(
        selection_severity(&SelectionIssue::SelectionOfPasswordFields),
        9.0
    );
}

#[test]
fn severity_payload_injection_high() {
    assert_eq!(
        selection_severity(&SelectionIssue::SelectionPayloadInjection),
        8.0
    );
}
