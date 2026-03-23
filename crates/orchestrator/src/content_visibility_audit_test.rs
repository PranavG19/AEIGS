use crate::content_visibility_audit::*;

#[test]
fn test_api_detected_css_property() {
    let body = r#"<style>.lazy { content-visibility: auto; }</style>"#;
    let issues = analyze_content_visibility(body);
    assert_eq!(issues, vec![ContentVisibilityIssue::ApiDetected]);
}

#[test]
fn test_api_detected_js_property() {
    let body = r#"<script>el.style.contentVisibility = 'auto';</script>"#;
    let issues = analyze_content_visibility(body);
    assert_eq!(issues, vec![ContentVisibilityIssue::ApiDetected]);
}

#[test]
fn test_api_detected_contain_intrinsic_size() {
    let body = r#"<style>.box { contain-intrinsic-size: 500px; }</style>"#;
    let issues = analyze_content_visibility(body);
    assert_eq!(issues, vec![ContentVisibilityIssue::ApiDetected]);
}

#[test]
fn test_hidden_content_xss_innerhtml() {
    let body = r#"
        <style>.hidden { content-visibility: hidden; }</style>
        <script>div.innerHTML = userInput;</script>
    "#;
    let issues = analyze_content_visibility(body);
    assert!(issues.contains(&ContentVisibilityIssue::ApiDetected));
    assert!(issues.contains(&ContentVisibilityIssue::HiddenContentXss));
}

#[test]
fn test_hidden_content_xss_insert_adjacent() {
    let body = r#"
        <style>.item { content-visibility:hidden; }</style>
        <script>el.insertAdjacentHTML('beforeend', data);</script>
    "#;
    let issues = analyze_content_visibility(body);
    assert!(issues.contains(&ContentVisibilityIssue::HiddenContentXss));
}

#[test]
fn test_hidden_content_xss_document_write() {
    let body = r#"
        <style>div { content-visibility: hidden; }</style>
        <script>document.write(html);</script>
    "#;
    let issues = analyze_content_visibility(body);
    assert!(issues.contains(&ContentVisibilityIssue::HiddenContentXss));
}

#[test]
fn test_rendering_timing_leak_intersection_observer() {
    let body = r#"
        <style>.lazy { content-visibility: auto; }</style>
        <script>
            const observer = new IntersectionObserver(() => {
                const start = performance.now();
            });
        </script>
    "#;
    let issues = analyze_content_visibility(body);
    assert!(issues.contains(&ContentVisibilityIssue::RenderingTimingLeak));
}

#[test]
fn test_rendering_timing_leak_state_change() {
    let body = r#"
        <style>.box { content-visibility: auto; }</style>
        <script>
            el.addEventListener('contentvisibilityautostatechange', () => {
                const t = Date.now();
            });
        </script>
    "#;
    let issues = analyze_content_visibility(body);
    assert!(issues.contains(&ContentVisibilityIssue::RenderingTimingLeak));
}

#[test]
fn test_content_exfiltration_mutation_observer_fetch() {
    let body = r#"
        <style>.offscreen { content-visibility: auto; }</style>
        <script>
            const mo = new MutationObserver(() => {
                fetch('/log', {method: 'POST'});
            });
        </script>
    "#;
    let issues = analyze_content_visibility(body);
    assert!(issues.contains(&ContentVisibilityIssue::ContentExfiltration));
}

#[test]
fn test_content_exfiltration_query_selector_beacon() {
    let body = r#"
        <style>div { content-visibility: auto; }</style>
        <script>
            const nodes = document.querySelectorAll('.hidden');
            navigator.sendBeacon('/track', data);
        </script>
    "#;
    let issues = analyze_content_visibility(body);
    assert!(issues.contains(&ContentVisibilityIssue::ContentExfiltration));
}

#[test]
fn test_security_control_bypass_captcha() {
    let body = r#"
        <style>.captcha { content-visibility: auto; }</style>
        <div class="captcha">reCAPTCHA</div>
    "#;
    let issues = analyze_content_visibility(body);
    assert!(issues.contains(&ContentVisibilityIssue::SecurityControlBypass));
}

#[test]
fn test_security_control_bypass_csrf() {
    let body = r#"
        <style>input { content-visibility: hidden; }</style>
        <input type="hidden" name="csrf_token" />
    "#;
    let issues = analyze_content_visibility(body);
    assert!(issues.contains(&ContentVisibilityIssue::SecurityControlBypass));
}

#[test]
fn test_security_control_bypass_consent() {
    let body = r#"
        <style>.banner { content-visibility: auto; }</style>
        <div class="consent">Cookie Consent Banner</div>
    "#;
    let issues = analyze_content_visibility(body);
    assert!(issues.contains(&ContentVisibilityIssue::SecurityControlBypass));
}

#[test]
fn test_security_control_bypass_warning() {
    let body = r#"
        <style>.alert { content-visibility: hidden; }</style>
        <div class="security-warning">Important security warning</div>
    "#;
    let issues = analyze_content_visibility(body);
    assert!(issues.contains(&ContentVisibilityIssue::SecurityControlBypass));
}

#[test]
fn test_no_issues_clean_page() {
    let body = r#"<html><body><h1>Hello World</h1></body></html>"#;
    let issues = analyze_content_visibility(body);
    assert!(issues.is_empty());
}

#[test]
fn test_multiple_issues_detected() {
    let body = r#"
        <style>
            .lazy { content-visibility: auto; }
            .hidden { content-visibility: hidden; }
        </style>
        <script>
            const observer = new IntersectionObserver(() => {});
            div.innerHTML = userInput;
            const t = performance.now();
            const mo = new MutationObserver(() => {});
            document.querySelectorAll('.data');
            fetch('/exfil', {method: 'POST'});
        </script>
        <div class="captcha">Verify you are human</div>
    "#;
    let issues = analyze_content_visibility(body);
    assert!(issues.contains(&ContentVisibilityIssue::ApiDetected));
    assert!(issues.contains(&ContentVisibilityIssue::HiddenContentXss));
    assert!(issues.contains(&ContentVisibilityIssue::RenderingTimingLeak));
    assert!(issues.contains(&ContentVisibilityIssue::ContentExfiltration));
    assert!(issues.contains(&ContentVisibilityIssue::SecurityControlBypass));
}

#[test]
fn test_severity_scores() {
    assert_eq!(content_visibility_severity(&ContentVisibilityIssue::ApiDetected), 2.0);
    assert_eq!(content_visibility_severity(&ContentVisibilityIssue::HiddenContentXss), 7.5);
    assert_eq!(content_visibility_severity(&ContentVisibilityIssue::RenderingTimingLeak), 6.5);
    assert_eq!(content_visibility_severity(&ContentVisibilityIssue::ContentExfiltration), 7.0);
    assert_eq!(content_visibility_severity(&ContentVisibilityIssue::SecurityControlBypass), 6.0);
}

#[test]
fn test_to_operations() {
    let issues = vec![
        ContentVisibilityIssue::ApiDetected,
        ContentVisibilityIssue::HiddenContentXss,
    ];
    let mut seq = 100;
    let ops = content_visibility_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 102);
}

#[test]
fn test_display_trait() {
    assert_eq!(ContentVisibilityIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(ContentVisibilityIssue::HiddenContentXss.to_string(), "hidden_content_xss");
    assert_eq!(ContentVisibilityIssue::RenderingTimingLeak.to_string(), "rendering_timing_leak");
    assert_eq!(ContentVisibilityIssue::ContentExfiltration.to_string(), "content_exfiltration");
    assert_eq!(ContentVisibilityIssue::SecurityControlBypass.to_string(), "security_control_bypass");
}
