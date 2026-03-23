use crate::ink_api_audit::*;

#[test]
fn no_ink_no_issues() {
    assert!(analyze_ink_api("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_navigator_ink() {
    let body = r#"<script>const presenter = await navigator.ink.requestPresenter({});</script>"#;
    let issues = analyze_ink_api(body);
    assert!(issues.contains(&InkApiIssue::ApiDetected));
}

#[test]
fn detects_api_ink_presenter() {
    let body = r#"<script>if (window.InkPresenter) {}</script>"#;
    let issues = analyze_ink_api(body);
    assert!(issues.contains(&InkApiIssue::ApiDetected));
}

#[test]
fn detects_input_tracking() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        canvas.addEventListener("pointermove", (e) => p.updateInkTrailStartPoint(e));
    </script>"#;
    let issues = analyze_ink_api(body);
    assert!(issues.contains(&InkApiIssue::InputTracking));
}

#[test]
fn no_tracking_without_events() {
    let body = r#"<script>const p = await navigator.ink.requestPresenter({});</script>"#;
    let issues = analyze_ink_api(body);
    assert!(!issues.contains(&InkApiIssue::InputTracking));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        fetch("/collect", {body: JSON.stringify(points)});
    </script>"#;
    let issues = analyze_ink_api(body);
    assert!(issues.contains(&InkApiIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        console.log(p);
    </script>"#;
    let issues = analyze_ink_api(body);
    assert!(!issues.contains(&InkApiIssue::DataExfiltration));
}

#[test]
fn detects_continuous_capture() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        requestAnimationFrame(function draw() {
            ctx.stroke();
            requestAnimationFrame(draw);
        });
    </script>"#;
    let issues = analyze_ink_api(body);
    assert!(issues.contains(&InkApiIssue::ContinuousCapture));
}

#[test]
fn detects_canvas_fingerprinting() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({presentationArea: canvas});
        const data = canvas.toDataURL();
    </script>"#;
    let issues = analyze_ink_api(body);
    assert!(issues.contains(&InkApiIssue::CanvasFingerprinting));
}

#[test]
fn no_fingerprint_without_canvas_export() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({presentationArea: canvas});
    </script>"#;
    let issues = analyze_ink_api(body);
    assert!(!issues.contains(&InkApiIssue::CanvasFingerprinting));
}

#[test]
fn severity_exfil_highest() {
    assert_eq!(ink_api_severity(&InkApiIssue::DataExfiltration), 6.5);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(ink_api_severity(&InkApiIssue::ApiDetected), 2.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![InkApiIssue::ApiDetected, InkApiIssue::InputTracking];
    let mut seq = 0;
    let ops = ink_api_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(InkApiIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(InkApiIssue::InputTracking.to_string(), "input_tracking");
    assert_eq!(InkApiIssue::DataExfiltration.to_string(), "data_exfiltration");
    assert_eq!(InkApiIssue::ContinuousCapture.to_string(), "continuous_capture");
    assert_eq!(InkApiIssue::CanvasFingerprinting.to_string(), "canvas_fingerprinting");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_ink_api("").is_empty());
}
