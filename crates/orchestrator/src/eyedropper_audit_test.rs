use crate::eyedropper_audit::*;

#[test]
fn no_eyedropper_no_issues() {
    assert!(analyze_eyedropper("<html></html>").is_empty());
}

#[test]
fn detects_api() {
    let body = r#"<script>const ed = new EyeDropper();</script>"#;
    let issues = analyze_eyedropper(body);
    assert!(issues.contains(&EyeDropperIssue::ApiDetected));
}

#[test]
fn detects_color_exfiltration() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const result = await ed.open();
        fetch("/track?color=" + result.sRGBHex);
    </script>"#;
    let issues = analyze_eyedropper(body);
    assert!(issues.contains(&EyeDropperIssue::ColorExfiltration));
}

#[test]
fn no_exfiltration_without_fetch() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const result = await ed.open();
        console.log(result.sRGBHex);
    </script>"#;
    let issues = analyze_eyedropper(body);
    assert!(!issues.contains(&EyeDropperIssue::ColorExfiltration));
}

#[test]
fn detects_no_user_activation() {
    let body = r#"<script>
        const ed = new EyeDropper();
        ed.open();
    </script>"#;
    let issues = analyze_eyedropper(body);
    assert!(issues.contains(&EyeDropperIssue::NoUserActivation));
}

#[test]
fn no_activation_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const ed = new EyeDropper();
            await ed.open();
        });
    </script>"#;
    let issues = analyze_eyedropper(body);
    assert!(!issues.contains(&EyeDropperIssue::NoUserActivation));
}

#[test]
fn detects_looped_picking() {
    let body = r#"<script>
        setInterval(async () => {
            const ed = new EyeDropper();
            await ed.open();
        }, 1000);
    </script>"#;
    let issues = analyze_eyedropper(body);
    assert!(issues.contains(&EyeDropperIssue::LoopedPicking));
}

#[test]
fn detects_pixel_data_access() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const result = await ed.open();
        const hex = result.sRGBHex;
    </script>"#;
    let issues = analyze_eyedropper(body);
    assert!(issues.contains(&EyeDropperIssue::PixelDataAccess));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(eyedropper_severity(&EyeDropperIssue::ColorExfiltration), 6.0);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(eyedropper_severity(&EyeDropperIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![EyeDropperIssue::ApiDetected, EyeDropperIssue::PixelDataAccess];
    let mut seq = 0;
    let ops = eyedropper_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(EyeDropperIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(EyeDropperIssue::ColorExfiltration.to_string(), "color_exfiltration");
    assert_eq!(EyeDropperIssue::NoUserActivation.to_string(), "no_user_activation");
    assert_eq!(EyeDropperIssue::LoopedPicking.to_string(), "looped_picking");
    assert_eq!(EyeDropperIssue::PixelDataAccess.to_string(), "pixel_data_access");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_eyedropper("").is_empty());
}
