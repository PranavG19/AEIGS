use crate::window_controls_overlay_audit::*;

#[test]
fn no_wco_no_issues() {
    assert!(analyze_window_controls_overlay("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_manifest_display_mode() {
    let body = r#"{"display_override": ["window-controls-overlay"]}"#;
    let issues = analyze_window_controls_overlay(body);
    assert!(issues.contains(&WindowControlsOverlayIssue::ApiDetected));
}

#[test]
fn detects_js_api() {
    let body = r#"<script>navigator.windowControlsOverlay.visible;</script>"#;
    let issues = analyze_window_controls_overlay(body);
    assert!(issues.contains(&WindowControlsOverlayIssue::ApiDetected));
}

#[test]
fn detects_titlebar_area_rect() {
    let body = r#"<script>const rect = navigator.windowControlsOverlay.titlebarAreaRect;</script>"#;
    let issues = analyze_window_controls_overlay(body);
    assert!(issues.contains(&WindowControlsOverlayIssue::ApiDetected));
}

#[test]
fn detects_ui_spoofing() {
    let body = r#"
        {"display_override": ["window-controls-overlay"]}
        <style>.titlebar { position: absolute; top: 0; left: env(titlebar-area-x); }</style>
    "#;
    let issues = analyze_window_controls_overlay(body);
    assert!(issues.contains(&WindowControlsOverlayIssue::UiSpoofing));
}

#[test]
fn detects_ui_spoofing_fixed() {
    let body = r#"
        {"display_override": ["window-controls-overlay"]}
        <style>.titlebar { position: fixed; top:0; }</style>
    "#;
    let issues = analyze_window_controls_overlay(body);
    assert!(issues.contains(&WindowControlsOverlayIssue::UiSpoofing));
}

#[test]
fn no_spoofing_without_positioning() {
    let body = r#"{"display_override": ["window-controls-overlay"]}"#;
    let issues = analyze_window_controls_overlay(body);
    assert!(!issues.contains(&WindowControlsOverlayIssue::UiSpoofing));
}

#[test]
fn detects_clickjacking_risk() {
    let body = r#"<script>
        navigator.windowControlsOverlay.visible;
    </script>
    <style>.titlebar { pointer-events: none; z-index: 999; }</style>"#;
    let issues = analyze_window_controls_overlay(body);
    assert!(issues.contains(&WindowControlsOverlayIssue::ClickjackingRisk));
}

#[test]
fn no_clickjacking_without_pointer_events() {
    let body = r#"<script>navigator.windowControlsOverlay.visible;</script>"#;
    let issues = analyze_window_controls_overlay(body);
    assert!(!issues.contains(&WindowControlsOverlayIssue::ClickjackingRisk));
}

#[test]
fn detects_geometry_tracking() {
    let body = r#"<script>
        navigator.windowControlsOverlay.addEventListener("geometrychange", (e) => {
            track(e.titlebarAreaRect);
        });
    </script>"#;
    let issues = analyze_window_controls_overlay(body);
    assert!(issues.contains(&WindowControlsOverlayIssue::GeometryTracking));
}

#[test]
fn no_geometry_without_event() {
    let body = r#"<script>navigator.windowControlsOverlay.visible;</script>"#;
    let issues = analyze_window_controls_overlay(body);
    assert!(!issues.contains(&WindowControlsOverlayIssue::GeometryTracking));
}

#[test]
fn detects_dynamic_titlebar() {
    let body = r#"<script>
        setInterval(() => {
            const rect = navigator.windowControlsOverlay.titlebarAreaRect;
            updateLayout(rect);
        }, 100);
    </script>"#;
    let issues = analyze_window_controls_overlay(body);
    assert!(issues.contains(&WindowControlsOverlayIssue::DynamicTitlebar));
}

#[test]
fn detects_dynamic_titlebar_raf() {
    let body = r#"<script>
        function update() {
            const rect = navigator.windowControlsOverlay.titlebarAreaRect;
            requestAnimationFrame(update);
        }
    </script>"#;
    let issues = analyze_window_controls_overlay(body);
    assert!(issues.contains(&WindowControlsOverlayIssue::DynamicTitlebar));
}

#[test]
fn no_dynamic_without_polling() {
    let body = r#"<script>const rect = navigator.windowControlsOverlay.titlebarAreaRect;</script>"#;
    let issues = analyze_window_controls_overlay(body);
    assert!(!issues.contains(&WindowControlsOverlayIssue::DynamicTitlebar));
}

#[test]
fn severity_spoofing_highest() {
    assert_eq!(
        window_controls_overlay_severity(&WindowControlsOverlayIssue::UiSpoofing),
        7.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(
        window_controls_overlay_severity(&WindowControlsOverlayIssue::ApiDetected),
        2.5
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        WindowControlsOverlayIssue::ApiDetected,
        WindowControlsOverlayIssue::UiSpoofing,
    ];
    let mut seq = 0;
    let ops = window_controls_overlay_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        WindowControlsOverlayIssue::ApiDetected.to_string(),
        "api_detected"
    );
    assert_eq!(
        WindowControlsOverlayIssue::UiSpoofing.to_string(),
        "ui_spoofing"
    );
    assert_eq!(
        WindowControlsOverlayIssue::ClickjackingRisk.to_string(),
        "clickjacking_risk"
    );
    assert_eq!(
        WindowControlsOverlayIssue::GeometryTracking.to_string(),
        "geometry_tracking"
    );
    assert_eq!(
        WindowControlsOverlayIssue::DynamicTitlebar.to_string(),
        "dynamic_titlebar"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_window_controls_overlay("").is_empty());
}
