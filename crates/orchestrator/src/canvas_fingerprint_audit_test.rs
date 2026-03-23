use crate::canvas_fingerprint_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_canvas_fingerprint("");
    assert!(issues.is_empty());
}

#[test]
fn no_fingerprint_no_issues() {
    let body = "var x = document.title;";
    let issues = analyze_canvas_fingerprint(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_to_data_url() {
    let body = "canvas.toDataURL('image/png');";
    let issues = analyze_canvas_fingerprint(body);
    assert!(issues.contains(&CanvasFingerprintIssue::CanvasToDataUrl));
}

#[test]
fn detects_get_image_data() {
    let body = "ctx.getImageData(0, 0, 100, 100);";
    let issues = analyze_canvas_fingerprint(body);
    assert!(issues.contains(&CanvasFingerprintIssue::CanvasGetImageData));
}

#[test]
fn detects_webgl_renderer() {
    let body = "gl.getExtension('WEBGL_debug_renderer_info');";
    let issues = analyze_canvas_fingerprint(body);
    assert!(issues.contains(&CanvasFingerprintIssue::WebGlRendererInfo));
}

#[test]
fn detects_unmasked_renderer() {
    let body = "gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);";
    let issues = analyze_canvas_fingerprint(body);
    assert!(issues.contains(&CanvasFingerprintIssue::WebGlRendererInfo));
}

#[test]
fn detects_unmasked_vendor() {
    let body = "gl.getParameter(ext.UNMASKED_VENDOR_WEBGL);";
    let issues = analyze_canvas_fingerprint(body);
    assert!(issues.contains(&CanvasFingerprintIssue::WebGlRendererInfo));
}

#[test]
fn detects_text_measurement_fingerprint() {
    let body = r#"
        ctx.fillText("test", 0, 0);
        ctx.measureText("test");
        canvas.toDataURL();
    "#;
    let issues = analyze_canvas_fingerprint(body);
    assert!(issues.contains(&CanvasFingerprintIssue::CanvasTextMeasurement));
}

#[test]
fn no_text_measurement_without_to_data_url() {
    let body = "ctx.measureText('test');";
    let issues = analyze_canvas_fingerprint(body);
    assert!(!issues.contains(&CanvasFingerprintIssue::CanvasTextMeasurement));
}

#[test]
fn detects_audio_fingerprint() {
    let body = r#"
        var ctx = new AudioContext();
        var osc = ctx.createOscillator();
    "#;
    let issues = analyze_canvas_fingerprint(body);
    assert!(issues.contains(&CanvasFingerprintIssue::AudioContextFingerprint));
}

#[test]
fn detects_offline_audio_fingerprint() {
    let body = r#"
        var ctx = new OfflineAudioContext(1, 44100, 44100);
        var comp = ctx.createDynamicsCompressor();
    "#;
    let issues = analyze_canvas_fingerprint(body);
    assert!(issues.contains(&CanvasFingerprintIssue::AudioContextFingerprint));
}

#[test]
fn no_audio_fingerprint_without_nodes() {
    let body = "var ctx = new AudioContext();";
    let issues = analyze_canvas_fingerprint(body);
    assert!(!issues.contains(&CanvasFingerprintIssue::AudioContextFingerprint));
}

#[test]
fn detects_font_enumeration() {
    let body = r#"
        document.fonts.forEach(font => {});
    "#;
    let issues = analyze_canvas_fingerprint(body);
    assert!(issues.contains(&CanvasFingerprintIssue::FontEnumeration));
}

#[test]
fn detects_font_check() {
    let body = r#"document.fonts.check("16px Arial");"#;
    let issues = analyze_canvas_fingerprint(body);
    assert!(issues.contains(&CanvasFingerprintIssue::FontEnumeration));
}

#[test]
fn detects_canvas_data_sent() {
    let body = r#"
        var data = canvas.toDataURL();
        fetch('/fingerprint', {body: data});
    "#;
    let issues = analyze_canvas_fingerprint(body);
    assert!(issues.contains(&CanvasFingerprintIssue::CanvasDataSent));
}

#[test]
fn no_data_sent_without_network() {
    let body = "var data = canvas.toDataURL(); console.log(data);";
    let issues = analyze_canvas_fingerprint(body);
    assert!(!issues.contains(&CanvasFingerprintIssue::CanvasDataSent));
}

#[test]
fn severity_data_sent_highest() {
    assert_eq!(
        canvas_fingerprint_severity(&CanvasFingerprintIssue::CanvasDataSent),
        7.0
    );
}

#[test]
fn severity_get_image_data_lowest() {
    assert_eq!(
        canvas_fingerprint_severity(&CanvasFingerprintIssue::CanvasGetImageData),
        4.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        CanvasFingerprintIssue::CanvasToDataUrl,
        CanvasFingerprintIssue::WebGlRendererInfo,
    ];
    let mut seq = 0;
    let ops = canvas_fingerprint_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        CanvasFingerprintIssue::CanvasToDataUrl.to_string(),
        "canvas_to_data_url"
    );
    assert_eq!(
        CanvasFingerprintIssue::CanvasGetImageData.to_string(),
        "canvas_get_image_data"
    );
    assert_eq!(
        CanvasFingerprintIssue::WebGlRendererInfo.to_string(),
        "webgl_renderer_info"
    );
    assert_eq!(
        CanvasFingerprintIssue::CanvasTextMeasurement.to_string(),
        "canvas_text_measurement"
    );
    assert_eq!(
        CanvasFingerprintIssue::AudioContextFingerprint.to_string(),
        "audio_fingerprint"
    );
    assert_eq!(
        CanvasFingerprintIssue::FontEnumeration.to_string(),
        "font_enumeration"
    );
    assert_eq!(
        CanvasFingerprintIssue::CanvasDataSent.to_string(),
        "canvas_data_sent"
    );
}
