use crate::shape_detection_audit::*;

#[test]
fn no_shape_no_issues() {
    assert!(analyze_shape_detection("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_face_detector() {
    let body = r#"<script>const fd = new FaceDetector();</script>"#;
    let issues = analyze_shape_detection(body);
    assert!(issues.contains(&ShapeDetectionIssue::ApiDetected));
    assert!(issues.contains(&ShapeDetectionIssue::FaceDetection));
}

#[test]
fn detects_text_detector() {
    let body = r#"<script>const td = new TextDetector();</script>"#;
    let issues = analyze_shape_detection(body);
    assert!(issues.contains(&ShapeDetectionIssue::ApiDetected));
    assert!(issues.contains(&ShapeDetectionIssue::TextOcr));
}

#[test]
fn detects_barcode_only() {
    let body = r#"<script>const bd = new BarcodeDetector();</script>"#;
    let issues = analyze_shape_detection(body);
    assert!(issues.contains(&ShapeDetectionIssue::ApiDetected));
    assert!(!issues.contains(&ShapeDetectionIssue::FaceDetection));
    assert!(!issues.contains(&ShapeDetectionIssue::TextOcr));
}

#[test]
fn detects_camera_access() {
    let body = r#"<script>
        const stream = await navigator.mediaDevices.getUserMedia({video: true});
        const fd = new FaceDetector();
    </script>"#;
    let issues = analyze_shape_detection(body);
    assert!(issues.contains(&ShapeDetectionIssue::CameraAccess));
}

#[test]
fn no_camera_without_media() {
    let body = r#"<script>const fd = new FaceDetector(); fd.detect(img);</script>"#;
    let issues = analyze_shape_detection(body);
    assert!(!issues.contains(&ShapeDetectionIssue::CameraAccess));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        const fd = new FaceDetector();
        const faces = await fd.detect(img);
        fetch("/collect", {body: JSON.stringify(faces)});
    </script>"#;
    let issues = analyze_shape_detection(body);
    assert!(issues.contains(&ShapeDetectionIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const fd = new FaceDetector();
        const faces = await fd.detect(img);
        console.log(faces);
    </script>"#;
    let issues = analyze_shape_detection(body);
    assert!(!issues.contains(&ShapeDetectionIssue::DataExfiltration));
}

#[test]
fn detects_continuous_detection() {
    let body = r#"<script>
        const fd = new FaceDetector();
        setInterval(async () => {
            const faces = await fd.detect(video);
        }, 100);
    </script>"#;
    let issues = analyze_shape_detection(body);
    assert!(issues.contains(&ShapeDetectionIssue::ContinuousDetection));
}

#[test]
fn detects_raf_loop() {
    let body = r#"<script>
        const td = new TextDetector();
        function scan() {
            td.detect(video);
            requestAnimationFrame(scan);
        }
    </script>"#;
    let issues = analyze_shape_detection(body);
    assert!(issues.contains(&ShapeDetectionIssue::ContinuousDetection));
}

#[test]
fn severity_face_highest() {
    assert_eq!(shape_detection_severity(&ShapeDetectionIssue::FaceDetection), 7.5);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(shape_detection_severity(&ShapeDetectionIssue::ApiDetected), 2.5);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![ShapeDetectionIssue::ApiDetected, ShapeDetectionIssue::FaceDetection];
    let mut seq = 0;
    let ops = shape_detection_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(ShapeDetectionIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(ShapeDetectionIssue::FaceDetection.to_string(), "face_detection");
    assert_eq!(ShapeDetectionIssue::TextOcr.to_string(), "text_ocr");
    assert_eq!(ShapeDetectionIssue::CameraAccess.to_string(), "camera_access");
    assert_eq!(ShapeDetectionIssue::DataExfiltration.to_string(), "data_exfiltration");
    assert_eq!(ShapeDetectionIssue::ContinuousDetection.to_string(), "continuous_detection");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_shape_detection("").is_empty());
}
