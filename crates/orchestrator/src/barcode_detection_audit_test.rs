use crate::barcode_detection_audit::*;

#[test]
fn no_barcode_no_issues() {
    assert!(analyze_barcode_detection("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api() {
    let body = r#"<script>const detector = new BarcodeDetector();</script>"#;
    let issues = analyze_barcode_detection(body);
    assert!(issues.contains(&BarcodeDetectionIssue::ApiDetected));
}

#[test]
fn detects_camera_access() {
    let body = r#"<script>
        const stream = await navigator.mediaDevices.getUserMedia({video: true});
        const detector = new BarcodeDetector();
    </script>"#;
    let issues = analyze_barcode_detection(body);
    assert!(issues.contains(&BarcodeDetectionIssue::CameraAccess));
}

#[test]
fn no_camera_without_media() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        const barcodes = await detector.detect(imageElement);
    </script>"#;
    let issues = analyze_barcode_detection(body);
    assert!(!issues.contains(&BarcodeDetectionIssue::CameraAccess));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        const barcodes = await detector.detect(frame);
        fetch("/collect", {body: JSON.stringify(barcodes)});
    </script>"#;
    let issues = analyze_barcode_detection(body);
    assert!(issues.contains(&BarcodeDetectionIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        const barcodes = await detector.detect(frame);
        console.log(barcodes);
    </script>"#;
    let issues = analyze_barcode_detection(body);
    assert!(!issues.contains(&BarcodeDetectionIssue::DataExfiltration));
}

#[test]
fn detects_continuous_scanning() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        setInterval(async () => {
            const barcodes = await detector.detect(video);
        }, 100);
    </script>"#;
    let issues = analyze_barcode_detection(body);
    assert!(issues.contains(&BarcodeDetectionIssue::ContinuousScanning));
}

#[test]
fn detects_raf_scanning() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        function scan() {
            detector.detect(video);
            requestAnimationFrame(scan);
        }
    </script>"#;
    let issues = analyze_barcode_detection(body);
    assert!(issues.contains(&BarcodeDetectionIssue::ContinuousScanning));
}

#[test]
fn detects_no_user_activation() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        detector.detect(video);
    </script>"#;
    let issues = analyze_barcode_detection(body);
    assert!(issues.contains(&BarcodeDetectionIssue::NoUserActivation));
}

#[test]
fn no_activation_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const detector = new BarcodeDetector();
            const barcodes = await detector.detect(frame);
        });
    </script>"#;
    let issues = analyze_barcode_detection(body);
    assert!(!issues.contains(&BarcodeDetectionIssue::NoUserActivation));
}

#[test]
fn severity_exfil_highest() {
    assert_eq!(
        barcode_detection_severity(&BarcodeDetectionIssue::DataExfiltration),
        7.0
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(
        barcode_detection_severity(&BarcodeDetectionIssue::ApiDetected),
        2.5
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        BarcodeDetectionIssue::ApiDetected,
        BarcodeDetectionIssue::CameraAccess,
    ];
    let mut seq = 0;
    let ops = barcode_detection_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        BarcodeDetectionIssue::ApiDetected.to_string(),
        "api_detected"
    );
    assert_eq!(
        BarcodeDetectionIssue::CameraAccess.to_string(),
        "camera_access"
    );
    assert_eq!(
        BarcodeDetectionIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
    assert_eq!(
        BarcodeDetectionIssue::ContinuousScanning.to_string(),
        "continuous_scanning"
    );
    assert_eq!(
        BarcodeDetectionIssue::NoUserActivation.to_string(),
        "no_user_activation"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_barcode_detection("").is_empty());
}
