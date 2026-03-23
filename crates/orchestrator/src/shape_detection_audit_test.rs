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
    assert_eq!(
        shape_detection_severity(&ShapeDetectionIssue::FaceDetection),
        7.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(
        shape_detection_severity(&ShapeDetectionIssue::ApiDetected),
        2.5
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        ShapeDetectionIssue::ApiDetected,
        ShapeDetectionIssue::FaceDetection,
    ];
    let mut seq = 0;
    let ops = shape_detection_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(ShapeDetectionIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        ShapeDetectionIssue::FaceDetection.to_string(),
        "face_detection"
    );
    assert_eq!(ShapeDetectionIssue::TextOcr.to_string(), "text_ocr");
    assert_eq!(
        ShapeDetectionIssue::CameraAccess.to_string(),
        "camera_access"
    );
    assert_eq!(
        ShapeDetectionIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
    assert_eq!(
        ShapeDetectionIssue::ContinuousDetection.to_string(),
        "continuous_detection"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_shape_detection("").is_empty());
}

// ===== ShapeDetectionSecurityIssue Tests =====

#[test]
fn security_empty_body_no_issues() {
    assert!(analyze_shape_detection_security("").is_empty());
}

#[test]
fn security_no_shape_apis_no_issues() {
    let body = r#"<html><body>hello world</body></html>"#;
    assert!(analyze_shape_detection_security(body).is_empty());
}

#[test]
fn security_detects_face_surveillance() {
    let body = r#"<script>
        const fd = new FaceDetector();
        const faces = await fd.detect(video);
        trackUser(faces);
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::FaceDetectionSurveillance));
}

#[test]
fn security_detects_face_surveillance_monitor() {
    let body = r#"<script>
        const fd = new FaceDetector();
        monitor(await fd.detect(img));
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::FaceDetectionSurveillance));
}

#[test]
fn security_detects_face_surveillance_watchlist() {
    let body = r#"<script>
        const fd = new FaceDetector();
        checkWatchlist(await fd.detect(frame));
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::FaceDetectionSurveillance));
}

#[test]
fn security_no_surveillance_without_keywords() {
    let body = r#"<script>
        const fd = new FaceDetector();
        const faces = await fd.detect(img);
        console.log(faces);
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(!issues.contains(&ShapeDetectionSecurityIssue::FaceDetectionSurveillance));
}

#[test]
fn security_detects_face_data_exfiltration_fetch() {
    let body = r#"<script>
        const fd = new FaceDetector();
        const faces = await fd.detect(img);
        fetch("/api/track", {body: JSON.stringify(faces)});
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::FaceDataExfiltration));
}

#[test]
fn security_detects_face_data_exfiltration_xhr() {
    let body = r#"<script>
        const fd = new FaceDetector();
        const faces = await fd.detect(img);
        const xhr = new XMLHttpRequest();
        xhr.send(faces);
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::FaceDataExfiltration));
}

#[test]
fn security_detects_face_data_exfiltration_beacon() {
    let body = r#"<script>
        const fd = new FaceDetector();
        const data = await fd.detect(video);
        navigator.sendBeacon("/log", data);
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::FaceDataExfiltration));
}

#[test]
fn security_detects_face_data_exfiltration_websocket() {
    let body = r#"<script>
        const fd = new FaceDetector();
        const ws = new WebSocket("wss://track.example.com");
        ws.send(await fd.detect(img));
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::FaceDataExfiltration));
}

#[test]
fn security_no_exfiltration_without_network() {
    let body = r#"<script>
        const fd = new FaceDetector();
        const faces = await fd.detect(img);
        displayFaces(faces);
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(!issues.contains(&ShapeDetectionSecurityIssue::FaceDataExfiltration));
}

#[test]
fn security_detects_face_without_consent() {
    let body = r#"<script>
        const fd = new FaceDetector();
        const faces = await fd.detect(video);
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::FaceDetectionWithoutConsent));
}

#[test]
fn security_no_consent_issue_when_permission_present() {
    let body = r#"<script>
        if (await requestPermission()) {
            const fd = new FaceDetector();
            fd.detect(img);
        }
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(!issues.contains(&ShapeDetectionSecurityIssue::FaceDetectionWithoutConsent));
}

#[test]
fn security_no_consent_issue_with_consent_keyword() {
    let body = r#"<script>
        if (userConsent) {
            const fd = new FaceDetector();
            fd.detect(video);
        }
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(!issues.contains(&ShapeDetectionSecurityIssue::FaceDetectionWithoutConsent));
}

#[test]
fn security_no_consent_issue_with_agree_keyword() {
    let body = r#"<script>
        if (userAgree()) {
            new FaceDetector().detect(img);
        }
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(!issues.contains(&ShapeDetectionSecurityIssue::FaceDetectionWithoutConsent));
}

#[test]
fn security_detects_text_recognition_privacy_password() {
    let body = r#"<script>
        const td = new TextDetector();
        const text = await td.detect(passwordField);
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::TextRecognitionPrivacy));
}

#[test]
fn security_detects_text_recognition_privacy_credit() {
    let body = r#"<script>
        const td = new TextDetector();
        scanCreditCard(await td.detect(img));
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::TextRecognitionPrivacy));
}

#[test]
fn security_detects_text_recognition_privacy_ssn() {
    let body = r#"<script>
        const td = new TextDetector();
        extractSSN(await td.detect(document));
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::TextRecognitionPrivacy));
}

#[test]
fn security_detects_text_recognition_privacy_sensitive() {
    let body = r#"<script>
        const td = new TextDetector();
        readSensitiveData(await td.detect(canvas));
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::TextRecognitionPrivacy));
}

#[test]
fn security_no_text_privacy_without_sensitive_keywords() {
    let body = r#"<script>
        const td = new TextDetector();
        const text = await td.detect(img);
        console.log(text);
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(!issues.contains(&ShapeDetectionSecurityIssue::TextRecognitionPrivacy));
}

#[test]
fn security_detects_face_fingerprinting() {
    let body = r#"<script>
        const fd = new FaceDetector();
        const faces = await fd.detect(img);
        fingerprintUser(faces);
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::FaceRecognitionFingerprinting));
}

#[test]
fn security_detects_face_fingerprinting_identity() {
    let body = r#"<script>
        const fd = new FaceDetector();
        verifyIdentity(await fd.detect(video));
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::FaceRecognitionFingerprinting));
}

#[test]
fn security_detects_face_fingerprinting_recognize() {
    let body = r#"<script>
        const fd = new FaceDetector();
        recognizeUser(await fd.detect(img));
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::FaceRecognitionFingerprinting));
}

#[test]
fn security_detects_face_fingerprinting_match() {
    let body = r#"<script>
        const fd = new FaceDetector();
        matchFace(await fd.detect(img));
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::FaceRecognitionFingerprinting));
}

#[test]
fn security_detects_shape_in_iframe() {
    let body = r#"<iframe src="scan.html"></iframe>
    <script>
        const fd = new FaceDetector();
        fd.detect(img);
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::ShapeDetectionInIframe));
}

#[test]
fn security_detects_shape_in_iframe_content_window() {
    let body = r#"<script>
        const fd = new FaceDetector();
        iframe.contentWindow.postMessage(await fd.detect(img));
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::ShapeDetectionInIframe));
}

#[test]
fn security_detects_shape_in_iframe_post_message() {
    let body = r#"<script>
        const td = new TextDetector();
        parent.postMessage(await td.detect(doc), "*");
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::ShapeDetectionInIframe));
}

#[test]
fn security_no_iframe_issue_without_iframe_context() {
    let body = r#"<script>
        const fd = new FaceDetector();
        const faces = await fd.detect(img);
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(!issues.contains(&ShapeDetectionSecurityIssue::ShapeDetectionInIframe));
}

#[test]
fn security_detects_face_persistence_local_storage() {
    let body = r#"<script>
        const fd = new FaceDetector();
        const faces = await fd.detect(img);
        localStorage.setItem("faces", JSON.stringify(faces));
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::FaceDataPersistence));
}

#[test]
fn security_detects_face_persistence_session_storage() {
    let body = r#"<script>
        const fd = new FaceDetector();
        sessionStorage.faces = await fd.detect(img);
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::FaceDataPersistence));
}

#[test]
fn security_detects_face_persistence_indexeddb() {
    let body = r#"<script>
        const fd = new FaceDetector();
        const db = indexedDB.open("facedb");
        db.add(await fd.detect(img));
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::FaceDataPersistence));
}

#[test]
fn security_no_persistence_without_storage() {
    let body = r#"<script>
        const fd = new FaceDetector();
        const faces = await fd.detect(img);
        console.log(faces);
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(!issues.contains(&ShapeDetectionSecurityIssue::FaceDataPersistence));
}

#[test]
fn security_detects_continuous_face_detection_interval() {
    let body = r#"<script>
        const fd = new FaceDetector();
        setInterval(async () => {
            await fd.detect(video);
        }, 100);
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::ContinuousFaceDetection));
}

#[test]
fn security_detects_continuous_face_detection_raf() {
    let body = r#"<script>
        const fd = new FaceDetector();
        function loop() {
            fd.detect(stream);
            requestAnimationFrame(loop);
        }
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::ContinuousFaceDetection));
}

#[test]
fn security_detects_continuous_face_detection_while() {
    let body = r#"<script>
        const fd = new FaceDetector();
        while(running) {
            await fd.detect(video);
        }
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::ContinuousFaceDetection));
}

#[test]
fn security_no_continuous_without_loop() {
    let body = r#"<script>
        const fd = new FaceDetector();
        const faces = await fd.detect(img);
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(!issues.contains(&ShapeDetectionSecurityIssue::ContinuousFaceDetection));
}

#[test]
fn security_detects_face_with_geolocation() {
    let body = r#"<script>
        const fd = new FaceDetector();
        const faces = await fd.detect(img);
        const pos = await navigator.geolocation.getCurrentPosition();
        log(faces, pos);
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::FaceDetectionWithGeolocation));
}

#[test]
fn security_detects_face_with_geolocation_watch() {
    let body = r#"<script>
        const fd = new FaceDetector();
        navigator.geolocation.watchPosition(pos => {
            fd.detect(video);
        });
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::FaceDetectionWithGeolocation));
}

#[test]
fn security_detects_face_with_geolocation_coords() {
    let body = r#"<script>
        const fd = new FaceDetector();
        const faces = await fd.detect(img);
        const coords = position.coords;
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::FaceDetectionWithGeolocation));
}

#[test]
fn security_no_geolocation_without_location_api() {
    let body = r#"<script>
        const fd = new FaceDetector();
        const faces = await fd.detect(img);
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(!issues.contains(&ShapeDetectionSecurityIssue::FaceDetectionWithGeolocation));
}

#[test]
fn security_detects_shape_in_worker() {
    let body = r#"<script>
        const worker = new Worker("scan.js");
        const fd = new FaceDetector();
        worker.postMessage(await fd.detect(img));
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::ShapeDetectionInWorker));
}

#[test]
fn security_detects_shape_in_shared_worker() {
    let body = r#"<script>
        const td = new TextDetector();
        const sw = new SharedWorker("ocr.js");
        sw.port.postMessage(await td.detect(img));
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::ShapeDetectionInWorker));
}

#[test]
fn security_detects_shape_in_service_worker() {
    let body = r#"<script>
        navigator.ServiceWorker.register("sw.js");
        const fd = new FaceDetector();
        fd.detect(img);
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::ShapeDetectionInWorker));
}

#[test]
fn security_no_worker_without_worker_api() {
    let body = r#"<script>
        const fd = new FaceDetector();
        const faces = await fd.detect(img);
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(!issues.contains(&ShapeDetectionSecurityIssue::ShapeDetectionInWorker));
}

#[test]
fn security_severity_surveillance_highest() {
    assert_eq!(
        shape_detection_security_severity(&ShapeDetectionSecurityIssue::FaceDetectionSurveillance),
        9.0
    );
}

#[test]
fn security_severity_exfiltration_high() {
    assert_eq!(
        shape_detection_security_severity(&ShapeDetectionSecurityIssue::FaceDataExfiltration),
        8.5
    );
}

#[test]
fn security_severity_worker_lowest() {
    assert_eq!(
        shape_detection_security_severity(&ShapeDetectionSecurityIssue::ShapeDetectionInWorker),
        4.5
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        ShapeDetectionSecurityIssue::FaceDetectionSurveillance,
        ShapeDetectionSecurityIssue::FaceDataExfiltration,
    ];
    let mut seq = 0;
    let ops = shape_detection_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_to_operations_empty() {
    let issues: Vec<ShapeDetectionSecurityIssue> = vec![];
    let mut seq = 0;
    let ops = shape_detection_security_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn security_display_surveillance() {
    assert_eq!(
        ShapeDetectionSecurityIssue::FaceDetectionSurveillance.to_string(),
        "face_detection_surveillance"
    );
}

#[test]
fn security_display_exfiltration() {
    assert_eq!(
        ShapeDetectionSecurityIssue::FaceDataExfiltration.to_string(),
        "face_data_exfiltration"
    );
}

#[test]
fn security_display_without_consent() {
    assert_eq!(
        ShapeDetectionSecurityIssue::FaceDetectionWithoutConsent.to_string(),
        "face_detection_without_consent"
    );
}

#[test]
fn security_display_text_privacy() {
    assert_eq!(
        ShapeDetectionSecurityIssue::TextRecognitionPrivacy.to_string(),
        "text_recognition_privacy"
    );
}

#[test]
fn security_display_fingerprinting() {
    assert_eq!(
        ShapeDetectionSecurityIssue::FaceRecognitionFingerprinting.to_string(),
        "face_recognition_fingerprinting"
    );
}

#[test]
fn security_display_iframe() {
    assert_eq!(
        ShapeDetectionSecurityIssue::ShapeDetectionInIframe.to_string(),
        "shape_detection_in_iframe"
    );
}

#[test]
fn security_display_persistence() {
    assert_eq!(
        ShapeDetectionSecurityIssue::FaceDataPersistence.to_string(),
        "face_data_persistence"
    );
}

#[test]
fn security_display_continuous() {
    assert_eq!(
        ShapeDetectionSecurityIssue::ContinuousFaceDetection.to_string(),
        "continuous_face_detection"
    );
}

#[test]
fn security_display_geolocation() {
    assert_eq!(
        ShapeDetectionSecurityIssue::FaceDetectionWithGeolocation.to_string(),
        "face_detection_with_geolocation"
    );
}

#[test]
fn security_display_worker() {
    assert_eq!(
        ShapeDetectionSecurityIssue::ShapeDetectionInWorker.to_string(),
        "shape_detection_in_worker"
    );
}

#[test]
fn security_multiple_issues_detected() {
    let body = r#"<script>
        const fd = new FaceDetector();
        const faces = await fd.detect(video);
        localStorage.faces = faces;
        fetch("/track", {body: JSON.stringify(faces)});
        trackUser(faces);
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::FaceDataPersistence));
    assert!(issues.contains(&ShapeDetectionSecurityIssue::FaceDataExfiltration));
    assert!(issues.contains(&ShapeDetectionSecurityIssue::FaceDetectionSurveillance));
}

#[test]
fn security_text_detector_triggers_checks() {
    let body = r#"<script>
        const td = new TextDetector();
        const worker = new Worker("ocr.js");
        worker.postMessage(await td.detect(img));
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::ShapeDetectionInWorker));
}

#[test]
fn security_barcode_detector_triggers_checks() {
    let body = r#"<script>
        const bd = new BarcodeDetector();
        const worker = new Worker("scan.js");
    </script>"#;
    let issues = analyze_shape_detection_security(body);
    assert!(issues.contains(&ShapeDetectionSecurityIssue::ShapeDetectionInWorker));
}
