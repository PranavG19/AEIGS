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
    assert_eq!(
        eyedropper_severity(&EyeDropperIssue::ColorExfiltration),
        6.0
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(eyedropper_severity(&EyeDropperIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        EyeDropperIssue::ApiDetected,
        EyeDropperIssue::PixelDataAccess,
    ];
    let mut seq = 0;
    let ops = eyedropper_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(EyeDropperIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        EyeDropperIssue::ColorExfiltration.to_string(),
        "color_exfiltration"
    );
    assert_eq!(
        EyeDropperIssue::NoUserActivation.to_string(),
        "no_user_activation"
    );
    assert_eq!(EyeDropperIssue::LoopedPicking.to_string(), "looped_picking");
    assert_eq!(
        EyeDropperIssue::PixelDataAccess.to_string(),
        "pixel_data_access"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_eyedropper("").is_empty());
}

// ========== EyeDropperSecurityIssue Tests ==========

// DropperWithoutFeaturePolicy tests
#[test]
fn security_detects_dropper_without_policy() {
    let body = r#"<script>const ed = new EyeDropper(); await ed.open();</script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::DropperWithoutFeaturePolicy))
    );
}

#[test]
fn security_no_issue_with_permissions_policy() {
    let body = r#"
        <meta http-equiv="Permissions-Policy" content="eyedropper=()">
        <script>const ed = new EyeDropper(); await ed.open();</script>
    "#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::DropperWithoutFeaturePolicy))
    );
}

#[test]
fn security_no_issue_with_feature_policy() {
    let body = r#"
        <meta http-equiv="Feature-Policy" content="eyedropper 'self'">
        <script>const ed = new EyeDropper();</script>
    "#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::DropperWithoutFeaturePolicy))
    );
}

// ColorDataPersistence tests
#[test]
fn security_detects_localstorage_persistence() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const result = await ed.open();
        localStorage.setItem('color', result.sRGBHex);
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::ColorDataPersistence))
    );
}

#[test]
fn security_detects_sessionstorage_persistence() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const result = await ed.open();
        sessionStorage.setItem('pickedColor', result.sRGBHex);
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::ColorDataPersistence))
    );
}

#[test]
fn security_detects_indexeddb_persistence() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const result = await ed.open();
        indexedDB.open('colors').onsuccess = (e) => { /* store */ };
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::ColorDataPersistence))
    );
}

#[test]
fn security_no_persistence_without_storage() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const result = await ed.open();
        console.log(result.sRGBHex);
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::ColorDataPersistence))
    );
}

// BulkColorCollection tests
#[test]
fn security_detects_bulk_collection_multiple_opens() {
    let body = r#"<script>
        const ed = new EyeDropper();
        await ed.open();
        await ed.open();
        await ed.open();
        await ed.open();
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::BulkColorCollection))
    );
}

#[test]
fn security_detects_bulk_collection_while_loop() {
    let body = r#"<script>
        const ed = new EyeDropper();
        while(collecting) {
            await ed.open();
        }
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::BulkColorCollection))
    );
}

#[test]
fn security_detects_bulk_collection_for_loop() {
    let body = r#"<script>
        const ed = new EyeDropper();
        for(let i = 0; i < 10; i++) {
            await ed.open();
        }
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::BulkColorCollection))
    );
}

#[test]
fn security_no_bulk_collection_single_open() {
    let body = r#"<script>
        const ed = new EyeDropper();
        await ed.open();
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::BulkColorCollection))
    );
}

// CrossOriginColorLeak tests
#[test]
fn security_detects_postmessage_leak() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const result = await ed.open();
        window.parent.postMessage({color: result.sRGBHex}, '*');
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::CrossOriginColorLeak))
    );
}

#[test]
fn security_detects_postmessage_with_result() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const colorSelectionResult = await ed.open();
        postMessage(colorSelectionResult, '*');
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::CrossOriginColorLeak))
    );
}

#[test]
fn security_no_leak_without_postmessage() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const result = await ed.open();
        console.log(result.sRGBHex);
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::CrossOriginColorLeak))
    );
}

// CanvasCorrelation tests
#[test]
fn security_detects_canvas_correlation() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const ctx = canvas.getContext('2d');
        const imageData = ctx.getImageData(0, 0, 100, 100);
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::CanvasCorrelation))
    );
}

#[test]
fn security_detects_canvas_with_eyedropper() {
    let body = r#"<script>
        const canvas = document.querySelector('canvas');
        const ed = new EyeDropper();
        await ed.open();
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::CanvasCorrelation))
    );
}

#[test]
fn security_no_correlation_without_canvas() {
    let body = r#"<script>
        const ed = new EyeDropper();
        await ed.open();
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::CanvasCorrelation))
    );
}

// AutomatedInvocation tests
#[test]
fn security_detects_settimeout_invocation() {
    let body = r#"<script>
        const ed = new EyeDropper();
        setTimeout(() => ed.open(), 1000);
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::AutomatedInvocation))
    );
}

#[test]
fn security_detects_setinterval_invocation() {
    let body = r#"<script>
        const ed = new EyeDropper();
        setInterval(() => ed.open(), 5000);
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::AutomatedInvocation))
    );
}

#[test]
fn security_no_automated_with_user_click() {
    let body = r#"<script>
        const ed = new EyeDropper();
        button.addEventListener('click', () => ed.open());
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::AutomatedInvocation))
    );
}

// ColorToCoordinateMapping tests
#[test]
fn security_detects_screenx_mapping() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const result = await ed.open();
        const data = {color: result.sRGBHex, x: event.screenX};
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::ColorToCoordinateMapping))
    );
}

#[test]
fn security_detects_clientxy_mapping() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const colorSelectionResult = await ed.open();
        fetch('/log?x=' + event.clientX + '&y=' + event.clientY);
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::ColorToCoordinateMapping))
    );
}

#[test]
fn security_no_mapping_without_coordinates() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const result = await ed.open();
        console.log(result.sRGBHex);
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::ColorToCoordinateMapping))
    );
}

// UnencryptedColorTransmission tests
#[test]
fn security_detects_http_transmission() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const result = await ed.open();
        fetch('http://example.com/track?color=' + result.sRGBHex);
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::UnencryptedColorTransmission))
    );
}

#[test]
fn security_detects_http_xhr() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const colorSelectionResult = await ed.open();
        const xhr = new XMLHttpRequest();
        xhr.open('POST', 'http://tracker.com');
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::UnencryptedColorTransmission))
    );
}

#[test]
fn security_no_unencrypted_with_https() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const result = await ed.open();
        fetch('https://example.com?color=' + result.sRGBHex);
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::UnencryptedColorTransmission))
    );
}

// WorkerBasedColorCollection tests
#[test]
fn security_detects_worker_usage() {
    let body = r#"<script>
        const worker = new Worker('color-collector.js');
        const ed = new EyeDropper();
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::WorkerBasedColorCollection))
    );
}

#[test]
fn security_detects_shared_worker() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const worker = new SharedWorker('colors.js');
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::WorkerBasedColorCollection))
    );
}

#[test]
fn security_no_worker_without_worker() {
    let body = r#"<script>
        const ed = new EyeDropper();
        await ed.open();
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::WorkerBasedColorCollection))
    );
}

// ThirdPartyColorSharing tests
#[test]
fn security_detects_third_party_sharing() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const result = await ed.open();
        fetch('https://analytics.example.com/track?color=' + result.sRGBHex);
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::ThirdPartyColorSharing))
    );
}

#[test]
fn security_detects_third_party_beacon() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const colorSelectionResult = await ed.open();
        navigator.sendBeacon('https://tracker.net/log', JSON.stringify(colorSelectionResult));
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::ThirdPartyColorSharing))
    );
}

#[test]
fn security_no_third_party_localhost() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const result = await ed.open();
        fetch('http://localhost:3000?color=' + result.sRGBHex);
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EyeDropperSecurityIssue::ThirdPartyColorSharing))
    );
}

// Edge case tests
#[test]
fn security_empty_body_no_issues() {
    assert!(analyze_eyedropper_security("").is_empty());
}

#[test]
fn security_no_eyedropper_no_issues() {
    let body = r#"<script>const x = 42;</script>"#;
    assert!(analyze_eyedropper_security(body).is_empty());
}

#[test]
fn security_multiple_issues_combined() {
    let body = r#"<script>
        const ed = new EyeDropper();
        const result = await ed.open();
        localStorage.setItem('color', result.sRGBHex);
        setTimeout(() => ed.open(), 1000);
        postMessage(result, '*');
        fetch('http://tracker.com?color=' + result.sRGBHex);
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(issues.len() >= 4);
}

#[test]
fn security_partial_match_no_false_positive() {
    let body = r#"<script>
        // Comment about EyeDropper API
        const myDropper = {open: () => {}};
    </script>"#;
    let issues = analyze_eyedropper_security(body);
    assert!(issues.is_empty() || issues.len() == 1); // Only DropperWithoutFeaturePolicy
}

// Display trait tests
#[test]
fn security_display_dropper_without_policy() {
    assert_eq!(
        EyeDropperSecurityIssue::DropperWithoutFeaturePolicy.to_string(),
        "dropper_without_feature_policy"
    );
}

#[test]
fn security_display_color_persistence() {
    assert_eq!(
        EyeDropperSecurityIssue::ColorDataPersistence.to_string(),
        "color_data_persistence"
    );
}

#[test]
fn security_display_bulk_collection() {
    assert_eq!(
        EyeDropperSecurityIssue::BulkColorCollection.to_string(),
        "bulk_color_collection"
    );
}

#[test]
fn security_display_cross_origin_leak() {
    assert_eq!(
        EyeDropperSecurityIssue::CrossOriginColorLeak.to_string(),
        "cross_origin_color_leak"
    );
}

#[test]
fn security_display_canvas_correlation() {
    assert_eq!(
        EyeDropperSecurityIssue::CanvasCorrelation.to_string(),
        "canvas_correlation"
    );
}

#[test]
fn security_display_automated_invocation() {
    assert_eq!(
        EyeDropperSecurityIssue::AutomatedInvocation.to_string(),
        "automated_invocation"
    );
}

#[test]
fn security_display_coordinate_mapping() {
    assert_eq!(
        EyeDropperSecurityIssue::ColorToCoordinateMapping.to_string(),
        "color_to_coordinate_mapping"
    );
}

#[test]
fn security_display_unencrypted_transmission() {
    assert_eq!(
        EyeDropperSecurityIssue::UnencryptedColorTransmission.to_string(),
        "unencrypted_color_transmission"
    );
}

#[test]
fn security_display_worker_based() {
    assert_eq!(
        EyeDropperSecurityIssue::WorkerBasedColorCollection.to_string(),
        "worker_based_color_collection"
    );
}

#[test]
fn security_display_third_party_sharing() {
    assert_eq!(
        EyeDropperSecurityIssue::ThirdPartyColorSharing.to_string(),
        "third_party_color_sharing"
    );
}

// Severity ordering tests
#[test]
fn security_severity_unencrypted_highest() {
    assert_eq!(
        eyedropper_security_severity(&EyeDropperSecurityIssue::UnencryptedColorTransmission),
        7.5
    );
}

#[test]
fn security_severity_third_party_high() {
    assert_eq!(
        eyedropper_security_severity(&EyeDropperSecurityIssue::ThirdPartyColorSharing),
        7.0
    );
}

#[test]
fn security_severity_cross_origin_high() {
    assert_eq!(
        eyedropper_security_severity(&EyeDropperSecurityIssue::CrossOriginColorLeak),
        6.5
    );
}

#[test]
fn security_severity_policy_lowest() {
    assert_eq!(
        eyedropper_security_severity(&EyeDropperSecurityIssue::DropperWithoutFeaturePolicy),
        3.0
    );
}

#[test]
fn security_severity_ordering_correct() {
    let unencrypted =
        eyedropper_security_severity(&EyeDropperSecurityIssue::UnencryptedColorTransmission);
    let third_party =
        eyedropper_security_severity(&EyeDropperSecurityIssue::ThirdPartyColorSharing);
    let policy =
        eyedropper_security_severity(&EyeDropperSecurityIssue::DropperWithoutFeaturePolicy);
    assert!(unencrypted > third_party);
    assert!(third_party > policy);
}

// Operations generation tests
#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        EyeDropperSecurityIssue::DropperWithoutFeaturePolicy,
        EyeDropperSecurityIssue::ColorDataPersistence,
    ];
    let mut seq = 0;
    let ops = eyedropper_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_to_operations_empty_vec() {
    let issues = vec![];
    let mut seq = 0;
    let ops = eyedropper_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 0);
}

#[test]
fn security_to_operations_single_issue() {
    let issues = vec![EyeDropperSecurityIssue::UnencryptedColorTransmission];
    let mut seq = 0;
    let ops = eyedropper_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn security_to_operations_all_issues() {
    let issues = vec![
        EyeDropperSecurityIssue::DropperWithoutFeaturePolicy,
        EyeDropperSecurityIssue::ColorDataPersistence,
        EyeDropperSecurityIssue::BulkColorCollection,
        EyeDropperSecurityIssue::CrossOriginColorLeak,
        EyeDropperSecurityIssue::CanvasCorrelation,
        EyeDropperSecurityIssue::AutomatedInvocation,
        EyeDropperSecurityIssue::ColorToCoordinateMapping,
        EyeDropperSecurityIssue::UnencryptedColorTransmission,
        EyeDropperSecurityIssue::WorkerBasedColorCollection,
        EyeDropperSecurityIssue::ThirdPartyColorSharing,
    ];
    let mut seq = 0;
    let ops = eyedropper_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 10);
    assert_eq!(seq, 10);
}
