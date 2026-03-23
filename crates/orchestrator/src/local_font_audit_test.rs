use crate::local_font_audit::*;

#[test]
fn no_font_api_no_issues() {
    assert!(analyze_local_font("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api() {
    let body = r#"<script>const fonts = await window.queryLocalFonts();</script>"#;
    let issues = analyze_local_font(body);
    assert!(issues.contains(&LocalFontIssue::ApiDetected));
}

#[test]
fn detects_api_permission_name() {
    let body = r#"<script>
        const perm = await navigator.permissions.query({name: "local-fonts"});
    </script>"#;
    let issues = analyze_local_font(body);
    assert!(issues.contains(&LocalFontIssue::ApiDetected));
}

#[test]
fn detects_font_exfiltration() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        fetch("/track?fonts=" + fonts.map(f => f.family).join(","));
    </script>"#;
    let issues = analyze_local_font(body);
    assert!(issues.contains(&LocalFontIssue::FontExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        console.log(fonts);
    </script>"#;
    let issues = analyze_local_font(body);
    assert!(!issues.contains(&LocalFontIssue::FontExfiltration));
}

#[test]
fn detects_full_enumeration() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        fonts.forEach(f => console.log(f.family));
    </script>"#;
    let issues = analyze_local_font(body);
    assert!(issues.contains(&LocalFontIssue::FullEnumeration));
}

#[test]
fn no_full_enum_with_filter() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts({postScriptName: ["Arial"]});
    </script>"#;
    let issues = analyze_local_font(body);
    assert!(!issues.contains(&LocalFontIssue::FullEnumeration));
}

#[test]
fn detects_font_data_access() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        const data = await fonts[0].blob();
    </script>"#;
    let issues = analyze_local_font(body);
    assert!(issues.contains(&LocalFontIssue::FontDataAccess));
}

#[test]
fn detects_no_permission_check() {
    let body = r#"<script>const fonts = await window.queryLocalFonts();</script>"#;
    let issues = analyze_local_font(body);
    assert!(issues.contains(&LocalFontIssue::NoPermissionCheck));
}

#[test]
fn no_permission_issue_with_query() {
    let body = r#"<script>
        const perm = await navigator.permissions.query({name: "local-fonts"});
        if (perm.state === "granted") {
            const fonts = await window.queryLocalFonts();
        }
    </script>"#;
    let issues = analyze_local_font(body);
    assert!(!issues.contains(&LocalFontIssue::NoPermissionCheck));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(local_font_severity(&LocalFontIssue::FontExfiltration), 7.0);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(local_font_severity(&LocalFontIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![LocalFontIssue::ApiDetected, LocalFontIssue::FullEnumeration];
    let mut seq = 0;
    let ops = local_font_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(LocalFontIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        LocalFontIssue::FontExfiltration.to_string(),
        "font_exfiltration"
    );
    assert_eq!(
        LocalFontIssue::FullEnumeration.to_string(),
        "full_enumeration"
    );
    assert_eq!(
        LocalFontIssue::FontDataAccess.to_string(),
        "font_data_access"
    );
    assert_eq!(
        LocalFontIssue::NoPermissionCheck.to_string(),
        "no_permission_check"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_local_font("").is_empty());
}

#[test]
fn security_no_font_api_no_issues() {
    assert!(analyze_local_font_security("<html><body>hello</body></html>").is_empty());
}

#[test]
fn security_empty_body_no_issues() {
    assert!(analyze_local_font_security("").is_empty());
}

#[test]
fn security_detects_font_enumeration() {
    let body = r#"<script>const fonts = await window.queryLocalFonts();</script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontEnumeration));
}

#[test]
fn security_detects_font_enumeration_with_options() {
    let body = r#"<script>const fonts = await window.queryLocalFonts({});</script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontEnumeration));
}

#[test]
fn security_detects_font_fingerprinting_family() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        const families = fonts.map(f => f.family);
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontFingerprinting));
}

#[test]
fn security_detects_font_fingerprinting_postscript() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        const names = fonts.map(f => f.postScriptName);
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontFingerprinting));
}

#[test]
fn security_detects_font_fingerprinting_fullname() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        console.log(fonts[0].fullName);
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontFingerprinting));
}

#[test]
fn security_detects_font_data_exfiltration_fetch() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        fetch("/track", {method: "POST", body: JSON.stringify(fonts)});
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontDataExfiltration));
}

#[test]
fn security_detects_font_data_exfiltration_beacon() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        navigator.sendBeacon("/analytics", JSON.stringify(fonts));
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontDataExfiltration));
}

#[test]
fn security_detects_font_data_exfiltration_xhr() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        const xhr = new XMLHttpRequest();
        xhr.open("POST", "/track");
        xhr.send(JSON.stringify(fonts));
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontDataExfiltration));
}

#[test]
fn security_detects_font_data_exfiltration_websocket() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        const ws = new WebSocket("wss://example.com");
        ws.send(JSON.stringify(fonts));
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontDataExfiltration));
}

#[test]
fn security_detects_font_without_permission() {
    let body = r#"<script>const fonts = await window.queryLocalFonts();</script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontWithoutPermission));
}

#[test]
fn security_no_permission_issue_when_checked() {
    let body = r#"<script>
        const perm = await navigator.permissions.query({name: "local-fonts"});
        if (perm.state === "granted") {
            const fonts = await window.queryLocalFonts();
        }
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(!issues.contains(&LocalFontSecurityIssue::FontWithoutPermission));
}

#[test]
fn security_detects_font_cross_origin_postmessage() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        window.parent.postMessage(fonts, "*");
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontCrossOrigin));
}

#[test]
fn security_detects_font_cross_origin_attribute() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        fetch("/api", {mode: "cross-origin"});
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontCrossOrigin));
}

#[test]
fn security_detects_font_cross_origin_shared_buffer() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        const buffer = new SharedArrayBuffer(1024);
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontCrossOrigin));
}

#[test]
fn security_detects_font_persistent_storage_local() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        localStorage.setItem("fonts", JSON.stringify(fonts));
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontPersistentStorage));
}

#[test]
fn security_detects_font_persistent_storage_session() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        sessionStorage.setItem("fonts", JSON.stringify(fonts));
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontPersistentStorage));
}

#[test]
fn security_detects_font_persistent_storage_indexeddb() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        const db = await indexedDB.open("fontDB");
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontPersistentStorage));
}

#[test]
fn security_detects_font_persistent_storage_cache() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        const cache = await caches.open("fonts");
        await Cache.put("/fonts", new Response(JSON.stringify(fonts)));
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontPersistentStorage));
}

#[test]
fn security_detects_font_with_canvas_direct() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        const canvas = document.createElement("canvas");
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontWithCanvas));
}

#[test]
fn security_detects_font_with_canvas_measuretext() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        const ctx = canvas.getContext("2d");
        ctx.font = fonts[0].family;
        const metrics = ctx.measureText("test");
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontWithCanvas));
}

#[test]
fn security_detects_font_with_canvas_getcontext() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        const gl = canvas.getContext("webgl");
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontWithCanvas));
}

#[test]
fn security_detects_font_timing_attack_performance_now() {
    let body = r#"<script>
        const start = performance.now();
        const fonts = await window.queryLocalFonts();
        const elapsed = performance.now() - start;
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontTimingAttack));
}

#[test]
fn security_detects_font_timing_attack_date_now() {
    let body = r#"<script>
        const start = Date.now();
        const fonts = await window.queryLocalFonts();
        const elapsed = Date.now() - start;
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontTimingAttack));
}

#[test]
fn security_detects_font_timing_attack_performance_mark() {
    let body = r#"<script>
        performance.mark("font-start");
        const fonts = await window.queryLocalFonts();
        performance.mark("font-end");
        performance.measure("font-time", "font-start", "font-end");
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontTimingAttack));
}

#[test]
fn security_detects_font_in_worker_basic() {
    let body = r#"<script>
        const worker = new Worker("font-worker.js");
        const fonts = await window.queryLocalFonts();
        worker.postMessage(fonts);
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontInWorker));
}

#[test]
fn security_detects_font_in_service_worker() {
    let body = r#"<script>
        navigator.serviceWorker.register("sw.js");
        const fonts = await window.queryLocalFonts();
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontInWorker));
}

#[test]
fn security_detects_font_in_shared_worker() {
    let body = r#"<script>
        const sharedWorker = new SharedWorker("font-shared.js");
        const fonts = await window.queryLocalFonts();
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::FontInWorker));
}

#[test]
fn security_detects_system_font_detection_arial() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        const hasArial = fonts.some(f => f.family === "Arial");
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::SystemFontDetection));
}

#[test]
fn security_detects_system_font_detection_times() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        if (fonts.find(f => f.family.includes("Times New Roman"))) {
            console.log("Windows detected");
        }
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::SystemFontDetection));
}

#[test]
fn security_detects_system_font_detection_helvetica() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        const hasHelvetica = fonts.filter(f => f.family === "Helvetica");
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(issues.contains(&LocalFontSecurityIssue::SystemFontDetection));
}

#[test]
fn security_no_system_font_without_system_names() {
    let body = r#"<script>
        const fonts = await window.queryLocalFonts();
        const customFont = fonts.find(f => f.family === "MyCustomFont");
    </script>"#;
    let issues = analyze_local_font_security(body);
    assert!(!issues.contains(&LocalFontSecurityIssue::SystemFontDetection));
}

#[test]
fn security_severity_exfiltration_highest() {
    assert_eq!(
        local_font_security_severity(&LocalFontSecurityIssue::FontDataExfiltration),
        8.5
    );
}

#[test]
fn security_severity_fingerprinting_high() {
    assert_eq!(
        local_font_security_severity(&LocalFontSecurityIssue::FontFingerprinting),
        7.5
    );
}

#[test]
fn security_severity_cross_origin() {
    assert_eq!(
        local_font_security_severity(&LocalFontSecurityIssue::FontCrossOrigin),
        7.0
    );
}

#[test]
fn security_severity_timing_attack() {
    assert_eq!(
        local_font_security_severity(&LocalFontSecurityIssue::FontTimingAttack),
        6.5
    );
}

#[test]
fn security_severity_canvas() {
    assert_eq!(
        local_font_security_severity(&LocalFontSecurityIssue::FontWithCanvas),
        6.0
    );
}

#[test]
fn security_severity_persistent_storage() {
    assert_eq!(
        local_font_security_severity(&LocalFontSecurityIssue::FontPersistentStorage),
        5.5
    );
}

#[test]
fn security_severity_system_detection() {
    assert_eq!(
        local_font_security_severity(&LocalFontSecurityIssue::SystemFontDetection),
        5.0
    );
}

#[test]
fn security_severity_enumeration() {
    assert_eq!(
        local_font_security_severity(&LocalFontSecurityIssue::FontEnumeration),
        4.5
    );
}

#[test]
fn security_severity_worker() {
    assert_eq!(
        local_font_security_severity(&LocalFontSecurityIssue::FontInWorker),
        4.0
    );
}

#[test]
fn security_severity_without_permission_lowest() {
    assert_eq!(
        local_font_security_severity(&LocalFontSecurityIssue::FontWithoutPermission),
        3.5
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        LocalFontSecurityIssue::FontEnumeration,
        LocalFontSecurityIssue::FontFingerprinting,
    ];
    let mut seq = 0;
    let ops = local_font_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_to_operations_empty_input() {
    let issues = vec![];
    let mut seq = 5;
    let ops = local_font_security_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn security_display_font_enumeration() {
    assert_eq!(
        LocalFontSecurityIssue::FontEnumeration.to_string(),
        "font_enumeration"
    );
}

#[test]
fn security_display_font_fingerprinting() {
    assert_eq!(
        LocalFontSecurityIssue::FontFingerprinting.to_string(),
        "font_fingerprinting"
    );
}

#[test]
fn security_display_font_data_exfiltration() {
    assert_eq!(
        LocalFontSecurityIssue::FontDataExfiltration.to_string(),
        "font_data_exfiltration"
    );
}

#[test]
fn security_display_font_without_permission() {
    assert_eq!(
        LocalFontSecurityIssue::FontWithoutPermission.to_string(),
        "font_without_permission"
    );
}

#[test]
fn security_display_font_cross_origin() {
    assert_eq!(
        LocalFontSecurityIssue::FontCrossOrigin.to_string(),
        "font_cross_origin"
    );
}

#[test]
fn security_display_font_persistent_storage() {
    assert_eq!(
        LocalFontSecurityIssue::FontPersistentStorage.to_string(),
        "font_persistent_storage"
    );
}

#[test]
fn security_display_font_with_canvas() {
    assert_eq!(
        LocalFontSecurityIssue::FontWithCanvas.to_string(),
        "font_with_canvas"
    );
}

#[test]
fn security_display_font_timing_attack() {
    assert_eq!(
        LocalFontSecurityIssue::FontTimingAttack.to_string(),
        "font_timing_attack"
    );
}

#[test]
fn security_display_font_in_worker() {
    assert_eq!(
        LocalFontSecurityIssue::FontInWorker.to_string(),
        "font_in_worker"
    );
}

#[test]
fn security_display_system_font_detection() {
    assert_eq!(
        LocalFontSecurityIssue::SystemFontDetection.to_string(),
        "system_font_detection"
    );
}
