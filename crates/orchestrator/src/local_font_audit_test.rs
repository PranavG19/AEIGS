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
