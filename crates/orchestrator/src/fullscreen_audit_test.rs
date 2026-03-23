use crate::fullscreen_audit::*;

#[test]
fn no_fullscreen_no_issues() {
    assert!(analyze_fullscreen("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_standard() {
    let body = r#"<script>el.requestFullscreen();</script>"#;
    let issues = analyze_fullscreen(body);
    assert!(issues.contains(&FullscreenIssue::ApiDetected));
}

#[test]
fn detects_api_webkit() {
    let body = r#"<script>el.webkitRequestFullscreen();</script>"#;
    assert!(analyze_fullscreen(body).contains(&FullscreenIssue::ApiDetected));
}

#[test]
fn detects_api_moz() {
    let body = r#"<script>el.mozRequestFullScreen();</script>"#;
    assert!(analyze_fullscreen(body).contains(&FullscreenIssue::ApiDetected));
}

#[test]
fn detects_api_ms() {
    let body = r#"<script>el.msRequestFullscreen();</script>"#;
    assert!(analyze_fullscreen(body).contains(&FullscreenIssue::ApiDetected));
}

#[test]
fn detects_ui_spoofing_with_address_bar() {
    let body = r#"<script>
        el.requestFullscreen().then(() => {
            if (document.fullscreenElement) {
                const fake_bar = document.createElement("div");
                fake_bar.className = "address-bar";
                document.body.appendChild(fake_bar);
            }
        });
    </script>"#;
    let issues = analyze_fullscreen(body);
    assert!(issues.contains(&FullscreenIssue::UiSpoofing));
}

#[test]
fn detects_ui_spoofing_with_toolbar() {
    let body = r#"<script>
        el.requestFullscreen();
        document.fullscreenElement && document.createElement("div") && toolbar.innerHTML = "Chrome";
    </script>"#;
    let issues = analyze_fullscreen(body);
    assert!(issues.contains(&FullscreenIssue::UiSpoofing));
}

#[test]
fn detects_ui_spoofing_with_navigation() {
    let body = r#"<script>
        el.webkitRequestFullscreen();
        if (webkitFullscreenElement) {
            const nav = document.createElement("nav");
            nav.className = "browser-chrome";
            document.body.appendChild(nav);
        }
    </script>"#;
    let issues = analyze_fullscreen(body);
    assert!(issues.contains(&FullscreenIssue::UiSpoofing));
}

#[test]
fn detects_phishing_overlay_with_password() {
    let body = r#"<script>
        el.requestFullscreen();
    </script>
    <form>
        <input type="password" name="password" />
        <input type="text" name="username" />
    </form>"#;
    let issues = analyze_fullscreen(body);
    assert!(issues.contains(&FullscreenIssue::PhishingOverlay));
}

#[test]
fn detects_phishing_overlay_with_login() {
    let body = r#"<script>
        document.body.requestFullscreen();
    </script>
    <form id="login">
        <input type="text" name="email" />
    </form>"#;
    let issues = analyze_fullscreen(body);
    assert!(issues.contains(&FullscreenIssue::PhishingOverlay));
}

#[test]
fn detects_phishing_overlay_with_credit_card() {
    let body = r#"<script>
        el.webkitRequestFullscreen();
    </script>
    <form>
        <input type="text" name="card-number" />
        <input type="text" name="cvv" />
    </form>"#;
    let issues = analyze_fullscreen(body);
    assert!(issues.contains(&FullscreenIssue::PhishingOverlay));
}

#[test]
fn detects_no_exit_indicator_missing_instruction() {
    let body = r#"<script>
        btn.addEventListener("click", () => {
            document.body.requestFullscreen();
        });
    </script>"#;
    let issues = analyze_fullscreen(body);
    assert!(issues.contains(&FullscreenIssue::NoExitIndicator));
}

#[test]
fn no_exit_issue_when_instruction_present() {
    let body = r#"<script>
        btn.addEventListener("click", () => {
            document.body.requestFullscreen();
            showMessage("Press ESC to exit fullscreen");
        });
    </script>"#;
    let issues = analyze_fullscreen(body);
    assert!(!issues.contains(&FullscreenIssue::NoExitIndicator));
}

#[test]
fn detects_iframe_fullscreen_cross_origin() {
    let body = r#"<script>el.requestFullscreen();</script><iframe src="https://evil.com/phish" allowfullscreen></iframe>"#;
    let issues = analyze_fullscreen(body);
    assert!(issues.contains(&FullscreenIssue::IframeFullscreen));
}

#[test]
fn detects_iframe_fullscreen_webkit() {
    let body = r#"<script>el.webkitRequestFullscreen();</script><iframe src="http://attacker.net" webkitallowfullscreen></iframe>"#;
    let issues = analyze_fullscreen(body);
    assert!(issues.contains(&FullscreenIssue::IframeFullscreen));
}

#[test]
fn detects_keyboard_trap_with_lock() {
    let body = r#"<script>
        el.addEventListener("click", async () => {
            await el.requestFullscreen();
            navigator.keyboard.lock(["Escape"]);
        });
    </script>"#;
    let issues = analyze_fullscreen(body);
    assert!(issues.contains(&FullscreenIssue::KeyboardTrap));
}

#[test]
fn detects_keyboard_trap_with_prevent_default() {
    let body = r#"<script>
        el.requestFullscreen();
        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape") {
                e.preventDefault();
            }
        });
    </script>"#;
    let issues = analyze_fullscreen(body);
    assert!(issues.contains(&FullscreenIssue::KeyboardTrap));
}

#[test]
fn detects_keyboard_trap_with_pointer_lock() {
    let body = r#"<script>
        el.addEventListener("click", () => {
            el.requestFullscreen();
            el.requestPointerLock();
        });
    </script>"#;
    let issues = analyze_fullscreen(body);
    assert!(issues.contains(&FullscreenIssue::KeyboardTrap));
}

#[test]
fn severity_phishing_overlay_highest() {
    assert_eq!(fullscreen_severity(&FullscreenIssue::PhishingOverlay), 8.5);
}

#[test]
fn severity_ui_spoofing_high() {
    assert_eq!(fullscreen_severity(&FullscreenIssue::UiSpoofing), 8.0);
}

#[test]
fn severity_keyboard_trap() {
    assert_eq!(fullscreen_severity(&FullscreenIssue::KeyboardTrap), 7.5);
}

#[test]
fn severity_iframe_fullscreen() {
    assert_eq!(fullscreen_severity(&FullscreenIssue::IframeFullscreen), 6.5);
}

#[test]
fn severity_no_exit_indicator() {
    assert_eq!(fullscreen_severity(&FullscreenIssue::NoExitIndicator), 5.5);
}

#[test]
fn severity_api_detected_lowest() {
    assert_eq!(fullscreen_severity(&FullscreenIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        FullscreenIssue::ApiDetected,
        FullscreenIssue::PhishingOverlay,
    ];
    let mut seq = 0u64;
    let ops = fullscreen_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_api_detected() {
    assert_eq!(FullscreenIssue::ApiDetected.to_string(), "api_detected");
}

#[test]
fn display_ui_spoofing() {
    assert_eq!(FullscreenIssue::UiSpoofing.to_string(), "ui_spoofing");
}

#[test]
fn display_phishing_overlay() {
    assert_eq!(
        FullscreenIssue::PhishingOverlay.to_string(),
        "phishing_overlay"
    );
}

#[test]
fn display_no_exit_indicator() {
    assert_eq!(
        FullscreenIssue::NoExitIndicator.to_string(),
        "no_exit_indicator"
    );
}

#[test]
fn display_iframe_fullscreen() {
    assert_eq!(
        FullscreenIssue::IframeFullscreen.to_string(),
        "iframe_fullscreen"
    );
}

#[test]
fn display_keyboard_trap() {
    assert_eq!(FullscreenIssue::KeyboardTrap.to_string(), "keyboard_trap");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_fullscreen("").is_empty());
}

#[test]
fn complex_phishing_attack() {
    let body = r#"
    <script>
        document.addEventListener("DOMContentLoaded", () => {
            document.body.requestFullscreen().then(() => {
                if (document.fullscreenElement) {
                    const chrome_bar = document.createElement("div");
                    chrome_bar.innerHTML = '<div class="address-bar">https://secure-bank.com/login</div>';
                    document.body.insertAdjacentHTML("afterbegin", chrome_bar.outerHTML);
                }
            });

            navigator.keyboard.lock(["Escape"]);
        });
    </script>
    <form id="signin">
        <input type="text" name="username" placeholder="Email" />
        <input type="password" name="password" placeholder="Password" />
        <button type="submit">Login</button>
    </form>
    "#;
    let issues = analyze_fullscreen(body);
    assert!(issues.contains(&FullscreenIssue::ApiDetected));
    assert!(issues.contains(&FullscreenIssue::UiSpoofing));
    assert!(issues.contains(&FullscreenIssue::PhishingOverlay));
    assert!(issues.contains(&FullscreenIssue::NoExitIndicator));
    assert!(issues.contains(&FullscreenIssue::KeyboardTrap));
    assert_eq!(issues.len(), 5);
}
