#[cfg(test)]
mod tests {
    use crate::bot_detection_probe::{
        BotProbeResult, DetectionMethod, analyze_bot_detection, detect_challenge_type,
        is_challenge_response,
    };

    fn ok_result(headers_sent: bool, rapid: bool) -> BotProbeResult {
        BotProbeResult {
            headers_sent,
            response_status: 200,
            response_body_snippet: "<html><body>OK</body></html>".to_string(),
            rapid_request: rapid,
        }
    }

    fn blocked_with_js_challenge(headers_sent: bool) -> BotProbeResult {
        BotProbeResult {
            headers_sent,
            response_status: 403,
            response_body_snippet: "<html><script>var challenge = verify();</script></html>"
                .to_string(),
            rapid_request: false,
        }
    }

    fn blocked_with_captcha(headers_sent: bool) -> BotProbeResult {
        BotProbeResult {
            headers_sent,
            response_status: 403,
            response_body_snippet:
                "<html><div class=\"g-recaptcha\" data-sitekey=\"abc\"></div></html>".to_string(),
            rapid_request: false,
        }
    }

    #[test]
    fn detection_method_display_javascript_challenge() {
        assert_eq!(
            DetectionMethod::JavaScriptChallenge.to_string(),
            "javascript_challenge"
        );
    }

    #[test]
    fn detection_method_display_captcha() {
        assert_eq!(DetectionMethod::Captcha.to_string(), "captcha");
    }

    #[test]
    fn detection_method_display_header_analysis() {
        assert_eq!(
            DetectionMethod::HeaderAnalysis.to_string(),
            "header_analysis"
        );
    }

    #[test]
    fn detection_method_display_behavioral() {
        assert_eq!(DetectionMethod::Behavioral.to_string(), "behavioral");
    }

    #[test]
    fn detection_method_display_unknown() {
        assert_eq!(DetectionMethod::Unknown.to_string(), "unknown");
    }

    #[test]
    fn detect_challenge_type_recaptcha() {
        let body = "<div class=\"g-recaptcha\"></div>";
        assert_eq!(detect_challenge_type(body), DetectionMethod::Captcha);
    }

    #[test]
    fn detect_challenge_type_hcaptcha() {
        let body = "<div class=\"h-captcha\" data-sitekey=\"key\"></div>";
        assert_eq!(detect_challenge_type(body), DetectionMethod::Captcha);
    }

    #[test]
    fn detect_challenge_type_turnstile() {
        let body = "<div class=\"cf-turnstile\"></div>";
        assert_eq!(detect_challenge_type(body), DetectionMethod::Captcha);
    }

    #[test]
    fn detect_challenge_type_js_challenge() {
        let body = "<script>function challenge() { return true; }</script>";
        assert_eq!(
            detect_challenge_type(body),
            DetectionMethod::JavaScriptChallenge
        );
    }

    #[test]
    fn detect_challenge_type_unknown_for_plain_html() {
        let body = "<html><body>Hello world</body></html>";
        assert_eq!(detect_challenge_type(body), DetectionMethod::Unknown);
    }

    #[test]
    fn is_challenge_response_403_with_captcha() {
        let body = "<div class=\"g-recaptcha\"></div>";
        assert!(is_challenge_response(403, body));
    }

    #[test]
    fn is_challenge_response_429_with_js_challenge() {
        let body = "<script>var x = verify();</script>";
        assert!(is_challenge_response(429, body));
    }

    #[test]
    fn is_challenge_response_503_with_turnstile() {
        let body = "<div class=\"cf-turnstile\"></div>";
        assert!(is_challenge_response(503, body));
    }

    #[test]
    fn is_challenge_response_false_for_200() {
        let body = "<div class=\"g-recaptcha\"></div>";
        assert!(!is_challenge_response(200, body));
    }

    #[test]
    fn is_challenge_response_false_for_403_plain_body() {
        let body = "<html><body>Forbidden</body></html>";
        assert!(!is_challenge_response(403, body));
    }

    #[test]
    fn analyze_header_based_detection() {
        let no_headers = blocked_with_js_challenge(false);
        let with_headers = ok_result(true, false);
        let result = analyze_bot_detection(&no_headers, &with_headers, &[]);
        let profile = result.unwrap();
        assert!(profile.detected);
        assert_eq!(profile.detection_method, "header_analysis");
        assert_eq!(profile.challenge_response_code, Some(403));
    }

    #[test]
    fn analyze_both_blocked_js_challenge() {
        let no_headers = blocked_with_js_challenge(false);
        let with_headers = blocked_with_js_challenge(true);
        let result = analyze_bot_detection(&no_headers, &with_headers, &[]);
        let profile = result.unwrap();
        assert!(profile.detected);
        assert_eq!(profile.detection_method, "javascript_challenge");
    }

    #[test]
    fn analyze_both_blocked_captcha() {
        let no_headers = blocked_with_captcha(false);
        let with_headers = blocked_with_captcha(true);
        let result = analyze_bot_detection(&no_headers, &with_headers, &[]);
        let profile = result.unwrap();
        assert!(profile.detected);
        assert_eq!(profile.detection_method, "captcha");
    }

    #[test]
    fn analyze_behavioral_detection() {
        let no_headers = ok_result(false, false);
        let with_headers = ok_result(true, false);
        let rapid = vec![
            ok_result(true, true),
            ok_result(true, true),
            BotProbeResult {
                headers_sent: true,
                response_status: 429,
                response_body_snippet: "<script>challenge();</script>".to_string(),
                rapid_request: true,
            },
        ];
        let result = analyze_bot_detection(&no_headers, &with_headers, &rapid);
        let profile = result.unwrap();
        assert!(profile.detected);
        assert_eq!(profile.detection_method, "behavioral");
        assert_eq!(profile.challenge_response_code, Some(429));
    }

    #[test]
    fn analyze_no_detection_when_nothing_blocked() {
        let no_headers = ok_result(false, false);
        let with_headers = ok_result(true, false);
        let result = analyze_bot_detection(&no_headers, &with_headers, &[]);
        assert!(result.is_none());
    }

    #[test]
    fn analyze_no_detection_when_rapid_results_all_ok() {
        let no_headers = ok_result(false, false);
        let with_headers = ok_result(true, false);
        let rapid = vec![ok_result(true, true), ok_result(true, true)];
        let result = analyze_bot_detection(&no_headers, &with_headers, &rapid);
        assert!(result.is_none());
    }
}
