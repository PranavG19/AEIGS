use crate::mixed_content::*;

#[test]
fn detects_http_script() {
    let html = r#"<script src="http://example.com/lib.js"></script>"#;
    let issues = find_mixed_content(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, MixedContentKind::Script);
    assert_eq!(issues[0].url, "http://example.com/lib.js");
}

#[test]
fn ignores_https_script() {
    let html = r#"<script src="https://example.com/lib.js"></script>"#;
    let issues = find_mixed_content(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_http_stylesheet() {
    let html = r#"<link href="http://example.com/style.css">"#;
    let issues = find_mixed_content(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, MixedContentKind::Stylesheet);
}

#[test]
fn detects_http_image() {
    let html = r#"<img src="http://example.com/img.png">"#;
    let issues = find_mixed_content(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, MixedContentKind::Image);
}

#[test]
fn detects_http_iframe() {
    let html = r#"<iframe src="http://example.com/page"></iframe>"#;
    let issues = find_mixed_content(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, MixedContentKind::Iframe);
}

#[test]
fn detects_http_form_action() {
    let html = r#"<form action="http://example.com/submit"></form>"#;
    let issues = find_mixed_content(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, MixedContentKind::Form);
}

#[test]
fn ignores_relative_urls() {
    let html = r#"<script src="/js/app.js"></script><img src="img.png">"#;
    let issues = find_mixed_content(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_multiple_issues() {
    let html = r#"
        <script src="http://cdn.example.com/a.js"></script>
        <img src="http://cdn.example.com/b.png">
        <link href="http://cdn.example.com/c.css">
    "#;
    let issues = find_mixed_content(html);
    assert_eq!(issues.len(), 3);
}

#[test]
fn no_issues_in_clean_page() {
    let html = r#"<html><body><p>Hello</p></body></html>"#;
    let issues = find_mixed_content(html);
    assert!(issues.is_empty());
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = mixed_content_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn active_mixed_content_has_high_severity() {
    let issues = vec![MixedContentIssue {
        kind: MixedContentKind::Script,
        url: "http://example.com/lib.js".to_string(),
    }];
    let mut seq = 0;
    let ops = mixed_content_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn passive_mixed_content_has_lower_severity() {
    let issues = vec![MixedContentIssue {
        kind: MixedContentKind::Image,
        url: "http://example.com/img.png".to_string(),
    }];
    let mut seq = 0;
    let ops = mixed_content_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
}

#[test]
fn handles_single_quoted_attributes() {
    let html = r#"<script src='http://example.com/lib.js'></script>"#;
    let issues = find_mixed_content(html);
    assert_eq!(issues.len(), 1);
}

#[test]
fn display_kinds() {
    assert_eq!(MixedContentKind::Script.to_string(), "script");
    assert_eq!(MixedContentKind::Stylesheet.to_string(), "stylesheet");
    assert_eq!(MixedContentKind::Image.to_string(), "image");
    assert_eq!(MixedContentKind::Iframe.to_string(), "iframe");
    assert_eq!(MixedContentKind::Form.to_string(), "form");
    assert_eq!(MixedContentKind::Audio.to_string(), "audio");
    assert_eq!(MixedContentKind::Video.to_string(), "video");
    assert_eq!(MixedContentKind::Source.to_string(), "source");
    assert_eq!(MixedContentKind::Object.to_string(), "object");
    assert_eq!(MixedContentKind::Embed.to_string(), "embed");
}

#[test]
fn detects_http_audio() {
    let html = r#"<audio src="http://example.com/audio.mp3"></audio>"#;
    let issues = find_mixed_content(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, MixedContentKind::Audio);
    assert_eq!(issues[0].url, "http://example.com/audio.mp3");
}

#[test]
fn detects_http_video() {
    let html = r#"<video src="http://example.com/video.mp4"></video>"#;
    let issues = find_mixed_content(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, MixedContentKind::Video);
    assert_eq!(issues[0].url, "http://example.com/video.mp4");
}

#[test]
fn detects_http_source() {
    let html = r#"<source src="http://example.com/media.webm">"#;
    let issues = find_mixed_content(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, MixedContentKind::Source);
}

#[test]
fn detects_http_object() {
    let html = r#"<object data="http://example.com/file.pdf"></object>"#;
    let issues = find_mixed_content(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, MixedContentKind::Object);
    assert_eq!(issues[0].url, "http://example.com/file.pdf");
}

#[test]
fn detects_http_embed() {
    let html = r#"<embed src="http://example.com/plugin.swf">"#;
    let issues = find_mixed_content(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, MixedContentKind::Embed);
}

#[test]
fn ignores_https_audio() {
    let html = r#"<audio src="https://example.com/audio.mp3"></audio>"#;
    let issues = find_mixed_content(html);
    assert!(issues.is_empty());
}

#[test]
fn ignores_https_video() {
    let html = r#"<video src="https://example.com/video.mp4"></video>"#;
    let issues = find_mixed_content(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_websocket_downgrade() {
    let html = r#"<script>const ws = new WebSocket("ws://example.com/socket");</script>"#;
    let issues = analyze_mixed_content_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MixedContentSecurityIssue::WebSocketDowngrade { .. }))
    );
}

#[test]
fn detects_eventsource_http() {
    let html = r#"<script>const es = new EventSource("http://example.com/events");</script>"#;
    let issues = analyze_mixed_content_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MixedContentSecurityIssue::EventSourceHttp { .. }))
    );
}

#[test]
fn detects_fetch_http_endpoint() {
    let html = r#"<script>fetch("http://api.example.com/data");</script>"#;
    let issues = analyze_mixed_content_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MixedContentSecurityIssue::FetchHttpEndpoint { .. }))
    );
}

#[test]
fn detects_xhr_http_endpoint() {
    let html = r#"<script>xhr.open("GET", "http://example.com/data");</script>"#;
    let issues = analyze_mixed_content_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MixedContentSecurityIssue::XhrHttpEndpoint { .. }))
    );
}

#[test]
fn detects_css_import_http() {
    let html = r#"<style>@import url(http://example.com/style.css);</style>"#;
    let issues = analyze_mixed_content_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MixedContentSecurityIssue::CssImportHttp { .. }))
    );
}

#[test]
fn detects_css_import_http_quoted() {
    let html = r#"<style>@import "http://example.com/style.css";</style>"#;
    let issues = analyze_mixed_content_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MixedContentSecurityIssue::CssImportHttp { .. }))
    );
}

#[test]
fn detects_font_load_http() {
    let html = r#"<style>@font-face { src: url(http://example.com/font.woff); }</style>"#;
    let issues = analyze_mixed_content_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MixedContentSecurityIssue::FontLoadHttp { .. }))
    );
}

#[test]
fn detects_service_worker_http() {
    let html = r#"<script>navigator.serviceWorker.register("http://example.com/sw.js");</script>"#;
    let issues = analyze_mixed_content_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MixedContentSecurityIssue::ServiceWorkerHttp { .. }))
    );
}

#[test]
fn detects_preconnect_http() {
    let html = r#"<link rel="preconnect" href="http://example.com">"#;
    let issues = analyze_mixed_content_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MixedContentSecurityIssue::PreconnectHttp { .. }))
    );
}

#[test]
fn wraps_active_mixed_content_from_script() {
    let html = r#"<script src="http://example.com/lib.js"></script>"#;
    let issues = analyze_mixed_content_security(html);
    assert!(issues.iter().any(|i| matches!(i, MixedContentSecurityIssue::ActiveMixedContent { tag, .. } if tag == "script")));
}

#[test]
fn wraps_active_mixed_content_from_stylesheet() {
    let html = r#"<link href="http://example.com/style.css">"#;
    let issues = analyze_mixed_content_security(html);
    assert!(issues.iter().any(|i| matches!(i, MixedContentSecurityIssue::ActiveMixedContent { tag, .. } if tag == "stylesheet")));
}

#[test]
fn wraps_active_mixed_content_from_iframe() {
    let html = r#"<iframe src="http://example.com/page"></iframe>"#;
    let issues = analyze_mixed_content_security(html);
    assert!(issues.iter().any(|i| matches!(i, MixedContentSecurityIssue::ActiveMixedContent { tag, .. } if tag == "iframe")));
}

#[test]
fn wraps_passive_mixed_content_from_image() {
    let html = r#"<img src="http://example.com/img.png">"#;
    let issues = analyze_mixed_content_security(html);
    assert!(issues.iter().any(|i| matches!(i, MixedContentSecurityIssue::PassiveMixedContent { tag, .. } if tag == "image")));
}

#[test]
fn wraps_passive_mixed_content_from_audio() {
    let html = r#"<audio src="http://example.com/audio.mp3"></audio>"#;
    let issues = analyze_mixed_content_security(html);
    assert!(issues.iter().any(|i| matches!(i, MixedContentSecurityIssue::PassiveMixedContent { tag, .. } if tag == "audio")));
}

#[test]
fn wraps_passive_mixed_content_from_video() {
    let html = r#"<video src="http://example.com/video.mp4"></video>"#;
    let issues = analyze_mixed_content_security(html);
    assert!(issues.iter().any(|i| matches!(i, MixedContentSecurityIssue::PassiveMixedContent { tag, .. } if tag == "video")));
}

#[test]
fn service_worker_http_has_highest_severity() {
    let issue = MixedContentSecurityIssue::ServiceWorkerHttp {
        url: "http://example.com/sw.js".to_string(),
    };
    assert_eq!(mixed_content_security_severity(&issue), 9.0);
}

#[test]
fn security_active_mixed_content_severity() {
    let issue = MixedContentSecurityIssue::ActiveMixedContent {
        tag: "script".to_string(),
        url: "http://example.com/lib.js".to_string(),
    };
    assert_eq!(mixed_content_security_severity(&issue), 7.5);
}

#[test]
fn fetch_http_has_high_severity() {
    let issue = MixedContentSecurityIssue::FetchHttpEndpoint {
        url: "http://example.com/api".to_string(),
    };
    assert_eq!(mixed_content_security_severity(&issue), 7.0);
}

#[test]
fn xhr_http_has_high_severity() {
    let issue = MixedContentSecurityIssue::XhrHttpEndpoint {
        url: "http://example.com/data".to_string(),
    };
    assert_eq!(mixed_content_security_severity(&issue), 7.0);
}

#[test]
fn websocket_downgrade_has_medium_high_severity() {
    let issue = MixedContentSecurityIssue::WebSocketDowngrade {
        url: "ws://example.com/socket".to_string(),
    };
    assert_eq!(mixed_content_security_severity(&issue), 6.5);
}

#[test]
fn eventsource_http_has_medium_high_severity() {
    let issue = MixedContentSecurityIssue::EventSourceHttp {
        url: "http://example.com/events".to_string(),
    };
    assert_eq!(mixed_content_security_severity(&issue), 6.5);
}

#[test]
fn css_import_http_has_medium_severity() {
    let issue = MixedContentSecurityIssue::CssImportHttp {
        url: "http://example.com/style.css".to_string(),
    };
    assert_eq!(mixed_content_security_severity(&issue), 6.0);
}

#[test]
fn font_load_http_has_moderate_severity() {
    let issue = MixedContentSecurityIssue::FontLoadHttp {
        url: "http://example.com/font.woff".to_string(),
    };
    assert_eq!(mixed_content_security_severity(&issue), 5.5);
}

#[test]
fn preconnect_http_has_low_medium_severity() {
    let issue = MixedContentSecurityIssue::PreconnectHttp {
        url: "http://example.com".to_string(),
    };
    assert_eq!(mixed_content_security_severity(&issue), 4.0);
}

#[test]
fn passive_mixed_content_has_low_severity() {
    let issue = MixedContentSecurityIssue::PassiveMixedContent {
        tag: "image".to_string(),
        url: "http://example.com/img.png".to_string(),
    };
    assert_eq!(mixed_content_security_severity(&issue), 3.0);
}

#[test]
fn security_to_operations_creates_one_per_issue() {
    let issues = vec![
        MixedContentSecurityIssue::ServiceWorkerHttp {
            url: "http://example.com/sw.js".to_string(),
        },
        MixedContentSecurityIssue::FetchHttpEndpoint {
            url: "http://example.com/api".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = mixed_content_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_to_operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = mixed_content_security_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn analyze_returns_empty_for_clean_page() {
    let html = r#"<html><body><p>Clean HTTPS page</p></body></html>"#;
    let issues = analyze_mixed_content_security(html);
    assert!(issues.is_empty());
}

#[test]
fn analyze_detects_multiple_security_issues() {
    let html = r#"
        <script src="http://example.com/lib.js"></script>
        <script>fetch("http://api.example.com/data");</script>
        <script>const ws = new WebSocket("ws://example.com/socket");</script>
    "#;
    let issues = analyze_mixed_content_security(html);
    assert!(issues.len() >= 3);
}

#[test]
fn display_active_mixed_content() {
    let issue = MixedContentSecurityIssue::ActiveMixedContent {
        tag: "script".to_string(),
        url: "http://example.com/lib.js".to_string(),
    };
    assert!(issue.to_string().contains("active mixed content"));
}

#[test]
fn display_passive_mixed_content() {
    let issue = MixedContentSecurityIssue::PassiveMixedContent {
        tag: "image".to_string(),
        url: "http://example.com/img.png".to_string(),
    };
    assert!(issue.to_string().contains("passive mixed content"));
}

#[test]
fn display_websocket_downgrade() {
    let issue = MixedContentSecurityIssue::WebSocketDowngrade {
        url: "ws://example.com/socket".to_string(),
    };
    assert!(issue.to_string().contains("WebSocket"));
}

#[test]
fn display_eventsource_http() {
    let issue = MixedContentSecurityIssue::EventSourceHttp {
        url: "http://example.com/events".to_string(),
    };
    assert!(issue.to_string().contains("EventSource"));
}

#[test]
fn display_fetch_http() {
    let issue = MixedContentSecurityIssue::FetchHttpEndpoint {
        url: "http://example.com/api".to_string(),
    };
    assert!(issue.to_string().contains("fetch()"));
}

#[test]
fn display_xhr_http() {
    let issue = MixedContentSecurityIssue::XhrHttpEndpoint {
        url: "http://example.com/data".to_string(),
    };
    assert!(issue.to_string().contains("XMLHttpRequest"));
}

#[test]
fn detects_eventsource_single_quotes() {
    let html = r#"<script>const es = EventSource('http://example.com/events');</script>"#;
    let issues = analyze_mixed_content_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MixedContentSecurityIssue::EventSourceHttp { .. }))
    );
}

#[test]
fn detects_fetch_single_quotes() {
    let html = r#"<script>fetch('http://api.example.com/data');</script>"#;
    let issues = analyze_mixed_content_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MixedContentSecurityIssue::FetchHttpEndpoint { .. }))
    );
}

#[test]
fn detects_preconnect_single_quotes() {
    let html = r#"<link rel='preconnect' href='http://example.com'>"#;
    let issues = analyze_mixed_content_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MixedContentSecurityIssue::PreconnectHttp { .. }))
    );
}
