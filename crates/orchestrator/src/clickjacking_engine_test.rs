use super::clickjacking_engine::*;

fn headers_with(xfo: Option<&str>, csp: Option<&str>) -> ResponseHeaders {
    ResponseHeaders {
        x_frame_options: xfo.map(String::from),
        content_security_policy: csp.map(String::from),
        content_type: Some("text/html".into()),
    }
}

fn page(url: &str, xfo: Option<&str>, csp: Option<&str>, body: &str) -> PageContext {
    PageContext {
        url: url.to_string(),
        headers: headers_with(xfo, csp),
        body: body.to_string(),
    }
}

#[test]
fn detect_missing_xfo_and_frame_ancestors() {
    let h = headers_with(None, None);
    let patterns = analyze_headers(&h);
    assert!(patterns.contains(&ClickjackingPattern::MissingXfo));
    assert!(patterns.contains(&ClickjackingPattern::MissingFrameAncestors));
}

#[test]
fn detect_missing_xfo_with_csp_present() {
    let h = headers_with(None, Some("frame-ancestors 'self'"));
    let patterns = analyze_headers(&h);
    assert!(patterns.contains(&ClickjackingPattern::MissingXfo));
    assert!(!patterns.contains(&ClickjackingPattern::MissingFrameAncestors));
}

#[test]
fn detect_missing_frame_ancestors_with_xfo_present() {
    let h = headers_with(Some("DENY"), None);
    let patterns = analyze_headers(&h);
    assert!(!patterns.contains(&ClickjackingPattern::MissingXfo));
    assert!(patterns.contains(&ClickjackingPattern::MissingFrameAncestors));
}

#[test]
fn no_missing_headers_when_both_present() {
    let h = headers_with(Some("DENY"), Some("frame-ancestors 'none'"));
    let patterns = analyze_headers(&h);
    assert!(!patterns.contains(&ClickjackingPattern::MissingXfo));
    assert!(!patterns.contains(&ClickjackingPattern::MissingFrameAncestors));
}

#[test]
fn detect_wildcard_frame_ancestors() {
    let h = headers_with(None, Some("frame-ancestors *"));
    let patterns = analyze_headers(&h);
    assert!(patterns.contains(&ClickjackingPattern::WildcardFrameAncestors));
}

#[test]
fn detect_allow_from_deprecated() {
    let h = headers_with(Some("ALLOW-FROM https://evil.com"), None);
    let patterns = analyze_headers(&h);
    let has_allow_from = patterns.iter().any(|p| {
        matches!(p, ClickjackingPattern::AllowFromDeprecated { origin } if origin == "https://evil.com")
    });
    assert!(has_allow_from);
}

#[test]
fn detect_weak_xfo_invalid_value() {
    let h = headers_with(Some("INVALID-VALUE"), None);
    let patterns = analyze_headers(&h);
    let has_weak = patterns
        .iter()
        .any(|p| matches!(p, ClickjackingPattern::WeakXfo { value } if value == "INVALID-VALUE"));
    assert!(has_weak);
}

#[test]
fn detect_conflicting_xfo_deny_csp_allows() {
    let h = headers_with(Some("DENY"), Some("frame-ancestors https://example.com"));
    let patterns = analyze_headers(&h);
    assert!(
        patterns
            .iter()
            .any(|p| matches!(p, ClickjackingPattern::ConflictingHeaders { .. }))
    );
}

#[test]
fn detect_conflicting_xfo_sameorigin_csp_none() {
    let h = headers_with(Some("SAMEORIGIN"), Some("frame-ancestors 'none'"));
    let patterns = analyze_headers(&h);
    assert!(
        patterns
            .iter()
            .any(|p| matches!(p, ClickjackingPattern::ConflictingHeaders { .. }))
    );
}

#[test]
fn no_conflict_when_both_deny() {
    let h = headers_with(Some("DENY"), Some("frame-ancestors 'none'"));
    let patterns = analyze_headers(&h);
    assert!(
        !patterns
            .iter()
            .any(|p| matches!(p, ClickjackingPattern::ConflictingHeaders { .. }))
    );
}

#[test]
fn detect_frame_buster_top_location() {
    let body = r#"<script>if (top != self) { top.location = self.location; }</script>"#;
    let patterns = detect_frame_busters(body);
    assert!(patterns.iter().any(|p| matches!(
        p,
        ClickjackingPattern::FrameBusterBypassable {
            technique: FrameBusterBypass::SandboxAttribute
        }
    )));
}

#[test]
fn detect_frame_buster_onbeforeunload_bypass() {
    let body = r#"<script>if(top!==self){top.location.replace(self.location)}</script>"#;
    let patterns = detect_frame_busters(body);
    assert!(patterns.iter().any(|p| matches!(
        p,
        ClickjackingPattern::FrameBusterBypassable {
            technique: FrameBusterBypass::OnBeforeUnload
        }
    )));
}

#[test]
fn detect_frame_buster_double_framing_bypass() {
    let body = "<script>if (parent !== self) { parent.location = self.location; }</script>";
    let patterns = detect_frame_busters(body);
    assert!(patterns.iter().any(|p| matches!(
        p,
        ClickjackingPattern::FrameBusterBypassable {
            technique: FrameBusterBypass::DoubleFraming
        }
    )));
}

#[test]
fn no_frame_buster_in_clean_body() {
    let body = "<html><body><h1>Hello</h1></body></html>";
    let patterns = detect_frame_busters(body);
    assert!(patterns.is_empty());
}

#[test]
fn sandbox_bypass_detected_with_frame_buster() {
    let body = r#"<script>window.top.location = window.self.location;</script>"#;
    let patterns = detect_frame_busters(body);
    assert!(patterns.contains(&ClickjackingPattern::SandboxBypass));
}

#[test]
fn is_frameable_no_headers() {
    let h = ResponseHeaders::default();
    assert!(is_frameable(&h));
}

#[test]
fn is_not_frameable_xfo_deny() {
    let h = headers_with(Some("DENY"), None);
    assert!(!is_frameable(&h));
}

#[test]
fn is_not_frameable_csp_none() {
    let h = headers_with(None, Some("frame-ancestors 'none'"));
    assert!(!is_frameable(&h));
}

#[test]
fn is_not_frameable_csp_self() {
    let h = headers_with(None, Some("frame-ancestors 'self'"));
    assert!(!is_frameable(&h));
}

#[test]
fn is_frameable_xfo_sameorigin_no_csp() {
    let h = headers_with(Some("SAMEORIGIN"), None);
    assert!(is_frameable(&h));
}

#[test]
fn full_analysis_no_protection() {
    let ctx = page(
        "https://target.com/admin",
        None,
        None,
        "<form><input type='text'></form>",
    );
    let result = analyze(&ctx);
    assert!(result.patterns.contains(&ClickjackingPattern::MissingXfo));
    assert!(
        result
            .patterns
            .contains(&ClickjackingPattern::DoubleClickVulnerable)
    );
    assert!(
        result
            .patterns
            .contains(&ClickjackingPattern::DragDropVulnerable)
    );
    assert!(
        result
            .patterns
            .contains(&ClickjackingPattern::CursorJackingVulnerable)
    );
    assert!(
        result
            .patterns
            .contains(&ClickjackingPattern::TouchJackingVulnerable)
    );
    assert!(!result.pocs.is_empty());
}

#[test]
fn full_analysis_with_social_actions() {
    let body = r#"<div class="fb-like" data-action="like"></div>"#;
    let ctx = page("https://social.com/page", None, None, body);
    let result = analyze(&ctx);
    assert!(
        result
            .patterns
            .contains(&ClickjackingPattern::LikejackingVulnerable)
    );
}

#[test]
fn full_analysis_no_social_no_likejacking() {
    let ctx = page("https://target.com/plain", None, None, "<p>No social</p>");
    let result = analyze(&ctx);
    assert!(
        !result
            .patterns
            .contains(&ClickjackingPattern::LikejackingVulnerable)
    );
}

#[test]
fn full_analysis_protected_no_interactive_patterns() {
    let ctx = page(
        "https://secure.com",
        Some("DENY"),
        Some("frame-ancestors 'none'"),
        "<p>Secure</p>",
    );
    let result = analyze(&ctx);
    assert!(
        !result
            .patterns
            .contains(&ClickjackingPattern::DoubleClickVulnerable)
    );
    assert!(
        !result
            .patterns
            .contains(&ClickjackingPattern::DragDropVulnerable)
    );
    assert!(
        !result
            .patterns
            .contains(&ClickjackingPattern::CursorJackingVulnerable)
    );
    assert!(
        !result
            .patterns
            .contains(&ClickjackingPattern::TouchJackingVulnerable)
    );
}

#[test]
fn poc_basic_iframe_contains_target_url() {
    let poc = generate_poc("https://target.com", &ClickjackingPattern::MissingXfo);
    assert!(poc.html.contains("https://target.com"));
    assert!(poc.html.contains("<iframe"));
    assert!(poc.html.contains("opacity"));
}

#[test]
fn poc_double_click_has_dblclick_handler() {
    let poc = generate_poc(
        "https://target.com",
        &ClickjackingPattern::DoubleClickVulnerable,
    );
    assert!(poc.html.contains("ondblclick"));
    assert!(poc.html.contains("handleClick"));
}

#[test]
fn poc_drag_drop_has_drop_zone() {
    let poc = generate_poc(
        "https://target.com",
        &ClickjackingPattern::DragDropVulnerable,
    );
    assert!(poc.html.contains("drop-zone"));
    assert!(poc.html.contains("dragover"));
}

#[test]
fn poc_cursor_jacking_hides_real_cursor() {
    let poc = generate_poc(
        "https://target.com",
        &ClickjackingPattern::CursorJackingVulnerable,
    );
    assert!(poc.html.contains("cursor: none"));
    assert!(poc.html.contains("fake-cursor"));
}

#[test]
fn poc_touch_jacking_has_viewport_meta() {
    let poc = generate_poc(
        "https://target.com",
        &ClickjackingPattern::TouchJackingVulnerable,
    );
    assert!(poc.html.contains("viewport"));
    assert!(poc.html.contains("tap-highlight-color"));
}

#[test]
fn poc_likejacking_has_bait() {
    let poc = generate_poc(
        "https://social.com",
        &ClickjackingPattern::LikejackingVulnerable,
    );
    assert!(poc.html.contains("bait"));
    assert!(poc.html.contains("scrolling=\"no\""));
}

#[test]
fn poc_sandbox_bypass_has_sandbox_attr() {
    let poc = generate_poc("https://target.com", &ClickjackingPattern::SandboxBypass);
    assert!(poc.html.contains("sandbox="));
    assert!(poc.html.contains("allow-forms"));
}

#[test]
fn multi_step_analysis_requires_two_frameable() {
    let p1 = page("https://a.com/step1", None, None, "");
    let p2 = page("https://a.com/step2", None, None, "");
    let result = analyze_multi_step(&[p1, p2]);
    assert!(result.is_some());
    let poc = result.unwrap();
    assert!(poc.html.contains("https://a.com/step1"));
    assert!(poc.html.contains("https://a.com/step2"));
}

#[test]
fn multi_step_analysis_single_page_returns_none() {
    let p1 = page("https://a.com/step1", None, None, "");
    assert!(analyze_multi_step(&[p1]).is_none());
}

#[test]
fn multi_step_excludes_non_frameable() {
    let p1 = page("https://a.com/step1", None, None, "");
    let p2 = page("https://a.com/step2", Some("DENY"), None, "");
    let p3 = page("https://a.com/step3", None, None, "");
    let result = analyze_multi_step(&[p1, p2, p3]);
    assert!(result.is_some());
    let poc = result.unwrap();
    assert!(!poc.html.contains("https://a.com/step2"));
}

#[test]
fn pattern_severity_ranges() {
    let patterns = vec![
        ClickjackingPattern::MissingXfo,
        ClickjackingPattern::WeakXfo { value: "x".into() },
        ClickjackingPattern::MissingFrameAncestors,
        ClickjackingPattern::WildcardFrameAncestors,
        ClickjackingPattern::AllowFromDeprecated { origin: "x".into() },
        ClickjackingPattern::FrameBusterBypassable {
            technique: FrameBusterBypass::SandboxAttribute,
        },
        ClickjackingPattern::DoubleClickVulnerable,
        ClickjackingPattern::DragDropVulnerable,
        ClickjackingPattern::CursorJackingVulnerable,
        ClickjackingPattern::LikejackingVulnerable,
        ClickjackingPattern::TouchJackingVulnerable,
        ClickjackingPattern::MultiStepVulnerable { step_count: 3 },
        ClickjackingPattern::ConflictingHeaders {
            xfo: "x".into(),
            csp_fa: "y".into(),
        },
        ClickjackingPattern::SandboxBypass,
    ];
    for p in &patterns {
        let sev = pattern_severity(p);
        assert!(sev >= 0.0 && sev <= 10.0, "severity out of range for {p}");
    }
}

#[test]
fn pattern_display_all_variants() {
    let patterns = vec![
        ClickjackingPattern::MissingXfo,
        ClickjackingPattern::WeakXfo {
            value: "BAD".into(),
        },
        ClickjackingPattern::MissingFrameAncestors,
        ClickjackingPattern::WildcardFrameAncestors,
        ClickjackingPattern::AllowFromDeprecated {
            origin: "http://x".into(),
        },
        ClickjackingPattern::FrameBusterBypassable {
            technique: FrameBusterBypass::SandboxAttribute,
        },
        ClickjackingPattern::DoubleClickVulnerable,
        ClickjackingPattern::DragDropVulnerable,
        ClickjackingPattern::CursorJackingVulnerable,
        ClickjackingPattern::LikejackingVulnerable,
        ClickjackingPattern::TouchJackingVulnerable,
        ClickjackingPattern::MultiStepVulnerable { step_count: 2 },
        ClickjackingPattern::ConflictingHeaders {
            xfo: "DENY".into(),
            csp_fa: "*".into(),
        },
        ClickjackingPattern::SandboxBypass,
    ];
    for p in &patterns {
        let s = p.to_string();
        assert!(!s.is_empty(), "empty display for pattern");
    }
}

#[test]
fn frame_buster_bypass_display() {
    let bypasses = vec![
        FrameBusterBypass::SandboxAttribute,
        FrameBusterBypass::OnBeforeUnload,
        FrameBusterBypass::DoubleFraming,
        FrameBusterBypass::XssFilter,
        FrameBusterBypass::RestrictedZone,
    ];
    for b in &bypasses {
        assert!(!b.to_string().is_empty());
    }
}

#[test]
fn deduplication_in_analyze() {
    let ctx = page("https://target.com", None, None, "");
    let result = analyze(&ctx);
    let mut seen = std::collections::HashSet::new();
    for p in &result.patterns {
        assert!(seen.insert(p.clone()), "duplicate pattern: {p}");
    }
}

#[test]
fn pocs_generated_for_every_pattern() {
    let ctx = page(
        "https://target.com/full",
        None,
        None,
        r#"<script>if (top != self) { top.location = self.location; }</script>
           <form><input type="text"><div class="fb-like"></div></form>"#,
    );
    let result = analyze(&ctx);
    assert_eq!(result.patterns.len(), result.pocs.len());
    for poc in &result.pocs {
        assert!(!poc.html.is_empty());
        assert!(!poc.description.is_empty());
    }
}

#[test]
fn draggable_content_detection() {
    let with_input = page("https://t.com", None, None, "<input type='text'>");
    let res = analyze(&with_input);
    assert!(
        res.patterns
            .contains(&ClickjackingPattern::DragDropVulnerable)
    );

    let with_textarea = page("https://t.com", None, None, "<textarea></textarea>");
    let res2 = analyze(&with_textarea);
    assert!(
        res2.patterns
            .contains(&ClickjackingPattern::DragDropVulnerable)
    );

    let without = page("https://t.com", None, None, "<p>plain</p>");
    let res3 = analyze(&without);
    assert!(
        !res3
            .patterns
            .contains(&ClickjackingPattern::DragDropVulnerable)
    );
}

#[test]
fn csp_frame_ancestors_extraction_multiple_directives() {
    let h = headers_with(
        None,
        Some("default-src 'self'; frame-ancestors https://allowed.com; script-src 'none'"),
    );
    let patterns = analyze_headers(&h);
    assert!(!patterns.contains(&ClickjackingPattern::WildcardFrameAncestors));
    assert!(!patterns.contains(&ClickjackingPattern::MissingFrameAncestors));
}

#[test]
fn multi_step_three_pages_poc() {
    let pages = vec![
        page("https://a.com/1", None, None, ""),
        page("https://a.com/2", None, None, ""),
        page("https://a.com/3", None, None, ""),
    ];
    let result = analyze_multi_step(&pages).unwrap();
    assert!(result.html.contains("https://a.com/1"));
    assert!(result.html.contains("https://a.com/2"));
    assert!(result.html.contains("https://a.com/3"));
    assert!(matches!(
        result.pattern,
        ClickjackingPattern::MultiStepVulnerable { step_count: 3 }
    ));
}

#[test]
fn poc_onbeforeunload_bypass_content() {
    let poc = generate_poc(
        "https://target.com",
        &ClickjackingPattern::FrameBusterBypassable {
            technique: FrameBusterBypass::OnBeforeUnload,
        },
    );
    assert!(poc.html.contains("onbeforeunload"));
}

#[test]
fn poc_double_framing_content() {
    let poc = generate_poc(
        "https://target.com",
        &ClickjackingPattern::FrameBusterBypassable {
            technique: FrameBusterBypass::DoubleFraming,
        },
    );
    assert!(poc.html.contains("outer"));
    assert!(poc.html.contains("contentDocument"));
}

#[test]
fn poc_xss_filter_bypass_content() {
    let poc = generate_poc(
        "https://target.com",
        &ClickjackingPattern::FrameBusterBypassable {
            technique: FrameBusterBypass::XssFilter,
        },
    );
    assert!(poc.html.contains("%3Cscript%3E"));
}
