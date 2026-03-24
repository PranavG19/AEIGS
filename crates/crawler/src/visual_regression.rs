use serde::{Deserialize, Serialize};

/// Result of comparing two screenshots pixel-by-pixel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PixelDiffResult {
    pub total_pixels: u64,
    pub changed_pixels: u64,
    pub change_percentage: f64,
    pub changed_regions: Vec<ChangedRegion>,
    pub is_significant: bool,
}

/// A rectangular region of the image that changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangedRegion {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub pixel_count: u64,
}

/// Result of comparing two DOM trees.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomDiffResult {
    pub added_elements: Vec<DomElement>,
    pub removed_elements: Vec<DomElement>,
    pub modified_elements: Vec<DomModification>,
    pub total_changes: u32,
    pub has_injected_content: bool,
}

/// A simplified DOM element representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomElement {
    pub tag: String,
    pub id: Option<String>,
    pub classes: Vec<String>,
    pub text_content: String,
    pub attributes: Vec<(String, String)>,
}

/// A modification to an existing DOM element.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomModification {
    pub element: DomElement,
    pub change_type: DomChangeType,
    pub old_value: String,
    pub new_value: String,
}

/// Type of DOM change detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomChangeType {
    TextChanged,
    AttributeChanged,
    StyleChanged,
    ClassChanged,
    ContentInjected,
}

/// Result of comparing text content between before/after states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextDiffResult {
    pub added_text: Vec<String>,
    pub removed_text: Vec<String>,
    pub has_data_leak: bool,
    pub leaked_patterns: Vec<LeakedPattern>,
}

/// A pattern that suggests data leakage into the page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakedPattern {
    pub pattern_type: LeakPatternType,
    pub matched_text: String,
    pub context: String,
}

/// Type of data leak pattern detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LeakPatternType {
    Email,
    SqlError,
    StackTrace,
    InternalPath,
    DatabaseRecord,
    SessionToken,
    ApiKey,
    ConfigData,
}

/// Full visual regression analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualRegressionResult {
    pub pixel_diff: Option<PixelDiffResult>,
    pub dom_diff: DomDiffResult,
    pub text_diff: TextDiffResult,
    pub xss_indicators: Vec<XssIndicator>,
    pub verdict: AttackVerdict,
}

/// Indicators that an XSS attack succeeded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssIndicator {
    pub indicator_type: XssIndicatorType,
    pub evidence: String,
    pub confidence: f64,
}

/// Type of XSS success indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XssIndicatorType {
    AlertDialog,
    NewScriptTag,
    NewIframe,
    NewEventHandler,
    DomContentInjection,
    UrlRedirect,
    CookieAccess,
}

/// Verdict on whether an attack was visually confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackVerdict {
    Confirmed,
    Likely,
    Inconclusive,
    NotDetected,
}

/// Configuration for visual regression detection thresholds.
#[derive(Debug, Clone)]
pub struct VisualRegressionConfig {
    pub pixel_change_threshold: f64,
    pub significant_region_min_pixels: u64,
    pub detect_xss: bool,
    pub detect_data_leaks: bool,
}

impl Default for VisualRegressionConfig {
    fn default() -> Self {
        Self {
            pixel_change_threshold: 0.01,
            significant_region_min_pixels: 100,
            detect_xss: true,
            detect_data_leaks: true,
        }
    }
}

impl VisualRegressionConfig {
    pub fn with_pixel_change_threshold(mut self, threshold: f64) -> Self {
        self.pixel_change_threshold = threshold;
        self
    }

    pub fn with_significant_region_min_pixels(mut self, min: u64) -> Self {
        self.significant_region_min_pixels = min;
        self
    }
}

/// Compare two raw pixel buffers (RGBA format) to detect visual changes.
///
/// Each pixel is 4 bytes (R, G, B, A). Returns change statistics and
/// identifies rectangular regions where significant changes occurred.
pub fn pixel_diff(
    before: &[u8],
    after: &[u8],
    width: u32,
    height: u32,
    config: &VisualRegressionConfig,
) -> PixelDiffResult {
    let total_pixels = (width as u64) * (height as u64);
    let mut changed_pixels = 0u64;

    let pixel_count = (width * height) as usize;
    let mut change_map = vec![false; pixel_count];

    let bytes_per_pixel = 4;
    for (i, changed) in change_map.iter_mut().enumerate() {
        let offset = i * bytes_per_pixel;
        if offset + bytes_per_pixel > before.len() || offset + bytes_per_pixel > after.len() {
            break;
        }

        let dr = (before[offset] as i32 - after[offset] as i32).unsigned_abs();
        let dg = (before[offset + 1] as i32 - after[offset + 1] as i32).unsigned_abs();
        let db = (before[offset + 2] as i32 - after[offset + 2] as i32).unsigned_abs();

        if dr > 10 || dg > 10 || db > 10 {
            changed_pixels += 1;
            *changed = true;
        }
    }

    let change_percentage = if total_pixels > 0 {
        changed_pixels as f64 / total_pixels as f64
    } else {
        0.0
    };

    let changed_regions = find_changed_regions(&change_map, width, height, config);
    let is_significant = change_percentage >= config.pixel_change_threshold;

    PixelDiffResult {
        total_pixels,
        changed_pixels,
        change_percentage,
        changed_regions,
        is_significant,
    }
}

fn find_changed_regions(
    change_map: &[bool],
    width: u32,
    height: u32,
    config: &VisualRegressionConfig,
) -> Vec<ChangedRegion> {
    let mut visited = vec![false; change_map.len()];
    let mut regions = Vec::new();

    for y in 0..height {
        for x in 0..width {
            let idx = (y * width + x) as usize;
            if change_map[idx] && !visited[idx] {
                let (min_x, min_y, max_x, max_y, count) =
                    flood_fill(change_map, &mut visited, width, height, x, y);

                if count >= config.significant_region_min_pixels {
                    regions.push(ChangedRegion {
                        x: min_x,
                        y: min_y,
                        width: max_x - min_x + 1,
                        height: max_y - min_y + 1,
                        pixel_count: count,
                    });
                }
            }
        }
    }

    regions
}

fn flood_fill(
    change_map: &[bool],
    visited: &mut [bool],
    width: u32,
    height: u32,
    start_x: u32,
    start_y: u32,
) -> (u32, u32, u32, u32, u64) {
    let mut stack = vec![(start_x, start_y)];
    let mut min_x = start_x;
    let mut min_y = start_y;
    let mut max_x = start_x;
    let mut max_y = start_y;
    let mut count = 0u64;

    while let Some((x, y)) = stack.pop() {
        let idx = (y * width + x) as usize;
        if visited[idx] || !change_map[idx] {
            continue;
        }
        visited[idx] = true;
        count += 1;

        min_x = min_x.min(x);
        min_y = min_y.min(y);
        max_x = max_x.max(x);
        max_y = max_y.max(y);

        if x > 0 {
            stack.push((x - 1, y));
        }
        if x + 1 < width {
            stack.push((x + 1, y));
        }
        if y > 0 {
            stack.push((x, y - 1));
        }
        if y + 1 < height {
            stack.push((x, y + 1));
        }
    }

    (min_x, min_y, max_x, max_y, count)
}

/// Compare two HTML DOM strings to detect structural changes.
///
/// Extracts elements from before/after HTML, finds additions, removals,
/// and modifications, and checks for injected content that might indicate
/// successful XSS or other injection attacks.
pub fn dom_diff(before_html: &str, after_html: &str) -> DomDiffResult {
    let before_elements = extract_dom_elements(before_html);
    let after_elements = extract_dom_elements(after_html);

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let modified: Vec<DomModification> = Vec::new();

    for elem in &after_elements {
        if !before_elements.contains(elem) {
            added.push(elem.clone());
        }
    }

    for elem in &before_elements {
        if !after_elements.contains(elem) {
            removed.push(elem.clone());
        }
    }

    let has_injected = added.iter().any(|e| {
        let tag = e.tag.to_lowercase();
        tag == "script"
            || tag == "iframe"
            || tag == "object"
            || tag == "embed"
            || e.text_content.contains("alert(")
            || e.text_content.contains("onerror=")
            || e.text_content.contains("javascript:")
    });

    let total = (added.len() + removed.len() + modified.len()) as u32;

    DomDiffResult {
        added_elements: added,
        removed_elements: removed,
        modified_elements: modified,
        total_changes: total,
        has_injected_content: has_injected,
    }
}

fn extract_dom_elements(html: &str) -> Vec<DomElement> {
    let mut elements = Vec::new();

    let tags = [
        "script", "iframe", "div", "span", "p", "a", "form", "input", "img", "button", "h1", "h2",
        "h3", "h4", "h5", "h6", "ul", "ol", "li", "table", "tr", "td", "th", "nav", "header",
        "footer", "section", "article", "object", "embed", "svg",
    ];

    let id_re = regex::Regex::new(r#"(?i)id\s*=\s*["']([^"']+)["']"#).unwrap();
    let class_re = regex::Regex::new(r#"(?i)class\s*=\s*["']([^"']+)["']"#).unwrap();

    for tag in tags {
        let pattern = format!(r"(?is)<{tag}(\s[^>]*)?>([^<]*)</{tag}>");
        let re = regex::Regex::new(&pattern).unwrap();

        for cap in re.captures_iter(html) {
            let attrs_str = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let text = cap[2].trim().to_string();

            let id = id_re.captures(attrs_str).map(|c| c[1].to_string());
            let classes = class_re
                .captures(attrs_str)
                .map(|c| {
                    c[1].split_whitespace()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            elements.push(DomElement {
                tag: tag.to_string(),
                id,
                classes,
                text_content: text,
                attributes: Vec::new(),
            });
        }
    }

    elements
}

/// Compare text content between before and after states to detect data leaks.
pub fn text_diff(before_text: &str, after_text: &str) -> TextDiffResult {
    let before_lines: std::collections::HashSet<&str> = before_text
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();
    let after_lines: std::collections::HashSet<&str> = after_text
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();

    let added: Vec<String> = after_lines
        .difference(&before_lines)
        .map(|s| s.to_string())
        .collect();
    let removed: Vec<String> = before_lines
        .difference(&after_lines)
        .map(|s| s.to_string())
        .collect();

    let leaked_patterns = detect_leak_patterns(&added);
    let has_data_leak = !leaked_patterns.is_empty();

    TextDiffResult {
        added_text: added,
        removed_text: removed,
        has_data_leak,
        leaked_patterns,
    }
}

fn detect_leak_patterns(added_text: &[String]) -> Vec<LeakedPattern> {
    let mut patterns = Vec::new();

    let checks: &[(&str, LeakPatternType)] = &[
        (
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            LeakPatternType::Email,
        ),
        (
            r"(?i)(?:sql|syntax|query)\s+error",
            LeakPatternType::SqlError,
        ),
        (
            r"(?i)(?:at\s+[\w.]+\.\w+\(|Traceback|stack\s*trace)",
            LeakPatternType::StackTrace,
        ),
        (
            r"(?:/home/|/var/|/etc/|C:\\|/usr/)[^\s]+",
            LeakPatternType::InternalPath,
        ),
        (
            r"(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\s+(?:FROM|INTO|SET|WHERE)",
            LeakPatternType::DatabaseRecord,
        ),
        (
            r"(?i)(?:session|token|sid)\s*[=:]\s*[A-Za-z0-9._-]{16,}",
            LeakPatternType::SessionToken,
        ),
        (
            r"(?i)(?:api[_-]?key|secret)\s*[=:]\s*[A-Za-z0-9._-]{16,}",
            LeakPatternType::ApiKey,
        ),
        (
            r"(?i)(?:database|db_host|db_pass|connection_string)\s*[=:]",
            LeakPatternType::ConfigData,
        ),
    ];

    for text in added_text {
        for (pattern, pattern_type) in checks {
            let re = regex::Regex::new(pattern).unwrap();
            for mat in re.find_iter(text) {
                patterns.push(LeakedPattern {
                    pattern_type: *pattern_type,
                    matched_text: mat.as_str().to_string(),
                    context: text.clone(),
                });
            }
        }
    }

    patterns
}

/// Detect XSS success indicators by comparing before/after DOM state.
pub fn detect_xss_indicators(before_html: &str, after_html: &str) -> Vec<XssIndicator> {
    let mut indicators = Vec::new();

    let script_re = regex::Regex::new(r"(?is)<script[^>]*>").unwrap();
    let before_scripts = script_re.find_iter(before_html).count();
    let after_scripts = script_re.find_iter(after_html).count();
    if after_scripts > before_scripts {
        indicators.push(XssIndicator {
            indicator_type: XssIndicatorType::NewScriptTag,
            evidence: format!(
                "New script tags detected: {} before, {} after",
                before_scripts, after_scripts
            ),
            confidence: 0.9,
        });
    }

    let iframe_re = regex::Regex::new(r"(?is)<iframe[^>]*>").unwrap();
    let before_iframes = iframe_re.find_iter(before_html).count();
    let after_iframes = iframe_re.find_iter(after_html).count();
    if after_iframes > before_iframes {
        indicators.push(XssIndicator {
            indicator_type: XssIndicatorType::NewIframe,
            evidence: format!(
                "New iframe tags detected: {} before, {} after",
                before_iframes, after_iframes
            ),
            confidence: 0.85,
        });
    }

    let handler_re =
        regex::Regex::new(r#"(?i)(?:onerror|onload|onclick|onmouseover)\s*=\s*["']"#).unwrap();
    let before_handlers = handler_re.find_iter(before_html).count();
    let after_handlers = handler_re.find_iter(after_html).count();
    if after_handlers > before_handlers {
        indicators.push(XssIndicator {
            indicator_type: XssIndicatorType::NewEventHandler,
            evidence: format!(
                "New event handlers: {} before, {} after",
                before_handlers, after_handlers
            ),
            confidence: 0.8,
        });
    }

    if after_html.contains("alert(") && !before_html.contains("alert(") {
        indicators.push(XssIndicator {
            indicator_type: XssIndicatorType::AlertDialog,
            evidence: "alert() call injected into page".to_string(),
            confidence: 0.95,
        });
    }

    if after_html.contains("document.cookie") && !before_html.contains("document.cookie") {
        indicators.push(XssIndicator {
            indicator_type: XssIndicatorType::CookieAccess,
            evidence: "document.cookie access injected".to_string(),
            confidence: 0.9,
        });
    }

    indicators
}

/// Perform full visual regression analysis between before and after states.
///
/// Combines pixel diffing (if screenshots provided), DOM comparison,
/// text comparison for data leaks, and XSS indicator detection into
/// a unified verdict on whether an attack was successful.
pub fn analyze_visual_regression(
    before_screenshot: Option<(&[u8], u32, u32)>,
    after_screenshot: Option<(&[u8], u32, u32)>,
    before_html: &str,
    after_html: &str,
    config: &VisualRegressionConfig,
) -> VisualRegressionResult {
    let pixel_diff_result = match (before_screenshot, after_screenshot) {
        (Some((before, bw, bh)), Some((after, aw, ah))) if bw == aw && bh == ah => {
            Some(pixel_diff(before, after, bw, bh, config))
        }
        _ => None,
    };

    let dom_diff_result = dom_diff(before_html, after_html);

    let before_text = strip_tags(before_html);
    let after_text = strip_tags(after_html);
    let text_diff_result = text_diff(&before_text, &after_text);

    let xss_indicators = if config.detect_xss {
        detect_xss_indicators(before_html, after_html)
    } else {
        Vec::new()
    };

    let verdict = determine_verdict(
        &pixel_diff_result,
        &dom_diff_result,
        &text_diff_result,
        &xss_indicators,
    );

    VisualRegressionResult {
        pixel_diff: pixel_diff_result,
        dom_diff: dom_diff_result,
        text_diff: text_diff_result,
        xss_indicators,
        verdict,
    }
}

fn determine_verdict(
    _pixel_diff: &Option<PixelDiffResult>,
    dom_diff: &DomDiffResult,
    text_diff: &TextDiffResult,
    xss_indicators: &[XssIndicator],
) -> AttackVerdict {
    let high_conf_xss = xss_indicators.iter().any(|i| i.confidence >= 0.9);
    if high_conf_xss && dom_diff.has_injected_content {
        return AttackVerdict::Confirmed;
    }

    if high_conf_xss || dom_diff.has_injected_content {
        return AttackVerdict::Likely;
    }

    if !xss_indicators.is_empty() || text_diff.has_data_leak {
        return AttackVerdict::Inconclusive;
    }

    AttackVerdict::NotDetected
}

fn strip_tags(html: &str) -> String {
    let re = regex::Regex::new(r"<[^>]+>").unwrap();
    re.replace_all(html, " ").to_string()
}

#[cfg(test)]
#[path = "visual_regression_test.rs"]
mod visual_regression_test;
