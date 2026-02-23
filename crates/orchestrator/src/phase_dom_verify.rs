use std::time::Duration;

use aegis_protocol::finding::{FindingData, VulnerabilityClass};
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::phase_error::PhaseError;
use crate::pipeline::{PhaseResult, ScanContext};
use crate::util::timestamp_ms;

/// Result of DOM verification for a single finding.
///
/// This is the orchestrator's representation -- does not depend on crawler
/// browser types. A future browser integration will produce these outcomes
/// from headless DOM execution.
#[derive(Debug, Clone)]
pub struct DomVerifyOutcome {
    pub finding_index: usize,
    pub dom_executed: bool,
    pub confidence_adjustment: f64,
}

/// Converts DOM verification outcomes into graph operations.
///
/// For each verified outcome where `dom_executed` is true, creates an
/// `AddFinding` operation with the original finding's vulnerability class
/// and severity, but with boosted confidence (original + adjustment, clamped
/// to 1.0). Non-executed outcomes are skipped to avoid creating
/// lower-confidence duplicate findings.
pub fn dom_verify_to_operations(
    outcomes: &[DomVerifyOutcome],
    findings: &[FindingData],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    outcomes
        .iter()
        .filter(|o| o.dom_executed && o.finding_index < findings.len())
        .map(|outcome| {
            let finding = &findings[outcome.finding_index];
            let boosted = (finding.confidence.composite.value() + outcome.confidence_adjustment)
                .clamp(0.0, 1.0);
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::Enumeration,
                operation: GraphOperation::AddFinding {
                    linked_node_ids: finding.linked_node_ids.clone(),
                    vulnerability_class: finding.vulnerability_class,
                    severity: finding.severity,
                    confidence: boosted,
                    certificate: Vec::new(),
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

/// XSS probe payload used for response-based verification. Contains a
/// distinctive marker that is unlikely to appear naturally in HTML, making
/// substring detection reliable.
const XSS_PROBE: &str = "<img src=x onerror=alert('AEGIS_XSS_PROBE')>";
const XSS_PROBE_MARKER: &str = "AEGIS_XSS_PROBE";

/// Confidence boost applied when an XSS probe is confirmed in a dangerous
/// HTML context. This moves a Statistical finding toward Confirmed territory.
const CONFIRMED_CONFIDENCE_BOOST: f64 = 0.3;

/// Event handler attribute prefixes that constitute dangerous injection
/// contexts when they contain user-controlled content.
const EVENT_HANDLER_PREFIXES: &[&str] = &[
    "onclick=",
    "onerror=",
    "onload=",
    "onmouseover=",
    "onfocus=",
    "onblur=",
    "onchange=",
    "onsubmit=",
    "onkeydown=",
    "onkeyup=",
    "onmouseout=",
    "ondblclick=",
];

/// Checks whether a payload marker appears unescaped inside a `<script>` block.
///
/// Scans for `<script` ... `</script>` regions and checks if `marker` appears
/// within them. Does not handle nested or CDATA scripts -- conservative
/// approximation that avoids false negatives on common templates.
pub fn payload_in_script_context(html: &str, marker: &str) -> bool {
    let lower = html.to_ascii_lowercase();
    let mut search_from = 0;
    while let Some(open) = lower[search_from..].find("<script") {
        let abs_open = search_from + open;
        let close = lower[abs_open..].find("</script");
        let abs_close = close.map_or(lower.len(), |c| abs_open + c);
        let block = &html[abs_open..abs_close];
        if block.contains(marker) {
            return true;
        }
        search_from = abs_close + 1;
    }
    false
}

/// Checks whether a payload marker appears inside an HTML event handler
/// attribute (e.g. `onclick="...marker..."`).
pub fn payload_in_event_handler(html: &str, marker: &str) -> bool {
    let lower = html.to_ascii_lowercase();
    for prefix in EVENT_HANDLER_PREFIXES {
        let mut search_from = 0;
        while let Some(pos) = lower[search_from..].find(prefix) {
            let abs_pos = search_from + pos + prefix.len();
            let remaining = &html[abs_pos..];
            let attr_end = find_attribute_end(remaining);
            if remaining[..attr_end].contains(marker) {
                return true;
            }
            search_from = abs_pos + attr_end;
        }
    }
    false
}

/// Finds the end of an HTML attribute value. Handles quoted (`"..."` or
/// `'...'`) and unquoted (terminated by whitespace or `>`) values.
fn find_attribute_end(s: &str) -> usize {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return 0;
    }
    match bytes[0] {
        b'"' => s[1..].find('"').map_or(s.len(), |i| i + 2),
        b'\'' => s[1..].find('\'').map_or(s.len(), |i| i + 2),
        _ => s
            .find(|c: char| c.is_ascii_whitespace() || c == '>')
            .unwrap_or(s.len()),
    }
}

/// Checks whether a payload marker appears inside a `javascript:` URI
/// in an `href` attribute.
pub fn payload_in_javascript_href(html: &str, marker: &str) -> bool {
    let lower = html.to_ascii_lowercase();
    let mut search_from = 0;
    while let Some(pos) = lower[search_from..].find("href=") {
        let abs_pos = search_from + pos + 5;
        let remaining = &html[abs_pos..];
        let attr_end = find_attribute_end(remaining);
        let attr_value = &remaining[..attr_end];
        let trimmed = attr_value.trim_start_matches(['"', '\'']);
        if trimmed.to_ascii_lowercase().starts_with("javascript:") && attr_value.contains(marker) {
            return true;
        }
        search_from = abs_pos + attr_end;
    }
    false
}

/// Returns `true` if `marker` appears in any dangerous HTML context in the
/// response body: inside script tags, event handlers, or javascript: hrefs.
pub fn is_payload_in_dangerous_context(html: &str, marker: &str) -> bool {
    payload_in_script_context(html, marker)
        || payload_in_event_handler(html, marker)
        || payload_in_javascript_href(html, marker)
}

/// Resolves the endpoint path and HTTP method for a finding by examining
/// its linked nodes. Returns `None` if no Endpoint node is found.
fn resolve_endpoint_info(finding: &FindingData, ctx: &ScanContext) -> Option<(String, String)> {
    for &node_id in &finding.linked_node_ids {
        if let Ok(Some(node)) = ctx.graph.get_node(node_id)
            && node.node_type == NodeType::Endpoint
        {
            let path = node.properties.get("path")?.clone();
            let method = node
                .properties
                .get("method")
                .cloned()
                .unwrap_or_else(|| "GET".to_string());
            return Some((path, method));
        }
    }
    None
}

/// Sends a probe request to the target endpoint and returns the response body.
/// Injects the XSS probe payload as a query parameter named `q`.
///
/// Returns `None` on transport errors.
fn fetch_with_probe(base_url: &str, path: &str) -> Option<String> {
    let url = format!("{base_url}{path}");
    let probe_url = if url.contains('?') {
        format!("{url}&q={}", urlencoded_probe())
    } else {
        format!("{url}?q={}", urlencoded_probe())
    };

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(false)
        .build()
        .ok()?;

    let response = client.get(&probe_url).send().ok()?;
    response.text().ok()
}

/// URL-encodes the XSS probe payload for safe injection into query strings.
fn urlencoded_probe() -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("", XSS_PROBE)
        .finish()
        .trim_start_matches('=')
        .to_string()
}

/// Verifies a single XSS finding by sending a probe request and checking
/// whether the payload lands in a dangerous HTML context.
fn verify_single_finding(
    finding: &FindingData,
    finding_index: usize,
    ctx: &ScanContext,
) -> DomVerifyOutcome {
    let Some((path, _method)) = resolve_endpoint_info(finding, ctx) else {
        return DomVerifyOutcome {
            finding_index,
            dom_executed: false,
            confidence_adjustment: 0.0,
        };
    };

    let base_url = ctx.config.target.clone();
    let body = std::thread::spawn(move || fetch_with_probe(&base_url, &path))
        .join()
        .unwrap_or(None);

    let Some(html) = body else {
        return DomVerifyOutcome {
            finding_index,
            dom_executed: false,
            confidence_adjustment: 0.0,
        };
    };

    let confirmed = is_payload_in_dangerous_context(&html, XSS_PROBE_MARKER);
    DomVerifyOutcome {
        finding_index,
        dom_executed: confirmed,
        confidence_adjustment: if confirmed {
            CONFIRMED_CONFIDENCE_BOOST
        } else {
            0.0
        },
    }
}

/// Runs the DOM verification phase.
///
/// Queries the graph for XSS findings and verifies each by re-sending a
/// probe request to the associated endpoint. Checks whether the probe
/// payload appears unescaped in a dangerous HTML context (script tags,
/// event handlers, javascript: URIs). Confirmed findings receive a
/// boosted-confidence AddFinding operation.
pub fn run_dom_verify(ctx: &mut ScanContext) -> Result<PhaseResult, PhaseError> {
    let xss_finding_ids = ctx
        .graph
        .findings_by_class(VulnerabilityClass::CrossSiteScripting)?;

    if xss_finding_ids.is_empty() {
        return Ok(PhaseResult {
            operations_applied: 0,
            findings_count: 0,
        });
    }

    let findings: Vec<FindingData> = xss_finding_ids
        .iter()
        .filter_map(|&id| ctx.graph.get_finding(id).ok().flatten())
        .collect();

    let outcomes: Vec<DomVerifyOutcome> = findings
        .iter()
        .enumerate()
        .map(|(i, f)| verify_single_finding(f, i, ctx))
        .collect();

    let confirmed_count = outcomes.iter().filter(|o| o.dom_executed).count();
    tracing::info!(
        total_xss = findings.len(),
        confirmed = confirmed_count,
        "DOM XSS verification complete"
    );

    let mut seq = ctx.graph.total_operations_applied()?;
    let ops = dom_verify_to_operations(&outcomes, &findings, &mut seq);
    let ops_count = ops.len() as u64;

    if !ops.is_empty() {
        ctx.graph.apply_operations(&ops)?;
    }

    Ok(PhaseResult {
        operations_applied: ops_count,
        findings_count: ops_count,
    })
}
