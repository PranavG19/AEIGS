use aegis_protocol::finding::{FindingData, VulnerabilityClass};
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

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
            let boosted = (finding.confidence + outcome.confidence_adjustment).clamp(0.0, 1.0);
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

/// Runs the DOM verification phase.
///
/// Queries the graph for XSS findings and would verify them via headless
/// browser DOM execution. Currently returns an empty result since
/// browser-backed verification requires the `browser` feature on the
/// crawler crate. The phase slot exists for future integration.
pub fn run_dom_verify(ctx: &mut ScanContext) -> Result<PhaseResult, String> {
    let _xss_finding_ids = ctx
        .graph
        .findings_by_class(VulnerabilityClass::CrossSiteScripting)
        .map_err(|e| format!("{e:?}"))?;

    Ok(PhaseResult {
        operations_applied: 0,
        findings_count: 0,
    })
}
