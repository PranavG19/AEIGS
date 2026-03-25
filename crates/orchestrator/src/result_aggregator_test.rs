use aegis_protocol::finding::{
    Confidence, EvidenceLevel, FindingConfidence, FindingData, VulnerabilityClass,
};
use aegis_protocol::operation::ModuleIdentifier;

use crate::result_aggregator::{AggregatorError, ResultAggregator, TechStackVote};

fn sample_finding(id: u64, class: VulnerabilityClass, node_ids: Vec<u64>) -> FindingData {
    FindingData {
        id,
        linked_node_ids: node_ids,
        vulnerability_class: class,
        severity: 7.5,
        confidence: FindingConfidence::from_simple(Confidence::new(0.8).unwrap()),
        certificate: Vec::new(),
        provenance_module: ModuleIdentifier::Fuzzing,
        timestamp_unix_ms: crate::util::timestamp_ms(),
        evidence_level: EvidenceLevel::Statistical,
        stable_id: None,
    }
}

// --- Submission ---

#[test]
fn submit_findings_tracks_count() {
    let mut agg = ResultAggregator::new(0.1);
    agg.submit_findings(
        "w1",
        vec![sample_finding(
            1,
            VulnerabilityClass::SqlInjection,
            vec![10],
        )],
    );
    assert_eq!(agg.raw_count(), 1);
}

#[test]
fn submit_from_multiple_workers() {
    let mut agg = ResultAggregator::new(0.1);
    agg.submit_findings(
        "w1",
        vec![sample_finding(
            1,
            VulnerabilityClass::SqlInjection,
            vec![10],
        )],
    );
    agg.submit_findings(
        "w2",
        vec![sample_finding(
            2,
            VulnerabilityClass::CrossSiteScripting,
            vec![20],
        )],
    );
    assert_eq!(agg.raw_count(), 2);
    assert_eq!(agg.worker_count(), 2);
}

// --- Aggregation ---

#[test]
fn aggregate_deduplicates_same_finding() {
    let mut agg = ResultAggregator::new(0.1);
    agg.submit_findings(
        "w1",
        vec![sample_finding(
            1,
            VulnerabilityClass::SqlInjection,
            vec![10],
        )],
    );
    agg.submit_findings(
        "w2",
        vec![sample_finding(
            1,
            VulnerabilityClass::SqlInjection,
            vec![10],
        )],
    );
    let results = agg.aggregate().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].confirmation_count, 2);
    assert_eq!(results[0].source_workers.len(), 2);
}

#[test]
fn aggregate_different_findings_stay_separate() {
    let mut agg = ResultAggregator::new(0.1);
    agg.submit_findings(
        "w1",
        vec![sample_finding(
            1,
            VulnerabilityClass::SqlInjection,
            vec![10],
        )],
    );
    agg.submit_findings(
        "w2",
        vec![sample_finding(
            2,
            VulnerabilityClass::CrossSiteScripting,
            vec![20],
        )],
    );
    let results = agg.aggregate().unwrap();
    assert_eq!(results.len(), 2);
}

#[test]
fn aggregate_boosts_confidence_on_confirmation() {
    let mut agg = ResultAggregator::new(0.05);
    agg.submit_findings(
        "w1",
        vec![sample_finding(
            1,
            VulnerabilityClass::SqlInjection,
            vec![10],
        )],
    );
    agg.submit_findings(
        "w2",
        vec![sample_finding(
            1,
            VulnerabilityClass::SqlInjection,
            vec![10],
        )],
    );
    agg.submit_findings(
        "w3",
        vec![sample_finding(
            1,
            VulnerabilityClass::SqlInjection,
            vec![10],
        )],
    );
    let results = agg.aggregate().unwrap();
    let boosted = results[0].boosted_confidence;
    assert!(boosted > 0.8, "confidence should be boosted: {boosted}");
}

#[test]
fn aggregate_confidence_capped_at_one() {
    let mut agg = ResultAggregator::new(0.5);
    for i in 0..10 {
        agg.submit_findings(
            &format!("w{i}"),
            vec![sample_finding(
                1,
                VulnerabilityClass::SqlInjection,
                vec![10],
            )],
        );
    }
    let results = agg.aggregate().unwrap();
    assert!(results[0].boosted_confidence <= 1.0);
}

#[test]
fn aggregate_empty_returns_error() {
    let agg = ResultAggregator::new(0.1);
    let result = agg.aggregate();
    assert!(result.is_err());
}

#[test]
fn aggregate_sorted_by_confidence_desc() {
    let mut agg = ResultAggregator::new(0.1);
    agg.submit_findings(
        "w1",
        vec![sample_finding(
            1,
            VulnerabilityClass::CrossSiteScripting,
            vec![20],
        )],
    );
    // Double-confirm the SQL injection to boost it
    agg.submit_findings(
        "w1",
        vec![sample_finding(
            2,
            VulnerabilityClass::SqlInjection,
            vec![10],
        )],
    );
    agg.submit_findings(
        "w2",
        vec![sample_finding(
            2,
            VulnerabilityClass::SqlInjection,
            vec![10],
        )],
    );
    let results = agg.aggregate().unwrap();
    assert!(results[0].boosted_confidence >= results[1].boosted_confidence);
}

// --- Tech stack resolution ---

#[test]
fn resolve_tech_stack_majority_vote() {
    let mut agg = ResultAggregator::new(0.1);
    agg.submit_tech_vote(TechStackVote {
        worker_id: "w1".to_string(),
        technology: "framework".to_string(),
        version: Some("express:4.18".to_string()),
    });
    agg.submit_tech_vote(TechStackVote {
        worker_id: "w2".to_string(),
        technology: "framework".to_string(),
        version: Some("express:4.18".to_string()),
    });
    agg.submit_tech_vote(TechStackVote {
        worker_id: "w3".to_string(),
        technology: "framework".to_string(),
        version: Some("flask:2.0".to_string()),
    });
    let resolved = agg.resolve_tech_stack();
    let winner = resolved.get("framework").unwrap();
    assert!(winner.contains("express"), "majority should win: {winner}");
}

#[test]
fn resolve_tech_stack_no_version() {
    let mut agg = ResultAggregator::new(0.1);
    agg.submit_tech_vote(TechStackVote {
        worker_id: "w1".to_string(),
        technology: "nginx".to_string(),
        version: None,
    });
    let resolved = agg.resolve_tech_stack();
    assert!(resolved.contains_key("nginx"));
}

#[test]
fn resolve_tech_stack_empty() {
    let agg = ResultAggregator::new(0.1);
    let resolved = agg.resolve_tech_stack();
    assert!(resolved.is_empty());
}

// --- Clear ---

#[test]
fn clear_resets_all_data() {
    let mut agg = ResultAggregator::new(0.1);
    agg.submit_findings(
        "w1",
        vec![sample_finding(
            1,
            VulnerabilityClass::SqlInjection,
            vec![10],
        )],
    );
    agg.submit_tech_vote(TechStackVote {
        worker_id: "w1".to_string(),
        technology: "express".to_string(),
        version: None,
    });
    agg.clear();
    assert_eq!(agg.raw_count(), 0);
    assert_eq!(agg.worker_count(), 0);
}

// --- Error display ---

#[test]
fn error_display() {
    let e = AggregatorError::NoFindings;
    assert!(format!("{e}").contains("no findings"));
    let e = AggregatorError::MergeConflict("test".to_string());
    assert!(format!("{e}").contains("merge conflict"));
}
