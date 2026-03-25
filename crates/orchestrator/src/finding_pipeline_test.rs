use super::finding_pipeline::*;
use aegis_protocol::finding::{
    Confidence, EvidenceLevel, FindingConfidence, FindingData, VulnerabilityClass,
};
use aegis_protocol::operation::ModuleIdentifier;

fn make_finding(
    id: u64,
    class: VulnerabilityClass,
    linked_nodes: Vec<u64>,
    confidence: f64,
) -> FindingData {
    FindingData::new(id, class, 7.5, confidence, ModuleIdentifier::Fuzzing, 1000)
        .with_linked_nodes(linked_nodes)
}

#[test]
fn dedup_removes_duplicates() {
    let findings = vec![
        make_finding(1, VulnerabilityClass::SqlInjection, vec![10], 0.8),
        make_finding(2, VulnerabilityClass::SqlInjection, vec![10], 0.8),
        make_finding(3, VulnerabilityClass::CrossSiteScripting, vec![10], 0.8),
    ];

    let pipeline = FindingPipeline::default();
    let (results, stats) = pipeline.process(findings);

    assert_eq!(stats.input_count, 3);
    assert_eq!(stats.after_dedup, 2);
    assert!(results.len() <= 2);
}

#[test]
fn correlation_links_shared_node_findings() {
    let findings = vec![
        make_finding(1, VulnerabilityClass::SqlInjection, vec![100], 0.8),
        make_finding(2, VulnerabilityClass::CrossSiteScripting, vec![100], 0.8),
    ];

    let pipeline = FindingPipeline::default();
    let (results, _stats) = pipeline.process(findings);

    for r in &results {
        assert!(
            !r.correlated_with.is_empty(),
            "findings on same node should be correlated"
        );
    }
}

#[test]
fn chain_linking_connects_chainable_classes() {
    let findings = vec![
        make_finding(1, VulnerabilityClass::OpenRedirect, vec![10], 0.8),
        make_finding(
            2,
            VulnerabilityClass::ServerSideRequestForgery,
            vec![20],
            0.8,
        ),
    ];

    let pipeline = FindingPipeline::default();
    let (results, _) = pipeline.process(findings);

    let has_chain = results.iter().any(|r| !r.chain_ids.is_empty());
    assert!(has_chain, "open redirect + SSRF should form a chain");
}

#[test]
fn scoring_ranks_critical_higher() {
    let findings = vec![
        make_finding(1, VulnerabilityClass::SqlInjection, vec![10], 0.8),
        make_finding(2, VulnerabilityClass::OpenRedirect, vec![20], 0.8),
    ];

    let pipeline = FindingPipeline::default();
    let (results, _) = pipeline.process(findings);

    assert!(results.len() >= 2);
    assert!(
        results[0].risk_score >= results[1].risk_score,
        "higher severity should rank first"
    );
}

#[test]
fn fast_config_skips_verification() {
    let findings = vec![make_finding(
        1,
        VulnerabilityClass::SqlInjection,
        vec![10],
        0.8,
    )];

    let pipeline = FindingPipeline::new(FindingPipelineConfig::fast());
    let (results, stats) = pipeline.process(findings);

    assert_eq!(stats.after_verification, stats.after_scoring);
    assert!(!results.is_empty());
}

#[test]
fn compliance_config_keeps_low_confidence() {
    let low = make_finding(
        1,
        VulnerabilityClass::SecurityMisconfiguration,
        vec![5],
        0.1,
    );

    let pipeline = FindingPipeline::new(FindingPipelineConfig::compliance());
    let (results, _) = pipeline.process(vec![low]);

    assert!(
        !results.is_empty(),
        "compliance mode should keep low-confidence findings"
    );
}

#[test]
fn empty_input_produces_empty_output() {
    let pipeline = FindingPipeline::default();
    let (results, stats) = pipeline.process(vec![]);
    assert!(results.is_empty());
    assert_eq!(stats.input_count, 0);
    assert_eq!(stats.output_count, 0);
}

#[test]
fn output_sorted_by_risk_score_descending() {
    let findings = vec![
        make_finding(1, VulnerabilityClass::OpenRedirect, vec![10], 0.8),
        make_finding(2, VulnerabilityClass::SqlInjection, vec![20], 0.8),
        make_finding(3, VulnerabilityClass::CrossSiteScripting, vec![30], 0.8),
    ];

    let pipeline = FindingPipeline::default();
    let (results, _) = pipeline.process(findings);

    for pair in results.windows(2) {
        assert!(
            pair[0].risk_score >= pair[1].risk_score,
            "results should be sorted by risk_score desc"
        );
    }
}

#[test]
fn pipeline_stats_counts_are_monotonically_decreasing_or_equal() {
    let findings = vec![
        make_finding(1, VulnerabilityClass::SqlInjection, vec![10], 0.8),
        make_finding(2, VulnerabilityClass::SqlInjection, vec![10], 0.8),
        make_finding(3, VulnerabilityClass::CrossSiteScripting, vec![20], 0.8),
    ];

    let pipeline = FindingPipeline::default();
    let (_, stats) = pipeline.process(findings);

    assert!(stats.input_count >= stats.after_dedup);
    assert_eq!(stats.output_count, stats.after_verification);
}
