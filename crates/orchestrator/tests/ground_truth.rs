use serde::Deserialize;
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct GroundTruthEntry {
    pub endpoint: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub parameter: Option<String>,
    pub vulnerability_class: String,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GroundTruth {
    pub findings: Vec<GroundTruthEntry>,
}

#[derive(Debug)]
pub struct ComparisonResult {
    pub true_positives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub matched: Vec<String>,
    pub missed: Vec<String>,
    pub extra: Vec<String>,
}

pub fn load_ground_truth(path: &Path) -> GroundTruth {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to load ground truth from {}: {}", path.display(), e));
    serde_json::from_str(&content).unwrap_or_else(|e| {
        panic!(
            "Failed to parse ground truth from {}: {}",
            path.display(),
            e
        )
    })
}

fn normalize_endpoint(raw: &str) -> String {
    if let Some(rest) = raw
        .strip_prefix("http://")
        .or_else(|| raw.strip_prefix("https://"))
    {
        if let Some(slash_pos) = rest.find('/') {
            return rest[slash_pos..].to_string();
        }
    }
    raw.to_string()
}

pub fn extract_sarif_findings(sarif_path: &Path) -> HashSet<(String, String)> {
    let content = std::fs::read_to_string(sarif_path)
        .unwrap_or_else(|e| panic!("Failed to read SARIF from {}: {}", sarif_path.display(), e));
    let sarif: serde_json::Value = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse SARIF from {}: {}", sarif_path.display(), e));

    let mut findings = HashSet::new();
    if let Some(runs) = sarif["runs"].as_array() {
        for run in runs {
            if let Some(results) = run["results"].as_array() {
                for result in results {
                    let endpoint = result["endpoint"]
                        .as_str()
                        .or_else(|| result["properties"]["endpoint"].as_str())
                        .unwrap_or("");
                    let endpoint = normalize_endpoint(endpoint);
                    let vuln_class = result["vulnerabilityClass"]
                        .as_str()
                        .or_else(|| result["properties"]["vulnerabilityClass"].as_str())
                        .unwrap_or("")
                        .to_string();
                    if !vuln_class.is_empty() {
                        findings.insert((endpoint, vuln_class));
                    }
                }
            }
        }
    }
    findings
}

pub fn compare(
    ground_truth: &GroundTruth,
    sarif_findings: &HashSet<(String, String)>,
) -> ComparisonResult {
    let gt_set: HashSet<(String, String)> = ground_truth
        .findings
        .iter()
        .map(|f| (f.endpoint.clone(), f.vulnerability_class.clone()))
        .collect();

    let tp: HashSet<_> = sarif_findings.intersection(&gt_set).cloned().collect();
    let fp: HashSet<_> = sarif_findings.difference(&gt_set).cloned().collect();
    let fn_set: HashSet<_> = gt_set.difference(sarif_findings).cloned().collect();

    let precision = if sarif_findings.is_empty() {
        0.0
    } else {
        tp.len() as f64 / sarif_findings.len() as f64
    };
    let recall = if gt_set.is_empty() {
        0.0
    } else {
        tp.len() as f64 / gt_set.len() as f64
    };
    let f1 = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };

    ComparisonResult {
        true_positives: tp.len(),
        false_positives: fp.len(),
        false_negatives: fn_set.len(),
        precision,
        recall,
        f1,
        matched: tp.iter().map(|(e, v)| format!("{} ({})", e, v)).collect(),
        missed: fn_set
            .iter()
            .map(|(e, v)| format!("{} ({})", e, v))
            .collect(),
        extra: fp.iter().map(|(e, v)| format!("{} ({})", e, v)).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparison_computes_metrics_correctly() {
        let gt = GroundTruth {
            findings: vec![
                GroundTruthEntry {
                    endpoint: "/a".into(),
                    method: "GET".into(),
                    parameter: None,
                    vulnerability_class: "SqlInjection".into(),
                    operation: None,
                    note: None,
                },
                GroundTruthEntry {
                    endpoint: "/b".into(),
                    method: "GET".into(),
                    parameter: None,
                    vulnerability_class: "Xss".into(),
                    operation: None,
                    note: None,
                },
            ],
        };
        let mut sarif = HashSet::new();
        sarif.insert(("/a".to_string(), "SqlInjection".to_string()));
        sarif.insert(("/c".to_string(), "PathTraversal".to_string()));

        let result = compare(&gt, &sarif);
        assert_eq!(result.true_positives, 1);
        assert_eq!(result.false_positives, 1);
        assert_eq!(result.false_negatives, 1);
        assert!((result.precision - 0.5).abs() < 0.001);
        assert!((result.recall - 0.5).abs() < 0.001);
    }

    #[test]
    fn perfect_detection_gives_f1_of_one() {
        let gt = GroundTruth {
            findings: vec![GroundTruthEntry {
                endpoint: "/api/users".into(),
                method: "GET".into(),
                parameter: Some("id".into()),
                vulnerability_class: "SqlInjection".into(),
                operation: None,
                note: None,
            }],
        };
        let mut sarif = HashSet::new();
        sarif.insert(("/api/users".to_string(), "SqlInjection".to_string()));

        let result = compare(&gt, &sarif);
        assert_eq!(result.true_positives, 1);
        assert_eq!(result.false_positives, 0);
        assert_eq!(result.false_negatives, 0);
        assert!((result.precision - 1.0).abs() < 0.001);
        assert!((result.recall - 1.0).abs() < 0.001);
        assert!((result.f1 - 1.0).abs() < 0.001);
    }

    #[test]
    fn empty_sarif_gives_zero_metrics() {
        let gt = GroundTruth {
            findings: vec![GroundTruthEntry {
                endpoint: "/a".into(),
                method: "GET".into(),
                parameter: None,
                vulnerability_class: "SqlInjection".into(),
                operation: None,
                note: None,
            }],
        };
        let sarif = HashSet::new();

        let result = compare(&gt, &sarif);
        assert_eq!(result.true_positives, 0);
        assert_eq!(result.false_negatives, 1);
        assert!((result.precision).abs() < 0.001);
        assert!((result.recall).abs() < 0.001);
        assert!((result.f1).abs() < 0.001);
    }

    #[test]
    fn empty_ground_truth_gives_zero_recall() {
        let gt = GroundTruth { findings: vec![] };
        let mut sarif = HashSet::new();
        sarif.insert(("/a".to_string(), "SqlInjection".to_string()));

        let result = compare(&gt, &sarif);
        assert_eq!(result.true_positives, 0);
        assert_eq!(result.false_positives, 1);
        assert_eq!(result.false_negatives, 0);
        assert!((result.recall).abs() < 0.001);
    }

    #[test]
    fn load_ground_truth_parses_express_fixture() {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let path = format!("{manifest}/../../defense-stacks/express-vuln-app/ground-truth.json");
        let gt = load_ground_truth(Path::new(&path));
        assert!(
            gt.findings.len() >= 10,
            "express ground truth should have many findings"
        );
        let has_sqli = gt
            .findings
            .iter()
            .any(|f| f.vulnerability_class == "SqlInjection");
        assert!(has_sqli, "express ground truth should include SqlInjection");
    }

    #[test]
    fn load_ground_truth_parses_graphql_fixture() {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let path = format!("{manifest}/../../defense-stacks/graphql-vuln-app/ground-truth.json");
        let gt = load_ground_truth(Path::new(&path));
        assert!(
            !gt.findings.is_empty(),
            "graphql ground truth should have findings"
        );
        let has_operation = gt.findings.iter().any(|f| f.operation.is_some());
        assert!(
            has_operation,
            "graphql ground truth should have operation fields"
        );
    }
}
