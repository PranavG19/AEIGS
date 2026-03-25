use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Ground-truth entry loaded from a JSON file.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct GroundTruthFileEntry {
    pub endpoint: String,
    pub vulnerability_class: String,
}

/// Result of comparing scan findings against ground truth.
#[derive(Debug, Clone)]
pub struct ComparisonResult {
    pub true_positives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
}

/// Load ground-truth entries from a JSON file.
fn load_ground_truth_file(path: &Path) -> Result<Vec<GroundTruthFileEntry>, String> {
    let data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&data).map_err(|e| e.to_string())
}

/// Extract `(endpoint, vulnerability_class)` pairs from a SARIF file.
fn extract_sarif_findings_from_file(path: &Path) -> Result<HashSet<(String, String)>, String> {
    let data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_str(&data).map_err(|e| e.to_string())?;
    let mut set = HashSet::new();
    if let Some(runs) = v.get("runs").and_then(|r| r.as_array()) {
        for run in runs {
            if let Some(results) = run.get("results").and_then(|r| r.as_array()) {
                for result in results {
                    let rule_id = result
                        .get("ruleId")
                        .and_then(|r| r.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let uri = result
                        .get("locations")
                        .and_then(|l| l.as_array())
                        .and_then(|l| l.first())
                        .and_then(|loc| loc.get("physicalLocation"))
                        .and_then(|pl| pl.get("artifactLocation"))
                        .and_then(|al| al.get("uri"))
                        .and_then(|u| u.as_str())
                        .unwrap_or_default()
                        .to_string();
                    set.insert((uri, rule_id));
                }
            }
        }
    }
    Ok(set)
}

/// Compare scan findings against ground-truth entries.
fn compare_findings(
    gt_entries: &[GroundTruthFileEntry],
    sarif_findings: &HashSet<(String, String)>,
) -> ComparisonResult {
    let gt_set: HashSet<(String, String)> = gt_entries
        .iter()
        .map(|e| (e.endpoint.clone(), e.vulnerability_class.clone()))
        .collect();

    let true_positives = sarif_findings.intersection(&gt_set).count();
    let false_positives = sarif_findings.difference(&gt_set).count();
    let false_negatives = gt_set.difference(sarif_findings).count();

    let precision = if true_positives + false_positives > 0 {
        true_positives as f64 / (true_positives + false_positives) as f64
    } else {
        0.0
    };
    let recall = if true_positives + false_negatives > 0 {
        true_positives as f64 / (true_positives + false_negatives) as f64
    } else {
        0.0
    };
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };

    ComparisonResult {
        true_positives,
        false_positives,
        false_negatives,
        precision,
        recall,
        f1,
    }
}

pub struct EvalArgs {
    pub fixture: String,
    pub no_cleanup: bool,
    pub verbose: bool,
}

pub struct FixtureConfig {
    pub name: &'static str,
    pub compose_file: &'static str,
    pub port: u16,
    pub health_path: &'static str,
    pub ground_truth_rel_path: &'static str,
}

pub struct EvalResult {
    pub fixture: String,
    pub comparison: ComparisonResult,
    pub scan_duration_ms: u64,
    pub per_class: Vec<ClassResult>,
}

pub struct ClassResult {
    pub vulnerability_class: String,
    pub detected: bool,
}

#[derive(Debug)]
pub enum EvalError {
    DockerNotAvailable(String),
    DockerStartFailed(String),
    HealthCheckFailed(String),
    ScanFailed(String),
    GroundTruthNotFound(String),
    SarifNotFound(String),
    Io(std::io::Error),
}

impl std::fmt::Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DockerNotAvailable(msg) => write!(f, "Docker not available: {msg}"),
            Self::DockerStartFailed(msg) => write!(f, "Docker start failed: {msg}"),
            Self::HealthCheckFailed(msg) => write!(f, "health check failed: {msg}"),
            Self::ScanFailed(msg) => write!(f, "scan failed: {msg}"),
            Self::GroundTruthNotFound(msg) => write!(f, "ground truth not found: {msg}"),
            Self::SarifNotFound(msg) => write!(f, "SARIF not found: {msg}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for EvalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for EvalError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

const FIXTURES: &[FixtureConfig] = &[
    FixtureConfig {
        name: "express",
        compose_file: "docker-compose.yml",
        port: 3000,
        health_path: "/health",
        ground_truth_rel_path: "express-vuln-app/ground-truth.json",
    },
    FixtureConfig {
        name: "flask",
        compose_file: "docker-compose.flask.yml",
        port: 5001,
        health_path: "/health",
        ground_truth_rel_path: "flask-vuln-app/ground-truth.json",
    },
    FixtureConfig {
        name: "graphql",
        compose_file: "docker-compose.graphql.yml",
        port: 4000,
        health_path: "/health",
        ground_truth_rel_path: "graphql-vuln-app/ground-truth.json",
    },
];

pub fn parse_eval_args(args: &[String]) -> Result<EvalArgs, EvalError> {
    let fixture = find_flag(args, "fixture")
        .ok_or_else(|| EvalError::ScanFailed("missing required --fixture argument".to_string()))?;

    let no_cleanup = args.iter().any(|a| a == "--no-cleanup");
    let verbose = args.iter().any(|a| a == "--verbose" || a == "-v");

    Ok(EvalArgs {
        fixture,
        no_cleanup,
        verbose,
    })
}

pub fn find_fixture(name: &str) -> Option<&'static FixtureConfig> {
    FIXTURES.iter().find(|f| f.name == name)
}

pub fn resolve_paths(fixture: &FixtureConfig) -> (PathBuf, PathBuf) {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let defense_stacks = manifest_dir.join("../../defense-stacks");
    let compose_dir = defense_stacks.join("compose");
    let ground_truth_path = defense_stacks.join(fixture.ground_truth_rel_path);
    (compose_dir, ground_truth_path)
}

fn check_docker_available() -> Result<(), EvalError> {
    let output = std::process::Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| EvalError::DockerNotAvailable(e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(EvalError::DockerNotAvailable(stderr.to_string()));
    }
    Ok(())
}

pub fn start_docker(
    compose_dir: &Path,
    compose_file: &str,
    project_name: &str,
) -> Result<(), EvalError> {
    let file_path = compose_dir.join(compose_file);
    let output = std::process::Command::new("docker")
        .args(["compose", "-f"])
        .arg(&file_path)
        .args(["-p", project_name, "up", "-d", "--build", "--wait"])
        .output()
        .map_err(|e| EvalError::DockerStartFailed(e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(EvalError::DockerStartFailed(stderr.to_string()));
    }
    Ok(())
}

pub fn stop_docker(compose_dir: &Path, compose_file: &str, project_name: &str) {
    let file_path = compose_dir.join(compose_file);
    let _ = std::process::Command::new("docker")
        .args(["compose", "-f"])
        .arg(&file_path)
        .args(["-p", project_name, "down", "-v"])
        .output();
}

pub fn wait_for_health(port: u16, health_path: &str, timeout_secs: u64) -> Result<(), EvalError> {
    let url = format!("http://localhost:{port}{health_path}");
    let deadline = Instant::now() + std::time::Duration::from_secs(timeout_secs);

    while Instant::now() < deadline {
        let result = std::process::Command::new("curl")
            .args(["--fail", "--silent", "--max-time", "5"])
            .arg(&url)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        if let Ok(status) = result
            && status.success()
        {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Err(EvalError::HealthCheckFailed(format!(
        "timed out after {timeout_secs}s waiting for {url}"
    )))
}

pub fn run_eval(args: &EvalArgs) -> Result<EvalResult, EvalError> {
    let fixture = find_fixture(&args.fixture).ok_or_else(|| {
        let names: Vec<&str> = FIXTURES.iter().map(|f| f.name).collect();
        EvalError::ScanFailed(format!(
            "unknown fixture '{}'. Available: {}",
            args.fixture,
            names.join(", ")
        ))
    })?;

    let (compose_dir, ground_truth_path) = resolve_paths(fixture);
    validate_ground_truth_exists(&ground_truth_path)?;

    check_docker_available()?;

    let project_name = format!("aegis-eval-{}", fixture.name);
    start_docker(&compose_dir, fixture.compose_file, &project_name)?;

    let result = run_eval_inner(fixture, &ground_truth_path, args);

    if !args.no_cleanup {
        stop_docker(&compose_dir, fixture.compose_file, &project_name);
    }

    result
}

fn validate_ground_truth_exists(path: &Path) -> Result<(), EvalError> {
    if !path.exists() {
        return Err(EvalError::GroundTruthNotFound(format!(
            "{}",
            path.display()
        )));
    }
    Ok(())
}

fn run_eval_inner(
    fixture: &FixtureConfig,
    ground_truth_path: &Path,
    args: &EvalArgs,
) -> Result<EvalResult, EvalError> {
    wait_for_health(fixture.port, fixture.health_path, 60)?;

    let tmp_dir = create_eval_tmp_dir()?;
    let sarif_path = tmp_dir.join("eval-report.sarif");

    let scan_start = Instant::now();
    run_scan_for_eval(fixture.port, &sarif_path, args.verbose)?;
    let scan_duration_ms = scan_start.elapsed().as_millis() as u64;

    let sarif_findings =
        extract_sarif_findings_from_file(&sarif_path).map_err(EvalError::SarifNotFound)?;

    let gt_entries =
        load_ground_truth_file(ground_truth_path).map_err(EvalError::GroundTruthNotFound)?;

    let comparison = compare_findings(&gt_entries, &sarif_findings);
    let per_class = build_per_class_breakdown(&gt_entries, &sarif_findings);

    Ok(EvalResult {
        fixture: fixture.name.to_string(),
        comparison,
        scan_duration_ms,
        per_class,
    })
}

fn run_scan_for_eval(port: u16, sarif_path: &Path, verbose: bool) -> Result<(), EvalError> {
    let target = format!("http://localhost:{port}");
    let output_str = sarif_path.to_string_lossy().to_string();

    let mut cli_args = vec![
        "aegis".to_string(),
        "--target".to_string(),
        target,
        "-o".to_string(),
        output_str,
        "-p".to_string(),
        "quick".to_string(),
        "--no-audit".to_string(),
        "--skip-evasion".to_string(),
    ];
    if verbose {
        cli_args.push("-v".to_string());
    }

    let mut config = crate::scan_config::ScanConfig::parse_and_apply_preset();
    // Override target and output from the CLI args we built
    config.target = format!("http://localhost:{port}");
    config.output = sarif_path.to_path_buf();
    config.audit.no_audit = true;

    let rt = tokio::runtime::Runtime::new().map_err(|e| EvalError::ScanFailed(e.to_string()))?;
    rt.block_on(crate::pipeline::run_scan(config))
        .map_err(|e| EvalError::ScanFailed(e.to_string()))?;

    Ok(())
}

fn build_per_class_breakdown(
    gt_entries: &[GroundTruthFileEntry],
    sarif_findings: &HashSet<(String, String)>,
) -> Vec<ClassResult> {
    let detected_classes: HashSet<&str> =
        sarif_findings.iter().map(|(_, vc)| vc.as_str()).collect();

    let mut seen = HashSet::new();
    gt_entries
        .iter()
        .filter(|e| seen.insert(e.vulnerability_class.clone()))
        .map(|e| ClassResult {
            vulnerability_class: e.vulnerability_class.clone(),
            detected: detected_classes.contains(e.vulnerability_class.as_str()),
        })
        .collect()
}

pub fn format_eval_result(result: &EvalResult) -> String {
    let mut lines = Vec::new();
    lines.push(format!("=== Eval: {} ===", result.fixture));
    lines.push(String::new());

    lines.push(format!(
        "Precision: {:.1}%",
        result.comparison.precision * 100.0
    ));
    lines.push(format!(
        "Recall:    {:.1}%",
        result.comparison.recall * 100.0
    ));
    lines.push(format!("F1:        {:.1}%", result.comparison.f1 * 100.0));
    lines.push(String::new());

    append_counts(&mut lines, &result.comparison);
    lines.push(String::new());
    append_per_class(&mut lines, &result.per_class);
    lines.push(String::new());

    lines.push(format!("Scan duration: {}ms", result.scan_duration_ms));

    lines.join("\n")
}

fn append_counts(lines: &mut Vec<String>, comparison: &ComparisonResult) {
    lines.push(format!(
        "TP: {}  FP: {}  FN: {}",
        comparison.true_positives, comparison.false_positives, comparison.false_negatives
    ));
}

fn append_per_class(lines: &mut Vec<String>, per_class: &[ClassResult]) {
    lines.push("Per-class:".to_string());
    for c in per_class {
        let mark = if c.detected { "[+]" } else { "[-]" };
        lines.push(format!("  {mark} {}", c.vulnerability_class));
    }
}

pub fn run_eval_command(args: &[String]) {
    match parse_eval_args(args) {
        Ok(eval_args) => match run_eval(&eval_args) {
            Ok(result) => {
                println!("{}", format_eval_result(&result));
            }
            Err(e) => {
                eprintln!("Eval failed: {e}");
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("Eval failed: {e}");
            eprintln!(
                "Usage: aegis eval --fixture <express|flask|graphql> [--no-cleanup] [--verbose]"
            );
            std::process::exit(1);
        }
    }
}

fn create_eval_tmp_dir() -> Result<PathBuf, EvalError> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let dir = std::env::temp_dir().join(format!("aegis-eval-{ts}"));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn find_flag(args: &[String], name: &str) -> Option<String> {
    let flag = format!("--{name}");
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

#[cfg(test)]
#[path = "eval_test.rs"]
mod eval_test;
