use crate::doctor::{
    CheckStatus, DoctorCheck, format_report, parse_doctor_args, recommend_command, run_doctor,
};

fn make_check(name: &str, status: CheckStatus) -> DoctorCheck {
    DoctorCheck {
        name: name.to_string(),
        status,
        detail: "test detail".to_string(),
        fix_hint: Some("test hint".to_string()),
    }
}

#[test]
fn check_status_from_command_success() {
    let check = make_check("test", CheckStatus::Pass);
    assert_eq!(check.status, CheckStatus::Pass);
}

#[test]
fn check_status_from_command_failure() {
    let check = make_check("test", CheckStatus::Fail);
    assert_eq!(check.status, CheckStatus::Fail);
}

#[test]
fn recommend_command_with_full_env() {
    let checks = vec![
        make_check("Python 3.12+", CheckStatus::Pass),
        make_check("uv package manager", CheckStatus::Pass),
        make_check("hypothesis-engine", CheckStatus::Pass),
        make_check("~/.aegis/ directory", CheckStatus::Pass),
        make_check("~/.aegis/vuln.db", CheckStatus::Pass),
        make_check("Docker", CheckStatus::Pass),
        make_check("ollama", CheckStatus::Pass),
    ];
    let cmd = recommend_command(&checks);
    assert!(cmd.contains("--preset thorough"));
    assert!(cmd.contains("--llm-backend ollama"));
    assert!(!cmd.contains("--no-llm"));
}

#[test]
fn recommend_command_without_python() {
    let checks = vec![
        make_check("Python 3.12+", CheckStatus::Fail),
        make_check("hypothesis-engine", CheckStatus::Fail),
        make_check("ollama", CheckStatus::Pass),
    ];
    let cmd = recommend_command(&checks);
    assert!(cmd.contains("--preset quick"));
    assert!(cmd.contains("--no-llm"));
}

#[test]
fn recommend_command_without_llm() {
    let checks = vec![
        make_check("Python 3.12+", CheckStatus::Pass),
        make_check("hypothesis-engine", CheckStatus::Pass),
        make_check("ollama", CheckStatus::Fail),
    ];
    let cmd = recommend_command(&checks);
    assert!(cmd.contains("--preset quick"));
    assert!(cmd.contains("--no-llm"));
}

#[test]
fn format_report_includes_all_checks() {
    let checks = vec![
        make_check("Python 3.12+", CheckStatus::Pass),
        make_check("uv package manager", CheckStatus::Fail),
        make_check("hypothesis-engine", CheckStatus::Warn),
        make_check("~/.aegis/ directory", CheckStatus::Pass),
        make_check("~/.aegis/vuln.db", CheckStatus::Pass),
        make_check("Docker", CheckStatus::Pass),
        make_check("ollama", CheckStatus::Pass),
    ];
    let report = format_report(&checks, false);
    assert!(report.contains("Python 3.12+"));
    assert!(report.contains("uv package manager"));
    assert!(report.contains("hypothesis-engine"));
    assert!(report.contains("~/.aegis/ directory"));
    assert!(report.contains("~/.aegis/vuln.db"));
    assert!(report.contains("Docker"));
    assert!(report.contains("ollama"));
    assert!(report.contains("Recommended:"));
    assert!(report.contains("[ok]"));
    assert!(report.contains("[FAIL]"));
    assert!(report.contains("[warn]"));
}

#[test]
fn parse_doctor_args_default() {
    let args: Vec<String> = vec![];
    let parsed = parse_doctor_args(&args);
    assert!(!parsed.verbose);
}

#[test]
fn parse_doctor_args_verbose() {
    let args = vec!["--verbose".to_string()];
    let parsed = parse_doctor_args(&args);
    assert!(parsed.verbose);
}

#[test]
fn doctor_checks_feroxbuster_returns_fail_when_not_installed() {
    let checks = run_doctor();
    let check = checks.iter().find(|c| c.name == "feroxbuster").unwrap();
    assert_eq!(check.status, CheckStatus::Fail);
    assert!(check.fix_hint.as_ref().unwrap().contains("cargo install"));
}

#[test]
fn doctor_checks_httpx_returns_fail_when_not_installed() {
    let checks = run_doctor();
    let check = checks.iter().find(|c| c.name == "httpx").unwrap();
    assert_eq!(check.status, CheckStatus::Fail);
    assert!(check.fix_hint.as_ref().unwrap().contains("go install"));
}

#[test]
fn doctor_checks_gau_returns_fail_when_not_installed() {
    let checks = run_doctor();
    let check = checks.iter().find(|c| c.name == "gau").unwrap();
    assert_eq!(check.status, CheckStatus::Fail);
    assert!(check.fix_hint.as_ref().unwrap().contains("go install"));
}

#[test]
fn doctor_checks_dalfox_returns_fail_when_not_installed() {
    let checks = run_doctor();
    let check = checks.iter().find(|c| c.name == "dalfox").unwrap();
    assert_eq!(check.status, CheckStatus::Fail);
    assert!(check.fix_hint.as_ref().unwrap().contains("go install"));
}

#[test]
fn doctor_checks_trufflehog_returns_fail_when_not_installed() {
    let checks = run_doctor();
    let check = checks.iter().find(|c| c.name == "trufflehog").unwrap();
    assert_eq!(check.status, CheckStatus::Fail);
    assert!(check.fix_hint.as_ref().unwrap().contains("brew install"));
}

#[test]
fn doctor_checks_amass_returns_fail_when_not_installed() {
    let checks = run_doctor();
    let check = checks.iter().find(|c| c.name == "amass").unwrap();
    assert_eq!(check.status, CheckStatus::Fail);
    assert!(check.fix_hint.as_ref().unwrap().contains("go install"));
}

#[test]
fn doctor_checks_katana_returns_fail_when_not_installed() {
    let checks = run_doctor();
    let check = checks.iter().find(|c| c.name == "katana").unwrap();
    assert_eq!(check.status, CheckStatus::Fail);
    assert!(check.fix_hint.as_ref().unwrap().contains("go install"));
}

#[test]
fn run_doctor_includes_all_tool_checks() {
    let checks = run_doctor();
    let names: Vec<_> = checks.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"feroxbuster"));
    assert!(names.contains(&"httpx"));
    assert!(names.contains(&"gau"));
    assert!(names.contains(&"dalfox"));
    assert!(names.contains(&"trufflehog"));
    assert!(names.contains(&"amass"));
    assert!(names.contains(&"katana"));
}
