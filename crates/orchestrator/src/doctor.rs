use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Fail,
    Warn,
}

#[derive(Debug, Clone)]
pub struct DoctorCheck {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
    pub fix_hint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DoctorArgs {
    pub verbose: bool,
}

pub fn parse_doctor_args(args: &[String]) -> DoctorArgs {
    let verbose = args.iter().any(|a| a == "--verbose" || a == "-v");
    DoctorArgs { verbose }
}

pub fn run_doctor() -> Vec<DoctorCheck> {
    vec![
        check_python(),
        check_uv(),
        check_hypothesis_engine(),
        check_aegis_directory(),
        check_vuln_db(),
        check_docker(),
        check_ollama(),
        check_feroxbuster(),
        check_httpx(),
        check_gau(),
        check_dalfox(),
        check_trufflehog(),
        check_amass(),
        check_katana(),
    ]
}

pub fn recommend_command(checks: &[DoctorCheck]) -> String {
    let python_ok = check_passed(checks, "python");
    let hypothesis_ok = check_passed(checks, "hypothesis-engine");
    let ollama_ok = check_passed(checks, "ollama");

    if python_ok && hypothesis_ok && ollama_ok {
        return "aegis --target http://localhost:3000 --preset thorough --llm-backend ollama"
            .to_string();
    }

    if python_ok && hypothesis_ok {
        return "aegis --target http://localhost:3000 --preset quick --no-llm".to_string();
    }

    "aegis --target http://localhost:3000 --preset quick --no-llm".to_string()
}

pub fn format_report(checks: &[DoctorCheck], verbose: bool) -> String {
    let mut lines = Vec::new();
    lines.push("AEGIS Environment Check".to_string());
    lines.push("=".repeat(40));
    lines.push(String::new());

    for check in checks {
        let icon = match check.status {
            CheckStatus::Pass => "[ok]",
            CheckStatus::Fail => "[FAIL]",
            CheckStatus::Warn => "[warn]",
        };
        lines.push(format!("  {icon:>6}  {}", check.name));

        if verbose || check.status != CheckStatus::Pass {
            lines.push(format!("          {}", check.detail));
        }

        if let Some(hint) = &check.fix_hint
            && check.status != CheckStatus::Pass
        {
            lines.push(format!("          fix: {hint}"));
        }
    }

    lines.push(String::new());
    let recommendation = recommend_command(checks);
    lines.push(format!("Recommended: {recommendation}"));
    lines.join("\n")
}

fn check_passed(checks: &[DoctorCheck], name_substring: &str) -> bool {
    checks
        .iter()
        .any(|c| c.name.to_lowercase().contains(name_substring) && c.status == CheckStatus::Pass)
}

fn check_python() -> DoctorCheck {
    let name = "Python 3.12+".to_string();
    let fix = Some("Install Python 3.12+ for LLM hypothesis generation".to_string());

    match Command::new("python3").arg("--version").output() {
        Ok(output) if output.status.success() => {
            let version_str = String::from_utf8_lossy(&output.stdout);
            match parse_python_version(version_str.trim()) {
                Some((major, minor)) if major >= 3 && minor >= 12 => DoctorCheck {
                    name,
                    status: CheckStatus::Pass,
                    detail: version_str.trim().to_string(),
                    fix_hint: fix,
                },
                Some((major, minor)) => DoctorCheck {
                    name,
                    status: CheckStatus::Warn,
                    detail: format!("Found Python {major}.{minor}, need 3.12+"),
                    fix_hint: fix,
                },
                None => DoctorCheck {
                    name,
                    status: CheckStatus::Warn,
                    detail: format!("Could not parse version: {}", version_str.trim()),
                    fix_hint: fix,
                },
            }
        }
        _ => DoctorCheck {
            name,
            status: CheckStatus::Fail,
            detail: "python3 not found".to_string(),
            fix_hint: fix,
        },
    }
}

fn parse_python_version(output: &str) -> Option<(u32, u32)> {
    let version_part = output.strip_prefix("Python ")?;
    let mut parts = version_part.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

fn check_uv() -> DoctorCheck {
    let name = "uv package manager".to_string();
    let fix = Some("Install uv: curl -LsSf https://astral.sh/uv/install.sh | sh".to_string());

    match Command::new("uv").arg("--version").output() {
        Ok(output) if output.status.success() => {
            let detail = String::from_utf8_lossy(&output.stdout).trim().to_string();
            DoctorCheck {
                name,
                status: CheckStatus::Pass,
                detail,
                fix_hint: fix,
            }
        }
        _ => DoctorCheck {
            name,
            status: CheckStatus::Fail,
            detail: "uv not found".to_string(),
            fix_hint: fix,
        },
    }
}

fn check_hypothesis_engine() -> DoctorCheck {
    let name = "hypothesis-engine".to_string();
    let fix = Some("cd hypothesis-engine && uv sync".to_string());

    match Command::new("python3")
        .args(["-c", "import hypothesis_engine"])
        .output()
    {
        Ok(output) if output.status.success() => DoctorCheck {
            name,
            status: CheckStatus::Pass,
            detail: "importable".to_string(),
            fix_hint: fix,
        },
        _ => DoctorCheck {
            name,
            status: CheckStatus::Fail,
            detail: "hypothesis_engine not importable".to_string(),
            fix_hint: fix,
        },
    }
}

fn check_aegis_directory() -> DoctorCheck {
    let name = "~/.aegis/ directory".to_string();
    let fix = Some("mkdir -p ~/.aegis".to_string());
    let aegis_dir = aegis_home_dir();

    if !aegis_dir.exists() {
        return DoctorCheck {
            name,
            status: CheckStatus::Fail,
            detail: "directory does not exist".to_string(),
            fix_hint: fix,
        };
    }

    if aegis_dir
        .metadata()
        .map(|m| m.permissions().readonly())
        .unwrap_or(true)
    {
        return DoctorCheck {
            name,
            status: CheckStatus::Warn,
            detail: "directory exists but may not be writable".to_string(),
            fix_hint: fix,
        };
    }

    DoctorCheck {
        name,
        status: CheckStatus::Pass,
        detail: aegis_dir.display().to_string(),
        fix_hint: fix,
    }
}

fn check_vuln_db() -> DoctorCheck {
    let name = "~/.aegis/vuln.db".to_string();
    let fix = Some("Run: aegis update-db --source-dir .".to_string());
    let db_path = aegis_home_dir().join("vuln.db");

    if !db_path.exists() {
        return DoctorCheck {
            name,
            status: CheckStatus::Warn,
            detail: "vulnerability database not found".to_string(),
            fix_hint: fix,
        };
    }

    let is_empty = db_path.metadata().map(|m| m.len() == 0).unwrap_or(true);

    if is_empty {
        return DoctorCheck {
            name,
            status: CheckStatus::Warn,
            detail: "vulnerability database is empty".to_string(),
            fix_hint: fix,
        };
    }

    DoctorCheck {
        name,
        status: CheckStatus::Pass,
        detail: format!("{}", db_path.display()),
        fix_hint: fix,
    }
}

fn check_docker() -> DoctorCheck {
    let name = "Docker".to_string();
    let fix = Some("Install Docker or Colima for integration testing".to_string());

    match Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
    {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            DoctorCheck {
                name,
                status: CheckStatus::Pass,
                detail: format!("Docker {version}"),
                fix_hint: fix,
            }
        }
        _ => DoctorCheck {
            name,
            status: CheckStatus::Fail,
            detail: "docker not available".to_string(),
            fix_hint: fix,
        },
    }
}

fn check_ollama() -> DoctorCheck {
    let name = "ollama".to_string();
    let fix = Some("Install ollama for local LLM: brew install ollama && ollama serve".to_string());
    let addr: SocketAddr = ([127, 0, 0, 1], 11434).into();
    let timeout = Duration::from_secs(2);

    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => DoctorCheck {
            name,
            status: CheckStatus::Pass,
            detail: "listening on localhost:11434".to_string(),
            fix_hint: fix,
        },
        Err(_) => DoctorCheck {
            name,
            status: CheckStatus::Fail,
            detail: "not reachable on localhost:11434".to_string(),
            fix_hint: fix,
        },
    }
}

fn check_cli_tool(name: &str, install_hint: &str) -> DoctorCheck {
    match Command::new(name).arg("--version").output() {
        Ok(output) if output.status.success() => {
            let detail = String::from_utf8_lossy(&output.stdout).trim().to_string();
            DoctorCheck {
                name: name.to_string(),
                status: CheckStatus::Pass,
                detail,
                fix_hint: Some(install_hint.to_string()),
            }
        }
        _ => DoctorCheck {
            name: name.to_string(),
            status: CheckStatus::Fail,
            detail: format!("{name} not found"),
            fix_hint: Some(install_hint.to_string()),
        },
    }
}

fn check_feroxbuster() -> DoctorCheck {
    check_cli_tool("feroxbuster", "cargo install feroxbuster")
}

fn check_httpx() -> DoctorCheck {
    check_cli_tool(
        "httpx",
        "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    )
}

fn check_gau() -> DoctorCheck {
    check_cli_tool("gau", "go install github.com/lc/gau/v2/cmd/gau@latest")
}

fn check_dalfox() -> DoctorCheck {
    check_cli_tool("dalfox", "go install github.com/hahwul/dalfox/v2@latest")
}

fn check_trufflehog() -> DoctorCheck {
    check_cli_tool("trufflehog", "brew install trufflehog")
}

fn check_amass() -> DoctorCheck {
    check_cli_tool(
        "amass",
        "go install github.com/owasp-amass/amass/v4/...@master",
    )
}

fn check_katana() -> DoctorCheck {
    check_cli_tool(
        "katana",
        "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    )
}

fn aegis_home_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".aegis")
}

#[cfg(test)]
#[path = "doctor_test.rs"]
mod doctor_test;
