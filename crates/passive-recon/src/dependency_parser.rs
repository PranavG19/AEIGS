use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDependency {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Ecosystem {
    Npm,
    Cargo,
    PyPi,
    Go,
    RubyGems,
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Npm => "npm",
            Self::Cargo => "cargo",
            Self::PyPi => "pypi",
            Self::Go => "go",
            Self::RubyGems => "rubygems",
        };
        write!(f, "{name}")
    }
}

impl Ecosystem {
    pub fn osv_name(&self) -> &'static str {
        match self {
            Self::Cargo => "crates.io",
            Self::Npm => "npm",
            Self::PyPi => "PyPI",
            Self::Go => "Go",
            Self::RubyGems => "RubyGems",
        }
    }

    pub fn from_osv_name(name: &str) -> Option<Self> {
        match name {
            "crates.io" => Some(Self::Cargo),
            "npm" => Some(Self::Npm),
            "PyPI" => Some(Self::PyPi),
            "Go" => Some(Self::Go),
            "RubyGems" => Some(Self::RubyGems),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum ParseError {
    IoError(std::io::Error),
    JsonError(serde_json::Error),
    UnsupportedFormat(String),
    MalformedContent(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "io error: {e}"),
            Self::JsonError(e) => write!(f, "json parse error: {e}"),
            Self::UnsupportedFormat(name) => write!(f, "unsupported lock file format: {name}"),
            Self::MalformedContent(msg) => write!(f, "malformed content: {msg}"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<serde_json::Error> for ParseError {
    fn from(e: serde_json::Error) -> Self {
        Self::JsonError(e)
    }
}

pub fn detect_ecosystem(filename: &str) -> Option<Ecosystem> {
    match filename {
        "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml" => Some(Ecosystem::Npm),
        "Cargo.lock" => Some(Ecosystem::Cargo),
        "requirements.txt" | "Pipfile.lock" | "poetry.lock" => Some(Ecosystem::PyPi),
        "go.sum" => Some(Ecosystem::Go),
        "Gemfile.lock" => Some(Ecosystem::RubyGems),
        _ => None,
    }
}

pub fn parse_lock_file(path: &Path) -> Result<Vec<ParsedDependency>, ParseError> {
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| ParseError::UnsupportedFormat("unknown".to_string()))?;

    let content = std::fs::read_to_string(path)?;
    parse_lock_file_content(filename, &content)
}

pub fn parse_lock_file_content(
    filename: &str,
    content: &str,
) -> Result<Vec<ParsedDependency>, ParseError> {
    match filename {
        "package-lock.json" => parse_package_lock_json(content),
        "Cargo.lock" => parse_cargo_lock(content),
        "requirements.txt" => parse_requirements_txt(content),
        "go.sum" => parse_go_sum(content),
        "Gemfile.lock" => parse_gemfile_lock(content),
        other => Err(ParseError::UnsupportedFormat(other.to_string())),
    }
}

#[derive(Deserialize)]
struct PackageLockJson {
    #[serde(default)]
    packages: HashMap<String, PackageLockEntry>,
    #[serde(default)]
    dependencies: HashMap<String, PackageLockDep>,
}

#[derive(Deserialize)]
struct PackageLockEntry {
    #[serde(default)]
    version: Option<String>,
}

#[derive(Deserialize)]
struct PackageLockDep {
    #[serde(default)]
    version: Option<String>,
}

fn parse_package_lock_json(content: &str) -> Result<Vec<ParsedDependency>, ParseError> {
    let lock: PackageLockJson = serde_json::from_str(content)?;
    let mut deps = Vec::new();

    for (path, entry) in &lock.packages {
        if path.is_empty() {
            continue;
        }
        let name = path
            .strip_prefix("node_modules/")
            .unwrap_or(path)
            .to_string();
        if let Some(version) = &entry.version {
            deps.push(ParsedDependency {
                name,
                version: version.clone(),
                ecosystem: Ecosystem::Npm,
            });
        }
    }

    if deps.is_empty() {
        for (name, dep) in &lock.dependencies {
            if let Some(version) = &dep.version {
                deps.push(ParsedDependency {
                    name: name.clone(),
                    version: version.clone(),
                    ecosystem: Ecosystem::Npm,
                });
            }
        }
    }

    deps.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(deps)
}

fn parse_cargo_lock(content: &str) -> Result<Vec<ParsedDependency>, ParseError> {
    let lockfile = cargo_lock::Lockfile::from_str(content)
        .map_err(|e| ParseError::MalformedContent(e.to_string()))?;

    let deps = lockfile
        .packages
        .into_iter()
        .filter(|p| p.source.as_ref().is_some_and(|s| s.is_default_registry()))
        .map(|p| ParsedDependency {
            name: p.name.as_str().to_string(),
            version: p.version.to_string(),
            ecosystem: Ecosystem::Cargo,
        })
        .collect();

    Ok(deps)
}

fn parse_requirements_txt(content: &str) -> Result<Vec<ParsedDependency>, ParseError> {
    let mut deps = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }

        if let Some((name, version)) = parse_pip_requirement(trimmed) {
            deps.push(ParsedDependency {
                name,
                version,
                ecosystem: Ecosystem::PyPi,
            });
        }
    }

    Ok(deps)
}

fn parse_pip_requirement(line: &str) -> Option<(String, String)> {
    let separators = ["==", ">=", "<=", "~=", "!=", ">", "<"];
    for sep in separators {
        if let Some(pos) = line.find(sep) {
            let name = line[..pos].trim().to_lowercase();
            let version = line[pos + sep.len()..].trim().to_string();
            let version = version.split(',').next().unwrap_or("").trim().to_string();
            if !name.is_empty() && !version.is_empty() {
                return Some((name, version));
            }
        }
    }
    None
}

fn parse_go_sum(content: &str) -> Result<Vec<ParsedDependency>, ParseError> {
    let mut deps = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let module = parts[0].to_string();
        let version_raw = parts[1];
        let version = version_raw
            .strip_prefix('v')
            .unwrap_or(version_raw)
            .strip_suffix("/go.mod")
            .unwrap_or(version_raw.strip_prefix('v').unwrap_or(version_raw))
            .to_string();

        let key = format!("{module}@{version}");
        if seen.insert(key) {
            deps.push(ParsedDependency {
                name: module,
                version,
                ecosystem: Ecosystem::Go,
            });
        }
    }

    Ok(deps)
}

fn parse_gemfile_lock(content: &str) -> Result<Vec<ParsedDependency>, ParseError> {
    let mut deps = Vec::new();
    let mut in_specs = false;
    let mut spec_indent: Option<usize> = None;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "specs:" {
            in_specs = true;
            spec_indent = None;
            continue;
        }

        if in_specs {
            if !line.starts_with(' ') && !line.starts_with('\t') {
                in_specs = false;
                spec_indent = None;
                continue;
            }

            let indent = line.len() - line.trim_start().len();

            if spec_indent.is_none() {
                spec_indent = Some(indent);
            }

            if indent != spec_indent.unwrap_or(0) {
                continue;
            }

            if let Some((name, version)) = parse_gem_spec_line(trimmed) {
                deps.push(ParsedDependency {
                    name,
                    version,
                    ecosystem: Ecosystem::RubyGems,
                });
            }
        }
    }

    Ok(deps)
}

fn parse_gem_spec_line(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    if let Some(paren_pos) = trimmed.find('(') {
        let name = trimmed[..paren_pos].trim().to_string();
        let version = trimmed[paren_pos + 1..]
            .trim_end_matches(')')
            .trim()
            .to_string();
        if !name.is_empty() && !version.is_empty() && !name.contains(' ') {
            return Some((name, version));
        }
    }
    None
}
