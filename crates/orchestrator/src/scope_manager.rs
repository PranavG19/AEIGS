use regex::Regex;
use std::collections::HashSet;

/// Manages scan scope: what URLs are in-scope and what to exclude.
#[derive(Debug, Clone)]
pub struct ScopeManager {
    include_patterns: Vec<ScopePattern>,
    exclude_patterns: Vec<ScopePattern>,
    robots_excluded: Vec<String>,
    respect_robots: bool,
    out_of_scope_alerts: Vec<String>,
    discovered_subdomains: HashSet<String>,
}

/// A compiled scope pattern from a wildcard string.
#[derive(Debug, Clone)]
pub struct ScopePattern {
    pub original: String,
    compiled: Regex,
}

impl ScopePattern {
    /// Create a scope pattern from a wildcard string.
    /// Supports * as wildcard (e.g., "*.example.com", "/api/*")
    pub fn new(pattern: &str) -> Result<Self, ScopeError> {
        let escaped = regex::escape(pattern);
        let regex_str = escaped.replace(r"\*", ".*");
        let compiled = Regex::new(&format!("^{regex_str}$"))
            .map_err(|e| ScopeError::InvalidPattern(format!("{pattern}: {e}")))?;
        Ok(Self {
            original: pattern.to_string(),
            compiled,
        })
    }

    pub fn matches(&self, input: &str) -> bool {
        self.compiled.is_match(input)
    }
}

#[derive(Debug)]
pub enum ScopeError {
    InvalidPattern(String),
    RobotsParseError(String),
}

impl std::fmt::Display for ScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPattern(msg) => write!(f, "invalid scope pattern: {msg}"),
            Self::RobotsParseError(msg) => write!(f, "robots.txt parse error: {msg}"),
        }
    }
}

impl std::error::Error for ScopeError {}

impl ScopeManager {
    /// Create a new scope manager.
    pub fn new() -> Self {
        Self {
            include_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
            robots_excluded: Vec::new(),
            respect_robots: false,
            out_of_scope_alerts: Vec::new(),
            discovered_subdomains: HashSet::new(),
        }
    }

    /// Create with a base domain. Auto-adds *.domain as include pattern.
    pub fn for_domain(domain: &str) -> Result<Self, ScopeError> {
        let mut manager = Self::new();
        manager.add_include(&format!("*://{domain}*"))?;
        manager.add_include(&format!("*://*.{domain}*"))?;
        Ok(manager)
    }

    /// Add an include pattern (URLs matching this are in-scope).
    pub fn add_include(&mut self, pattern: &str) -> Result<(), ScopeError> {
        self.include_patterns.push(ScopePattern::new(pattern)?);
        Ok(())
    }

    /// Add an exclude pattern (URLs matching this are out-of-scope).
    pub fn add_exclude(&mut self, pattern: &str) -> Result<(), ScopeError> {
        self.exclude_patterns.push(ScopePattern::new(pattern)?);
        Ok(())
    }

    /// Add multiple exclusion patterns at once.
    pub fn add_excludes(&mut self, patterns: &[String]) -> Result<(), ScopeError> {
        for p in patterns {
            self.add_exclude(p)?;
        }
        Ok(())
    }

    /// Enable robots.txt respect.
    pub fn set_respect_robots(&mut self, respect: bool) {
        self.respect_robots = respect;
    }

    /// Parse and apply robots.txt content.
    pub fn apply_robots_txt(&mut self, robots_content: &str) {
        let mut in_global = false;
        for line in robots_content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let lower = trimmed.to_lowercase();
            if lower.starts_with("user-agent:") {
                let agent = lower.trim_start_matches("user-agent:").trim();
                in_global = agent == "*";
            } else if in_global && lower.starts_with("disallow:") {
                let path = trimmed.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");
                if !path.is_empty() {
                    self.robots_excluded.push(path.to_string());
                }
            }
        }
    }

    /// Check if a URL is in scope.
    pub fn is_in_scope(&mut self, url: &str) -> bool {
        for pattern in &self.exclude_patterns {
            if pattern.matches(url) {
                return false;
            }
        }

        if self.respect_robots {
            let path = extract_path(url);
            for excluded in &self.robots_excluded {
                if path.starts_with(excluded) {
                    return false;
                }
            }
        }

        if self.include_patterns.is_empty() {
            return true;
        }

        let in_scope = self.include_patterns.iter().any(|p| p.matches(url));
        if !in_scope {
            self.out_of_scope_alerts.push(url.to_string());
        }
        in_scope
    }

    /// Register a discovered subdomain.
    pub fn add_subdomain(&mut self, subdomain: &str) {
        self.discovered_subdomains.insert(subdomain.to_string());
    }

    /// Get all discovered subdomains.
    pub fn subdomains(&self) -> &HashSet<String> {
        &self.discovered_subdomains
    }

    /// Get all out-of-scope alerts (URLs that were checked but not in scope).
    pub fn out_of_scope_alerts(&self) -> &[String] {
        &self.out_of_scope_alerts
    }

    /// Clear out-of-scope alerts.
    pub fn clear_alerts(&mut self) {
        self.out_of_scope_alerts.clear();
    }

    /// Get the number of include patterns.
    pub fn include_count(&self) -> usize {
        self.include_patterns.len()
    }

    /// Get the number of exclude patterns.
    pub fn exclude_count(&self) -> usize {
        self.exclude_patterns.len()
    }
}

impl Default for ScopeManager {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn extract_path(url: &str) -> String {
    url.split("://")
        .nth(1)
        .and_then(|rest| rest.split_once('/'))
        .map(|(_, path)| format!("/{path}"))
        .unwrap_or_else(|| "/".to_string())
}

/// Common exclusion patterns for safety endpoints.
pub fn default_exclusions() -> Vec<String> {
    vec![
        "*/logout*".to_string(),
        "*/signout*".to_string(),
        "*/api/health*".to_string(),
        "*/healthcheck*".to_string(),
        "*/_health*".to_string(),
        "*/api/ping*".to_string(),
        "*/unsubscribe*".to_string(),
        "*/delete-account*".to_string(),
    ]
}
