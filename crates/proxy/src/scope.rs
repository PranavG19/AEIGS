use regex::Regex;

/// Error returned when a scope rule pattern is invalid.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ScopeError {
    #[error("invalid scope pattern: {0}")]
    InvalidPattern(String),
}

/// A single include or exclude URL scope rule.
#[derive(Debug, Clone)]
pub struct ScopeRule {
    pub id: u64,
    pub pattern: String,
    pub is_include: bool,
    pub enabled: bool,
}

/// Evaluates URLs against include/exclude regex rules to determine scope.
///
/// Rules are evaluated as follows:
/// - If no enabled include rules exist, all URLs pass the include check.
/// - If enabled include rules exist, a URL must match at least one.
/// - A URL matching any enabled exclude rule is out of scope (exclude wins).
pub struct ScopeEngine {
    rules: Vec<ScopeRule>,
    compiled: Vec<(Regex, bool, bool)>,
    next_id: u64,
}

impl ScopeEngine {
    /// Creates an empty scope engine where everything is in scope.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            compiled: Vec::new(),
            next_id: 1,
        }
    }

    /// Adds a rule with the given regex pattern. Returns the assigned rule ID.
    pub fn add_rule(&mut self, pattern: &str, is_include: bool) -> Result<u64, ScopeError> {
        let compiled =
            Regex::new(pattern).map_err(|e| ScopeError::InvalidPattern(e.to_string()))?;

        let id = self.next_id;
        self.next_id += 1;

        self.rules.push(ScopeRule {
            id,
            pattern: pattern.to_string(),
            is_include,
            enabled: true,
        });
        self.compiled.push((compiled, is_include, true));

        Ok(id)
    }

    /// Removes a rule by ID. Returns whether the rule was found.
    pub fn remove_rule(&mut self, id: u64) -> bool {
        if let Some(pos) = self.rules.iter().position(|r| r.id == id) {
            self.rules.remove(pos);
            self.compiled.remove(pos);
            return true;
        }
        false
    }

    /// Toggles a rule's enabled state. Returns whether the rule was found.
    pub fn toggle_rule(&mut self, id: u64) -> bool {
        if let Some(pos) = self.rules.iter().position(|r| r.id == id) {
            self.rules[pos].enabled = !self.rules[pos].enabled;
            self.compiled[pos].2 = self.rules[pos].enabled;
            return true;
        }
        false
    }

    /// Evaluates whether a URL is in scope.
    ///
    /// Include rules are checked first (any match passes), then exclude
    /// rules (any match rejects). Exclude takes precedence over include.
    #[must_use]
    pub fn is_in_scope(&self, url: &str) -> bool {
        let has_enabled_includes = self
            .compiled
            .iter()
            .any(|(_, is_include, enabled)| *is_include && *enabled);

        if has_enabled_includes {
            let matches_include = self
                .compiled
                .iter()
                .any(|(re, is_include, enabled)| *is_include && *enabled && re.is_match(url));

            if !matches_include {
                return false;
            }
        }

        !self
            .compiled
            .iter()
            .any(|(re, is_include, enabled)| !*is_include && *enabled && re.is_match(url))
    }

    /// Returns a read-only slice of all current rules.
    #[must_use]
    pub fn rules(&self) -> &[ScopeRule] {
        &self.rules
    }
}

impl Default for ScopeEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "scope_test.rs"]
mod scope_test;
