use regex::Regex;

/// Which part of the HTTP exchange a rule targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchTarget {
    RequestHeader,
    RequestBody,
    ResponseHeader,
    ResponseBody,
}

/// A single match-and-replace rule applied to proxy traffic.
#[derive(Debug, Clone)]
pub struct ModificationRule {
    pub id: u64,
    pub enabled: bool,
    pub match_target: MatchTarget,
    pub match_pattern: String,
    pub replace_with: String,
}

/// Engine that manages an ordered collection of modification rules.
pub struct ModificationEngine {
    rules: Vec<ModificationRule>,
    next_id: u64,
}

/// Errors from rule creation or application.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ModificationError {
    #[error("invalid modification pattern: {0}")]
    InvalidPattern(String),
}

impl ModificationEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            next_id: 1,
        }
    }

    /// Validate the regex pattern, add a new enabled rule, and return its ID.
    pub fn add_rule(
        &mut self,
        target: MatchTarget,
        pattern: &str,
        replace_with: &str,
    ) -> Result<u64, ModificationError> {
        Regex::new(pattern).map_err(|e| ModificationError::InvalidPattern(e.to_string()))?;
        let id = self.next_id;
        self.next_id += 1;
        self.rules.push(ModificationRule {
            id,
            enabled: true,
            match_target: target,
            match_pattern: pattern.to_string(),
            replace_with: replace_with.to_string(),
        });
        Ok(id)
    }

    /// Remove a rule by ID. Returns true if the rule existed.
    pub fn remove_rule(&mut self, id: u64) -> bool {
        let len_before = self.rules.len();
        self.rules.retain(|r| r.id != id);
        self.rules.len() != len_before
    }

    /// Toggle a rule's enabled state. Returns true if the rule existed.
    pub fn toggle_rule(&mut self, id: u64) -> bool {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == id) {
            rule.enabled = !rule.enabled;
            true
        } else {
            false
        }
    }

    /// Read-only access to the ordered rule list.
    pub fn rules(&self) -> &[ModificationRule] {
        &self.rules
    }
}

impl Default for ModificationEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Apply all enabled RequestHeader and RequestBody rules to the given request parts.
pub fn apply_request_modifications(
    rules: &[ModificationRule],
    headers: &mut Vec<(String, String)>,
    body: &mut Vec<u8>,
) {
    for rule in rules.iter().filter(|r| r.enabled) {
        match rule.match_target {
            MatchTarget::RequestHeader => apply_header_rule(rule, headers),
            MatchTarget::RequestBody => apply_body_rule(rule, body),
            _ => {}
        }
    }
}

/// Apply all enabled ResponseHeader and ResponseBody rules to the given response parts.
pub fn apply_response_modifications(
    rules: &[ModificationRule],
    headers: &mut Vec<(String, String)>,
    body: &mut Vec<u8>,
) {
    for rule in rules.iter().filter(|r| r.enabled) {
        match rule.match_target {
            MatchTarget::ResponseHeader => apply_header_rule(rule, headers),
            MatchTarget::ResponseBody => apply_body_rule(rule, body),
            _ => {}
        }
    }
}

fn apply_header_rule(rule: &ModificationRule, headers: &mut Vec<(String, String)>) {
    let Ok(re) = Regex::new(&rule.match_pattern) else {
        return;
    };
    let mut i = 0;
    while i < headers.len() {
        let combined = format!("{}: {}", headers[i].0, headers[i].1);
        let replaced = re.replace_all(&combined, rule.replace_with.as_str());
        if replaced.is_empty() {
            headers.remove(i);
        } else if let Some((name, value)) = replaced.split_once(": ") {
            headers[i] = (name.to_string(), value.to_string());
            i += 1;
        } else {
            headers[i] = (replaced.into_owned(), String::new());
            i += 1;
        }
    }
}

fn apply_body_rule(rule: &ModificationRule, body: &mut Vec<u8>) {
    let Ok(re) = Regex::new(&rule.match_pattern) else {
        return;
    };
    let text = String::from_utf8_lossy(body);
    let replaced = re.replace_all(&text, rule.replace_with.as_str());
    *body = replaced.into_owned().into_bytes();
}

#[cfg(test)]
#[path = "modification_test.rs"]
mod modification_test;
