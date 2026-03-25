/// Memory-efficient finding store with arena allocation and string interning.
///
/// Stores vulnerability findings in a compact arena (Vec-backed, u64-indexed)
/// with deduplication of repeated strings (URLs, CWE IDs, vulnerability class
/// names) via a `StringInterner`. Supports indexed queries by URL, severity,
/// CWE, and vulnerability class. When in-memory capacity is exceeded, oldest
/// findings spill to a JSONL file on disk.
use serde_json;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Deduplicates common strings by assigning sequential `u32` identifiers.
///
/// Strings inserted more than once receive the same ID, avoiding redundant
/// heap allocations for values that repeat across many findings (endpoint
/// URLs, CWE identifiers, vulnerability class names).
#[derive(Debug)]
pub struct StringInterner {
    strings: Vec<String>,
    lookup: HashMap<String, u32>,
}

impl StringInterner {
    pub fn new() -> Self {
        Self {
            strings: Vec::new(),
            lookup: HashMap::new(),
        }
    }

    /// Intern a string, returning its stable numeric ID.
    /// Repeated calls with the same value return the same ID.
    pub fn intern(&mut self, s: &str) -> u32 {
        if let Some(&id) = self.lookup.get(s) {
            return id;
        }
        let id = self.strings.len() as u32;
        self.strings.push(s.to_owned());
        self.lookup.insert(s.to_owned(), id);
        id
    }

    /// Resolve an interned ID back to its string, or `None` if out of range.
    pub fn resolve(&self, id: u32) -> Option<&str> {
        self.strings.get(id as usize).map(|s| s.as_str())
    }

    pub fn len(&self) -> usize {
        self.strings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }
}

/// Severity level for findings, ordered from informational to critical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "Info"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// A compact finding stored in the arena.
///
/// Fields that repeat across findings (`url`, `cwe`, `vuln_class`, `title`)
/// are stored as interned `u32` identifiers. The `description` and `evidence`
/// fields are unique per finding and stored inline.
#[derive(Debug, Clone)]
pub struct CompactFinding {
    pub id: u64,
    pub url_id: u32,
    pub cwe_id: u32,
    pub vuln_class_id: u32,
    pub severity: Severity,
    pub title_id: u32,
    pub description: String,
    pub evidence: String,
    pub confidence: f64,
    pub timestamp_ms: u64,
}

/// Configuration for the finding store.
///
/// Controls memory limits, disk spillover, and whether secondary indices
/// are maintained for fast query lookups.
#[derive(Debug, Clone)]
pub struct FindingStoreConfig {
    pub max_memory_findings: usize,
    pub spill_to_disk: bool,
    pub spill_path: Option<PathBuf>,
    pub enable_indexing: bool,
}

impl Default for FindingStoreConfig {
    fn default() -> Self {
        Self {
            max_memory_findings: 10_000,
            spill_to_disk: true,
            spill_path: None,
            enable_indexing: true,
        }
    }
}

impl FindingStoreConfig {
    pub fn with_max_memory(mut self, n: usize) -> Self {
        self.max_memory_findings = n;
        self
    }

    pub fn with_spill_to_disk(mut self, b: bool) -> Self {
        self.spill_to_disk = b;
        self
    }

    pub fn with_spill_path(mut self, p: PathBuf) -> Self {
        self.spill_path = Some(p);
        self
    }

    pub fn with_indexing(mut self, b: bool) -> Self {
        self.enable_indexing = b;
        self
    }
}

/// Aggregate statistics for the finding store.
#[derive(Debug, Clone, Default)]
pub struct StoreStats {
    pub total_findings: u64,
    pub in_memory_findings: usize,
    pub spilled_findings: u64,
    pub interned_strings: usize,
    pub unique_urls: usize,
    pub unique_cwes: usize,
    pub unique_vuln_classes: usize,
    pub severity_counts: HashMap<String, usize>,
    pub memory_estimate_bytes: usize,
}

/// Memory-efficient arena-backed finding store.
///
/// Findings are appended to a `Vec<CompactFinding>` arena and looked up by
/// direct index. Optional secondary indices (URL, severity, CWE, vuln class)
/// accelerate filtered queries. When the arena exceeds `max_memory_findings`,
/// the oldest entries are serialized to a JSONL spill file on disk.
pub struct FindingStoreV2 {
    config: FindingStoreConfig,
    arena: Vec<CompactFinding>,
    interner: StringInterner,
    next_id: u64,
    url_index: HashMap<u32, Vec<usize>>,
    severity_index: HashMap<Severity, Vec<usize>>,
    cwe_index: HashMap<u32, Vec<usize>>,
    vuln_class_index: HashMap<u32, Vec<usize>>,
    spilled_count: u64,
    spill_path: Option<PathBuf>,
}

impl FindingStoreV2 {
    pub fn new(config: FindingStoreConfig) -> Self {
        Self {
            arena: Vec::with_capacity(config.max_memory_findings.min(4096)),
            interner: StringInterner::new(),
            next_id: 0,
            url_index: HashMap::new(),
            severity_index: HashMap::new(),
            cwe_index: HashMap::new(),
            vuln_class_index: HashMap::new(),
            spilled_count: 0,
            spill_path: config.spill_path.clone(),
            config,
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(FindingStoreConfig::default())
    }

    /// Insert a finding into the store, returning its unique ID.
    ///
    /// If the arena is at capacity and `spill_to_disk` is enabled, the oldest
    /// half of in-memory findings are flushed to disk before the new finding
    /// is inserted.
    #[allow(clippy::too_many_arguments)]
    pub fn add_finding(
        &mut self,
        url: &str,
        cwe: &str,
        vuln_class: &str,
        severity: Severity,
        title: &str,
        description: String,
        evidence: String,
        confidence: f64,
    ) -> u64 {
        if self.arena.len() >= self.config.max_memory_findings && self.config.spill_to_disk {
            let _ = self.spill_to_disk();
        }

        let id = self.next_id;
        self.next_id += 1;

        let url_id = self.interner.intern(url);
        let cwe_id = self.interner.intern(cwe);
        let vuln_class_id = self.interner.intern(vuln_class);
        let title_id = self.interner.intern(title);

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let finding = CompactFinding {
            id,
            url_id,
            cwe_id,
            vuln_class_id,
            severity,
            title_id,
            description,
            evidence,
            confidence,
            timestamp_ms,
        };

        let arena_idx = self.arena.len();
        self.arena.push(finding);

        if self.config.enable_indexing {
            self.index_finding(arena_idx, url_id, severity, cwe_id, vuln_class_id);
        }

        id
    }

    fn index_finding(
        &mut self,
        arena_idx: usize,
        url_id: u32,
        severity: Severity,
        cwe_id: u32,
        vuln_class_id: u32,
    ) {
        self.url_index.entry(url_id).or_default().push(arena_idx);
        self.severity_index.entry(severity).or_default().push(arena_idx);
        self.cwe_index.entry(cwe_id).or_default().push(arena_idx);
        self.vuln_class_index
            .entry(vuln_class_id)
            .or_default()
            .push(arena_idx);
    }

    /// Retrieve a finding by its unique ID via linear scan.
    pub fn get_finding(&self, id: u64) -> Option<&CompactFinding> {
        self.arena.iter().find(|f| f.id == id)
    }

    /// Return all in-memory findings matching the given URL.
    pub fn find_by_url(&self, url: &str) -> Vec<&CompactFinding> {
        if let Some(&url_id) = self.interner.lookup.get(url) {
            self.resolve_indices(self.url_index.get(&url_id))
        } else {
            Vec::new()
        }
    }

    /// Return all in-memory findings with the given severity.
    pub fn find_by_severity(&self, severity: Severity) -> Vec<&CompactFinding> {
        self.resolve_indices(self.severity_index.get(&severity))
    }

    /// Return all in-memory findings matching the given CWE identifier.
    pub fn find_by_cwe(&self, cwe: &str) -> Vec<&CompactFinding> {
        if let Some(&cwe_id) = self.interner.lookup.get(cwe) {
            self.resolve_indices(self.cwe_index.get(&cwe_id))
        } else {
            Vec::new()
        }
    }

    /// Return all in-memory findings matching the given vulnerability class.
    pub fn find_by_vuln_class(&self, vuln_class: &str) -> Vec<&CompactFinding> {
        if let Some(&vc_id) = self.interner.lookup.get(vuln_class) {
            self.resolve_indices(self.vuln_class_index.get(&vc_id))
        } else {
            Vec::new()
        }
    }

    fn resolve_indices(&self, indices: Option<&Vec<usize>>) -> Vec<&CompactFinding> {
        match indices {
            Some(idxs) => idxs
                .iter()
                .filter_map(|&i| self.arena.get(i))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Serialize all in-memory findings to a JSON array with resolved strings.
    pub fn to_json(&self) -> String {
        let entries: Vec<serde_json::Value> = self
            .arena
            .iter()
            .map(|f| self.finding_to_json(f))
            .collect();
        serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".to_owned())
    }

    fn finding_to_json(&self, f: &CompactFinding) -> serde_json::Value {
        serde_json::json!({
            "id": f.id,
            "url": self.interner.resolve(f.url_id).unwrap_or(""),
            "cwe": self.interner.resolve(f.cwe_id).unwrap_or(""),
            "vuln_class": self.interner.resolve(f.vuln_class_id).unwrap_or(""),
            "severity": f.severity.to_string(),
            "title": self.interner.resolve(f.title_id).unwrap_or(""),
            "description": f.description,
            "evidence": f.evidence,
            "confidence": f.confidence,
            "timestamp_ms": f.timestamp_ms,
        })
    }

    /// Flush the oldest half of in-memory findings to a JSONL file on disk.
    ///
    /// Returns the number of findings written. Indices are rebuilt after the
    /// spill to reflect the remaining arena contents.
    pub fn spill_to_disk(&mut self) -> Result<usize, std::io::Error> {
        let spill_count = self.arena.len() / 2;
        if spill_count == 0 {
            return Ok(0);
        }

        let path = self.resolve_spill_path()?;
        let drained: Vec<CompactFinding> = self.arena.drain(..spill_count).collect();

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        for finding in &drained {
            let json = self.finding_to_json(finding);
            serde_json::to_writer(&mut file, &json)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            file.write_all(b"\n")?;
        }

        self.spilled_count += drained.len() as u64;
        self.rebuild_indices();

        Ok(drained.len())
    }

    fn resolve_spill_path(&mut self) -> Result<PathBuf, std::io::Error> {
        if let Some(ref p) = self.spill_path {
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent)?;
            }
            return Ok(p.clone());
        }
        let dir = std::env::temp_dir().join("aegis-finding-store");
        fs::create_dir_all(&dir)?;
        let path = dir.join("spilled_findings.jsonl");
        self.spill_path = Some(path.clone());
        Ok(path)
    }

    fn rebuild_indices(&mut self) {
        self.url_index.clear();
        self.severity_index.clear();
        self.cwe_index.clear();
        self.vuln_class_index.clear();

        if !self.config.enable_indexing {
            return;
        }

        for (arena_idx, finding) in self.arena.iter().enumerate() {
            self.url_index
                .entry(finding.url_id)
                .or_default()
                .push(arena_idx);
            self.severity_index
                .entry(finding.severity)
                .or_default()
                .push(arena_idx);
            self.cwe_index
                .entry(finding.cwe_id)
                .or_default()
                .push(arena_idx);
            self.vuln_class_index
                .entry(finding.vuln_class_id)
                .or_default()
                .push(arena_idx);
        }
    }

    pub fn resolve_url(&self, finding: &CompactFinding) -> Option<&str> {
        self.interner.resolve(finding.url_id)
    }

    pub fn resolve_cwe(&self, finding: &CompactFinding) -> Option<&str> {
        self.interner.resolve(finding.cwe_id)
    }

    pub fn resolve_vuln_class(&self, finding: &CompactFinding) -> Option<&str> {
        self.interner.resolve(finding.vuln_class_id)
    }

    pub fn resolve_title(&self, finding: &CompactFinding) -> Option<&str> {
        self.interner.resolve(finding.title_id)
    }

    /// Compute aggregate statistics for the store.
    pub fn stats(&self) -> StoreStats {
        let mut severity_counts: HashMap<String, usize> = HashMap::new();
        let mut unique_urls: std::collections::HashSet<u32> = std::collections::HashSet::new();
        let mut unique_cwes: std::collections::HashSet<u32> = std::collections::HashSet::new();
        let mut unique_vcs: std::collections::HashSet<u32> = std::collections::HashSet::new();

        for finding in &self.arena {
            *severity_counts
                .entry(finding.severity.to_string())
                .or_default() += 1;
            unique_urls.insert(finding.url_id);
            unique_cwes.insert(finding.cwe_id);
            unique_vcs.insert(finding.vuln_class_id);
        }

        let per_finding_bytes = 200;
        let interned_bytes: usize = self
            .interner
            .strings
            .iter()
            .map(|s| s.len() + std::mem::size_of::<String>())
            .sum();
        let memory_estimate =
            self.arena.len() * per_finding_bytes + interned_bytes;

        StoreStats {
            total_findings: self.next_id,
            in_memory_findings: self.arena.len(),
            spilled_findings: self.spilled_count,
            interned_strings: self.interner.len(),
            unique_urls: unique_urls.len(),
            unique_cwes: unique_cwes.len(),
            unique_vuln_classes: unique_vcs.len(),
            severity_counts,
            memory_estimate_bytes: memory_estimate,
        }
    }

    pub fn len(&self) -> usize {
        self.arena.len()
    }

    pub fn is_empty(&self) -> bool {
        self.arena.is_empty()
    }

    /// Remove all in-memory findings and reset indices.
    /// Spill counts and the interner are preserved.
    pub fn clear(&mut self) {
        self.arena.clear();
        self.url_index.clear();
        self.severity_index.clear();
        self.cwe_index.clear();
        self.vuln_class_index.clear();
    }
}

#[cfg(test)]
#[path = "finding_store_v2_test.rs"]
mod finding_store_v2_test;
