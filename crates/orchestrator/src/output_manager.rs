use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Supported export formats for scan results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExportFormat {
    Sarif,
    Json,
    Csv,
    Html,
}

impl ExportFormat {
    pub fn extension(&self) -> &str {
        match self {
            Self::Sarif => "sarif.json",
            Self::Json => "json",
            Self::Csv => "csv",
            Self::Html => "html",
        }
    }

    pub fn all() -> &'static [ExportFormat] {
        &[Self::Sarif, Self::Json, Self::Csv, Self::Html]
    }
}

/// Metadata about a stored scan output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOutputEntry {
    pub scan_id: String,
    pub created_at_unix_ms: u64,
    pub target_url: String,
    pub findings_count: u64,
    pub report_paths: HashMap<String, String>,
    pub evidence_files: Vec<String>,
}

/// A single finding stored in the output manager's database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFinding {
    pub id: u64,
    pub scan_id: String,
    pub vulnerability_class: String,
    pub endpoint: String,
    pub severity: f64,
    pub confidence: f64,
    pub evidence: String,
}

/// Manages all scan outputs: findings DB, evidence files, screenshots, reports.
///
/// Organizes outputs by scan ID under a root directory. Each scan gets its own
/// subdirectory with findings, evidence, and reports stored in a structured layout.
///
/// ```text
/// output_root/
///   {scan_id}/
///     findings.json
///     evidence/
///     reports/
///       report.sarif.json
///       report.json
///       report.csv
///       report.html
///     metadata.json
/// ```
pub struct OutputManager {
    output_root: PathBuf,
    scans: HashMap<String, ScanOutputEntry>,
    max_retained_scans: usize,
}

/// Errors from the output manager.
#[derive(Debug)]
pub enum OutputError {
    Io(io::Error),
    Serialization(String),
    ScanNotFound(String),
}

impl std::fmt::Display for OutputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Serialization(msg) => write!(f, "serialization error: {}", msg),
            Self::ScanNotFound(id) => write!(f, "scan not found: {}", id),
        }
    }
}

impl std::error::Error for OutputError {}

impl From<io::Error> for OutputError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl OutputManager {
    /// Creates a new output manager rooted at the given directory.
    pub fn new(output_root: impl Into<PathBuf>) -> Self {
        Self {
            output_root: output_root.into(),
            scans: HashMap::new(),
            max_retained_scans: 50,
        }
    }

    /// Sets the maximum number of scan outputs to retain. Oldest scans beyond
    /// this limit are cleaned up automatically.
    pub fn with_max_retained(mut self, max: usize) -> Self {
        self.max_retained_scans = max;
        self
    }

    /// Returns the root output directory.
    pub fn output_root(&self) -> &Path {
        &self.output_root
    }

    /// Initializes a new scan output directory. Returns the scan directory path.
    pub fn init_scan(&mut self, scan_id: &str, target_url: &str) -> Result<PathBuf, OutputError> {
        let scan_dir = self.output_root.join(scan_id);
        fs::create_dir_all(scan_dir.join("evidence"))?;
        fs::create_dir_all(scan_dir.join("reports"))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let entry = ScanOutputEntry {
            scan_id: scan_id.to_string(),
            created_at_unix_ms: now,
            target_url: target_url.to_string(),
            findings_count: 0,
            report_paths: HashMap::new(),
            evidence_files: Vec::new(),
        };

        self.scans.insert(scan_id.to_string(), entry);
        Ok(scan_dir)
    }

    /// Stores findings for a scan as a JSON file.
    pub fn store_findings(
        &mut self,
        scan_id: &str,
        findings: &[StoredFinding],
    ) -> Result<PathBuf, OutputError> {
        let scan_dir = self.scan_dir(scan_id)?;
        let path = scan_dir.join("findings.json");
        let json = serde_json::to_string_pretty(findings)
            .map_err(|e| OutputError::Serialization(e.to_string()))?;
        fs::write(&path, json)?;

        if let Some(entry) = self.scans.get_mut(scan_id) {
            entry.findings_count = findings.len() as u64;
        }
        Ok(path)
    }

    /// Stores an evidence file (payload dump, screenshot, etc).
    pub fn store_evidence(
        &mut self,
        scan_id: &str,
        filename: &str,
        data: &[u8],
    ) -> Result<PathBuf, OutputError> {
        let scan_dir = self.scan_dir(scan_id)?;
        let path = scan_dir.join("evidence").join(filename);
        fs::write(&path, data)?;

        if let Some(entry) = self.scans.get_mut(scan_id) {
            entry.evidence_files.push(filename.to_string());
        }
        Ok(path)
    }

    /// Exports scan results in the given format. Returns the output file path.
    pub fn export(
        &mut self,
        scan_id: &str,
        format: ExportFormat,
        content: &str,
    ) -> Result<PathBuf, OutputError> {
        let scan_dir = self.scan_dir(scan_id)?;
        let filename = format!("report.{}", format.extension());
        let path = scan_dir.join("reports").join(&filename);
        fs::write(&path, content)?;

        if let Some(entry) = self.scans.get_mut(scan_id) {
            entry
                .report_paths
                .insert(format!("{:?}", format), path.to_string_lossy().to_string());
        }
        Ok(path)
    }

    /// Saves scan metadata to disk.
    pub fn save_metadata(&self, scan_id: &str) -> Result<PathBuf, OutputError> {
        let entry = self
            .scans
            .get(scan_id)
            .ok_or_else(|| OutputError::ScanNotFound(scan_id.to_string()))?;

        let scan_dir = self.output_root.join(scan_id);
        let path = scan_dir.join("metadata.json");
        let json = serde_json::to_string_pretty(entry)
            .map_err(|e| OutputError::Serialization(e.to_string()))?;
        fs::write(&path, json)?;
        Ok(path)
    }

    /// Lists all managed scan IDs, most recent first.
    pub fn list_scans(&self) -> Vec<&ScanOutputEntry> {
        let mut entries: Vec<_> = self.scans.values().collect();
        entries.sort_by(|a, b| b.created_at_unix_ms.cmp(&a.created_at_unix_ms));
        entries
    }

    /// Returns the output entry for a scan, if it exists.
    pub fn get_scan(&self, scan_id: &str) -> Option<&ScanOutputEntry> {
        self.scans.get(scan_id)
    }

    /// Removes a scan's output directory and metadata.
    pub fn delete_scan(&mut self, scan_id: &str) -> Result<(), OutputError> {
        let scan_dir = self.output_root.join(scan_id);
        if scan_dir.exists() {
            fs::remove_dir_all(&scan_dir)?;
        }
        self.scans.remove(scan_id);
        Ok(())
    }

    /// Cleans up old scans beyond the retention limit. Removes oldest first.
    pub fn cleanup_old_scans(&mut self) -> Result<u32, OutputError> {
        let mut entries: Vec<(String, u64)> = self
            .scans
            .iter()
            .map(|(k, v)| (k.clone(), v.created_at_unix_ms))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1));

        let mut removed = 0u32;
        if entries.len() > self.max_retained_scans {
            let to_remove: Vec<String> = entries[self.max_retained_scans..]
                .iter()
                .map(|(id, _)| id.clone())
                .collect();
            for id in to_remove {
                self.delete_scan(&id)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Total disk usage of all managed scans in bytes.
    pub fn total_disk_usage(&self) -> u64 {
        let mut total = 0u64;
        for scan_id in self.scans.keys() {
            let dir = self.output_root.join(scan_id);
            if dir.exists() {
                total += dir_size(&dir).unwrap_or(0);
            }
        }
        total
    }

    fn scan_dir(&self, scan_id: &str) -> Result<PathBuf, OutputError> {
        let dir = self.output_root.join(scan_id);
        if !dir.exists() {
            return Err(OutputError::ScanNotFound(scan_id.to_string()));
        }
        Ok(dir)
    }
}

fn dir_size(path: &Path) -> io::Result<u64> {
    let mut total = 0u64;
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            if meta.is_dir() {
                total += dir_size(&entry.path())?;
            } else {
                total += meta.len();
            }
        }
    }
    Ok(total)
}
