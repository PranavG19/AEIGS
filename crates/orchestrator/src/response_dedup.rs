use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::Instant;

/// Configuration for response deduplication.
///
/// Controls when endpoints are considered duplicates based on response
/// fingerprinting. Endpoints producing structurally identical responses
/// (same status code, content length, and body hash) beyond a configurable
/// threshold are marked as skippable to avoid redundant fuzzing.
#[derive(Debug, Clone)]
pub struct DedupConfig {
    pub min_duplicates_to_skip: usize,
    pub similarity_threshold: f64,
    pub max_tracked_responses: usize,
    pub include_headers_in_hash: bool,
    pub ignore_status_codes: Vec<u16>,
}

impl Default for DedupConfig {
    fn default() -> Self {
        Self {
            min_duplicates_to_skip: 3,
            similarity_threshold: 0.95,
            max_tracked_responses: 10_000,
            include_headers_in_hash: false,
            ignore_status_codes: Vec::new(),
        }
    }
}

impl DedupConfig {
    pub fn with_min_duplicates(mut self, n: usize) -> Self {
        self.min_duplicates_to_skip = n.max(1);
        self
    }

    pub fn with_similarity_threshold(mut self, t: f64) -> Self {
        self.similarity_threshold = t.clamp(0.0, 1.0);
        self
    }

    pub fn with_max_tracked(mut self, n: usize) -> Self {
        self.max_tracked_responses = n;
        self
    }

    pub fn with_headers_in_hash(mut self, b: bool) -> Self {
        self.include_headers_in_hash = b;
        self
    }

    pub fn with_ignored_status_codes(mut self, codes: Vec<u16>) -> Self {
        self.ignore_status_codes = codes;
        self
    }
}

/// A structural fingerprint of an HTTP response.
///
/// Captures the status code, content length, body hash, and optional
/// content type. Two responses with identical fingerprints are treated
/// as structurally equivalent regardless of endpoint origin.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ResponseFingerprint {
    pub status_code: u16,
    pub content_length: usize,
    pub body_hash: u64,
    pub content_type: Option<String>,
}

/// A group of endpoints that produced structurally identical responses.
///
/// Once the number of endpoints in a group meets or exceeds the configured
/// `min_duplicates_to_skip`, the group is marked as skippable and further
/// testing of its member endpoints can be elided.
#[derive(Debug, Clone)]
pub struct DuplicateGroup {
    pub fingerprint: ResponseFingerprint,
    pub endpoints: Vec<String>,
    pub first_seen_at: Instant,
    pub should_skip: bool,
}

/// Aggregate statistics for the deduplication process.
#[derive(Debug, Clone, Default)]
pub struct DedupStats {
    pub total_responses_seen: u64,
    pub unique_fingerprints: usize,
    pub duplicate_groups: usize,
    pub endpoints_skipped: u64,
    pub bytes_saved_estimate: u64,
}

/// Tracks response fingerprints across endpoints to identify and skip duplicates.
///
/// The deduplicator maintains a mapping from response fingerprints to duplicate
/// groups, and from endpoints to their observed fingerprints. When enough
/// endpoints produce the same fingerprint, subsequent endpoints matching that
/// fingerprint are flagged as skippable.
pub struct ResponseDeduplicator {
    config: DedupConfig,
    fingerprints: HashMap<ResponseFingerprint, DuplicateGroup>,
    endpoint_to_fingerprint: HashMap<String, ResponseFingerprint>,
    stats: DedupStats,
}

impl ResponseDeduplicator {
    pub fn new(config: DedupConfig) -> Self {
        Self {
            config,
            fingerprints: HashMap::new(),
            endpoint_to_fingerprint: HashMap::new(),
            stats: DedupStats::default(),
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(DedupConfig::default())
    }

    /// Produces a deterministic fingerprint from an HTTP response's observable structure.
    pub fn fingerprint_response(
        status_code: u16,
        body: &[u8],
        content_type: Option<&str>,
    ) -> ResponseFingerprint {
        let mut hasher = DefaultHasher::new();
        body.hash(&mut hasher);
        let body_hash = hasher.finish();

        ResponseFingerprint {
            status_code,
            content_length: body.len(),
            body_hash,
            content_type: content_type.map(|s| s.to_string()),
        }
    }

    /// Records an endpoint's response fingerprint and updates duplicate group state.
    pub fn record_response(&mut self, endpoint: &str, fingerprint: ResponseFingerprint) {
        if self.is_ignored_status_code(fingerprint.status_code) {
            return;
        }

        if self.endpoint_to_fingerprint.len() >= self.config.max_tracked_responses
            && !self.endpoint_to_fingerprint.contains_key(endpoint)
        {
            return;
        }

        self.stats.total_responses_seen += 1;
        let content_length = fingerprint.content_length as u64;

        self.endpoint_to_fingerprint
            .insert(endpoint.to_string(), fingerprint.clone());

        let group = self
            .fingerprints
            .entry(fingerprint.clone())
            .or_insert_with(|| DuplicateGroup {
                fingerprint,
                endpoints: Vec::new(),
                first_seen_at: Instant::now(),
                should_skip: false,
            });

        if !group.endpoints.contains(&endpoint.to_string()) {
            group.endpoints.push(endpoint.to_string());
        }

        if group.endpoints.len() >= self.config.min_duplicates_to_skip && !group.should_skip {
            group.should_skip = true;
        }

        if group.should_skip {
            self.stats.endpoints_skipped += 1;
            self.stats.bytes_saved_estimate += content_length;
        }

        self.refresh_aggregate_stats();
    }

    /// Returns true if the given endpoint has been recorded and belongs to
    /// a duplicate group that has reached the skip threshold.
    pub fn should_skip(&self, endpoint: &str) -> bool {
        let Some(fp) = self.endpoint_to_fingerprint.get(endpoint) else {
            return false;
        };
        self.should_skip_fingerprint(fp)
    }

    /// Returns true if the given fingerprint belongs to a duplicate group
    /// that has reached the skip threshold.
    pub fn should_skip_fingerprint(&self, fingerprint: &ResponseFingerprint) -> bool {
        self.fingerprints
            .get(fingerprint)
            .is_some_and(|group| group.should_skip)
    }

    pub fn get_duplicate_group(
        &self,
        fingerprint: &ResponseFingerprint,
    ) -> Option<&DuplicateGroup> {
        self.fingerprints.get(fingerprint)
    }

    pub fn get_endpoint_fingerprint(&self, endpoint: &str) -> Option<&ResponseFingerprint> {
        self.endpoint_to_fingerprint.get(endpoint)
    }

    /// Returns all duplicate groups that have reached the skip threshold.
    pub fn duplicate_groups(&self) -> Vec<&DuplicateGroup> {
        self.fingerprints
            .values()
            .filter(|g| g.should_skip)
            .collect()
    }

    /// Returns endpoints that belong to a skippable duplicate group.
    pub fn skippable_endpoints(&self) -> Vec<&str> {
        self.endpoint_to_fingerprint
            .iter()
            .filter(|(_, fp)| self.should_skip_fingerprint(fp))
            .map(|(ep, _)| ep.as_str())
            .collect()
    }

    pub fn stats(&self) -> &DedupStats {
        &self.stats
    }

    pub fn reset(&mut self) {
        self.fingerprints.clear();
        self.endpoint_to_fingerprint.clear();
        self.stats = DedupStats::default();
    }

    pub fn unique_fingerprint_count(&self) -> usize {
        self.fingerprints.len()
    }

    pub fn total_endpoints_tracked(&self) -> usize {
        self.endpoint_to_fingerprint.len()
    }

    fn is_ignored_status_code(&self, status_code: u16) -> bool {
        self.config.ignore_status_codes.contains(&status_code)
    }

    fn refresh_aggregate_stats(&mut self) {
        self.stats.unique_fingerprints = self.fingerprints.len();
        self.stats.duplicate_groups = self.fingerprints.values().filter(|g| g.should_skip).count();
    }
}
