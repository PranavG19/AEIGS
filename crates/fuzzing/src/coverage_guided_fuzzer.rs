use std::collections::{HashMap, HashSet};

use rand::Rng;

use crate::coverage_tracker::{CoverageResult, CoverageTracker};
use crate::executor::FuzzResponse;

/// A minimized input that triggered novel behavioral coverage.
#[derive(Debug, Clone)]
pub struct CorpusEntry {
    pub payload: String,
    pub signature_hash: u64,
    pub energy: f64,
    pub times_mutated: u64,
    pub novel_children: u64,
    pub body_size: usize,
}

/// Power schedule strategy controlling how energy is allocated across corpus entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerSchedule {
    /// Equal energy to all corpus entries.
    Uniform,
    /// More energy to entries that discovered the most new paths.
    PathFavored,
    /// More energy to recently added entries.
    RecencyBiased,
    /// Exponential backoff: entries that haven't produced novel children lose energy.
    ExponentialBackoff,
}

/// What kind of crash or anomaly was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CrashType {
    ServerError,
    Timeout,
    ConnectionReset,
    EmptyResponse,
    ContentTypeMismatch,
}

/// A detected crash event with its triggering payload.
#[derive(Debug, Clone)]
pub struct CrashRecord {
    pub crash_type: CrashType,
    pub payload: String,
    pub status_code: u16,
    pub response_time_ms: u64,
}

/// AFL-style coverage-guided fuzzer for HTTP endpoints.
///
/// Maintains a corpus of interesting inputs, assigns energy via a power schedule,
/// and detects crashes (5xx errors, timeouts, connection resets) as new paths.
/// Performs input minimization to find the shortest payload triggering each behavior.
pub struct CoverageGuidedFuzzer {
    coverage: CoverageTracker,
    corpus: Vec<CorpusEntry>,
    crashes: Vec<CrashRecord>,
    power_schedule: PowerSchedule,
    max_corpus_size: usize,
    total_executions: u64,
    last_novel_at: u64,
    crash_dedup: HashSet<(CrashType, u64)>,
    signature_to_corpus: HashMap<u64, usize>,
}

impl CoverageGuidedFuzzer {
    pub fn new() -> Self {
        Self {
            coverage: CoverageTracker::new(),
            corpus: Vec::new(),
            crashes: Vec::new(),
            power_schedule: PowerSchedule::PathFavored,
            max_corpus_size: 10_000,
            total_executions: 0,
            last_novel_at: 0,
            crash_dedup: HashSet::new(),
            signature_to_corpus: HashMap::new(),
        }
    }

    pub fn with_power_schedule(mut self, schedule: PowerSchedule) -> Self {
        self.power_schedule = schedule;
        self
    }

    pub fn with_max_corpus_size(mut self, size: usize) -> Self {
        self.max_corpus_size = size;
        self
    }

    /// Record a fuzz response and determine if the payload is interesting.
    /// Returns `true` if the payload triggered novel behavior and was added to the corpus.
    pub fn record_execution(&mut self, payload: &str, response: &FuzzResponse) -> bool {
        self.total_executions += 1;

        self.detect_crash(payload, response);

        let result = self.coverage.record(response, payload);
        match result {
            CoverageResult::Novel(sig) => {
                let hash = sig.combined_hash();
                self.last_novel_at = self.total_executions;
                self.add_to_corpus(payload, hash, response.body_size_bytes);
                true
            }
            CoverageResult::Known(_) => false,
        }
    }

    /// Select the next corpus entry to mutate based on the power schedule.
    /// Returns `None` if the corpus is empty.
    pub fn select_input(&self) -> Option<&CorpusEntry> {
        if self.corpus.is_empty() {
            return None;
        }
        let mut rng = rand::rng();
        let weights: Vec<f64> = self.compute_weights();
        let total: f64 = weights.iter().sum();
        if total <= 0.0 {
            return self.corpus.first();
        }

        let mut pick = rng.random_range(0.0..total);
        for (idx, weight) in weights.iter().enumerate() {
            pick -= weight;
            if pick <= 0.0 {
                return Some(&self.corpus[idx]);
            }
        }
        self.corpus.last()
    }

    /// Minimize a payload: attempt to find the shortest substring that still
    /// triggers the same behavioral signature hash.
    pub fn minimize_input(
        &self,
        payload: &str,
        target_hash: u64,
        evaluate: impl Fn(&str) -> Option<FuzzResponse>,
    ) -> String {
        let mut current = payload.to_string();
        let char_count = current.chars().count();

        if char_count <= 1 {
            return current;
        }

        for chunk_size in [char_count / 2, char_count / 4, 1].iter().copied() {
            if chunk_size == 0 {
                continue;
            }
            let mut offset = 0;
            while offset + chunk_size <= current.chars().count() {
                let candidate: String = current
                    .chars()
                    .take(offset)
                    .chain(current.chars().skip(offset + chunk_size))
                    .collect();

                if candidate.is_empty() {
                    offset += 1;
                    continue;
                }

                if let Some(resp) = evaluate(&candidate) {
                    let sig = build_quick_signature(&resp);
                    if sig == target_hash {
                        current = candidate;
                        continue;
                    }
                }
                offset += 1;
            }
        }
        current
    }

    /// Number of executions since the last novel coverage discovery.
    pub fn executions_since_novel(&self) -> u64 {
        self.total_executions - self.last_novel_at
    }

    pub fn total_executions(&self) -> u64 {
        self.total_executions
    }

    pub fn coverage_count(&self) -> usize {
        self.coverage.coverage_count()
    }

    pub fn corpus(&self) -> &[CorpusEntry] {
        &self.corpus
    }

    pub fn corpus_size(&self) -> usize {
        self.corpus.len()
    }

    pub fn crashes(&self) -> &[CrashRecord] {
        &self.crashes
    }

    pub fn power_schedule(&self) -> PowerSchedule {
        self.power_schedule
    }

    /// Notify that a corpus entry produced a child that triggered novel coverage.
    pub fn record_novel_child(&mut self, parent_index: usize) {
        if let Some(entry) = self.corpus.get_mut(parent_index) {
            entry.novel_children += 1;
            entry.energy = (entry.energy * 1.5).min(100.0);
        }
    }

    /// Notify that a corpus entry was mutated without producing novel coverage.
    pub fn record_mutation(&mut self, corpus_index: usize) {
        if let Some(entry) = self.corpus.get_mut(corpus_index) {
            entry.times_mutated += 1;
            if self.power_schedule == PowerSchedule::ExponentialBackoff {
                entry.energy *= 0.95;
                if entry.energy < 0.1 {
                    entry.energy = 0.1;
                }
            }
        }
    }

    fn add_to_corpus(&mut self, payload: &str, sig_hash: u64, body_size: usize) {
        if self.corpus.len() >= self.max_corpus_size {
            self.evict_lowest_energy();
        }

        let idx = self.corpus.len();
        self.corpus.push(CorpusEntry {
            payload: payload.to_string(),
            signature_hash: sig_hash,
            energy: 1.0,
            times_mutated: 0,
            novel_children: 0,
            body_size,
        });
        self.signature_to_corpus.insert(sig_hash, idx);
    }

    fn evict_lowest_energy(&mut self) {
        if self.corpus.is_empty() {
            return;
        }
        let mut min_idx = 0;
        let mut min_energy = f64::MAX;
        for (idx, entry) in self.corpus.iter().enumerate() {
            if entry.energy < min_energy {
                min_energy = entry.energy;
                min_idx = idx;
            }
        }
        let removed = self.corpus.remove(min_idx);
        self.signature_to_corpus.remove(&removed.signature_hash);
        self.rebuild_corpus_index();
    }

    fn rebuild_corpus_index(&mut self) {
        self.signature_to_corpus.clear();
        for (idx, entry) in self.corpus.iter().enumerate() {
            self.signature_to_corpus.insert(entry.signature_hash, idx);
        }
    }

    fn compute_weights(&self) -> Vec<f64> {
        match self.power_schedule {
            PowerSchedule::Uniform => vec![1.0; self.corpus.len()],
            PowerSchedule::PathFavored => self
                .corpus
                .iter()
                .map(|e| 1.0 + e.novel_children as f64 * 2.0)
                .collect(),
            PowerSchedule::RecencyBiased => {
                let len = self.corpus.len() as f64;
                self.corpus
                    .iter()
                    .enumerate()
                    .map(|(idx, _)| 1.0 + (idx as f64 / len) * 5.0)
                    .collect()
            }
            PowerSchedule::ExponentialBackoff => self.corpus.iter().map(|e| e.energy).collect(),
        }
    }

    fn detect_crash(&mut self, payload: &str, response: &FuzzResponse) {
        let crash_type = classify_crash(response);
        if let Some(ct) = crash_type {
            let dedup_key = (ct, quick_hash(payload));
            if self.crash_dedup.insert(dedup_key) {
                self.crashes.push(CrashRecord {
                    crash_type: ct,
                    payload: payload.to_string(),
                    status_code: response.status_code,
                    response_time_ms: response.response_time.as_millis() as u64,
                });
            }
        }
    }
}

impl Default for CoverageGuidedFuzzer {
    fn default() -> Self {
        Self::new()
    }
}

fn classify_crash(response: &FuzzResponse) -> Option<CrashType> {
    if response.status_code >= 500 {
        return Some(CrashType::ServerError);
    }
    if response.response_time.as_secs() >= 10 {
        return Some(CrashType::Timeout);
    }
    if response.body.is_empty() && response.status_code == 0 {
        return Some(CrashType::ConnectionReset);
    }
    if response.body.is_empty() && response.status_code >= 200 && response.status_code < 300 {
        return Some(CrashType::EmptyResponse);
    }
    None
}

fn build_quick_signature(response: &FuzzResponse) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    (response.status_code / 100).hash(&mut hasher);
    (response.body.len() / 256).hash(&mut hasher);
    response.response_time.as_millis().hash(&mut hasher);
    hasher.finish()
}

fn quick_hash(s: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}
