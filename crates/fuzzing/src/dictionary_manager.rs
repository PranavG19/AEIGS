/// Manages all payload dictionaries with lazy loading, searchable context/technique/WAF
/// filters, deduplication, custom payload import, payload tagging (stealth vs aggressive),
/// and per-payload success rate statistics across scans.
use std::collections::{HashMap, HashSet};

use crate::cmdi_payloads_v2::{self, CmdiTechnique};
use crate::sqli_payloads::{self, SqliCategory};
use crate::ssrf_payloads::{self, SsrfCategory};
use crate::ssti_payloads;
use crate::xss_payloads::{self, XssCategory, XssPayload};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadDictionary {
    Xss,
    Sqli,
    Ssti,
    Ssrf,
    CmdiV2,
}

impl PayloadDictionary {
    pub fn all() -> &'static [PayloadDictionary] {
        &[
            PayloadDictionary::Xss,
            PayloadDictionary::Sqli,
            PayloadDictionary::Ssti,
            PayloadDictionary::Ssrf,
            PayloadDictionary::CmdiV2,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadAggressiveness {
    Stealth,
    Normal,
    Aggressive,
}

#[derive(Debug, Clone)]
pub struct PayloadStats {
    pub attempts: u64,
    pub successes: u64,
}

impl PayloadStats {
    pub fn success_rate(&self) -> f64 {
        if self.attempts == 0 {
            return 0.0;
        }
        self.successes as f64 / self.attempts as f64
    }
}

#[derive(Debug, Clone)]
pub struct TaggedPayloadEntry {
    pub payload: String,
    pub dictionary: PayloadDictionary,
    pub aggressiveness: PayloadAggressiveness,
    pub tags: Vec<String>,
}

/// Central manager for all fuzzing payload dictionaries.
///
/// Supports lazy loading so dictionaries are only materialized when accessed,
/// deduplication of payloads, custom payload import, tagging, and per-payload
/// success rate tracking.
pub struct DictionaryManager {
    loaded: HashSet<PayloadDictionary>,
    payloads: HashMap<PayloadDictionary, Vec<TaggedPayloadEntry>>,
    custom_payloads: Vec<TaggedPayloadEntry>,
    stats: HashMap<String, PayloadStats>,
    dedup_set: HashSet<String>,
}

impl DictionaryManager {
    pub fn new() -> Self {
        Self {
            loaded: HashSet::new(),
            payloads: HashMap::new(),
            custom_payloads: Vec::new(),
            stats: HashMap::new(),
            dedup_set: HashSet::new(),
        }
    }

    /// Ensure a dictionary is loaded. No-op if already loaded.
    pub fn load_dictionary(&mut self, dict: PayloadDictionary) {
        if self.loaded.contains(&dict) {
            return;
        }
        let entries = match dict {
            PayloadDictionary::Xss => self.load_xss(),
            PayloadDictionary::Sqli => self.load_sqli(),
            PayloadDictionary::Ssti => self.load_ssti(),
            PayloadDictionary::Ssrf => self.load_ssrf(),
            PayloadDictionary::CmdiV2 => self.load_cmdi_v2(),
        };
        for entry in &entries {
            self.dedup_set.insert(entry.payload.clone());
        }
        self.payloads.insert(dict, entries);
        self.loaded.insert(dict);
    }

    /// Check if a dictionary has been loaded.
    pub fn is_loaded(&self, dict: PayloadDictionary) -> bool {
        self.loaded.contains(&dict)
    }

    /// Number of loaded dictionaries.
    pub fn loaded_count(&self) -> usize {
        self.loaded.len()
    }

    /// Get all payloads from a loaded dictionary.
    pub fn get_payloads(&mut self, dict: PayloadDictionary) -> &[TaggedPayloadEntry] {
        self.load_dictionary(dict);
        self.payloads
            .get(&dict)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Total payload count across all loaded dictionaries plus custom payloads.
    pub fn total_payload_count(&self) -> usize {
        let lib_count: usize = self.payloads.values().map(|v| v.len()).sum();
        lib_count + self.custom_payloads.len()
    }

    /// Search payloads containing a substring (case-insensitive).
    pub fn search(
        &mut self,
        query: &str,
        dictionaries: &[PayloadDictionary],
    ) -> Vec<&TaggedPayloadEntry> {
        let lower = query.to_lowercase();
        for dict in dictionaries {
            self.load_dictionary(*dict);
        }
        let mut results = Vec::new();
        for dict in dictionaries {
            if let Some(entries) = self.payloads.get(dict) {
                for entry in entries {
                    if entry.payload.to_lowercase().contains(&lower)
                        || entry.tags.iter().any(|t| t.to_lowercase().contains(&lower))
                    {
                        results.push(entry);
                    }
                }
            }
        }
        for entry in &self.custom_payloads {
            if dictionaries.contains(&entry.dictionary)
                && (entry.payload.to_lowercase().contains(&lower)
                    || entry.tags.iter().any(|t| t.to_lowercase().contains(&lower)))
            {
                results.push(entry);
            }
        }
        results
    }

    /// Filter payloads by aggressiveness level.
    pub fn filter_by_aggressiveness(
        &mut self,
        dict: PayloadDictionary,
        level: PayloadAggressiveness,
    ) -> Vec<&TaggedPayloadEntry> {
        self.load_dictionary(dict);
        let mut results = Vec::new();
        if let Some(entries) = self.payloads.get(&dict) {
            for entry in entries {
                if entry.aggressiveness == level {
                    results.push(entry);
                }
            }
        }
        results
    }

    /// Import a custom payload with deduplication.
    pub fn import_custom_payload(
        &mut self,
        payload: String,
        dictionary: PayloadDictionary,
        aggressiveness: PayloadAggressiveness,
        tags: Vec<String>,
    ) -> bool {
        if self.dedup_set.contains(&payload) {
            return false;
        }
        self.dedup_set.insert(payload.clone());
        self.custom_payloads.push(TaggedPayloadEntry {
            payload,
            dictionary,
            aggressiveness,
            tags,
        });
        true
    }

    /// Bulk import with deduplication, returns count of newly added payloads.
    pub fn import_bulk(
        &mut self,
        payloads: Vec<String>,
        dictionary: PayloadDictionary,
        aggressiveness: PayloadAggressiveness,
        tags: Vec<String>,
    ) -> usize {
        let mut added = 0;
        for payload in payloads {
            if self.import_custom_payload(payload, dictionary, aggressiveness, tags.clone()) {
                added += 1;
            }
        }
        added
    }

    /// Record a payload attempt (success or failure) for statistics tracking.
    pub fn record_attempt(&mut self, payload: &str, success: bool) {
        let stats = self
            .stats
            .entry(payload.to_string())
            .or_insert(PayloadStats {
                attempts: 0,
                successes: 0,
            });
        stats.attempts += 1;
        if success {
            stats.successes += 1;
        }
    }

    /// Get stats for a specific payload.
    pub fn get_stats(&self, payload: &str) -> Option<&PayloadStats> {
        self.stats.get(payload)
    }

    /// Get top N payloads by success rate (minimum `min_attempts` to qualify).
    pub fn top_payloads(&self, n: usize, min_attempts: u64) -> Vec<(&str, f64)> {
        let mut rated: Vec<(&str, f64)> = self
            .stats
            .iter()
            .filter(|(_, s)| s.attempts >= min_attempts)
            .map(|(p, s)| (p.as_str(), s.success_rate()))
            .collect();
        rated.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        rated.truncate(n);
        rated
    }

    /// Count of custom payloads imported.
    pub fn custom_payload_count(&self) -> usize {
        self.custom_payloads.len()
    }

    /// Get all custom payloads.
    pub fn custom_payloads(&self) -> &[TaggedPayloadEntry] {
        &self.custom_payloads
    }

    // -----------------------------------------------------------------------
    // Private loader helpers
    // -----------------------------------------------------------------------

    fn classify_xss_aggressiveness(p: &XssPayload) -> PayloadAggressiveness {
        match p.category {
            XssCategory::Polyglot | XssCategory::MutationXss => PayloadAggressiveness::Aggressive,
            XssCategory::Reflected => {
                if p.payload.contains("script") {
                    PayloadAggressiveness::Normal
                } else {
                    PayloadAggressiveness::Stealth
                }
            }
            _ => PayloadAggressiveness::Normal,
        }
    }

    fn load_xss(&self) -> Vec<TaggedPayloadEntry> {
        xss_payloads::all_xss_payloads()
            .into_iter()
            .map(|p| TaggedPayloadEntry {
                payload: p.payload.to_string(),
                dictionary: PayloadDictionary::Xss,
                aggressiveness: Self::classify_xss_aggressiveness(p),
                tags: vec![
                    format!("{:?}", p.category),
                    format!("{:?}", p.context),
                    format!("{:?}", p.waf_bypass),
                ],
            })
            .collect()
    }

    fn load_sqli(&self) -> Vec<TaggedPayloadEntry> {
        sqli_payloads::all_sqli_payloads()
            .into_iter()
            .map(|p| {
                let aggressiveness = match p.category {
                    SqliCategory::BooleanBlind => PayloadAggressiveness::Stealth,
                    SqliCategory::StackedQuery | SqliCategory::OutOfBand => {
                        PayloadAggressiveness::Aggressive
                    }
                    _ => PayloadAggressiveness::Normal,
                };
                TaggedPayloadEntry {
                    payload: p.payload.to_string(),
                    dictionary: PayloadDictionary::Sqli,
                    aggressiveness,
                    tags: vec![
                        format!("{:?}", p.category),
                        format!("{:?}", p.dbms),
                        format!("{:?}", p.waf_bypass),
                    ],
                }
            })
            .collect()
    }

    fn load_ssti(&self) -> Vec<TaggedPayloadEntry> {
        ssti_payloads::all_ssti_payloads()
            .into_iter()
            .map(|p| {
                let aggressiveness = match p.phase {
                    ssti_payloads::SstiPhase::Detection
                    | ssti_payloads::SstiPhase::Identification => PayloadAggressiveness::Stealth,
                    ssti_payloads::SstiPhase::Rce => PayloadAggressiveness::Aggressive,
                    _ => PayloadAggressiveness::Normal,
                };
                TaggedPayloadEntry {
                    payload: p.payload.to_string(),
                    dictionary: PayloadDictionary::Ssti,
                    aggressiveness,
                    tags: vec![format!("{:?}", p.engine), format!("{:?}", p.phase)],
                }
            })
            .collect()
    }

    fn load_ssrf(&self) -> Vec<TaggedPayloadEntry> {
        ssrf_payloads::all_ssrf_payloads()
            .into_iter()
            .map(|p| {
                let aggressiveness = match p.category {
                    SsrfCategory::IpFormatBypass | SsrfCategory::DnsRebinding => {
                        PayloadAggressiveness::Stealth
                    }
                    SsrfCategory::ProtocolSmuggling => PayloadAggressiveness::Aggressive,
                    _ => PayloadAggressiveness::Normal,
                };
                TaggedPayloadEntry {
                    payload: p.payload.to_string(),
                    dictionary: PayloadDictionary::Ssrf,
                    aggressiveness,
                    tags: vec![
                        format!("{:?}", p.category),
                        p.cloud_provider
                            .map(|c| format!("{:?}", c))
                            .unwrap_or_else(|| "None".to_string()),
                    ],
                }
            })
            .collect()
    }

    fn load_cmdi_v2(&self) -> Vec<TaggedPayloadEntry> {
        cmdi_payloads_v2::all_cmdi_v2_payloads()
            .into_iter()
            .map(|p| {
                let aggressiveness = match p.technique {
                    CmdiTechnique::BlindTimeBased | CmdiTechnique::BlindDns => {
                        PayloadAggressiveness::Stealth
                    }
                    CmdiTechnique::InlineExecution => {
                        if p.payload.contains("reverse") || p.payload.contains("/dev/tcp") {
                            PayloadAggressiveness::Aggressive
                        } else {
                            PayloadAggressiveness::Normal
                        }
                    }
                    _ => PayloadAggressiveness::Normal,
                };
                TaggedPayloadEntry {
                    payload: p.payload.to_string(),
                    dictionary: PayloadDictionary::CmdiV2,
                    aggressiveness,
                    tags: vec![
                        format!("{:?}", p.os),
                        format!("{:?}", p.context),
                        format!("{:?}", p.technique),
                    ],
                }
            })
            .collect()
    }
}

impl Default for DictionaryManager {
    fn default() -> Self {
        Self::new()
    }
}
