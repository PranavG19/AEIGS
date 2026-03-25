use std::collections::{HashMap, VecDeque};
use std::time::Instant;

const MIN_PER_CONTEXT: usize = 1;
const MAX_PER_CONTEXT: usize = 100_000;
const MIN_TOTAL: usize = 1;
const MAX_TOTAL: usize = 1_000_000;
const DEFAULT_PER_CONTEXT: usize = 1000;
const DEFAULT_TOTAL: usize = 10_000;

/// Configuration for the payload cache.
///
/// Controls per-context and total entry limits, plus optional statistics
/// tracking. All sizes are clamped to safe bounds on construction.
#[derive(Debug, Clone)]
pub struct PayloadCacheConfig {
    pub max_entries_per_context: usize,
    pub max_total_entries: usize,
    pub enable_stats: bool,
}

impl Default for PayloadCacheConfig {
    fn default() -> Self {
        Self {
            max_entries_per_context: DEFAULT_PER_CONTEXT,
            max_total_entries: DEFAULT_TOTAL,
            enable_stats: true,
        }
    }
}

impl PayloadCacheConfig {
    pub fn with_max_entries_per_context(mut self, n: usize) -> Self {
        self.max_entries_per_context = n.clamp(MIN_PER_CONTEXT, MAX_PER_CONTEXT);
        self
    }

    pub fn with_max_total_entries(mut self, n: usize) -> Self {
        self.max_total_entries = n.clamp(MIN_TOTAL, MAX_TOTAL);
        self
    }

    pub fn with_stats_enabled(mut self, enabled: bool) -> Self {
        self.enable_stats = enabled;
        self
    }
}

/// A cached payload entry with access tracking metadata.
#[derive(Debug, Clone)]
pub struct CachedPayload {
    pub payload: String,
    pub context: String,
    pub created_at: Instant,
    pub last_accessed: Instant,
    pub access_count: u64,
}

/// Aggregate statistics for cache operations.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub total_hits: u64,
    pub total_misses: u64,
    pub total_evictions: u64,
    pub total_entries: usize,
    pub contexts_tracked: usize,
    pub per_context_counts: HashMap<String, usize>,
}

struct ContextCache {
    entries: HashMap<String, CachedPayload>,
    lru_order: VecDeque<String>,
    max_entries: usize,
}

impl ContextCache {
    fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            lru_order: VecDeque::new(),
            max_entries,
        }
    }

    fn touch(&mut self, payload: &str) {
        self.lru_order.retain(|p| p != payload);
        self.lru_order.push_back(payload.to_string());
    }

    fn evict_lru(&mut self) -> Option<String> {
        let evicted = self.lru_order.pop_front()?;
        self.entries.remove(&evicted);
        Some(evicted)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn contains(&self, payload: &str) -> bool {
        self.entries.contains_key(payload)
    }

    fn remove(&mut self, payload: &str) -> bool {
        if self.entries.remove(payload).is_some() {
            self.lru_order.retain(|p| p != payload);
            true
        } else {
            false
        }
    }
}

/// LRU payload cache with per-context isolation and lazy generation support.
///
/// Payloads are keyed by a string context (typically derived from
/// `VulnerabilityClass::to_string()`). Each context maintains its own LRU
/// eviction queue bounded by `max_entries_per_context`. A global cap
/// `max_total_entries` triggers cross-context eviction of the oldest entry
/// when the combined size exceeds the limit.
pub struct PayloadCache {
    config: PayloadCacheConfig,
    contexts: HashMap<String, ContextCache>,
    stats: CacheStats,
    lazy_generators: HashMap<String, Box<dyn Fn() -> Vec<String>>>,
}

impl PayloadCache {
    pub fn new(config: PayloadCacheConfig) -> Self {
        Self {
            config,
            contexts: HashMap::new(),
            stats: CacheStats::default(),
            lazy_generators: HashMap::new(),
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(PayloadCacheConfig::default())
    }

    /// Retrieves a cached payload, updating LRU order and access metadata.
    ///
    /// Returns `None` and increments `total_misses` if the payload is not
    /// present in the given context.
    pub fn get(&mut self, context: &str, payload: &str) -> Option<&CachedPayload> {
        let ctx = self.contexts.get_mut(context);
        match ctx {
            Some(ctx) if ctx.contains(payload) => {
                ctx.touch(payload);
                let entry = ctx.entries.get_mut(payload).unwrap();
                entry.last_accessed = Instant::now();
                entry.access_count += 1;
                if self.config.enable_stats {
                    self.stats.total_hits += 1;
                }
                let ctx_ref = self.contexts.get(context).unwrap();
                ctx_ref.entries.get(payload)
            }
            _ => {
                if self.config.enable_stats {
                    self.stats.total_misses += 1;
                }
                None
            }
        }
    }

    /// Inserts a payload into the cache under the given context.
    ///
    /// Returns `true` if the payload was newly inserted, `false` if it already
    /// existed (existing entries are touched but not duplicated). Triggers LRU
    /// eviction when per-context or total limits are reached.
    pub fn insert(&mut self, context: &str, payload: String) -> bool {
        let max_per = self.config.max_entries_per_context;
        let ctx = self
            .contexts
            .entry(context.to_string())
            .or_insert_with(|| ContextCache::new(max_per));

        if ctx.contains(&payload) {
            ctx.touch(&payload);
            return false;
        }

        self.evict_if_context_full(context);
        self.evict_if_total_full(context);

        let now = Instant::now();
        let entry = CachedPayload {
            payload: payload.clone(),
            context: context.to_string(),
            created_at: now,
            last_accessed: now,
            access_count: 0,
        };

        let ctx = self.contexts.get_mut(context).unwrap();
        ctx.entries.insert(payload.clone(), entry);
        ctx.lru_order.push_back(payload);
        self.refresh_stats_counts();
        true
    }

    /// Removes a specific payload from a context.
    ///
    /// Returns `true` if the payload was found and removed.
    pub fn remove(&mut self, context: &str, payload: &str) -> bool {
        let removed = self
            .contexts
            .get_mut(context)
            .map(|ctx| ctx.remove(payload))
            .unwrap_or(false);
        if removed {
            self.refresh_stats_counts();
        }
        removed
    }

    /// Checks whether a payload exists in the given context without
    /// updating LRU order or statistics.
    pub fn contains(&self, context: &str, payload: &str) -> bool {
        self.contexts
            .get(context)
            .map(|ctx| ctx.contains(payload))
            .unwrap_or(false)
    }

    /// Bulk-inserts payloads from a dictionary into the given context.
    ///
    /// Returns the number of payloads actually inserted (duplicates and
    /// entries beyond the per-context limit are skipped).
    pub fn warm_from_dictionary(&mut self, context: &str, payloads: Vec<String>) -> usize {
        let mut inserted = 0;
        for payload in payloads {
            if self.insert(context, payload) {
                inserted += 1;
            }
        }
        inserted
    }

    /// Returns all payload strings currently cached for a context.
    pub fn get_all_for_context(&self, context: &str) -> Vec<&str> {
        self.contexts
            .get(context)
            .map(|ctx| ctx.lru_order.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    /// Removes all entries for a context, returning the count removed.
    pub fn clear_context(&mut self, context: &str) -> usize {
        let removed = self
            .contexts
            .remove(context)
            .map(|ctx| ctx.len())
            .unwrap_or(0);
        self.refresh_stats_counts();
        removed
    }

    /// Removes all entries from every context.
    pub fn clear_all(&mut self) {
        self.contexts.clear();
        self.refresh_stats_counts();
    }

    /// Registers a lazy generator for a context.
    ///
    /// The generator is invoked by `get_or_generate` only when the context
    /// has no cached entries. Replaces any previously registered generator
    /// for the same context.
    pub fn register_generator(&mut self, context: &str, generator: Box<dyn Fn() -> Vec<String>>) {
        self.lazy_generators.insert(context.to_string(), generator);
    }

    /// Returns cached payloads for a context, invoking the registered
    /// generator to populate the cache if empty.
    ///
    /// If no generator is registered and the context is empty, returns
    /// an empty vec.
    pub fn get_or_generate(&mut self, context: &str) -> Vec<String> {
        let has_entries = self
            .contexts
            .get(context)
            .map(|ctx| !ctx.entries.is_empty())
            .unwrap_or(false);

        if !has_entries && let Some(generator) = self.lazy_generators.remove(context) {
            let payloads = generator();
            self.warm_from_dictionary(context, payloads);
            self.lazy_generators.insert(context.to_string(), generator);
        }

        self.get_all_for_context(context)
            .into_iter()
            .map(|s| s.to_string())
            .collect()
    }

    /// Returns a reference to the current cache statistics.
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }

    /// Resets hit, miss, and eviction counters to zero.
    pub fn reset_stats(&mut self) {
        self.stats.total_hits = 0;
        self.stats.total_misses = 0;
        self.stats.total_evictions = 0;
    }

    /// Returns the number of payloads cached for a specific context.
    pub fn context_count(&self, context: &str) -> usize {
        self.contexts.get(context).map(|ctx| ctx.len()).unwrap_or(0)
    }

    /// Returns the total number of cached payloads across all contexts.
    pub fn total_entries(&self) -> usize {
        self.contexts.values().map(|ctx| ctx.len()).sum()
    }

    /// Returns the list of context names that have cached entries.
    pub fn contexts(&self) -> Vec<&str> {
        self.contexts.keys().map(|s| s.as_str()).collect()
    }

    fn evict_if_context_full(&mut self, context: &str) {
        let ctx = match self.contexts.get_mut(context) {
            Some(ctx) => ctx,
            None => return,
        };
        while ctx.len() >= ctx.max_entries {
            if ctx.evict_lru().is_some() && self.config.enable_stats {
                self.stats.total_evictions += 1;
            }
        }
    }

    fn evict_if_total_full(&mut self, skip_context: &str) {
        while self.total_entries() >= self.config.max_total_entries {
            if !self.evict_globally(skip_context) {
                break;
            }
        }
    }

    fn evict_globally(&mut self, prefer_other_than: &str) -> bool {
        let target = self.pick_eviction_target(prefer_other_than);
        match target {
            Some(ctx_key) => {
                let ctx = self.contexts.get_mut(&ctx_key).unwrap();
                let evicted = ctx.evict_lru().is_some();
                if evicted && self.config.enable_stats {
                    self.stats.total_evictions += 1;
                }
                evicted
            }
            None => false,
        }
    }

    fn pick_eviction_target(&self, prefer_other_than: &str) -> Option<String> {
        let mut best: Option<(&str, usize)> = None;
        for (key, ctx) in &self.contexts {
            if ctx.entries.is_empty() {
                continue;
            }
            if key == prefer_other_than {
                continue;
            }
            match best {
                None => best = Some((key, ctx.len())),
                Some((_, best_len)) if ctx.len() > best_len => {
                    best = Some((key, ctx.len()));
                }
                _ => {}
            }
        }
        if best.is_none() {
            for (key, ctx) in &self.contexts {
                if !ctx.entries.is_empty() {
                    return Some(key.clone());
                }
            }
        }
        best.map(|(k, _)| k.to_string())
    }

    fn refresh_stats_counts(&mut self) {
        self.stats.total_entries = self.total_entries();
        self.stats.contexts_tracked = self.contexts.len();
        self.stats.per_context_counts.clear();
        for (key, ctx) in &self.contexts {
            self.stats.per_context_counts.insert(key.clone(), ctx.len());
        }
    }
}
