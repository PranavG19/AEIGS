use std::collections::HashSet;

use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};

use crate::fingerprint_db::{BrowserFingerprintEntry, BrowserFamily, FingerprintDb, FingerprintId, OsFamily};

/// Trigger condition that causes a fingerprint rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RotationTrigger {
    BlockDetected,
    RateLimited,
    TimeInterval,
    SessionEnd,
    Manual,
}

/// Configuration for the fingerprint rotator.
#[derive(Debug, Clone)]
pub struct RotatorConfig {
    pub pool_size: usize,
    pub rotation_interval_secs: u64,
    pub anti_correlation_distance: usize,
    pub session_sticky: bool,
    pub preferred_browsers: Vec<BrowserFamily>,
    pub preferred_os: Vec<OsFamily>,
}

impl Default for RotatorConfig {
    fn default() -> Self {
        Self {
            pool_size: 100,
            rotation_interval_secs: 300,
            anti_correlation_distance: 3,
            session_sticky: true,
            preferred_browsers: Vec::new(),
            preferred_os: Vec::new(),
        }
    }
}

impl RotatorConfig {
    pub fn with_pool_size(mut self, size: usize) -> Self {
        self.pool_size = size;
        self
    }

    pub fn with_rotation_interval_secs(mut self, secs: u64) -> Self {
        self.rotation_interval_secs = secs;
        self
    }

    pub fn with_anti_correlation_distance(mut self, dist: usize) -> Self {
        self.anti_correlation_distance = dist;
        self
    }

    pub fn with_session_sticky(mut self, sticky: bool) -> Self {
        self.session_sticky = sticky;
        self
    }

    pub fn with_preferred_browsers(mut self, browsers: Vec<BrowserFamily>) -> Self {
        self.preferred_browsers = browsers;
        self
    }

    pub fn with_preferred_os(mut self, os_list: Vec<OsFamily>) -> Self {
        self.preferred_os = os_list;
        self
    }
}

/// A pre-generated browser identity drawn from the fingerprint database.
#[derive(Debug, Clone)]
pub struct IdentitySlot {
    pub slot_index: usize,
    pub fingerprint_id: FingerprintId,
    pub user_agent: String,
}

/// Rotates complete browser identities per-session or per-request.
///
/// Pre-generates an identity pool at startup from the JA4+ fingerprint database.
/// Ensures internal consistency (TLS + HTTP/2 + headers + navigator all match),
/// provides session-sticky identities for authenticated sessions, and enforces
/// anti-correlation so consecutive identities look like different humans.
pub struct FingerprintRotator {
    config: RotatorConfig,
    pool: Vec<IdentitySlot>,
    current_index: usize,
    recent_indices: Vec<usize>,
    rotation_count: u64,
    session_locked: bool,
    rng: StdRng,
}

impl FingerprintRotator {
    /// Creates a new rotator and pre-generates the identity pool from the database.
    pub fn new(config: RotatorConfig, db: &FingerprintDb) -> Self {
        let mut rotator = Self {
            config,
            pool: Vec::new(),
            current_index: 0,
            recent_indices: Vec::new(),
            rotation_count: 0,
            session_locked: false,
            rng: StdRng::from_os_rng(),
        };
        rotator.generate_pool(db);
        rotator
    }

    /// Creates a rotator with a deterministic seed for testing.
    pub fn with_seed(config: RotatorConfig, db: &FingerprintDb, seed: u64) -> Self {
        let mut rotator = Self {
            config,
            pool: Vec::new(),
            current_index: 0,
            recent_indices: Vec::new(),
            rotation_count: 0,
            session_locked: false,
            rng: StdRng::seed_from_u64(seed),
        };
        rotator.generate_pool(db);
        rotator
    }

    /// Returns the current active identity.
    pub fn current_identity(&self) -> Option<&IdentitySlot> {
        self.pool.get(self.current_index)
    }

    /// Returns the full identity pool.
    pub fn pool(&self) -> &[IdentitySlot] {
        &self.pool
    }

    /// Returns the number of identities in the pool.
    pub fn pool_size(&self) -> usize {
        self.pool.len()
    }

    /// Returns the total number of rotations performed.
    pub fn rotation_count(&self) -> u64 {
        self.rotation_count
    }

    /// Looks up the full fingerprint entry for the current identity.
    pub fn current_fingerprint<'a>(&self, db: &'a FingerprintDb) -> Option<&'a BrowserFingerprintEntry> {
        self.current_identity().and_then(|slot| db.get(&slot.fingerprint_id))
    }

    /// Rotates to a new identity, enforcing anti-correlation constraints.
    /// Returns the newly selected identity slot.
    pub fn rotate(&mut self, _trigger: RotationTrigger) -> Option<&IdentitySlot> {
        if self.session_locked && _trigger != RotationTrigger::SessionEnd {
            return self.pool.get(self.current_index);
        }

        if self.pool.is_empty() {
            return None;
        }

        let excluded: HashSet<usize> = self.recent_indices.iter().copied().collect();
        let candidates: Vec<usize> = (0..self.pool.len())
            .filter(|i| !excluded.contains(i))
            .collect();

        let new_index = if candidates.is_empty() {
            self.rng.random_range(0..self.pool.len())
        } else {
            candidates[self.rng.random_range(0..candidates.len())]
        };

        self.recent_indices.push(self.current_index);
        if self.recent_indices.len() > self.config.anti_correlation_distance {
            self.recent_indices.remove(0);
        }

        self.current_index = new_index;
        self.rotation_count += 1;

        if _trigger == RotationTrigger::SessionEnd {
            self.session_locked = false;
        }

        self.pool.get(self.current_index)
    }

    /// Locks the current identity for an authenticated session.
    pub fn lock_session(&mut self) {
        if self.config.session_sticky {
            self.session_locked = true;
        }
    }

    /// Unlocks the session, allowing rotation again.
    pub fn unlock_session(&mut self) {
        self.session_locked = false;
    }

    /// Returns whether the rotator is currently session-locked.
    pub fn is_session_locked(&self) -> bool {
        self.session_locked
    }

    fn generate_pool(&mut self, db: &FingerprintDb) {
        let all_entries = db.all();
        if all_entries.is_empty() {
            return;
        }

        let filtered: Vec<&BrowserFingerprintEntry> = all_entries.iter()
            .filter(|e| {
                let browser_ok = self.config.preferred_browsers.is_empty()
                    || self.config.preferred_browsers.contains(&e.id.browser);
                let os_ok = self.config.preferred_os.is_empty()
                    || self.config.preferred_os.contains(&e.id.os);
                browser_ok && os_ok
            })
            .collect();

        let source = if filtered.is_empty() { all_entries } else { &filtered.iter().map(|e| (*e).clone()).collect::<Vec<_>>() };

        let target_size = self.config.pool_size;
        for i in 0..target_size {
            let entry = &source[self.rng.random_range(0..source.len())];
            self.pool.push(IdentitySlot {
                slot_index: i,
                fingerprint_id: entry.id.clone(),
                user_agent: entry.user_agent.clone(),
            });
        }
    }
}

#[cfg(test)]
#[path = "fingerprint_rotator_test.rs"]
mod fingerprint_rotator_test;
