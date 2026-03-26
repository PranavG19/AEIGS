use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::PersonaId;

/// Session compartmentalization for cross-session correlation resistance.
///
/// Each scan session gets a completely isolated identity: unique persona rotation,
/// fresh cookies, independent fingerprints, and no shared state. Prevents
/// defenders from correlating activity across sessions.

/// Unique session identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionIdentity {
    pub session_id: String,
    pub persona: PersonaId,
    pub fingerprint_seed: u64,
    pub cookie_jar_id: String,
    pub tls_session_id: Vec<u8>,
    pub created_at_ms: u64,
    pub max_duration_ms: u64,
}

/// Session isolation guarantees.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationReport {
    pub session_id: String,
    pub cookies_isolated: bool,
    pub fingerprint_unique: bool,
    pub tls_session_unique: bool,
    pub no_shared_state: bool,
    pub correlation_resistance_score: f64,
}

/// Configuration for session compartmentalization.
#[derive(Debug, Clone)]
pub struct SessionCompartmentConfig {
    pub max_session_duration_ms: u64,
    pub rotate_persona_per_session: bool,
    pub isolate_cookies: bool,
    pub isolate_tls_sessions: bool,
    pub isolate_local_storage: bool,
    pub clear_dns_cache_per_session: bool,
}

impl Default for SessionCompartmentConfig {
    fn default() -> Self {
        Self {
            max_session_duration_ms: 300_000,
            rotate_persona_per_session: true,
            isolate_cookies: true,
            isolate_tls_sessions: true,
            isolate_local_storage: true,
            clear_dns_cache_per_session: true,
        }
    }
}

/// Available personas for rotation (excluding bot identities).
const ROTATABLE_PERSONAS: &[PersonaId] = &[
    PersonaId::ChromeDesktop,
    PersonaId::FirefoxDesktop,
    PersonaId::SafariDesktop,
    PersonaId::ChromeMobile,
    PersonaId::EdgeDesktop,
    PersonaId::OperaDesktop,
    PersonaId::SafariMobile,
];

/// Session compartment manager.
pub struct SessionCompartment {
    config: SessionCompartmentConfig,
    active_sessions: Vec<SessionIdentity>,
    used_session_ids: HashSet<String>,
    used_seeds: HashSet<u64>,
    rng_state: u64,
    session_counter: u64,
}

impl SessionCompartment {
    pub fn new(config: SessionCompartmentConfig) -> Self {
        Self {
            config,
            active_sessions: Vec::new(),
            used_session_ids: HashSet::new(),
            used_seeds: HashSet::new(),
            rng_state: 0xfeedface12345678,
            session_counter: 0,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(SessionCompartmentConfig::default())
    }

    /// Create a new isolated session with a fresh identity.
    pub fn create_session(&mut self) -> SessionIdentity {
        self.session_counter += 1;
        self.rng_state = xorshift64(self.rng_state);

        let session_id = format!("sess-{:016x}", self.rng_state);

        let persona = if self.config.rotate_persona_per_session {
            let idx = (self.rng_state as usize) % ROTATABLE_PERSONAS.len();
            ROTATABLE_PERSONAS[idx]
        } else {
            PersonaId::ChromeDesktop
        };

        self.rng_state = xorshift64(self.rng_state);
        let mut fingerprint_seed = self.rng_state;
        while self.used_seeds.contains(&fingerprint_seed) {
            self.rng_state = xorshift64(self.rng_state);
            fingerprint_seed = self.rng_state;
        }
        self.used_seeds.insert(fingerprint_seed);

        self.rng_state = xorshift64(self.rng_state);
        let cookie_jar_id = format!("jar-{:016x}", self.rng_state);

        self.rng_state = xorshift64(self.rng_state);
        let tls_session_id: Vec<u8> = (0..32)
            .map(|i| ((self.rng_state.wrapping_add(i as u64)) & 0xFF) as u8)
            .collect();

        let identity = SessionIdentity {
            session_id: session_id.clone(),
            persona,
            fingerprint_seed,
            cookie_jar_id,
            tls_session_id,
            created_at_ms: self.session_counter * 1000,
            max_duration_ms: self.config.max_session_duration_ms,
        };

        self.used_session_ids.insert(session_id);
        self.active_sessions.push(identity.clone());
        identity
    }

    /// Destroy a session and wipe all associated state.
    pub fn destroy_session(&mut self, session_id: &str) -> bool {
        let before = self.active_sessions.len();
        self.active_sessions.retain(|s| s.session_id != session_id);
        self.active_sessions.len() < before
    }

    /// Verify isolation guarantees for a session.
    pub fn verify_isolation(&self, session_id: &str) -> Option<IsolationReport> {
        let session = self
            .active_sessions
            .iter()
            .find(|s| s.session_id == session_id)?;

        let fingerprint_unique = self
            .active_sessions
            .iter()
            .filter(|s| s.session_id != session_id)
            .all(|s| s.fingerprint_seed != session.fingerprint_seed);

        let tls_unique = self
            .active_sessions
            .iter()
            .filter(|s| s.session_id != session_id)
            .all(|s| s.tls_session_id != session.tls_session_id);

        let cookies_isolated = self
            .active_sessions
            .iter()
            .filter(|s| s.session_id != session_id)
            .all(|s| s.cookie_jar_id != session.cookie_jar_id);

        let no_shared_state = fingerprint_unique && tls_unique && cookies_isolated;

        let score = [
            if cookies_isolated { 0.25 } else { 0.0 },
            if fingerprint_unique { 0.25 } else { 0.0 },
            if tls_unique { 0.25 } else { 0.0 },
            if self.config.clear_dns_cache_per_session {
                0.15
            } else {
                0.0
            },
            if self.config.isolate_local_storage {
                0.10
            } else {
                0.0
            },
        ]
        .iter()
        .sum();

        Some(IsolationReport {
            session_id: session_id.to_string(),
            cookies_isolated,
            fingerprint_unique,
            tls_session_unique: tls_unique,
            no_shared_state,
            correlation_resistance_score: score,
        })
    }

    /// Number of active sessions.
    pub fn active_count(&self) -> usize {
        self.active_sessions.len()
    }

    /// Total sessions created (including destroyed).
    pub fn total_created(&self) -> u64 {
        self.session_counter
    }

    /// Check if any sessions have exceeded their max duration.
    pub fn expired_sessions(&self, current_time_ms: u64) -> Vec<String> {
        self.active_sessions
            .iter()
            .filter(|s| current_time_ms > s.created_at_ms + s.max_duration_ms)
            .map(|s| s.session_id.clone())
            .collect()
    }

    /// Destroy all active sessions.
    pub fn destroy_all(&mut self) {
        self.active_sessions.clear();
    }
}

fn xorshift64(mut state: u64) -> u64 {
    if state == 0 {
        state = 0xdeadbeefcafe1234;
    }
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    state
}
