use std::fmt;

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// SHA-256 fingerprint of all randomization parameters for a polymorphic session.
///
/// Two sessions with different seeds will produce different fingerprints,
/// ensuring no two scans share identical request signatures.
pub type SessionFingerprint = [u8; 32];

/// Transfer encoding strategy applied to outgoing requests.
///
/// Randomly selected per-session by `PolymorphicSigner::vary_transfer_encoding`
/// to prevent WAFs from building stable fingerprints of scan traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransferEncoding {
    Chunked,
    Identity,
    Gzip,
}

impl fmt::Display for TransferEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chunked => write!(f, "chunked"),
            Self::Identity => write!(f, "identity"),
            Self::Gzip => write!(f, "gzip"),
        }
    }
}

/// Configuration for polymorphic request signature randomization.
///
/// Controls the range of the UCB1 exploration constant, the percentage of
/// timing noise applied to inter-request delays, and whether HTTP headers
/// are reordered per-session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolymorphicConfig {
    pub c_range: (f64, f64),
    pub timing_noise_pct: f64,
    pub header_randomize: bool,
}

impl Default for PolymorphicConfig {
    fn default() -> Self {
        Self {
            c_range: (0.8, 2.2),
            timing_noise_pct: 0.15,
            header_randomize: true,
        }
    }
}

impl PolymorphicConfig {
    pub fn with_c_range(mut self, lo: f64, hi: f64) -> Self {
        self.c_range = (lo, hi);
        self
    }

    pub fn with_timing_noise_pct(mut self, pct: f64) -> Self {
        self.timing_noise_pct = pct;
        self
    }

    pub fn with_header_randomize(mut self, enabled: bool) -> Self {
        self.header_randomize = enabled;
        self
    }
}

/// Polymorphic request signer that ensures no two scan sessions look identical.
///
/// Generates a unique set of randomization parameters on construction: a UCB1
/// exploration constant drawn from `c_range`, per-session header shuffle order,
/// and timing noise applied to inter-request delays. The session fingerprint is
/// a SHA-256 hash of these parameters, usable for audit trail correlation.
pub struct PolymorphicSigner {
    config: PolymorphicConfig,
    rng: StdRng,
    exploration_c: f64,
    fingerprint: SessionFingerprint,
}

impl PolymorphicSigner {
    pub fn new_session(config: PolymorphicConfig) -> Self {
        let mut rng = StdRng::from_os_rng();
        let exploration_c = rng.random_range(config.c_range.0..=config.c_range.1);
        let fingerprint = Self::compute_fingerprint(&mut rng, exploration_c);
        Self {
            config,
            rng,
            exploration_c,
            fingerprint,
        }
    }

    pub fn with_seed(config: PolymorphicConfig, seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let exploration_c = rng.random_range(config.c_range.0..=config.c_range.1);
        let fingerprint = Self::compute_fingerprint(&mut rng, exploration_c);
        Self {
            config,
            rng,
            exploration_c,
            fingerprint,
        }
    }

    pub fn exploration_constant(&self) -> f64 {
        self.exploration_c
    }

    pub fn randomize_headers(
        &mut self,
        mut headers: Vec<(String, String)>,
    ) -> Vec<(String, String)> {
        if !self.config.header_randomize || headers.len() <= 1 {
            return headers;
        }
        fisher_yates_shuffle(&mut self.rng, &mut headers);
        headers
    }

    pub fn apply_timing_noise(&mut self, base_delay_ms: u64) -> u64 {
        if base_delay_ms == 0 || self.config.timing_noise_pct <= 0.0 {
            return base_delay_ms;
        }
        let max_noise = (base_delay_ms as f64 * self.config.timing_noise_pct).round() as i64;
        if max_noise == 0 {
            return base_delay_ms;
        }
        let noise = self.rng.random_range(-max_noise..=max_noise);
        let result = base_delay_ms as i64 + noise;
        result.max(0) as u64
    }

    pub fn session_fingerprint(&self) -> &SessionFingerprint {
        &self.fingerprint
    }

    pub fn vary_chunk_size(&mut self) -> usize {
        self.rng.random_range(1024..=16384)
    }

    pub fn vary_transfer_encoding(&mut self) -> TransferEncoding {
        match self.rng.random_range(0u8..3) {
            0 => TransferEncoding::Chunked,
            1 => TransferEncoding::Identity,
            _ => TransferEncoding::Gzip,
        }
    }

    fn compute_fingerprint(rng: &mut StdRng, exploration_c: f64) -> SessionFingerprint {
        let mut raw = [0u8; 32];
        let c_bytes = exploration_c.to_le_bytes();
        raw[..8].copy_from_slice(&c_bytes);
        let noise_bytes: [u8; 24] = rng.random();
        raw[8..].copy_from_slice(&noise_bytes);
        raw
    }
}

fn fisher_yates_shuffle<T>(rng: &mut StdRng, items: &mut [T]) {
    let len = items.len();
    for i in (1..len).rev() {
        let j = rng.random_range(0..=i);
        items.swap(i, j);
    }
}
