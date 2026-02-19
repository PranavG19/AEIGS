use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StealthConfig {
    pub max_requests_per_second: f64,
    pub jitter_range_ms: (u64, u64),
    pub min_delay_ms: u64,
    pub max_delay_ms: u64,
    pub session_rotation_interval: u64,
    pub prefer_blind_payloads: bool,
    pub avoid_signature_payloads: bool,
}

impl StealthConfig {
    pub fn benchmark() -> Self {
        Self {
            max_requests_per_second: f64::MAX,
            jitter_range_ms: (0, 0),
            min_delay_ms: 0,
            max_delay_ms: 0,
            session_rotation_interval: 0,
            prefer_blind_payloads: false,
            avoid_signature_payloads: false,
        }
    }

    pub fn aggressive() -> Self {
        Self {
            max_requests_per_second: 50.0,
            jitter_range_ms: (0, 50),
            min_delay_ms: 0,
            max_delay_ms: 100,
            session_rotation_interval: 0,
            prefer_blind_payloads: false,
            avoid_signature_payloads: false,
        }
    }

    pub fn paranoid() -> Self {
        Self {
            max_requests_per_second: 2.0,
            jitter_range_ms: (500, 2000),
            min_delay_ms: 500,
            max_delay_ms: 5000,
            session_rotation_interval: 20,
            prefer_blind_payloads: true,
            avoid_signature_payloads: true,
        }
    }

    pub fn with_max_requests_per_second(mut self, value: f64) -> Self {
        self.max_requests_per_second = value;
        self
    }

    pub fn with_jitter_range_ms(mut self, min: u64, max: u64) -> Self {
        self.jitter_range_ms = (min, max);
        self
    }

    pub fn with_min_delay_ms(mut self, value: u64) -> Self {
        self.min_delay_ms = value;
        self
    }

    pub fn with_max_delay_ms(mut self, value: u64) -> Self {
        self.max_delay_ms = value;
        self
    }

    pub fn with_session_rotation_interval(mut self, value: u64) -> Self {
        self.session_rotation_interval = value;
        self
    }

    pub fn with_prefer_blind_payloads(mut self, value: bool) -> Self {
        self.prefer_blind_payloads = value;
        self
    }

    pub fn with_avoid_signature_payloads(mut self, value: bool) -> Self {
        self.avoid_signature_payloads = value;
        self
    }
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            max_requests_per_second: 10.0,
            jitter_range_ms: (50, 200),
            min_delay_ms: 50,
            max_delay_ms: 500,
            session_rotation_interval: 100,
            prefer_blind_payloads: false,
            avoid_signature_payloads: false,
        }
    }
}
