use std::collections::{HashMap, HashSet};
use std::fmt;

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// Browser fingerprint components for identity rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserFingerprint {
    pub user_agent: String,
    pub accept_language: String,
    pub platform: String,
    pub screen_resolution: (u32, u32),
    pub color_depth: u8,
    pub timezone_offset: i16,
    pub webgl_renderer: String,
    pub canvas_hash: String,
    pub installed_fonts: Vec<String>,
    pub do_not_track: bool,
}

/// Network identity layer for proxy/VPN/Tor rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkIdentityType {
    DirectProxy,
    VpnTunnel,
    TorCircuit,
    ResidentialProxy,
    MobileProxy,
}

impl fmt::Display for NetworkIdentityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectProxy => write!(f, "proxy"),
            Self::VpnTunnel => write!(f, "vpn"),
            Self::TorCircuit => write!(f, "tor"),
            Self::ResidentialProxy => write!(f, "residential"),
            Self::MobileProxy => write!(f, "mobile"),
        }
    }
}

/// Network identity details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIdentity {
    pub identity_type: NetworkIdentityType,
    pub exit_ip_hint: String,
    pub geo_region: String,
}

/// Application-level session identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationIdentity {
    pub session_token: String,
    pub cookies: HashMap<String, String>,
    pub api_key: Option<String>,
    pub csrf_token: Option<String>,
}

/// Behavioral browsing pattern for identity differentiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BrowsingBehavior {
    CasualBrowser,
    PowerUser,
    MobileUser,
    ApiClient,
    SearchCrawler,
}

impl fmt::Display for BrowsingBehavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CasualBrowser => write!(f, "casual"),
            Self::PowerUser => write!(f, "power-user"),
            Self::MobileUser => write!(f, "mobile"),
            Self::ApiClient => write!(f, "api-client"),
            Self::SearchCrawler => write!(f, "crawler"),
        }
    }
}

/// Behavioral identity parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralIdentity {
    pub pattern: BrowsingBehavior,
    pub mean_delay_ms: u64,
    pub click_variance: f64,
    pub scroll_depth_pct: f64,
    pub tab_switches: bool,
}

/// Identity lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdentityState {
    Created,
    Active,
    Rotating,
    Destroyed,
}

impl fmt::Display for IdentityState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Active => write!(f, "active"),
            Self::Rotating => write!(f, "rotating"),
            Self::Destroyed => write!(f, "destroyed"),
        }
    }
}

/// A complete identity stack combining browser, network, application, and behavioral layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityStack {
    pub id: u64,
    pub browser: BrowserFingerprint,
    pub network: NetworkIdentity,
    pub application: ApplicationIdentity,
    pub behavior: BehavioralIdentity,
    pub state: IdentityState,
    pub correlation_tag: String,
}

impl IdentityStack {
    /// Returns a unique fingerprint hash combining all identity layers.
    pub fn fingerprint_hash(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.browser.canvas_hash,
            self.network.exit_ip_hint,
            self.application.session_token,
            self.behavior.pattern
        )
    }
}

/// Correlation check result between two identities.
#[derive(Debug, Clone)]
pub struct CorrelationCheck {
    pub id_a: u64,
    pub id_b: u64,
    pub shared_features: Vec<String>,
    pub correlation_score: f64,
    pub safe: bool,
}

/// Configuration for the identity rotation engine.
#[derive(Debug, Clone)]
pub struct IdentityRotationConfig {
    pub pool_size: usize,
    pub max_uses_per_identity: u32,
    pub rotation_on_detection: bool,
    pub correlation_threshold: f64,
    pub destroy_on_rotate: bool,
}

impl Default for IdentityRotationConfig {
    fn default() -> Self {
        Self {
            pool_size: 10,
            max_uses_per_identity: 50,
            rotation_on_detection: true,
            correlation_threshold: 0.3,
            destroy_on_rotate: true,
        }
    }
}

impl IdentityRotationConfig {
    pub fn with_pool_size(mut self, size: usize) -> Self {
        self.pool_size = size;
        self
    }

    pub fn with_max_uses(mut self, max: u32) -> Self {
        self.max_uses_per_identity = max;
        self
    }

    pub fn with_correlation_threshold(mut self, threshold: f64) -> Self {
        self.correlation_threshold = threshold;
        self
    }
}

/// Pre-generated browser fingerprint templates.
const UA_TEMPLATES: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 Safari/605.1.15",
];

const PLATFORMS: &[&str] = &[
    "Win32",
    "MacIntel",
    "Linux x86_64",
    "iPhone",
    "Linux armv81",
];
const LANGUAGES: &[&str] = &[
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "de-DE,de;q=0.9,en;q=0.5",
    "fr-FR,fr;q=0.9",
    "ja-JP,ja;q=0.9",
];
const RESOLUTIONS: &[(u32, u32)] = &[
    (1920, 1080),
    (2560, 1440),
    (1366, 768),
    (1440, 900),
    (390, 844),
    (375, 812),
];
const WEBGL_RENDERERS: &[&str] = &[
    "ANGLE (Intel, Mesa Intel(R) UHD Graphics 630)",
    "ANGLE (NVIDIA GeForce RTX 3060)",
    "Apple GPU",
    "ANGLE (AMD Radeon RX 580)",
    "Mali-G78",
];
const GEO_REGIONS: &[&str] = &[
    "US-East",
    "US-West",
    "EU-West",
    "EU-Central",
    "APAC-East",
    "SA-East",
];

/// Identity rotation engine that manages a pool of complete identity stacks,
/// rotates them on detection or schedule, and ensures no two identities
/// share detectable features.
pub struct IdentityRotationEngine {
    config: IdentityRotationConfig,
    rng: StdRng,
    identities: Vec<IdentityStack>,
    use_counts: HashMap<u64, u32>,
    active_id: Option<u64>,
    next_id: u64,
    destroyed_ids: HashSet<u64>,
}

impl IdentityRotationEngine {
    pub fn new(config: IdentityRotationConfig) -> Self {
        Self {
            config,
            rng: StdRng::from_os_rng(),
            identities: Vec::new(),
            use_counts: HashMap::new(),
            active_id: None,
            next_id: 1,
            destroyed_ids: HashSet::new(),
        }
    }

    pub fn with_seed(config: IdentityRotationConfig, seed: u64) -> Self {
        Self {
            config,
            rng: StdRng::seed_from_u64(seed),
            identities: Vec::new(),
            use_counts: HashMap::new(),
            active_id: None,
            next_id: 1,
            destroyed_ids: HashSet::new(),
        }
    }

    /// Pre-generates a pool of identities for instant rotation.
    pub fn generate_pool(&mut self) {
        let count = self.config.pool_size;
        for _ in 0..count {
            let identity = self.create_identity();
            self.identities.push(identity);
        }
    }

    /// Creates a single new identity with randomized components.
    fn create_identity(&mut self) -> IdentityStack {
        let id = self.next_id;
        self.next_id += 1;

        let ua_idx = self.rng.random_range(0..UA_TEMPLATES.len());
        let platform_idx = self.rng.random_range(0..PLATFORMS.len());
        let lang_idx = self.rng.random_range(0..LANGUAGES.len());
        let res_idx = self.rng.random_range(0..RESOLUTIONS.len());
        let webgl_idx = self.rng.random_range(0..WEBGL_RENDERERS.len());
        let geo_idx = self.rng.random_range(0..GEO_REGIONS.len());

        let canvas_hash = format!("{:016x}", self.rng.random::<u64>());
        let session_token = format!("{:032x}", self.rng.random::<u128>());
        let correlation_tag = format!("id-{id}-{:08x}", self.rng.random::<u32>());

        let tz_offsets = [-300, -360, -420, -480, 0, 60, 120, 540];
        let tz_idx = self.rng.random_range(0..tz_offsets.len());

        let network_types = [
            NetworkIdentityType::DirectProxy,
            NetworkIdentityType::VpnTunnel,
            NetworkIdentityType::TorCircuit,
            NetworkIdentityType::ResidentialProxy,
        ];
        let net_idx = self.rng.random_range(0..network_types.len());

        let behaviors = [
            BrowsingBehavior::CasualBrowser,
            BrowsingBehavior::PowerUser,
            BrowsingBehavior::MobileUser,
            BrowsingBehavior::ApiClient,
        ];
        let beh_idx = self.rng.random_range(0..behaviors.len());

        let browser = BrowserFingerprint {
            user_agent: UA_TEMPLATES[ua_idx].to_string(),
            accept_language: LANGUAGES[lang_idx].to_string(),
            platform: PLATFORMS[platform_idx].to_string(),
            screen_resolution: RESOLUTIONS[res_idx],
            color_depth: if self.rng.random_bool(0.8) { 24 } else { 32 },
            timezone_offset: tz_offsets[tz_idx],
            webgl_renderer: WEBGL_RENDERERS[webgl_idx].to_string(),
            canvas_hash: canvas_hash.clone(),
            installed_fonts: vec!["Arial".to_string(), "Helvetica".to_string()],
            do_not_track: self.rng.random_bool(0.3),
        };

        let exit_octets: [u8; 4] = [
            self.rng.random_range(1..254),
            self.rng.random_range(0..254),
            self.rng.random_range(0..254),
            self.rng.random_range(1..254),
        ];

        let network = NetworkIdentity {
            identity_type: network_types[net_idx],
            exit_ip_hint: format!(
                "{}.{}.{}.{}",
                exit_octets[0], exit_octets[1], exit_octets[2], exit_octets[3]
            ),
            geo_region: GEO_REGIONS[geo_idx].to_string(),
        };

        let mut cookies = HashMap::new();
        cookies.insert(
            "session_id".to_string(),
            format!("{:016x}", self.rng.random::<u64>()),
        );
        cookies.insert(
            "_ga".to_string(),
            format!(
                "GA1.2.{}.{}",
                self.rng.random::<u32>(),
                self.rng.random::<u32>()
            ),
        );

        let application = ApplicationIdentity {
            session_token,
            cookies,
            api_key: None,
            csrf_token: Some(format!("{:032x}", self.rng.random::<u128>())),
        };

        let behavior = BehavioralIdentity {
            pattern: behaviors[beh_idx],
            mean_delay_ms: match behaviors[beh_idx] {
                BrowsingBehavior::CasualBrowser => self.rng.random_range(1500..4000),
                BrowsingBehavior::PowerUser => self.rng.random_range(300..1000),
                BrowsingBehavior::MobileUser => self.rng.random_range(2000..5000),
                BrowsingBehavior::ApiClient => self.rng.random_range(100..500),
                BrowsingBehavior::SearchCrawler => self.rng.random_range(500..2000),
            },
            click_variance: self.rng.random_range(0.1..0.8),
            scroll_depth_pct: self.rng.random_range(0.2..0.95),
            tab_switches: self.rng.random_bool(0.4),
        };

        self.use_counts.insert(id, 0);

        IdentityStack {
            id,
            browser,
            network,
            application,
            behavior,
            state: IdentityState::Created,
            correlation_tag,
        }
    }

    /// Activates the next available identity from the pool.
    pub fn activate_next(&mut self) -> Option<u64> {
        if let Some(current) = self.active_id {
            for identity in &mut self.identities {
                if identity.id == current && identity.state == IdentityState::Active {
                    identity.state = IdentityState::Rotating;
                }
            }
        }

        let next = self
            .identities
            .iter_mut()
            .find(|i| i.state == IdentityState::Created);

        if let Some(identity) = next {
            identity.state = IdentityState::Active;
            let id = identity.id;
            self.active_id = Some(id);
            Some(id)
        } else {
            None
        }
    }

    /// Records a use of the active identity. Triggers rotation if max uses reached.
    pub fn record_use(&mut self) -> Option<u64> {
        let active = self.active_id?;
        let count = self.use_counts.entry(active).or_insert(0);
        *count += 1;

        if *count >= self.config.max_uses_per_identity {
            return self.rotate();
        }

        Some(active)
    }

    /// Explicitly rotates to the next identity, destroying the current if configured.
    pub fn rotate(&mut self) -> Option<u64> {
        if let Some(current) = self.active_id {
            if self.config.destroy_on_rotate {
                self.destroy_identity(current);
            }
        }
        self.activate_next()
    }

    /// Destroys an identity, marking it unusable.
    pub fn destroy_identity(&mut self, id: u64) {
        for identity in &mut self.identities {
            if identity.id == id {
                identity.state = IdentityState::Destroyed;
            }
        }
        self.destroyed_ids.insert(id);
        if self.active_id == Some(id) {
            self.active_id = None;
        }
    }

    /// Checks two identities for detectable correlations.
    pub fn check_correlation(&self, id_a: u64, id_b: u64) -> Option<CorrelationCheck> {
        let a = self.get_identity(id_a)?;
        let b = self.get_identity(id_b)?;

        let mut shared = Vec::new();
        let mut score = 0.0;
        let checks = 8.0;

        if a.browser.user_agent == b.browser.user_agent {
            shared.push("user_agent".to_string());
            score += 1.0;
        }
        if a.browser.canvas_hash == b.browser.canvas_hash {
            shared.push("canvas_hash".to_string());
            score += 1.0;
        }
        if a.browser.screen_resolution == b.browser.screen_resolution {
            shared.push("screen_resolution".to_string());
            score += 0.5;
        }
        if a.browser.webgl_renderer == b.browser.webgl_renderer {
            shared.push("webgl_renderer".to_string());
            score += 1.0;
        }
        if a.network.exit_ip_hint == b.network.exit_ip_hint {
            shared.push("exit_ip".to_string());
            score += 1.5;
        }
        if a.network.geo_region == b.network.geo_region {
            shared.push("geo_region".to_string());
            score += 0.5;
        }
        if a.browser.timezone_offset == b.browser.timezone_offset {
            shared.push("timezone".to_string());
            score += 0.5;
        }
        if a.browser.accept_language == b.browser.accept_language {
            shared.push("language".to_string());
            score += 0.5;
        }

        let normalized = score / checks;

        Some(CorrelationCheck {
            id_a,
            id_b,
            shared_features: shared,
            correlation_score: normalized,
            safe: normalized < self.config.correlation_threshold,
        })
    }

    /// Returns the currently active identity.
    pub fn active_identity(&self) -> Option<&IdentityStack> {
        let active_id = self.active_id?;
        self.get_identity(active_id)
    }

    /// Returns an identity by ID.
    pub fn get_identity(&self, id: u64) -> Option<&IdentityStack> {
        self.identities.iter().find(|i| i.id == id)
    }

    /// Returns the total pool size (all states).
    pub fn pool_size(&self) -> usize {
        self.identities.len()
    }

    /// Returns the number of available (created) identities.
    pub fn available_count(&self) -> usize {
        self.identities
            .iter()
            .filter(|i| i.state == IdentityState::Created)
            .count()
    }

    /// Returns the number of destroyed identities.
    pub fn destroyed_count(&self) -> usize {
        self.destroyed_ids.len()
    }

    /// Returns use count for an identity.
    pub fn use_count(&self, id: u64) -> u32 {
        self.use_counts.get(&id).copied().unwrap_or(0)
    }
}
