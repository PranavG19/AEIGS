use crate::scan_config::ScanConfig;
use std::time::Duration;

/// Pre-configured scan profiles for common use cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanProfile {
    Quick,
    Standard,
    Deep,
    Stealth,
    Custom,
}

/// Configuration for a scan profile.
#[derive(Debug, Clone)]
pub struct ProfileConfig {
    pub profile: ScanProfile,
    pub max_threads: usize,
    pub timeout: Option<Duration>,
    pub max_iterations: u32,
    pub convergence_threshold: u32,
    pub stealth_level: String,
    pub max_rps: Option<u32>,
    pub skip_evasion: bool,
    pub use_llm: bool,
    pub skip_crawl: bool,
    pub skip_fingerprint: bool,
    pub description: String,
}

impl ProfileConfig {
    /// Apply this profile's settings to a ScanConfig.
    pub fn apply_to(&self, config: &mut ScanConfig) {
        config.pipeline.max_iterations = self.max_iterations;
        config.pipeline.convergence_threshold = self.convergence_threshold;
        config.stealth.stealth_level = self.stealth_level.clone();
        config.stealth.max_rps = self.max_rps;
        config.stealth.skip_evasion = self.skip_evasion;
        config.llm.no_llm = !self.use_llm;
        config.pipeline.skip_crawl = self.skip_crawl;
        config.pipeline.skip_fingerprint = self.skip_fingerprint;
    }
}

/// Get the Quick scan profile.
/// Top-10 vulns only, 1 thread, 5 min timeout.
pub fn quick_profile() -> ProfileConfig {
    ProfileConfig {
        profile: ScanProfile::Quick,
        max_threads: 1,
        timeout: Some(Duration::from_secs(300)),
        max_iterations: 1,
        convergence_threshold: 1,
        stealth_level: "default".into(),
        max_rps: Some(10),
        skip_evasion: true,
        use_llm: false,
        skip_crawl: false,
        skip_fingerprint: false,
        description: "Fast scan: top vulns, single pass, 5 min timeout".into(),
    }
}

/// Get the Standard scan profile.
/// OWASP Top 10, 10 threads, 30 min.
pub fn standard_profile() -> ProfileConfig {
    ProfileConfig {
        profile: ScanProfile::Standard,
        max_threads: 10,
        timeout: Some(Duration::from_secs(1800)),
        max_iterations: 2,
        convergence_threshold: 2,
        stealth_level: "default".into(),
        max_rps: Some(20),
        skip_evasion: false,
        use_llm: false,
        skip_crawl: false,
        skip_fingerprint: false,
        description: "Standard scan: OWASP Top 10, moderate speed".into(),
    }
}

/// Get the Deep scan profile.
/// All modules, 50 threads, unlimited time, recursive.
pub fn deep_profile() -> ProfileConfig {
    ProfileConfig {
        profile: ScanProfile::Deep,
        max_threads: 50,
        timeout: None,
        max_iterations: 5,
        convergence_threshold: 3,
        stealth_level: "default".into(),
        max_rps: None,
        skip_evasion: false,
        use_llm: true,
        skip_crawl: false,
        skip_fingerprint: false,
        description: "Deep scan: all modules, LLM hypotheses, maximum coverage".into(),
    }
}

/// Get the Stealth scan profile.
/// Slow, randomized timing, proxy rotation, evasion on.
pub fn stealth_profile() -> ProfileConfig {
    ProfileConfig {
        profile: ScanProfile::Stealth,
        max_threads: 1,
        timeout: None,
        max_iterations: 3,
        convergence_threshold: 2,
        stealth_level: "paranoid".into(),
        max_rps: Some(2),
        skip_evasion: false,
        use_llm: true,
        skip_crawl: false,
        skip_fingerprint: false,
        description: "Stealth scan: slow, paranoid evasion, low rate".into(),
    }
}

/// Create a custom profile from individual parameters.
pub fn custom_profile(
    max_threads: usize,
    timeout: Option<Duration>,
    max_iterations: u32,
    use_llm: bool,
    stealth_level: &str,
    max_rps: Option<u32>,
) -> ProfileConfig {
    ProfileConfig {
        profile: ScanProfile::Custom,
        max_threads,
        timeout,
        max_iterations,
        convergence_threshold: max_iterations.min(2),
        stealth_level: stealth_level.to_string(),
        max_rps,
        skip_evasion: stealth_level == "default",
        use_llm,
        skip_crawl: false,
        skip_fingerprint: false,
        description: "Custom scan profile".into(),
    }
}

/// Get profile config by name.
pub fn get_profile(name: &str) -> Option<ProfileConfig> {
    match name.to_lowercase().as_str() {
        "quick" => Some(quick_profile()),
        "standard" => Some(standard_profile()),
        "deep" => Some(deep_profile()),
        "stealth" => Some(stealth_profile()),
        _ => None,
    }
}

/// List all available profile names with descriptions.
pub fn list_profiles() -> Vec<(String, String)> {
    vec![
        ("quick".into(), quick_profile().description),
        ("standard".into(), standard_profile().description),
        ("deep".into(), deep_profile().description),
        ("stealth".into(), stealth_profile().description),
    ]
}
