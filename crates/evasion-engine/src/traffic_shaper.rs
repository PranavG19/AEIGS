use std::collections::VecDeque;

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// Distribution model for inter-request timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimingDistribution {
    Poisson,
    LogNormal,
    Weibull,
}

/// Time-of-day window for realistic traffic simulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BusinessHours {
    pub start_hour: u8,
    pub end_hour: u8,
}

impl BusinessHours {
    pub fn contains_hour(&self, hour: u8) -> bool {
        if self.start_hour <= self.end_hour {
            hour >= self.start_hour && hour < self.end_hour
        } else {
            hour >= self.start_hour || hour < self.end_hour
        }
    }
}

impl Default for BusinessHours {
    fn default() -> Self {
        Self {
            start_hour: 8,
            end_hour: 18,
        }
    }
}

/// A navigation step in a session simulation path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavigationStep {
    pub url: String,
    pub referer: Option<String>,
    pub is_attack_request: bool,
}

/// Cover traffic request mixed in to mask attack patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverRequest {
    pub url: String,
    pub referer: Option<String>,
}

/// Simulated mouse movement data point for bot detection evasion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MouseEvent {
    pub x: u32,
    pub y: u32,
    pub timestamp_offset_ms: u64,
    pub event_type: MouseEventType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MouseEventType {
    Move,
    Click,
    Scroll,
}

/// Configuration for traffic shaping behavior.
#[derive(Debug, Clone)]
pub struct TrafficShaperConfig {
    pub mean_delay_ms: f64,
    pub distribution: TimingDistribution,
    pub burst_dampening: bool,
    pub max_burst_size: usize,
    pub cover_traffic_ratio: f64,
    pub business_hours: Option<BusinessHours>,
    pub simulate_mouse: bool,
    pub session_warmup_steps: usize,
}

impl Default for TrafficShaperConfig {
    fn default() -> Self {
        Self {
            mean_delay_ms: 2000.0,
            distribution: TimingDistribution::Poisson,
            burst_dampening: true,
            max_burst_size: 3,
            cover_traffic_ratio: 0.2,
            business_hours: None,
            simulate_mouse: false,
            session_warmup_steps: 3,
        }
    }
}

impl TrafficShaperConfig {
    pub fn with_mean_delay_ms(mut self, ms: f64) -> Self {
        self.mean_delay_ms = ms;
        self
    }

    pub fn with_distribution(mut self, dist: TimingDistribution) -> Self {
        self.distribution = dist;
        self
    }

    pub fn with_burst_dampening(mut self, enabled: bool) -> Self {
        self.burst_dampening = enabled;
        self
    }

    pub fn with_cover_traffic_ratio(mut self, ratio: f64) -> Self {
        self.cover_traffic_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    pub fn with_business_hours(mut self, hours: BusinessHours) -> Self {
        self.business_hours = Some(hours);
        self
    }

    pub fn with_simulate_mouse(mut self, enabled: bool) -> Self {
        self.simulate_mouse = enabled;
        self
    }

    pub fn with_session_warmup_steps(mut self, steps: usize) -> Self {
        self.session_warmup_steps = steps;
        self
    }
}

/// Traffic shaper that makes scan traffic patterns indistinguishable
/// from real user browsing sessions.
///
/// Provides human-like timing, session warmup navigation, referrer chain
/// building, burst dampening, cover traffic interleaving, and optional
/// mouse movement simulation data.
pub struct TrafficShaper {
    config: TrafficShaperConfig,
    rng: StdRng,
    recent_delays: VecDeque<f64>,
    total_requests: u64,
    cover_requests_sent: u64,
}

impl TrafficShaper {
    pub fn new(config: TrafficShaperConfig) -> Self {
        Self {
            config,
            rng: StdRng::from_os_rng(),
            recent_delays: VecDeque::with_capacity(10),
            total_requests: 0,
            cover_requests_sent: 0,
        }
    }

    pub fn with_seed(config: TrafficShaperConfig, seed: u64) -> Self {
        Self {
            config,
            rng: StdRng::seed_from_u64(seed),
            recent_delays: VecDeque::with_capacity(10),
            total_requests: 0,
            cover_requests_sent: 0,
        }
    }

    /// Computes the next inter-request delay in milliseconds using the
    /// configured distribution, applying burst dampening when enabled.
    pub fn next_delay_ms(&mut self) -> u64 {
        let raw = match self.config.distribution {
            TimingDistribution::Poisson => self.sample_poisson(),
            TimingDistribution::LogNormal => self.sample_lognormal(),
            TimingDistribution::Weibull => self.sample_weibull(),
        };

        let delay = if self.config.burst_dampening && self.is_bursting() {
            raw * 2.5
        } else {
            raw
        };

        let clamped = delay.max(50.0).min(self.config.mean_delay_ms * 5.0);
        self.recent_delays.push_back(clamped);
        if self.recent_delays.len() > 10 {
            self.recent_delays.pop_front();
        }
        self.total_requests += 1;

        clamped.round() as u64
    }

    /// Generates a session warmup navigation sequence: homepage, then intermediate
    /// pages, building a realistic referrer chain toward the target URL.
    pub fn generate_session_warmup(
        &mut self,
        base_url: &str,
        target_path: &str,
    ) -> Vec<NavigationStep> {
        let mut steps = Vec::with_capacity(self.config.session_warmup_steps + 1);
        let warmup_paths = [
            "/",
            "/about",
            "/products",
            "/services",
            "/blog",
            "/contact",
            "/faq",
        ];

        steps.push(NavigationStep {
            url: base_url.to_string(),
            referer: None,
            is_attack_request: false,
        });

        let count = self.config.session_warmup_steps.min(warmup_paths.len());
        for i in 0..count {
            let prev_url = steps.last().map(|s| s.url.clone());
            let path = warmup_paths[i % warmup_paths.len()];
            steps.push(NavigationStep {
                url: format!("{base_url}{path}"),
                referer: prev_url,
                is_attack_request: false,
            });
        }

        let prev_url = steps.last().map(|s| s.url.clone());
        steps.push(NavigationStep {
            url: format!("{base_url}{target_path}"),
            referer: prev_url,
            is_attack_request: true,
        });

        steps
    }

    /// Builds a referer header value by constructing a plausible referrer
    /// for the given target URL.
    pub fn build_referer(&self, target_url: &str) -> String {
        if let Some(slash_pos) = target_url.rfind('/')
            && slash_pos > 8
        {
            return target_url[..slash_pos].to_string();
        }
        target_url.to_string()
    }

    /// Generates cover traffic URLs that can be interleaved with attack requests.
    pub fn generate_cover_traffic(&mut self, base_url: &str, count: usize) -> Vec<CoverRequest> {
        let benign_paths = [
            "/",
            "/about",
            "/contact",
            "/privacy",
            "/terms",
            "/blog",
            "/faq",
            "/sitemap.xml",
            "/robots.txt",
            "/css/style.css",
            "/js/main.js",
            "/images/logo.png",
        ];

        let mut cover = Vec::with_capacity(count);
        for _ in 0..count {
            let idx = self.rng.random_range(0..benign_paths.len());
            let path = benign_paths[idx];
            let referer = if self.rng.random_bool(0.7) {
                Some(base_url.to_string())
            } else {
                None
            };
            cover.push(CoverRequest {
                url: format!("{base_url}{path}"),
                referer,
            });
            self.cover_requests_sent += 1;
        }
        cover
    }

    /// Determines how many cover requests should be inserted before the
    /// next attack request to maintain the configured ratio.
    pub fn cover_requests_needed(&self) -> usize {
        if self.config.cover_traffic_ratio <= 0.0 {
            return 0;
        }
        let target_cover = (self.total_requests as f64 * self.config.cover_traffic_ratio) as u64;
        target_cover.saturating_sub(self.cover_requests_sent) as usize
    }

    /// Generates simulated mouse movement data for a page interaction.
    pub fn generate_mouse_events(
        &mut self,
        viewport_width: u32,
        viewport_height: u32,
    ) -> Vec<MouseEvent> {
        if !self.config.simulate_mouse {
            return Vec::new();
        }

        let event_count = self.rng.random_range(5..15);
        let mut events = Vec::with_capacity(event_count);
        let mut time_offset: u64 = 0;
        let mut x = viewport_width / 2;
        let mut y = viewport_height / 2;

        for _ in 0..event_count {
            let dx: i32 = self.rng.random_range(0..=40) - 20;
            let dy: i32 = self.rng.random_range(0..=40) - 20;
            x = (x as i32 + dx).max(0).min(viewport_width as i32) as u32;
            y = (y as i32 + dy).max(0).min(viewport_height as i32) as u32;
            time_offset += self.rng.random_range(16..120);

            let event_type = if self.rng.random_bool(0.1) {
                MouseEventType::Click
            } else if self.rng.random_bool(0.1) {
                MouseEventType::Scroll
            } else {
                MouseEventType::Move
            };

            events.push(MouseEvent {
                x,
                y,
                timestamp_offset_ms: time_offset,
                event_type,
            });
        }

        events
    }

    /// Checks whether the current hour falls within the configured business hours.
    pub fn is_within_business_hours(&self, current_hour: u8) -> bool {
        match &self.config.business_hours {
            Some(hours) => hours.contains_hour(current_hour),
            None => true,
        }
    }

    /// Returns the total number of requests tracked by this shaper.
    pub fn total_requests(&self) -> u64 {
        self.total_requests
    }

    /// Returns the number of cover traffic requests generated.
    pub fn cover_requests_sent(&self) -> u64 {
        self.cover_requests_sent
    }

    fn sample_poisson(&mut self) -> f64 {
        let u: f64 = self.rng.random_range(0.0001f64..1.0);
        -self.config.mean_delay_ms * u.ln()
    }

    fn sample_lognormal(&mut self) -> f64 {
        let mean_ln = (self.config.mean_delay_ms).ln();
        let sigma = 0.5;
        let u1: f64 = self.rng.random_range(0.0001f64..1.0);
        let u2: f64 = self.rng.random_range(0.0001f64..1.0);
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        (mean_ln + sigma * z).exp()
    }

    fn sample_weibull(&mut self) -> f64 {
        let shape = 1.5;
        let scale = self.config.mean_delay_ms;
        let u: f64 = self.rng.random_range(0.0001f64..1.0);
        scale * (-u.ln()).powf(1.0 / shape)
    }

    fn is_bursting(&self) -> bool {
        if self.recent_delays.len() < self.config.max_burst_size {
            return false;
        }
        let recent: Vec<&f64> = self
            .recent_delays
            .iter()
            .rev()
            .take(self.config.max_burst_size)
            .collect();
        let threshold = self.config.mean_delay_ms * 0.3;
        recent.iter().all(|&&d| d < threshold)
    }
}

#[cfg(test)]
#[path = "traffic_shaper_test.rs"]
mod traffic_shaper_test;
