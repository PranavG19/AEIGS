use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Represents a cover traffic URL mixed with attack traffic to appear as normal browsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverUrl {
    pub url: String,
    pub category: UrlCategory,
    pub rank: u32,
}

/// Categories of cover traffic URLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UrlCategory {
    SearchEngine,
    SocialMedia,
    News,
    Shopping,
    Entertainment,
    Technology,
    Finance,
    Education,
    Reference,
    Portal,
}

impl std::fmt::Display for UrlCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SearchEngine => write!(f, "search"),
            Self::SocialMedia => write!(f, "social"),
            Self::News => write!(f, "news"),
            Self::Shopping => write!(f, "shopping"),
            Self::Entertainment => write!(f, "entertainment"),
            Self::Technology => write!(f, "technology"),
            Self::Finance => write!(f, "finance"),
            Self::Education => write!(f, "education"),
            Self::Reference => write!(f, "reference"),
            Self::Portal => write!(f, "portal"),
        }
    }
}

/// Simulated click action within a cover browsing session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickAction {
    pub url: String,
    pub delay_ms: u64,
    pub action_type: ClickType,
}

/// Types of click interactions that mimic real browsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClickType {
    PageLoad,
    InternalLink,
    ResourceFetch,
    FormInteraction,
    MediaPlay,
    Scroll,
}

/// Resource loading ratios that match real browser traffic patterns.
///
/// A real page load generates ~70% resource fetches (images, CSS, JS),
/// ~20% XHR/API calls, and ~10% navigation requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRatios {
    pub navigation_pct: f64,
    pub resource_pct: f64,
    pub xhr_pct: f64,
}

impl Default for ResourceRatios {
    fn default() -> Self {
        Self {
            navigation_pct: 10.0,
            resource_pct: 70.0,
            xhr_pct: 20.0,
        }
    }
}

/// Configuration for cover traffic generation.
#[derive(Debug, Clone)]
pub struct CoverTrafficConfig {
    pub attack_to_cover_ratio: f64,
    pub min_cover_requests: usize,
    pub max_cover_requests: usize,
    pub resource_ratios: ResourceRatios,
    pub session_duration_secs: u64,
    pub click_depth_min: u32,
    pub click_depth_max: u32,
    pub enable_media_interactions: bool,
}

impl Default for CoverTrafficConfig {
    fn default() -> Self {
        Self {
            attack_to_cover_ratio: 0.3,
            min_cover_requests: 5,
            max_cover_requests: 50,
            resource_ratios: ResourceRatios::default(),
            session_duration_secs: 300,
            click_depth_min: 1,
            click_depth_max: 5,
            enable_media_interactions: true,
        }
    }
}

/// Alexa-style top site database used as cover traffic sources.
///
/// Contains representative URLs from major site categories weighted
/// by typical browsing frequency.
pub struct CoverTrafficGenerator {
    sites: Vec<CoverUrl>,
    config: CoverTrafficConfig,
}

/// Top sites mimicking Alexa top-10k distribution across categories.
const TOP_SITES: &[(&str, UrlCategory, u32)] = &[
    ("https://www.google.com/", UrlCategory::SearchEngine, 1),
    ("https://www.youtube.com/", UrlCategory::Entertainment, 2),
    ("https://www.facebook.com/", UrlCategory::SocialMedia, 3),
    ("https://www.amazon.com/", UrlCategory::Shopping, 5),
    ("https://www.wikipedia.org/", UrlCategory::Reference, 7),
    ("https://twitter.com/", UrlCategory::SocialMedia, 10),
    ("https://www.instagram.com/", UrlCategory::SocialMedia, 12),
    ("https://www.reddit.com/", UrlCategory::SocialMedia, 15),
    ("https://www.linkedin.com/", UrlCategory::SocialMedia, 20),
    ("https://www.netflix.com/", UrlCategory::Entertainment, 22),
    ("https://www.bing.com/", UrlCategory::SearchEngine, 30),
    ("https://www.cnn.com/", UrlCategory::News, 35),
    ("https://www.bbc.com/", UrlCategory::News, 40),
    ("https://www.nytimes.com/", UrlCategory::News, 50),
    ("https://github.com/", UrlCategory::Technology, 55),
    ("https://stackoverflow.com/", UrlCategory::Technology, 60),
    ("https://www.apple.com/", UrlCategory::Technology, 70),
    ("https://www.microsoft.com/", UrlCategory::Technology, 80),
    ("https://www.ebay.com/", UrlCategory::Shopping, 90),
    ("https://www.walmart.com/", UrlCategory::Shopping, 100),
    ("https://www.bloomberg.com/", UrlCategory::Finance, 120),
    ("https://finance.yahoo.com/", UrlCategory::Finance, 130),
    ("https://www.reuters.com/", UrlCategory::News, 150),
    ("https://www.espn.com/", UrlCategory::Entertainment, 180),
    ("https://www.weather.com/", UrlCategory::Reference, 200),
    ("https://www.quora.com/", UrlCategory::Reference, 250),
    ("https://medium.com/", UrlCategory::Technology, 300),
    ("https://www.twitch.tv/", UrlCategory::Entertainment, 350),
    ("https://www.pinterest.com/", UrlCategory::SocialMedia, 400),
    ("https://www.paypal.com/", UrlCategory::Finance, 450),
    ("https://www.coursera.org/", UrlCategory::Education, 500),
    ("https://www.khanacademy.org/", UrlCategory::Education, 600),
    (
        "https://news.ycombinator.com/",
        UrlCategory::Technology,
        700,
    ),
    ("https://www.imdb.com/", UrlCategory::Entertainment, 800),
    ("https://www.washingtonpost.com/", UrlCategory::News, 900),
    ("https://www.yahoo.com/", UrlCategory::Portal, 1000),
    ("https://www.msn.com/", UrlCategory::Portal, 1100),
    ("https://www.theguardian.com/", UrlCategory::News, 1200),
    ("https://www.foxnews.com/", UrlCategory::News, 1300),
    ("https://www.cnbc.com/", UrlCategory::Finance, 1400),
];

impl CoverTrafficGenerator {
    pub fn new(config: CoverTrafficConfig) -> Self {
        let sites: Vec<CoverUrl> = TOP_SITES
            .iter()
            .map(|(url, cat, rank)| CoverUrl {
                url: url.to_string(),
                category: *cat,
                rank: *rank,
            })
            .collect();
        Self { sites, config }
    }

    pub fn with_defaults() -> Self {
        Self::new(CoverTrafficConfig::default())
    }

    /// Generate a browsing session of cover traffic URLs.
    ///
    /// Returns a sequence of click actions that simulate realistic browsing
    /// mixed with the attack traffic. The ratio is controlled by `attack_to_cover_ratio`.
    pub fn generate_session(&self, seed: u64) -> Vec<ClickAction> {
        let mut actions = Vec::new();
        let mut rng_state = seed;

        let session_count = self.config.min_cover_requests
            + ((rng_state as usize)
                % (self.config.max_cover_requests - self.config.min_cover_requests + 1));

        for i in 0..session_count {
            rng_state = xorshift64(rng_state);
            let site_idx = (rng_state as usize) % self.sites.len();
            let site = &self.sites[site_idx];

            rng_state = xorshift64(rng_state);
            let delay = 500 + (rng_state % 5000);

            actions.push(ClickAction {
                url: site.url.clone(),
                delay_ms: delay,
                action_type: ClickType::PageLoad,
            });

            rng_state = xorshift64(rng_state);
            let depth = self.config.click_depth_min
                + ((rng_state as u32)
                    % (self.config.click_depth_max - self.config.click_depth_min + 1));

            for _d in 0..depth {
                rng_state = xorshift64(rng_state);
                let resource_roll = (rng_state % 100) as f64;

                let action_type = if resource_roll < self.config.resource_ratios.navigation_pct {
                    ClickType::InternalLink
                } else if resource_roll
                    < self.config.resource_ratios.navigation_pct
                        + self.config.resource_ratios.resource_pct
                {
                    ClickType::ResourceFetch
                } else {
                    ClickType::Scroll
                };

                rng_state = xorshift64(rng_state);
                let sub_delay = 200 + (rng_state % 3000);

                actions.push(ClickAction {
                    url: format!("{}{}", site.url, pseudo_path(i as u64 + rng_state)),
                    delay_ms: sub_delay,
                    action_type,
                });
            }

            if self.config.enable_media_interactions && (rng_state % 5 == 0) {
                rng_state = xorshift64(rng_state);
                actions.push(ClickAction {
                    url: format!("{}media/{}", site.url, rng_state % 1000),
                    delay_ms: 1000 + (rng_state % 10000),
                    action_type: ClickType::MediaPlay,
                });
            }
        }

        actions
    }

    /// Calculate what percentage of total traffic the attack requests represent.
    pub fn compute_attack_ratio(&self, attack_count: usize, cover_count: usize) -> f64 {
        let total = attack_count + cover_count;
        if total == 0 {
            return 0.0;
        }
        attack_count as f64 / total as f64
    }

    /// Returns how many cover requests are needed to achieve the target ratio
    /// given a number of attack requests.
    pub fn cover_requests_needed(&self, attack_count: usize) -> usize {
        if self.config.attack_to_cover_ratio <= 0.0 || self.config.attack_to_cover_ratio >= 1.0 {
            return self.config.min_cover_requests;
        }
        let needed = (attack_count as f64 * (1.0 - self.config.attack_to_cover_ratio)
            / self.config.attack_to_cover_ratio)
            .ceil() as usize;
        needed.max(self.config.min_cover_requests)
    }

    /// Number of sites in the cover traffic database.
    pub fn site_count(&self) -> usize {
        self.sites.len()
    }

    /// Distribution of sites by category.
    pub fn category_distribution(&self) -> HashMap<UrlCategory, usize> {
        let mut dist = HashMap::new();
        for site in &self.sites {
            *dist.entry(site.category).or_insert(0) += 1;
        }
        dist
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

fn pseudo_path(seed: u64) -> String {
    let segments = [
        "articles", "posts", "pages", "category", "tag", "search", "news", "blog",
    ];
    let idx = (seed as usize) % segments.len();
    format!("{}/{}", segments[idx], seed % 10000)
}
