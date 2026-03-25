use std::collections::HashMap;

/// Classification of an endpoint by its likely function within the target application.
///
/// Determines both the base priority score and whether the endpoint should be
/// skipped entirely (e.g. static assets during a vulnerability scan).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EndpointCategory {
    Authentication,
    AdminPanel,
    ApiEndpoint,
    FileUpload,
    DynamicContent,
    StaticAsset,
    CdnResource,
    Unknown,
}

impl std::fmt::Display for EndpointCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authentication => write!(f, "Authentication"),
            Self::AdminPanel => write!(f, "AdminPanel"),
            Self::ApiEndpoint => write!(f, "ApiEndpoint"),
            Self::FileUpload => write!(f, "FileUpload"),
            Self::DynamicContent => write!(f, "DynamicContent"),
            Self::StaticAsset => write!(f, "StaticAsset"),
            Self::CdnResource => write!(f, "CdnResource"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Relative importance of each scoring signal when computing final priority.
///
/// All four weights should sum to 1.0 for normalized output. The defaults
/// emphasize endpoint category (0.4) as the strongest signal, followed by
/// technology stack risk, historical vulnerability rate, and business criticality.
#[derive(Debug, Clone)]
pub struct SchedulerWeights {
    pub category_weight: f64,
    pub tech_risk_weight: f64,
    pub vuln_history_weight: f64,
    pub business_crit_weight: f64,
}

impl Default for SchedulerWeights {
    fn default() -> Self {
        Self {
            category_weight: 0.4,
            tech_risk_weight: 0.25,
            vuln_history_weight: 0.2,
            business_crit_weight: 0.15,
        }
    }
}

/// Configuration for the smart scheduler including weights, skip rules, and
/// known-safe URL patterns that bypass scanning entirely.
#[derive(Debug, Clone)]
pub struct SmartSchedulerConfig {
    pub weights: SchedulerWeights,
    pub skip_static_assets: bool,
    pub skip_cdn_resources: bool,
    pub known_safe_patterns: Vec<String>,
    pub max_queue_size: usize,
    pub category_base_scores: HashMap<EndpointCategory, f64>,
}

impl Default for SmartSchedulerConfig {
    fn default() -> Self {
        Self {
            weights: SchedulerWeights::default(),
            skip_static_assets: true,
            skip_cdn_resources: true,
            known_safe_patterns: Vec::new(),
            max_queue_size: 10_000,
            category_base_scores: default_category_scores(),
        }
    }
}

impl SmartSchedulerConfig {
    pub fn with_weights(mut self, weights: SchedulerWeights) -> Self {
        self.weights = weights;
        self
    }

    pub fn with_skip_static(mut self, skip: bool) -> Self {
        self.skip_static_assets = skip;
        self
    }

    pub fn with_skip_cdn(mut self, skip: bool) -> Self {
        self.skip_cdn_resources = skip;
        self
    }

    pub fn with_safe_pattern(mut self, pattern: String) -> Self {
        self.known_safe_patterns.push(pattern);
        self
    }

    pub fn with_max_queue_size(mut self, n: usize) -> Self {
        self.max_queue_size = n;
        self
    }
}

fn default_category_scores() -> HashMap<EndpointCategory, f64> {
    HashMap::from([
        (EndpointCategory::Authentication, 1.0),
        (EndpointCategory::AdminPanel, 0.95),
        (EndpointCategory::FileUpload, 0.9),
        (EndpointCategory::ApiEndpoint, 0.8),
        (EndpointCategory::DynamicContent, 0.6),
        (EndpointCategory::Unknown, 0.4),
        (EndpointCategory::StaticAsset, 0.1),
        (EndpointCategory::CdnResource, 0.05),
    ])
}

/// A scan target with its computed priority score and classification metadata.
///
/// The `skipped` flag indicates the endpoint matched a skip rule (static asset,
/// CDN resource, or known-safe pattern) and should not be fuzzed. The
/// `skip_reason` provides the rationale when `skipped` is true.
#[derive(Debug, Clone)]
pub struct ScheduledTarget {
    pub url: String,
    pub method: String,
    pub category: EndpointCategory,
    pub priority_score: f64,
    pub tech_risk_score: f64,
    pub vuln_history_score: f64,
    pub business_criticality: f64,
    pub skipped: bool,
    pub skip_reason: Option<String>,
}

/// Aggregate statistics about the scheduler's current queue state.
#[derive(Debug, Clone, Default)]
pub struct SchedulerStats {
    pub total_endpoints: usize,
    pub skipped_endpoints: usize,
    pub category_counts: HashMap<String, usize>,
    pub average_priority: f64,
    pub highest_priority: f64,
}

/// Priority-aware endpoint scheduler that ranks scan targets by combining
/// category classification, technology stack risk, historical vulnerability
/// rates, and business criticality into a single weighted score.
///
/// Endpoints matching skip rules (static assets, CDN resources, known-safe
/// patterns) are flagged but retained in the queue for auditability.
pub struct SmartScheduler {
    config: SmartSchedulerConfig,
    targets: Vec<ScheduledTarget>,
    tech_risk_scores: HashMap<String, f64>,
    vuln_history: HashMap<String, f64>,
    business_critical: HashMap<String, f64>,
    stats: SchedulerStats,
}

impl SmartScheduler {
    pub fn new(config: SmartSchedulerConfig) -> Self {
        Self {
            config,
            targets: Vec::new(),
            tech_risk_scores: HashMap::new(),
            vuln_history: HashMap::new(),
            business_critical: HashMap::new(),
            stats: SchedulerStats::default(),
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(SmartSchedulerConfig::default())
    }

    /// Determines the functional category of an endpoint from its URL and HTTP method.
    ///
    /// Checks patterns in priority order: authentication, admin, API, file upload,
    /// static asset, CDN resource, dynamic content, and finally unknown. The first
    /// matching rule wins.
    pub fn classify_endpoint(url: &str, _method: &str) -> EndpointCategory {
        let lower = url.to_lowercase();

        if is_auth_endpoint(&lower) {
            return EndpointCategory::Authentication;
        }
        if is_admin_endpoint(&lower) {
            return EndpointCategory::AdminPanel;
        }
        if is_api_endpoint(&lower) {
            return EndpointCategory::ApiEndpoint;
        }
        if is_upload_endpoint(&lower) {
            return EndpointCategory::FileUpload;
        }
        if is_static_asset(&lower) {
            return EndpointCategory::StaticAsset;
        }
        if is_cdn_resource(&lower) {
            return EndpointCategory::CdnResource;
        }
        if is_dynamic_content(&lower) {
            return EndpointCategory::DynamicContent;
        }
        EndpointCategory::Unknown
    }

    /// Registers a technology stack risk score. Higher values (closer to 1.0) indicate
    /// riskier stacks. Matched against the URL via substring containment.
    pub fn set_tech_risk(&mut self, tech: &str, risk_score: f64) {
        self.tech_risk_scores
            .insert(tech.to_lowercase(), clamp_score(risk_score));
    }

    /// Registers a historical vulnerability rate for a URL pattern. Matched via
    /// substring containment against each endpoint URL.
    pub fn set_vuln_history(&mut self, url_pattern: &str, vuln_rate: f64) {
        self.vuln_history
            .insert(url_pattern.to_lowercase(), clamp_score(vuln_rate));
    }

    /// Registers a business criticality score for a URL pattern. Matched via
    /// substring containment against each endpoint URL.
    pub fn set_business_criticality(&mut self, url_pattern: &str, criticality: f64) {
        self.business_critical
            .insert(url_pattern.to_lowercase(), clamp_score(criticality));
    }

    /// Classifies, scores, and enqueues an endpoint. Returns a reference to the
    /// newly added target. Respects `max_queue_size`; silently drops if full.
    pub fn add_endpoint(&mut self, url: &str, method: &str) -> &ScheduledTarget {
        let category = Self::classify_endpoint(url, method);
        let (skipped, skip_reason) = self.compute_skip(url, &category);
        let tech_risk_score = self.lookup_tech_risk(url);
        let vuln_history_score = self.lookup_vuln_history(url);
        let business_criticality = self.lookup_business_criticality(url);
        let priority_score = self.compute_priority(
            &category,
            tech_risk_score,
            vuln_history_score,
            business_criticality,
        );

        let target = ScheduledTarget {
            url: url.to_string(),
            method: method.to_uppercase(),
            category,
            priority_score,
            tech_risk_score,
            vuln_history_score,
            business_criticality,
            skipped,
            skip_reason,
        };

        if self.targets.len() < self.config.max_queue_size {
            self.targets.push(target);
        }
        self.targets.last().expect("target was just pushed")
    }

    /// Sorts all targets by priority score in descending order. Skipped targets
    /// sink to the bottom regardless of their computed score.
    pub fn prioritize(&mut self) {
        self.targets.sort_by(|a, b| {
            let a_effective = if a.skipped { -1.0 } else { a.priority_score };
            let b_effective = if b.skipped { -1.0 } else { b.priority_score };
            b_effective
                .partial_cmp(&a_effective)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    /// Removes and returns the highest-priority non-skipped target, or `None`
    /// if only skipped targets remain.
    pub fn next_target(&mut self) -> Option<ScheduledTarget> {
        self.prioritize();
        let pos = self.targets.iter().position(|t| !t.skipped)?;
        Some(self.targets.remove(pos))
    }

    /// Returns a reference to the highest-priority non-skipped target without
    /// removing it from the queue.
    pub fn peek_next(&self) -> Option<&ScheduledTarget> {
        let mut best: Option<&ScheduledTarget> = None;
        for target in &self.targets {
            if target.skipped {
                continue;
            }
            match best {
                None => best = Some(target),
                Some(current) if target.priority_score > current.priority_score => {
                    best = Some(target);
                }
                _ => {}
            }
        }
        best
    }

    pub fn targets(&self) -> &[ScheduledTarget] {
        &self.targets
    }

    pub fn skipped_targets(&self) -> Vec<&ScheduledTarget> {
        self.targets.iter().filter(|t| t.skipped).collect()
    }

    pub fn active_targets(&self) -> Vec<&ScheduledTarget> {
        self.targets.iter().filter(|t| !t.skipped).collect()
    }

    /// Computes aggregate statistics across all queued targets.
    pub fn stats(&self) -> SchedulerStats {
        let total_endpoints = self.targets.len();
        let skipped_endpoints = self.targets.iter().filter(|t| t.skipped).count();

        let mut category_counts: HashMap<String, usize> = HashMap::new();
        for target in &self.targets {
            *category_counts
                .entry(target.category.to_string())
                .or_insert(0) += 1;
        }

        let active: Vec<&ScheduledTarget> = self.targets.iter().filter(|t| !t.skipped).collect();
        let average_priority = if active.is_empty() {
            0.0
        } else {
            active.iter().map(|t| t.priority_score).sum::<f64>() / active.len() as f64
        };

        let highest_priority = active
            .iter()
            .map(|t| t.priority_score)
            .fold(0.0_f64, f64::max);

        SchedulerStats {
            total_endpoints,
            skipped_endpoints,
            category_counts,
            average_priority,
            highest_priority,
        }
    }

    pub fn clear(&mut self) {
        self.targets.clear();
        self.stats = SchedulerStats::default();
    }

    pub fn target_count(&self) -> usize {
        self.targets.len()
    }

    fn compute_priority(
        &self,
        category: &EndpointCategory,
        tech_risk: f64,
        vuln_history: f64,
        business_crit: f64,
    ) -> f64 {
        let base = self
            .config
            .category_base_scores
            .get(category)
            .copied()
            .unwrap_or(0.4);
        let w = &self.config.weights;

        let raw = (w.category_weight * base)
            + (w.tech_risk_weight * tech_risk)
            + (w.vuln_history_weight * vuln_history)
            + (w.business_crit_weight * business_crit);

        clamp_score(raw)
    }

    fn compute_skip(&self, url: &str, category: &EndpointCategory) -> (bool, Option<String>) {
        if self.config.skip_static_assets && *category == EndpointCategory::StaticAsset {
            return (true, Some("static asset".to_string()));
        }
        if self.config.skip_cdn_resources && *category == EndpointCategory::CdnResource {
            return (true, Some("CDN resource".to_string()));
        }
        let lower = url.to_lowercase();
        for pattern in &self.config.known_safe_patterns {
            if lower.contains(&pattern.to_lowercase()) {
                return (true, Some(format!("matched safe pattern: {pattern}")));
            }
        }
        (false, None)
    }

    fn lookup_tech_risk(&self, url: &str) -> f64 {
        let lower = url.to_lowercase();
        self.tech_risk_scores
            .iter()
            .filter(|(tech, _)| lower.contains(tech.as_str()))
            .map(|(_, score)| *score)
            .fold(0.0_f64, f64::max)
    }

    fn lookup_vuln_history(&self, url: &str) -> f64 {
        let lower = url.to_lowercase();
        self.vuln_history
            .iter()
            .filter(|(pattern, _)| lower.contains(pattern.as_str()))
            .map(|(_, rate)| *rate)
            .fold(0.0_f64, f64::max)
    }

    fn lookup_business_criticality(&self, url: &str) -> f64 {
        let lower = url.to_lowercase();
        self.business_critical
            .iter()
            .filter(|(pattern, _)| lower.contains(pattern.as_str()))
            .map(|(_, crit)| *crit)
            .fold(0.0_f64, f64::max)
    }
}

fn clamp_score(value: f64) -> f64 {
    value.clamp(0.0, 1.0)
}

fn is_auth_endpoint(lower: &str) -> bool {
    let markers = [
        "/auth",
        "/login",
        "/signin",
        "/oauth",
        "/token",
        "/session",
        "/register",
        "/signup",
        "/password",
        "/2fa",
        "/mfa",
    ];
    markers.iter().any(|m| lower.contains(m))
}

fn is_admin_endpoint(lower: &str) -> bool {
    let markers = ["/admin", "/dashboard", "/manage", "/control", "/panel"];
    markers.iter().any(|m| lower.contains(m))
}

fn is_api_endpoint(lower: &str) -> bool {
    let markers = ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/"];
    markers.iter().any(|m| lower.contains(m))
}

fn is_upload_endpoint(lower: &str) -> bool {
    let markers = ["/upload", "/import", "/attach"];
    markers.iter().any(|m| lower.contains(m))
}

fn is_static_asset(lower: &str) -> bool {
    let extensions = [
        ".js", ".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".ico", ".map",
    ];
    extensions.iter().any(|ext| lower.ends_with(ext))
}

fn is_cdn_resource(lower: &str) -> bool {
    let markers = [
        "cdn.", "static.", "assets.", "/static/", "/assets/", "/dist/", "/bundle",
    ];
    markers.iter().any(|m| lower.contains(m))
}

fn is_dynamic_content(lower: &str) -> bool {
    let markers = [".php", ".asp", ".jsp", ".py", "?", "="];
    markers.iter().any(|m| lower.contains(m))
}

#[cfg(test)]
#[path = "smart_scheduler_test.rs"]
mod smart_scheduler_test;
