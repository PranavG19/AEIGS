use serde::{Deserialize, Serialize};

/// Individual detection risk factor with score and weight.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionFactor {
    pub name: String,
    pub score: f64,
    pub weight: f64,
    pub description: String,
}

/// Recommendation for reducing detection risk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthRecommendation {
    pub priority: RecommendationPriority,
    pub action: String,
    pub expected_improvement: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RecommendationPriority {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for RecommendationPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "CRITICAL"),
            Self::High => write!(f, "HIGH"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::Low => write!(f, "LOW"),
        }
    }
}

/// Complete stealth assessment result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthReport {
    pub overall_score: f64,
    pub factors: Vec<DetectionFactor>,
    pub recommendations: Vec<StealthRecommendation>,
    pub grade: StealthGrade,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StealthGrade {
    Undetectable,
    Stealthy,
    Moderate,
    Risky,
    Exposed,
}

impl std::fmt::Display for StealthGrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Undetectable => write!(f, "Undetectable"),
            Self::Stealthy => write!(f, "Stealthy"),
            Self::Moderate => write!(f, "Moderate"),
            Self::Risky => write!(f, "Risky"),
            Self::Exposed => write!(f, "Exposed"),
        }
    }
}

/// Input metrics for the detection scorer.
#[derive(Debug, Clone)]
pub struct ScanMetrics {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub unique_ips_used: u32,
    pub requests_per_second: f64,
    pub typical_traffic_rps: f64,
    pub fingerprint_changes: u32,
    pub fingerprint_consistency_score: f64,
    pub cover_traffic_ratio: f64,
    pub scanner_signatures_detected: u32,
    pub has_proxy_chain: bool,
    pub geo_regions_used: u32,
    pub session_duration_secs: u64,
}

impl Default for ScanMetrics {
    fn default() -> Self {
        Self {
            total_requests: 0,
            blocked_requests: 0,
            unique_ips_used: 1,
            requests_per_second: 0.0,
            typical_traffic_rps: 10.0,
            fingerprint_changes: 0,
            fingerprint_consistency_score: 1.0,
            cover_traffic_ratio: 0.0,
            scanner_signatures_detected: 0,
            has_proxy_chain: false,
            geo_regions_used: 1,
            session_duration_secs: 0,
        }
    }
}

/// Detection score calculator.
///
/// Analyzes request patterns, IP diversity, timing, fingerprint consistency,
/// WAF trigger counts, and scanner signatures to produce an overall stealth
/// score from 0-100 (100 = undetectable) with actionable recommendations.
pub struct DetectionScorer;

impl DetectionScorer {
    /// Computes a full stealth report from the given scan metrics.
    pub fn score(metrics: &ScanMetrics) -> StealthReport {
        let factors = vec![
            Self::score_ip_diversity(metrics),
            Self::score_request_rate(metrics),
            Self::score_fingerprint_consistency(metrics),
            Self::score_waf_triggers(metrics),
            Self::score_cover_traffic(metrics),
            Self::score_scanner_signatures(metrics),
            Self::score_proxy_usage(metrics),
            Self::score_geo_diversity(metrics),
        ];

        let total_weight: f64 = factors.iter().map(|f| f.weight).sum();
        let weighted_sum: f64 = factors.iter().map(|f| f.score * f.weight).sum();
        let overall = if total_weight > 0.0 {
            (weighted_sum / total_weight).clamp(0.0, 100.0)
        } else {
            0.0
        };

        let grade = Self::grade_from_score(overall);
        let recommendations = Self::generate_recommendations(metrics, &factors);

        StealthReport {
            overall_score: overall,
            factors,
            recommendations,
            grade,
        }
    }

    fn score_ip_diversity(metrics: &ScanMetrics) -> DetectionFactor {
        let score = match metrics.unique_ips_used {
            0..=1 => 20.0,
            2..=5 => 50.0,
            6..=20 => 75.0,
            _ => 95.0,
        };
        DetectionFactor {
            name: "IP Diversity".to_string(),
            score,
            weight: 20.0,
            description: format!("{} unique IPs used", metrics.unique_ips_used),
        }
    }

    fn score_request_rate(metrics: &ScanMetrics) -> DetectionFactor {
        let ratio = if metrics.typical_traffic_rps > 0.0 {
            metrics.requests_per_second / metrics.typical_traffic_rps
        } else {
            0.0
        };
        let score = if ratio <= 0.5 {
            95.0
        } else if ratio <= 1.0 {
            80.0
        } else if ratio <= 2.0 {
            50.0
        } else if ratio <= 5.0 {
            25.0
        } else {
            5.0
        };
        DetectionFactor {
            name: "Request Rate".to_string(),
            score,
            weight: 15.0,
            description: format!(
                "{:.1} req/s vs {:.1} typical",
                metrics.requests_per_second, metrics.typical_traffic_rps
            ),
        }
    }

    fn score_fingerprint_consistency(metrics: &ScanMetrics) -> DetectionFactor {
        let score = metrics.fingerprint_consistency_score * 100.0;
        DetectionFactor {
            name: "Fingerprint Consistency".to_string(),
            score: score.clamp(0.0, 100.0),
            weight: 15.0,
            description: format!("consistency {:.0}%", score),
        }
    }

    fn score_waf_triggers(metrics: &ScanMetrics) -> DetectionFactor {
        let block_rate = if metrics.total_requests > 0 {
            metrics.blocked_requests as f64 / metrics.total_requests as f64
        } else {
            0.0
        };
        let score = ((1.0 - block_rate) * 100.0).clamp(0.0, 100.0);
        DetectionFactor {
            name: "WAF Trigger Rate".to_string(),
            score,
            weight: 20.0,
            description: format!(
                "{} blocked of {} total",
                metrics.blocked_requests, metrics.total_requests
            ),
        }
    }

    fn score_cover_traffic(metrics: &ScanMetrics) -> DetectionFactor {
        let score = if metrics.cover_traffic_ratio >= 0.3 {
            90.0
        } else if metrics.cover_traffic_ratio >= 0.15 {
            70.0
        } else if metrics.cover_traffic_ratio > 0.0 {
            40.0
        } else {
            10.0
        };
        DetectionFactor {
            name: "Cover Traffic".to_string(),
            score,
            weight: 10.0,
            description: format!(
                "{:.0}% cover traffic ratio",
                metrics.cover_traffic_ratio * 100.0
            ),
        }
    }

    fn score_scanner_signatures(metrics: &ScanMetrics) -> DetectionFactor {
        let score = match metrics.scanner_signatures_detected {
            0 => 100.0,
            1 => 60.0,
            2..=3 => 30.0,
            _ => 5.0,
        };
        DetectionFactor {
            name: "Scanner Signatures".to_string(),
            score,
            weight: 10.0,
            description: format!(
                "{} signatures detected",
                metrics.scanner_signatures_detected
            ),
        }
    }

    fn score_proxy_usage(metrics: &ScanMetrics) -> DetectionFactor {
        let score = if metrics.has_proxy_chain { 90.0 } else { 30.0 };
        DetectionFactor {
            name: "Proxy Usage".to_string(),
            score,
            weight: 5.0,
            description: if metrics.has_proxy_chain {
                "proxy chain active".to_string()
            } else {
                "direct connection".to_string()
            },
        }
    }

    fn score_geo_diversity(metrics: &ScanMetrics) -> DetectionFactor {
        let score = match metrics.geo_regions_used {
            0..=1 => 30.0,
            2..=3 => 60.0,
            4..=5 => 80.0,
            _ => 95.0,
        };
        DetectionFactor {
            name: "Geographic Diversity".to_string(),
            score,
            weight: 5.0,
            description: format!("{} regions used", metrics.geo_regions_used),
        }
    }

    fn grade_from_score(score: f64) -> StealthGrade {
        if score >= 90.0 {
            StealthGrade::Undetectable
        } else if score >= 75.0 {
            StealthGrade::Stealthy
        } else if score >= 50.0 {
            StealthGrade::Moderate
        } else if score >= 25.0 {
            StealthGrade::Risky
        } else {
            StealthGrade::Exposed
        }
    }

    fn generate_recommendations(
        _metrics: &ScanMetrics,
        factors: &[DetectionFactor],
    ) -> Vec<StealthRecommendation> {
        let mut recs = Vec::new();

        for factor in factors {
            if factor.score < 50.0 {
                let (priority, action, improvement) = match factor.name.as_str() {
                    "IP Diversity" => (
                        RecommendationPriority::Critical,
                        "Enable proxy chain rotation to increase IP diversity".to_string(),
                        20.0,
                    ),
                    "Request Rate" => (
                        RecommendationPriority::High,
                        "Reduce request rate to match typical traffic baseline".to_string(),
                        15.0,
                    ),
                    "Fingerprint Consistency" => (
                        RecommendationPriority::High,
                        "Enable fingerprint rotation with anti-correlation".to_string(),
                        10.0,
                    ),
                    "WAF Trigger Rate" => (
                        RecommendationPriority::Critical,
                        "Increase payload obfuscation and encoding evasion".to_string(),
                        20.0,
                    ),
                    "Cover Traffic" => (
                        RecommendationPriority::Medium,
                        "Enable cover traffic generation at 20%+ ratio".to_string(),
                        8.0,
                    ),
                    "Scanner Signatures" => (
                        RecommendationPriority::High,
                        "Enable anti-forensics module to clean scanner signatures".to_string(),
                        12.0,
                    ),
                    "Proxy Usage" => (
                        RecommendationPriority::Medium,
                        "Configure proxy chain for all outbound requests".to_string(),
                        5.0,
                    ),
                    "Geographic Diversity" => (
                        RecommendationPriority::Low,
                        "Add proxy nodes from additional geographic regions".to_string(),
                        3.0,
                    ),
                    _ => continue,
                };
                recs.push(StealthRecommendation {
                    priority,
                    action,
                    expected_improvement: improvement,
                });
            }
        }

        recs.sort_by(|a, b| a.priority.cmp(&b.priority));
        recs
    }
}

#[cfg(test)]
#[path = "detection_scorer_test.rs"]
mod detection_scorer_test;
