use crate::finding::VulnerabilityClass;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefenseContext {
    pub has_waf: bool,
    pub waf_vendor: Option<String>,
    pub waf_blocked_categories: Vec<VulnerabilityClass>,
    pub rate_limit_rps: Option<f64>,
    pub bot_detection_present: bool,
    pub bot_detection_evaded: bool,
}
