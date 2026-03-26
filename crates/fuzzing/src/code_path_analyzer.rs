use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

/// Type of request variation applied to probe for differential code paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VariationType {
    Encoding,
    ParameterOrder,
    CaseChange,
    Whitespace,
    NullByte,
    DuplicateParam,
    PathTraversal,
    MethodChange,
    ContentTypeSwitch,
}

impl std::fmt::Display for VariationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encoding => write!(f, "Encoding"),
            Self::ParameterOrder => write!(f, "Parameter Order"),
            Self::CaseChange => write!(f, "Case Change"),
            Self::Whitespace => write!(f, "Whitespace"),
            Self::NullByte => write!(f, "Null Byte"),
            Self::DuplicateParam => write!(f, "Duplicate Parameter"),
            Self::PathTraversal => write!(f, "Path Traversal"),
            Self::MethodChange => write!(f, "Method Change"),
            Self::ContentTypeSwitch => write!(f, "Content-Type Switch"),
        }
    }
}

/// Lightweight HTTP request representation for code path analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub params: HashMap<String, String>,
}

/// Lightweight HTTP response representation for code path analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

/// Structural hash of a response, capturing status, header shape, and body shape.
///
/// Two responses with the same `combined` hash exercised the same server code path.
/// Different `combined` values indicate different handling logic was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResponseHash {
    pub status_hash: u64,
    pub header_hash: u64,
    pub body_hash: u64,
    pub combined: u64,
}

/// A variation of the base request along with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVariation {
    pub description: String,
    pub modified_request: HttpRequest,
    pub variation_type: VariationType,
}

/// Result of sending a single variation and comparing against baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariationResult {
    pub variation: RequestVariation,
    pub response_hash: ResponseHash,
    pub differs_from_baseline: bool,
}

/// Full analysis output: baseline + all variation results + summary stats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodePathAnalysis {
    pub baseline_hash: ResponseHash,
    pub variations: Vec<VariationResult>,
    pub unique_paths: usize,
    pub interesting_variations: Vec<RequestVariation>,
}

/// Maps response hash signatures to the variation types that produced them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageMap {
    pub paths: HashMap<u64, Vec<VariationType>>,
    pub total_unique_paths: usize,
}

/// Configuration for the differential code path analyzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodePathConfig {
    pub target_url: String,
    pub timeout_ms: u64,
    pub max_variations: usize,
}

impl Default for CodePathConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            timeout_ms: 5000,
            max_variations: 50,
        }
    }
}

impl CodePathConfig {
    pub fn with_target_url(mut self, url: impl Into<String>) -> Self {
        self.target_url = url.into();
        self
    }

    pub fn with_timeout_ms(mut self, timeout: u64) -> Self {
        self.timeout_ms = timeout;
        self
    }

    pub fn with_max_variations(mut self, max: usize) -> Self {
        self.max_variations = max;
        self
    }
}

/// Detects differential server behavior by sending structurally equivalent
/// but syntactically varied requests and comparing response signatures.
///
/// Variation types cover encoding differences, parameter ordering, case
/// sensitivity, whitespace injection, null bytes, duplicate parameters,
/// path traversal sequences, HTTP method changes, and content-type switches.
/// Each variation that produces a different response hash indicates a distinct
/// server code path, which may reveal input validation inconsistencies.
pub struct CodePathAnalyzer {
    config: CodePathConfig,
}

impl CodePathAnalyzer {
    pub fn new(config: CodePathConfig) -> Self {
        Self { config }
    }

    /// Generate all request variations from a base request.
    ///
    /// Produces up to `config.max_variations` variations covering each
    /// `VariationType`. The base request is not included in the output.
    pub fn generate_variations(&self, base_request: &HttpRequest) -> Vec<RequestVariation> {
        let mut variations = Vec::new();

        variations.extend(generate_encoding_variations(base_request));
        variations.extend(generate_parameter_order_variations(base_request));
        variations.extend(generate_case_variations(base_request));
        variations.extend(generate_whitespace_variations(base_request));
        variations.extend(generate_null_byte_variations(base_request));
        variations.extend(generate_duplicate_param_variations(base_request));
        variations.extend(generate_path_traversal_variations(base_request));
        variations.extend(generate_method_variations(base_request));
        variations.extend(generate_content_type_variations(base_request));

        variations.truncate(self.config.max_variations);
        variations
    }

    /// Hash a response into a structural signature.
    ///
    /// Hashes status code, sorted header key set, and body content separately,
    /// then combines them into a single `ResponseHash`. Two structurally
    /// identical responses will always produce the same hash.
    pub fn hash_response(&self, response: &HttpResponse) -> ResponseHash {
        let status_hash = hash_value(&response.status);

        let mut header_keys: Vec<&String> = response.headers.keys().collect();
        header_keys.sort();
        let header_hash = hash_value(&header_keys);

        let body_hash = hash_value(&response.body);

        let combined = hash_value(&(status_hash, header_hash, body_hash));

        ResponseHash {
            status_hash,
            header_hash,
            body_hash,
            combined,
        }
    }

    /// Run a full differential analysis: hash the baseline, generate and
    /// "send" all variations, compare hashes, and return the analysis.
    ///
    /// In a real scan this would make HTTP requests; here it accepts
    /// pre-computed responses keyed by variation index for testability.
    pub fn analyze(
        &self,
        base_request: &HttpRequest,
        baseline_response: &HttpResponse,
        variation_responses: &[HttpResponse],
    ) -> CodePathAnalysis {
        let baseline_hash = self.hash_response(baseline_response);
        let variations = self.generate_variations(base_request);

        let mut results = Vec::new();
        let mut interesting = Vec::new();

        for (i, variation) in variations.into_iter().enumerate() {
            let response_hash = if i < variation_responses.len() {
                self.hash_response(&variation_responses[i])
            } else {
                baseline_hash
            };

            let differs = response_hash.combined != baseline_hash.combined;
            if differs {
                interesting.push(variation.clone());
            }

            results.push(VariationResult {
                variation,
                response_hash,
                differs_from_baseline: differs,
            });
        }

        let coverage = self.build_coverage_map(&results);

        CodePathAnalysis {
            baseline_hash,
            variations: results,
            unique_paths: coverage.total_unique_paths,
            interesting_variations: interesting,
        }
    }

    /// Build a coverage map from variation results, grouping variation types
    /// by the response hash they produced.
    pub fn build_coverage_map(&self, results: &[VariationResult]) -> CoverageMap {
        let mut paths: HashMap<u64, Vec<VariationType>> = HashMap::new();

        for result in results {
            paths
                .entry(result.response_hash.combined)
                .or_default()
                .push(result.variation.variation_type);
        }

        let total_unique_paths = paths.len();
        CoverageMap {
            paths,
            total_unique_paths,
        }
    }

    pub fn config(&self) -> &CodePathConfig {
        &self.config
    }
}

/// Hash any hashable value using DefaultHasher.
fn hash_value<T: Hash>(value: &T) -> u64 {
    let mut hasher = std::hash::DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn generate_encoding_variations(base: &HttpRequest) -> Vec<RequestVariation> {
    let mut variations = Vec::new();

    let mut url_encoded = base.clone();
    url_encoded.url = base.url.replace('/', "%2F");
    variations.push(RequestVariation {
        description: "URL-encode path separators".to_string(),
        modified_request: url_encoded,
        variation_type: VariationType::Encoding,
    });

    let mut double_encoded = base.clone();
    double_encoded.url = base.url.replace('/', "%252F");
    variations.push(RequestVariation {
        description: "Double URL-encode path separators".to_string(),
        modified_request: double_encoded,
        variation_type: VariationType::Encoding,
    });

    if let Some(body) = &base.body {
        let mut unicode_body = base.clone();
        unicode_body.body = Some(body.replace('a', "\u{FF41}"));
        variations.push(RequestVariation {
            description: "Replace ASCII with fullwidth Unicode equivalents".to_string(),
            modified_request: unicode_body,
            variation_type: VariationType::Encoding,
        });
    }

    variations
}

fn generate_parameter_order_variations(base: &HttpRequest) -> Vec<RequestVariation> {
    let mut variations = Vec::new();

    if base.params.len() >= 2 {
        let mut keys: Vec<String> = base.params.keys().cloned().collect();
        keys.sort();
        keys.reverse();

        let mut reordered = base.clone();
        let mut new_params = HashMap::new();
        for key in &keys {
            if let Some(val) = base.params.get(key) {
                new_params.insert(key.clone(), val.clone());
            }
        }
        reordered.params = new_params;

        variations.push(RequestVariation {
            description: "Reverse parameter order".to_string(),
            modified_request: reordered,
            variation_type: VariationType::ParameterOrder,
        });
    }

    variations
}

fn generate_case_variations(base: &HttpRequest) -> Vec<RequestVariation> {
    let mut variations = Vec::new();

    let mut upper_url = base.clone();
    upper_url.url = base.url.to_uppercase();
    variations.push(RequestVariation {
        description: "Uppercase URL path".to_string(),
        modified_request: upper_url,
        variation_type: VariationType::CaseChange,
    });

    let mut mixed_method = base.clone();
    mixed_method.method = alternate_case(&base.method);
    variations.push(RequestVariation {
        description: "Mixed-case HTTP method".to_string(),
        modified_request: mixed_method,
        variation_type: VariationType::CaseChange,
    });

    variations
}

fn generate_whitespace_variations(base: &HttpRequest) -> Vec<RequestVariation> {
    let mut variations = Vec::new();

    let mut tab_url = base.clone();
    tab_url.url = format!("{}\t", base.url);
    variations.push(RequestVariation {
        description: "Append tab to URL".to_string(),
        modified_request: tab_url,
        variation_type: VariationType::Whitespace,
    });

    let mut space_params = base.clone();
    let new_params: HashMap<String, String> = base
        .params
        .iter()
        .map(|(k, v)| (format!(" {}", k), v.clone()))
        .collect();
    space_params.params = new_params;
    variations.push(RequestVariation {
        description: "Prepend space to parameter names".to_string(),
        modified_request: space_params,
        variation_type: VariationType::Whitespace,
    });

    variations
}

fn generate_null_byte_variations(base: &HttpRequest) -> Vec<RequestVariation> {
    let mut variations = Vec::new();

    let mut null_url = base.clone();
    null_url.url = format!("{}\x00", base.url);
    variations.push(RequestVariation {
        description: "Append null byte to URL".to_string(),
        modified_request: null_url,
        variation_type: VariationType::NullByte,
    });

    let mut null_params = base.clone();
    let new_params: HashMap<String, String> = base
        .params
        .iter()
        .map(|(k, v)| (k.clone(), format!("{}\x00", v)))
        .collect();
    null_params.params = new_params;
    variations.push(RequestVariation {
        description: "Append null byte to parameter values".to_string(),
        modified_request: null_params,
        variation_type: VariationType::NullByte,
    });

    variations
}

fn generate_duplicate_param_variations(base: &HttpRequest) -> Vec<RequestVariation> {
    let mut variations = Vec::new();

    if let Some((first_key, first_val)) = base.params.iter().next() {
        let mut duped = base.clone();
        duped
            .params
            .insert(format!("{}_dup", first_key), first_val.clone());
        variations.push(RequestVariation {
            description: format!("Duplicate parameter '{}' with suffix", first_key),
            modified_request: duped,
            variation_type: VariationType::DuplicateParam,
        });
    }

    variations
}

fn generate_path_traversal_variations(base: &HttpRequest) -> Vec<RequestVariation> {
    let mut variations = Vec::new();

    let mut traversal = base.clone();
    traversal.url = format!("{}/../{}", base.url, base.url.trim_start_matches('/'));
    variations.push(RequestVariation {
        description: "Insert path traversal sequence".to_string(),
        modified_request: traversal,
        variation_type: VariationType::PathTraversal,
    });

    let mut dot_url = base.clone();
    dot_url.url = format!("{}/./", base.url);
    variations.push(RequestVariation {
        description: "Append dot-slash to URL".to_string(),
        modified_request: dot_url,
        variation_type: VariationType::PathTraversal,
    });

    variations
}

fn generate_method_variations(base: &HttpRequest) -> Vec<RequestVariation> {
    let mut variations = Vec::new();
    let alternative_methods = match base.method.to_uppercase().as_str() {
        "GET" => vec!["POST", "PUT", "PATCH"],
        "POST" => vec!["GET", "PUT", "PATCH"],
        _ => vec!["GET", "POST"],
    };

    for method in alternative_methods {
        let mut changed = base.clone();
        changed.method = method.to_string();
        variations.push(RequestVariation {
            description: format!("Switch method to {}", method),
            modified_request: changed,
            variation_type: VariationType::MethodChange,
        });
    }

    variations
}

fn generate_content_type_variations(base: &HttpRequest) -> Vec<RequestVariation> {
    let mut variations = Vec::new();

    let content_types = [
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "text/xml",
    ];

    for ct in &content_types {
        let current = base.headers.get("content-type").map(|s| s.as_str());
        if current == Some(ct) {
            continue;
        }
        let mut switched = base.clone();
        switched
            .headers
            .insert("content-type".to_string(), ct.to_string());
        variations.push(RequestVariation {
            description: format!("Switch Content-Type to {}", ct),
            modified_request: switched,
            variation_type: VariationType::ContentTypeSwitch,
        });
    }

    variations
}

/// Alternate uppercase/lowercase for each character.
fn alternate_case(s: &str) -> String {
    s.chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_uppercase().to_string()
            } else {
                c.to_lowercase().to_string()
            }
        })
        .collect()
}

/// Returns all variation types.
pub fn all_variation_types() -> Vec<VariationType> {
    vec![
        VariationType::Encoding,
        VariationType::ParameterOrder,
        VariationType::CaseChange,
        VariationType::Whitespace,
        VariationType::NullByte,
        VariationType::DuplicateParam,
        VariationType::PathTraversal,
        VariationType::MethodChange,
        VariationType::ContentTypeSwitch,
    ]
}
