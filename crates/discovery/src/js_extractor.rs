use std::collections::HashSet;

use regex::Regex;
use url::Url;

#[derive(Debug, Clone)]
pub struct ExtractedEndpoint {
    pub url: String,
    pub method: Option<String>,
    pub source_pattern: String,
}

pub struct JsEndpointExtractor {
    base_url: String,
    base_host: String,
    patterns: Vec<JsPattern>,
}

struct JsPattern {
    regex: Regex,
    name: &'static str,
    extractor: fn(&regex::Captures) -> Option<RawMatch>,
}

struct RawMatch {
    url: String,
    method: Option<String>,
}

impl JsEndpointExtractor {
    pub fn new(base_url: &str) -> Self {
        let base = base_url.trim_end_matches('/').to_string();
        let base_host = Url::parse(&base)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_lowercase()))
            .unwrap_or_default();

        Self {
            base_url: base,
            base_host,
            patterns: build_patterns(),
        }
    }

    pub fn extract_from_js(&self, js_content: &str) -> Vec<ExtractedEndpoint> {
        let mut results = Vec::new();

        for pattern in &self.patterns {
            for caps in pattern.regex.captures_iter(js_content) {
                if let Some(raw) = (pattern.extractor)(&caps)
                    && let Some(endpoint) = self.resolve_url(&raw, pattern.name)
                {
                    results.push(endpoint);
                }
            }
        }

        deduplicate(results)
    }

    fn resolve_url(&self, raw: &RawMatch, pattern_name: &str) -> Option<ExtractedEndpoint> {
        let stripped = strip_query_and_fragment(&raw.url);
        if stripped.is_empty() {
            return None;
        }

        let resolved = if stripped.starts_with("http://") || stripped.starts_with("https://") {
            let parsed = Url::parse(&stripped).ok()?;
            let host = parsed.host_str()?.to_lowercase();
            if host != self.base_host {
                return None;
            }
            normalize_url(&stripped)
        } else if stripped.starts_with('/') {
            normalize_url(&format!("{}{stripped}", self.base_url))
        } else {
            return None;
        };

        Some(ExtractedEndpoint {
            url: resolved,
            method: raw.method.clone(),
            source_pattern: pattern_name.to_string(),
        })
    }
}

fn build_patterns() -> Vec<JsPattern> {
    vec![
        JsPattern {
            regex: Regex::new(r#"fetch\(["']([^"']+)["']"#).unwrap(),
            name: "fetch",
            extractor: |caps| {
                Some(RawMatch {
                    url: caps[1].to_string(),
                    method: None,
                })
            },
        },
        JsPattern {
            regex: Regex::new(r#"axios\.(get|post|put|delete|patch)\(["']([^"']+)["']"#).unwrap(),
            name: "axios",
            extractor: |caps| {
                Some(RawMatch {
                    url: caps[2].to_string(),
                    method: Some(caps[1].to_uppercase()),
                })
            },
        },
        JsPattern {
            regex: Regex::new(r#"\.ajax\(\{[^}]*url:\s*["']([^"']+)["']"#).unwrap(),
            name: "jquery_ajax",
            extractor: |caps| {
                Some(RawMatch {
                    url: caps[1].to_string(),
                    method: None,
                })
            },
        },
        JsPattern {
            regex: Regex::new(r#"\.open\(["']([A-Z]+)["'],\s*["']([^"']+)["']"#).unwrap(),
            name: "xmlhttprequest",
            extractor: |caps| {
                Some(RawMatch {
                    url: caps[2].to_string(),
                    method: Some(caps[1].to_string()),
                })
            },
        },
        JsPattern {
            regex: Regex::new(r#"(?:router|app)\.(get|post|put|delete|patch)\(["']([^"']+)["']"#)
                .unwrap(),
            name: "route_definition",
            extractor: |caps| {
                Some(RawMatch {
                    url: caps[2].to_string(),
                    method: Some(caps[1].to_uppercase()),
                })
            },
        },
        JsPattern {
            regex: Regex::new(r#"(https?://[a-zA-Z0-9._-]+(?::\d+)?/[a-zA-Z0-9/_.-]+)"#).unwrap(),
            name: "full_url",
            extractor: |caps| {
                Some(RawMatch {
                    url: caps[1].to_string(),
                    method: None,
                })
            },
        },
        JsPattern {
            regex: Regex::new(r#"["'](/api/[a-zA-Z0-9/_-]+)["']"#).unwrap(),
            name: "api_path_literal",
            extractor: |caps| {
                Some(RawMatch {
                    url: caps[1].to_string(),
                    method: None,
                })
            },
        },
    ]
}

fn strip_query_and_fragment(url: &str) -> String {
    let without_fragment = url.split('#').next().unwrap_or(url);
    without_fragment
        .split('?')
        .next()
        .unwrap_or(without_fragment)
        .to_string()
}

fn normalize_url(url: &str) -> String {
    match Url::parse(url) {
        Ok(mut parsed) => {
            if let Some(host) = parsed.host_str() {
                let lower_host = host.to_lowercase();
                if host != lower_host {
                    let _ = parsed.set_host(Some(&lower_host));
                }
            }
            let mut result = parsed.to_string();
            if result.ends_with('/') && result.len() > 1 {
                result.pop();
            }
            result
        }
        Err(_) => url.to_string(),
    }
}

fn deduplicate(endpoints: Vec<ExtractedEndpoint>) -> Vec<ExtractedEndpoint> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for ep in endpoints {
        if seen.insert(ep.url.clone()) {
            result.push(ep);
        }
    }

    result
}
