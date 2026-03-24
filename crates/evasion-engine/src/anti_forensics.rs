use std::collections::{HashMap, HashSet};

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// Scanner signature patterns that forensic analysis looks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScannerSignature {
    ToolSpecificUserAgent,
    SequentialParameterOrdering,
    KnownScannerUrlPattern,
    ScannerSpecificCookie,
    ScannerSpecificHeader,
    AbnormalHeaderOrdering,
}

impl std::fmt::Display for ScannerSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ToolSpecificUserAgent => write!(f, "tool-specific-user-agent"),
            Self::SequentialParameterOrdering => write!(f, "sequential-param-ordering"),
            Self::KnownScannerUrlPattern => write!(f, "known-scanner-url-pattern"),
            Self::ScannerSpecificCookie => write!(f, "scanner-specific-cookie"),
            Self::ScannerSpecificHeader => write!(f, "scanner-specific-header"),
            Self::AbnormalHeaderOrdering => write!(f, "abnormal-header-ordering"),
        }
    }
}

/// A cleaned request with forensic artifacts removed.
#[derive(Debug, Clone)]
pub struct CleanedRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub parameters: Vec<(String, String)>,
    pub signatures_removed: Vec<ScannerSignature>,
}

/// Configuration for the anti-forensics module.
#[derive(Debug, Clone)]
pub struct AntiForensicsConfig {
    pub clean_user_agent: bool,
    pub randomize_param_order: bool,
    pub mimic_crawler: Option<CrawlerMimicry>,
    pub sanitize_logs: bool,
    pub browser_header_order: bool,
}

impl Default for AntiForensicsConfig {
    fn default() -> Self {
        Self {
            clean_user_agent: true,
            randomize_param_order: true,
            mimic_crawler: None,
            sanitize_logs: true,
            browser_header_order: true,
        }
    }
}

impl AntiForensicsConfig {
    pub fn with_crawler_mimicry(mut self, crawler: CrawlerMimicry) -> Self {
        self.mimic_crawler = Some(crawler);
        self
    }

    pub fn with_sanitize_logs(mut self, enabled: bool) -> Self {
        self.sanitize_logs = enabled;
        self
    }
}

/// Legitimate crawler to mimic for cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrawlerMimicry {
    Googlebot,
    Bingbot,
    Yandexbot,
    DuckDuckBot,
}

impl CrawlerMimicry {
    pub fn user_agent(&self) -> &'static str {
        match self {
            Self::Googlebot => {
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
            }
            Self::Bingbot => {
                "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
            }
            Self::Yandexbot => "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
            Self::DuckDuckBot => "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)",
        }
    }

    pub fn header_order(&self) -> Vec<&'static str> {
        match self {
            Self::Googlebot | Self::Bingbot => vec![
                "Host",
                "Connection",
                "User-Agent",
                "Accept",
                "Accept-Encoding",
                "Accept-Language",
                "From",
            ],
            Self::Yandexbot | Self::DuckDuckBot => {
                vec!["Host", "User-Agent", "Accept", "Accept-Encoding"]
            }
        }
    }
}

/// Known scanner-specific URL patterns to avoid.
const SCANNER_URL_PATTERNS: &[&str] = &[
    "/wp-admin/admin-ajax.php?action=",
    "/.env",
    "/actuator/health",
    "/config.php.bak",
    "/phpinfo.php",
    "/server-status",
    "/elmah.axd",
    "/__debug__/",
    "/telescope/",
];

/// Known scanner-specific header names.
const SCANNER_HEADERS: &[&str] = &[
    "X-Scanner",
    "X-Scan-Id",
    "X-Burp-Token",
    "X-ZAP-Scan",
    "X-Nikto-Version",
    "X-Sqlmap-Token",
    "X-Acunetix",
];

/// Known scanner-specific User-Agent substrings.
const SCANNER_UA_SIGNATURES: &[&str] = &[
    "sqlmap",
    "nikto",
    "nessus",
    "nmap",
    "burpsuite",
    "acunetix",
    "w3af",
    "skipfish",
    "arachni",
    "wfuzz",
    "dirbuster",
    "gobuster",
    "feroxbuster",
    "nuclei",
    "masscan",
    "zgrab",
];

/// Anti-forensics module that minimizes forensic evidence of scanning.
///
/// Cleans User-Agent strings, randomizes parameter ordering, avoids
/// scanner-specific URL patterns, mimics legitimate crawlers, enforces
/// real browser header ordering, and sanitizes scan logs.
pub struct AntiForensics {
    config: AntiForensicsConfig,
    rng: StdRng,
}

impl AntiForensics {
    pub fn new(config: AntiForensicsConfig) -> Self {
        Self {
            config,
            rng: StdRng::from_os_rng(),
        }
    }

    pub fn with_seed(config: AntiForensicsConfig, seed: u64) -> Self {
        Self {
            config,
            rng: StdRng::seed_from_u64(seed),
        }
    }

    /// Cleans a request by removing scanner signatures and applying
    /// anti-forensic transforms.
    pub fn clean_request(
        &mut self,
        url: &str,
        method: &str,
        headers: &[(String, String)],
        parameters: &[(String, String)],
    ) -> CleanedRequest {
        let mut signatures_removed = Vec::new();

        let cleaned_headers = self.clean_headers(headers, &mut signatures_removed);
        let cleaned_params = self.randomize_parameters(parameters, &mut signatures_removed);
        let cleaned_url = self.clean_url(url, &mut signatures_removed);

        CleanedRequest {
            url: cleaned_url,
            method: method.to_string(),
            headers: cleaned_headers,
            parameters: cleaned_params,
            signatures_removed,
        }
    }

    /// Checks a User-Agent string for known scanner signatures.
    pub fn is_scanner_ua(&self, user_agent: &str) -> bool {
        let lower = user_agent.to_lowercase();
        SCANNER_UA_SIGNATURES.iter().any(|sig| lower.contains(sig))
    }

    /// Checks whether a URL contains known scanner-specific patterns.
    pub fn is_scanner_url_pattern(&self, url: &str) -> bool {
        let lower = url.to_lowercase();
        SCANNER_URL_PATTERNS
            .iter()
            .any(|pat| lower.contains(&pat.to_lowercase()))
    }

    /// Sanitizes a log entry by redacting target-specific data.
    pub fn sanitize_log_entry(&self, entry: &str) -> String {
        if !self.config.sanitize_logs {
            return entry.to_string();
        }
        let mut sanitized = entry.to_string();

        sanitized = redact_ip_addresses(&sanitized);

        for keyword in &[
            "password", "token", "cookie", "session", "secret", "api_key",
        ] {
            loop {
                let lower = sanitized.to_lowercase();
                if let Some(pos) = lower.find(keyword) {
                    let end = sanitized[pos..]
                        .find(' ')
                        .map_or(sanitized.len(), |p| pos + p);
                    sanitized.replace_range(pos..end, "[REDACTED]");
                } else {
                    break;
                }
            }
        }
        sanitized
    }

    /// Returns the browser-matching header order for the configured crawler or default Chrome.
    pub fn browser_header_order(&self) -> Vec<&'static str> {
        if let Some(crawler) = &self.config.mimic_crawler {
            return crawler.header_order();
        }
        vec![
            "Host",
            "Connection",
            "Cache-Control",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "Upgrade-Insecure-Requests",
            "User-Agent",
            "Accept",
            "Sec-Fetch-Site",
            "Sec-Fetch-Mode",
            "Sec-Fetch-User",
            "Sec-Fetch-Dest",
            "Accept-Encoding",
            "Accept-Language",
        ]
    }

    fn clean_headers(
        &self,
        headers: &[(String, String)],
        removed: &mut Vec<ScannerSignature>,
    ) -> Vec<(String, String)> {
        let scanner_header_set: HashSet<String> =
            SCANNER_HEADERS.iter().map(|h| h.to_lowercase()).collect();

        let mut cleaned: Vec<(String, String)> = headers
            .iter()
            .filter(|(name, _)| {
                if scanner_header_set.contains(&name.to_lowercase()) {
                    removed.push(ScannerSignature::ScannerSpecificHeader);
                    false
                } else {
                    true
                }
            })
            .cloned()
            .collect();

        if self.config.clean_user_agent {
            for (name, value) in &mut cleaned {
                if name.to_lowercase() == "user-agent" && self.is_scanner_ua(value) {
                    if let Some(crawler) = &self.config.mimic_crawler {
                        *value = crawler.user_agent().to_string();
                    } else {
                        *value = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36".to_string();
                    }
                    removed.push(ScannerSignature::ToolSpecificUserAgent);
                }
            }
        }

        if self.config.browser_header_order {
            let order = self.browser_header_order();
            let order_map: HashMap<String, usize> = order
                .iter()
                .enumerate()
                .map(|(i, h)| (h.to_lowercase(), i))
                .collect();
            cleaned.sort_by_key(|(name, _)| {
                order_map.get(&name.to_lowercase()).copied().unwrap_or(999)
            });
        }

        cleaned
    }

    fn randomize_parameters(
        &mut self,
        parameters: &[(String, String)],
        removed: &mut Vec<ScannerSignature>,
    ) -> Vec<(String, String)> {
        if !self.config.randomize_param_order || parameters.len() <= 1 {
            return parameters.to_vec();
        }

        let mut params = parameters.to_vec();
        let len = params.len();
        for i in (1..len).rev() {
            let j = self.rng.random_range(0..=i);
            params.swap(i, j);
        }
        removed.push(ScannerSignature::SequentialParameterOrdering);
        params
    }

    fn clean_url(&self, url: &str, removed: &mut Vec<ScannerSignature>) -> String {
        if self.is_scanner_url_pattern(url) {
            removed.push(ScannerSignature::KnownScannerUrlPattern);
        }
        url.to_string()
    }
}

/// Naively redacts sequences that look like IPv4 addresses (N.N.N.N).
fn redact_ip_addresses(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            let start = i;
            let mut dots = 0;
            let mut j = i;
            while j < chars.len() && (chars[j].is_ascii_digit() || chars[j] == '.') {
                if chars[j] == '.' {
                    dots += 1;
                }
                j += 1;
            }
            if dots >= 3 && j > start + 6 {
                result.push_str("[REDACTED_IP]");
                i = j;
                continue;
            }
        }
        result.push(chars[i]);
        i += 1;
    }
    result
}

#[cfg(test)]
#[path = "anti_forensics_test.rs"]
mod anti_forensics_test;
