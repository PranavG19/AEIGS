use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PersonaId {
    ChromeDesktop,
    FirefoxDesktop,
    SafariDesktop,
    ChromeMobile,
    Googlebot,
    EdgeDesktop,
    OperaDesktop,
    SafariMobile,
    CurlClient,
    PythonRequests,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JitterDistribution {
    Uniform,
    Exponential,
    Normal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Persona {
    pub id: PersonaId,
    pub user_agent: String,
    pub accept_header: String,
    pub accept_language: String,
    pub accept_encoding: String,
    pub sec_fetch_headers: Vec<(String, String)>,
    pub header_order: Vec<String>,
    pub min_request_interval_ms: u64,
    pub max_request_interval_ms: u64,
    pub jitter_distribution: JitterDistribution,
}

impl Persona {
    pub fn custom(id: PersonaId) -> PersonaBuilder {
        PersonaBuilder {
            id,
            user_agent: String::new(),
            accept_header: String::new(),
            accept_language: "en-US,en;q=0.9".to_string(),
            accept_encoding: "gzip, deflate, br".to_string(),
            sec_fetch_headers: Vec::new(),
            header_order: Vec::new(),
            min_request_interval_ms: 500,
            max_request_interval_ms: 2000,
            jitter_distribution: JitterDistribution::Uniform,
        }
    }
}

pub struct PersonaBuilder {
    id: PersonaId,
    user_agent: String,
    accept_header: String,
    accept_language: String,
    accept_encoding: String,
    sec_fetch_headers: Vec<(String, String)>,
    header_order: Vec<String>,
    min_request_interval_ms: u64,
    max_request_interval_ms: u64,
    jitter_distribution: JitterDistribution,
}

impl PersonaBuilder {
    pub fn with_user_agent(mut self, ua: &str) -> Self {
        self.user_agent = ua.to_string();
        self
    }

    pub fn with_accept_header(mut self, accept: &str) -> Self {
        self.accept_header = accept.to_string();
        self
    }

    pub fn with_accept_language(mut self, lang: &str) -> Self {
        self.accept_language = lang.to_string();
        self
    }

    pub fn with_accept_encoding(mut self, encoding: &str) -> Self {
        self.accept_encoding = encoding.to_string();
        self
    }

    pub fn with_sec_fetch_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.sec_fetch_headers = headers;
        self
    }

    pub fn with_header_order(mut self, order: Vec<String>) -> Self {
        self.header_order = order;
        self
    }

    pub fn with_request_interval(mut self, min_ms: u64, max_ms: u64) -> Self {
        self.min_request_interval_ms = min_ms;
        self.max_request_interval_ms = max_ms;
        self
    }

    pub fn with_jitter_distribution(mut self, dist: JitterDistribution) -> Self {
        self.jitter_distribution = dist;
        self
    }

    pub fn build(self) -> Persona {
        Persona {
            id: self.id,
            user_agent: self.user_agent,
            accept_header: self.accept_header,
            accept_language: self.accept_language,
            accept_encoding: self.accept_encoding,
            sec_fetch_headers: self.sec_fetch_headers,
            header_order: self.header_order,
            min_request_interval_ms: self.min_request_interval_ms,
            max_request_interval_ms: self.max_request_interval_ms,
            jitter_distribution: self.jitter_distribution,
        }
    }
}

pub fn persona_catalog() -> Vec<Persona> {
    vec![
        build_chrome_desktop(),
        build_firefox_desktop(),
        build_safari_desktop(),
        build_chrome_mobile(),
        build_googlebot(),
        build_edge_desktop(),
        build_opera_desktop(),
        build_safari_mobile(),
        build_curl_client(),
        build_python_requests(),
    ]
}

fn build_chrome_desktop() -> Persona {
    Persona {
        id: PersonaId::ChromeDesktop,
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string(),
        accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8".to_string(),
        accept_language: "en-US,en;q=0.9".to_string(),
        accept_encoding: "gzip, deflate, br, zstd".to_string(),
        sec_fetch_headers: vec![
            ("Sec-Fetch-Site".to_string(), "none".to_string()),
            ("Sec-Fetch-Mode".to_string(), "navigate".to_string()),
            ("Sec-Fetch-Dest".to_string(), "document".to_string()),
        ],
        header_order: chrome_header_order(),
        min_request_interval_ms: 800,
        max_request_interval_ms: 3000,
        jitter_distribution: JitterDistribution::Normal,
    }
}

fn build_firefox_desktop() -> Persona {
    Persona {
        id: PersonaId::FirefoxDesktop,
        user_agent:
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0"
                .to_string(),
        accept_header:
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
                .to_string(),
        accept_language: "en-US,en;q=0.5".to_string(),
        accept_encoding: "gzip, deflate, br, zstd".to_string(),
        sec_fetch_headers: vec![
            ("Sec-Fetch-Site".to_string(), "none".to_string()),
            ("Sec-Fetch-Mode".to_string(), "navigate".to_string()),
            ("Sec-Fetch-Dest".to_string(), "document".to_string()),
        ],
        header_order: firefox_header_order(),
        min_request_interval_ms: 700,
        max_request_interval_ms: 2500,
        jitter_distribution: JitterDistribution::Normal,
    }
}

fn build_safari_desktop() -> Persona {
    Persona {
        id: PersonaId::SafariDesktop,
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15".to_string(),
        accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string(),
        accept_language: "en-US,en;q=0.9".to_string(),
        accept_encoding: "gzip, deflate, br".to_string(),
        sec_fetch_headers: vec![
            ("Sec-Fetch-Site".to_string(), "none".to_string()),
            ("Sec-Fetch-Mode".to_string(), "navigate".to_string()),
            ("Sec-Fetch-Dest".to_string(), "document".to_string()),
        ],
        header_order: safari_header_order(),
        min_request_interval_ms: 900,
        max_request_interval_ms: 3500,
        jitter_distribution: JitterDistribution::Exponential,
    }
}

fn build_chrome_mobile() -> Persona {
    Persona {
        id: PersonaId::ChromeMobile,
        user_agent: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36".to_string(),
        accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8".to_string(),
        accept_language: "en-US,en;q=0.9".to_string(),
        accept_encoding: "gzip, deflate, br, zstd".to_string(),
        sec_fetch_headers: vec![
            ("Sec-Fetch-Site".to_string(), "none".to_string()),
            ("Sec-Fetch-Mode".to_string(), "navigate".to_string()),
            ("Sec-Fetch-Dest".to_string(), "document".to_string()),
        ],
        header_order: chrome_header_order(),
        min_request_interval_ms: 1000,
        max_request_interval_ms: 4000,
        jitter_distribution: JitterDistribution::Normal,
    }
}

fn build_googlebot() -> Persona {
    Persona {
        id: PersonaId::Googlebot,
        user_agent: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
            .to_string(),
        accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            .to_string(),
        accept_language: "en".to_string(),
        accept_encoding: "gzip, deflate".to_string(),
        sec_fetch_headers: Vec::new(),
        header_order: vec![
            "Host".to_string(),
            "User-Agent".to_string(),
            "Accept".to_string(),
            "Accept-Encoding".to_string(),
        ],
        min_request_interval_ms: 2000,
        max_request_interval_ms: 8000,
        jitter_distribution: JitterDistribution::Exponential,
    }
}

fn build_edge_desktop() -> Persona {
    Persona {
        id: PersonaId::EdgeDesktop,
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0".to_string(),
        accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8".to_string(),
        accept_language: "en-US,en;q=0.9".to_string(),
        accept_encoding: "gzip, deflate, br, zstd".to_string(),
        sec_fetch_headers: vec![
            ("Sec-Fetch-Site".to_string(), "none".to_string()),
            ("Sec-Fetch-Mode".to_string(), "navigate".to_string()),
            ("Sec-Fetch-Dest".to_string(), "document".to_string()),
        ],
        header_order: chrome_header_order(),
        min_request_interval_ms: 800,
        max_request_interval_ms: 3000,
        jitter_distribution: JitterDistribution::Normal,
    }
}

fn build_opera_desktop() -> Persona {
    Persona {
        id: PersonaId::OperaDesktop,
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/116.0.0.0".to_string(),
        accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8".to_string(),
        accept_language: "en-US,en;q=0.9".to_string(),
        accept_encoding: "gzip, deflate, br, zstd".to_string(),
        sec_fetch_headers: vec![
            ("Sec-Fetch-Site".to_string(), "none".to_string()),
            ("Sec-Fetch-Mode".to_string(), "navigate".to_string()),
            ("Sec-Fetch-Dest".to_string(), "document".to_string()),
        ],
        header_order: chrome_header_order(),
        min_request_interval_ms: 700,
        max_request_interval_ms: 2500,
        jitter_distribution: JitterDistribution::Normal,
    }
}

fn build_safari_mobile() -> Persona {
    Persona {
        id: PersonaId::SafariMobile,
        user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1".to_string(),
        accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string(),
        accept_language: "en-US,en;q=0.9".to_string(),
        accept_encoding: "gzip, deflate, br".to_string(),
        sec_fetch_headers: vec![
            ("Sec-Fetch-Site".to_string(), "none".to_string()),
            ("Sec-Fetch-Mode".to_string(), "navigate".to_string()),
            ("Sec-Fetch-Dest".to_string(), "document".to_string()),
        ],
        header_order: safari_header_order(),
        min_request_interval_ms: 1000,
        max_request_interval_ms: 4000,
        jitter_distribution: JitterDistribution::Exponential,
    }
}

fn build_curl_client() -> Persona {
    Persona {
        id: PersonaId::CurlClient,
        user_agent: "curl/8.4.0".to_string(),
        accept_header: "*/*".to_string(),
        accept_language: "en-US,en;q=0.9".to_string(),
        accept_encoding: "gzip, deflate, br".to_string(),
        sec_fetch_headers: Vec::new(),
        header_order: minimal_header_order(),
        min_request_interval_ms: 500,
        max_request_interval_ms: 2000,
        jitter_distribution: JitterDistribution::Uniform,
    }
}

fn build_python_requests() -> Persona {
    Persona {
        id: PersonaId::PythonRequests,
        user_agent: "python-requests/2.31.0".to_string(),
        accept_header: "*/*".to_string(),
        accept_language: "en-US,en;q=0.9".to_string(),
        accept_encoding: "gzip, deflate, br".to_string(),
        sec_fetch_headers: Vec::new(),
        header_order: minimal_header_order(),
        min_request_interval_ms: 500,
        max_request_interval_ms: 2000,
        jitter_distribution: JitterDistribution::Uniform,
    }
}

fn minimal_header_order() -> Vec<String> {
    vec![
        "Host".to_string(),
        "User-Agent".to_string(),
        "Accept".to_string(),
        "Accept-Encoding".to_string(),
    ]
}

fn chrome_header_order() -> Vec<String> {
    vec![
        "Host".to_string(),
        "Connection".to_string(),
        "sec-ch-ua".to_string(),
        "sec-ch-ua-mobile".to_string(),
        "sec-ch-ua-platform".to_string(),
        "Upgrade-Insecure-Requests".to_string(),
        "User-Agent".to_string(),
        "Accept".to_string(),
        "Sec-Fetch-Site".to_string(),
        "Sec-Fetch-Mode".to_string(),
        "Sec-Fetch-Dest".to_string(),
        "Accept-Encoding".to_string(),
        "Accept-Language".to_string(),
    ]
}

fn firefox_header_order() -> Vec<String> {
    vec![
        "Host".to_string(),
        "User-Agent".to_string(),
        "Accept".to_string(),
        "Accept-Language".to_string(),
        "Accept-Encoding".to_string(),
        "Connection".to_string(),
        "Upgrade-Insecure-Requests".to_string(),
        "Sec-Fetch-Dest".to_string(),
        "Sec-Fetch-Mode".to_string(),
        "Sec-Fetch-Site".to_string(),
    ]
}

fn safari_header_order() -> Vec<String> {
    vec![
        "Host".to_string(),
        "Accept".to_string(),
        "User-Agent".to_string(),
        "Accept-Language".to_string(),
        "Accept-Encoding".to_string(),
        "Connection".to_string(),
        "Sec-Fetch-Dest".to_string(),
        "Sec-Fetch-Mode".to_string(),
        "Sec-Fetch-Site".to_string(),
    ]
}

#[cfg(test)]
#[path = "persona_test.rs"]
mod persona_test;
