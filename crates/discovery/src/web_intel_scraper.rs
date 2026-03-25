use std::collections::HashMap;
use std::time::Duration;

use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};

/// A Google dork query and its purpose.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DorkQuery {
    pub query: String,
    pub category: DorkCategory,
    pub description: String,
}

/// Categories of Google dork queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DorkCategory {
    SiteEnumeration,
    FileDiscovery,
    EmailExposure,
    CredentialLeak,
    AdminPanel,
    SensitiveDirectory,
    TechStack,
    SubdomainDiscovery,
}

impl std::fmt::Display for DorkCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SiteEnumeration => write!(f, "Site Enumeration"),
            Self::FileDiscovery => write!(f, "File Discovery"),
            Self::EmailExposure => write!(f, "Email Exposure"),
            Self::CredentialLeak => write!(f, "Credential Leak"),
            Self::AdminPanel => write!(f, "Admin Panel"),
            Self::SensitiveDirectory => write!(f, "Sensitive Directory"),
            Self::TechStack => write!(f, "Tech Stack"),
            Self::SubdomainDiscovery => write!(f, "Subdomain Discovery"),
        }
    }
}

/// A single search result from any search engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub title: String,
    pub url: String,
    pub snippet: String,
    pub source: SearchSource,
}

/// Where a search result came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SearchSource {
    DuckDuckGo,
    Pastebin,
    GitHubGist,
    WaybackMachine,
    LinkedIn,
    NewsApi,
}

impl std::fmt::Display for SearchSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuckDuckGo => write!(f, "DuckDuckGo"),
            Self::Pastebin => write!(f, "Pastebin"),
            Self::GitHubGist => write!(f, "GitHub Gist"),
            Self::WaybackMachine => write!(f, "Wayback Machine"),
            Self::LinkedIn => write!(f, "LinkedIn"),
            Self::NewsApi => write!(f, "News API"),
        }
    }
}

/// A Shodan-compatible dork string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanDork {
    pub query: String,
    pub description: String,
    pub expected_results: String,
}

/// LinkedIn profile URL generated from name/company.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkedInSearchUrl {
    pub url: String,
    pub search_type: LinkedInSearchType,
    pub query_terms: String,
}

/// Type of LinkedIn search.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkedInSearchType {
    PeopleByName,
    PeopleByCompany,
    CompanyPage,
    JobPostings,
}

/// Extracted tech stack mention from job postings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechMention {
    pub technology: String,
    pub category: TechCategory,
    pub mention_count: u32,
    pub source_urls: Vec<String>,
}

/// Category of a technology mention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TechCategory {
    Language,
    Framework,
    Database,
    Cloud,
    DevOps,
    Security,
    Other,
}

impl std::fmt::Display for TechCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Language => write!(f, "Language"),
            Self::Framework => write!(f, "Framework"),
            Self::Database => write!(f, "Database"),
            Self::Cloud => write!(f, "Cloud"),
            Self::DevOps => write!(f, "DevOps"),
            Self::Security => write!(f, "Security"),
            Self::Other => write!(f, "Other"),
        }
    }
}

/// Aggregated web intelligence for a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebIntelligence {
    pub target: String,
    pub dork_queries: Vec<DorkQuery>,
    pub search_results: Vec<SearchResult>,
    pub shodan_dorks: Vec<ShodanDork>,
    pub linkedin_urls: Vec<LinkedInSearchUrl>,
    pub tech_mentions: Vec<TechMention>,
    pub paste_results: Vec<SearchResult>,
    pub news_results: Vec<SearchResult>,
}

/// Configuration for the web intelligence scraper.
#[derive(Debug, Clone)]
pub struct WebIntelConfig {
    pub max_results_per_query: usize,
    pub search_pastebin: bool,
    pub search_gists: bool,
    pub search_news: bool,
    pub generate_shodan_dorks: bool,
    pub generate_linkedin_urls: bool,
    pub timeout_secs: u64,
    pub delay_between_ms: u64,
    pub user_agent: String,
}

impl Default for WebIntelConfig {
    fn default() -> Self {
        Self {
            max_results_per_query: 25,
            search_pastebin: true,
            search_gists: true,
            search_news: true,
            generate_shodan_dorks: true,
            generate_linkedin_urls: true,
            timeout_secs: 15,
            delay_between_ms: 500,
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".into(),
        }
    }
}

/// The main web intelligence scraper.
pub struct WebIntelScraper {
    pub client: reqwest::Client,
    pub config: WebIntelConfig,
    pub tech_patterns: Vec<(String, TechCategory, Regex)>,
}

impl WebIntelScraper {
    pub fn new(config: WebIntelConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .expect("failed to build HTTP client");

        let tech_patterns = build_tech_patterns();

        Self {
            client,
            config,
            tech_patterns,
        }
    }

    /// Scrape web intelligence for a domain target.
    pub async fn scrape_domain(&self, domain: &str) -> WebIntelligence {
        let dork_queries = generate_dork_queries(domain);

        let mut search_results = Vec::new();
        for dork in &dork_queries {
            if let Ok(results) = self.search_duckduckgo(&dork.query).await {
                search_results.extend(results);
            }
            if self.config.delay_between_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.config.delay_between_ms)).await;
            }
        }

        let paste_results = if self.config.search_pastebin || self.config.search_gists {
            self.search_paste_sites(domain).await
        } else {
            Vec::new()
        };

        let news_results = if self.config.search_news {
            self.search_news(domain).await.unwrap_or_default()
        } else {
            Vec::new()
        };

        let shodan_dorks = if self.config.generate_shodan_dorks {
            generate_shodan_dorks(domain)
        } else {
            Vec::new()
        };

        let linkedin_urls = if self.config.generate_linkedin_urls {
            generate_linkedin_urls(domain)
        } else {
            Vec::new()
        };

        let tech_mentions = self.extract_tech_mentions(&search_results);

        WebIntelligence {
            target: domain.to_string(),
            dork_queries,
            search_results,
            shodan_dorks,
            linkedin_urls,
            tech_mentions,
            paste_results,
            news_results,
        }
    }

    /// Scrape web intelligence for an email target.
    pub async fn scrape_email(&self, email: &str) -> WebIntelligence {
        let dork_queries = generate_email_dork_queries(email);

        let mut search_results = Vec::new();
        for dork in &dork_queries {
            if let Ok(results) = self.search_duckduckgo(&dork.query).await {
                search_results.extend(results);
            }
            if self.config.delay_between_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.config.delay_between_ms)).await;
            }
        }

        let paste_results = if self.config.search_pastebin || self.config.search_gists {
            self.search_paste_sites(email).await
        } else {
            Vec::new()
        };

        WebIntelligence {
            target: email.to_string(),
            dork_queries,
            search_results,
            shodan_dorks: Vec::new(),
            linkedin_urls: Vec::new(),
            tech_mentions: Vec::new(),
            paste_results,
            news_results: Vec::new(),
        }
    }

    async fn search_duckduckgo(&self, query: &str) -> Result<Vec<SearchResult>, String> {
        let encoded = url::form_urlencoded::byte_serialize(query.as_bytes()).collect::<String>();
        let url = format!("https://api.duckduckgo.com/?q={encoded}&format=json&no_html=1&skip_disambig=1");

        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_str(&self.config.user_agent)
            .unwrap_or_else(|_| HeaderValue::from_static("Mozilla/5.0")));

        let resp = self.client.get(&url).headers(headers).send().await.map_err(|e| e.to_string())?;
        let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;

        let mut results = Vec::new();

        if let Some(abstract_text) = json.get("AbstractText").and_then(|v| v.as_str()) {
            if !abstract_text.is_empty() {
                results.push(SearchResult {
                    title: json.get("Heading").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    url: json.get("AbstractURL").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    snippet: abstract_text.to_string(),
                    source: SearchSource::DuckDuckGo,
                });
            }
        }

        if let Some(related) = json.get("RelatedTopics").and_then(|v| v.as_array()) {
            for topic in related.iter().take(self.config.max_results_per_query) {
                if let Some(text) = topic.get("Text").and_then(|v| v.as_str()) {
                    results.push(SearchResult {
                        title: text.chars().take(100).collect(),
                        url: topic.get("FirstURL").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        snippet: text.to_string(),
                        source: SearchSource::DuckDuckGo,
                    });
                }
            }
        }

        Ok(results)
    }

    async fn search_paste_sites(&self, query: &str) -> Vec<SearchResult> {
        let mut results = Vec::new();

        if self.config.search_gists {
            let encoded = url::form_urlencoded::byte_serialize(query.as_bytes()).collect::<String>();
            let url = format!("https://gist.github.com/search?q={encoded}");
            results.push(SearchResult {
                title: format!("GitHub Gist search: {query}"),
                url,
                snippet: format!("Search GitHub Gists for mentions of {query}"),
                source: SearchSource::GitHubGist,
            });
        }

        if self.config.search_pastebin {
            let encoded = url::form_urlencoded::byte_serialize(query.as_bytes()).collect::<String>();
            let url = format!("https://pastebin.com/search?q={encoded}");
            results.push(SearchResult {
                title: format!("Pastebin search: {query}"),
                url,
                snippet: format!("Search Pastebin for mentions of {query}"),
                source: SearchSource::Pastebin,
            });
        }

        results
    }

    async fn search_news(&self, query: &str) -> Result<Vec<SearchResult>, String> {
        let encoded = url::form_urlencoded::byte_serialize(query.as_bytes()).collect::<String>();
        let url = format!("https://api.duckduckgo.com/?q={encoded}+news&format=json&no_html=1");

        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_str(&self.config.user_agent)
            .unwrap_or_else(|_| HeaderValue::from_static("Mozilla/5.0")));

        let resp = self.client.get(&url).headers(headers).send().await.map_err(|e| e.to_string())?;
        let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;

        let mut results = Vec::new();
        if let Some(related) = json.get("RelatedTopics").and_then(|v| v.as_array()) {
            for topic in related.iter().take(10) {
                if let Some(text) = topic.get("Text").and_then(|v| v.as_str()) {
                    results.push(SearchResult {
                        title: text.chars().take(100).collect(),
                        url: topic.get("FirstURL").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        snippet: text.to_string(),
                        source: SearchSource::NewsApi,
                    });
                }
            }
        }

        Ok(results)
    }

    pub fn extract_tech_mentions(&self, results: &[SearchResult]) -> Vec<TechMention> {
        let mut counts: HashMap<String, (TechCategory, u32, Vec<String>)> = HashMap::new();

        for result in results {
            let combined = format!("{} {}", result.title, result.snippet);
            for (tech_name, category, regex) in &self.tech_patterns {
                if regex.is_match(&combined) {
                    let entry = counts.entry(tech_name.clone()).or_insert((*category, 0, Vec::new()));
                    entry.1 += 1;
                    if entry.2.len() < 5 && !result.url.is_empty() {
                        entry.2.push(result.url.clone());
                    }
                }
            }
        }

        let mut mentions: Vec<TechMention> = counts
            .into_iter()
            .map(|(tech, (cat, count, urls))| TechMention {
                technology: tech,
                category: cat,
                mention_count: count,
                source_urls: urls,
            })
            .collect();

        mentions.sort_by(|a, b| b.mention_count.cmp(&a.mention_count));
        mentions
    }
}

/// Generate Google dork queries for a domain.
pub fn generate_dork_queries(domain: &str) -> Vec<DorkQuery> {
    vec![
        DorkQuery {
            query: format!("site:{domain}"),
            category: DorkCategory::SiteEnumeration,
            description: format!("All indexed pages for {domain}"),
        },
        DorkQuery {
            query: format!("site:{domain} filetype:pdf"),
            category: DorkCategory::FileDiscovery,
            description: "Public PDF documents".into(),
        },
        DorkQuery {
            query: format!("site:{domain} filetype:doc OR filetype:docx"),
            category: DorkCategory::FileDiscovery,
            description: "Public Word documents".into(),
        },
        DorkQuery {
            query: format!("site:{domain} filetype:xls OR filetype:xlsx"),
            category: DorkCategory::FileDiscovery,
            description: "Public spreadsheets".into(),
        },
        DorkQuery {
            query: format!("site:{domain} filetype:sql"),
            category: DorkCategory::CredentialLeak,
            description: "SQL database dumps".into(),
        },
        DorkQuery {
            query: format!("site:{domain} filetype:env"),
            category: DorkCategory::CredentialLeak,
            description: "Exposed .env configuration files".into(),
        },
        DorkQuery {
            query: format!("site:{domain} filetype:log"),
            category: DorkCategory::SensitiveDirectory,
            description: "Exposed log files".into(),
        },
        DorkQuery {
            query: format!("site:{domain} inurl:admin"),
            category: DorkCategory::AdminPanel,
            description: "Admin panel pages".into(),
        },
        DorkQuery {
            query: format!("site:{domain} inurl:login"),
            category: DorkCategory::AdminPanel,
            description: "Login pages".into(),
        },
        DorkQuery {
            query: format!("site:{domain} inurl:wp-admin OR inurl:wp-login"),
            category: DorkCategory::AdminPanel,
            description: "WordPress admin pages".into(),
        },
        DorkQuery {
            query: format!("site:{domain} intitle:\"index of /\""),
            category: DorkCategory::SensitiveDirectory,
            description: "Open directory listings".into(),
        },
        DorkQuery {
            query: format!("site:{domain} ext:xml | ext:conf | ext:cfg | ext:ini"),
            category: DorkCategory::SensitiveDirectory,
            description: "Exposed configuration files".into(),
        },
        DorkQuery {
            query: format!("site:{domain} \"password\" | \"passwd\" | \"pwd\""),
            category: DorkCategory::CredentialLeak,
            description: "Pages containing password references".into(),
        },
        DorkQuery {
            query: format!("site:{domain} inurl:api"),
            category: DorkCategory::TechStack,
            description: "API endpoints".into(),
        },
        DorkQuery {
            query: format!("site:{domain} inurl:swagger OR inurl:api-docs"),
            category: DorkCategory::TechStack,
            description: "Swagger/OpenAPI documentation".into(),
        },
        DorkQuery {
            query: format!("site:*.{domain}"),
            category: DorkCategory::SubdomainDiscovery,
            description: "Subdomain enumeration via search".into(),
        },
        DorkQuery {
            query: format!("\"@{domain}\" email"),
            category: DorkCategory::EmailExposure,
            description: "Email addresses with this domain".into(),
        },
        DorkQuery {
            query: format!("site:{domain} filetype:bak OR filetype:old"),
            category: DorkCategory::FileDiscovery,
            description: "Backup files".into(),
        },
        DorkQuery {
            query: format!("site:{domain} inurl:.git"),
            category: DorkCategory::CredentialLeak,
            description: "Exposed git repositories".into(),
        },
        DorkQuery {
            query: format!("site:{domain} \"phpinfo()\""),
            category: DorkCategory::TechStack,
            description: "Exposed PHP info pages".into(),
        },
    ]
}

/// Generate dork queries for an email target.
pub fn generate_email_dork_queries(email: &str) -> Vec<DorkQuery> {
    vec![
        DorkQuery {
            query: format!("\"{email}\""),
            category: DorkCategory::EmailExposure,
            description: "Pages mentioning this email".into(),
        },
        DorkQuery {
            query: format!("\"{email}\" filetype:pdf"),
            category: DorkCategory::FileDiscovery,
            description: "PDFs containing this email".into(),
        },
        DorkQuery {
            query: format!("\"{email}\" password OR leak OR dump"),
            category: DorkCategory::CredentialLeak,
            description: "Potential credential leaks".into(),
        },
        DorkQuery {
            query: format!("\"{email}\" site:pastebin.com"),
            category: DorkCategory::CredentialLeak,
            description: "Pastebin mentions".into(),
        },
        DorkQuery {
            query: format!("\"{email}\" site:github.com"),
            category: DorkCategory::EmailExposure,
            description: "GitHub mentions".into(),
        },
    ]
}

/// Generate Shodan dork strings for a domain.
pub fn generate_shodan_dorks(domain: &str) -> Vec<ShodanDork> {
    vec![
        ShodanDork {
            query: format!("hostname:{domain}"),
            description: "All hosts with this hostname".into(),
            expected_results: "IP addresses, ports, services".into(),
        },
        ShodanDork {
            query: format!("ssl.cert.subject.CN:{domain}"),
            description: "Hosts with SSL certs for this domain".into(),
            expected_results: "HTTPS services, certificate details".into(),
        },
        ShodanDork {
            query: format!("http.title:\"{domain}\""),
            description: "Web servers mentioning domain in title".into(),
            expected_results: "Web applications, landing pages".into(),
        },
        ShodanDork {
            query: format!("org:\"{domain}\" port:22"),
            description: "SSH servers in this organization".into(),
            expected_results: "SSH endpoints, version info".into(),
        },
        ShodanDork {
            query: format!("hostname:{domain} port:3306 OR port:5432 OR port:27017"),
            description: "Exposed databases".into(),
            expected_results: "MySQL, PostgreSQL, MongoDB endpoints".into(),
        },
        ShodanDork {
            query: format!("hostname:{domain} port:9200"),
            description: "Exposed Elasticsearch".into(),
            expected_results: "Elasticsearch clusters".into(),
        },
        ShodanDork {
            query: format!("hostname:{domain} port:6379"),
            description: "Exposed Redis".into(),
            expected_results: "Redis instances".into(),
        },
        ShodanDork {
            query: format!("hostname:{domain} \"Server: Apache\" OR \"Server: nginx\""),
            description: "Web server technology".into(),
            expected_results: "Web server types and versions".into(),
        },
        ShodanDork {
            query: format!("ssl.cert.subject.CN:{domain} has_screenshot:true"),
            description: "Hosts with screenshots available".into(),
            expected_results: "Visual reconnaissance of web services".into(),
        },
        ShodanDork {
            query: format!("hostname:{domain} vuln:CVE-*"),
            description: "Known vulnerable hosts".into(),
            expected_results: "CVEs affecting this domain's hosts".into(),
        },
    ]
}

/// Generate LinkedIn search URLs for a domain/company.
pub fn generate_linkedin_urls(domain: &str) -> Vec<LinkedInSearchUrl> {
    let company = domain.split('.').next().unwrap_or(domain);
    let encoded_company = url::form_urlencoded::byte_serialize(company.as_bytes()).collect::<String>();

    vec![
        LinkedInSearchUrl {
            url: format!("https://www.linkedin.com/company/{company}"),
            search_type: LinkedInSearchType::CompanyPage,
            query_terms: company.to_string(),
        },
        LinkedInSearchUrl {
            url: format!("https://www.linkedin.com/search/results/people/?keywords={encoded_company}"),
            search_type: LinkedInSearchType::PeopleByCompany,
            query_terms: company.to_string(),
        },
        LinkedInSearchUrl {
            url: format!("https://www.linkedin.com/jobs/search/?keywords={encoded_company}"),
            search_type: LinkedInSearchType::JobPostings,
            query_terms: company.to_string(),
        },
    ]
}

fn build_tech_patterns() -> Vec<(String, TechCategory, Regex)> {
    let raw: Vec<(&str, TechCategory, &str)> = vec![
        ("Python", TechCategory::Language, r"(?i)\bpython\b"),
        ("JavaScript", TechCategory::Language, r"(?i)\bjavascript\b"),
        ("TypeScript", TechCategory::Language, r"(?i)\btypescript\b"),
        ("Rust", TechCategory::Language, r"(?i)\brust\b"),
        ("Go", TechCategory::Language, r"(?i)\bgolang\b|\bgo\s+lang"),
        ("Java", TechCategory::Language, r"(?i)\bjava\b"),
        ("C#", TechCategory::Language, r"(?i)\bc#\b|\.net"),
        ("Ruby", TechCategory::Language, r"(?i)\bruby\b"),
        ("PHP", TechCategory::Language, r"(?i)\bphp\b"),
        ("Swift", TechCategory::Language, r"(?i)\bswift\b"),
        ("Kotlin", TechCategory::Language, r"(?i)\bkotlin\b"),
        ("React", TechCategory::Framework, r"(?i)\breact\.?js\b|\breact\b"),
        ("Angular", TechCategory::Framework, r"(?i)\bangular\b"),
        ("Vue", TechCategory::Framework, r"(?i)\bvue\.?js\b|\bvue\b"),
        ("Django", TechCategory::Framework, r"(?i)\bdjango\b"),
        ("Flask", TechCategory::Framework, r"(?i)\bflask\b"),
        ("Rails", TechCategory::Framework, r"(?i)\bruby on rails\b|\brails\b"),
        ("Spring", TechCategory::Framework, r"(?i)\bspring\s*(boot)?\b"),
        ("Express", TechCategory::Framework, r"(?i)\bexpress\.?js\b|\bexpress\b"),
        ("Next.js", TechCategory::Framework, r"(?i)\bnext\.?js\b"),
        ("PostgreSQL", TechCategory::Database, r"(?i)\bpostgres(ql)?\b"),
        ("MySQL", TechCategory::Database, r"(?i)\bmysql\b"),
        ("MongoDB", TechCategory::Database, r"(?i)\bmongodb\b|\bmongo\b"),
        ("Redis", TechCategory::Database, r"(?i)\bredis\b"),
        ("Elasticsearch", TechCategory::Database, r"(?i)\belasticsearch\b|\belastic\b"),
        ("AWS", TechCategory::Cloud, r"(?i)\baws\b|\bamazon web services\b"),
        ("Azure", TechCategory::Cloud, r"(?i)\bazure\b"),
        ("GCP", TechCategory::Cloud, r"(?i)\bgcp\b|\bgoogle cloud\b"),
        ("Docker", TechCategory::DevOps, r"(?i)\bdocker\b"),
        ("Kubernetes", TechCategory::DevOps, r"(?i)\bkubernetes\b|\bk8s\b"),
        ("Terraform", TechCategory::DevOps, r"(?i)\bterraform\b"),
        ("Jenkins", TechCategory::DevOps, r"(?i)\bjenkins\b"),
        ("GitHub Actions", TechCategory::DevOps, r"(?i)\bgithub actions\b"),
    ];

    raw.into_iter()
        .filter_map(|(name, cat, pattern)| {
            Regex::new(pattern).ok().map(|re| (name.to_string(), cat, re))
        })
        .collect()
}

/// Errors from the web intelligence scraper.
#[derive(Debug, Clone)]
pub enum WebIntelError {
    Network(String),
    ParseError(String),
    RateLimited,
}

impl std::fmt::Display for WebIntelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(e) => write!(f, "Network error: {e}"),
            Self::ParseError(e) => write!(f, "Parse error: {e}"),
            Self::RateLimited => write!(f, "Rate limited"),
        }
    }
}

impl std::error::Error for WebIntelError {}
