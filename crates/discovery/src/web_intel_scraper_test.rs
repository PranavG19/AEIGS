use super::web_intel_scraper::*;

#[test]
fn default_config_values() {
    let config = WebIntelConfig::default();
    assert_eq!(config.max_results_per_query, 25);
    assert!(config.search_pastebin);
    assert!(config.search_gists);
    assert!(config.search_news);
    assert!(config.generate_shodan_dorks);
    assert!(config.generate_linkedin_urls);
    assert_eq!(config.timeout_secs, 15);
}

#[test]
fn generate_dork_queries_returns_at_least_15() {
    let dorks = generate_dork_queries("example.com");
    assert!(dorks.len() >= 15, "expected 15+ dorks, got {}", dorks.len());
}

#[test]
fn dork_queries_contain_domain() {
    let dorks = generate_dork_queries("target.org");
    for dork in &dorks {
        assert!(
            dork.query.contains("target.org"),
            "Dork query missing domain: {}",
            dork.query,
        );
    }
}

#[test]
fn dork_queries_cover_all_categories() {
    let dorks = generate_dork_queries("test.com");
    let categories: std::collections::HashSet<DorkCategory> =
        dorks.iter().map(|d| d.category).collect();
    assert!(categories.contains(&DorkCategory::SiteEnumeration));
    assert!(categories.contains(&DorkCategory::FileDiscovery));
    assert!(categories.contains(&DorkCategory::CredentialLeak));
    assert!(categories.contains(&DorkCategory::AdminPanel));
    assert!(categories.contains(&DorkCategory::TechStack));
    assert!(categories.contains(&DorkCategory::SubdomainDiscovery));
    assert!(categories.contains(&DorkCategory::EmailExposure));
}

#[test]
fn email_dork_queries_contain_email() {
    let dorks = generate_email_dork_queries("user@example.com");
    assert!(!dorks.is_empty());
    for dork in &dorks {
        assert!(
            dork.query.contains("user@example.com"),
            "Email dork missing address: {}",
            dork.query,
        );
    }
}

#[test]
fn shodan_dorks_generated_for_domain() {
    let dorks = generate_shodan_dorks("target.com");
    assert!(dorks.len() >= 8, "expected 8+ shodan dorks, got {}", dorks.len());
    for dork in &dorks {
        assert!(
            dork.query.contains("target.com"),
            "Shodan dork missing domain: {}",
            dork.query,
        );
    }
}

#[test]
fn shodan_dorks_include_ssl_and_port_checks() {
    let dorks = generate_shodan_dorks("example.com");
    let queries: Vec<&str> = dorks.iter().map(|d| d.query.as_str()).collect();
    assert!(queries.iter().any(|q| q.contains("ssl.cert")));
    assert!(queries.iter().any(|q| q.contains("port:")));
}

#[test]
fn linkedin_urls_generated() {
    let urls = generate_linkedin_urls("acme.com");
    assert!(urls.len() >= 3);

    let types: Vec<LinkedInSearchType> = urls.iter().map(|u| u.search_type).collect();
    assert!(types.contains(&LinkedInSearchType::CompanyPage));
    assert!(types.contains(&LinkedInSearchType::PeopleByCompany));
    assert!(types.contains(&LinkedInSearchType::JobPostings));
}

#[test]
fn linkedin_urls_contain_company_name() {
    let urls = generate_linkedin_urls("tesla.com");
    for url in &urls {
        assert!(
            url.url.contains("tesla") || url.query_terms.contains("tesla"),
            "LinkedIn URL missing company: {:?}",
            url,
        );
    }
}

#[test]
fn dork_category_display() {
    assert_eq!(DorkCategory::SiteEnumeration.to_string(), "Site Enumeration");
    assert_eq!(DorkCategory::FileDiscovery.to_string(), "File Discovery");
    assert_eq!(DorkCategory::CredentialLeak.to_string(), "Credential Leak");
    assert_eq!(DorkCategory::AdminPanel.to_string(), "Admin Panel");
    assert_eq!(DorkCategory::TechStack.to_string(), "Tech Stack");
}

#[test]
fn search_source_display() {
    assert_eq!(SearchSource::DuckDuckGo.to_string(), "DuckDuckGo");
    assert_eq!(SearchSource::Pastebin.to_string(), "Pastebin");
    assert_eq!(SearchSource::GitHubGist.to_string(), "GitHub Gist");
    assert_eq!(SearchSource::NewsApi.to_string(), "News API");
}

#[test]
fn tech_category_display() {
    assert_eq!(TechCategory::Language.to_string(), "Language");
    assert_eq!(TechCategory::Framework.to_string(), "Framework");
    assert_eq!(TechCategory::Database.to_string(), "Database");
    assert_eq!(TechCategory::Cloud.to_string(), "Cloud");
    assert_eq!(TechCategory::DevOps.to_string(), "DevOps");
}

#[test]
fn web_intel_error_display() {
    assert!(WebIntelError::Network("timeout".into()).to_string().contains("timeout"));
    assert!(WebIntelError::ParseError("bad json".into()).to_string().contains("bad json"));
    assert_eq!(WebIntelError::RateLimited.to_string(), "Rate limited");
}

#[test]
fn scraper_creation() {
    let scraper = WebIntelScraper::new(WebIntelConfig::default());
    assert!(!scraper.tech_patterns.is_empty());
}

#[test]
fn tech_patterns_compile_and_match() {
    let scraper = WebIntelScraper::new(WebIntelConfig::default());
    let test_text = "We use Python and React with PostgreSQL on AWS";
    let mut found = Vec::new();
    for (name, _cat, re) in &scraper.tech_patterns {
        if re.is_match(test_text) {
            found.push(name.clone());
        }
    }
    assert!(found.contains(&"Python".to_string()));
    assert!(found.contains(&"React".to_string()));
    assert!(found.contains(&"PostgreSQL".to_string()));
    assert!(found.contains(&"AWS".to_string()));
}

#[test]
fn tech_mentions_extraction() {
    let scraper = WebIntelScraper::new(WebIntelConfig::default());
    let results = vec![
        SearchResult {
            title: "Jobs at Acme".into(),
            url: "https://acme.com/jobs".into(),
            snippet: "Looking for Python and Django developers with AWS experience".into(),
            source: SearchSource::DuckDuckGo,
        },
        SearchResult {
            title: "Acme Engineering Blog".into(),
            url: "https://acme.com/blog".into(),
            snippet: "Our migration from Python to Rust with Kubernetes".into(),
            source: SearchSource::DuckDuckGo,
        },
    ];
    let mentions = scraper.extract_tech_mentions(&results);
    let tech_names: Vec<&str> = mentions.iter().map(|m| m.technology.as_str()).collect();
    assert!(tech_names.contains(&"Python"));
    assert!(tech_names.contains(&"AWS"));

    let python = mentions.iter().find(|m| m.technology == "Python").unwrap();
    assert_eq!(python.mention_count, 2);
}

#[test]
fn web_intelligence_serialization() {
    let intel = WebIntelligence {
        target: "example.com".into(),
        dork_queries: vec![DorkQuery {
            query: "site:example.com".into(),
            category: DorkCategory::SiteEnumeration,
            description: "test".into(),
        }],
        search_results: Vec::new(),
        shodan_dorks: Vec::new(),
        linkedin_urls: Vec::new(),
        tech_mentions: Vec::new(),
        paste_results: Vec::new(),
        news_results: Vec::new(),
    };
    let json = serde_json::to_string(&intel).unwrap();
    assert!(json.contains("example.com"));
}

#[test]
fn search_result_serialization_roundtrip() {
    let result = SearchResult {
        title: "Test Page".into(),
        url: "https://example.com/test".into(),
        snippet: "A test search result".into(),
        source: SearchSource::DuckDuckGo,
    };
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: SearchResult = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.title, "Test Page");
    assert_eq!(deserialized.source, SearchSource::DuckDuckGo);
}

#[test]
fn shodan_dork_serialization() {
    let dork = ShodanDork {
        query: "hostname:test.com".into(),
        description: "test".into(),
        expected_results: "IPs".into(),
    };
    let json = serde_json::to_string(&dork).unwrap();
    let deserialized: ShodanDork = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.query, "hostname:test.com");
}

#[test]
fn dork_queries_include_file_types() {
    let dorks = generate_dork_queries("target.com");
    let file_dorks: Vec<&DorkQuery> = dorks
        .iter()
        .filter(|d| d.category == DorkCategory::FileDiscovery)
        .collect();
    assert!(file_dorks.len() >= 3, "expected 3+ file discovery dorks");
    let all_queries: String = file_dorks.iter().map(|d| d.query.as_str()).collect::<Vec<_>>().join(" ");
    assert!(all_queries.contains("pdf"));
    assert!(all_queries.contains("doc"));
}

#[tokio::test]
async fn scrape_domain_runs_without_panic() {
    let config = WebIntelConfig {
        timeout_secs: 2,
        delay_between_ms: 0,
        search_pastebin: false,
        search_gists: false,
        search_news: false,
        generate_shodan_dorks: true,
        generate_linkedin_urls: true,
        ..WebIntelConfig::default()
    };
    let scraper = WebIntelScraper::new(config);
    let result = scraper.scrape_domain("nonexistent-test-domain.invalid").await;
    assert_eq!(result.target, "nonexistent-test-domain.invalid");
    assert!(!result.dork_queries.is_empty());
    assert!(!result.shodan_dorks.is_empty());
    assert!(!result.linkedin_urls.is_empty());
}
