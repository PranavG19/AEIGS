use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier};

use crate::sitemap_parser::{
    RobotsResult, SitemapResult, parse_robots_txt, parse_sitemap_xml, sitemap_results_to_operations,
};

#[test]
fn robots_parses_disallow_directives() {
    let content = "User-agent: *\nDisallow: /admin\nDisallow: /secret/\n";
    let result = parse_robots_txt(content);
    assert_eq!(result.disallowed_paths, vec!["/admin", "/secret/"]);
}

#[test]
fn robots_parses_allow_directives() {
    let content = "User-agent: *\nAllow: /public\nAllow: /api/v1\n";
    let result = parse_robots_txt(content);
    assert_eq!(result.allowed_paths, vec!["/public", "/api/v1"]);
}

#[test]
fn robots_parses_sitemap_urls() {
    let content =
        "Sitemap: https://localhost/sitemap.xml\nSitemap: https://localhost/sitemap2.xml\n";
    let result = parse_robots_txt(content);
    assert_eq!(
        result.sitemap_urls,
        vec![
            "https://localhost/sitemap.xml",
            "https://localhost/sitemap2.xml"
        ]
    );
}

#[test]
fn robots_ignores_comments() {
    let content = "# This is a comment\nDisallow: /admin\n# Another comment\nAllow: /public\n";
    let result = parse_robots_txt(content);
    assert_eq!(result.disallowed_paths, vec!["/admin"]);
    assert_eq!(result.allowed_paths, vec!["/public"]);
}

#[test]
fn robots_case_insensitive_directives() {
    let content = "DISALLOW: /upper\ndisallow: /lower\nDisAllow: /mixed\n";
    let result = parse_robots_txt(content);
    assert_eq!(result.disallowed_paths, vec!["/upper", "/lower", "/mixed"]);
}

#[test]
fn robots_handles_extra_whitespace() {
    let content = "  Disallow:   /spaced  \n  Allow:   /also-spaced  \n";
    let result = parse_robots_txt(content);
    assert_eq!(result.disallowed_paths, vec!["/spaced"]);
    assert_eq!(result.allowed_paths, vec!["/also-spaced"]);
}

#[test]
fn robots_skips_empty_values() {
    let content = "Disallow:\nAllow: /valid\nDisallow: /also-valid\n";
    let result = parse_robots_txt(content);
    assert_eq!(result.disallowed_paths, vec!["/also-valid"]);
    assert_eq!(result.allowed_paths, vec!["/valid"]);
}

#[test]
fn robots_skips_user_agent_lines() {
    let content = "User-agent: Googlebot\nDisallow: /private\nUser-agent: *\nAllow: /\n";
    let result = parse_robots_txt(content);
    assert_eq!(result.disallowed_paths, vec!["/private"]);
    assert_eq!(result.allowed_paths, vec!["/"]);
}

#[test]
fn robots_handles_inline_comments() {
    let content = "Disallow: /admin # admin area\nAllow: /public # public area\n";
    let result = parse_robots_txt(content);
    assert_eq!(result.disallowed_paths, vec!["/admin"]);
    assert_eq!(result.allowed_paths, vec!["/public"]);
}

#[test]
fn robots_empty_content_returns_defaults() {
    let result = parse_robots_txt("");
    assert!(result.disallowed_paths.is_empty());
    assert!(result.allowed_paths.is_empty());
    assert!(result.sitemap_urls.is_empty());
}

#[test]
fn robots_mixed_directives() {
    let content = "\
User-agent: *
Disallow: /admin
Disallow: /api/internal
Allow: /api/public
Sitemap: http://localhost:3000/sitemap.xml
# end of file
";
    let result = parse_robots_txt(content);
    assert_eq!(result.disallowed_paths, vec!["/admin", "/api/internal"]);
    assert_eq!(result.allowed_paths, vec!["/api/public"]);
    assert_eq!(
        result.sitemap_urls,
        vec!["http://localhost:3000/sitemap.xml"]
    );
}

#[test]
fn sitemap_extracts_loc_tags() {
    let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url><loc>http://localhost/page1</loc></url>
    <url><loc>http://localhost/page2</loc></url>
</urlset>"#;
    let result = parse_sitemap_xml(content);
    assert_eq!(
        result.urls,
        vec!["http://localhost/page1", "http://localhost/page2"]
    );
}

#[test]
fn sitemap_handles_index_file() {
    let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <sitemap><loc>http://localhost/sitemap1.xml</loc></sitemap>
    <sitemap><loc>http://localhost/sitemap2.xml</loc></sitemap>
</sitemapindex>"#;
    let result = parse_sitemap_xml(content);
    assert_eq!(
        result.urls,
        vec![
            "http://localhost/sitemap1.xml",
            "http://localhost/sitemap2.xml"
        ]
    );
}

#[test]
fn sitemap_handles_whitespace_in_loc() {
    let content = "<urlset><url><loc>  http://localhost/spaced  </loc></url></urlset>";
    let result = parse_sitemap_xml(content);
    assert_eq!(result.urls, vec!["http://localhost/spaced"]);
}

#[test]
fn sitemap_empty_content_returns_empty() {
    let result = parse_sitemap_xml("");
    assert!(result.urls.is_empty());
}

#[test]
fn sitemap_no_loc_tags_returns_empty() {
    let content = r#"<?xml version="1.0"?><urlset></urlset>"#;
    let result = parse_sitemap_xml(content);
    assert!(result.urls.is_empty());
}

#[test]
fn sitemap_skips_empty_loc_tags() {
    let content =
        "<urlset><url><loc></loc></url><url><loc>http://localhost/real</loc></url></urlset>";
    let result = parse_sitemap_xml(content);
    assert_eq!(result.urls, vec!["http://localhost/real"]);
}

#[test]
fn graph_ops_empty_results_produce_no_operations() {
    let robots = RobotsResult::default();
    let sitemap = SitemapResult::default();
    let ops = sitemap_results_to_operations(&robots, &sitemap, 0);
    assert!(ops.is_empty());
}

#[test]
fn graph_ops_disallowed_paths_become_endpoints() {
    let robots = RobotsResult {
        disallowed_paths: vec!["/admin".to_string(), "/secret".to_string()],
        sitemap_urls: Vec::new(),
        allowed_paths: Vec::new(),
    };
    let sitemap = SitemapResult::default();
    let ops = sitemap_results_to_operations(&robots, &sitemap, 0);

    assert_eq!(ops.len(), 2);
    assert_endpoint_op(&ops[0], "/admin", "robots_txt_disallowed");
    assert_endpoint_op(&ops[1], "/secret", "robots_txt_disallowed");
}

#[test]
fn graph_ops_sitemap_urls_become_endpoints() {
    let robots = RobotsResult::default();
    let sitemap = SitemapResult {
        urls: vec![
            "http://localhost/page1".to_string(),
            "http://localhost/page2".to_string(),
        ],
    };
    let ops = sitemap_results_to_operations(&robots, &sitemap, 0);

    assert_eq!(ops.len(), 2);
    assert_endpoint_op(&ops[0], "http://localhost/page1", "sitemap");
    assert_endpoint_op(&ops[1], "http://localhost/page2", "sitemap");
}

#[test]
fn graph_ops_combined_results() {
    let robots = RobotsResult {
        disallowed_paths: vec!["/admin".to_string()],
        sitemap_urls: Vec::new(),
        allowed_paths: Vec::new(),
    };
    let sitemap = SitemapResult {
        urls: vec!["http://localhost/page".to_string()],
    };
    let ops = sitemap_results_to_operations(&robots, &sitemap, 0);

    assert_eq!(ops.len(), 2);
    assert_endpoint_op(&ops[0], "/admin", "robots_txt_disallowed");
    assert_endpoint_op(&ops[1], "http://localhost/page", "sitemap");
}

#[test]
fn graph_ops_sequence_numbers_are_consecutive() {
    let robots = RobotsResult {
        disallowed_paths: vec!["/a".to_string()],
        sitemap_urls: Vec::new(),
        allowed_paths: Vec::new(),
    };
    let sitemap = SitemapResult {
        urls: vec!["http://localhost/b".to_string()],
    };
    let ops = sitemap_results_to_operations(&robots, &sitemap, 10);

    assert_eq!(ops[0].sequence_number, 11);
    assert_eq!(ops[1].sequence_number, 12);
}

#[test]
fn graph_ops_module_is_discovery() {
    let robots = RobotsResult {
        disallowed_paths: vec!["/test".to_string()],
        sitemap_urls: Vec::new(),
        allowed_paths: Vec::new(),
    };
    let ops = sitemap_results_to_operations(&robots, &SitemapResult::default(), 0);
    assert_eq!(ops[0].module, ModuleIdentifier::Discovery);
}

#[test]
fn graph_ops_timestamps_are_nonzero() {
    let robots = RobotsResult {
        disallowed_paths: vec!["/test".to_string()],
        sitemap_urls: Vec::new(),
        allowed_paths: Vec::new(),
    };
    let ops = sitemap_results_to_operations(&robots, &SitemapResult::default(), 0);
    assert!(ops[0].timestamp_unix_ms > 0);
}

#[test]
fn fetch_rejects_non_localhost() {
    let result = crate::sitemap_parser::fetch_and_parse("http://example.com");
    assert!(result.is_err());
}

fn assert_endpoint_op(
    entry: &aegis_protocol::operation::OperationLogEntry,
    path: &str,
    source: &str,
) {
    assert_eq!(entry.module, ModuleIdentifier::Discovery);
    if let GraphOperation::AddNode {
        node_type,
        properties,
    } = &entry.operation
    {
        assert_eq!(*node_type, NodeType::Endpoint);
        let props: std::collections::HashMap<&str, &str> = properties
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(props["path"], path);
        assert_eq!(props["method"], "GET");
        assert_eq!(props["discovery_source"], source);
    } else {
        panic!("expected AddNode operation");
    }
}
