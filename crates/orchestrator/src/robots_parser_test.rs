use crate::robots_parser::*;

#[test]
fn parse_robots_txt_extracts_disallow() {
    let content = "User-agent: *\nDisallow: /admin\nDisallow: /api/internal\n";
    let paths = parse_robots_txt(content);
    assert!(paths.contains(&"/admin".to_string()));
    assert!(paths.contains(&"/api/internal".to_string()));
}

#[test]
fn parse_robots_txt_extracts_allow() {
    let content = "User-agent: *\nAllow: /public\nDisallow: /private\n";
    let paths = parse_robots_txt(content);
    assert!(paths.contains(&"/public".to_string()));
    assert!(paths.contains(&"/private".to_string()));
}

#[test]
fn parse_robots_txt_extracts_sitemap() {
    let content = "Sitemap: https://example.com/sitemap.xml\n";
    let paths = parse_robots_txt(content);
    assert!(paths.contains(&"https://example.com/sitemap.xml".to_string()));
}

#[test]
fn parse_robots_txt_skips_comments_and_empty() {
    let content = "# comment\n\nUser-agent: *\nDisallow: /secret\n";
    let paths = parse_robots_txt(content);
    assert_eq!(paths, vec!["/secret"]);
}

#[test]
fn parse_robots_txt_skips_root_disallow() {
    let content = "User-agent: *\nDisallow: /\nDisallow: /admin\n";
    let paths = parse_robots_txt(content);
    assert_eq!(paths, vec!["/admin"]);
}

#[test]
fn parse_robots_txt_deduplicates() {
    let content = "User-agent: *\nDisallow: /admin\nDisallow: /admin\n";
    let paths = parse_robots_txt(content);
    assert_eq!(paths.iter().filter(|p| *p == "/admin").count(), 1);
}

#[test]
fn parse_robots_txt_preserves_path_case() {
    let content = "Disallow: /API/Internal\nAllow: /Public/Docs\n";
    let paths = parse_robots_txt(content);
    assert!(paths.contains(&"/API/Internal".to_string()));
    assert!(paths.contains(&"/Public/Docs".to_string()));
}

#[test]
fn parse_robots_txt_empty() {
    let paths = parse_robots_txt("");
    assert!(paths.is_empty());
}

#[test]
fn parse_sitemap_urls_extracts_locs() {
    let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset>
  <url><loc>https://example.com/page1</loc></url>
  <url><loc>https://example.com/page2</loc></url>
</urlset>"#;
    let urls = parse_sitemap_urls(content);
    assert_eq!(urls.len(), 2);
    assert!(urls.contains(&"https://example.com/page1".to_string()));
    assert!(urls.contains(&"https://example.com/page2".to_string()));
}

#[test]
fn parse_sitemap_urls_empty() {
    let urls = parse_sitemap_urls("");
    assert!(urls.is_empty());
}

#[test]
fn parse_sitemap_urls_no_locs() {
    let content = "<urlset></urlset>";
    let urls = parse_sitemap_urls(content);
    assert!(urls.is_empty());
}

#[test]
fn discovered_paths_to_operations_creates_nodes() {
    let paths = vec!["/admin".to_string(), "/api".to_string()];
    let mut seq = 0;
    let ops = discovered_paths_to_operations(&paths, "robots.txt", &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
    for op in &ops {
        match &op.operation {
            aegis_protocol::operation::GraphOperation::AddNode {
                node_type,
                properties,
            } => {
                assert_eq!(*node_type, aegis_protocol::node::NodeType::Endpoint);
                let source = properties.iter().find(|(k, _)| k == "source").unwrap();
                assert_eq!(source.1, "robots.txt");
            }
            _ => panic!("expected AddNode"),
        }
    }
}

#[test]
fn discovered_paths_to_operations_empty() {
    let mut seq = 3;
    let ops = discovered_paths_to_operations(&[], "sitemap", &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 3);
}

#[test]
fn fetch_robots_txt_skips_localhost() {
    let paths = fetch_robots_txt("http://localhost:8080");
    assert!(paths.is_empty());
}

#[test]
fn fetch_sitemap_skips_localhost() {
    let urls = fetch_sitemap("http://localhost:8080");
    assert!(urls.is_empty());
}
