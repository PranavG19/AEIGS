use super::*;
use crate::types::{ApiResourceType, InterceptedApiCall};

#[test]
fn page_content_default_is_empty() {
    let content = PageContent::default();
    assert!(content.final_url.is_empty());
    assert!(content.links.is_empty());
    assert!(content.forms.is_empty());
    assert!(content.event_handlers.is_empty());
    assert!(content.script_sources.is_empty());
    assert!(content.intercepted_api_calls.is_empty());
}

#[test]
fn page_content_collects_links() {
    let content = PageContent {
        final_url: "http://localhost:3000/".to_string(),
        links: vec![
            "http://localhost:3000/a".to_string(),
            "http://localhost:3000/b".to_string(),
        ],
        ..Default::default()
    };
    assert_eq!(content.links.len(), 2);
    assert_eq!(content.links[0], "http://localhost:3000/a");
    assert_eq!(content.links[1], "http://localhost:3000/b");
}

#[test]
fn page_content_collects_intercepted_api_calls() {
    let content = PageContent {
        final_url: "http://localhost:3000/".to_string(),
        intercepted_api_calls: vec![InterceptedApiCall {
            url: "http://localhost:3000/api/data".to_string(),
            method: "POST".to_string(),
            resource_type: ApiResourceType::Xhr,
        }],
        ..Default::default()
    };
    assert_eq!(content.intercepted_api_calls.len(), 1);
    assert_eq!(
        content.intercepted_api_calls[0].url,
        "http://localhost:3000/api/data"
    );
    assert_eq!(content.intercepted_api_calls[0].method, "POST");
    assert_eq!(
        content.intercepted_api_calls[0].resource_type,
        ApiResourceType::Xhr
    );
}
