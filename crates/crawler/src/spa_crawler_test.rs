use crate::spa_crawler::*;

#[test]
fn detect_react_from_data_reactroot() {
    let html = r#"<div id="root" data-reactroot=""></div>"#;
    assert_eq!(detect_spa_framework(html), Some(SpaFramework::React));
}

#[test]
fn detect_angular_from_ng_version() {
    let html = r#"<app-root ng-version="16.2.0"></app-root>"#;
    assert_eq!(detect_spa_framework(html), Some(SpaFramework::Angular));
}

#[test]
fn detect_vue_from_data_v() {
    let html = r#"<div id="app" data-v-a1b2c3></div>"#;
    assert_eq!(detect_spa_framework(html), Some(SpaFramework::Vue));
}

#[test]
fn detect_svelte_from_svelte_marker() {
    let html = r#"<div class="svelte-1abc2de">Hello</div>"#;
    assert_eq!(detect_spa_framework(html), Some(SpaFramework::Svelte));
}

#[test]
fn detect_nextjs_from_next_data() {
    let html = r#"<script id="__NEXT_DATA__" type="application/json">{}</script>"#;
    assert_eq!(detect_spa_framework(html), Some(SpaFramework::NextJs));
}

#[test]
fn detect_nuxt_from_nuxt_marker() {
    let html = r#"<script>window.__NUXT__={}</script>"#;
    assert_eq!(detect_spa_framework(html), Some(SpaFramework::Nuxt));
}

#[test]
fn detect_ember_from_data_ember() {
    let html = r#"<div id="ember-application" data-ember-version="4.0"></div>"#;
    assert_eq!(detect_spa_framework(html), Some(SpaFramework::Ember));
}

#[test]
fn no_framework_detected_for_plain_html() {
    let html = r#"<html><body><h1>Plain HTML</h1></body></html>"#;
    assert_eq!(detect_spa_framework(html), None);
}

#[test]
fn extract_routes_from_react_router() {
    let js = r#"
        <Route path="/dashboard" component={Dashboard} />
        <Route path="/settings/profile" component={Profile} />
        <Route path="/users/:id" component={UserDetail} />
    "#;
    let routes = extract_client_routes(js);
    assert!(routes.contains(&"/dashboard".to_string()));
    assert!(routes.contains(&"/settings/profile".to_string()));
}

#[test]
fn extract_routes_from_hash_fragments() {
    let html = r##"
        <a href="#/home">Home</a>
        <a href="#/about">About</a>
        <a href="#/contact">Contact</a>
    "##;
    let routes = extract_client_routes(html);
    assert!(routes.contains(&"/home".to_string()));
    assert!(routes.contains(&"/about".to_string()));
    assert!(routes.contains(&"/contact".to_string()));
}

#[test]
fn extract_routes_from_vue_router_links() {
    let html = r#"
        <router-link to="/products">Products</router-link>
        <router-link to="/cart">Cart</router-link>
    "#;
    let routes = extract_client_routes(html);
    assert!(routes.contains(&"/products".to_string()));
    assert!(routes.contains(&"/cart".to_string()));
}

#[test]
fn extract_fetch_api_calls() {
    let js = r#"
        fetch("/api/users")
        fetch('/api/products', { method: 'POST' })
        fetch(`/api/orders`)
    "#;
    let endpoints = extract_api_endpoints_from_js(js);
    assert_eq!(endpoints.len(), 3);
    assert!(endpoints.iter().any(|e| e.url == "/api/users"));
    assert!(endpoints.iter().any(|e| e.url == "/api/products"));
    assert!(endpoints.iter().any(|e| e.url == "/api/orders"));
    assert!(endpoints.iter().all(|e| e.call_type == JsCallType::Fetch));
}

#[test]
fn extract_axios_api_calls() {
    let js = r#"
        axios.get("/api/data")
        axios.post('/api/submit', data)
        axios.delete("/api/item/5")
    "#;
    let endpoints = extract_api_endpoints_from_js(js);
    assert_eq!(endpoints.len(), 3);
    assert!(endpoints
        .iter()
        .any(|e| e.url == "/api/data" && e.method == "GET"));
    assert!(endpoints
        .iter()
        .any(|e| e.url == "/api/submit" && e.method == "POST"));
    assert!(endpoints
        .iter()
        .any(|e| e.url == "/api/item/5" && e.method == "DELETE"));
}

#[test]
fn extract_xhr_api_calls() {
    let js = r#"
        xhr.open("GET", "/api/legacy")
        req.open('POST', '/api/old-submit')
    "#;
    let endpoints = extract_api_endpoints_from_js(js);
    assert_eq!(endpoints.len(), 2);
    assert!(endpoints
        .iter()
        .any(|e| e.url == "/api/legacy" && e.method == "GET"));
    assert!(endpoints
        .iter()
        .any(|e| e.url == "/api/old-submit" && e.method == "POST"));
}

#[test]
fn deduplicates_api_endpoints() {
    let js = r#"
        fetch("/api/users")
        fetch("/api/users")
        fetch("/api/users")
    "#;
    let endpoints = extract_api_endpoints_from_js(js);
    assert_eq!(endpoints.len(), 1);
}

#[test]
fn classify_buttons() {
    let html = r#"
        <button id="submit-btn">Submit</button>
        <button class="cancel-btn danger">Cancel</button>
    "#;
    let elements = classify_interactive_elements(html);
    assert_eq!(elements.len(), 2);
    assert_eq!(elements[0].selector, "#submit-btn");
    assert_eq!(elements[0].element_type, InteractiveElementType::Button);
    assert_eq!(elements[1].selector, "button.cancel-btn");
}

#[test]
fn classify_tab_roles() {
    let html = r#"
        <a role="tab" onclick="switchTab('info')" id="tab-info">Info</a>
    "#;
    let elements = classify_interactive_elements(html);
    assert_eq!(elements.len(), 1);
    assert_eq!(elements[0].element_type, InteractiveElementType::Tab);
}

#[test]
fn detect_infinite_scroll_pagination() {
    let html = r#"<div class="infinite-scroll" data-page="1"></div>"#;
    assert_eq!(detect_pagination(html), PaginationPattern::InfiniteScroll);
}

#[test]
fn detect_load_more_pagination() {
    let html = r#"<button class="load-more">Load More</button>"#;
    assert_eq!(detect_pagination(html), PaginationPattern::LoadMore);
}

#[test]
fn detect_numbered_pagination() {
    let html = r#"<a href="/posts?page=2">2</a><a href="/posts?page=3">3</a>"#;
    assert_eq!(detect_pagination(html), PaginationPattern::NumberedPages);
}

#[test]
fn detect_cursor_pagination() {
    let html = r#"<a href="/api/items?cursor=abc123">Next</a>"#;
    assert_eq!(detect_pagination(html), PaginationPattern::CursorBased);
}

#[test]
fn detect_no_pagination() {
    let html = r#"<div>Just some content</div>"#;
    assert_eq!(detect_pagination(html), PaginationPattern::None);
}

#[test]
fn crawl_spa_full_integration() {
    let html = r#"
        <html>
        <div data-reactroot="">
            <nav>
                <a href="/dashboard">Dashboard</a>
                <a href="/settings">Settings</a>
            </nav>
            <div class="infinite-scroll">
                <button id="refresh-btn">Refresh</button>
            </div>
            <form action="/api/search" method="POST">
                <input type="text" name="query" />
            </form>
        </div>
        <script>
            fetch("/api/users")
        </script>
        </html>
    "#;
    let js = r#"
        axios.get("/api/products")
        axios.post("/api/orders", data)
    "#;

    let config = SpaCrawlConfig::default();
    let result = crawl_spa(html, &[js], "http://localhost:3000", &config);

    assert_eq!(result.detected_framework, Some(SpaFramework::React));
    assert!(result.client_routes.contains(&"/dashboard".to_string()));
    assert!(result.client_routes.contains(&"/settings".to_string()));
    assert!(result.api_endpoints.len() >= 3);
    assert_eq!(result.pagination_pattern, PaginationPattern::InfiniteScroll);
    assert!(result
        .interactive_elements
        .iter()
        .any(|e| e.text == "Refresh"));
    assert!(!result.discovered_forms.is_empty());
    assert_eq!(result.pages_loaded, 1);
}

#[test]
fn spa_framework_as_str() {
    assert_eq!(SpaFramework::React.as_str(), "React");
    assert_eq!(SpaFramework::Angular.as_str(), "Angular");
    assert_eq!(SpaFramework::Vue.as_str(), "Vue");
    assert_eq!(SpaFramework::Svelte.as_str(), "Svelte");
    assert_eq!(SpaFramework::NextJs.as_str(), "Next.js");
    assert_eq!(SpaFramework::Nuxt.as_str(), "Nuxt");
    assert_eq!(SpaFramework::Ember.as_str(), "Ember");
    assert_eq!(SpaFramework::Unknown.as_str(), "Unknown");
}

#[test]
fn spa_crawl_config_builder() {
    let config = SpaCrawlConfig::default()
        .with_max_interactions(50)
        .with_max_scroll_attempts(5)
        .with_mutation_wait_ms(200)
        .with_click_delay_ms(100);
    assert_eq!(config.max_interactions, 50);
    assert_eq!(config.max_scroll_attempts, 5);
    assert_eq!(config.mutation_wait_ms, 200);
    assert_eq!(config.click_delay_ms, 100);
}

#[test]
fn resolve_relative_api_urls_to_base() {
    let html = r#"<script>fetch("/api/data")</script>"#;
    let config = SpaCrawlConfig::default();
    let result = crawl_spa(html, &[], "http://localhost:8080", &config);
    assert!(result
        .discovered_endpoints
        .iter()
        .any(|e| e.url == "http://localhost:8080/api/data"));
}

#[test]
fn absolute_api_urls_preserved() {
    let js = r#"fetch("http://localhost:9090/external/api")"#;
    let endpoints = extract_api_endpoints_from_js(js);
    assert_eq!(endpoints[0].url, "http://localhost:9090/external/api");
}
