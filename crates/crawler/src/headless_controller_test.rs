use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::CrawlError;
use crate::headless_controller::*;

struct MockBrowser {
    pages: Mutex<Vec<PageCapture>>,
    js_results: Mutex<Vec<String>>,
    closed: Mutex<bool>,
}

impl MockBrowser {
    fn new() -> Self {
        Self {
            pages: Mutex::new(Vec::new()),
            js_results: Mutex::new(Vec::new()),
            closed: Mutex::new(false),
        }
    }

    fn with_page(self, capture: PageCapture) -> Self {
        self.pages.lock().unwrap().push(capture);
        self
    }

    fn with_js_result(self, result: &str) -> Self {
        self.js_results.lock().unwrap().push(result.to_string());
        self
    }
}

impl BrowserBackend for MockBrowser {
    async fn navigate(&self, url: &str) -> Result<PageCapture, CrawlError> {
        let mut pages = self.pages.lock().unwrap();
        if let Some(page) = pages.pop() {
            Ok(page)
        } else {
            Ok(PageCapture {
                url: url.to_string(),
                dom_html: "<html><body>Mock</body></html>".to_string(),
                title: "Mock Page".to_string(),
                ..Default::default()
            })
        }
    }

    async fn execute_js(&self, _script: &str) -> Result<String, CrawlError> {
        let mut results = self.js_results.lock().unwrap();
        Ok(results.pop().unwrap_or_else(|| "undefined".to_string()))
    }

    async fn click_element(&self, _selector: &str) -> Result<(), CrawlError> {
        Ok(())
    }

    async fn fill_field(&self, _selector: &str, _value: &str) -> Result<(), CrawlError> {
        Ok(())
    }

    async fn submit_form(&self, _selector: &str) -> Result<(), CrawlError> {
        Ok(())
    }

    async fn take_screenshot(&self) -> Result<Vec<u8>, CrawlError> {
        Ok(vec![0x89, 0x50, 0x4E, 0x47])
    }

    async fn get_storage(&self) -> Result<StorageSnapshot, CrawlError> {
        let mut local = HashMap::new();
        local.insert("token".to_string(), "abc123".to_string());
        Ok(StorageSnapshot {
            cookies: vec![CookieEntry {
                name: "session".to_string(),
                value: "xyz789".to_string(),
                domain: "localhost".to_string(),
                path: "/".to_string(),
                secure: false,
                http_only: true,
                same_site: Some("Lax".to_string()),
                expires: None,
            }],
            local_storage: local,
            session_storage: HashMap::new(),
        })
    }

    async fn close(&self) -> Result<(), CrawlError> {
        *self.closed.lock().unwrap() = true;
        Ok(())
    }
}

#[tokio::test]
async fn navigate_localhost_succeeds() {
    let backend = MockBrowser::new();
    let controller = HeadlessController::new(HeadlessConfig::default(), backend);

    let result = controller
        .navigate_and_capture("http://localhost:8080/api/test")
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn navigate_remote_url_rejected() {
    let backend = MockBrowser::new();
    let controller = HeadlessController::new(HeadlessConfig::default(), backend);

    let result = controller
        .navigate_and_capture("http://example.com/evil")
        .await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("localhost"));
}

#[tokio::test]
async fn navigate_captures_network_requests() {
    let page = PageCapture {
        url: "http://localhost:8080/".to_string(),
        network_requests: vec![CapturedNetworkRequest {
            url: "http://localhost:8080/api/data".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body: None,
            resource_type: NetworkResourceType::Fetch,
        }],
        ..Default::default()
    };
    let backend = MockBrowser::new().with_page(page);
    let controller = HeadlessController::new(HeadlessConfig::default(), backend);

    let _ = controller
        .navigate_and_capture("http://localhost:8080/")
        .await
        .unwrap();
    let requests = controller.captured_network_requests().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url, "http://localhost:8080/api/data");
}

#[tokio::test]
async fn fill_and_submit_form() {
    let backend = MockBrowser::new();
    let controller = HeadlessController::new(HeadlessConfig::default(), backend);

    let fields = vec![("#username", "admin"), ("#password", "secret")];
    let result = controller
        .fill_and_submit(&fields, Some("#login-btn"))
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn execute_javascript_returns_result() {
    let backend = MockBrowser::new().with_js_result("42");
    let controller = HeadlessController::new(HeadlessConfig::default(), backend);

    let result = controller
        .execute_javascript("return 40 + 2")
        .await
        .unwrap();
    assert_eq!(result, "42");
}

#[tokio::test]
async fn screenshot_returns_png_bytes() {
    let backend = MockBrowser::new();
    let controller = HeadlessController::new(HeadlessConfig::default(), backend);

    let bytes = controller.screenshot().await.unwrap();
    assert_eq!(&bytes[..4], &[0x89, 0x50, 0x4E, 0x47]);
}

#[tokio::test]
async fn storage_extraction() {
    let backend = MockBrowser::new();
    let controller = HeadlessController::new(HeadlessConfig::default(), backend);

    let storage = controller.extract_storage().await.unwrap();
    assert_eq!(storage.cookies.len(), 1);
    assert_eq!(storage.cookies[0].name, "session");
    assert_eq!(storage.local_storage.get("token").unwrap(), "abc123");
}

#[tokio::test]
async fn page_concurrency_tracking() {
    let backend = MockBrowser::new();
    let config = HeadlessConfig::default().with_max_concurrent_pages(2);
    let controller = HeadlessController::new(config, backend);

    assert!(controller.can_open_page().await);
    controller.register_page_open().await;
    controller.register_page_open().await;
    assert!(!controller.can_open_page().await);
    controller.register_page_close().await;
    assert!(controller.can_open_page().await);
}

#[tokio::test]
async fn shutdown_closes_backend() {
    let backend = MockBrowser::new();
    let controller = HeadlessController::new(HeadlessConfig::default(), backend);
    let result = controller.shutdown().await;
    assert!(result.is_ok());
}

#[test]
fn extract_forms_from_html_parses_correctly() {
    let html = r#"
        <form action="/login" method="POST">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="submit" name="submit" value="Login" />
        </form>
    "#;

    let forms = extract_forms_from_html(html, "http://localhost:8080");
    assert_eq!(forms.len(), 1);
    assert_eq!(forms[0].action, "/login");
    assert_eq!(forms[0].method, "POST");
    assert_eq!(forms[0].inputs.len(), 3);
    assert_eq!(forms[0].inputs[0].name, "username");
    assert_eq!(forms[0].inputs[1].input_type, "password");
}

#[test]
fn network_requests_to_endpoints_filters_api_calls() {
    let requests = vec![
        CapturedNetworkRequest {
            url: "http://localhost:8080/api/users".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body: None,
            resource_type: NetworkResourceType::Fetch,
        },
        CapturedNetworkRequest {
            url: "http://localhost:8080/style.css".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body: None,
            resource_type: NetworkResourceType::Stylesheet,
        },
        CapturedNetworkRequest {
            url: "http://localhost:8080/api/data".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            body: Some(r#"{"key":"val"}"#.to_string()),
            resource_type: NetworkResourceType::Xhr,
        },
    ];

    let endpoints = network_requests_to_endpoints(&requests);
    assert_eq!(endpoints.len(), 2);
    assert_eq!(endpoints[0].url, "http://localhost:8080/api/users");
    assert_eq!(endpoints[1].method, "POST");
}

#[test]
fn browser_fingerprint_defaults_are_reasonable() {
    let fp = BrowserFingerprint::default();
    assert!(fp.user_agent.contains("Chrome"));
    assert_eq!(fp.viewport_width, 1920);
    assert_eq!(fp.viewport_height, 1080);
    assert_eq!(fp.language, "en-US");
}

#[test]
fn headless_config_builder_works() {
    let config = HeadlessConfig::default()
        .with_headless(false)
        .with_capture_screenshots(true)
        .with_max_concurrent_pages(8);
    assert!(!config.headless);
    assert!(config.capture_screenshots);
    assert_eq!(config.max_concurrent_pages, 8);
}

#[tokio::test]
async fn navigate_127_0_0_1_succeeds() {
    let backend = MockBrowser::new();
    let controller = HeadlessController::new(HeadlessConfig::default(), backend);

    let result = controller
        .navigate_and_capture("http://127.0.0.1:3000/")
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn navigate_ipv6_localhost_succeeds() {
    let backend = MockBrowser::new();
    let controller = HeadlessController::new(HeadlessConfig::default(), backend);

    let result = controller.navigate_and_capture("http://[::1]:3000/").await;
    assert!(result.is_ok());
}

#[test]
fn extract_forms_handles_missing_action() {
    let html = r#"<form method="POST"><input type="text" name="q" /></form>"#;
    let forms = extract_forms_from_html(html, "http://localhost:8080/search");
    assert_eq!(forms.len(), 1);
    assert_eq!(forms[0].action, "http://localhost:8080/search");
}
