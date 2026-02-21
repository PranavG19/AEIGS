use std::sync::{Arc, Mutex};
use std::time::Duration;

use chromiumoxide::Browser;
use chromiumoxide::cdp::browser_protocol::network::{
    EnableParams, EventRequestWillBeSent, ResourceType,
};
use futures::StreamExt;

use crate::error::CrawlError;
use crate::page_fetcher::{PageContent, PageFetcher};
use crate::types::{
    ApiResourceType, CrawlConfig, DiscoveredForm, DomEventHandler, FormInput, InterceptedApiCall,
};

/// PageFetcher backed by a headless Chrome browser via CDP.
///
/// Uses chromiumoxide to navigate pages, execute JavaScript for DOM extraction,
/// and intercept XHR/fetch network requests via the CDP Network domain.
/// Does not own the browser lifecycle -- accepts a shared `Browser` reference
/// so one instance can be reused across all page fetches.
pub struct BrowserFetcher {
    browser: Browser,
    config: CrawlConfig,
}

impl BrowserFetcher {
    pub fn new(browser: Browser, config: CrawlConfig) -> Self {
        Self { browser, config }
    }
}

impl PageFetcher for BrowserFetcher {
    async fn fetch_page(&mut self, url: &str) -> Result<PageContent, CrawlError> {
        let page = self
            .browser
            .new_page("about:blank")
            .await
            .map_err(|e| CrawlError::BrowserLaunch(format!("failed to open tab: {e}")))?;

        page.execute(EnableParams::default())
            .await
            .map_err(|e| CrawlError::Internal(format!("failed to enable Network domain: {e}")))?;

        let intercepted: Arc<Mutex<Vec<InterceptedApiCall>>> = Arc::new(Mutex::new(Vec::new()));
        let intercepted_clone = Arc::clone(&intercepted);

        let mut event_stream = page
            .event_listener::<EventRequestWillBeSent>()
            .await
            .map_err(|e| CrawlError::Internal(format!("failed to attach event listener: {e}")))?;

        let listener_handle = tokio::spawn(async move {
            while let Some(event) = event_stream.next().await {
                let resource_type = match event.r#type {
                    Some(ResourceType::Xhr) => ApiResourceType::Xhr,
                    Some(ResourceType::Fetch) => ApiResourceType::Fetch,
                    _ => continue,
                };

                let call_url = &event.request.url;
                if !is_localhost_api_url(call_url) {
                    continue;
                }

                let call = InterceptedApiCall {
                    url: call_url.clone(),
                    method: event.request.method.clone(),
                    resource_type,
                };

                if let Ok(mut locked) = intercepted_clone.lock() {
                    locked.push(call);
                }
            }
        });

        let timeout = Duration::from_secs(self.config.timeout_secs);
        let nav_result = tokio::time::timeout(timeout, page.goto(url)).await;

        match nav_result {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                listener_handle.abort();
                return Err(CrawlError::Navigation(format!(
                    "navigation to {url} failed: {e}"
                )));
            }
            Err(_) => {
                listener_handle.abort();
                return Err(CrawlError::Timeout(format!(
                    "navigation to {url} timed out after {timeout:?}"
                )));
            }
        }

        let wait_ms = self.config.wait_after_load_ms;
        if wait_ms > 0 {
            tokio::time::sleep(Duration::from_millis(wait_ms)).await;
        }

        listener_handle.abort();

        let final_url = page
            .url()
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| url.to_string());

        let links = extract_links(&page).await;
        let forms = extract_forms(&page).await;
        let event_handlers = extract_event_handlers(&page).await;
        let script_sources = extract_script_sources(&page).await;

        let api_calls = match Arc::try_unwrap(intercepted) {
            Ok(mutex) => mutex.into_inner().unwrap_or_default(),
            Err(arc) => arc.lock().unwrap().clone(),
        };

        Ok(PageContent {
            final_url,
            links,
            forms,
            event_handlers,
            script_sources,
            intercepted_api_calls: api_calls,
        })
    }
}

const EXTRACT_LINKS_JS: &str = r#"
(() => {
    return Array.from(document.querySelectorAll('a[href]'))
        .map(a => a.href)
        .filter(href => href.length > 0);
})()
"#;

const EXTRACT_FORMS_JS: &str = r#"
(() => {
    return Array.from(document.querySelectorAll('form')).map(form => {
        const inputs = Array.from(form.querySelectorAll('input, textarea, select')).map(el => ({
            name: el.name || '',
            input_type: el.type || el.tagName.toLowerCase(),
            value: el.value || null
        }));
        return {
            action: form.action || '',
            method: (form.method || 'GET').toUpperCase(),
            inputs: inputs
        };
    });
})()
"#;

const EXTRACT_EVENT_HANDLERS_JS: &str = r#"
(() => {
    const handlers = [];
    const attrs = ['onclick', 'onsubmit', 'onchange', 'onload', 'onerror',
                   'onmouseover', 'onfocus', 'onblur', 'oninput', 'onkeyup'];
    const allElements = document.querySelectorAll('*');
    for (const el of allElements) {
        for (const attr of attrs) {
            const val = el.getAttribute(attr);
            if (val) {
                const tag = el.tagName.toLowerCase();
                const id = el.id ? '#' + el.id : '';
                const cls = el.className ? '.' + el.className.split(' ').join('.') : '';
                handlers.push({
                    element_selector: tag + id + cls,
                    event_name: attr,
                    handler_snippet: val
                });
            }
        }
    }
    return handlers;
})()
"#;

const EXTRACT_SCRIPTS_JS: &str = r#"
(() => {
    return Array.from(document.querySelectorAll('script[src]'))
        .map(s => s.src)
        .filter(src => src.length > 0);
})()
"#;

async fn extract_links(page: &chromiumoxide::Page) -> Vec<String> {
    page.evaluate(EXTRACT_LINKS_JS)
        .await
        .ok()
        .and_then(|val| val.into_value().ok())
        .unwrap_or_default()
}

async fn extract_forms(page: &chromiumoxide::Page) -> Vec<DiscoveredForm> {
    let raw: Vec<RawForm> = page
        .evaluate(EXTRACT_FORMS_JS)
        .await
        .ok()
        .and_then(|val| val.into_value().ok())
        .unwrap_or_default();

    raw.into_iter()
        .map(|f| DiscoveredForm {
            action: f.action,
            method: f.method,
            inputs: f
                .inputs
                .into_iter()
                .map(|i| FormInput {
                    name: i.name,
                    input_type: i.input_type,
                    value: i.value,
                })
                .collect(),
        })
        .collect()
}

async fn extract_event_handlers(page: &chromiumoxide::Page) -> Vec<DomEventHandler> {
    page.evaluate(EXTRACT_EVENT_HANDLERS_JS)
        .await
        .ok()
        .and_then(|val| val.into_value().ok())
        .unwrap_or_default()
}

async fn extract_script_sources(page: &chromiumoxide::Page) -> Vec<String> {
    page.evaluate(EXTRACT_SCRIPTS_JS)
        .await
        .ok()
        .and_then(|val| val.into_value().ok())
        .unwrap_or_default()
}

fn is_localhost_api_url(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let lower = host.to_ascii_lowercase();
    matches!(lower.as_str(), "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

#[derive(serde::Deserialize)]
struct RawForm {
    action: String,
    method: String,
    inputs: Vec<RawFormInput>,
}

#[derive(serde::Deserialize)]
struct RawFormInput {
    name: String,
    input_type: String,
    value: Option<String>,
}

#[cfg(test)]
#[path = "browser_fetcher_test.rs"]
mod browser_fetcher_test;
