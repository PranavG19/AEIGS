use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::CrawlError;

/// Evidence type from DOM-based XSS verification.
///
/// Ranked by signal strength: AlertFired/CookieAccess/NavigationAttempt indicate
/// confirmed execution (0.3 boost), DomMutation/FetchToExternal indicate likely
/// execution (0.25 boost), NoExecution indicates payload was reflected but inert
/// (-0.2 penalty).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DomEvidence {
    AlertFired,
    DomMutation,
    CookieAccess,
    NavigationAttempt,
    FetchToExternal,
    NoExecution,
}

impl fmt::Display for DomEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlertFired => write!(f, "Alert Fired"),
            Self::DomMutation => write!(f, "DOM Mutation"),
            Self::CookieAccess => write!(f, "Cookie Access"),
            Self::NavigationAttempt => write!(f, "Navigation Attempt"),
            Self::FetchToExternal => write!(f, "Fetch to External"),
            Self::NoExecution => write!(f, "No Execution"),
        }
    }
}

/// Result of verifying a suspected XSS payload in a real browser DOM.
///
/// Produced by injecting a payload into a page and checking whether it executed.
/// `confidence_boost` is added to the existing finding's confidence score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DomVerificationResult {
    pub payload: String,
    pub endpoint: String,
    pub dom_executed: bool,
    pub evidence: DomEvidence,
    pub confidence_boost: f64,
}

/// JavaScript injected before payload delivery to intercept XSS-indicative browser APIs.
///
/// Sets `window.__aegis_*` marker flags when alert(), location assignment,
/// document.cookie access, or external fetch() calls occur.
const INSTRUMENTATION_JS: &str = r#"
(() => {
    window.__aegis_xss_fired = false;
    window.__aegis_nav_attempt = false;
    window.__aegis_cookie_access = false;
    window.__aegis_external_fetch = false;

    const origAlert = window.alert;
    window.alert = function() {
        window.__aegis_xss_fired = true;
        return origAlert.apply(this, arguments);
    };

    const locationDesc = Object.getOwnPropertyDescriptor(window, 'location');
    if (locationDesc && locationDesc.configurable) {
        let currentLocation = window.location;
        Object.defineProperty(window, 'location', {
            get() { return currentLocation; },
            set(val) {
                window.__aegis_nav_attempt = true;
                currentLocation = val;
            },
            configurable: true
        });
    }

    const cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    if (cookieDesc) {
        Object.defineProperty(document, 'cookie', {
            get() {
                window.__aegis_cookie_access = true;
                return cookieDesc.get.call(this);
            },
            set(val) {
                window.__aegis_cookie_access = true;
                return cookieDesc.set.call(this, val);
            },
            configurable: true
        });
    }

    const origFetch = window.fetch;
    window.fetch = function(input) {
        try {
            const urlStr = typeof input === 'string' ? input : input.url;
            const parsed = new URL(urlStr, window.location.origin);
            if (parsed.origin !== window.location.origin) {
                window.__aegis_external_fetch = true;
            }
        } catch (e) {
            window.__aegis_external_fetch = true;
        }
        return origFetch.apply(this, arguments);
    };
})()
"#;

/// JavaScript that checks for injected script elements or inline event handlers
/// added after instrumentation, indicating DOM mutation from XSS.
const CHECK_DOM_MUTATION_JS: &str = r#"
(() => {
    const scripts = document.querySelectorAll('script');
    for (const s of scripts) {
        if (s.textContent && s.textContent.includes('__aegis')) continue;
        if (s.src || s.textContent) return true;
    }
    const allElements = document.querySelectorAll('*');
    const eventAttrs = ['onclick', 'onerror', 'onload', 'onmouseover', 'onfocus'];
    for (const el of allElements) {
        for (const attr of eventAttrs) {
            if (el.getAttribute(attr)) return true;
        }
    }
    return false;
})()
"#;

/// JavaScript that reads back all `window.__aegis_*` marker flags as a JSON object.
const READ_MARKERS_JS: &str = r#"
(() => {
    return {
        xss_fired: !!window.__aegis_xss_fired,
        nav_attempt: !!window.__aegis_nav_attempt,
        cookie_access: !!window.__aegis_cookie_access,
        external_fetch: !!window.__aegis_external_fetch
    };
})()
"#;

#[derive(Deserialize)]
struct MarkerFlags {
    xss_fired: bool,
    nav_attempt: bool,
    cookie_access: bool,
    external_fetch: bool,
}

/// Injects XSS detection instrumentation into a browser page.
///
/// Must be called before navigating to or injecting the payload under test.
/// Overrides `window.alert`, `window.location` setter, `document.cookie`,
/// and `window.fetch` to set `window.__aegis_*` marker flags on invocation.
pub async fn inject_xss_instrumentation(page: &chromiumoxide::Page) -> Result<(), CrawlError> {
    page.evaluate(INSTRUMENTATION_JS)
        .await
        .map_err(|e| CrawlError::Internal(format!("failed to inject XSS instrumentation: {e}")))?;
    Ok(())
}

/// Reads XSS marker flags and DOM state to determine what evidence of execution exists.
///
/// Checks instrumentation markers in priority order (AlertFired > NavigationAttempt >
/// CookieAccess > FetchToExternal > DomMutation > NoExecution) and returns the
/// highest-signal evidence found.
pub async fn check_xss_markers(page: &chromiumoxide::Page) -> Result<DomEvidence, CrawlError> {
    let markers: MarkerFlags = page
        .evaluate(READ_MARKERS_JS)
        .await
        .map_err(|e| CrawlError::Internal(format!("failed to read XSS markers: {e}")))?
        .into_value()
        .map_err(|e| CrawlError::Internal(format!("failed to deserialize XSS markers: {e}")))?;

    if markers.xss_fired {
        return Ok(DomEvidence::AlertFired);
    }
    if markers.nav_attempt {
        return Ok(DomEvidence::NavigationAttempt);
    }
    if markers.cookie_access {
        return Ok(DomEvidence::CookieAccess);
    }
    if markers.external_fetch {
        return Ok(DomEvidence::FetchToExternal);
    }

    let has_mutation: bool = page
        .evaluate(CHECK_DOM_MUTATION_JS)
        .await
        .ok()
        .and_then(|val| val.into_value().ok())
        .unwrap_or(false);

    if has_mutation {
        return Ok(DomEvidence::DomMutation);
    }

    Ok(DomEvidence::NoExecution)
}

/// Maps DOM evidence type to a confidence score adjustment.
///
/// Confirmed execution indicators (AlertFired, CookieAccess, NavigationAttempt)
/// yield +0.3. Likely execution (DomMutation, FetchToExternal) yields +0.25.
/// NoExecution (payload reflected but inert) yields -0.2.
pub fn confidence_boost_for_evidence(evidence: &DomEvidence) -> f64 {
    match evidence {
        DomEvidence::AlertFired => 0.3,
        DomEvidence::CookieAccess => 0.3,
        DomEvidence::NavigationAttempt => 0.3,
        DomEvidence::DomMutation => 0.25,
        DomEvidence::FetchToExternal => 0.25,
        DomEvidence::NoExecution => -0.2,
    }
}

/// Builds a URL with the XSS payload injected as a query parameter.
///
/// For GET requests, appends `q=<url-encoded payload>` to the query string.
/// For other methods (POST, PUT, etc.), returns the endpoint unchanged since
/// the payload would be delivered in the request body.
pub fn inject_payload_into_url(endpoint: &str, payload: &str, method: &str) -> String {
    if !method.eq_ignore_ascii_case("GET") {
        return endpoint.to_string();
    }

    let encoded: String = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("q", payload)
        .finish();

    if endpoint.contains('?') {
        format!("{endpoint}&{encoded}")
    } else {
        format!("{endpoint}?{encoded}")
    }
}

/// Verifies a suspected XSS payload by executing it in a real browser DOM.
///
/// Opens a new browser page, injects XSS detection instrumentation,
/// navigates to the endpoint with the payload, and checks whether
/// any execution markers fired. Returns `NoExecution` on timeout
/// rather than propagating an error.
pub async fn verify_xss_in_dom(
    browser: &chromiumoxide::Browser,
    endpoint: &str,
    method: &str,
    payload: &str,
    auth_cookies: Option<&[(String, String)]>,
    timeout_secs: u64,
) -> Result<DomVerificationResult, CrawlError> {
    let page = browser
        .new_page("about:blank")
        .await
        .map_err(|e| CrawlError::Internal(format!("failed to open page: {e}")))?;

    let url = inject_payload_into_url(endpoint, payload, method);

    inject_auth_cookies(&page, auth_cookies).await?;
    inject_xss_instrumentation(&page).await?;

    let evidence = match navigate_and_check(&page, &url, timeout_secs).await {
        Ok(ev) => ev,
        Err(_) => DomEvidence::NoExecution,
    };

    let dom_executed = evidence != DomEvidence::NoExecution;
    let confidence_boost = confidence_boost_for_evidence(&evidence);

    Ok(DomVerificationResult {
        payload: payload.to_string(),
        endpoint: endpoint.to_string(),
        dom_executed,
        evidence,
        confidence_boost,
    })
}

async fn inject_auth_cookies(
    page: &chromiumoxide::Page,
    auth_cookies: Option<&[(String, String)]>,
) -> Result<(), CrawlError> {
    let Some(cookies) = auth_cookies else {
        return Ok(());
    };
    for (name, value) in cookies {
        let cookie = chromiumoxide::cdp::browser_protocol::network::CookieParam::new(name, value);
        page.set_cookie(cookie)
            .await
            .map_err(|e| CrawlError::Internal(format!("failed to set cookie {name}: {e}")))?;
    }
    Ok(())
}

async fn navigate_and_check(
    page: &chromiumoxide::Page,
    url: &str,
    timeout_secs: u64,
) -> Result<DomEvidence, CrawlError> {
    let timeout = Duration::from_secs(timeout_secs);
    let nav_result = tokio::time::timeout(timeout, page.goto(url)).await;

    match nav_result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return Err(CrawlError::Navigation(format!(
                "navigation to {url} failed: {e}"
            )));
        }
        Err(_) => return Ok(DomEvidence::NoExecution),
    }

    check_xss_markers(page).await
}

#[cfg(test)]
#[path = "dom_verifier_test.rs"]
mod dom_verifier_test;
