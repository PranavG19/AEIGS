use std::fmt;

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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        // 0.3: confirmed JS execution via intercepted API
        DomEvidence::AlertFired => 0.3,
        // 0.3: confirmed document.cookie read/write
        DomEvidence::CookieAccess => 0.3,
        // 0.3: confirmed navigation hijack attempt
        DomEvidence::NavigationAttempt => 0.3,
        // 0.25: DOM tree modified with executable content
        DomEvidence::DomMutation => 0.25,
        // 0.25: fetch to non-origin domain detected
        DomEvidence::FetchToExternal => 0.25,
        // -0.2: payload in DOM but no execution observed
        DomEvidence::NoExecution => -0.2,
    }
}

#[cfg(test)]
#[path = "dom_verifier_test.rs"]
mod dom_verifier_test;
