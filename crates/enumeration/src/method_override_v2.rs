use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Headers and mechanisms used to override HTTP methods at the application or proxy layer.
///
/// Frameworks like Rails, Django, Express, and reverse proxies (nginx, HAProxy)
/// honor various override headers. Exhaustive testing across all known vectors
/// catches misconfigurations that single-header scanners miss.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OverrideHeader {
    /// `X-HTTP-Method-Override` — the most widely recognized override header (Rails, Spring, .NET).
    XHttpMethodOverride,
    /// `X-Method-Override` — common alias used by Express.js middleware and JAX-RS.
    XMethodOverride,
    /// `X-HTTP-Method` — Microsoft IIS / WCF variant.
    XHttpMethod,
    /// `Method-Override` — Connect/Express methodOverride middleware default.
    MethodOverride,
    /// `Request-Method` — legacy override seen in older PHP frameworks.
    RequestMethod,
    /// `X-Original-Method` — reverse-proxy passthrough header (nginx, Envoy).
    XOriginalMethod,
    /// `X-Real-Method` — alternate passthrough header in custom proxy configs.
    XRealMethod,
    /// `Access-Control-Request-Method` — CORS preflight header repurposed for override testing.
    AccessControlRequestMethod,
    /// `Content-Type` override via `application/x-www-form-urlencoded` with `_method` field.
    ContentTypeOverride,
    /// `Accept` header manipulation to coerce different handler dispatch paths.
    AcceptOverride,
    /// `?_method=` query string parameter (Rails, Laravel, Symfony).
    OverrideQuery,
    /// `_method` form field embedded in POST body.
    OverrideFormField,
    /// `X-HTTP-Method-Override` via URL fragment (edge-case WAF bypass).
    XHttpMethodOverrideFragment,
    /// `X-Forwarded-Method` — seen in Cloudflare Workers and custom edge proxies.
    XForwardedMethod,
    /// Arbitrary header supplied by the caller for framework-specific overrides.
    CustomHeader(String),
}

impl fmt::Display for OverrideHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XHttpMethodOverride => write!(f, "X-HTTP-Method-Override"),
            Self::XMethodOverride => write!(f, "X-Method-Override"),
            Self::XHttpMethod => write!(f, "X-HTTP-Method"),
            Self::MethodOverride => write!(f, "Method-Override"),
            Self::RequestMethod => write!(f, "Request-Method"),
            Self::XOriginalMethod => write!(f, "X-Original-Method"),
            Self::XRealMethod => write!(f, "X-Real-Method"),
            Self::AccessControlRequestMethod => write!(f, "Access-Control-Request-Method"),
            Self::ContentTypeOverride => write!(f, "Content-Type (_method)"),
            Self::AcceptOverride => write!(f, "Accept"),
            Self::OverrideQuery => write!(f, "?_method="),
            Self::OverrideFormField => write!(f, "_method (form)"),
            Self::XHttpMethodOverrideFragment => write!(f, "X-HTTP-Method-Override (fragment)"),
            Self::XForwardedMethod => write!(f, "X-Forwarded-Method"),
            Self::CustomHeader(h) => write!(f, "{h}"),
        }
    }
}

impl OverrideHeader {
    /// Returns the canonical HTTP header name for header-based overrides,
    /// or `None` for query/form/fragment mechanisms.
    pub fn header_name(&self) -> Option<&str> {
        match self {
            Self::XHttpMethodOverride | Self::XHttpMethodOverrideFragment => {
                Some("X-HTTP-Method-Override")
            }
            Self::XMethodOverride => Some("X-Method-Override"),
            Self::XHttpMethod => Some("X-HTTP-Method"),
            Self::MethodOverride => Some("Method-Override"),
            Self::RequestMethod => Some("Request-Method"),
            Self::XOriginalMethod => Some("X-Original-Method"),
            Self::XRealMethod => Some("X-Real-Method"),
            Self::AccessControlRequestMethod => Some("Access-Control-Request-Method"),
            Self::XForwardedMethod => Some("X-Forwarded-Method"),
            Self::CustomHeader(h) => Some(h.as_str()),
            Self::ContentTypeOverride | Self::AcceptOverride => None,
            Self::OverrideQuery | Self::OverrideFormField => None,
        }
    }
}

/// HTTP methods tested during override scanning, including dangerous/rarely-allowed verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Options,
    Head,
    /// TRACE — reflects request body; enables Cross-Site Tracing (XST) when combined with XSS.
    Trace,
    /// TRACK — Microsoft IIS alias for TRACE; same XST implications.
    Track,
    /// CONNECT — HTTP tunnel; proxy abuse vector if accepted by origin servers.
    Connect,
    /// PROPFIND — WebDAV; information disclosure of directory structure.
    Propfind,
    /// MKCOL — WebDAV directory creation.
    Mkcol,
    /// COPY — WebDAV resource duplication.
    Copy,
    /// MOVE — WebDAV resource relocation.
    Move,
    /// LOCK — WebDAV resource locking; denial-of-service vector.
    Lock,
    /// UNLOCK — WebDAV resource unlocking.
    Unlock,
    /// PURGE — cache invalidation (Varnish, Squid); can flush CDN caches.
    Purge,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl HttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Options => "OPTIONS",
            Self::Head => "HEAD",
            Self::Trace => "TRACE",
            Self::Track => "TRACK",
            Self::Connect => "CONNECT",
            Self::Propfind => "PROPFIND",
            Self::Mkcol => "MKCOL",
            Self::Copy => "COPY",
            Self::Move => "MOVE",
            Self::Lock => "LOCK",
            Self::Unlock => "UNLOCK",
            Self::Purge => "PURGE",
        }
    }

    /// All 17 method variants for exhaustive iteration.
    pub fn all() -> &'static [HttpMethod] {
        &[
            Self::Get,
            Self::Post,
            Self::Put,
            Self::Delete,
            Self::Patch,
            Self::Options,
            Self::Head,
            Self::Trace,
            Self::Track,
            Self::Connect,
            Self::Propfind,
            Self::Mkcol,
            Self::Copy,
            Self::Move,
            Self::Lock,
            Self::Unlock,
            Self::Purge,
        ]
    }

    /// Whether this method is associated with XST (Cross-Site Tracing).
    pub fn is_xst_relevant(&self) -> bool {
        matches!(self, Self::Trace | Self::Track)
    }

    /// Whether this method enables proxy tunneling abuse.
    pub fn is_proxy_relevant(&self) -> bool {
        matches!(self, Self::Connect)
    }
}

/// A single override test specification: send `original_method` with the override
/// header set to `override_method` and observe the response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideTest {
    pub header: OverrideHeader,
    pub original_method: HttpMethod,
    pub override_method: HttpMethod,
    pub description: String,
}

/// Result of executing a single override test against a target endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverrideResult {
    pub test: OverrideTest,
    pub response_code: u16,
    pub response_differs: bool,
    pub auth_bypass_detected: bool,
    pub xst_vulnerable: bool,
    pub proxy_abuse_possible: bool,
    pub evidence: String,
}

/// Captures an auth-bypass finding where a method override changed the authorization outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthBypassCheck {
    pub endpoint: String,
    pub required_role: String,
    pub tested_method: HttpMethod,
    pub original_response_code: u16,
    pub override_response_code: u16,
    pub bypass_confirmed: bool,
}

/// Controls which categories of override tests to execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodOverrideConfig {
    /// Test every known override header (when false, only the top-5 most common).
    pub test_all_headers: bool,
    /// Include TRACE/TRACK XST probes.
    pub test_xst: bool,
    /// Include CONNECT proxy-abuse probes.
    pub test_connect: bool,
    /// Perform auth-bypass differential analysis.
    pub test_auth_bypass: bool,
    /// Which override target methods to test (empty = all 17).
    pub target_methods: Vec<HttpMethod>,
    /// Maximum concurrent requests during the scan.
    pub max_parallel: usize,
}

impl Default for MethodOverrideConfig {
    fn default() -> Self {
        Self {
            test_all_headers: true,
            test_xst: true,
            test_connect: true,
            test_auth_bypass: true,
            target_methods: Vec::new(),
            max_parallel: 10,
        }
    }
}

/// Aggregate statistics from an exhaustive method override scan.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OverrideReport {
    pub total_tests: usize,
    pub successful_overrides: usize,
    pub auth_bypasses: usize,
    pub xst_findings: usize,
    pub proxy_findings: usize,
    pub results: Vec<OverrideResult>,
    pub auth_bypass_details: Vec<AuthBypassCheck>,
}

/// Exhaustive HTTP method override scanner.
///
/// Generates the full cartesian product of override headers × HTTP methods,
/// sends each probe against a target endpoint, and classifies the response
/// into override success, auth bypass, XST, or proxy abuse.
#[derive(Debug, Clone)]
pub struct MethodOverrideV2 {
    config: MethodOverrideConfig,
    base_url: String,
    baseline_responses: HashMap<String, u16>,
}

impl MethodOverrideV2 {
    /// Create a new scanner for `base_url` with the given configuration.
    pub fn new(base_url: &str, config: MethodOverrideConfig) -> Self {
        Self {
            config,
            base_url: base_url.trim_end_matches('/').to_string(),
            baseline_responses: HashMap::new(),
        }
    }

    /// All known override headers (15 built-in variants, no custom).
    fn all_headers() -> Vec<OverrideHeader> {
        vec![
            OverrideHeader::XHttpMethodOverride,
            OverrideHeader::XMethodOverride,
            OverrideHeader::XHttpMethod,
            OverrideHeader::MethodOverride,
            OverrideHeader::RequestMethod,
            OverrideHeader::XOriginalMethod,
            OverrideHeader::XRealMethod,
            OverrideHeader::AccessControlRequestMethod,
            OverrideHeader::ContentTypeOverride,
            OverrideHeader::AcceptOverride,
            OverrideHeader::OverrideQuery,
            OverrideHeader::OverrideFormField,
            OverrideHeader::XHttpMethodOverrideFragment,
            OverrideHeader::XForwardedMethod,
        ]
    }

    /// Top-5 most commonly honored override headers for quick scans.
    fn common_headers() -> Vec<OverrideHeader> {
        vec![
            OverrideHeader::XHttpMethodOverride,
            OverrideHeader::XMethodOverride,
            OverrideHeader::XHttpMethod,
            OverrideHeader::MethodOverride,
            OverrideHeader::OverrideQuery,
        ]
    }

    /// Which headers to test based on `config.test_all_headers`.
    fn active_headers(&self) -> Vec<OverrideHeader> {
        if self.config.test_all_headers {
            Self::all_headers()
        } else {
            Self::common_headers()
        }
    }

    /// Which target methods to probe based on config (empty = all).
    fn active_methods(&self) -> Vec<HttpMethod> {
        if self.config.target_methods.is_empty() {
            HttpMethod::all().to_vec()
        } else {
            self.config.target_methods.clone()
        }
    }

    /// Generate the full set of override test pairs.
    ///
    /// Each test pairs an original wire method (POST is the most common
    /// carrier because most override handlers only inspect POST bodies)
    /// with every combination of override header and target method.
    /// Wire methods GET and POST are both used as carriers to catch
    /// handlers that only inspect one.
    pub fn generate_all_test_pairs(&self) -> Vec<OverrideTest> {
        let headers = self.active_headers();
        let methods = self.active_methods();
        let carriers = [HttpMethod::Post, HttpMethod::Get];
        let mut tests = Vec::with_capacity(headers.len() * methods.len() * carriers.len());

        for header in &headers {
            for &carrier in &carriers {
                for &target in &methods {
                    if carrier == target {
                        continue;
                    }
                    if !self.config.test_xst && target.is_xst_relevant() {
                        continue;
                    }
                    if !self.config.test_connect && target.is_proxy_relevant() {
                        continue;
                    }
                    let desc = format!("{carrier} + {header} → {target}",);
                    tests.push(OverrideTest {
                        header: header.clone(),
                        original_method: carrier,
                        override_method: target,
                        description: desc,
                    });
                }
            }
        }
        tests
    }

    /// Store a baseline response code for a given `endpoint + method` key.
    pub fn record_baseline(&mut self, endpoint: &str, method: HttpMethod, status: u16) {
        let key = format!("{endpoint}:{method}");
        self.baseline_responses.insert(key, status);
    }

    /// Retrieve the baseline response code for a given endpoint and method.
    pub fn baseline_for(&self, endpoint: &str, method: HttpMethod) -> Option<u16> {
        let key = format!("{endpoint}:{method}");
        self.baseline_responses.get(&key).copied()
    }

    /// Simulate executing a single override test and classify the result.
    ///
    /// In a real scan this would issue an HTTP request; here we accept
    /// the raw response code and response body hash so the caller can
    /// plug in any HTTP backend.
    pub fn test_override(
        &self,
        test: &OverrideTest,
        endpoint: &str,
        response_code: u16,
        response_body_hash: u64,
        baseline_body_hash: u64,
    ) -> OverrideResult {
        let response_differs = response_body_hash != baseline_body_hash;
        let baseline = self.baseline_for(endpoint, test.original_method);
        let code_changed = baseline.map_or(false, |b| b != response_code);
        let xst_vulnerable = self.check_xst(test, response_code);
        let proxy_abuse = self.check_proxy_abuse(test, response_code);
        let auth_bypass = self.check_auth_bypass_signal(response_code, baseline);
        let evidence = self.build_evidence(
            test,
            response_code,
            baseline,
            code_changed,
            response_differs,
        );

        OverrideResult {
            test: test.clone(),
            response_code,
            response_differs,
            auth_bypass_detected: auth_bypass,
            xst_vulnerable,
            proxy_abuse_possible: proxy_abuse,
            evidence,
        }
    }

    /// Detect auth bypass: the override produced a 200 when the baseline was 401/403.
    fn check_auth_bypass_signal(&self, response_code: u16, baseline: Option<u16>) -> bool {
        let Some(base) = baseline else {
            return false;
        };
        let was_denied = base == 401 || base == 403;
        let now_allowed = response_code >= 200 && response_code < 300;
        was_denied && now_allowed
    }

    /// XST detection: TRACE/TRACK returning 200 means the server echoes the request body.
    fn check_xst(&self, test: &OverrideTest, response_code: u16) -> bool {
        test.override_method.is_xst_relevant() && response_code == 200
    }

    /// CONNECT returning 200 or 407 indicates proxy tunnel capability.
    fn check_proxy_abuse(&self, test: &OverrideTest, response_code: u16) -> bool {
        test.override_method.is_proxy_relevant() && (response_code == 200 || response_code == 407)
    }

    /// Assemble a human-readable evidence string for the result.
    fn build_evidence(
        &self,
        test: &OverrideTest,
        response_code: u16,
        baseline: Option<u16>,
        code_changed: bool,
        response_differs: bool,
    ) -> String {
        let mut parts: Vec<String> = Vec::new();
        parts.push(format!("Response: {response_code}"));
        if let Some(b) = baseline {
            parts.push(format!("Baseline: {b}"));
        }
        if code_changed {
            parts.push("Status code changed from baseline".into());
        }
        if response_differs {
            parts.push("Response body differs from baseline".into());
        }
        if test.override_method.is_xst_relevant() && response_code == 200 {
            parts.push(format!(
                "XST: {} returned 200 — server may echo request",
                test.override_method,
            ));
        }
        if test.override_method.is_proxy_relevant() {
            parts.push(format!(
                "CONNECT returned {response_code} — proxy tunnel may be open",
            ));
        }
        parts.join("; ")
    }

    /// Full auth-bypass differential for a single endpoint.
    ///
    /// Compares the baseline (denied) response to the override response
    /// and returns a structured `AuthBypassCheck`.
    pub fn detect_auth_bypass(
        &self,
        endpoint: &str,
        required_role: &str,
        tested_method: HttpMethod,
        original_code: u16,
        override_code: u16,
    ) -> AuthBypassCheck {
        let bypass_confirmed = (original_code == 401 || original_code == 403)
            && override_code >= 200
            && override_code < 300;
        AuthBypassCheck {
            endpoint: endpoint.to_string(),
            required_role: required_role.to_string(),
            tested_method,
            original_response_code: original_code,
            override_response_code: override_code,
            bypass_confirmed,
        }
    }

    /// Dedicated XST probe: send the override with a TRACE/TRACK target
    /// and report whether the response echoes back the probe body.
    pub fn test_xst_trace(
        &self,
        endpoint: &str,
        header: &OverrideHeader,
        response_code: u16,
        response_body_contains_probe: bool,
    ) -> OverrideResult {
        let test = OverrideTest {
            header: header.clone(),
            original_method: HttpMethod::Post,
            override_method: HttpMethod::Trace,
            description: format!("XST probe: POST + {header} → TRACE on {endpoint}",),
        };
        let xst_hit = response_code == 200 && response_body_contains_probe;
        let evidence = if xst_hit {
            format!("TRACE returned 200 and echoed probe body at {endpoint} — XST confirmed",)
        } else {
            format!("TRACE returned {response_code}, echo={response_body_contains_probe}",)
        };
        OverrideResult {
            test,
            response_code,
            response_differs: xst_hit,
            auth_bypass_detected: false,
            xst_vulnerable: xst_hit,
            proxy_abuse_possible: false,
            evidence,
        }
    }

    /// Dedicated CONNECT proxy-abuse probe.
    pub fn test_connect_proxy(
        &self,
        endpoint: &str,
        header: &OverrideHeader,
        response_code: u16,
    ) -> OverrideResult {
        let test = OverrideTest {
            header: header.clone(),
            original_method: HttpMethod::Post,
            override_method: HttpMethod::Connect,
            description: format!("Proxy probe: POST + {header} → CONNECT on {endpoint}",),
        };
        let proxy_hit = response_code == 200 || response_code == 407;
        let evidence = if proxy_hit {
            format!("CONNECT returned {response_code} at {endpoint} — tunnel may be open",)
        } else {
            format!("CONNECT returned {response_code} — no tunnel indication")
        };
        OverrideResult {
            test,
            response_code,
            response_differs: false,
            auth_bypass_detected: false,
            xst_vulnerable: false,
            proxy_abuse_possible: proxy_hit,
            evidence,
        }
    }

    /// Run the full exhaustive scan using a caller-provided request executor.
    ///
    /// `execute_request` takes `(url, wire_method, override_header, override_target)`
    /// and returns `(status_code, body_hash)`. This keeps the scanner transport-agnostic.
    pub fn run_exhaustive_scan<F>(&mut self, endpoint: &str, execute_request: F) -> OverrideReport
    where
        F: Fn(&str, HttpMethod, &OverrideHeader, HttpMethod) -> (u16, u64),
    {
        let url = format!("{}{}", self.base_url, endpoint);
        let pairs = self.generate_all_test_pairs();
        let baseline_hash = self.collect_baselines(&url, endpoint, &execute_request);
        let mut report = OverrideReport::default();
        report.total_tests = pairs.len();

        for test in &pairs {
            let (code, body_hash) = execute_request(
                &url,
                test.original_method,
                &test.header,
                test.override_method,
            );
            let result = self.test_override(test, endpoint, code, body_hash, baseline_hash);
            self.accumulate_report(&mut report, &result, endpoint);
            report.results.push(result);
        }
        report
    }

    /// Collect baseline responses for the two carrier methods.
    fn collect_baselines<F>(&mut self, url: &str, endpoint: &str, execute_request: &F) -> u64
    where
        F: Fn(&str, HttpMethod, &OverrideHeader, HttpMethod) -> (u16, u64),
    {
        let (post_code, post_hash) = execute_request(
            url,
            HttpMethod::Post,
            &OverrideHeader::XHttpMethodOverride,
            HttpMethod::Post,
        );
        self.record_baseline(endpoint, HttpMethod::Post, post_code);

        let (get_code, _) = execute_request(
            url,
            HttpMethod::Get,
            &OverrideHeader::XHttpMethodOverride,
            HttpMethod::Get,
        );
        self.record_baseline(endpoint, HttpMethod::Get, get_code);

        post_hash
    }

    /// Accumulate a single result into the running report totals.
    fn accumulate_report(
        &self,
        report: &mut OverrideReport,
        result: &OverrideResult,
        endpoint: &str,
    ) {
        if result.response_differs || result.auth_bypass_detected {
            report.successful_overrides += 1;
        }
        if result.xst_vulnerable {
            report.xst_findings += 1;
        }
        if result.proxy_abuse_possible {
            report.proxy_findings += 1;
        }
        if result.auth_bypass_detected {
            report.auth_bypasses += 1;
            report.auth_bypass_details.push(AuthBypassCheck {
                endpoint: endpoint.to_string(),
                required_role: "unknown".to_string(),
                tested_method: result.test.override_method,
                original_response_code: self
                    .baseline_for(endpoint, result.test.original_method)
                    .unwrap_or(0),
                override_response_code: result.response_code,
                bypass_confirmed: true,
            });
        }
    }

    /// Build a summary report from accumulated results.
    pub fn generate_report(&self, results: &[OverrideResult]) -> OverrideReport {
        let mut report = OverrideReport {
            total_tests: results.len(),
            ..Default::default()
        };
        for r in results {
            if r.response_differs || r.auth_bypass_detected {
                report.successful_overrides += 1;
            }
            if r.auth_bypass_detected {
                report.auth_bypasses += 1;
            }
            if r.xst_vulnerable {
                report.xst_findings += 1;
            }
            if r.proxy_abuse_possible {
                report.proxy_findings += 1;
            }
            report.results.push(r.clone());
        }
        report
    }

    /// URL accessor for external callers.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Config accessor.
    pub fn config(&self) -> &MethodOverrideConfig {
        &self.config
    }
}
