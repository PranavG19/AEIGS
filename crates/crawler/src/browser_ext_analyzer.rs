use std::collections::HashMap;
use std::fmt;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Severity rating for a browser extension security finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum ExtensionSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for ExtensionSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        write!(f, "{label}")
    }
}

/// Category of browser extension vulnerability discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExtensionVulnType {
    /// Extension detected via `chrome-extension://` URL in page resources.
    ExtensionIdExposure,
    /// Content script injects code into web pages without proper isolation.
    ContentScriptInjection,
    /// Background page uses privileged Chrome APIs accessible from content scripts.
    BackgroundApiAccess,
    /// Exposed `chrome.runtime.connect`/`onConnectExternal` message handler.
    MessagePassingExposure,
    /// Extension requests overly broad permissions.
    DangerousPermission,
    /// `web_accessible_resources` expose files usable for XSS or fingerprinting.
    WebAccessibleResourceXss,
    /// Extension leaks data from privileged context to web page DOM.
    ExtensionDataLeakage,
    /// Extension uses `chrome.storage` accessible by other extensions sharing a storage area.
    CrossExtensionStorageAttack,
    /// Externally connectable messaging without origin restrictions.
    ExternallyConnectable,
}

impl fmt::Display for ExtensionVulnType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ExtensionIdExposure => "extension-id-exposure",
            Self::ContentScriptInjection => "content-script-injection",
            Self::BackgroundApiAccess => "background-api-access",
            Self::MessagePassingExposure => "message-passing-exposure",
            Self::DangerousPermission => "dangerous-permission",
            Self::WebAccessibleResourceXss => "web-accessible-resource-xss",
            Self::ExtensionDataLeakage => "extension-data-leakage",
            Self::CrossExtensionStorageAttack => "cross-extension-storage-attack",
            Self::ExternallyConnectable => "externally-connectable",
        };
        write!(f, "{label}")
    }
}

/// A dangerous Chrome API that an extension uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DangerousApi {
    TabsExecuteScript,
    TabsSendMessage,
    RuntimeSendNativeMessage,
    WebRequestOnBeforeRequest,
    WebRequestOnBeforeSendHeaders,
    CookiesGetAll,
    CookiesSet,
    DebuggerAttach,
    DownloadsDownload,
    ManagementGetAll,
    ContentSettingsClear,
    HistorySearch,
    BookmarksGetTree,
    TopSitesGet,
}

impl fmt::Display for DangerousApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::TabsExecuteScript => "chrome.tabs.executeScript",
            Self::TabsSendMessage => "chrome.tabs.sendMessage",
            Self::RuntimeSendNativeMessage => "chrome.runtime.sendNativeMessage",
            Self::WebRequestOnBeforeRequest => "chrome.webRequest.onBeforeRequest",
            Self::WebRequestOnBeforeSendHeaders => "chrome.webRequest.onBeforeSendHeaders",
            Self::CookiesGetAll => "chrome.cookies.getAll",
            Self::CookiesSet => "chrome.cookies.set",
            Self::DebuggerAttach => "chrome.debugger.attach",
            Self::DownloadsDownload => "chrome.downloads.download",
            Self::ManagementGetAll => "chrome.management.getAll",
            Self::ContentSettingsClear => "chrome.contentSettings.clear",
            Self::HistorySearch => "chrome.history.search",
            Self::BookmarksGetTree => "chrome.bookmarks.getTree",
            Self::TopSitesGet => "chrome.topSites.get",
        };
        write!(f, "{label}")
    }
}

/// Permission risk level classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PermissionRisk {
    /// Grants access to all URLs or extremely broad capability.
    Critical,
    /// Can intercept/modify requests or access sensitive user data.
    High,
    /// Can read tab metadata or inject limited content.
    Medium,
    /// Informational or scoped capability.
    Low,
}

/// A parsed browser extension manifest (v2 or v3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionManifest {
    pub manifest_version: u8,
    pub name: String,
    pub version: String,
    pub permissions: Vec<String>,
    pub optional_permissions: Vec<String>,
    pub host_permissions: Vec<String>,
    pub content_scripts: Vec<ContentScriptEntry>,
    pub background: Option<BackgroundConfig>,
    pub web_accessible_resources: Vec<String>,
    pub externally_connectable: Option<ExternallyConnectable>,
    pub content_security_policy: Option<String>,
}

/// A single content_scripts entry from the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentScriptEntry {
    pub matches: Vec<String>,
    pub js: Vec<String>,
    pub css: Vec<String>,
    pub run_at: String,
    pub all_frames: bool,
}

/// Background script/service worker configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackgroundConfig {
    pub scripts: Vec<String>,
    pub service_worker: Option<String>,
    pub persistent: bool,
}

/// externally_connectable manifest key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternallyConnectable {
    pub matches: Vec<String>,
    pub ids: Vec<String>,
    pub accepts_tls_channel_id: bool,
}

/// A single finding from the extension security analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionFinding {
    pub vuln_type: ExtensionVulnType,
    pub severity: ExtensionSeverity,
    pub description: String,
    pub evidence: String,
    pub remediation: String,
}

/// Full result of browser extension security analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionAnalysis {
    pub extension_id: Option<String>,
    pub manifest: Option<ExtensionManifest>,
    pub findings: Vec<ExtensionFinding>,
    pub dangerous_apis_used: Vec<DangerousApi>,
    pub summary: ExtensionSummary,
}

/// Summary statistics for extension analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionSummary {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub patterns_checked: usize,
}

/// Configuration for extension analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionAnalysisConfig {
    pub check_permissions: bool,
    pub check_content_scripts: bool,
    pub check_message_passing: bool,
    pub check_web_accessible_resources: bool,
    pub check_background_apis: bool,
    pub check_data_leakage: bool,
    pub check_cross_extension: bool,
    pub check_externally_connectable: bool,
}

impl Default for ExtensionAnalysisConfig {
    fn default() -> Self {
        Self {
            check_permissions: true,
            check_content_scripts: true,
            check_message_passing: true,
            check_web_accessible_resources: true,
            check_background_apis: true,
            check_data_leakage: true,
            check_cross_extension: true,
            check_externally_connectable: true,
        }
    }
}

impl ExtensionAnalysisConfig {
    pub fn with_permissions(mut self, enabled: bool) -> Self {
        self.check_permissions = enabled;
        self
    }

    pub fn with_content_scripts(mut self, enabled: bool) -> Self {
        self.check_content_scripts = enabled;
        self
    }

    pub fn with_message_passing(mut self, enabled: bool) -> Self {
        self.check_message_passing = enabled;
        self
    }

    pub fn with_web_accessible_resources(mut self, enabled: bool) -> Self {
        self.check_web_accessible_resources = enabled;
        self
    }

    pub fn with_background_apis(mut self, enabled: bool) -> Self {
        self.check_background_apis = enabled;
        self
    }

    pub fn with_data_leakage(mut self, enabled: bool) -> Self {
        self.check_data_leakage = enabled;
        self
    }

    pub fn with_cross_extension(mut self, enabled: bool) -> Self {
        self.check_cross_extension = enabled;
        self
    }

    pub fn with_externally_connectable(mut self, enabled: bool) -> Self {
        self.check_externally_connectable = enabled;
        self
    }
}

/// Extracts chrome extension IDs from page source (URLs, script tags, link tags).
pub fn extract_extension_ids(page_source: &str) -> Vec<String> {
    let re = Regex::new(r"chrome-extension://([a-z]{32})").expect("valid regex");
    let mut ids: Vec<String> = re
        .captures_iter(page_source)
        .map(|cap| cap[1].to_string())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// Parses a manifest.json string into an ExtensionManifest.
pub fn parse_manifest(manifest_json: &str) -> Result<ExtensionManifest, String> {
    let raw: serde_json::Value =
        serde_json::from_str(manifest_json).map_err(|e| format!("invalid JSON: {e}"))?;

    let manifest_version = raw
        .get("manifest_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(2) as u8;

    let name = raw
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let version = raw
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("0.0.0")
        .to_string();

    let permissions = extract_string_array(&raw, "permissions");
    let optional_permissions = extract_string_array(&raw, "optional_permissions");

    let host_permissions = if manifest_version >= 3 {
        extract_string_array(&raw, "host_permissions")
    } else {
        permissions
            .iter()
            .filter(|p| p.contains("://") || p.starts_with("<all_urls>"))
            .cloned()
            .collect()
    };

    let content_scripts = parse_content_scripts(&raw);
    let background = parse_background(&raw, manifest_version);
    let web_accessible_resources = parse_web_accessible_resources(&raw, manifest_version);
    let externally_connectable = parse_externally_connectable(&raw);

    let content_security_policy = raw.get("content_security_policy").and_then(|v| {
        if let Some(s) = v.as_str() {
            Some(s.to_string())
        } else {
            v.get("extension")
                .and_then(|e| e.as_str())
                .map(String::from)
        }
    });

    Ok(ExtensionManifest {
        manifest_version,
        name,
        version,
        permissions,
        optional_permissions,
        host_permissions,
        content_scripts,
        background,
        web_accessible_resources,
        externally_connectable,
        content_security_policy,
    })
}

fn extract_string_array(value: &serde_json::Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_content_scripts(raw: &serde_json::Value) -> Vec<ContentScriptEntry> {
    let Some(arr) = raw.get("content_scripts").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    arr.iter()
        .map(|entry| ContentScriptEntry {
            matches: extract_string_array(entry, "matches"),
            js: extract_string_array(entry, "js"),
            css: extract_string_array(entry, "css"),
            run_at: entry
                .get("run_at")
                .and_then(|v| v.as_str())
                .unwrap_or("document_idle")
                .to_string(),
            all_frames: entry
                .get("all_frames")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        })
        .collect()
}

fn parse_background(raw: &serde_json::Value, manifest_version: u8) -> Option<BackgroundConfig> {
    let bg = raw.get("background")?;

    if manifest_version >= 3 {
        let sw = bg
            .get("service_worker")
            .and_then(|v| v.as_str())
            .map(String::from);
        Some(BackgroundConfig {
            scripts: Vec::new(),
            service_worker: sw,
            persistent: false,
        })
    } else {
        let scripts = extract_string_array(bg, "scripts");
        let persistent = bg
            .get("persistent")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if scripts.is_empty() && bg.get("page").is_none() {
            return None;
        }
        Some(BackgroundConfig {
            scripts,
            service_worker: None,
            persistent,
        })
    }
}

fn parse_web_accessible_resources(raw: &serde_json::Value, manifest_version: u8) -> Vec<String> {
    let Some(war) = raw.get("web_accessible_resources") else {
        return Vec::new();
    };

    if manifest_version >= 3 {
        let Some(arr) = war.as_array() else {
            return Vec::new();
        };
        arr.iter()
            .flat_map(|entry| extract_string_array(entry, "resources"))
            .collect()
    } else {
        extract_string_array(raw, "web_accessible_resources")
    }
}

fn parse_externally_connectable(raw: &serde_json::Value) -> Option<ExternallyConnectable> {
    let ec = raw.get("externally_connectable")?;

    Some(ExternallyConnectable {
        matches: extract_string_array(ec, "matches"),
        ids: extract_string_array(ec, "ids"),
        accepts_tls_channel_id: ec
            .get("accepts_tls_channel_id")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}

/// Permission risk classification.
const DANGEROUS_PERMISSIONS: &[(&str, PermissionRisk, &str)] = &[
    (
        "<all_urls>",
        PermissionRisk::Critical,
        "grants access to all URLs — full page content read/modify",
    ),
    (
        "*://*/*",
        PermissionRisk::Critical,
        "wildcard host grants access to all HTTP/HTTPS pages",
    ),
    (
        "http://*/*",
        PermissionRisk::Critical,
        "grants access to all HTTP pages — can intercept unencrypted traffic",
    ),
    (
        "https://*/*",
        PermissionRisk::Critical,
        "grants access to all HTTPS pages",
    ),
    (
        "webRequest",
        PermissionRisk::High,
        "can observe and analyze all web requests",
    ),
    (
        "webRequestBlocking",
        PermissionRisk::Critical,
        "can intercept, block, and modify all web requests in-flight",
    ),
    (
        "cookies",
        PermissionRisk::High,
        "can read and modify cookies for any permitted host",
    ),
    (
        "tabs",
        PermissionRisk::Medium,
        "can read tab URLs and titles — browsing history exposure",
    ),
    (
        "activeTab",
        PermissionRisk::Low,
        "temporary access to current tab on user gesture",
    ),
    (
        "debugger",
        PermissionRisk::Critical,
        "full Chrome DevTools Protocol access — can read/modify any page",
    ),
    (
        "management",
        PermissionRisk::High,
        "can enable/disable/uninstall other extensions",
    ),
    (
        "nativeMessaging",
        PermissionRisk::High,
        "can communicate with native applications on the host",
    ),
    (
        "proxy",
        PermissionRisk::High,
        "can redirect all browser traffic through attacker-controlled proxy",
    ),
    (
        "downloads",
        PermissionRisk::Medium,
        "can trigger file downloads — potential for drive-by download attacks",
    ),
    (
        "history",
        PermissionRisk::Medium,
        "can read full browsing history",
    ),
    (
        "bookmarks",
        PermissionRisk::Low,
        "can read and modify bookmarks",
    ),
    (
        "topSites",
        PermissionRisk::Low,
        "can read most visited sites",
    ),
    (
        "contentSettings",
        PermissionRisk::Medium,
        "can modify per-site content settings (JS, cookies, plugins)",
    ),
    (
        "clipboardRead",
        PermissionRisk::High,
        "can read clipboard contents — password/credential theft",
    ),
    (
        "clipboardWrite",
        PermissionRisk::Medium,
        "can write to clipboard — clipboard hijacking",
    ),
    (
        "geolocation",
        PermissionRisk::Medium,
        "can access precise user location",
    ),
    (
        "storage",
        PermissionRisk::Low,
        "local extension storage — benign unless shared",
    ),
    (
        "unlimitedStorage",
        PermissionRisk::Low,
        "can store unlimited data locally",
    ),
];

/// Dangerous Chrome APIs and their patterns in JS source.
const DANGEROUS_API_PATTERNS: &[(&str, DangerousApi)] = &[
    (
        r"chrome\.tabs\.executeScript\s*\(",
        DangerousApi::TabsExecuteScript,
    ),
    (
        r"chrome\.tabs\.sendMessage\s*\(",
        DangerousApi::TabsSendMessage,
    ),
    (
        r"chrome\.runtime\.sendNativeMessage\s*\(",
        DangerousApi::RuntimeSendNativeMessage,
    ),
    (
        r"chrome\.webRequest\.onBeforeRequest\.",
        DangerousApi::WebRequestOnBeforeRequest,
    ),
    (
        r"chrome\.webRequest\.onBeforeSendHeaders\.",
        DangerousApi::WebRequestOnBeforeSendHeaders,
    ),
    (r"chrome\.cookies\.getAll\s*\(", DangerousApi::CookiesGetAll),
    (r"chrome\.cookies\.set\s*\(", DangerousApi::CookiesSet),
    (
        r"chrome\.debugger\.attach\s*\(",
        DangerousApi::DebuggerAttach,
    ),
    (
        r"chrome\.downloads\.download\s*\(",
        DangerousApi::DownloadsDownload,
    ),
    (
        r"chrome\.management\.getAll\s*\(",
        DangerousApi::ManagementGetAll,
    ),
    (
        r"chrome\.contentSettings\.\w+\.clear\s*\(",
        DangerousApi::ContentSettingsClear,
    ),
    (r"chrome\.history\.search\s*\(", DangerousApi::HistorySearch),
    (
        r"chrome\.bookmarks\.getTree\s*\(",
        DangerousApi::BookmarksGetTree,
    ),
    (r"chrome\.topSites\.get\s*\(", DangerousApi::TopSitesGet),
];

/// Detects dangerous APIs used in extension JavaScript source.
pub fn detect_dangerous_apis(js_source: &str) -> Vec<DangerousApi> {
    let mut found = Vec::new();
    for (pattern, api) in DANGEROUS_API_PATTERNS {
        if let Ok(re) = Regex::new(pattern)
            && re.is_match(js_source)
        {
            found.push(*api);
        }
    }
    found
}

/// Detects content script injection patterns in JS source.
pub fn detect_content_script_injection(js_source: &str) -> Vec<String> {
    let mut issues = Vec::new();

    let dom_write_patterns: &[(&str, &str)] = &[
        (
            r"document\.write\s*\(",
            "document.write() in content script -- DOM clobbering risk",
        ),
        (
            r#"\.innerHTML\s*=\s*[^'";\n]*(?:chrome\.runtime|chrome\.storage|chrome\.tabs)"#,
            "innerHTML set from extension API data -- XSS via privileged data injection",
        ),
        (
            r#"\.innerHTML\s*=\s*[^'";\n]*(?:response|data|result|msg)"#,
            "innerHTML set from dynamic data in content script -- potential XSS",
        ),
        (
            r"eval\s*\(\s*(?:chrome\.runtime|chrome\.storage|message|msg|response|data)",
            "eval() on extension API data -- code execution via message injection",
        ),
        (
            r#"document\.createElement\s*\(\s*['"]script['"]\s*\)"#,
            "dynamic script element creation in content script -- script injection vector",
        ),
        (
            r"window\.__\w+\s*=\s*(?:chrome\.runtime|chrome\.extension)",
            "extension API reference leaked to page global scope",
        ),
    ];

    for (pattern, desc) in dom_write_patterns {
        if let Ok(re) = Regex::new(pattern)
            && re.is_match(js_source)
        {
            issues.push(desc.to_string());
        }
    }

    issues
}

/// Detects exposed message passing handlers in extension JS.
pub fn detect_message_passing_exposure(js_source: &str) -> Vec<String> {
    let mut issues = Vec::new();

    let patterns: &[(&str, &str)] = &[
        (
            r"chrome\.runtime\.onMessageExternal\.addListener",
            "onMessageExternal handler — any extension or webpage can send messages",
        ),
        (
            r"chrome\.runtime\.onConnectExternal\.addListener",
            "onConnectExternal handler — any extension or webpage can open a port",
        ),
        (
            r"chrome\.runtime\.onMessage\.addListener\s*\(\s*(?:function\s*\([^)]*\)|(?:\([^)]*\)|\w+)\s*=>)\s*\{[^}]*(?:sender\.url|sender\.tab)",
            "onMessage handler references sender but may not validate sender identity",
        ),
    ];

    for (pattern, desc) in patterns {
        if let Ok(re) = Regex::new(pattern)
            && re.is_match(js_source)
        {
            issues.push(desc.to_string());
        }
    }

    let external_listener_re =
        Regex::new(r"chrome\.runtime\.onMessageExternal\.addListener").expect("valid regex");

    let sender_check_re = Regex::new(r"sender\.id\s*(?:===|!==|==|!=)").expect("valid regex");

    if external_listener_re.is_match(js_source) && !sender_check_re.is_match(js_source) {
        issues.push(
            "onMessageExternal lacks sender.id validation — any extension can impersonate messages"
                .to_string(),
        );
    }

    issues
}

/// Detects extension-to-webpage data leakage patterns.
pub fn detect_data_leakage(js_source: &str) -> Vec<String> {
    let mut issues = Vec::new();

    let patterns: &[(&str, &str)] = &[
        (
            r"window\.postMessage\s*\([^)]*(?:chrome\.storage|chrome\.cookies|chrome\.tabs)",
            "extension data sent to page via window.postMessage — cross-context leakage",
        ),
        (
            r"document\.dispatchEvent\s*\(\s*new\s+CustomEvent\s*\([^)]*(?:detail|data)\s*:",
            "extension data dispatched via CustomEvent — page scripts can intercept",
        ),
        (
            r"(?:document|window)\.\w+\s*=\s*(?:chrome\.storage|chrome\.cookies|chrome\.runtime)",
            "extension API data assigned to DOM global — accessible by page scripts",
        ),
        (
            r#"\.setAttribute\s*\(\s*['"]data-\w+['"]\s*,\s*(?:JSON\.stringify|chrome\.)"#,
            "extension data embedded in DOM attribute -- readable by page scripts",
        ),
        (
            r"\.textContent\s*=\s*(?:JSON\.stringify\s*\(\s*)?(?:chrome\.storage|chrome\.cookies)",
            "extension data written to DOM textContent — extractable by page scripts",
        ),
    ];

    for (pattern, desc) in patterns {
        if let Ok(re) = Regex::new(pattern)
            && re.is_match(js_source)
        {
            issues.push(desc.to_string());
        }
    }

    issues
}

/// Detects cross-extension storage attack patterns.
pub fn detect_cross_extension_storage(js_source: &str) -> Vec<String> {
    let mut issues = Vec::new();

    let patterns: &[(&str, &str)] = &[
        (
            r"chrome\.storage\.sync\.get\s*\(\s*null\s*[,)]",
            "reads all sync storage keys — exposed to any synced extension",
        ),
        (
            r"chrome\.storage\.local\.get\s*\(\s*null\s*[,)]",
            "reads all local storage keys — information disclosure if storage is shared",
        ),
        (
            r"chrome\.storage\.onChanged\.addListener",
            "listens for storage changes — can detect other extensions' state changes",
        ),
        (
            r"chrome\.storage\.sync\.set\s*\(",
            "writes to sync storage — data persists across devices and potentially accessible by other extensions sharing account",
        ),
    ];

    for (pattern, desc) in patterns {
        if let Ok(re) = Regex::new(pattern)
            && re.is_match(js_source)
        {
            issues.push(desc.to_string());
        }
    }

    issues
}

/// Detects web_accessible_resources XSS vectors in source.
pub fn detect_war_xss_vectors(web_accessible_resources: &[String], js_source: &str) -> Vec<String> {
    let mut issues = Vec::new();

    for resource in web_accessible_resources {
        if resource.ends_with(".html") || resource.ends_with(".htm") {
            issues.push(format!(
                "HTML file '{}' in web_accessible_resources — potential XSS if it includes user-controlled content",
                resource
            ));
        }
        if resource.ends_with(".js") {
            issues.push(format!(
                "JavaScript file '{}' in web_accessible_resources — can be loaded by any webpage for fingerprinting or exploitation",
                resource
            ));
        }
        if resource == "*" || resource == "/*" {
            issues.push(
                "wildcard web_accessible_resources — all extension files accessible to any webpage"
                    .to_string(),
            );
        }
    }

    let war_load_re =
        Regex::new(r#"chrome\.runtime\.getURL\s*\(\s*['"]([^'"]+)['"]\s*\)"#).expect("valid regex");

    for cap in war_load_re.captures_iter(js_source) {
        let resource_path = &cap[1];
        if resource_path.ends_with(".html") {
            issues.push(format!(
                "getURL('{}') loads extension HTML — if web-accessible, attackers can iframe it",
                resource_path
            ));
        }
    }

    issues
}

/// Analyzes extension permissions and returns findings for dangerous ones.
fn analyze_permissions(manifest: &ExtensionManifest) -> Vec<ExtensionFinding> {
    let mut findings = Vec::new();
    let permission_map: HashMap<&str, (PermissionRisk, &str)> = DANGEROUS_PERMISSIONS
        .iter()
        .map(|(name, risk, desc)| (*name, (*risk, *desc)))
        .collect();

    let all_permissions: Vec<&String> = manifest
        .permissions
        .iter()
        .chain(manifest.host_permissions.iter())
        .collect();

    for perm in &all_permissions {
        let perm_str = perm.as_str();
        if let Some((risk, desc)) = permission_map.get(perm_str) {
            let severity = match risk {
                PermissionRisk::Critical => ExtensionSeverity::Critical,
                PermissionRisk::High => ExtensionSeverity::High,
                PermissionRisk::Medium => ExtensionSeverity::Medium,
                PermissionRisk::Low => ExtensionSeverity::Low,
            };
            findings.push(ExtensionFinding {
                vuln_type: ExtensionVulnType::DangerousPermission,
                severity,
                description: format!("Permission '{}': {}", perm, desc),
                evidence: format!("manifest.json permissions: {:?}", manifest.permissions),
                remediation: format!(
                    "Review whether '{}' is necessary; prefer narrower scoped permissions",
                    perm
                ),
            });
        }
    }

    findings
}

/// Analyzes content script entries for security issues.
fn analyze_content_scripts(manifest: &ExtensionManifest) -> Vec<ExtensionFinding> {
    let mut findings = Vec::new();

    for cs in &manifest.content_scripts {
        if cs.matches.contains(&"<all_urls>".to_string())
            || cs.matches.contains(&"*://*/*".to_string())
        {
            findings.push(ExtensionFinding {
                vuln_type: ExtensionVulnType::ContentScriptInjection,
                severity: ExtensionSeverity::High,
                description: format!(
                    "Content script injected on all pages (matches: {:?}) — large attack surface",
                    cs.matches
                ),
                evidence: format!("JS files: {:?}, run_at: {}", cs.js, cs.run_at),
                remediation: "Restrict content_scripts matches to only required domains"
                    .to_string(),
            });
        }

        if cs.all_frames {
            findings.push(ExtensionFinding {
                vuln_type: ExtensionVulnType::ContentScriptInjection,
                severity: ExtensionSeverity::Medium,
                description: "Content script runs in all_frames — injected into iframes including cross-origin".to_string(),
                evidence: format!("matches: {:?}, all_frames: true", cs.matches),
                remediation: "Set all_frames to false unless iframe injection is required".to_string(),
            });
        }

        if cs.run_at == "document_start" {
            findings.push(ExtensionFinding {
                vuln_type: ExtensionVulnType::ContentScriptInjection,
                severity: ExtensionSeverity::Medium,
                description: "Content script runs at document_start — can modify page before any other script executes".to_string(),
                evidence: format!("run_at: document_start, matches: {:?}", cs.matches),
                remediation: "Use document_idle unless early injection is required".to_string(),
            });
        }
    }

    findings
}

/// Analyzes web_accessible_resources for security issues.
fn analyze_web_accessible_resources(manifest: &ExtensionManifest) -> Vec<ExtensionFinding> {
    let mut findings = Vec::new();

    if manifest.web_accessible_resources.is_empty() {
        return findings;
    }

    let has_wildcard = manifest
        .web_accessible_resources
        .iter()
        .any(|r| r == "*" || r == "/*" || r == "**/*");

    if has_wildcard {
        findings.push(ExtensionFinding {
            vuln_type: ExtensionVulnType::WebAccessibleResourceXss,
            severity: ExtensionSeverity::High,
            description:
                "Wildcard web_accessible_resources exposes all extension files to any webpage"
                    .to_string(),
            evidence: format!(
                "web_accessible_resources: {:?}",
                manifest.web_accessible_resources
            ),
            remediation: "List only specific required files instead of wildcards".to_string(),
        });
    }

    let html_resources: Vec<&String> = manifest
        .web_accessible_resources
        .iter()
        .filter(|r| r.ends_with(".html") || r.ends_with(".htm"))
        .collect();

    for html in &html_resources {
        findings.push(ExtensionFinding {
            vuln_type: ExtensionVulnType::WebAccessibleResourceXss,
            severity: ExtensionSeverity::High,
            description: format!(
                "HTML file '{}' is web-accessible — can be iframed by attacker pages for XSS or clickjacking",
                html
            ),
            evidence: format!("web_accessible_resources contains '{}'", html),
            remediation: format!("Remove '{}' from web_accessible_resources or add CSP frame-ancestors", html),
        });
    }

    findings
}

/// Analyzes externally_connectable configuration.
fn analyze_externally_connectable(manifest: &ExtensionManifest) -> Vec<ExtensionFinding> {
    let mut findings = Vec::new();

    let Some(ec) = &manifest.externally_connectable else {
        return findings;
    };

    if ec.matches.contains(&"*://*/*".to_string()) || ec.matches.contains(&"<all_urls>".to_string())
    {
        findings.push(ExtensionFinding {
            vuln_type: ExtensionVulnType::ExternallyConnectable,
            severity: ExtensionSeverity::Critical,
            description: "externally_connectable matches all URLs — any webpage can send messages to this extension".to_string(),
            evidence: format!("externally_connectable.matches: {:?}", ec.matches),
            remediation: "Restrict matches to specific trusted domains".to_string(),
        });
    } else if !ec.matches.is_empty() {
        let broad_matches: Vec<&String> = ec.matches.iter().filter(|m| m.contains("*")).collect();

        if !broad_matches.is_empty() {
            findings.push(ExtensionFinding {
                vuln_type: ExtensionVulnType::ExternallyConnectable,
                severity: ExtensionSeverity::High,
                description: format!(
                    "externally_connectable uses wildcard patterns: {:?} — subdomain takeover could grant messaging access",
                    broad_matches
                ),
                evidence: format!("externally_connectable.matches: {:?}", ec.matches),
                remediation: "Use exact domain matches instead of wildcards".to_string(),
            });
        }
    }

    if ec.ids.contains(&"*".to_string()) {
        findings.push(ExtensionFinding {
            vuln_type: ExtensionVulnType::ExternallyConnectable,
            severity: ExtensionSeverity::High,
            description: "externally_connectable.ids includes wildcard — any extension can connect"
                .to_string(),
            evidence: format!("externally_connectable.ids: {:?}", ec.ids),
            remediation: "List specific extension IDs that should be allowed to connect"
                .to_string(),
        });
    }

    findings
}

/// Analyzes background script APIs for dangerous usage.
fn analyze_background_apis(manifest: &ExtensionManifest, js_source: &str) -> Vec<ExtensionFinding> {
    let mut findings = Vec::new();

    if manifest.background.is_none() {
        return findings;
    }

    let apis = detect_dangerous_apis(js_source);

    for api in &apis {
        let severity = match api {
            DangerousApi::DebuggerAttach => ExtensionSeverity::Critical,
            DangerousApi::TabsExecuteScript
            | DangerousApi::WebRequestOnBeforeRequest
            | DangerousApi::WebRequestOnBeforeSendHeaders
            | DangerousApi::CookiesGetAll => ExtensionSeverity::High,
            DangerousApi::RuntimeSendNativeMessage
            | DangerousApi::ManagementGetAll
            | DangerousApi::CookiesSet => ExtensionSeverity::High,
            DangerousApi::TabsSendMessage
            | DangerousApi::DownloadsDownload
            | DangerousApi::HistorySearch
            | DangerousApi::ContentSettingsClear => ExtensionSeverity::Medium,
            DangerousApi::BookmarksGetTree | DangerousApi::TopSitesGet => ExtensionSeverity::Low,
        };

        findings.push(ExtensionFinding {
            vuln_type: ExtensionVulnType::BackgroundApiAccess,
            severity,
            description: format!("Background script uses {} — privileged API accessible from content scripts via messaging", api),
            evidence: format!("API call: {}", api),
            remediation: format!("Validate message sender before executing {} calls", api),
        });
    }

    findings
}

/// Run the full browser extension security analysis pipeline.
pub fn analyze_extension(
    manifest_json: Option<&str>,
    js_source: &str,
    page_source: Option<&str>,
    config: &ExtensionAnalysisConfig,
) -> ExtensionAnalysis {
    let mut findings = Vec::new();
    let mut dangerous_apis = Vec::new();
    let mut patterns_checked = 0u16;

    let extension_id = page_source.and_then(|src| extract_extension_ids(src).into_iter().next());

    if let Some(ps) = page_source {
        let ids = extract_extension_ids(ps);
        if !ids.is_empty() {
            patterns_checked += 1;
            findings.push(ExtensionFinding {
                vuln_type: ExtensionVulnType::ExtensionIdExposure,
                severity: ExtensionSeverity::Info,
                description: format!(
                    "Extension IDs detected in page source: {}",
                    ids.join(", ")
                ),
                evidence: "chrome-extension:// URLs found in HTML/JS source".to_string(),
                remediation: "Extension IDs can be used for fingerprinting — consider if exposure is necessary".to_string(),
            });
        }
    }

    let manifest = manifest_json.and_then(|json| parse_manifest(json).ok());

    if let Some(ref m) = manifest {
        if config.check_permissions {
            patterns_checked += 1;
            findings.extend(analyze_permissions(m));
        }

        if config.check_content_scripts {
            patterns_checked += 1;
            findings.extend(analyze_content_scripts(m));
        }

        if config.check_web_accessible_resources {
            patterns_checked += 1;
            let mut war_findings = analyze_web_accessible_resources(m);
            let js_war_issues = detect_war_xss_vectors(&m.web_accessible_resources, js_source);
            for issue in js_war_issues {
                war_findings.push(ExtensionFinding {
                    vuln_type: ExtensionVulnType::WebAccessibleResourceXss,
                    severity: ExtensionSeverity::Medium,
                    description: issue,
                    evidence: format!("web_accessible_resources: {:?}", m.web_accessible_resources),
                    remediation:
                        "Review web-accessible files for user-controlled content injection"
                            .to_string(),
                });
            }
            findings.extend(war_findings);
        }

        if config.check_externally_connectable {
            patterns_checked += 1;
            findings.extend(analyze_externally_connectable(m));
        }

        if config.check_background_apis {
            patterns_checked += 1;
            let bg_findings = analyze_background_apis(m, js_source);
            dangerous_apis = detect_dangerous_apis(js_source);
            findings.extend(bg_findings);
        }
    }

    if config.check_message_passing {
        patterns_checked += 1;
        let msg_issues = detect_message_passing_exposure(js_source);
        for issue in msg_issues {
            findings.push(ExtensionFinding {
                vuln_type: ExtensionVulnType::MessagePassingExposure,
                severity: ExtensionSeverity::High,
                description: issue,
                evidence: "chrome.runtime message handler found in JS source".to_string(),
                remediation: "Validate sender.id and sender.url in all message handlers"
                    .to_string(),
            });
        }
    }

    if config.check_content_scripts {
        let cs_issues = detect_content_script_injection(js_source);
        for issue in cs_issues {
            findings.push(ExtensionFinding {
                vuln_type: ExtensionVulnType::ContentScriptInjection,
                severity: ExtensionSeverity::High,
                description: issue,
                evidence: "Content script pattern found in JS source".to_string(),
                remediation: "Sanitize all data before DOM insertion in content scripts"
                    .to_string(),
            });
        }
    }

    if config.check_data_leakage {
        patterns_checked += 1;
        let leak_issues = detect_data_leakage(js_source);
        for issue in leak_issues {
            findings.push(ExtensionFinding {
                vuln_type: ExtensionVulnType::ExtensionDataLeakage,
                severity: ExtensionSeverity::High,
                description: issue,
                evidence: "Data leakage pattern found in JS source".to_string(),
                remediation: "Do not expose extension API data to page context; use chrome.runtime messaging instead".to_string(),
            });
        }
    }

    if config.check_cross_extension {
        patterns_checked += 1;
        let storage_issues = detect_cross_extension_storage(js_source);
        for issue in storage_issues {
            findings.push(ExtensionFinding {
                vuln_type: ExtensionVulnType::CrossExtensionStorageAttack,
                severity: ExtensionSeverity::Medium,
                description: issue,
                evidence: "chrome.storage pattern found in JS source".to_string(),
                remediation: "Encrypt sensitive data before storing in chrome.storage.sync"
                    .to_string(),
            });
        }
    }

    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    let critical_count = findings
        .iter()
        .filter(|f| f.severity == ExtensionSeverity::Critical)
        .count();
    let high_count = findings
        .iter()
        .filter(|f| f.severity == ExtensionSeverity::High)
        .count();
    let medium_count = findings
        .iter()
        .filter(|f| f.severity == ExtensionSeverity::Medium)
        .count();

    let summary = ExtensionSummary {
        total_findings: findings.len(),
        critical_count,
        high_count,
        medium_count,
        patterns_checked: patterns_checked as usize,
    };

    ExtensionAnalysis {
        extension_id,
        manifest,
        findings,
        dangerous_apis_used: dangerous_apis,
        summary,
    }
}

#[cfg(test)]
#[path = "browser_ext_analyzer_test.rs"]
mod browser_ext_analyzer_test;
