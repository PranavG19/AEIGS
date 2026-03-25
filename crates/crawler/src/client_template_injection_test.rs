use super::client_template_injection::*;

const HTML_ANGULAR_APP: &str = r#"
<html ng-app="myApp">
<body ng-controller="MainCtrl">
    <div ng-bind-html="userInput">{{message}}</div>
    <input ng-model="search">
</body>
</html>
"#;

const JS_ANGULAR: &str = r#"
angular.module('myApp', []);
"#;

const HTML_VUE_APP: &str = r#"
<div id="app">
    <p v-html="userContent">loading...</p>
    <span v-if="show">{{title}}</span>
    <input v-model="query">
</div>
"#;

const JS_VUE: &str = r#"
new Vue({
    el: '#app',
    data: { userContent: '', title: '', query: '' }
});
"#;

const HTML_REACT_DANGEROUS: &str = r#"
<div>
    <div dangerouslySetInnerHTML={{ __html: userInput }}></div>
    <div dangerouslySetInnerHTML={{ __html: sanitizedContent }}></div>
</div>
"#;

const JS_REACT: &str = r#"
ReactDOM.render(React.createElement('div', null), document.getElementById('root'));
"#;

const HTML_SVELTE_HTML: &str = r#"
<div>
    <p>{@html userMessage}</p>
    <p>{@html staticContent}</p>
</div>
"#;

const HTML_HANDLEBARS_UNESCAPED: &str = r#"
<div>
    <p>{{{userComment}}}</p>
    <p>{{safeContent}}</p>
    <p>{{{htmlBody}}}</p>
</div>
"#;

const JS_HANDLEBARS: &str = r#"
var template = Handlebars.compile(source);
"#;

const HTML_ANGULAR_SANDBOX_ESCAPE: &str = r#"
<html ng-app>
<body>
    <div>{{constructor.constructor('alert(1)')()}}</div>
</body>
</html>
"#;

const HTML_VUE_COMPILE: &str = r#"
<div id="app"></div>
"#;

const JS_VUE_COMPILE: &str = r#"
var compiled = Vue.compile(req.body.template);
new Vue({ el: '#app', render: compiled.render });
"#;

const HTML_SSR_LEAK: &str = r#"
<div>
    <p><%= req.query.name %></p>
    <span>#{request.params.id}</span>
</div>
"#;

const HTML_CLEAN_NO_TEMPLATES: &str = r#"
<div class="container">
    <p>Plain HTML content</p>
    <span>No template expressions here</span>
</div>
"#;

const JS_CLEAN: &str = r#"
document.getElementById('output').textContent = 'safe';
"#;

#[test]
fn detects_angular_framework() {
    let frameworks = detect_frameworks(HTML_ANGULAR_APP, JS_ANGULAR);
    assert!(
        frameworks.contains(&JsFramework::Angular),
        "should detect Angular framework"
    );
}

#[test]
fn detects_vue_framework() {
    let frameworks = detect_frameworks(HTML_VUE_APP, JS_VUE);
    assert!(
        frameworks.contains(&JsFramework::Vue),
        "should detect Vue framework"
    );
}

#[test]
fn detects_react_framework() {
    let frameworks = detect_frameworks(HTML_REACT_DANGEROUS, JS_REACT);
    assert!(
        frameworks.contains(&JsFramework::React),
        "should detect React framework"
    );
}

#[test]
fn detects_svelte_framework() {
    let frameworks = detect_frameworks(HTML_SVELTE_HTML, "");
    assert!(
        frameworks.contains(&JsFramework::Svelte),
        "should detect Svelte framework"
    );
}

#[test]
fn detects_handlebars_framework() {
    let frameworks = detect_frameworks(HTML_HANDLEBARS_UNESCAPED, JS_HANDLEBARS);
    assert!(
        frameworks.contains(&JsFramework::Handlebars),
        "should detect Handlebars framework"
    );
}

#[test]
fn detects_angular_expression_injection() {
    let config = CstiConfig::default().with_target("http://localhost:4200");
    let analysis = analyze_csti(HTML_ANGULAR_APP, JS_ANGULAR, &config);

    let angular_findings: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.csti_type == CstiType::AngularExpressionInjection)
        .collect();

    assert!(
        !angular_findings.is_empty(),
        "should detect Angular expression injection via ng-bind-html"
    );

    let has_critical = angular_findings
        .iter()
        .any(|f| f.severity == CstiSeverity::Critical);
    assert!(
        has_critical,
        "ng-bind-html with user input should be critical"
    );
}

#[test]
fn detects_angular_sandbox_escape_pattern() {
    let config = CstiConfig::default().with_target("http://localhost:4200");
    let findings = detect_angular_injection(HTML_ANGULAR_SANDBOX_ESCAPE, &config);

    let sandbox_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.matched_pattern.contains("constructor"))
        .collect();

    assert!(
        !sandbox_findings.is_empty(),
        "should detect Angular sandbox escape patterns"
    );
}

#[test]
fn detects_vue_vhtml_injection() {
    let config = CstiConfig::default().with_target("http://localhost:8080");
    let analysis = analyze_csti(HTML_VUE_APP, JS_VUE, &config);

    let vue_findings: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.csti_type == CstiType::VueTemplateInjection)
        .collect();

    assert!(
        !vue_findings.is_empty(),
        "should detect Vue v-html injection"
    );

    let user_controlled = vue_findings
        .iter()
        .find(|f| f.matched_pattern.contains("userContent"));
    assert!(
        user_controlled.is_some(),
        "should flag v-html bound to user-controllable expression"
    );
}

#[test]
fn detects_vue_compile_with_user_input() {
    let config = CstiConfig::default().with_target("http://localhost:8080");
    let findings = detect_vue_injection(HTML_VUE_COMPILE, JS_VUE_COMPILE, &config);

    assert!(
        !findings.is_empty(),
        "should detect Vue.compile with user input"
    );

    let compile_finding = findings
        .iter()
        .find(|f| f.description.contains("Vue.compile"));
    assert!(
        compile_finding.is_some(),
        "should specifically flag Vue.compile"
    );
}

#[test]
fn detects_react_dangerous_innerhtml() {
    let config = CstiConfig::default().with_target("http://localhost:3000");
    let analysis = analyze_csti(HTML_REACT_DANGEROUS, JS_REACT, &config);

    let react_findings: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.csti_type == CstiType::ReactDangerousInnerHtml)
        .collect();

    assert!(
        react_findings.len() >= 2,
        "should detect both dangerouslySetInnerHTML usages, found {}",
        react_findings.len()
    );

    let user_input_finding = react_findings
        .iter()
        .find(|f| f.matched_pattern.contains("userInput"));
    assert!(user_input_finding.is_some());
    assert_eq!(
        user_input_finding.unwrap().severity,
        CstiSeverity::Critical,
        "user-controlled dangerouslySetInnerHTML should be critical"
    );
}

#[test]
fn detects_svelte_html_tag_injection() {
    let config = CstiConfig::default().with_target("http://localhost:5173");
    let analysis = analyze_csti(HTML_SVELTE_HTML, "", &config);

    let svelte_findings: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.csti_type == CstiType::SvelteHtmlTag)
        .collect();

    assert!(
        svelte_findings.len() >= 2,
        "should detect both {@html} usages"
    );

    let user_msg = svelte_findings
        .iter()
        .find(|f| f.matched_pattern.contains("userMessage"));
    assert!(user_msg.is_some());
    assert_eq!(
        user_msg.unwrap().severity,
        CstiSeverity::Critical,
        "user-controllable {@html} should be critical"
    );
}

#[test]
fn detects_unescaped_handlebars_output() {
    let config = CstiConfig::default().with_target("http://localhost:3000");
    let analysis = analyze_csti(HTML_HANDLEBARS_UNESCAPED, JS_HANDLEBARS, &config);

    let unescaped_findings: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.csti_type == CstiType::UnescapedTemplateOutput)
        .collect();

    assert!(
        unescaped_findings.len() >= 2,
        "should detect unescaped triple-brace outputs, found {}",
        unescaped_findings.len()
    );
}

#[test]
fn detects_ssr_template_exposure() {
    let config = CstiConfig::default().with_target("http://localhost:3000");
    let findings = detect_ssr_exposure(HTML_SSR_LEAK, &config);

    assert!(
        !findings.is_empty(),
        "should detect SSR template leaks in client HTML"
    );

    let has_req = findings
        .iter()
        .any(|f| f.matched_pattern.contains("req.") || f.matched_pattern.contains("request."));
    assert!(
        has_req,
        "should flag server-side expressions with request references"
    );
}

#[test]
fn clean_html_produces_no_findings() {
    let config = CstiConfig::default().with_target("http://localhost:3000");
    let analysis = analyze_csti(HTML_CLEAN_NO_TEMPLATES, JS_CLEAN, &config);

    assert_eq!(
        analysis.findings.len(),
        0,
        "clean HTML should produce no CSTI findings"
    );
}

#[test]
fn generates_angular_payloads() {
    let payloads = generate_csti_payloads(JsFramework::Angular);
    assert!(
        payloads.len() >= 5,
        "should generate at least 5 Angular payloads"
    );
    assert!(
        payloads.iter().any(|p| p.contains("constructor")),
        "Angular payloads should include sandbox escape"
    );
}

#[test]
fn generates_vue_payloads() {
    let payloads = generate_csti_payloads(JsFramework::Vue);
    assert!(
        payloads.len() >= 3,
        "should generate at least 3 Vue payloads"
    );
}

#[test]
fn generates_react_payloads() {
    let payloads = generate_csti_payloads(JsFramework::React);
    assert!(
        payloads.len() >= 3,
        "should generate at least 3 React payloads"
    );
    assert!(
        payloads.iter().any(|p| p.contains("onerror")),
        "React payloads should include event handler XSS"
    );
}

#[test]
fn generates_svelte_payloads() {
    let payloads = generate_csti_payloads(JsFramework::Svelte);
    assert!(
        payloads.len() >= 3,
        "should generate at least 3 Svelte payloads"
    );
}

#[test]
fn summary_counts_match() {
    let config = CstiConfig::default().with_target("http://localhost:3000");
    let analysis = analyze_csti(HTML_ANGULAR_APP, JS_ANGULAR, &config);

    assert_eq!(
        analysis.summary.total_findings,
        analysis.findings.len(),
        "summary count should match findings vec"
    );

    let actual_critical = analysis
        .findings
        .iter()
        .filter(|f| f.severity == CstiSeverity::Critical)
        .count();
    assert_eq!(analysis.summary.critical_count, actual_critical);
}

#[test]
fn findings_sorted_by_severity() {
    let config = CstiConfig::default().with_target("http://localhost:3000");
    let analysis = analyze_csti(HTML_ANGULAR_APP, JS_ANGULAR, &config);

    for pair in analysis.findings.windows(2) {
        assert!(
            pair[0].severity >= pair[1].severity,
            "findings should be sorted by severity descending"
        );
    }
}

#[test]
fn framework_display_formatting() {
    assert_eq!(format!("{}", JsFramework::Angular), "Angular");
    assert_eq!(format!("{}", JsFramework::Vue), "Vue");
    assert_eq!(format!("{}", JsFramework::React), "React");
    assert_eq!(format!("{}", JsFramework::Svelte), "Svelte");
    assert_eq!(format!("{}", JsFramework::Handlebars), "Handlebars");
    assert_eq!(format!("{}", JsFramework::EJS), "EJS");
}

#[test]
fn severity_display_formatting() {
    assert_eq!(format!("{}", CstiSeverity::Critical), "critical");
    assert_eq!(format!("{}", CstiSeverity::High), "high");
    assert_eq!(format!("{}", CstiSeverity::Medium), "medium");
    assert_eq!(format!("{}", CstiSeverity::Low), "low");
    assert_eq!(format!("{}", CstiSeverity::Info), "info");
}

#[test]
fn csti_type_display_formatting() {
    assert_eq!(
        format!("{}", CstiType::AngularExpressionInjection),
        "angular-expression-injection"
    );
    assert_eq!(
        format!("{}", CstiType::VueTemplateInjection),
        "vue-template-injection"
    );
    assert_eq!(
        format!("{}", CstiType::ReactDangerousInnerHtml),
        "react-dangerous-innerhtml"
    );
    assert_eq!(format!("{}", CstiType::SvelteHtmlTag), "svelte-html-tag");
}

#[test]
fn config_builder_pattern() {
    let config = CstiConfig::default()
        .with_target("http://test.com")
        .with_payloads(false)
        .with_reflected_params(vec!["q".to_string(), "search".to_string()]);

    assert_eq!(config.target_url, "http://test.com");
    assert!(!config.generate_payloads);
    assert_eq!(config.check_reflected_params.len(), 2);
}

#[test]
fn extract_template_expressions_finds_double_braces() {
    let html = r#"<p>{{message}}</p><span>{{user.name}}</span>"#;
    let frameworks = vec![JsFramework::Angular];
    let exprs = extract_template_expressions(html, &frameworks);

    assert!(
        exprs.len() >= 2,
        "should find at least 2 template expressions"
    );

    let has_message = exprs.iter().any(|e| e.raw.contains("message"));
    assert!(has_message, "should find {{message}} expression");
}

#[test]
fn disabled_payload_generation() {
    let config = CstiConfig::default()
        .with_target("http://localhost:3000")
        .with_payloads(false);

    let analysis = analyze_csti(HTML_ANGULAR_APP, JS_ANGULAR, &config);

    for f in &analysis.findings {
        assert!(
            f.payload.is_none(),
            "should not generate payloads when disabled"
        );
    }
}
