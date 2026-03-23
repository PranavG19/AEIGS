use crate::template_injection_audit::*;

#[test]
fn empty_body_no_issues() {
    assert!(analyze_template_injection("").is_empty());
}

#[test]
fn safe_html_no_issues() {
    let body = "<h1>Hello</h1><p>Normal page</p>";
    assert!(analyze_template_injection(body).is_empty());
}

#[test]
fn angular_ng_bind_html_detected() {
    let body = r#"<div ng-bind-html="userInput"></div>"#;
    let issues = analyze_template_injection(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TemplateInjectionIssue::AngularExpression))
    );
}

#[test]
fn angular_bypass_security_detected() {
    let body = "this.sanitizer.bypassSecurityTrustHtml(input)";
    let issues = analyze_template_injection(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TemplateInjectionIssue::AngularExpression))
    );
}

#[test]
fn angular_innerhtml_binding() {
    let body = r#"<div [innerHTML]="content"></div>"#;
    let issues = analyze_template_injection(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TemplateInjectionIssue::AngularExpression))
    );
}

#[test]
fn vue_v_html_detected() {
    let body = r#"<div v-html="rawHtml"></div>"#;
    let issues = analyze_template_injection(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TemplateInjectionIssue::VueInterpolation))
    );
}

#[test]
fn handlebars_triple_brace_detected() {
    let body = "{{{userInput}}}";
    let issues = analyze_template_injection(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TemplateInjectionIssue::HandlebarsExpression))
    );
}

#[test]
fn handlebars_lookup_detected() {
    let body = "{{lookup this 'constructor'}}";
    let issues = analyze_template_injection(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TemplateInjectionIssue::HandlebarsExpression))
    );
}

#[test]
fn handlebars_with_block_detected() {
    let body = "{{#with 'constructor'}}{{this}}{{/with}}";
    let issues = analyze_template_injection(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TemplateInjectionIssue::HandlebarsExpression))
    );
}

#[test]
fn ejs_expression_detected() {
    let body = "<%= user.name %>";
    let issues = analyze_template_injection(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TemplateInjectionIssue::EjsExpression))
    );
}

#[test]
fn ejs_unescaped_detected() {
    let body = "<%- rawContent %>";
    let issues = analyze_template_injection(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TemplateInjectionIssue::EjsExpression))
    );
}

#[test]
fn jinja_class_access_detected() {
    let body = "{{request.__class__.__mro__}}";
    let issues = analyze_template_injection(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TemplateInjectionIssue::JinjaExpression))
    );
}

#[test]
fn jinja_subclasses_detected() {
    let body = "{{''.__class__.__mro__[2].__subclasses__()}}";
    let issues = analyze_template_injection(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TemplateInjectionIssue::JinjaExpression))
    );
}

#[test]
fn template_eval_new_function_detected() {
    let body = "var fn = new Function(userInput);";
    let issues = analyze_template_injection(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TemplateInjectionIssue::TemplateStringEval))
    );
}

#[test]
fn template_eval_settimeout_string_detected() {
    let body = r#"setTimeout("doSomething()", 100);"#;
    let issues = analyze_template_injection(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TemplateInjectionIssue::TemplateStringEval))
    );
}

#[test]
fn safe_double_braces_not_flagged_as_jinja() {
    let body = "{{title}} and {{content}}";
    let issues = analyze_template_injection(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, TemplateInjectionIssue::JinjaExpression))
    );
}

#[test]
fn severity_ordering() {
    assert!(
        template_injection_severity(&TemplateInjectionIssue::AngularExpression)
            > template_injection_severity(&TemplateInjectionIssue::JinjaExpression)
    );
    assert!(
        template_injection_severity(&TemplateInjectionIssue::JinjaExpression)
            > template_injection_severity(&TemplateInjectionIssue::TemplateStringEval)
    );
}

#[test]
fn display_format() {
    assert_eq!(
        TemplateInjectionIssue::AngularExpression.to_string(),
        "angular_template_injection"
    );
    assert_eq!(
        TemplateInjectionIssue::VueInterpolation.to_string(),
        "vue_template_injection"
    );
}

#[test]
fn to_operations_count() {
    let issues = vec![
        TemplateInjectionIssue::AngularExpression,
        TemplateInjectionIssue::TemplateStringEval,
    ];
    let mut seq = 0;
    let ops = template_injection_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}
