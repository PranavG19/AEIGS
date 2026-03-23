use crate::custom_element_audit::*;

#[test]
fn empty_body() {
    assert!(analyze_custom_element("").is_empty());
}

#[test]
fn no_api() {
    let body = "const x = document.querySelector('.widget');";
    assert!(analyze_custom_element(body).is_empty());
}

#[test]
fn detects_custom_elements_define() {
    let body = "customElements.define('my-tag', MyTag);";
    let issues = analyze_custom_element(body);
    assert!(issues.contains(&CustomElementIssue::ApiDetected));
}

#[test]
fn detects_html_element_extends() {
    let body = "class MyTag extends HTMLElement { }";
    let issues = analyze_custom_element(body);
    assert!(issues.contains(&CustomElementIssue::ApiDetected));
}

#[test]
fn detects_unsanitized_content() {
    let body = r#"
        customElements.define('my-tag', class extends HTMLElement {
            connectedCallback() {
                this.innerHTML = this.getAttribute('data');
            }
        });
    "#;
    let issues = analyze_custom_element(body);
    assert!(issues.contains(&CustomElementIssue::UnsanitizedContent));
}

#[test]
fn no_unsanitized_with_dompurify() {
    let body = r#"
        customElements.define('my-tag', class extends HTMLElement {
            connectedCallback() {
                this.innerHTML = DOMPurify.sanitize(this.getAttribute('data'));
            }
        });
    "#;
    let issues = analyze_custom_element(body);
    assert!(!issues.contains(&CustomElementIssue::UnsanitizedContent));
}

#[test]
fn detects_prototype_pollution() {
    let body = r#"
        customElements.define('my-tag', class extends HTMLElement {
            connectedCallback() {
                const opts = {};
                opts.__proto__.polluted = true;
            }
        });
    "#;
    let issues = analyze_custom_element(body);
    assert!(issues.contains(&CustomElementIssue::PrototypePollution));
}

#[test]
fn no_pollution_without_callback() {
    let body = r#"
        customElements.define('my-tag', class extends HTMLElement {});
        const x = {}; x.__proto__.bad = true;
    "#;
    let issues = analyze_custom_element(body);
    assert!(!issues.contains(&CustomElementIssue::PrototypePollution));
}

#[test]
fn detects_event_hijacking() {
    let body = r#"
        customElements.define('my-tag', class extends HTMLElement {
            connectedCallback() {
                document.dispatchEvent(new CustomEvent('data', {detail: this}));
            }
        });
    "#;
    let issues = analyze_custom_element(body);
    assert!(issues.contains(&CustomElementIssue::EventHijacking));
}

#[test]
fn no_hijacking_with_stop_propagation() {
    let body = r#"
        customElements.define('my-tag', class extends HTMLElement {
            connectedCallback() {
                const ev = new CustomEvent('data');
                document.dispatchEvent(ev);
                ev.stopPropagation();
            }
        });
    "#;
    let issues = analyze_custom_element(body);
    assert!(!issues.contains(&CustomElementIssue::EventHijacking));
}

#[test]
fn detects_name_collision() {
    let body = r#"
        customElements.define('my-tag', MyTag);
        customElements.whenDefined('my-tag').then(() => {});
    "#;
    let issues = analyze_custom_element(body);
    assert!(issues.contains(&CustomElementIssue::NameCollision));
}

#[test]
fn all_issues() {
    let body = r#"
        customElements.define('my-tag', class extends HTMLElement {
            connectedCallback() {
                this.innerHTML = this.getAttribute('data');
                const opts = {}; opts.__proto__.x = 1;
                document.dispatchEvent(new CustomEvent('x'));
            }
        });
        customElements.whenDefined('my-tag');
    "#;
    let issues = analyze_custom_element(body);
    assert_eq!(issues.len(), 5);
    assert!(issues.contains(&CustomElementIssue::ApiDetected));
    assert!(issues.contains(&CustomElementIssue::UnsanitizedContent));
    assert!(issues.contains(&CustomElementIssue::PrototypePollution));
    assert!(issues.contains(&CustomElementIssue::EventHijacking));
    assert!(issues.contains(&CustomElementIssue::NameCollision));
}

#[test]
fn severity_values() {
    assert_eq!(custom_element_severity(&CustomElementIssue::ApiDetected), 2.0);
    assert_eq!(custom_element_severity(&CustomElementIssue::UnsanitizedContent), 7.5);
    assert_eq!(custom_element_severity(&CustomElementIssue::PrototypePollution), 7.0);
    assert_eq!(custom_element_severity(&CustomElementIssue::EventHijacking), 6.0);
    assert_eq!(custom_element_severity(&CustomElementIssue::NameCollision), 5.0);
}

#[test]
fn display_impl() {
    assert_eq!(CustomElementIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(CustomElementIssue::UnsanitizedContent.to_string(), "unsanitized_content");
    assert_eq!(CustomElementIssue::PrototypePollution.to_string(), "prototype_pollution");
    assert_eq!(CustomElementIssue::EventHijacking.to_string(), "event_hijacking");
    assert_eq!(CustomElementIssue::NameCollision.to_string(), "name_collision");
}

#[test]
fn ops_generated() {
    let issues = vec![CustomElementIssue::ApiDetected, CustomElementIssue::UnsanitizedContent];
    let mut seq = 0;
    let ops = custom_element_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
}

#[test]
fn ops_increment_seq() {
    let issues = vec![
        CustomElementIssue::ApiDetected,
        CustomElementIssue::PrototypePollution,
        CustomElementIssue::EventHijacking,
    ];
    let mut seq = 5;
    let ops = custom_element_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 8);
}

#[test]
fn detects_attribute_changed_callback() {
    let body = r#"
        customElements.define('my-tag', class extends HTMLElement {
            attributeChangedCallback(name, old, val) {
                Object.assign(this.config, JSON.parse(val));
            }
        });
    "#;
    let issues = analyze_custom_element(body);
    assert!(issues.contains(&CustomElementIssue::PrototypePollution));
}

#[test]
fn no_api_plain_html() {
    let body = "<html><body><h1>Hello World</h1><p>No components here</p></body></html>";
    assert!(analyze_custom_element(body).is_empty());
}
