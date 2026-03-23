use crate::dependency_confusion_audit::*;

#[test]
fn empty_body_no_issues() {
    assert!(analyze_dependency_confusion("").is_empty());
}

#[test]
fn no_packages_no_issues() {
    let body = "<h1>Hello World</h1>";
    assert!(analyze_dependency_confusion(body).is_empty());
}

#[test]
fn public_scope_not_flagged() {
    let body = r#"import "@angular/core""#;
    let issues = analyze_dependency_confusion(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DepConfusionIssue::InternalScopedPackage { .. }))
    );
}

#[test]
fn internal_scope_detected() {
    let body = r#"require("@mycompany/shared-utils")"#;
    let issues = analyze_dependency_confusion(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        DepConfusionIssue::InternalScopedPackage { scope } if scope == "@mycompany"
    )));
}

#[test]
fn multiple_scopes_deduped() {
    let body = r#"
        import "@mycompany/lib-a"
        import "@mycompany/lib-b"
    "#;
    let issues = analyze_dependency_confusion(body);
    let scope_count = issues
        .iter()
        .filter(|i| matches!(i, DepConfusionIssue::InternalScopedPackage { .. }))
        .count();
    assert_eq!(scope_count, 1);
}

#[test]
fn private_registry_detected() {
    let body = r#"registry: "https://npm.pkg.github.com""#;
    let issues = analyze_dependency_confusion(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DepConfusionIssue::PrivateRegistryUrl { .. }))
    );
}

#[test]
fn artifactory_detected() {
    let body = r#"url = "https://mycompany.jfrog.io/npm/""#;
    let issues = analyze_dependency_confusion(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DepConfusionIssue::PrivateRegistryUrl { .. }))
    );
}

#[test]
fn public_npm_registry_not_flagged() {
    let body = r#"registry = "https://registry.npmjs.org""#;
    let issues = analyze_dependency_confusion(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DepConfusionIssue::PrivateRegistryUrl { .. }))
    );
}

#[test]
fn lockfile_reference_detected() {
    let body = r#"href="/package-lock.json""#;
    let issues = analyze_dependency_confusion(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        DepConfusionIssue::LockfileExposed { path } if path == "package-lock.json"
    )));
}

#[test]
fn yarn_lock_detected() {
    let body = r#"<a href="yarn.lock">download</a>"#;
    let issues = analyze_dependency_confusion(body);
    assert!(
        issues.iter().any(
            |i| matches!(i, DepConfusionIssue::LockfileExposed { path } if path == "yarn.lock")
        )
    );
}

#[test]
fn cargo_lock_detected() {
    let body = "See cargo.lock for details";
    let issues = analyze_dependency_confusion(body);
    assert!(
        issues.iter().any(
            |i| matches!(i, DepConfusionIssue::LockfileExposed { path } if path == "cargo.lock")
        )
    );
}

#[test]
fn internal_package_name_detected() {
    let body = r#"package: "my-company-internal""#;
    let issues = analyze_dependency_confusion(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DepConfusionIssue::InternalPackageName { .. }))
    );
}

#[test]
fn private_lib_name_detected() {
    let body = r#"import "auth-private""#;
    let issues = analyze_dependency_confusion(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DepConfusionIssue::InternalPackageName { .. }))
    );
}

#[test]
fn email_at_sign_not_flagged() {
    let body = "Contact us at user@example.com";
    let issues = analyze_dependency_confusion(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DepConfusionIssue::InternalScopedPackage { .. }))
    );
}

#[test]
fn severity_ordering() {
    assert!(
        dep_confusion_severity(&DepConfusionIssue::InternalScopedPackage { scope: "x".into() })
            > dep_confusion_severity(&DepConfusionIssue::PrivateRegistryUrl { url: "x".into() })
    );
    assert!(
        dep_confusion_severity(&DepConfusionIssue::LockfileExposed { path: "x".into() })
            > dep_confusion_severity(&DepConfusionIssue::InternalPackageName { name: "x".into() })
    );
}

#[test]
fn display_format() {
    let issue = DepConfusionIssue::InternalScopedPackage {
        scope: "@myco".into(),
    };
    assert_eq!(issue.to_string(), "internal_scope:@myco");

    let issue = DepConfusionIssue::LockfileExposed {
        path: "yarn.lock".into(),
    };
    assert_eq!(issue.to_string(), "lockfile_exposed:yarn.lock");
}

#[test]
fn to_operations_count() {
    let issues = vec![
        DepConfusionIssue::InternalScopedPackage { scope: "@x".into() },
        DepConfusionIssue::LockfileExposed { path: "y".into() },
    ];
    let mut seq = 0;
    let ops = dep_confusion_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn react_scope_not_flagged() {
    let body = r#"from "@react/scheduler""#;
    let issues = analyze_dependency_confusion(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DepConfusionIssue::InternalScopedPackage { .. }))
    );
}

#[test]
fn types_scope_not_flagged() {
    let body = r#"from "@types/node""#;
    let issues = analyze_dependency_confusion(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DepConfusionIssue::InternalScopedPackage { .. }))
    );
}
