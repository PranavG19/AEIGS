use crate::path_traversal_audit::*;

#[test]
fn traversal_detected_on_success() {
    let result = analyze_traversal_response(
        "file",
        "../../../etc/passwd",
        "root:",
        200,
        "root:x:0:0:root:/root:/bin/bash\n",
    );
    assert!(result.is_some());
    let issue = result.unwrap();
    assert!(
        matches!(issue, PathTraversalIssue::TraversalSucceeded { param, .. } if param == "file")
    );
}

#[test]
fn traversal_not_detected_on_404() {
    let result = analyze_traversal_response(
        "file",
        "../../../etc/passwd",
        "root:",
        404,
        "root:x:0:0:root:/root:/bin/bash\n",
    );
    assert!(result.is_none());
}

#[test]
fn traversal_not_detected_without_indicator() {
    let result = analyze_traversal_response(
        "file",
        "../../../etc/passwd",
        "root:",
        200,
        "File not found",
    );
    assert!(result.is_none());
}

#[test]
fn traversal_not_detected_on_500() {
    let result = analyze_traversal_response(
        "file",
        "../../../etc/passwd",
        "root:",
        500,
        "Internal Server Error",
    );
    assert!(result.is_none());
}

#[test]
fn encoded_traversal_display() {
    let issue = PathTraversalIssue::EncodedTraversalSucceeded {
        param: "path".to_string(),
        encoding: "url_encoded".to_string(),
    };
    assert_eq!(issue.to_string(), "encoded_path_traversal:path:url_encoded");
}

#[test]
fn null_byte_display() {
    let issue = PathTraversalIssue::NullByteInjection {
        param: "file".to_string(),
    };
    assert_eq!(issue.to_string(), "null_byte_injection:file");
}

#[test]
fn traversal_display() {
    let issue = PathTraversalIssue::TraversalSucceeded {
        param: "file".to_string(),
        payload: "../etc/passwd".to_string(),
        indicator: "root:".to_string(),
    };
    assert_eq!(issue.to_string(), "path_traversal:file:../etc/passwd");
}

#[test]
fn severity_ordering() {
    assert!(
        path_traversal_severity(&PathTraversalIssue::TraversalSucceeded {
            param: "x".to_string(),
            payload: "y".to_string(),
            indicator: "z".to_string()
        }) > path_traversal_severity(&PathTraversalIssue::EncodedTraversalSucceeded {
            param: "x".to_string(),
            encoding: "y".to_string()
        })
    );
    assert!(
        path_traversal_severity(&PathTraversalIssue::EncodedTraversalSucceeded {
            param: "x".to_string(),
            encoding: "y".to_string()
        }) > path_traversal_severity(&PathTraversalIssue::NullByteInjection {
            param: "x".to_string()
        })
    );
}

#[test]
fn operations_generated() {
    let issues = vec![PathTraversalIssue::TraversalSucceeded {
        param: "file".to_string(),
        payload: "../etc/passwd".to_string(),
        indicator: "root:".to_string(),
    }];
    let mut seq = 0;
    let ops = path_traversal_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn operations_empty_for_no_issues() {
    let mut seq = 0;
    let ops = path_traversal_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn audit_skips_localhost() {
    let issues = audit_path_traversal("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn audit_skips_loopback() {
    let issues = audit_path_traversal("http://127.0.0.1");
    assert!(issues.is_empty());
}

#[test]
fn status_201_is_success() {
    let result = analyze_traversal_response("file", "../etc/passwd", "root:", 201, "root:x:0:0:");
    assert!(result.is_some());
}

#[test]
fn status_299_is_success() {
    let result = analyze_traversal_response("file", "../etc/passwd", "root:", 299, "root:x:0:0:");
    assert!(result.is_some());
}

#[test]
fn status_300_is_not_success() {
    let result = analyze_traversal_response("file", "../etc/passwd", "root:", 300, "root:x:0:0:");
    assert!(result.is_none());
}
