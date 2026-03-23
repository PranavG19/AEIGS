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

// PathTraversalSecurityIssue tests

#[test]
fn detect_dot_dot_slash_forward() {
    let issues = analyze_path_traversal_security("", "http://example.com?file=../../../etc/passwd");
    assert!(issues
        .iter()
        .any(|i| matches!(i, PathTraversalSecurityIssue::DotDotSlashInUrl { pattern, .. } if pattern == "../")));
}

#[test]
fn detect_dot_dot_slash_backward() {
    let issues =
        analyze_path_traversal_security("", "http://example.com?file=..\\..\\windows\\win.ini");
    assert!(issues
        .iter()
        .any(|i| matches!(i, PathTraversalSecurityIssue::DotDotSlashInUrl { pattern, .. } if pattern == "..\\")));
}

#[test]
fn detect_dot_dot_slash_quadruple() {
    let issues =
        analyze_path_traversal_security("", "http://example.com?file=....//....//etc/passwd");
    assert!(issues
        .iter()
        .any(|i| matches!(i, PathTraversalSecurityIssue::DotDotSlashInUrl { pattern, .. } if pattern == "....//")));
}

#[test]
fn detect_encoded_traversal_url_encoded() {
    let issues = analyze_path_traversal_security(
        "",
        "http://example.com?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    );
    assert!(issues.iter().any(|i| matches!(
        i,
        PathTraversalSecurityIssue::EncodedTraversal { encoding_type, .. } if encoding_type == "url_encoded"
    )));
}

#[test]
fn detect_encoded_traversal_partial() {
    let issues = analyze_path_traversal_security("", "http://example.com?file=%2e%2e/etc/passwd");
    assert!(issues.iter().any(|i| matches!(
        i,
        PathTraversalSecurityIssue::EncodedTraversal { encoding_type, .. } if encoding_type == "url_encoded"
    )));
}

#[test]
fn detect_encoded_traversal_mixed() {
    let issues = analyze_path_traversal_security("", "http://example.com?file=%252e%252f");
    assert!(issues.iter().any(|i| matches!(
        i,
        PathTraversalSecurityIssue::EncodedTraversal { encoding_type, .. } if encoding_type == "partial_encoded"
    )));
}

#[test]
fn detect_double_encoded_forward_slash() {
    let issues = analyze_path_traversal_security("", "http://example.com?file=%252f%252e%252e");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PathTraversalSecurityIssue::DoubleEncodedTraversal { .. }))
    );
}

#[test]
fn detect_double_encoded_backslash() {
    let issues = analyze_path_traversal_security("", "http://example.com?file=%255c%255c");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PathTraversalSecurityIssue::DoubleEncodedTraversal { .. }))
    );
}

#[test]
fn detect_null_byte_encoded() {
    let issues =
        analyze_path_traversal_security("", "http://example.com?file=../etc/passwd%00.png");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PathTraversalSecurityIssue::NullByteTraversal { .. }))
    );
}

#[test]
fn detect_null_byte_raw() {
    let issues = analyze_path_traversal_security("", "http://example.com?file=../etc/passwd\0.png");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PathTraversalSecurityIssue::NullByteTraversal { .. }))
    );
}

#[test]
fn detect_unicode_traversal_u002e() {
    let issues =
        analyze_path_traversal_security("", "http://example.com?file=\\u002e\\u002e\\u002f");
    assert!(issues.iter().any(|i| matches!(
        i,
        PathTraversalSecurityIssue::UnicodeTraversal { unicode_pattern, .. } if unicode_pattern == "\\u002e"
    )));
}

#[test]
fn detect_unicode_traversal_u002f() {
    let issues = analyze_path_traversal_security("", "http://example.com?file=\\u002f\\u002fetc");
    assert!(issues.iter().any(|i| matches!(
        i,
        PathTraversalSecurityIssue::UnicodeTraversal { unicode_pattern, .. } if unicode_pattern == "\\u002f"
    )));
}

#[test]
fn detect_unicode_traversal_percent_u() {
    let issues = analyze_path_traversal_security("", "http://example.com?file=%u002e%u002e");
    assert!(issues.iter().any(|i| matches!(
        i,
        PathTraversalSecurityIssue::UnicodeTraversal { unicode_pattern, .. } if unicode_pattern == "\\u002e"
    )));
}

#[test]
fn detect_unicode_traversal_utf8_overlong() {
    let issues = analyze_path_traversal_security("", "http://example.com?file=%c0%ae%c0%ae");
    assert!(issues.iter().any(|i| matches!(
        i,
        PathTraversalSecurityIssue::UnicodeTraversal { unicode_pattern, .. } if unicode_pattern == "utf8_overlong"
    )));
}

#[test]
fn detect_backslash_traversal_double() {
    let issues = analyze_path_traversal_security("", "http://example.com?file=..\\..\\windows");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PathTraversalSecurityIssue::BackslashTraversal { .. }))
    );
}

#[test]
fn detect_backslash_traversal_single() {
    let issues = analyze_path_traversal_security("", "http://example.com?file=..\\windows");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PathTraversalSecurityIssue::BackslashTraversal { .. }))
    );
}

#[test]
fn detect_absolute_path_etc() {
    let issues = analyze_path_traversal_security("", "http://example.com?file=/etc/passwd");
    assert!(issues.iter().any(|i| matches!(
        i,
        PathTraversalSecurityIssue::AbsolutePathInParam { path, .. } if path == "/etc/"
    )));
}

#[test]
fn detect_absolute_path_usr() {
    let issues = analyze_path_traversal_security("", "http://example.com?file=/usr/local/bin");
    assert!(issues.iter().any(|i| matches!(
        i,
        PathTraversalSecurityIssue::AbsolutePathInParam { path, .. } if path == "/usr/"
    )));
}

#[test]
fn detect_absolute_path_var() {
    let issues = analyze_path_traversal_security("", "http://example.com?file=/var/log/auth.log");
    assert!(issues.iter().any(|i| matches!(
        i,
        PathTraversalSecurityIssue::AbsolutePathInParam { path, .. } if path == "/var/"
    )));
}

#[test]
fn detect_absolute_path_windows_uppercase() {
    let issues =
        analyze_path_traversal_security("", "http://example.com?file=C:\\Windows\\System32");
    assert!(issues.iter().any(|i| matches!(
        i,
        PathTraversalSecurityIssue::AbsolutePathInParam { path, .. } if path == "C:\\"
    )));
}

#[test]
fn detect_absolute_path_windows_lowercase() {
    let issues = analyze_path_traversal_security("", "http://example.com?file=c:\\windows");
    assert!(issues.iter().any(|i| matches!(
        i,
        PathTraversalSecurityIssue::AbsolutePathInParam { path, .. } if path == "C:\\"
    )));
}

#[test]
fn detect_absolute_path_windows_forward_slash() {
    let issues = analyze_path_traversal_security("", "http://example.com?file=C:/Windows");
    assert!(issues.iter().any(|i| matches!(
        i,
        PathTraversalSecurityIssue::AbsolutePathInParam { path, .. } if path == "C:\\"
    )));
}

#[test]
fn detect_file_protocol_standard() {
    let issues = analyze_path_traversal_security("", "http://example.com?file=file:///etc/passwd");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PathTraversalSecurityIssue::FileProtocolAccess { .. }))
    );
}

#[test]
fn detect_file_protocol_single_slash() {
    let issues = analyze_path_traversal_security("", "http://example.com?file=file:/etc/passwd");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, PathTraversalSecurityIssue::FileProtocolAccess { .. }))
    );
}

#[test]
fn detect_path_traversal_in_body_passwd() {
    let issues =
        analyze_path_traversal_security("root:x:0:0:root:/root:/bin/bash\n", "http://example.com");
    assert!(issues.iter().any(|i| matches!(
        i,
        PathTraversalSecurityIssue::PathTraversalInBody { body_snippet } if body_snippet == "root:x:0:0:"
    )));
}

#[test]
fn detect_path_traversal_in_body_win_ini_fonts() {
    let issues = analyze_path_traversal_security("[fonts]\nArial=arial.ttf", "http://example.com");
    assert!(issues.iter().any(|i| matches!(
        i,
        PathTraversalSecurityIssue::PathTraversalInBody { body_snippet } if body_snippet == "win.ini"
    )));
}

#[test]
fn detect_path_traversal_in_body_win_ini_extensions() {
    let issues =
        analyze_path_traversal_security("[extensions]\ntext=notepad.exe", "http://example.com");
    assert!(issues.iter().any(|i| matches!(
        i,
        PathTraversalSecurityIssue::PathTraversalInBody { body_snippet } if body_snippet == "win.ini"
    )));
}

#[test]
fn detect_path_traversal_in_body_bash() {
    let issues =
        analyze_path_traversal_security("root:x:0:0:root:/root:/bin/bash", "http://example.com");
    assert!(issues.iter().any(|i| matches!(
        i,
        PathTraversalSecurityIssue::PathTraversalInBody { body_snippet } if body_snippet == "shell_path"
    )));
}

#[test]
fn detect_path_traversal_in_body_sh() {
    let issues = analyze_path_traversal_security("#!/bin/sh\necho hello", "http://example.com");
    assert!(issues.iter().any(|i| matches!(
        i,
        PathTraversalSecurityIssue::PathTraversalInBody { body_snippet } if body_snippet == "shell_path"
    )));
}

#[test]
fn detect_symlink_traversal_arrow() {
    let issues = analyze_path_traversal_security("link -> /etc/passwd", "http://example.com");
    assert!(issues.iter().any(|i| matches!(
        i,
        PathTraversalSecurityIssue::SymlinkTraversal { symlink_indicator, .. } if symlink_indicator == "symlink_detected"
    )));
}

#[test]
fn detect_symlink_traversal_text() {
    let issues =
        analyze_path_traversal_security("This is a symbolic link to /var", "http://example.com");
    assert!(issues.iter().any(|i| matches!(
        i,
        PathTraversalSecurityIssue::SymlinkTraversal { symlink_indicator, .. } if symlink_indicator == "symlink_detected"
    )));
}

#[test]
fn detect_symlink_traversal_ls_output() {
    let issues = analyze_path_traversal_security(
        "lrwxrwxrwx 1 root root 11 Jan 1 12:00 link",
        "http://example.com",
    );
    assert!(issues.iter().any(|i| matches!(
        i,
        PathTraversalSecurityIssue::SymlinkTraversal { symlink_indicator, .. } if symlink_indicator == "ls_output"
    )));
}

#[test]
fn security_issue_display_dot_dot_slash() {
    let issue = PathTraversalSecurityIssue::DotDotSlashInUrl {
        url: "http://test.com".to_string(),
        pattern: "../".to_string(),
    };
    assert_eq!(issue.to_string(), "dot_dot_slash_in_url:../");
}

#[test]
fn security_issue_display_encoded_traversal() {
    let issue = PathTraversalSecurityIssue::EncodedTraversal {
        url: "http://test.com".to_string(),
        encoding_type: "url_encoded".to_string(),
    };
    assert_eq!(issue.to_string(), "encoded_traversal:url_encoded");
}

#[test]
fn security_issue_display_double_encoded() {
    let issue = PathTraversalSecurityIssue::DoubleEncodedTraversal {
        url: "http://test.com".to_string(),
    };
    assert_eq!(issue.to_string(), "double_encoded_traversal");
}

#[test]
fn security_issue_display_null_byte() {
    let issue = PathTraversalSecurityIssue::NullByteTraversal {
        url: "http://test.com".to_string(),
    };
    assert_eq!(issue.to_string(), "null_byte_traversal");
}

#[test]
fn security_issue_display_unicode() {
    let issue = PathTraversalSecurityIssue::UnicodeTraversal {
        url: "http://test.com".to_string(),
        unicode_pattern: "\\u002e".to_string(),
    };
    assert_eq!(issue.to_string(), "unicode_traversal:\\u002e");
}

#[test]
fn security_issue_display_backslash() {
    let issue = PathTraversalSecurityIssue::BackslashTraversal {
        url: "http://test.com".to_string(),
    };
    assert_eq!(issue.to_string(), "backslash_traversal");
}

#[test]
fn security_issue_display_absolute_path() {
    let issue = PathTraversalSecurityIssue::AbsolutePathInParam {
        url: "http://test.com".to_string(),
        path: "/etc/".to_string(),
    };
    assert_eq!(issue.to_string(), "absolute_path_in_param:/etc/");
}

#[test]
fn security_issue_display_file_protocol() {
    let issue = PathTraversalSecurityIssue::FileProtocolAccess {
        url: "http://test.com".to_string(),
    };
    assert_eq!(issue.to_string(), "file_protocol_access");
}

#[test]
fn security_issue_display_body() {
    let issue = PathTraversalSecurityIssue::PathTraversalInBody {
        body_snippet: "root:x:0:0:".to_string(),
    };
    assert_eq!(issue.to_string(), "path_traversal_in_body:root:x:0:0:");
}

#[test]
fn security_issue_display_symlink() {
    let issue = PathTraversalSecurityIssue::SymlinkTraversal {
        url: "http://test.com".to_string(),
        symlink_indicator: "ls_output".to_string(),
    };
    assert_eq!(issue.to_string(), "symlink_traversal:ls_output");
}

#[test]
fn security_severity_ordering() {
    let body = PathTraversalSecurityIssue::PathTraversalInBody {
        body_snippet: "root:".to_string(),
    };
    let dot_dot = PathTraversalSecurityIssue::DotDotSlashInUrl {
        url: "".to_string(),
        pattern: "../".to_string(),
    };
    let encoded = PathTraversalSecurityIssue::EncodedTraversal {
        url: "".to_string(),
        encoding_type: "url".to_string(),
    };
    let symlink = PathTraversalSecurityIssue::SymlinkTraversal {
        url: "".to_string(),
        symlink_indicator: "x".to_string(),
    };

    assert!(path_traversal_security_severity(&body) > path_traversal_security_severity(&dot_dot));
    assert!(
        path_traversal_security_severity(&dot_dot) > path_traversal_security_severity(&encoded)
    );
    assert!(
        path_traversal_security_severity(&encoded) > path_traversal_security_severity(&symlink)
    );
}

#[test]
fn security_operations_generated() {
    let issues = vec![PathTraversalSecurityIssue::DotDotSlashInUrl {
        url: "http://test.com".to_string(),
        pattern: "../".to_string(),
    }];
    let mut seq = 0;
    let ops = path_traversal_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn security_operations_multiple_issues() {
    let issues = vec![
        PathTraversalSecurityIssue::DotDotSlashInUrl {
            url: "http://test.com".to_string(),
            pattern: "../".to_string(),
        },
        PathTraversalSecurityIssue::EncodedTraversal {
            url: "http://test.com".to_string(),
            encoding_type: "url_encoded".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = path_traversal_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_operations_empty_for_no_issues() {
    let mut seq = 0;
    let ops = path_traversal_security_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn no_issues_on_clean_url_and_body() {
    let issues = analyze_path_traversal_security("Hello world", "http://example.com?page=1");
    assert!(issues.is_empty());
}

#[test]
fn multiple_issues_detected_simultaneously() {
    let issues = analyze_path_traversal_security(
        "root:x:0:0:root:/root:/bin/bash",
        "http://example.com?file=../../../etc/passwd%00",
    );
    assert!(issues.len() >= 3); // DotDotSlash + NullByte + PathTraversalInBody
}

#[test]
fn url_with_multiple_encoding_types() {
    let issues =
        analyze_path_traversal_security("", "http://example.com?file=%2e%2e/%252e%252e/..\\");
    assert!(issues.len() >= 3); // url_encoded + partial_encoded + backslash
}
