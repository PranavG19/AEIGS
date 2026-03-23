use crate::compression_stream_audit::*;

#[test]
fn test_no_compression_stream_api() {
    let body = r#"
        const data = await fetch('/api/data');
        const text = await data.text();
    "#;
    let issues = analyze_compression_stream(body);
    assert!(issues.is_empty());
}

#[test]
fn test_compression_stream_detected() {
    let body = r#"
        const cs = new CompressionStream('gzip');
        const writer = cs.writable.getWriter();
        const maxSize = 1024;
    "#;
    let issues = analyze_compression_stream(body);
    assert_eq!(issues.len(), 2);
    assert!(issues.contains(&CompressionStreamIssue::ApiDetected));
    assert!(issues.contains(&CompressionStreamIssue::NoChecksumValidation));
}

#[test]
fn test_decompression_stream_detected() {
    let body = r#"
        const ds = new DecompressionStream('gzip');
        const reader = ds.readable.getReader();
    "#;
    let issues = analyze_compression_stream(body);
    assert!(issues.contains(&CompressionStreamIssue::ApiDetected));
}

#[test]
fn test_zip_bomb_risk_with_untrusted_data() {
    let body = r#"
        const ds = new DecompressionStream('gzip');
        const untrusted = await fetch(userUrl);
        await untrusted.body.pipeThrough(ds);
    "#;
    let issues = analyze_compression_stream(body);
    assert!(issues.contains(&CompressionStreamIssue::ApiDetected));
    assert!(issues.contains(&CompressionStreamIssue::ZipBombRisk));
}

#[test]
fn test_no_zip_bomb_without_untrusted() {
    let body = r#"
        const ds = new DecompressionStream('gzip');
        const trusted = await fetch('/internal/data');
    "#;
    let issues = analyze_compression_stream(body);
    assert!(issues.contains(&CompressionStreamIssue::ApiDetected));
    assert!(!issues.contains(&CompressionStreamIssue::ZipBombRisk));
}

#[test]
fn test_no_size_limits() {
    let body = r#"
        const ds = new DecompressionStream('deflate');
        const decompressed = await response.body.pipeThrough(ds);
    "#;
    let issues = analyze_compression_stream(body);
    assert!(issues.contains(&CompressionStreamIssue::NoSizeLimits));
}

#[test]
fn test_max_size_present() {
    let body = r#"
        const ds = new DecompressionStream('gzip');
        if (decompressed.length > maxSize) throw new Error('Too large');
    "#;
    let issues = analyze_compression_stream(body);
    assert!(!issues.contains(&CompressionStreamIssue::NoSizeLimits));
}

#[test]
fn test_size_limit_present() {
    let body = r#"
        const ds = new DecompressionStream('gzip');
        const limited = decompressed.slice(0, sizeLimit);
    "#;
    let issues = analyze_compression_stream(body);
    assert!(!issues.contains(&CompressionStreamIssue::NoSizeLimits));
}

#[test]
fn test_byte_limit_present() {
    let body = r#"
        const cs = new CompressionStream('gzip');
        let bytes = 0;
        while (bytes < byteLimit) { }
    "#;
    let issues = analyze_compression_stream(body);
    assert!(!issues.contains(&CompressionStreamIssue::NoSizeLimits));
}

#[test]
fn test_timing_leak_risk_with_secret() {
    let body = r#"
        const cs = new CompressionStream('deflate');
        const data = secret + userInput;
        await data.pipeThrough(cs);
    "#;
    let issues = analyze_compression_stream(body);
    assert!(issues.contains(&CompressionStreamIssue::TimingLeakRisk));
}

#[test]
fn test_no_timing_leak_without_secret() {
    let body = r#"
        const cs = new CompressionStream('gzip');
        const publicData = await fetch('/public');
    "#;
    let issues = analyze_compression_stream(body);
    assert!(!issues.contains(&CompressionStreamIssue::TimingLeakRisk));
}

#[test]
fn test_no_checksum_validation() {
    let body = r#"
        const ds = new DecompressionStream('gzip');
        const result = await response.body.pipeThrough(ds);
    "#;
    let issues = analyze_compression_stream(body);
    assert!(issues.contains(&CompressionStreamIssue::NoChecksumValidation));
}

#[test]
fn test_checksum_present() {
    let body = r#"
        const ds = new DecompressionStream('gzip');
        const result = await decompress(data);
        if (checksum !== expected) throw new Error();
    "#;
    let issues = analyze_compression_stream(body);
    assert!(!issues.contains(&CompressionStreamIssue::NoChecksumValidation));
}

#[test]
fn test_integrity_check_present() {
    let body = r#"
        const ds = new DecompressionStream('deflate');
        await verifyIntegrity(decompressed, result_hash);
    "#;
    let issues = analyze_compression_stream(body);
    assert!(!issues.contains(&CompressionStreamIssue::NoChecksumValidation));
}

#[test]
fn test_hash_validation_present() {
    let body = r#"
        const cs = new CompressionStream('gzip');
        const result_hash = await computeHash(compressed);
    "#;
    let issues = analyze_compression_stream(body);
    assert!(!issues.contains(&CompressionStreamIssue::NoChecksumValidation));
}

#[test]
fn test_combined_issues() {
    let body = r#"
        const ds = new DecompressionStream('gzip');
        const untrusted = await fetch(userUrl);
        const data = secret + untrusted;
        await data.pipeThrough(ds);
    "#;
    let issues = analyze_compression_stream(body);
    assert_eq!(issues.len(), 5);
    assert!(issues.contains(&CompressionStreamIssue::ApiDetected));
    assert!(issues.contains(&CompressionStreamIssue::ZipBombRisk));
    assert!(issues.contains(&CompressionStreamIssue::NoSizeLimits));
    assert!(issues.contains(&CompressionStreamIssue::TimingLeakRisk));
    assert!(issues.contains(&CompressionStreamIssue::NoChecksumValidation));
}

#[test]
fn test_severity_api_detected() {
    let severity = compression_stream_severity(&CompressionStreamIssue::ApiDetected);
    assert_eq!(severity, 2.0);
}

#[test]
fn test_severity_zip_bomb_risk() {
    let severity = compression_stream_severity(&CompressionStreamIssue::ZipBombRisk);
    assert_eq!(severity, 8.0);
}

#[test]
fn test_severity_no_size_limits() {
    let severity = compression_stream_severity(&CompressionStreamIssue::NoSizeLimits);
    assert_eq!(severity, 7.0);
}

#[test]
fn test_severity_timing_leak_risk() {
    let severity = compression_stream_severity(&CompressionStreamIssue::TimingLeakRisk);
    assert_eq!(severity, 6.0);
}

#[test]
fn test_severity_no_checksum_validation() {
    let severity = compression_stream_severity(&CompressionStreamIssue::NoChecksumValidation);
    assert_eq!(severity, 5.0);
}

#[test]
fn test_to_operations() {
    let issues = vec![
        CompressionStreamIssue::ApiDetected,
        CompressionStreamIssue::ZipBombRisk,
    ];
    let mut seq = 0u64;
    let ops = compression_stream_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn test_to_operations_empty() {
    let issues = vec![];
    let mut seq = 10u64;
    let ops = compression_stream_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 10);
}

#[test]
fn test_display_api_detected() {
    let issue = CompressionStreamIssue::ApiDetected;
    assert_eq!(issue.to_string(), "api_detected");
}

#[test]
fn test_display_zip_bomb_risk() {
    let issue = CompressionStreamIssue::ZipBombRisk;
    assert_eq!(issue.to_string(), "zip_bomb_risk");
}

#[test]
fn test_display_no_size_limits() {
    let issue = CompressionStreamIssue::NoSizeLimits;
    assert_eq!(issue.to_string(), "no_size_limits");
}

#[test]
fn test_display_timing_leak_risk() {
    let issue = CompressionStreamIssue::TimingLeakRisk;
    assert_eq!(issue.to_string(), "timing_leak_risk");
}

#[test]
fn test_display_no_checksum_validation() {
    let issue = CompressionStreamIssue::NoChecksumValidation;
    assert_eq!(issue.to_string(), "no_checksum_validation");
}
