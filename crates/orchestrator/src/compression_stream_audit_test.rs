use crate::compression_stream_audit::*;

#[test]
fn no_compression_no_issues() {
    assert!(analyze_compression_stream("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_compression_stream() {
    let body = r#"<script>
        const cs = new CompressionStream("gzip");
        readable.pipeThrough(cs).pipeTo(writable);
    </script>"#;
    let issues = analyze_compression_stream(body);
    assert!(issues.contains(&CompressionStreamIssue::ApiDetected));
}

#[test]
fn detects_decompression_stream() {
    let body = r#"<script>
        const ds = new DecompressionStream("gzip");
        response.body.pipeThrough(ds);
    </script>"#;
    let issues = analyze_compression_stream(body);
    assert!(issues.contains(&CompressionStreamIssue::ApiDetected));
}

#[test]
fn detects_zip_bomb_risk() {
    let body = r#"<script>
        const ds = new DecompressionStream("gzip");
        compressed.pipeThrough(ds).pipeTo(output);
    </script>"#;
    let issues = analyze_compression_stream(body);
    assert!(issues.contains(&CompressionStreamIssue::ZipBombRisk));
}

#[test]
fn no_zip_bomb_with_limit() {
    let body = r#"<script>
        const ds = new DecompressionStream("gzip");
        const maxSize = 10 * 1024 * 1024;
        compressed.pipeThrough(ds).pipeTo(output);
    </script>"#;
    let issues = analyze_compression_stream(body);
    assert!(!issues.contains(&CompressionStreamIssue::ZipBombRisk));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        const cs = new CompressionStream("gzip");
        const compressed = await compress(data);
        fetch("/exfil", {body: compressed});
    </script>"#;
    let issues = analyze_compression_stream(body);
    assert!(issues.contains(&CompressionStreamIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_network() {
    let body = r#"<script>
        const cs = new CompressionStream("gzip");
        readable.pipeThrough(cs).pipeTo(writable);
    </script>"#;
    let issues = analyze_compression_stream(body);
    assert!(!issues.contains(&CompressionStreamIssue::DataExfiltration));
}

#[test]
fn detects_resource_exhaustion() {
    let body = r#"<script>
        const cs = new CompressionStream("gzip");
        while (hasMore) {
            cs.writable.getWriter().write(chunk);
        }
    </script>"#;
    let issues = analyze_compression_stream(body);
    assert!(issues.contains(&CompressionStreamIssue::ResourceExhaustion));
}

#[test]
fn no_exhaustion_with_break() {
    let body = r#"<script>
        const cs = new CompressionStream("gzip");
        while (hasMore) {
            if (tooLarge) break;
            cs.writable.getWriter().write(chunk);
        }
    </script>"#;
    let issues = analyze_compression_stream(body);
    assert!(!issues.contains(&CompressionStreamIssue::ResourceExhaustion));
}

#[test]
fn detects_untrusted_decompression() {
    let body = r#"<script>
        const ds = new DecompressionStream("gzip");
        const userUpload = input.files[0];
        userUpload.stream().pipeThrough(ds);
    </script>"#;
    let issues = analyze_compression_stream(body);
    assert!(issues.contains(&CompressionStreamIssue::UntrustedDecompression));
}

#[test]
fn no_untrusted_with_validate() {
    let body = r#"<script>
        const ds = new DecompressionStream("gzip");
        validate(userInput);
        userInput.stream().pipeThrough(ds);
    </script>"#;
    let issues = analyze_compression_stream(body);
    assert!(!issues.contains(&CompressionStreamIssue::UntrustedDecompression));
}

#[test]
fn severity_zip_bomb_highest() {
    assert_eq!(compression_stream_severity(&CompressionStreamIssue::ZipBombRisk), 8.0);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(compression_stream_severity(&CompressionStreamIssue::ApiDetected), 2.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![CompressionStreamIssue::ApiDetected, CompressionStreamIssue::ZipBombRisk];
    let mut seq = 0;
    let ops = compression_stream_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(CompressionStreamIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(CompressionStreamIssue::ZipBombRisk.to_string(), "zip_bomb_risk");
    assert_eq!(CompressionStreamIssue::DataExfiltration.to_string(), "data_exfiltration");
    assert_eq!(CompressionStreamIssue::ResourceExhaustion.to_string(), "resource_exhaustion");
    assert_eq!(CompressionStreamIssue::UntrustedDecompression.to_string(), "untrusted_decompression");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_compression_stream("").is_empty());
}
