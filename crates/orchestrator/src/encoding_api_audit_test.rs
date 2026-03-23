use crate::encoding_api_audit::*;

#[test]
fn no_encoding_api_no_issues() {
    assert!(analyze_encoding_api("<html><body>hello</body></html>").is_empty());
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_encoding_api("").is_empty());
}

#[test]
fn detects_text_encoder() {
    let body = r#"<script>const enc = new TextEncoder();</script>"#;
    let issues = analyze_encoding_api(body);
    assert!(issues.contains(&EncodingApiIssue::ApiDetected));
}

#[test]
fn detects_text_decoder() {
    let body = r#"<script>const dec = new TextDecoder("utf-8");</script>"#;
    let issues = analyze_encoding_api(body);
    assert!(issues.contains(&EncodingApiIssue::ApiDetected));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        const enc = new TextEncoder();
        const encoded = enc.encode(secret);
        const b = btoa(encoded);
        fetch("/exfil", {body: b});
    </script>"#;
    let issues = analyze_encoding_api(body);
    assert!(issues.contains(&EncodingApiIssue::DataExfiltration));
}

#[test]
fn no_exfiltration_without_base64() {
    let body = r#"<script>
        const enc = new TextEncoder();
        const encoded = enc.encode(data);
        fetch("/api", {body: encoded});
    </script>"#;
    let issues = analyze_encoding_api(body);
    assert!(!issues.contains(&EncodingApiIssue::DataExfiltration));
}

#[test]
fn no_exfiltration_without_network() {
    let body = r#"<script>
        const enc = new TextEncoder();
        const encoded = enc.encode(data);
        const b = btoa(encoded);
    </script>"#;
    let issues = analyze_encoding_api(body);
    assert!(!issues.contains(&EncodingApiIssue::DataExfiltration));
}

#[test]
fn detects_buffer_overflow() {
    let body = r#"<script>
        const enc = new TextEncoder();
        const buf = new ArrayBuffer(1024);
        while (offset < data.length) {
            enc.encodeInto(data.slice(offset), new Uint8Array(buf));
            offset += 1024;
        }
    </script>"#;
    let issues = analyze_encoding_api(body);
    assert!(issues.contains(&EncodingApiIssue::BufferOverflow));
}

#[test]
fn no_buffer_overflow_with_limit() {
    let body = r#"<script>
        const enc = new TextEncoder();
        const buf = new ArrayBuffer(1024);
        const limit = 10000;
        while (offset < data.length) {
            enc.encodeInto(data.slice(offset), new Uint8Array(buf));
        }
    </script>"#;
    let issues = analyze_encoding_api(body);
    assert!(!issues.contains(&EncodingApiIssue::BufferOverflow));
}

#[test]
fn no_buffer_overflow_with_max_length() {
    let body = r#"<script>
        const dec = new TextDecoder();
        const buf = new Uint8Array(1024);
        const maxLength = 5000;
        for (let i = 0; i < chunks.length; i++) { dec.decode(chunks[i]); }
    </script>"#;
    let issues = analyze_encoding_api(body);
    assert!(!issues.contains(&EncodingApiIssue::BufferOverflow));
}

#[test]
fn detects_encoding_bypass() {
    let body = r#"<script>
        const dec = new TextDecoder();
        const text = dec.decode(buffer);
        document.innerHTML = text;
    </script>"#;
    let issues = analyze_encoding_api(body);
    assert!(issues.contains(&EncodingApiIssue::EncodingBypass));
}

#[test]
fn no_encoding_bypass_with_sanitize() {
    let body = r#"<script>
        const dec = new TextDecoder();
        const text = dec.decode(buffer);
        document.innerHTML = sanitize(text);
    </script>"#;
    let issues = analyze_encoding_api(body);
    assert!(!issues.contains(&EncodingApiIssue::EncodingBypass));
}

#[test]
fn no_encoding_bypass_with_escape() {
    let body = r#"<script>
        const enc = new TextEncoder();
        const text = enc.encode(data);
        el.innerHTML = escape(text);
    </script>"#;
    let issues = analyze_encoding_api(body);
    assert!(!issues.contains(&EncodingApiIssue::EncodingBypass));
}

#[test]
fn detects_resource_exhaustion() {
    let body = r#"<script>
        const enc = new TextEncoder();
        while (true) {
            enc.encodeInto(data, buffer);
        }
    </script>"#;
    let issues = analyze_encoding_api(body);
    assert!(issues.contains(&EncodingApiIssue::ResourceExhaustion));
}

#[test]
fn no_resource_exhaustion_with_break() {
    let body = r#"<script>
        const enc = new TextEncoder();
        while (true) {
            enc.encodeInto(data, buffer);
            if (done) break;
        }
    </script>"#;
    let issues = analyze_encoding_api(body);
    assert!(!issues.contains(&EncodingApiIssue::ResourceExhaustion));
}

#[test]
fn no_resource_exhaustion_with_clear_interval() {
    let body = r#"<script>
        const dec = new TextDecoder();
        const id = setInterval(() => { dec.decode(chunk); }, 100);
        clearInterval(id);
    </script>"#;
    let issues = analyze_encoding_api(body);
    assert!(!issues.contains(&EncodingApiIssue::ResourceExhaustion));
}

#[test]
fn all_issues_detected() {
    let body = r#"<script>
        const enc = new TextEncoder();
        const dec = new TextDecoder();
        const buf = new ArrayBuffer(1024);
        const arr = new Uint8Array(buf);
        enc.encodeInto(data, arr);
        const text = dec.decode(arr);
        document.innerHTML = text;
        const b = btoa(text);
        fetch("/exfil", {body: b});
        while (true) {
            enc.encodeInto(data, arr);
        }
    </script>"#;
    let issues = analyze_encoding_api(body);
    assert!(issues.contains(&EncodingApiIssue::ApiDetected));
    assert!(issues.contains(&EncodingApiIssue::DataExfiltration));
    assert!(issues.contains(&EncodingApiIssue::BufferOverflow));
    assert!(issues.contains(&EncodingApiIssue::EncodingBypass));
    assert!(issues.contains(&EncodingApiIssue::ResourceExhaustion));
    assert_eq!(issues.len(), 5);
}

#[test]
fn severity_values() {
    assert_eq!(encoding_api_severity(&EncodingApiIssue::ApiDetected), 2.0);
    assert_eq!(encoding_api_severity(&EncodingApiIssue::DataExfiltration), 7.0);
    assert_eq!(encoding_api_severity(&EncodingApiIssue::BufferOverflow), 6.5);
    assert_eq!(encoding_api_severity(&EncodingApiIssue::EncodingBypass), 7.5);
    assert_eq!(encoding_api_severity(&EncodingApiIssue::ResourceExhaustion), 5.5);
}

#[test]
fn display_variants() {
    assert_eq!(EncodingApiIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(EncodingApiIssue::DataExfiltration.to_string(), "data_exfiltration");
    assert_eq!(EncodingApiIssue::BufferOverflow.to_string(), "buffer_overflow");
    assert_eq!(EncodingApiIssue::EncodingBypass.to_string(), "encoding_bypass");
    assert_eq!(EncodingApiIssue::ResourceExhaustion.to_string(), "resource_exhaustion");
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![EncodingApiIssue::ApiDetected, EncodingApiIssue::EncodingBypass];
    let mut seq = 0;
    let ops = encoding_api_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}
