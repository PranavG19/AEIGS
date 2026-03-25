use crate::wasm_analyzer::*;

fn minimal_wasm() -> Vec<u8> {
    build_wasm_module(&[])
}

#[test]
fn empty_input_not_valid() {
    let analysis = analyze_wasm(&[]);
    assert!(!analysis.valid);
}

#[test]
fn too_short_not_valid() {
    let analysis = analyze_wasm(&[0x00, 0x61, 0x73]);
    assert!(!analysis.valid);
}

#[test]
fn bad_magic_not_valid() {
    let analysis = analyze_wasm(&[0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00]);
    assert!(!analysis.valid);
}

#[test]
fn bad_version_not_valid() {
    let analysis = analyze_wasm(&[0x00, 0x61, 0x73, 0x6D, 0x02, 0x00, 0x00, 0x00]);
    assert!(!analysis.valid);
}

#[test]
fn minimal_valid_wasm() {
    let wasm = minimal_wasm();
    let analysis = analyze_wasm(&wasm);
    assert!(analysis.valid);
    assert_eq!(analysis.version, 1);
    assert!(analysis.imports.is_empty());
    assert!(analysis.exports.is_empty());
}

#[test]
fn parse_single_function_import() {
    let imports = build_import_section_funcs(&[("env", "log", 0)]);
    let wasm = build_wasm_module(&[(2, imports)]);
    let analysis = analyze_wasm(&wasm);
    assert_eq!(analysis.imports.len(), 1);
    assert_eq!(analysis.imports[0].module, "env");
    assert_eq!(analysis.imports[0].name, "log");
    assert_eq!(analysis.imports[0].kind, ImportKind::Function(0));
}

#[test]
fn parse_multiple_imports() {
    let imports = build_import_section_funcs(&[
        ("env", "log", 0),
        ("env", "abort", 1),
        ("wasi_snapshot_preview1", "fd_write", 2),
    ]);
    let wasm = build_wasm_module(&[(2, imports)]);
    let analysis = analyze_wasm(&wasm);
    assert_eq!(analysis.imports.len(), 3);
    assert_eq!(analysis.imports[2].module, "wasi_snapshot_preview1");
    assert_eq!(analysis.imports[2].name, "fd_write");
}

#[test]
fn parse_single_export() {
    let exports = build_export_section(&[("main", 0x00, 0)]);
    let wasm = build_wasm_module(&[(7, exports)]);
    let analysis = analyze_wasm(&wasm);
    assert_eq!(analysis.exports.len(), 1);
    assert_eq!(analysis.exports[0].name, "main");
    assert_eq!(analysis.exports[0].kind, ExportKind::Function);
    assert_eq!(analysis.exports[0].index, 0);
}

#[test]
fn parse_multiple_exports() {
    let exports = build_export_section(&[
        ("memory", 0x02, 0),
        ("_start", 0x00, 1),
        ("__heap_base", 0x03, 0),
    ]);
    let wasm = build_wasm_module(&[(7, exports)]);
    let analysis = analyze_wasm(&wasm);
    assert_eq!(analysis.exports.len(), 3);
    assert_eq!(analysis.exports[0].kind, ExportKind::Memory);
    assert_eq!(analysis.exports[1].kind, ExportKind::Function);
    assert_eq!(analysis.exports[2].kind, ExportKind::Global);
}

#[test]
fn parse_memory_section_no_max() {
    let mem = build_memory_section(16, None);
    let wasm = build_wasm_module(&[(5, mem)]);
    let analysis = analyze_wasm(&wasm);
    let info = analysis.memory_info.unwrap();
    assert_eq!(info.initial_pages, 16);
    assert!(info.maximum_pages.is_none());
}

#[test]
fn parse_memory_section_with_max() {
    let mem = build_memory_section(16, Some(256));
    let wasm = build_wasm_module(&[(5, mem)]);
    let analysis = analyze_wasm(&wasm);
    let info = analysis.memory_info.unwrap();
    assert_eq!(info.initial_pages, 16);
    assert_eq!(info.maximum_pages, Some(256));
}

#[test]
fn parse_function_count() {
    let funcs = build_function_section(&[0, 1, 2, 3, 4]);
    let wasm = build_wasm_module(&[(3, funcs)]);
    let analysis = analyze_wasm(&wasm);
    assert_eq!(analysis.function_count, 5);
}

#[test]
fn extract_url_string() {
    let data = build_data_section_passive(&[b"https://evil.com/exfil"]);
    let wasm = build_wasm_module(&[(11, data)]);
    let analysis = analyze_wasm(&wasm);
    let urls: Vec<_> = analysis
        .strings
        .iter()
        .filter(|s| s.category == StringCategory::Url)
        .collect();
    assert_eq!(urls.len(), 1);
    assert!(urls[0].value.contains("evil.com"));
}

#[test]
fn extract_api_key_string() {
    // Pad with non-printable byte so LEB128 length doesn't merge into the string run
    let mut segment = vec![0x00];
    segment.extend_from_slice(b"sk-proj-abcdefghijklmnopqrstuvwxyz");
    let data = build_data_section_passive(&[&segment]);
    let wasm = build_wasm_module(&[(11, data)]);
    let analysis = analyze_wasm(&wasm);
    let keys: Vec<_> = analysis
        .strings
        .iter()
        .filter(|s| s.category == StringCategory::ApiKey)
        .collect();
    assert_eq!(keys.len(), 1);
    assert!(keys[0].value.starts_with("sk-"));
}

#[test]
fn extract_credential_string() {
    let data = build_data_section_passive(&[b"password=hunter2"]);
    let wasm = build_wasm_module(&[(11, data)]);
    let analysis = analyze_wasm(&wasm);
    let creds: Vec<_> = analysis
        .strings
        .iter()
        .filter(|s| s.category == StringCategory::Credential)
        .collect();
    assert_eq!(creds.len(), 1);
}

#[test]
fn extract_aws_key() {
    let data = build_data_section_passive(&[b"AKIAIOSFODNN7EXAMPLE"]);
    let wasm = build_wasm_module(&[(11, data)]);
    let analysis = analyze_wasm(&wasm);
    let keys: Vec<_> = analysis
        .strings
        .iter()
        .filter(|s| s.category == StringCategory::ApiKey)
        .collect();
    assert_eq!(keys.len(), 1);
}

#[test]
fn custom_section_name_parsed() {
    let custom = build_custom_section("producers", &[0x00; 10]);
    let wasm = build_wasm_module(&[(0, custom)]);
    let analysis = analyze_wasm(&wasm);
    assert_eq!(analysis.custom_sections.len(), 1);
    assert_eq!(analysis.custom_sections[0].name, "producers");
    assert_eq!(analysis.custom_sections[0].size, 10);
}

#[test]
fn debug_section_flagged() {
    let custom = build_custom_section(".debug_info", &[0x00; 50]);
    let wasm = build_wasm_module(&[(0, custom)]);
    let analysis = analyze_wasm(&wasm);
    let debug_findings: Vec<_> = analysis
        .security_findings
        .iter()
        .filter(|f| f.category == FindingCategory::DebugInfoLeak)
        .collect();
    assert_eq!(debug_findings.len(), 1);
    assert_eq!(debug_findings[0].severity, Severity::Medium);
}

#[test]
fn source_map_section_flagged() {
    let custom = build_custom_section("sourceMappingURL", &[0x00; 20]);
    let wasm = build_wasm_module(&[(0, custom)]);
    let analysis = analyze_wasm(&wasm);
    assert!(
        analysis
            .security_findings
            .iter()
            .any(|f| f.category == FindingCategory::DebugInfoLeak)
    );
}

#[test]
fn dangerous_import_eval_bridge() {
    let imports = build_import_section_funcs(&[("env", "eval", 0)]);
    let wasm = build_wasm_module(&[(2, imports)]);
    let analysis = analyze_wasm(&wasm);
    let eval_findings: Vec<_> = analysis
        .security_findings
        .iter()
        .filter(|f| {
            f.category == FindingCategory::DangerousImport && f.severity == Severity::Critical
        })
        .collect();
    assert!(
        !eval_findings.is_empty(),
        "eval import should flag critical"
    );
}

#[test]
fn dangerous_import_wasi_fd_write() {
    let imports = build_import_section_funcs(&[("wasi_snapshot_preview1", "fd_write", 0)]);
    let wasm = build_wasm_module(&[(2, imports)]);
    let analysis = analyze_wasm(&wasm);
    assert!(
        analysis
            .security_findings
            .iter()
            .any(|f| f.category == FindingCategory::DangerousImport)
    );
}

#[test]
fn dangerous_import_wasi_path_open() {
    let imports = build_import_section_funcs(&[("wasi_snapshot_preview1", "path_open", 0)]);
    let wasm = build_wasm_module(&[(2, imports)]);
    let analysis = analyze_wasm(&wasm);
    let findings: Vec<_> = analysis
        .security_findings
        .iter()
        .filter(|f| f.severity == Severity::High && f.category == FindingCategory::DangerousImport)
        .collect();
    assert!(!findings.is_empty());
}

#[test]
fn dangerous_import_emscripten_run_script() {
    let imports = build_import_section_funcs(&[("env", "emscripten_run_script", 0)]);
    let wasm = build_wasm_module(&[(2, imports)]);
    let analysis = analyze_wasm(&wasm);
    assert!(
        analysis
            .security_findings
            .iter()
            .any(|f| f.severity == Severity::Critical)
    );
}

#[test]
fn dangerous_import_syscall() {
    let imports = build_import_section_funcs(&[("env", "__syscall", 0)]);
    let wasm = build_wasm_module(&[(2, imports)]);
    let analysis = analyze_wasm(&wasm);
    assert!(
        analysis
            .security_findings
            .iter()
            .any(|f| f.category == FindingCategory::DangerousImport)
    );
}

#[test]
fn dangerous_import_wasi_socket() {
    let imports = build_import_section_funcs(&[("wasi_snapshot_preview1", "sock_accept", 0)]);
    let wasm = build_wasm_module(&[(2, imports)]);
    let analysis = analyze_wasm(&wasm);
    assert!(
        analysis
            .security_findings
            .iter()
            .any(|f| f.category == FindingCategory::DangerousImport)
    );
}

#[test]
fn suspicious_export_heap_base() {
    let exports = build_export_section(&[("__heap_base", 0x03, 0)]);
    let wasm = build_wasm_module(&[(7, exports)]);
    let analysis = analyze_wasm(&wasm);
    assert!(
        analysis
            .security_findings
            .iter()
            .any(|f| f.category == FindingCategory::SuspiciousExport)
    );
}

#[test]
fn suspicious_export_malloc() {
    let exports = build_export_section(&[("_malloc", 0x00, 0), ("_free", 0x00, 1)]);
    let wasm = build_wasm_module(&[(7, exports)]);
    let analysis = analyze_wasm(&wasm);
    let suspicious: Vec<_> = analysis
        .security_findings
        .iter()
        .filter(|f| f.category == FindingCategory::SuspiciousExport)
        .collect();
    assert_eq!(suspicious.len(), 2);
}

#[test]
fn excessive_memory_flagged() {
    let mem = build_memory_section(2048, None);
    let wasm = build_wasm_module(&[(5, mem)]);
    let analysis = analyze_wasm(&wasm);
    assert!(
        analysis
            .security_findings
            .iter()
            .any(|f| f.category == FindingCategory::ExcessiveMemory)
    );
}

#[test]
fn max_memory_4gb_flagged() {
    let mem = build_memory_section(1, Some(65536));
    let wasm = build_wasm_module(&[(5, mem)]);
    let analysis = analyze_wasm(&wasm);
    assert!(
        analysis
            .security_findings
            .iter()
            .any(|f| f.category == FindingCategory::ExcessiveMemory)
    );
}

#[test]
fn credential_string_generates_finding() {
    let data = build_data_section_passive(&[b"access_token=eyJhbGciOiJIUzI1NiJ9"]);
    let wasm = build_wasm_module(&[(11, data)]);
    let analysis = analyze_wasm(&wasm);
    assert!(
        analysis
            .security_findings
            .iter()
            .any(|f| f.category == FindingCategory::CredentialLeak)
    );
}

#[test]
fn api_key_generates_critical_finding() {
    let mut segment = vec![0x00];
    segment.extend_from_slice(b"ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456");
    let data = build_data_section_passive(&[&segment]);
    let wasm = build_wasm_module(&[(11, data)]);
    let analysis = analyze_wasm(&wasm);
    let crit: Vec<_> = analysis
        .security_findings
        .iter()
        .filter(|f| {
            f.severity == Severity::Critical && f.category == FindingCategory::CredentialLeak
        })
        .collect();
    assert!(!crit.is_empty());
}

#[test]
fn multiple_sections_combined() {
    let imports = build_import_section_funcs(&[("env", "eval", 0)]);
    let exports = build_export_section(&[("_malloc", 0x00, 0)]);
    let mem = build_memory_section(16, Some(256));
    let custom = build_custom_section(".debug_info", &[0xAB; 100]);
    let data = build_data_section_passive(&[b"https://c2.example.com/beacon"]);

    let wasm = build_wasm_module(&[
        (2, imports),
        (7, exports),
        (5, mem),
        (0, custom),
        (11, data),
    ]);
    let analysis = analyze_wasm(&wasm);
    assert!(analysis.valid);
    assert_eq!(analysis.imports.len(), 1);
    assert_eq!(analysis.exports.len(), 1);
    assert!(analysis.memory_info.is_some());
    assert_eq!(analysis.custom_sections.len(), 1);
    assert!(!analysis.strings.is_empty());
    assert!(analysis.security_findings.len() >= 3);
}

#[test]
fn leb128_roundtrip() {
    for &val in &[0u32, 1, 127, 128, 300, 16384, 2_097_152, u32::MAX] {
        let mut buf = Vec::new();
        encode_leb128_u32(val, &mut buf);
        let (decoded, consumed) = read_leb128_u32(&buf, 0).unwrap();
        assert_eq!(decoded, val, "roundtrip failed for {val}");
        assert_eq!(consumed, buf.len());
    }
}

#[test]
fn filepath_string_classified() {
    let data = build_data_section_passive(&[b"/etc/passwd"]);
    let wasm = build_wasm_module(&[(11, data)]);
    let analysis = analyze_wasm(&wasm);
    let paths: Vec<_> = analysis
        .strings
        .iter()
        .filter(|s| s.category == StringCategory::FilePath)
        .collect();
    assert_eq!(paths.len(), 1);
}

#[test]
fn short_strings_ignored() {
    let data = build_data_section_passive(&[b"abc"]);
    let wasm = build_wasm_module(&[(11, data)]);
    let analysis = analyze_wasm(&wasm);
    assert!(analysis.strings.is_empty());
}

#[test]
fn multiple_data_segments() {
    let data = build_data_section_passive(&[b"https://api.evil.com", b"password=supersecret"]);
    let wasm = build_wasm_module(&[(11, data)]);
    let analysis = analyze_wasm(&wasm);
    assert!(analysis.strings.len() >= 2);
}

#[test]
fn normal_memory_no_finding() {
    let mem = build_memory_section(16, Some(256));
    let wasm = build_wasm_module(&[(5, mem)]);
    let analysis = analyze_wasm(&wasm);
    assert!(
        !analysis
            .security_findings
            .iter()
            .any(|f| f.category == FindingCategory::ExcessiveMemory)
    );
}

#[test]
fn truncated_section_handled() {
    let mut wasm = minimal_wasm();
    wasm.push(2); // import section id
    wasm.push(99); // claims 99 bytes but data ends here
    let analysis = analyze_wasm(&wasm);
    assert!(analysis.valid);
    assert!(analysis.imports.is_empty());
}
