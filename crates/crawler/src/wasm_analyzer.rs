//! WebAssembly binary analyzer for security issue detection.
//!
//! Parses raw WASM binary format (not WAT text), extracts structural
//! information, and flags security-relevant patterns: dangerous imports,
//! leaked credentials in data sections, debug info in custom sections,
//! and suspicious memory layouts.

const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D]; // \0asm
const WASM_VERSION_1: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

const SECTION_IMPORT: u8 = 2;
const SECTION_FUNCTION: u8 = 3;
const SECTION_MEMORY: u8 = 5;
const SECTION_EXPORT: u8 = 7;
const SECTION_DATA: u8 = 11;
const SECTION_CUSTOM: u8 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmAnalysis {
    pub valid: bool,
    pub version: u32,
    pub imports: Vec<WasmImport>,
    pub exports: Vec<WasmExport>,
    pub strings: Vec<ExtractedString>,
    pub custom_sections: Vec<CustomSection>,
    pub memory_info: Option<MemoryInfo>,
    pub security_findings: Vec<SecurityFinding>,
    pub function_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmImport {
    pub module: String,
    pub name: String,
    pub kind: ImportKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportKind {
    Function(u32),
    Table,
    Memory,
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmExport {
    pub name: String,
    pub kind: ExportKind,
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportKind {
    Function,
    Table,
    Memory,
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedString {
    pub value: String,
    pub category: StringCategory,
    pub offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringCategory {
    Url,
    ApiKey,
    Credential,
    FilePath,
    Generic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomSection {
    pub name: String,
    pub size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryInfo {
    pub initial_pages: u32,
    pub maximum_pages: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityFinding {
    pub severity: Severity,
    pub category: FindingCategory,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingCategory {
    DangerousImport,
    CredentialLeak,
    DebugInfoLeak,
    ExcessiveMemory,
    SuspiciousExport,
    NetworkAccess,
}

/// Top-level entry point: analyze raw WASM bytes.
pub fn analyze_wasm(data: &[u8]) -> WasmAnalysis {
    let mut analysis = WasmAnalysis {
        valid: false,
        version: 0,
        imports: Vec::new(),
        exports: Vec::new(),
        strings: Vec::new(),
        custom_sections: Vec::new(),
        memory_info: None,
        security_findings: Vec::new(),
        function_count: 0,
    };

    if data.len() < 8 {
        return analysis;
    }
    if data[0..4] != WASM_MAGIC {
        return analysis;
    }
    if data[4..8] != WASM_VERSION_1 {
        return analysis;
    }

    analysis.valid = true;
    analysis.version = 1;

    let mut cursor = 8;
    while cursor < data.len() {
        let Some((section_id, section_bytes, next)) = read_section(data, cursor) else {
            break;
        };
        match section_id {
            SECTION_IMPORT => parse_import_section(section_bytes, &mut analysis),
            SECTION_EXPORT => parse_export_section(section_bytes, &mut analysis),
            SECTION_DATA => extract_data_strings(section_bytes, &mut analysis),
            SECTION_CUSTOM => parse_custom_section(section_bytes, &mut analysis),
            SECTION_MEMORY => parse_memory_section(section_bytes, &mut analysis),
            SECTION_FUNCTION => parse_function_section(section_bytes, &mut analysis),
            _ => {}
        }
        cursor = next;
    }

    run_security_checks(&mut analysis);
    analysis
}

fn read_section(data: &[u8], offset: usize) -> Option<(u8, &[u8], usize)> {
    if offset >= data.len() {
        return None;
    }
    let section_id = data[offset];
    let (size, consumed) = read_leb128_u32(data, offset + 1)?;
    let payload_start = offset + 1 + consumed;
    let payload_end = payload_start + size as usize;
    if payload_end > data.len() {
        return None;
    }
    Some((section_id, &data[payload_start..payload_end], payload_end))
}

pub fn read_leb128_u32(data: &[u8], offset: usize) -> Option<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    let mut pos = offset;
    loop {
        if pos >= data.len() {
            return None;
        }
        let byte = data[pos];
        let low_bits = (byte & 0x7F) as u32;
        if shift >= 32 && low_bits != 0 {
            return None;
        }
        result |= low_bits.checked_shl(shift)?;
        pos += 1;
        if byte & 0x80 == 0 {
            return Some((result, pos - offset));
        }
        shift += 7;
        if shift > 35 {
            return None;
        }
    }
}

fn read_name(data: &[u8], offset: usize) -> Option<(String, usize)> {
    let (len, consumed) = read_leb128_u32(data, offset)?;
    let start = offset + consumed;
    let end = start + len as usize;
    if end > data.len() {
        return None;
    }
    let s = String::from_utf8_lossy(&data[start..end]).into_owned();
    Some((s, consumed + len as usize))
}

fn parse_import_section(data: &[u8], analysis: &mut WasmAnalysis) {
    let Some((count, mut pos)) = read_leb128_u32(data, 0) else {
        return;
    };
    for _ in 0..count {
        let Some((module, mod_consumed)) = read_name(data, pos) else {
            return;
        };
        pos += mod_consumed;
        let Some((name, name_consumed)) = read_name(data, pos) else {
            return;
        };
        pos += name_consumed;
        if pos >= data.len() {
            return;
        }
        let kind_byte = data[pos];
        pos += 1;
        let kind = match kind_byte {
            0x00 => {
                let Some((type_idx, c)) = read_leb128_u32(data, pos) else {
                    return;
                };
                pos += c;
                ImportKind::Function(type_idx)
            }
            0x01 => {
                // table: reftype + limits
                pos += 1; // reftype
                let Some(c) = skip_limits(data, pos) else {
                    return;
                };
                pos += c;
                ImportKind::Table
            }
            0x02 => {
                let Some(c) = skip_limits(data, pos) else {
                    return;
                };
                pos += c;
                ImportKind::Memory
            }
            0x03 => {
                // global: valtype + mutability
                pos += 2;
                ImportKind::Global
            }
            _ => return,
        };
        analysis.imports.push(WasmImport { module, name, kind });
    }
}

fn skip_limits(data: &[u8], offset: usize) -> Option<usize> {
    if offset >= data.len() {
        return None;
    }
    let flags = data[offset];
    let (_, c1) = read_leb128_u32(data, offset + 1)?;
    if flags & 0x01 != 0 {
        let (_, c2) = read_leb128_u32(data, offset + 1 + c1)?;
        Some(1 + c1 + c2)
    } else {
        Some(1 + c1)
    }
}

fn parse_export_section(data: &[u8], analysis: &mut WasmAnalysis) {
    let Some((count, mut pos)) = read_leb128_u32(data, 0) else {
        return;
    };
    for _ in 0..count {
        let Some((name, name_consumed)) = read_name(data, pos) else {
            return;
        };
        pos += name_consumed;
        if pos >= data.len() {
            return;
        }
        let kind_byte = data[pos];
        pos += 1;
        let kind = match kind_byte {
            0x00 => ExportKind::Function,
            0x01 => ExportKind::Table,
            0x02 => ExportKind::Memory,
            0x03 => ExportKind::Global,
            _ => return,
        };
        let Some((index, c)) = read_leb128_u32(data, pos) else {
            return;
        };
        pos += c;
        analysis.exports.push(WasmExport { name, kind, index });
    }
}

fn parse_memory_section(data: &[u8], analysis: &mut WasmAnalysis) {
    let Some((count, mut pos)) = read_leb128_u32(data, 0) else {
        return;
    };
    if count == 0 {
        return;
    }
    if pos >= data.len() {
        return;
    }
    let flags = data[pos];
    pos += 1;
    let Some((initial, c1)) = read_leb128_u32(data, pos) else {
        return;
    };
    pos += c1;
    let maximum = if flags & 0x01 != 0 {
        read_leb128_u32(data, pos).map(|(v, _)| v)
    } else {
        None
    };
    analysis.memory_info = Some(MemoryInfo {
        initial_pages: initial,
        maximum_pages: maximum,
    });
}

fn parse_function_section(data: &[u8], analysis: &mut WasmAnalysis) {
    if let Some((count, _)) = read_leb128_u32(data, 0) {
        analysis.function_count = count;
    }
}

fn extract_data_strings(data: &[u8], analysis: &mut WasmAnalysis) {
    let min_printable_run = 6;
    let mut run_start = None;
    let mut run_bytes = Vec::new();

    for (i, &b) in data.iter().enumerate() {
        if is_printable_ascii(b) {
            if run_start.is_none() {
                run_start = Some(i);
                run_bytes.clear();
            }
            run_bytes.push(b);
        } else if let Some(start) = run_start.take() {
            if run_bytes.len() >= min_printable_run {
                let value = String::from_utf8_lossy(&run_bytes).into_owned();
                let category = classify_string(&value);
                analysis.strings.push(ExtractedString {
                    value,
                    category,
                    offset: start,
                });
            }
            run_bytes.clear();
        }
    }
    if let Some(start) = run_start
        && run_bytes.len() >= min_printable_run
    {
        let value = String::from_utf8_lossy(&run_bytes).into_owned();
        let category = classify_string(&value);
        analysis.strings.push(ExtractedString {
            value,
            category,
            offset: start,
        });
    }
}

fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7E).contains(&b)
}

fn classify_string(s: &str) -> StringCategory {
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("ws://") {
        return StringCategory::Url;
    }
    if looks_like_api_key(s) {
        return StringCategory::ApiKey;
    }
    if looks_like_credential(&lower) {
        return StringCategory::Credential;
    }
    if lower.starts_with('/') && lower.contains('/') && lower.len() > 2 {
        return StringCategory::FilePath;
    }
    StringCategory::Generic
}

fn looks_like_api_key(s: &str) -> bool {
    let prefixes = [
        "sk-", "pk-", "AKIA", "AIza", "ghp_", "gho_", "glpat-", "xoxb-", "xoxp-",
    ];
    for prefix in &prefixes {
        if s.starts_with(prefix) {
            return true;
        }
    }
    let lower = s.to_ascii_lowercase();
    if (lower.contains("api_key") || lower.contains("apikey")) && s.contains('=') {
        return true;
    }
    false
}

fn looks_like_credential(lower: &str) -> bool {
    let patterns = [
        "password=",
        "passwd=",
        "secret=",
        "token=",
        "auth_token=",
        "access_token=",
        "private_key",
        "-----begin",
    ];
    patterns.iter().any(|p| lower.contains(p))
}

fn parse_custom_section(data: &[u8], analysis: &mut WasmAnalysis) {
    let Some((name, name_consumed)) = read_name(data, 0) else {
        return;
    };
    let remaining = data.len().saturating_sub(name_consumed);
    analysis.custom_sections.push(CustomSection {
        name,
        size: remaining,
    });
}

const DANGEROUS_IMPORTS: &[(&str, &str, Severity, &str)] = &[
    (
        "eval",
        "eval",
        Severity::Critical,
        "eval bridge allows arbitrary code execution from WASM",
    ),
    (
        "emscripten",
        "invoke_",
        Severity::High,
        "emscripten invoke can call arbitrary function pointers",
    ),
    (
        "env",
        "__syscall",
        Severity::High,
        "raw syscall access bypasses sandboxing",
    ),
    (
        "env",
        "emscripten_run_script",
        Severity::Critical,
        "direct JavaScript eval from WASM module",
    ),
    (
        "wasi_snapshot_preview1",
        "fd_write",
        Severity::Medium,
        "filesystem write access via WASI",
    ),
    (
        "wasi_snapshot_preview1",
        "fd_read",
        Severity::Medium,
        "filesystem read access via WASI",
    ),
    (
        "wasi_snapshot_preview1",
        "path_open",
        Severity::High,
        "arbitrary path opening via WASI",
    ),
    (
        "wasi_snapshot_preview1",
        "sock_",
        Severity::High,
        "network socket access via WASI",
    ),
    (
        "env",
        "memory",
        Severity::Medium,
        "raw memory import grants unscoped memory access",
    ),
    (
        "env",
        "abort",
        Severity::Low,
        "abort import may indicate unsafe memory patterns",
    ),
    (
        "env",
        "__memory_base",
        Severity::Medium,
        "dynamic memory base suggests relocatable code with direct memory manipulation",
    ),
    (
        "env",
        "__indirect_function_table",
        Severity::Medium,
        "indirect function table import enables dynamic dispatch and potential control-flow hijacking",
    ),
];

const DEBUG_SECTION_NAMES: &[&str] = &[
    "name",
    ".debug_info",
    ".debug_line",
    ".debug_str",
    ".debug_abbrev",
    ".debug_ranges",
    "sourceMappingURL",
    "producers",
];

const SUSPICIOUS_EXPORT_NAMES: &[(&str, &str)] = &[
    ("__heap_base", "heap base address leaked via export"),
    ("__data_end", "data segment boundary leaked via export"),
    ("stackSave", "stack manipulation exported"),
    ("stackRestore", "stack manipulation exported"),
    ("stackAlloc", "raw stack allocation exported"),
    (
        "_malloc",
        "raw malloc exported, potential heap exploitation vector",
    ),
    (
        "_free",
        "raw free exported, potential use-after-free vector",
    ),
    (
        "__indirect_function_table",
        "indirect call table exported, enables function pointer manipulation",
    ),
];

fn run_security_checks(analysis: &mut WasmAnalysis) {
    check_dangerous_imports(analysis);
    check_debug_sections(analysis);
    check_suspicious_exports(analysis);
    check_credential_strings(analysis);
    check_memory_size(analysis);
}

fn check_dangerous_imports(analysis: &mut WasmAnalysis) {
    let mut findings = Vec::new();
    for imp in &analysis.imports {
        for &(module_pattern, name_pattern, ref severity, description) in DANGEROUS_IMPORTS {
            let module_match = imp.module.contains(module_pattern)
                || module_pattern == "eval" && imp.module == "env";
            let name_match = imp.name.contains(name_pattern)
                || (module_pattern == "eval" && imp.name.contains("eval"));
            if module_match && name_match {
                findings.push(SecurityFinding {
                    severity: severity.clone(),
                    category: FindingCategory::DangerousImport,
                    description: format!("import {}.{}: {}", imp.module, imp.name, description),
                });
            }
        }
    }
    analysis.security_findings.extend(findings);
}

fn check_debug_sections(analysis: &mut WasmAnalysis) {
    let mut findings = Vec::new();
    for section in &analysis.custom_sections {
        for &debug_name in DEBUG_SECTION_NAMES {
            if section.name == debug_name || section.name.starts_with(debug_name) {
                findings.push(SecurityFinding {
                    severity: Severity::Medium,
                    category: FindingCategory::DebugInfoLeak,
                    description: format!(
                        "custom section '{}' ({} bytes) leaks build/debug information",
                        section.name, section.size
                    ),
                });
                break;
            }
        }
    }
    analysis.security_findings.extend(findings);
}

fn check_suspicious_exports(analysis: &mut WasmAnalysis) {
    let mut findings = Vec::new();
    for exp in &analysis.exports {
        for &(pattern, description) in SUSPICIOUS_EXPORT_NAMES {
            if exp.name == pattern || exp.name.contains(pattern) {
                findings.push(SecurityFinding {
                    severity: Severity::Low,
                    category: FindingCategory::SuspiciousExport,
                    description: format!("export '{}': {}", exp.name, description),
                });
                break;
            }
        }
    }
    analysis.security_findings.extend(findings);
}

fn check_credential_strings(analysis: &mut WasmAnalysis) {
    let mut findings = Vec::new();
    for s in &analysis.strings {
        match s.category {
            StringCategory::ApiKey => {
                findings.push(SecurityFinding {
                    severity: Severity::Critical,
                    category: FindingCategory::CredentialLeak,
                    description: format!(
                        "potential API key at data offset {}: '{}'",
                        s.offset,
                        truncate_for_display(&s.value, 40)
                    ),
                });
            }
            StringCategory::Credential => {
                findings.push(SecurityFinding {
                    severity: Severity::High,
                    category: FindingCategory::CredentialLeak,
                    description: format!(
                        "potential credential at data offset {}: '{}'",
                        s.offset,
                        truncate_for_display(&s.value, 40)
                    ),
                });
            }
            _ => {}
        }
    }
    analysis.security_findings.extend(findings);
}

fn check_memory_size(analysis: &mut WasmAnalysis) {
    let excessive_pages = 1024; // 64 MiB
    if let Some(ref mem) = analysis.memory_info {
        if mem.initial_pages >= excessive_pages {
            analysis.security_findings.push(SecurityFinding {
                severity: Severity::Medium,
                category: FindingCategory::ExcessiveMemory,
                description: format!(
                    "initial memory {} pages ({} MiB) is unusually large",
                    mem.initial_pages,
                    mem.initial_pages as u64 * 64 / 1024
                ),
            });
        }
        if let Some(max) = mem.maximum_pages
            && max == 65536
        {
            analysis.security_findings.push(SecurityFinding {
                severity: Severity::Low,
                category: FindingCategory::ExcessiveMemory,
                description: "maximum memory set to 4 GiB (65536 pages), the absolute WASM limit"
                    .to_owned(),
            });
        }
    }
}

fn truncate_for_display(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_owned()
    } else {
        format!("{}...", &s[..max_len])
    }
}

/// Build a minimal valid WASM module from sections.
/// Useful for constructing test fixtures programmatically.
pub fn build_wasm_module(sections: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&WASM_MAGIC);
    out.extend_from_slice(&WASM_VERSION_1);
    for (id, payload) in sections {
        out.push(*id);
        encode_leb128_u32(payload.len() as u32, &mut out);
        out.extend_from_slice(payload);
    }
    out
}

/// Encode a u32 as LEB128 and append to the buffer.
pub fn encode_leb128_u32(mut value: u32, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Encode a name (length-prefixed UTF-8) and append to the buffer.
pub fn encode_name(s: &str, out: &mut Vec<u8>) {
    encode_leb128_u32(s.len() as u32, out);
    out.extend_from_slice(s.as_bytes());
}

/// Build an import section payload from a list of (module, name, type_index) function imports.
pub fn build_import_section_funcs(imports: &[(&str, &str, u32)]) -> Vec<u8> {
    let mut payload = Vec::new();
    encode_leb128_u32(imports.len() as u32, &mut payload);
    for (module, name, type_idx) in imports {
        encode_name(module, &mut payload);
        encode_name(name, &mut payload);
        payload.push(0x00); // function import
        encode_leb128_u32(*type_idx, &mut payload);
    }
    payload
}

/// Build an export section payload from a list of (name, kind_byte, index) exports.
pub fn build_export_section(exports: &[(&str, u8, u32)]) -> Vec<u8> {
    let mut payload = Vec::new();
    encode_leb128_u32(exports.len() as u32, &mut payload);
    for (name, kind, index) in exports {
        encode_name(name, &mut payload);
        payload.push(*kind);
        encode_leb128_u32(*index, &mut payload);
    }
    payload
}

/// Build a memory section payload.
pub fn build_memory_section(initial: u32, maximum: Option<u32>) -> Vec<u8> {
    let mut payload = Vec::new();
    encode_leb128_u32(1, &mut payload); // count=1
    match maximum {
        Some(max) => {
            payload.push(0x01); // has-max flag
            encode_leb128_u32(initial, &mut payload);
            encode_leb128_u32(max, &mut payload);
        }
        None => {
            payload.push(0x00);
            encode_leb128_u32(initial, &mut payload);
        }
    }
    payload
}

/// Build a custom section payload with a name.
pub fn build_custom_section(name: &str, extra_bytes: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    encode_name(name, &mut payload);
    payload.extend_from_slice(extra_bytes);
    payload
}

/// Build a data section payload containing raw byte segments.
pub fn build_data_section_passive(segments: &[&[u8]]) -> Vec<u8> {
    let mut payload = Vec::new();
    encode_leb128_u32(segments.len() as u32, &mut payload);
    for seg in segments {
        payload.push(0x01); // passive segment flag
        encode_leb128_u32(seg.len() as u32, &mut payload);
        payload.extend_from_slice(seg);
    }
    payload
}

/// Build a function section payload (just type indices).
pub fn build_function_section(type_indices: &[u32]) -> Vec<u8> {
    let mut payload = Vec::new();
    encode_leb128_u32(type_indices.len() as u32, &mut payload);
    for idx in type_indices {
        encode_leb128_u32(*idx, &mut payload);
    }
    payload
}
