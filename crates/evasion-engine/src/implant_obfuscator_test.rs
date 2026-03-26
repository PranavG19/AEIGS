use crate::implant_obfuscator::*;

#[test]
fn test_obfuscator_creation_defaults() {
    let obfuscator = ImplantObfuscator::with_defaults();
    let implant = ImplantDescriptor::default();
    let report = obfuscator.obfuscate(&implant);
    assert!(report.encrypted_strings.is_empty());
    assert!(report.api_hashes.is_empty());
    assert!(!report.control_flow_transforms.is_empty());
    assert!(report.packer_config.is_some());
}

#[test]
fn test_string_encryption_xor_rolling() {
    let obfuscator = ImplantObfuscator::with_defaults();
    let implant = ImplantDescriptor {
        strings: vec![
            "CreateRemoteThread".to_string(),
            "VirtualAllocEx".to_string(),
            "cmd.exe /c whoami".to_string(),
        ],
        ..Default::default()
    };

    let report = obfuscator.obfuscate(&implant);
    assert_eq!(report.encrypted_strings.len(), 3);

    for enc in &report.encrypted_strings {
        assert_eq!(enc.algorithm, StringEncryptionAlgorithm::XorRollingKey);
        assert!(!enc.encrypted_bytes.is_empty());
        assert!(!enc.key.is_empty());
        assert_ne!(enc.encrypted_bytes, enc.original.as_bytes());
        assert!(enc.decryption_stub.contains("rolling"));
    }
}

#[test]
fn test_string_encryption_roundtrip() {
    let obfuscator = ImplantObfuscator::with_defaults();
    let original = "Hello, World!";
    let implant = ImplantDescriptor {
        strings: vec![original.to_string()],
        ..Default::default()
    };

    let report = obfuscator.obfuscate(&implant);
    let enc = &report.encrypted_strings[0];

    let decrypted: Vec<u8> = enc
        .encrypted_bytes
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ enc.key[i % enc.key.len()])
        .collect();
    assert_eq!(decrypted, original.as_bytes());
}

#[test]
fn test_api_hashing_djb2() {
    let obfuscator = ImplantObfuscator::with_defaults();
    let implant = ImplantDescriptor {
        api_imports: vec![
            ("kernel32.dll".to_string(), "VirtualAlloc".to_string()),
            ("ntdll.dll".to_string(), "NtCreateThreadEx".to_string()),
        ],
        ..Default::default()
    };

    let report = obfuscator.obfuscate(&implant);
    assert_eq!(report.api_hashes.len(), 2);

    for hash in &report.api_hashes {
        assert_eq!(hash.algorithm, ApiHashAlgorithm::Djb2);
        assert_ne!(hash.hash_value, 0);
        assert!(hash.resolution_stub.contains("0x"));
        assert!(hash.resolution_stub.contains(&hash.dll_name));
    }
}

#[test]
fn test_api_hash_deterministic() {
    let hash1 = ImplantObfuscator::djb2_hash("VirtualAlloc");
    let hash2 = ImplantObfuscator::djb2_hash("VirtualAlloc");
    assert_eq!(hash1, hash2);

    let hash3 = ImplantObfuscator::djb2_hash("VirtualAllocEx");
    assert_ne!(hash1, hash3);
}

#[test]
fn test_crc32_hash() {
    let hash = ImplantObfuscator::crc32_hash("CreateRemoteThread");
    assert_ne!(hash, 0);
    assert_eq!(hash, ImplantObfuscator::crc32_hash("CreateRemoteThread"));
    assert_ne!(hash, ImplantObfuscator::crc32_hash("VirtualAlloc"));
}

#[test]
fn test_ror13_hash() {
    let hash = ImplantObfuscator::ror13_hash("LoadLibraryA");
    assert_ne!(hash, 0);
    assert_eq!(hash, ImplantObfuscator::ror13_hash("LoadLibraryA"));
}

#[test]
fn test_multiple_hash_algorithms() {
    let name = "VirtualAlloc";
    let crc = ImplantObfuscator::crc32_hash(name);
    let djb2 = ImplantObfuscator::djb2_hash(name);
    let ror13 = ImplantObfuscator::ror13_hash(name);

    assert_ne!(crc, djb2);
    assert_ne!(crc, ror13);
    assert_ne!(djb2, ror13);
}

#[test]
fn test_control_flow_transforms() {
    let obfuscator = ImplantObfuscator::with_defaults();
    let implant = ImplantDescriptor::default();

    let report = obfuscator.obfuscate(&implant);
    assert_eq!(report.control_flow_transforms.len(), 3);

    let patterns: Vec<_> = report
        .control_flow_transforms
        .iter()
        .map(|t| t.pattern)
        .collect();
    assert!(patterns.contains(&ControlFlowPattern::OpaquePredicate));
    assert!(patterns.contains(&ControlFlowPattern::JunkCodeInsertion));
    assert!(patterns.contains(&ControlFlowPattern::FlattenedDispatch));

    for transform in &report.control_flow_transforms {
        assert!(!transform.code_template.is_empty());
        assert!(transform.entropy_increase > 0.0);
        assert!(transform.performance_overhead_pct > 0.0);
    }
}

#[test]
fn test_packer_stub_generation() {
    let obfuscator = ImplantObfuscator::with_defaults();
    let implant = ImplantDescriptor {
        payload_size_bytes: 65536,
        target_arch: TargetArch::X64,
        is_windows: true,
        ..Default::default()
    };

    let report = obfuscator.obfuscate(&implant);
    let packer = report.packer_config.as_ref().unwrap();
    assert_eq!(packer.compression_algorithm, "LZMA2");
    assert!(!packer.anti_debug_checks.is_empty());
    assert!(packer
        .anti_debug_checks
        .iter()
        .any(|c| c.contains("IsDebuggerPresent")));
    assert!(packer.anti_debug_checks.iter().any(|c| c.contains("RDTSC")));
    assert!(packer.stub_template.contains("65536"));
    assert!(packer.estimated_size_overhead_pct > 0.0);
}

#[test]
fn test_pe_header_stomp_windows_only() {
    let obfuscator = ImplantObfuscator::with_defaults();

    let win_implant = ImplantDescriptor {
        is_windows: true,
        ..Default::default()
    };
    let report = obfuscator.obfuscate(&win_implant);
    assert!(report.pe_stomp_config.is_some());
    let pe_config = report.pe_stomp_config.unwrap();
    assert!(pe_config.stomp_dos_header);
    assert!(pe_config.stomp_pe_signature);
    assert!(pe_config.preserve_entry_point);
    assert!(pe_config.command.contains("VirtualProtect"));

    let linux_implant = ImplantDescriptor {
        is_windows: false,
        ..Default::default()
    };
    let report2 = obfuscator.obfuscate(&linux_implant);
    assert!(report2.pe_stomp_config.is_none());
}

#[test]
fn test_process_hollowing_windows_only() {
    let obfuscator = ImplantObfuscator::with_defaults();

    let win_implant = ImplantDescriptor {
        is_windows: true,
        ..Default::default()
    };
    let report = obfuscator.obfuscate(&win_implant);
    assert!(!report.hollowing_configs.is_empty());
    for config in &report.hollowing_configs {
        assert!(config.create_suspended);
        assert!(config.unmap_original);
        assert!(!config.api_sequence.is_empty());
        assert!(config
            .api_sequence
            .iter()
            .any(|a| a.contains("CREATE_SUSPENDED")));
        assert!(config
            .api_sequence
            .iter()
            .any(|a| a.contains("NtUnmapViewOfSection")));
        assert!(config
            .api_sequence
            .iter()
            .any(|a| a.contains("ResumeThread")));
    }

    let linux_implant = ImplantDescriptor {
        is_windows: false,
        ..Default::default()
    };
    let report2 = obfuscator.obfuscate(&linux_implant);
    assert!(report2.hollowing_configs.is_empty());
}

#[test]
fn test_reflective_loading_dll_only() {
    let obfuscator = ImplantObfuscator::with_defaults();

    let dll_implant = ImplantDescriptor {
        is_dll: true,
        is_windows: true,
        ..Default::default()
    };
    let report = obfuscator.obfuscate(&dll_implant);
    assert!(!report.reflective_configs.is_empty());
    let loader_types: Vec<_> = report
        .reflective_configs
        .iter()
        .map(|r| r.loader_type)
        .collect();
    assert!(loader_types.contains(&ReflectiveLoaderType::ReflectiveDll));
    assert!(loader_types.contains(&ReflectiveLoaderType::ManualMap));
    assert!(loader_types.contains(&ReflectiveLoaderType::ModuleStomping));

    let exe_implant = ImplantDescriptor {
        is_dll: false,
        is_windows: true,
        ..Default::default()
    };
    let report2 = obfuscator.obfuscate(&exe_implant);
    assert!(report2.reflective_configs.is_empty());
}

#[test]
fn test_evasion_score_calculation() {
    let obfuscator = ImplantObfuscator::with_defaults();
    let implant = ImplantDescriptor {
        strings: vec!["test".to_string()],
        api_imports: vec![("kernel32.dll".to_string(), "VirtualAlloc".to_string())],
        payload_size_bytes: 4096,
        is_windows: true,
        is_dll: true,
        target_arch: TargetArch::X64,
    };

    let report = obfuscator.obfuscate(&implant);
    assert!(report.estimated_av_evasion_score > 0.0);
    assert!(report.estimated_av_evasion_score <= 100.0);
}

#[test]
fn test_technique_coverage_tracking() {
    let obfuscator = ImplantObfuscator::with_defaults();
    let implant = ImplantDescriptor {
        strings: vec!["test".to_string()],
        api_imports: vec![("kernel32.dll".to_string(), "VirtualAlloc".to_string())],
        payload_size_bytes: 4096,
        is_windows: true,
        is_dll: true,
        target_arch: TargetArch::X64,
    };

    let report = obfuscator.obfuscate(&implant);
    assert!(report
        .technique_coverage
        .contains_key(&ObfuscationTechnique::StringEncryption));
    assert!(report
        .technique_coverage
        .contains_key(&ObfuscationTechnique::ApiHashing));
    assert!(report
        .technique_coverage
        .contains_key(&ObfuscationTechnique::ControlFlowObfuscation));
    assert!(report
        .technique_coverage
        .contains_key(&ObfuscationTechnique::PackerStub));
    assert!(report
        .technique_coverage
        .contains_key(&ObfuscationTechnique::PeHeaderStomp));
    assert!(report
        .technique_coverage
        .contains_key(&ObfuscationTechnique::ProcessHollowing));
    assert!(report
        .technique_coverage
        .contains_key(&ObfuscationTechnique::ReflectiveLoading));
}

#[test]
fn test_disabled_techniques() {
    let config = ImplantObfuscatorConfig {
        enable_string_encryption: false,
        enable_api_hashing: false,
        enable_control_flow: false,
        enable_packer: false,
        enable_pe_stomp: false,
        enable_process_hollowing: false,
        enable_reflective_loading: false,
        ..Default::default()
    };
    let obfuscator = ImplantObfuscator::new(config);
    let implant = ImplantDescriptor {
        strings: vec!["test".to_string()],
        api_imports: vec![("kernel32.dll".to_string(), "VirtualAlloc".to_string())],
        is_windows: true,
        is_dll: true,
        ..Default::default()
    };

    let report = obfuscator.obfuscate(&implant);
    assert!(report.encrypted_strings.is_empty());
    assert!(report.api_hashes.is_empty());
    assert!(report.control_flow_transforms.is_empty());
    assert!(report.packer_config.is_none());
    assert!(report.pe_stomp_config.is_none());
    assert!(report.hollowing_configs.is_empty());
    assert!(report.reflective_configs.is_empty());
    assert_eq!(report.estimated_av_evasion_score, 0.0);
}

#[test]
fn test_common_implant_apis() {
    let apis = ImplantObfuscator::common_implant_apis();
    assert!(apis.len() >= 20);
    assert!(apis
        .iter()
        .any(|(dll, func)| *dll == "kernel32.dll" && *func == "VirtualAlloc"));
    assert!(apis
        .iter()
        .any(|(dll, func)| *dll == "ntdll.dll" && *func == "NtCreateThreadEx"));
    assert!(apis
        .iter()
        .any(|(dll, func)| *dll == "ws2_32.dll" && *func == "connect"));
}

#[test]
fn test_custom_hash_algorithm() {
    let config = ImplantObfuscatorConfig {
        api_hash_algorithm: ApiHashAlgorithm::Crc32,
        ..Default::default()
    };
    let obfuscator = ImplantObfuscator::new(config);
    let implant = ImplantDescriptor {
        api_imports: vec![("kernel32.dll".to_string(), "VirtualAlloc".to_string())],
        ..Default::default()
    };

    let report = obfuscator.obfuscate(&implant);
    assert_eq!(report.api_hashes[0].algorithm, ApiHashAlgorithm::Crc32);
    assert_eq!(
        report.api_hashes[0].hash_value,
        ImplantObfuscator::crc32_hash("VirtualAlloc")
    );
}

#[test]
fn test_custom_string_encryption() {
    let config = ImplantObfuscatorConfig {
        string_encryption_algorithm: StringEncryptionAlgorithm::XorSingleByte,
        ..Default::default()
    };
    let obfuscator = ImplantObfuscator::new(config);
    let implant = ImplantDescriptor {
        strings: vec!["secret".to_string()],
        ..Default::default()
    };

    let report = obfuscator.obfuscate(&implant);
    assert_eq!(
        report.encrypted_strings[0].algorithm,
        StringEncryptionAlgorithm::XorSingleByte
    );
    assert_eq!(report.encrypted_strings[0].key.len(), 1);
}

#[test]
fn test_obfuscation_technique_display() {
    assert_eq!(
        format!("{}", ObfuscationTechnique::StringEncryption),
        "string-encryption"
    );
    assert_eq!(
        format!("{}", ObfuscationTechnique::ApiHashing),
        "api-hashing"
    );
    assert_eq!(
        format!("{}", ObfuscationTechnique::ControlFlowObfuscation),
        "control-flow-obfuscation"
    );
    assert_eq!(
        format!("{}", ObfuscationTechnique::PackerStub),
        "packer-stub"
    );
    assert_eq!(
        format!("{}", ObfuscationTechnique::PeHeaderStomp),
        "pe-header-stomp"
    );
    assert_eq!(
        format!("{}", ObfuscationTechnique::ProcessHollowing),
        "process-hollowing"
    );
    assert_eq!(
        format!("{}", ObfuscationTechnique::ReflectiveLoading),
        "reflective-loading"
    );
}

#[test]
fn test_string_encryption_algorithm_display() {
    assert_eq!(
        format!("{}", StringEncryptionAlgorithm::XorSingleByte),
        "XOR-single-byte"
    );
    assert_eq!(
        format!("{}", StringEncryptionAlgorithm::XorRollingKey),
        "XOR-rolling-key"
    );
    assert_eq!(format!("{}", StringEncryptionAlgorithm::Rc4), "RC4");
    assert_eq!(
        format!("{}", StringEncryptionAlgorithm::Aes256Cbc),
        "AES-256-CBC"
    );
    assert_eq!(
        format!("{}", StringEncryptionAlgorithm::ChaCha20),
        "ChaCha20"
    );
}

#[test]
fn test_api_hash_algorithm_display() {
    assert_eq!(format!("{}", ApiHashAlgorithm::Crc32), "CRC32");
    assert_eq!(format!("{}", ApiHashAlgorithm::Djb2), "DJB2");
    assert_eq!(format!("{}", ApiHashAlgorithm::FowlerNollVo), "FNV-1a");
    assert_eq!(format!("{}", ApiHashAlgorithm::Ror13AddHash), "ROR13-add");
    assert_eq!(format!("{}", ApiHashAlgorithm::Sdbm), "SDBM");
    assert_eq!(
        format!("{}", ApiHashAlgorithm::JenkinsOneAtATime),
        "Jenkins-OAT"
    );
    assert_eq!(format!("{}", ApiHashAlgorithm::MurmurHash3), "MurmurHash3");
}

#[test]
fn test_control_flow_pattern_display() {
    assert_eq!(
        format!("{}", ControlFlowPattern::OpaquePredicate),
        "opaque-predicate"
    );
    assert_eq!(
        format!("{}", ControlFlowPattern::JunkCodeInsertion),
        "junk-code-insertion"
    );
    assert_eq!(
        format!("{}", ControlFlowPattern::FlattenedDispatch),
        "flattened-dispatch"
    );
    assert_eq!(
        format!("{}", ControlFlowPattern::BogusControlFlow),
        "bogus-control-flow"
    );
    assert_eq!(
        format!("{}", ControlFlowPattern::CallStackSpoofing),
        "call-stack-spoofing"
    );
    assert_eq!(
        format!("{}", ControlFlowPattern::IndirectBranching),
        "indirect-branching"
    );
}

#[test]
fn test_hollowing_target_display() {
    assert_eq!(format!("{}", HollowingTarget::Svchost), "svchost.exe");
    assert_eq!(format!("{}", HollowingTarget::Explorer), "explorer.exe");
    assert_eq!(
        format!("{}", HollowingTarget::RuntimeBroker),
        "RuntimeBroker.exe"
    );
    assert_eq!(format!("{}", HollowingTarget::Notepad), "notepad.exe");
    assert_eq!(format!("{}", HollowingTarget::Dllhost), "dllhost.exe");
    assert_eq!(format!("{}", HollowingTarget::WerFault), "WerFault.exe");
}

#[test]
fn test_reflective_loader_type_display() {
    assert_eq!(
        format!("{}", ReflectiveLoaderType::ReflectiveDll),
        "reflective-dll"
    );
    assert_eq!(format!("{}", ReflectiveLoaderType::ManualMap), "manual-map");
    assert_eq!(
        format!("{}", ReflectiveLoaderType::ModuleStomping),
        "module-stomping"
    );
    assert_eq!(
        format!("{}", ReflectiveLoaderType::TransactedHollowing),
        "transacted-hollowing"
    );
    assert_eq!(
        format!("{}", ReflectiveLoaderType::PhantomDll),
        "phantom-dll"
    );
}

#[test]
fn test_target_arch_display() {
    assert_eq!(format!("{}", TargetArch::X86), "x86");
    assert_eq!(format!("{}", TargetArch::X64), "x64");
    assert_eq!(format!("{}", TargetArch::Arm64), "ARM64");
}

#[test]
fn test_target_arch_default() {
    let arch = TargetArch::default();
    assert_eq!(arch, TargetArch::X64);
}

#[test]
fn test_max_detection_risk_filter_hollowing() {
    let config = ImplantObfuscatorConfig {
        max_detection_risk: 0.35,
        ..Default::default()
    };
    let obfuscator = ImplantObfuscator::new(config);
    let implant = ImplantDescriptor {
        is_windows: true,
        ..Default::default()
    };

    let report = obfuscator.obfuscate(&implant);
    for config in &report.hollowing_configs {
        assert!(config.detection_risk <= 0.35);
    }
}

#[test]
fn test_full_obfuscation_pipeline() {
    let obfuscator = ImplantObfuscator::with_defaults();
    let implant = ImplantDescriptor {
        strings: vec![
            "http://c2.evil.com/beacon".to_string(),
            "cmd.exe".to_string(),
            "powershell.exe -enc".to_string(),
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
        ],
        api_imports: vec![
            ("kernel32.dll".to_string(), "VirtualAlloc".to_string()),
            ("kernel32.dll".to_string(), "CreateRemoteThread".to_string()),
            ("ntdll.dll".to_string(), "NtCreateThreadEx".to_string()),
            ("wininet.dll".to_string(), "InternetOpenA".to_string()),
        ],
        payload_size_bytes: 131072,
        target_arch: TargetArch::X64,
        is_dll: true,
        is_windows: true,
    };

    let report = obfuscator.obfuscate(&implant);
    assert_eq!(report.encrypted_strings.len(), 4);
    assert_eq!(report.api_hashes.len(), 4);
    assert!(!report.control_flow_transforms.is_empty());
    assert!(report.packer_config.is_some());
    assert!(report.pe_stomp_config.is_some());
    assert!(!report.hollowing_configs.is_empty());
    assert!(!report.reflective_configs.is_empty());
    assert!(report.estimated_av_evasion_score > 50.0);

    for enc in &report.encrypted_strings {
        let decrypted: Vec<u8> = enc
            .encrypted_bytes
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ enc.key[i % enc.key.len()])
            .collect();
        assert_eq!(decrypted, enc.original.as_bytes());
    }
}
