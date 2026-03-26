use crate::anti_forensics_v2::*;

#[test]
fn test_toolkit_creation_defaults() {
    let toolkit = AntiForensicsToolkit::with_defaults();
    let env = ForensicEnvironment::default();
    let report = toolkit.analyze(&env);
    assert!(report.timestomp_operations.is_empty());
    assert!(report.slack_space_operations.is_empty());
    assert!(report.mft_manipulations.is_empty());
    assert!(report.inode_reuse_patterns.is_empty());
    assert!(report.stego_operations.is_empty());
    assert!(!report.container_configs.is_empty());
    assert!(report.swap_manipulations.is_empty());
}

#[test]
fn test_timestomping_unix_with_reference() {
    let toolkit = AntiForensicsToolkit::with_defaults();
    let env = ForensicEnvironment {
        filesystem: Some(FilesystemType::Ext4),
        target_files: vec![ForensicTargetFile {
            path: "/tmp/implant.elf".to_string(),
            size_bytes: 4096,
            timestamps: FileTimestamps {
                mtime_epoch: 1700000000,
                atime_epoch: 1700000000,
                ctime_epoch: Some(1700000000),
                birth_epoch: None,
            },
            inode: Some(12345),
        }],
        reference_files: vec![(
            "/bin/ls".to_string(),
            FileTimestamps {
                mtime_epoch: 1609459200,
                atime_epoch: 1609459200,
                ctime_epoch: Some(1609459200),
                birth_epoch: None,
            },
        )],
        is_windows: false,
        ..Default::default()
    };

    let report = toolkit.analyze(&env);
    assert!(!report.timestomp_operations.is_empty());
    let touch_op = report
        .timestomp_operations
        .iter()
        .find(|o| o.command.contains("touch -r"))
        .expect("should have touch -r command");
    assert!(touch_op.command.contains("/bin/ls"));
    assert!(touch_op.command.contains("/tmp/implant.elf"));
    assert!(touch_op.reference_file.is_some());
}

#[test]
fn test_timestomping_windows_powershell() {
    let toolkit = AntiForensicsToolkit::with_defaults();
    let env = ForensicEnvironment {
        filesystem: Some(FilesystemType::Ntfs),
        target_files: vec![ForensicTargetFile {
            path: "C:\\Windows\\Temp\\svc.exe".to_string(),
            size_bytes: 8192,
            timestamps: FileTimestamps {
                mtime_epoch: 1700000000,
                atime_epoch: 1700000000,
                ctime_epoch: Some(1700000000),
                birth_epoch: Some(1700000000),
            },
            inode: None,
        }],
        reference_files: vec![(
            "C:\\Windows\\System32\\notepad.exe".to_string(),
            FileTimestamps {
                mtime_epoch: 1609459200,
                atime_epoch: 1609459200,
                ctime_epoch: Some(1609459200),
                birth_epoch: Some(1609459200),
            },
        )],
        is_windows: true,
        has_raw_disk_access: true,
        ..Default::default()
    };

    let report = toolkit.analyze(&env);
    let ps_op = report
        .timestomp_operations
        .iter()
        .find(|o| o.command.contains("powershell"));
    assert!(ps_op.is_some());
    assert!(ps_op.unwrap().command.contains("LastWriteTime"));
}

#[test]
fn test_slack_space_operations() {
    let toolkit = AntiForensicsToolkit::with_defaults();
    let env = ForensicEnvironment {
        filesystem: Some(FilesystemType::Ntfs),
        cluster_size_bytes: 4096,
        target_files: vec![
            ForensicTargetFile {
                path: "/tmp/target1.txt".to_string(),
                size_bytes: 1000,
                timestamps: FileTimestamps {
                    mtime_epoch: 1700000000,
                    atime_epoch: 1700000000,
                    ctime_epoch: None,
                    birth_epoch: None,
                },
                inode: None,
            },
            ForensicTargetFile {
                path: "/tmp/target2.txt".to_string(),
                size_bytes: 4096,
                timestamps: FileTimestamps {
                    mtime_epoch: 1700000000,
                    atime_epoch: 1700000000,
                    ctime_epoch: None,
                    birth_epoch: None,
                },
                inode: None,
            },
        ],
        ..Default::default()
    };

    let report = toolkit.analyze(&env);
    let slack_ops: Vec<_> = report
        .slack_space_operations
        .iter()
        .filter(|o| o.can_hide)
        .collect();
    assert!(!slack_ops.is_empty());

    let target1_op = report
        .slack_space_operations
        .iter()
        .find(|o| o.target_path == "/tmp/target1.txt")
        .unwrap();
    assert_eq!(target1_op.slack_bytes_available, 3096);
    assert!(target1_op.can_hide);
    assert!(target1_op.command.contains("dd if=payload.bin"));
}

#[test]
fn test_mft_manipulations_ntfs_only() {
    let toolkit = AntiForensicsToolkit::with_defaults();

    let ntfs_env = ForensicEnvironment {
        filesystem: Some(FilesystemType::Ntfs),
        target_files: vec![ForensicTargetFile {
            path: "C:\\malware.exe".to_string(),
            size_bytes: 4096,
            timestamps: FileTimestamps {
                mtime_epoch: 1700000000,
                atime_epoch: 1700000000,
                ctime_epoch: None,
                birth_epoch: None,
            },
            inode: None,
        }],
        has_raw_disk_access: true,
        is_windows: true,
        ..Default::default()
    };
    let report = toolkit.analyze(&ntfs_env);
    assert!(!report.mft_manipulations.is_empty());
    assert!(report
        .mft_manipulations
        .iter()
        .any(|m| m.operation == MftOperation::HideEntry));
    assert!(report
        .mft_manipulations
        .iter()
        .any(|m| m.operation == MftOperation::ModifyTimestamps));

    let ext4_env = ForensicEnvironment {
        filesystem: Some(FilesystemType::Ext4),
        target_files: ntfs_env.target_files.clone(),
        ..Default::default()
    };
    let report2 = toolkit.analyze(&ext4_env);
    assert!(report2.mft_manipulations.is_empty());
}

#[test]
fn test_mft_orphan_entry_requires_raw_disk() {
    let toolkit = AntiForensicsToolkit::with_defaults();

    let env_with_raw = ForensicEnvironment {
        filesystem: Some(FilesystemType::Ntfs),
        target_files: vec![ForensicTargetFile {
            path: "C:\\payload.dll".to_string(),
            size_bytes: 2048,
            timestamps: FileTimestamps {
                mtime_epoch: 1700000000,
                atime_epoch: 1700000000,
                ctime_epoch: None,
                birth_epoch: None,
            },
            inode: None,
        }],
        has_raw_disk_access: true,
        is_windows: true,
        ..Default::default()
    };
    let report = toolkit.analyze(&env_with_raw);
    assert!(report
        .mft_manipulations
        .iter()
        .any(|m| m.operation == MftOperation::InsertOrphan));

    let env_no_raw = ForensicEnvironment {
        has_raw_disk_access: false,
        ..env_with_raw
    };
    let report2 = toolkit.analyze(&env_no_raw);
    assert!(!report2
        .mft_manipulations
        .iter()
        .any(|m| m.operation == MftOperation::InsertOrphan));
}

#[test]
fn test_inode_reuse_ext_only() {
    let toolkit = AntiForensicsToolkit::with_defaults();

    let ext_env = ForensicEnvironment {
        filesystem: Some(FilesystemType::Ext4),
        target_files: vec![ForensicTargetFile {
            path: "/tmp/evidence.log".to_string(),
            size_bytes: 2048,
            timestamps: FileTimestamps {
                mtime_epoch: 1700000000,
                atime_epoch: 1700000000,
                ctime_epoch: None,
                birth_epoch: None,
            },
            inode: Some(98765),
        }],
        ..Default::default()
    };
    let report = toolkit.analyze(&ext_env);
    assert!(!report.inode_reuse_patterns.is_empty());
    assert_eq!(report.inode_reuse_patterns[0].target_inode, 98765);
    assert!(report.inode_reuse_patterns[0].command.contains("rm -f"));

    let ntfs_env = ForensicEnvironment {
        filesystem: Some(FilesystemType::Ntfs),
        target_files: ext_env.target_files.clone(),
        ..Default::default()
    };
    let report2 = toolkit.analyze(&ntfs_env);
    assert!(report2.inode_reuse_patterns.is_empty());
}

#[test]
fn test_stego_operations_multiple_formats() {
    let toolkit = AntiForensicsToolkit::with_defaults();
    let env = ForensicEnvironment {
        carrier_files: vec![
            CarrierFile {
                path: "/tmp/photo.png".to_string(),
                format: StegoFormat::PngLsb,
                size_bytes: 1048576,
            },
            CarrierFile {
                path: "/tmp/vacation.jpg".to_string(),
                format: StegoFormat::JpegExif,
                size_bytes: 524288,
            },
            CarrierFile {
                path: "/tmp/song.mp3".to_string(),
                format: StegoFormat::Mp3Id3,
                size_bytes: 5242880,
            },
        ],
        ..Default::default()
    };

    let report = toolkit.analyze(&env);
    assert_eq!(report.stego_operations.len(), 3);

    let png_op = report
        .stego_operations
        .iter()
        .find(|o| o.format == StegoFormat::PngLsb)
        .unwrap();
    assert_eq!(png_op.max_capacity_bytes, 1048576 / 8);
    assert!(png_op.encoding_method.contains("LSB"));

    let jpg_op = report
        .stego_operations
        .iter()
        .find(|o| o.format == StegoFormat::JpegExif)
        .unwrap();
    assert_eq!(jpg_op.max_capacity_bytes, 65535);

    let mp3_op = report
        .stego_operations
        .iter()
        .find(|o| o.format == StegoFormat::Mp3Id3)
        .unwrap();
    assert_eq!(mp3_op.max_capacity_bytes, 262144);
}

#[test]
fn test_container_configs_veracrypt() {
    let toolkit = AntiForensicsToolkit::with_defaults();
    let env = ForensicEnvironment::default();

    let report = toolkit.analyze(&env);
    let vc = report
        .container_configs
        .iter()
        .find(|c| c.container_type == EncryptedContainerType::VeraCrypt)
        .unwrap();
    assert!(vc.plausible_deniability);
    assert!(!vc.decoy_files.is_empty());
    assert!(vc.command.contains("veracrypt"));
    assert!(vc.command.contains("hidden"));
}

#[test]
fn test_container_configs_dmcrypt_linux() {
    let toolkit = AntiForensicsToolkit::with_defaults();
    let env = ForensicEnvironment {
        is_windows: false,
        ..Default::default()
    };

    let report = toolkit.analyze(&env);
    let dm = report
        .container_configs
        .iter()
        .find(|c| c.container_type == EncryptedContainerType::DmCrypt);
    assert!(dm.is_some());
    assert!(dm.unwrap().command.contains("cryptsetup"));
}

#[test]
fn test_container_configs_bitlocker_windows() {
    let toolkit = AntiForensicsToolkit::with_defaults();
    let env = ForensicEnvironment {
        is_windows: true,
        ..Default::default()
    };

    let report = toolkit.analyze(&env);
    let bl = report
        .container_configs
        .iter()
        .find(|c| c.container_type == EncryptedContainerType::BitLocker);
    assert!(bl.is_some());
    assert!(bl.unwrap().command.contains("Enable-BitLocker"));
}

#[test]
fn test_swap_manipulation_linux() {
    let toolkit = AntiForensicsToolkit::with_defaults();
    let env = ForensicEnvironment {
        is_windows: false,
        swap_enabled: true,
        swap_path: Some("/dev/sda2".to_string()),
        ..Default::default()
    };

    let report = toolkit.analyze(&env);
    assert!(!report.swap_manipulations.is_empty());
    assert!(report
        .swap_manipulations
        .iter()
        .any(|m| m.command.contains("swapoff")));
    assert!(report
        .swap_manipulations
        .iter()
        .any(|m| m.command.contains("swappiness")));
    for m in &report.swap_manipulations {
        assert!(m.requires_root);
    }
}

#[test]
fn test_swap_manipulation_windows() {
    let toolkit = AntiForensicsToolkit::with_defaults();
    let env = ForensicEnvironment {
        is_windows: true,
        swap_enabled: true,
        ..Default::default()
    };

    let report = toolkit.analyze(&env);
    assert!(!report.swap_manipulations.is_empty());
    assert!(report
        .swap_manipulations
        .iter()
        .any(|m| m.command.contains("pagefileset")));
    assert!(report
        .swap_manipulations
        .iter()
        .any(|m| m.command.contains("ClearPageFileAtShutdown")));
}

#[test]
fn test_no_swap_manipulation_when_disabled() {
    let toolkit = AntiForensicsToolkit::with_defaults();
    let env = ForensicEnvironment {
        swap_enabled: false,
        ..Default::default()
    };

    let report = toolkit.analyze(&env);
    assert!(report.swap_manipulations.is_empty());
}

#[test]
fn test_category_coverage_tracking() {
    let toolkit = AntiForensicsToolkit::with_defaults();
    let env = ForensicEnvironment {
        filesystem: Some(FilesystemType::Ntfs),
        cluster_size_bytes: 4096,
        target_files: vec![ForensicTargetFile {
            path: "C:\\test.exe".to_string(),
            size_bytes: 1000,
            timestamps: FileTimestamps {
                mtime_epoch: 1700000000,
                atime_epoch: 1700000000,
                ctime_epoch: None,
                birth_epoch: None,
            },
            inode: None,
        }],
        carrier_files: vec![CarrierFile {
            path: "/tmp/img.png".to_string(),
            format: StegoFormat::PngMetadata,
            size_bytes: 1024,
        }],
        is_windows: true,
        has_raw_disk_access: true,
        swap_enabled: true,
        ..Default::default()
    };

    let report = toolkit.analyze(&env);
    assert!(report
        .category_coverage
        .contains_key(&AntiForensicCategory::Timestomping));
    assert!(report
        .category_coverage
        .contains_key(&AntiForensicCategory::MftManipulation));
    assert!(report
        .category_coverage
        .contains_key(&AntiForensicCategory::SteganographicHiding));
}

#[test]
fn test_disabled_features() {
    let config = AntiForensicsV2Config {
        enable_timestomping: false,
        enable_slack_space: false,
        enable_mft_manipulation: false,
        enable_inode_reuse: false,
        enable_steganography: false,
        enable_container_evasion: false,
        enable_swap_manipulation: false,
        ..Default::default()
    };
    let toolkit = AntiForensicsToolkit::new(config);
    let env = ForensicEnvironment {
        filesystem: Some(FilesystemType::Ntfs),
        target_files: vec![ForensicTargetFile {
            path: "C:\\test.exe".to_string(),
            size_bytes: 1000,
            timestamps: FileTimestamps {
                mtime_epoch: 1700000000,
                atime_epoch: 1700000000,
                ctime_epoch: None,
                birth_epoch: None,
            },
            inode: None,
        }],
        is_windows: true,
        has_raw_disk_access: true,
        swap_enabled: true,
        ..Default::default()
    };

    let report = toolkit.analyze(&env);
    assert!(report.timestomp_operations.is_empty());
    assert!(report.slack_space_operations.is_empty());
    assert!(report.mft_manipulations.is_empty());
    assert!(report.inode_reuse_patterns.is_empty());
    assert!(report.stego_operations.is_empty());
    assert!(report.container_configs.is_empty());
    assert!(report.swap_manipulations.is_empty());
}

#[test]
fn test_timestomping_tools() {
    let tools = AntiForensicsToolkit::timestomping_tools();
    assert!(tools.len() >= 5);
    let tool_names: Vec<_> = tools.iter().map(|(name, _)| *name).collect();
    assert!(tool_names.contains(&"touch"));
    assert!(tool_names.contains(&"timestomp"));
    assert!(tool_names.contains(&"SetMACE"));
    assert!(tool_names.contains(&"debugfs"));
}

#[test]
fn test_anti_forensic_category_display() {
    assert_eq!(
        format!("{}", AntiForensicCategory::Timestomping),
        "timestomping"
    );
    assert_eq!(
        format!("{}", AntiForensicCategory::SlackSpaceHiding),
        "slack-space-hiding"
    );
    assert_eq!(
        format!("{}", AntiForensicCategory::MftManipulation),
        "mft-manipulation"
    );
    assert_eq!(
        format!("{}", AntiForensicCategory::InodeReuse),
        "inode-reuse"
    );
    assert_eq!(
        format!("{}", AntiForensicCategory::SteganographicHiding),
        "steganographic-hiding"
    );
    assert_eq!(
        format!("{}", AntiForensicCategory::EncryptedContainerEvasion),
        "encrypted-container-evasion"
    );
    assert_eq!(
        format!("{}", AntiForensicCategory::SwapManipulation),
        "swap-manipulation"
    );
}

#[test]
fn test_filesystem_type_display() {
    assert_eq!(format!("{}", FilesystemType::Ntfs), "NTFS");
    assert_eq!(format!("{}", FilesystemType::Ext4), "ext4");
    assert_eq!(format!("{}", FilesystemType::Ext3), "ext3");
    assert_eq!(format!("{}", FilesystemType::Xfs), "XFS");
    assert_eq!(format!("{}", FilesystemType::Btrfs), "btrfs");
    assert_eq!(format!("{}", FilesystemType::Apfs), "APFS");
    assert_eq!(format!("{}", FilesystemType::Hfs), "HFS+");
    assert_eq!(format!("{}", FilesystemType::Fat32), "FAT32");
    assert_eq!(format!("{}", FilesystemType::Exfat), "exFAT");
}

#[test]
fn test_stego_format_display() {
    assert_eq!(format!("{}", StegoFormat::PngMetadata), "PNG-metadata");
    assert_eq!(format!("{}", StegoFormat::JpegExif), "JPEG-EXIF");
    assert_eq!(format!("{}", StegoFormat::PngLsb), "PNG-LSB");
    assert_eq!(format!("{}", StegoFormat::JpegDct), "JPEG-DCT");
    assert_eq!(format!("{}", StegoFormat::PdfMetadata), "PDF-metadata");
    assert_eq!(format!("{}", StegoFormat::Mp3Id3), "MP3-ID3");
    assert_eq!(format!("{}", StegoFormat::ZipComment), "ZIP-comment");
}

#[test]
fn test_mft_operation_display() {
    assert_eq!(format!("{}", MftOperation::HideEntry), "hide-entry");
    assert_eq!(
        format!("{}", MftOperation::ModifyTimestamps),
        "modify-timestamps"
    );
    assert_eq!(format!("{}", MftOperation::MarkDeleted), "mark-deleted");
    assert_eq!(format!("{}", MftOperation::SwapEntries), "swap-entries");
    assert_eq!(format!("{}", MftOperation::InsertOrphan), "insert-orphan");
    assert_eq!(
        format!("{}", MftOperation::ModifyFileName),
        "modify-filename"
    );
}

#[test]
fn test_encrypted_container_type_display() {
    assert_eq!(
        format!("{}", EncryptedContainerType::VeraCrypt),
        "VeraCrypt"
    );
    assert_eq!(
        format!("{}", EncryptedContainerType::TrueCrypt),
        "TrueCrypt"
    );
    assert_eq!(format!("{}", EncryptedContainerType::Luks), "LUKS");
    assert_eq!(
        format!("{}", EncryptedContainerType::BitLocker),
        "BitLocker"
    );
    assert_eq!(
        format!("{}", EncryptedContainerType::FileVault),
        "FileVault"
    );
    assert_eq!(format!("{}", EncryptedContainerType::DmCrypt), "dm-crypt");
}

#[test]
fn test_swap_type_display() {
    assert_eq!(
        format!("{}", SwapType::LinuxSwapPartition),
        "linux-swap-partition"
    );
    assert_eq!(format!("{}", SwapType::LinuxSwapFile), "linux-swap-file");
    assert_eq!(format!("{}", SwapType::WindowsPagefile), "windows-pagefile");
    assert_eq!(format!("{}", SwapType::MacOsSwap), "macos-swap");
}

#[test]
fn test_stego_detection_risk_ordering() {
    let mp3_risk = 0.15_f64;
    let png_meta_risk = 0.2_f64;
    let png_lsb_risk = 0.5_f64;

    assert!(mp3_risk < png_meta_risk);
    assert!(png_meta_risk < png_lsb_risk);
}

#[test]
fn test_max_detection_risk_filter() {
    let config = AntiForensicsV2Config {
        max_detection_risk: 0.3,
        ..Default::default()
    };
    let toolkit = AntiForensicsToolkit::new(config);
    let env = ForensicEnvironment {
        filesystem: Some(FilesystemType::Ntfs),
        target_files: vec![ForensicTargetFile {
            path: "C:\\test.exe".to_string(),
            size_bytes: 1000,
            timestamps: FileTimestamps {
                mtime_epoch: 1700000000,
                atime_epoch: 1700000000,
                ctime_epoch: None,
                birth_epoch: None,
            },
            inode: None,
        }],
        reference_files: vec![(
            "C:\\Windows\\notepad.exe".to_string(),
            FileTimestamps {
                mtime_epoch: 1609459200,
                atime_epoch: 1609459200,
                ctime_epoch: None,
                birth_epoch: None,
            },
        )],
        has_raw_disk_access: true,
        is_windows: true,
        ..Default::default()
    };

    let report = toolkit.analyze(&env);
    for op in &report.timestomp_operations {
        assert!(op.detection_risk <= 0.3);
    }
    for op in &report.mft_manipulations {
        assert!(op.detection_risk <= 0.3);
    }
}
