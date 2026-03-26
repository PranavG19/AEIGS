use crate::log_evasion::*;

#[test]
fn test_log_evasion_engine_creation() {
    let engine = LogEvasionEngine::with_defaults();
    let env = LogEnvironment::default();
    let report = engine.analyze(&env);
    assert!(report.injection_payloads.is_empty());
    assert!(report.login_records.is_empty());
    assert!(report.sysmon_evasions.is_empty());
    assert!(report.event_log_commands.is_empty());
    assert!(!report.history_commands.is_empty());
}

#[test]
fn test_log_injection_payloads_for_writable_logs() {
    let engine = LogEvasionEngine::with_defaults();
    let env = LogEnvironment {
        detected_systems: vec![LoggingSystem::Syslog],
        log_files: vec![
            LogFilePath {
                path: "/var/log/syslog".to_string(),
                logging_system: LoggingSystem::Syslog,
                writable: true,
                size_bytes: 1024000,
                rotation_config: None,
            },
            LogFilePath {
                path: "/var/log/auth.log".to_string(),
                logging_system: LoggingSystem::Syslog,
                writable: false,
                size_bytes: 512000,
                rotation_config: None,
            },
        ],
        ..Default::default()
    };

    let report = engine.analyze(&env);
    assert!(!report.injection_payloads.is_empty());
    for payload in &report.injection_payloads {
        if payload.payload.contains(">>") {
            assert!(payload.payload.contains("/var/log/syslog"));
            assert!(!payload.payload.contains("/var/log/auth.log"));
        }
    }
}

#[test]
fn test_syslog_logger_injection() {
    let engine = LogEvasionEngine::with_defaults();
    let env = LogEnvironment {
        detected_systems: vec![LoggingSystem::Syslog, LoggingSystem::Rsyslog],
        log_files: vec![],
        ..Default::default()
    };

    let report = engine.analyze(&env);
    let logger_payloads: Vec<_> = report
        .injection_payloads
        .iter()
        .filter(|p| p.payload.contains("logger"))
        .collect();
    assert!(!logger_payloads.is_empty());
    assert!(logger_payloads[0].payload.contains("auth.info"));
}

#[test]
fn test_rotation_exploit_generation() {
    let engine = LogEvasionEngine::with_defaults();
    let env = LogEnvironment {
        log_files: vec![LogFilePath {
            path: "/var/log/syslog".to_string(),
            logging_system: LoggingSystem::Syslog,
            writable: true,
            size_bytes: 500000,
            rotation_config: Some(RotationConfig {
                max_size_bytes: 1048576,
                max_files: 5,
                compress_on_rotate: true,
                rotation_schedule: "daily".to_string(),
            }),
        }],
        ..Default::default()
    };

    let report = engine.analyze(&env);
    assert!(!report.rotation_exploits.is_empty());
    let has_race_condition = report
        .rotation_exploits
        .iter()
        .any(|e| e.payload.contains("inotifywait"));
    assert!(has_race_condition);
}

#[test]
fn test_rotation_force_fill_exploit() {
    let engine = LogEvasionEngine::with_defaults();
    let env = LogEnvironment {
        log_files: vec![LogFilePath {
            path: "/var/log/messages".to_string(),
            logging_system: LoggingSystem::Syslog,
            writable: true,
            size_bytes: 100000,
            rotation_config: Some(RotationConfig {
                max_size_bytes: 2097152,
                max_files: 3,
                compress_on_rotate: false,
                rotation_schedule: "weekly".to_string(),
            }),
        }],
        ..Default::default()
    };

    let report = engine.analyze(&env);
    let has_dd_fill = report
        .rotation_exploits
        .iter()
        .any(|e| e.payload.contains("dd if="));
    assert!(has_dd_fill);
}

#[test]
fn test_utmp_wtmp_record_collection() {
    let engine = LogEvasionEngine::with_defaults();
    let env = LogEnvironment {
        utmp_records: vec![LoginRecord {
            record_type: LoginRecordType::UserLogin,
            username: "attacker".to_string(),
            terminal: "pts/0".to_string(),
            host: "10.0.0.5".to_string(),
            timestamp_epoch: 1700000000,
        }],
        wtmp_records: vec![
            LoginRecord {
                record_type: LoginRecordType::UserLogin,
                username: "attacker".to_string(),
                terminal: "pts/1".to_string(),
                host: "10.0.0.5".to_string(),
                timestamp_epoch: 1699999000,
            },
            LoginRecord {
                record_type: LoginRecordType::UserLogout,
                username: "attacker".to_string(),
                terminal: "pts/1".to_string(),
                host: "10.0.0.5".to_string(),
                timestamp_epoch: 1699999500,
            },
        ],
        ..Default::default()
    };

    let report = engine.analyze(&env);
    assert_eq!(report.login_records.len(), 3);
}

#[test]
fn test_sysmon_evasion_strategies() {
    let engine = LogEvasionEngine::with_defaults();
    let env = LogEnvironment {
        is_windows: true,
        sysmon_config: Some(SysmonConfig {
            version: "15.0".to_string(),
            monitored_events: vec![
                SysmonEventId::ProcessCreate,
                SysmonEventId::NetworkConnect,
                SysmonEventId::CreateRemoteThread,
                SysmonEventId::DnsQuery,
            ],
            excluded_processes: vec!["chrome.exe".to_string()],
            excluded_ips: vec!["10.0.0.0/8".to_string()],
            hash_algorithms: vec!["SHA256".to_string()],
        }),
        ..Default::default()
    };

    let report = engine.analyze(&env);
    assert!(!report.sysmon_evasions.is_empty());
    let event_ids: Vec<_> = report.sysmon_evasions.iter().map(|e| e.event_id).collect();
    assert!(event_ids.contains(&SysmonEventId::ProcessCreate));
    assert!(event_ids.contains(&SysmonEventId::NetworkConnect));
    assert!(event_ids.contains(&SysmonEventId::CreateRemoteThread));
    assert!(event_ids.contains(&SysmonEventId::DnsQuery));
    for evasion in &report.sysmon_evasions {
        assert!(evasion.alternative_api.is_some());
    }
}

#[test]
fn test_no_sysmon_evasion_without_config() {
    let engine = LogEvasionEngine::with_defaults();
    let env = LogEnvironment {
        is_windows: true,
        sysmon_config: None,
        ..Default::default()
    };

    let report = engine.analyze(&env);
    assert!(report.sysmon_evasions.is_empty());
}

#[test]
fn test_windows_event_log_commands() {
    let engine = LogEvasionEngine::with_defaults();
    let env = LogEnvironment {
        is_windows: true,
        ..Default::default()
    };

    let report = engine.analyze(&env);
    assert!(!report.event_log_commands.is_empty());

    let wevtutil_commands: Vec<_> = report
        .event_log_commands
        .iter()
        .filter(|c| c.command.contains("wevtutil"))
        .collect();
    assert!(!wevtutil_commands.is_empty());

    let powershell_commands: Vec<_> = report
        .event_log_commands
        .iter()
        .filter(|c| c.command.contains("powershell"))
        .collect();
    assert!(!powershell_commands.is_empty());

    for cmd in &report.event_log_commands {
        assert!(cmd.requires_admin);
    }
}

#[test]
fn test_no_event_log_commands_on_linux() {
    let engine = LogEvasionEngine::with_defaults();
    let env = LogEnvironment {
        is_windows: false,
        ..Default::default()
    };

    let report = engine.analyze(&env);
    assert!(report.event_log_commands.is_empty());
}

#[test]
fn test_history_evasion_commands() {
    let engine = LogEvasionEngine::with_defaults();
    let env = LogEnvironment::default();

    let report = engine.analyze(&env);
    assert!(report.history_commands.len() >= 8);
    assert!(report
        .history_commands
        .contains(&"unset HISTFILE".to_string()));
    assert!(report
        .history_commands
        .contains(&"export HISTSIZE=0".to_string()));
    assert!(report
        .history_commands
        .contains(&"set +o history".to_string()));
}

#[test]
fn test_utmp_manipulation_commands() {
    let commands = LogEvasionEngine::utmp_wtmp_manipulation_commands("hacker");
    assert!(commands.len() >= 4);
    for cmd in &commands {
        assert!(cmd.contains("hacker"));
    }
    assert!(commands.iter().any(|c| c.contains("utmpdump")));
}

#[test]
fn test_auditd_evasion_commands() {
    let commands = LogEvasionEngine::auditd_evasion_commands();
    assert!(!commands.is_empty());
    assert!(commands.iter().any(|c| c.contains("auditctl -e 0")));
    assert!(commands.iter().any(|c| c.contains("auditctl -D")));
}

#[test]
fn test_debian_log_paths() {
    let paths = LogEvasionEngine::log_paths_for_distro(LinuxDistro::Debian);
    let path_strs: Vec<_> = paths.iter().map(|(p, _)| *p).collect();
    assert!(path_strs.contains(&"/var/log/syslog"));
    assert!(path_strs.contains(&"/var/log/auth.log"));
    assert!(path_strs.contains(&"/var/log/wtmp"));
}

#[test]
fn test_redhat_log_paths() {
    let paths = LogEvasionEngine::log_paths_for_distro(LinuxDistro::RedHat);
    let path_strs: Vec<_> = paths.iter().map(|(p, _)| *p).collect();
    assert!(path_strs.contains(&"/var/log/messages"));
    assert!(path_strs.contains(&"/var/log/secure"));
    assert!(path_strs.contains(&"/var/log/audit/audit.log"));
}

#[test]
fn test_windows_event_channels() {
    let channels = LogEvasionEngine::windows_event_channels();
    assert!(channels.len() >= 8);
    assert!(channels.contains(&"Security"));
    assert!(channels.contains(&"System"));
    assert!(channels.contains(&"Application"));
    assert!(channels.iter().any(|c| c.contains("Sysmon")));
}

#[test]
fn test_sysmon_monitored_apis() {
    let apis = LogEvasionEngine::sysmon_monitored_apis();
    assert!(!apis.is_empty());
    let api_names: Vec<_> = apis.iter().map(|(name, _, _)| *name).collect();
    assert!(api_names.iter().any(|n| n.contains("CreateProcess")));
    assert!(api_names.iter().any(|n| n.contains("CreateRemoteThread")));
}

#[test]
fn test_technique_coverage_tracking() {
    let engine = LogEvasionEngine::with_defaults();
    let env = LogEnvironment {
        detected_systems: vec![LoggingSystem::Syslog],
        log_files: vec![LogFilePath {
            path: "/var/log/syslog".to_string(),
            logging_system: LoggingSystem::Syslog,
            writable: true,
            size_bytes: 100000,
            rotation_config: Some(RotationConfig {
                max_size_bytes: 1048576,
                max_files: 5,
                compress_on_rotate: true,
                rotation_schedule: "daily".to_string(),
            }),
        }],
        is_windows: true,
        sysmon_config: Some(SysmonConfig {
            version: "15.0".to_string(),
            monitored_events: vec![SysmonEventId::ProcessCreate],
            excluded_processes: vec![],
            excluded_ips: vec![],
            hash_algorithms: vec![],
        }),
        utmp_records: vec![LoginRecord {
            record_type: LoginRecordType::UserLogin,
            username: "test".to_string(),
            terminal: "pts/0".to_string(),
            host: "127.0.0.1".to_string(),
            timestamp_epoch: 1700000000,
        }],
        ..Default::default()
    };

    let report = engine.analyze(&env);
    assert!(report
        .technique_coverage
        .contains_key(&LogEvasionMethod::LogInjection));
    assert!(report
        .technique_coverage
        .contains_key(&LogEvasionMethod::HistoryManipulation));
    assert!(report
        .technique_coverage
        .contains_key(&LogEvasionMethod::SysmonEvasion));
}

#[test]
fn test_max_detection_risk_filter() {
    let config = LogEvasionConfig {
        max_detection_risk: 0.25,
        ..Default::default()
    };
    let engine = LogEvasionEngine::new(config);
    let env = LogEnvironment {
        detected_systems: vec![LoggingSystem::Syslog],
        log_files: vec![LogFilePath {
            path: "/var/log/syslog".to_string(),
            logging_system: LoggingSystem::Syslog,
            writable: true,
            size_bytes: 100000,
            rotation_config: None,
        }],
        ..Default::default()
    };

    let report = engine.analyze(&env);
    for payload in &report.injection_payloads {
        assert!(payload.detection_risk <= 0.25);
    }
}

#[test]
fn test_disabled_features_config() {
    let config = LogEvasionConfig {
        generate_injection_payloads: false,
        generate_rotation_exploits: false,
        generate_sysmon_evasions: false,
        generate_event_log_commands: false,
        generate_history_commands: false,
        ..Default::default()
    };
    let engine = LogEvasionEngine::new(config);
    let env = LogEnvironment {
        is_windows: true,
        detected_systems: vec![LoggingSystem::Syslog],
        log_files: vec![LogFilePath {
            path: "/var/log/syslog".to_string(),
            logging_system: LoggingSystem::Syslog,
            writable: true,
            size_bytes: 100000,
            rotation_config: None,
        }],
        sysmon_config: Some(SysmonConfig {
            version: "15.0".to_string(),
            monitored_events: vec![SysmonEventId::ProcessCreate],
            excluded_processes: vec![],
            excluded_ips: vec![],
            hash_algorithms: vec![],
        }),
        ..Default::default()
    };

    let report = engine.analyze(&env);
    assert!(report.injection_payloads.is_empty());
    assert!(report.rotation_exploits.is_empty());
    assert!(report.sysmon_evasions.is_empty());
    assert!(report.event_log_commands.is_empty());
    assert!(report.history_commands.is_empty());
}

#[test]
fn test_logging_system_display() {
    assert_eq!(format!("{}", LoggingSystem::Syslog), "syslog");
    assert_eq!(format!("{}", LoggingSystem::Journald), "journald");
    assert_eq!(format!("{}", LoggingSystem::Auditd), "auditd");
    assert_eq!(format!("{}", LoggingSystem::Rsyslog), "rsyslog");
    assert_eq!(format!("{}", LoggingSystem::SyslogNg), "syslog-ng");
    assert_eq!(
        format!("{}", LoggingSystem::WindowsEventLog),
        "windows-event-log"
    );
    assert_eq!(format!("{}", LoggingSystem::Sysmon), "sysmon");
    assert_eq!(format!("{}", LoggingSystem::Nxlog), "nxlog");
    assert_eq!(format!("{}", LoggingSystem::Fluentd), "fluentd");
    assert_eq!(format!("{}", LoggingSystem::Logrotate), "logrotate");
}

#[test]
fn test_linux_distro_display() {
    assert_eq!(format!("{}", LinuxDistro::Debian), "debian");
    assert_eq!(format!("{}", LinuxDistro::Ubuntu), "ubuntu");
    assert_eq!(format!("{}", LinuxDistro::RedHat), "redhat");
    assert_eq!(format!("{}", LinuxDistro::CentOS), "centos");
    assert_eq!(format!("{}", LinuxDistro::Fedora), "fedora");
    assert_eq!(format!("{}", LinuxDistro::Arch), "arch");
    assert_eq!(format!("{}", LinuxDistro::Alpine), "alpine");
    assert_eq!(format!("{}", LinuxDistro::Suse), "suse");
    assert_eq!(format!("{}", LinuxDistro::Gentoo), "gentoo");
    assert_eq!(format!("{}", LinuxDistro::Unknown), "unknown");
}

#[test]
fn test_log_evasion_technique_display() {
    assert_eq!(
        format!("{}", LogEvasionMethod::LogInjection),
        "log-injection"
    );
    assert_eq!(
        format!("{}", LogEvasionMethod::RotationExploit),
        "rotation-exploit"
    );
    assert_eq!(
        format!("{}", LogEvasionMethod::UtmpManipulation),
        "utmp-manipulation"
    );
    assert_eq!(
        format!("{}", LogEvasionMethod::EventLogClearing),
        "event-log-clearing"
    );
    assert_eq!(
        format!("{}", LogEvasionMethod::SysmonEvasion),
        "sysmon-evasion"
    );
}

#[test]
fn test_sysmon_event_id_display() {
    assert_eq!(
        format!("{}", SysmonEventId::ProcessCreate),
        "1:ProcessCreate"
    );
    assert_eq!(
        format!("{}", SysmonEventId::NetworkConnect),
        "3:NetworkConnect"
    );
    assert_eq!(
        format!("{}", SysmonEventId::CreateRemoteThread),
        "8:CreateRemoteThread"
    );
    assert_eq!(format!("{}", SysmonEventId::DnsQuery), "22:DnsQuery");
}

#[test]
fn test_login_record_type_display() {
    assert_eq!(format!("{}", LoginRecordType::UserLogin), "user-login");
    assert_eq!(format!("{}", LoginRecordType::UserLogout), "user-logout");
    assert_eq!(format!("{}", LoginRecordType::BootTime), "boot-time");
    assert_eq!(format!("{}", LoginRecordType::RunLevel), "run-level");
    assert_eq!(format!("{}", LoginRecordType::DeadProcess), "dead-process");
}
