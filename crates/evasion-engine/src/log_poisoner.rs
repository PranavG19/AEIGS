use std::fmt;

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// Target log format for decoy entry generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LogFormat {
    ApacheCombined,
    NginxAccess,
    SyslogRfc5424,
    WindowsEventXml,
}

impl fmt::Display for LogFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApacheCombined => write!(f, "apache-combined"),
            Self::NginxAccess => write!(f, "nginx-access"),
            Self::SyslogRfc5424 => write!(f, "syslog-rfc5424"),
            Self::WindowsEventXml => write!(f, "windows-event-xml"),
        }
    }
}

/// A single decoy log entry with fields common across formats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyEntry {
    pub timestamp: String,
    pub source_ip: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub user_agent: String,
}

/// Configuration for timeline confusion window generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineConfusionConfig {
    pub window_hours: f64,
    pub decoy_count_before: usize,
    pub decoy_count_after: usize,
}

impl Default for TimelineConfusionConfig {
    fn default() -> Self {
        Self {
            window_hours: 6.0,
            decoy_count_before: 5,
            decoy_count_after: 5,
        }
    }
}

const DECOY_METHODS: &[&str] = &["GET", "POST", "HEAD", "OPTIONS", "PUT"];

const DECOY_PATHS: &[&str] = &[
    "/",
    "/index.html",
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
    "/wp-login.php",
    "/api/v1/health",
    "/assets/style.css",
    "/images/logo.png",
    "/api/v2/users",
    "/login",
    "/about",
    "/contact",
    "/.well-known/security.txt",
    "/feed/rss",
];

const DECOY_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "curl/8.4.0",
    "python-requests/2.31.0",
];

const DECOY_STATUSES: &[u16] = &[200, 200, 200, 200, 301, 302, 304, 403, 404, 500];

const SYSLOG_APP_NAMES: &[&str] = &[
    "sshd", "nginx", "apache2", "cron", "systemd", "kernel", "postfix",
];

const SYSLOG_MESSAGES: &[&str] = &[
    "Connection closed by authenticating user admin",
    "Accepted publickey for deploy from 10.0.0.50 port 43210",
    "pam_unix(sshd:session): session opened for user www-data",
    "New session 4821 of user root",
    "Started Daily apt download activities",
    "UFW BLOCK IN=eth0 OUT= SRC=198.51.100.77 DST=10.0.0.1",
    "connect from unknown[203.0.113.45]",
];

const WINDOWS_EVENT_IDS: &[(u32, &str, &str)] = &[
    (4624, "Security", "An account was successfully logged on"),
    (4625, "Security", "An account failed to log on"),
    (
        4648,
        "Security",
        "A logon was attempted using explicit credentials",
    ),
    (7045, "System", "A service was installed in the system"),
    (1102, "Security", "The audit log was cleared"),
    (4688, "Security", "A new process has been created"),
    (4672, "Security", "Special privileges assigned to new logon"),
];

/// Log poisoning engine that generates realistic decoy log entries
/// across multiple formats to create timeline confusion and dilute
/// forensic evidence of actual scanning activity.
pub struct LogPoisoner {
    config: TimelineConfusionConfig,
    rng: StdRng,
}

impl LogPoisoner {
    pub fn new(config: TimelineConfusionConfig) -> Self {
        Self {
            config,
            rng: StdRng::from_os_rng(),
        }
    }

    pub fn with_seed(config: TimelineConfusionConfig, seed: u64) -> Self {
        Self {
            config,
            rng: StdRng::seed_from_u64(seed),
        }
    }

    /// Generates a random IP address from RFC 1918 private ranges
    /// or public-looking addresses for decoy entries.
    pub fn generate_decoy_ip(&mut self) -> String {
        let choice = self.rng.random_range(0..5_u8);
        match choice {
            0 => format!(
                "10.{}.{}.{}",
                self.rng.random_range(0..=255_u8),
                self.rng.random_range(1..=254_u8),
                self.rng.random_range(1..=254_u8)
            ),
            1 => format!(
                "172.{}.{}.{}",
                self.rng.random_range(16..=31_u8),
                self.rng.random_range(1..=254_u8),
                self.rng.random_range(1..=254_u8)
            ),
            2 => format!(
                "192.168.{}.{}",
                self.rng.random_range(0..=255_u8),
                self.rng.random_range(1..=254_u8)
            ),
            3 => format!(
                "{}.{}.{}.{}",
                self.rng.random_range(44..=223_u8),
                self.rng.random_range(1..=254_u8),
                self.rng.random_range(1..=254_u8),
                self.rng.random_range(1..=254_u8)
            ),
            _ => format!(
                "{}.{}.{}.{}",
                self.rng.random_range(100..=200_u8),
                self.rng.random_range(50..=200_u8),
                self.rng.random_range(1..=254_u8),
                self.rng.random_range(1..=254_u8)
            ),
        }
    }

    /// Generates a formatted log entry in the specified format with
    /// randomized fields. An optional timestamp override replaces
    /// the randomly generated timestamp.
    pub fn generate_entry(
        &mut self,
        format: LogFormat,
        timestamp_override: Option<String>,
    ) -> String {
        let entry = self.build_decoy_entry(timestamp_override);
        match format {
            LogFormat::ApacheCombined => self.generate_apache_combined(&entry),
            LogFormat::NginxAccess => self.generate_nginx_access(&entry),
            LogFormat::SyslogRfc5424 => self.generate_syslog_rfc5424(&entry),
            LogFormat::WindowsEventXml => self.generate_windows_event_xml(&entry),
        }
    }

    /// Formats a decoy entry as an Apache Combined Log Format line.
    pub fn generate_apache_combined(&self, entry: &DecoyEntry) -> String {
        let size = 200 + (entry.path.len() * 37) % 15000;
        format!(
            "{} - - [{}] \"{} {} HTTP/1.1\" {} {} \"-\" \"{}\"",
            entry.source_ip,
            entry.timestamp,
            entry.method,
            entry.path,
            entry.status,
            size,
            entry.user_agent,
        )
    }

    /// Formats a decoy entry as an Nginx access log line.
    pub fn generate_nginx_access(&self, entry: &DecoyEntry) -> String {
        let size = 150 + (entry.path.len() * 23) % 12000;
        let upstream_time = format!("{:.3}", (entry.status as f64 / 1000.0) + 0.001);
        format!(
            "{} - - [{}] \"{} {} HTTP/1.1\" {} {} \"-\" \"{}\" \"-\" {}",
            entry.source_ip,
            entry.timestamp,
            entry.method,
            entry.path,
            entry.status,
            size,
            entry.user_agent,
            upstream_time,
        )
    }

    /// Formats a decoy entry as an RFC 5424 syslog message.
    pub fn generate_syslog_rfc5424(&self, entry: &DecoyEntry) -> String {
        let app_idx = entry.source_ip.as_bytes().last().copied().unwrap_or(0) as usize
            % SYSLOG_APP_NAMES.len();
        let msg_idx = entry.status as usize % SYSLOG_MESSAGES.len();
        let app_name = SYSLOG_APP_NAMES[app_idx];
        let pid = 1000 + (entry.path.len() * 7) % 60000;
        let message = SYSLOG_MESSAGES[msg_idx];
        format!(
            "<{}>{} {} {} {} {} - - {}",
            34 + (entry.status as u32 % 8),
            1,
            entry.timestamp,
            "localhost",
            app_name,
            pid,
            message,
        )
    }

    /// Formats a decoy entry as a Windows Event XML structure.
    pub fn generate_windows_event_xml(&self, entry: &DecoyEntry) -> String {
        let event_idx = entry.status as usize % WINDOWS_EVENT_IDS.len();
        let (event_id, channel, message) = WINDOWS_EVENT_IDS[event_idx];
        let record_id = 10000 + (entry.path.len() * 31) % 999999;
        format!(
            "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
             <System>\
             <Provider Name=\"Microsoft-Windows-Security-Auditing\" />\
             <EventID>{event_id}</EventID>\
             <Level>0</Level>\
             <Channel>{channel}</Channel>\
             <Computer>WORKSTATION-{ip_suffix}</Computer>\
             <TimeCreated SystemTime=\"{timestamp}\" />\
             <EventRecordID>{record_id}</EventRecordID>\
             </System>\
             <EventData>\
             <Data Name=\"SubjectUserName\">SYSTEM</Data>\
             <Data Name=\"IpAddress\">{source_ip}</Data>\
             <Data Name=\"Message\">{message}</Data>\
             </EventData>\
             </Event>",
            event_id = event_id,
            channel = channel,
            ip_suffix = entry.source_ip.replace('.', ""),
            timestamp = entry.timestamp,
            record_id = record_id,
            source_ip = entry.source_ip,
            message = message,
        )
    }

    /// Creates a timeline confusion window around a real event timestamp.
    /// Generates decoy entries spread across the configured window,
    /// with `decoy_count_before` entries before and `decoy_count_after`
    /// entries after the real timestamp.
    pub fn create_confusion_window(
        &mut self,
        real_timestamp_ms: u64,
        format: LogFormat,
    ) -> Vec<String> {
        let window_ms = (self.config.window_hours * 3_600_000.0) as u64;
        let half_window = window_ms / 2;
        let mut entries =
            Vec::with_capacity(self.config.decoy_count_before + self.config.decoy_count_after);

        for i in 0..self.config.decoy_count_before {
            let spread = if self.config.decoy_count_before <= 1 {
                half_window
            } else {
                half_window * (self.config.decoy_count_before - i) as u64
                    / self.config.decoy_count_before as u64
            };
            let jitter = self.rng.random_range(0..=(spread / 4).max(1));
            let ts_ms = real_timestamp_ms
                .saturating_sub(spread)
                .saturating_add(jitter);
            let ts_str = self.format_timestamp_for_format(ts_ms, format);
            entries.push(self.generate_entry(format, Some(ts_str)));
        }

        for i in 0..self.config.decoy_count_after {
            let spread = if self.config.decoy_count_after <= 1 {
                half_window
            } else {
                half_window * (i + 1) as u64 / self.config.decoy_count_after as u64
            };
            let jitter = self.rng.random_range(0..=(spread / 4).max(1));
            let ts_ms = real_timestamp_ms
                .saturating_add(spread)
                .saturating_add(jitter);
            let ts_str = self.format_timestamp_for_format(ts_ms, format);
            entries.push(self.generate_entry(format, Some(ts_str)));
        }

        entries
    }

    fn build_decoy_entry(&mut self, timestamp_override: Option<String>) -> DecoyEntry {
        let timestamp = timestamp_override.unwrap_or_else(|| {
            let ts_ms = 1700000000000_u64 + self.rng.random_range(0..86_400_000_u64);
            self.format_timestamp_for_format(ts_ms, LogFormat::ApacheCombined)
        });

        let method_idx = self.rng.random_range(0..DECOY_METHODS.len());
        let path_idx = self.rng.random_range(0..DECOY_PATHS.len());
        let status_idx = self.rng.random_range(0..DECOY_STATUSES.len());
        let ua_idx = self.rng.random_range(0..DECOY_USER_AGENTS.len());

        DecoyEntry {
            timestamp,
            source_ip: self.generate_decoy_ip(),
            method: DECOY_METHODS[method_idx].to_string(),
            path: DECOY_PATHS[path_idx].to_string(),
            status: DECOY_STATUSES[status_idx],
            user_agent: DECOY_USER_AGENTS[ua_idx].to_string(),
        }
    }

    fn format_timestamp_for_format(&self, epoch_ms: u64, format: LogFormat) -> String {
        let secs = epoch_ms / 1000;
        let days_since_epoch = secs / 86400;
        let time_of_day = secs % 86400;
        let hours = time_of_day / 3600;
        let minutes = (time_of_day % 3600) / 60;
        let seconds = time_of_day % 60;

        let (year, month, day) = epoch_days_to_ymd(days_since_epoch);

        match format {
            LogFormat::ApacheCombined | LogFormat::NginxAccess => {
                let month_str = MONTH_ABBREVS[month as usize - 1];
                format!(
                    "{:02}/{}/{:04}:{:02}:{:02}:{:02} +0000",
                    day, month_str, year, hours, minutes, seconds
                )
            }
            LogFormat::SyslogRfc5424 => {
                let millis = epoch_ms % 1000;
                format!(
                    "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
                    year, month, day, hours, minutes, seconds, millis
                )
            }
            LogFormat::WindowsEventXml => {
                let millis = epoch_ms % 1000;
                format!(
                    "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
                    year, month, day, hours, minutes, seconds, millis
                )
            }
        }
    }
}

const MONTH_ABBREVS: &[&str] = &[
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn epoch_days_to_ymd(days: u64) -> (u64, u64, u64) {
    let mut y = 1970;
    let mut remaining = days;

    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }

    let leap = is_leap(y);
    let month_days: &[u64] = if leap {
        &[31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        &[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut m = 0;
    while m < 12 && remaining >= month_days[m] {
        remaining -= month_days[m];
        m += 1;
    }

    (y, m as u64 + 1, remaining + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
