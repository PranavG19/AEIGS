use regex::Regex;

use super::log_poisoner::*;

fn make_poisoner() -> LogPoisoner {
    LogPoisoner::with_seed(TimelineConfusionConfig::default(), 42)
}

#[test]
fn test_apache_combined_format_valid() {
    let mut poisoner = make_poisoner();
    let entry = poisoner.generate_entry(LogFormat::ApacheCombined, None);

    let re = Regex::new(
        r#"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} - - \[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} \+0000\] "(GET|POST|HEAD|OPTIONS|PUT) /[^\s]* HTTP/1\.1" \d{3} \d+ "-" ".+""#,
    ).unwrap();

    assert!(
        re.is_match(&entry),
        "Apache combined entry did not match expected format: {}",
        entry
    );
}

#[test]
fn test_nginx_format_valid() {
    let mut poisoner = make_poisoner();
    let entry = poisoner.generate_entry(LogFormat::NginxAccess, None);

    let re = Regex::new(
        r#"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} - - \[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} \+0000\] "(GET|POST|HEAD|OPTIONS|PUT) /[^\s]* HTTP/1\.1" \d{3} \d+ "-" ".+" "-" \d+\.\d+"#,
    ).unwrap();

    assert!(
        re.is_match(&entry),
        "Nginx access entry did not match expected format: {}",
        entry
    );
}

#[test]
fn test_syslog_rfc5424_format_valid() {
    let mut poisoner = make_poisoner();
    let entry = poisoner.generate_entry(LogFormat::SyslogRfc5424, None);

    let re = Regex::new(
        r"^<\d+>\d+ \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z localhost \w+ \d+ - - .+",
    )
    .unwrap();

    assert!(
        re.is_match(&entry),
        "Syslog RFC5424 entry did not match expected format: {}",
        entry
    );
}

#[test]
fn test_windows_event_xml_valid() {
    let mut poisoner = make_poisoner();
    let entry = poisoner.generate_entry(LogFormat::WindowsEventXml, None);

    assert!(entry
        .starts_with("<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">"));
    assert!(entry.ends_with("</Event>"));
    assert!(entry.contains("<EventID>"));
    assert!(entry.contains("</EventID>"));
    assert!(entry.contains("<System>"));
    assert!(entry.contains("</System>"));
    assert!(entry.contains("<EventData>"));
    assert!(entry.contains("</EventData>"));
    assert!(entry.contains("<TimeCreated SystemTime="));
    assert!(entry.contains("<Data Name=\"IpAddress\">"));
}

#[test]
fn test_timeline_confusion() {
    let mut poisoner = LogPoisoner::with_seed(
        TimelineConfusionConfig {
            window_hours: 4.0,
            decoy_count_before: 3,
            decoy_count_after: 3,
            ..Default::default()
        },
        99,
    );

    let real_ts = 1700000000000_u64;
    let entries = poisoner.create_confusion_window(real_ts, LogFormat::ApacheCombined);

    assert_eq!(entries.len(), 6);

    for entry in &entries {
        assert!(!entry.is_empty());
        assert!(entry.contains("HTTP/1.1"));
    }
}

#[test]
fn test_decoy_ips_varied() {
    let mut poisoner = make_poisoner();
    let mut ips = std::collections::HashSet::new();

    for _ in 0..50 {
        ips.insert(poisoner.generate_decoy_ip());
    }

    assert!(
        ips.len() >= 20,
        "Expected at least 20 unique IPs from 50 generations, got {}",
        ips.len()
    );

    let mut has_rfc1918 = false;
    let mut has_public_looking = false;

    for ip in &ips {
        if ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("172.") {
            has_rfc1918 = true;
        } else {
            has_public_looking = true;
        }
    }

    assert!(has_rfc1918, "No RFC 1918 IPs generated");
    assert!(has_public_looking, "No public-looking IPs generated");
}

#[test]
fn test_log_format_display() {
    assert_eq!(format!("{}", LogFormat::ApacheCombined), "apache-combined");
    assert_eq!(format!("{}", LogFormat::NginxAccess), "nginx-access");
    assert_eq!(format!("{}", LogFormat::SyslogRfc5424), "syslog-rfc5424");
    assert_eq!(
        format!("{}", LogFormat::WindowsEventXml),
        "windows-event-xml"
    );
}

#[test]
fn test_custom_timestamp_override() {
    let mut poisoner = make_poisoner();
    let custom_ts = "01/Jan/2024:12:00:00 +0000".to_string();
    let entry = poisoner.generate_entry(LogFormat::ApacheCombined, Some(custom_ts.clone()));
    assert!(
        entry.contains(&custom_ts),
        "Custom timestamp not found in entry: {}",
        entry
    );
}

#[test]
fn test_confusion_window_empty_config() {
    let mut poisoner = LogPoisoner::with_seed(
        TimelineConfusionConfig {
            window_hours: 1.0,
            decoy_count_before: 0,
            decoy_count_after: 0,
        },
        42,
    );

    let entries = poisoner.create_confusion_window(1700000000000, LogFormat::NginxAccess);
    assert!(entries.is_empty());
}

#[test]
fn test_generate_apache_combined_direct() {
    let poisoner = make_poisoner();
    let entry = DecoyEntry {
        timestamp: "15/Nov/2023:10:30:00 +0000".to_string(),
        source_ip: "192.168.1.100".to_string(),
        method: "GET".to_string(),
        path: "/index.html".to_string(),
        status: 200,
        user_agent: "Mozilla/5.0".to_string(),
    };
    let line = poisoner.generate_apache_combined(&entry);
    assert!(line.starts_with("192.168.1.100 - -"));
    assert!(line.contains("GET /index.html HTTP/1.1"));
    assert!(line.contains("200"));
    assert!(line.contains("Mozilla/5.0"));
}

#[test]
fn test_generate_syslog_rfc5424_direct() {
    let poisoner = make_poisoner();
    let entry = DecoyEntry {
        timestamp: "2023-11-15T10:30:00.000Z".to_string(),
        source_ip: "10.0.0.5".to_string(),
        method: "POST".to_string(),
        path: "/api/v1/health".to_string(),
        status: 200,
        user_agent: "curl/8.4.0".to_string(),
    };
    let line = poisoner.generate_syslog_rfc5424(&entry);
    assert!(line.starts_with('<'));
    assert!(line.contains("localhost"));
    assert!(line.contains("2023-11-15T10:30:00.000Z"));
}
