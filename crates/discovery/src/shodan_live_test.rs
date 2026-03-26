use super::shodan_live::*;

#[test]
fn build_host_url_format() {
    let url = build_host_url("1.2.3.4", "testkey");
    assert_eq!(url, "https://api.shodan.io/shodan/host/1.2.3.4?key=testkey");
}

#[test]
fn build_search_url_format() {
    let url = build_search_url("hostname:example.com", "testkey", 1);
    assert!(url.contains("hostname:example.com"));
    assert!(url.contains("page=1"));
    assert!(url.contains("key=testkey"));
}

#[test]
fn build_target_queries_generates() {
    let queries = build_target_queries("acme.com");
    assert!(queries.len() >= 5);
    assert!(queries.iter().any(|q| q.contains("hostname:acme.com")));
    assert!(queries.iter().any(|q| q.contains("ssl.cert")));
    assert!(queries.iter().any(|q| q.contains("vuln")));
}

#[test]
fn detect_protocol_common_ports() {
    assert_eq!(detect_protocol(80, "tcp", ""), ShodanProtocol::Http);
    assert_eq!(detect_protocol(443, "tcp", ""), ShodanProtocol::Https);
    assert_eq!(detect_protocol(22, "tcp", ""), ShodanProtocol::Ssh);
    assert_eq!(detect_protocol(21, "tcp", ""), ShodanProtocol::Ftp);
    assert_eq!(detect_protocol(23, "tcp", ""), ShodanProtocol::Telnet);
    assert_eq!(detect_protocol(3389, "tcp", ""), ShodanProtocol::Rdp);
    assert_eq!(detect_protocol(445, "tcp", ""), ShodanProtocol::Smb);
    assert_eq!(detect_protocol(502, "tcp", ""), ShodanProtocol::Modbus);
}

#[test]
fn detect_protocol_from_banner() {
    assert_eq!(
        detect_protocol(8080, "tcp", "HTTP/1.1 200 OK"),
        ShodanProtocol::Http
    );
    assert_eq!(
        detect_protocol(2222, "tcp", "SSH-2.0-OpenSSH"),
        ShodanProtocol::Ssh
    );
    assert_eq!(
        detect_protocol(9999, "tcp", "220 FTP ready"),
        ShodanProtocol::Ftp
    );
}

#[test]
fn detect_protocol_unknown() {
    assert_eq!(
        detect_protocol(12345, "tcp", "custom protocol"),
        ShodanProtocol::Unknown
    );
}

#[test]
fn parse_host_response_full() {
    let json = r#"{
        "ip_str": "93.184.216.34",
        "hostnames": ["example.com"],
        "org": "Edgecast",
        "asn": "AS15133",
        "isp": "Edgecast Inc",
        "os": "Linux",
        "country_code": "US",
        "city": "Los Angeles",
        "last_update": "2024-01-15T12:00:00Z",
        "tags": ["cloud"],
        "vulns": ["CVE-2021-44228"],
        "data": [
            {
                "port": 80,
                "transport": "tcp",
                "data": "HTTP/1.1 200 OK\nServer: nginx/1.20.0",
                "product": "nginx",
                "version": "1.20.0",
                "cpe": ["cpe:/a:nginx:nginx:1.20.0"],
                "vulns": []
            },
            {
                "port": 443,
                "transport": "tcp",
                "data": "HTTP/2 200",
                "product": "nginx",
                "version": "1.20.0",
                "cpe": [],
                "vulns": [],
                "ssl": {
                    "versions": ["TLSv1.2", "TLSv1.3"],
                    "cert": {
                        "subject": {"CN": "example.com"},
                        "issuer": {"O": "Let's Encrypt"},
                        "expires": "2025-06-01"
                    },
                    "cipher": {"name": "TLS_AES_256_GCM_SHA384"},
                    "jarm": "29d29d15d29d29d21c29d29d29d29d..."
                }
            }
        ]
    }"#;

    let host = parse_host_response(json).unwrap();
    assert_eq!(host.ip, "93.184.216.34");
    assert_eq!(host.hostnames, vec!["example.com"]);
    assert_eq!(host.org, Some("Edgecast".to_string()));
    assert_eq!(host.services.len(), 2);
    assert_eq!(host.services[0].port, 80);
    assert_eq!(host.services[0].protocol, ShodanProtocol::Http);
    assert_eq!(host.services[1].port, 443);
    assert!(host.services[1].ssl.is_some());
    let ssl = host.services[1].ssl.as_ref().unwrap();
    assert_eq!(ssl.cert_subject, Some("example.com".to_string()));
    assert!(ssl.versions.contains(&"TLSv1.3".to_string()));
}

#[test]
fn parse_host_response_invalid_json() {
    assert!(parse_host_response("not json").is_none());
}

#[test]
fn parse_search_response_valid() {
    let json = r#"{
        "total": 42,
        "matches": [
            {
                "ip_str": "10.0.0.1",
                "port": 8080,
                "data": "HTTP/1.1 200 OK\nServer: Apache",
                "org": "TestOrg",
                "product": "Apache",
                "version": "2.4.51",
                "hostnames": ["test.example.com"],
                "asn": "AS1234",
                "location": {"country_code": "US"}
            }
        ]
    }"#;
    let result = parse_search_response(json).unwrap();
    assert_eq!(result.total, 42);
    assert_eq!(result.matches.len(), 1);
    assert_eq!(result.matches[0].ip_str, "10.0.0.1");
    assert_eq!(result.matches[0].port, 8080);
    assert_eq!(result.matches[0].org, Some("TestOrg".to_string()));
    assert_eq!(result.matches[0].country, Some("US".to_string()));
}

#[test]
fn parse_search_response_invalid() {
    assert!(parse_search_response("{}").is_none());
}

#[test]
fn analyze_banner_outdated_version() {
    let svc = ShodanService {
        port: 80,
        protocol: ShodanProtocol::Http,
        product: Some("Apache".to_string()),
        version: Some("2.2.34".to_string()),
        banner: "HTTP/1.1 200 OK\nServer: Apache/2.2.34".to_string(),
        cpe: vec![],
        vulns: vec![],
        ssl: None,
    };
    let analysis = analyze_banner(&svc);
    assert_eq!(analysis.port, 80);
    assert!(!analysis.security_issues.is_empty());
    assert!(analysis
        .security_issues
        .iter()
        .any(|i| i.contains("Outdated")));
}

#[test]
fn analyze_banner_default_creds() {
    let svc = ShodanService {
        port: 8080,
        protocol: ShodanProtocol::Http,
        product: None,
        version: None,
        banner: "Login: admin:admin default password".to_string(),
        cpe: vec![],
        vulns: vec![],
        ssl: None,
    };
    let analysis = analyze_banner(&svc);
    assert!(analysis
        .security_issues
        .iter()
        .any(|i| i.contains("Default credentials")));
}

#[test]
fn analyze_banner_critical_vulns() {
    let svc = ShodanService {
        port: 443,
        protocol: ShodanProtocol::Https,
        product: Some("OpenSSL".to_string()),
        version: Some("1.0.2k".to_string()),
        banner: "TLS connection".to_string(),
        cpe: vec![],
        vulns: vec![
            "CVE-2021-3449".to_string(),
            "CVE-2021-3450".to_string(),
            "CVE-2021-23840".to_string(),
            "CVE-2022-0778".to_string(),
        ],
        ssl: None,
    };
    let analysis = analyze_banner(&svc);
    assert_eq!(analysis.risk, ShodanRisk::Critical);
}

#[test]
fn analyze_banner_clean() {
    let svc = ShodanService {
        port: 443,
        protocol: ShodanProtocol::Https,
        product: Some("nginx".to_string()),
        version: Some("1.25.0".to_string()),
        banner: "HTTP/2 200".to_string(),
        cpe: vec![],
        vulns: vec![],
        ssl: None,
    };
    let analysis = analyze_banner(&svc);
    assert_eq!(analysis.risk, ShodanRisk::Info);
    assert!(analysis.security_issues.is_empty());
}

#[test]
fn analyze_banner_telnet_medium() {
    let svc = ShodanService {
        port: 23,
        protocol: ShodanProtocol::Telnet,
        product: None,
        version: None,
        banner: "Welcome to telnet".to_string(),
        cpe: vec![],
        vulns: vec![],
        ssl: None,
    };
    let analysis = analyze_banner(&svc);
    assert_eq!(analysis.risk, ShodanRisk::Medium);
}

#[test]
fn build_shodan_report_aggregates() {
    let host = ShodanHostResult {
        ip: "1.2.3.4".to_string(),
        hostnames: vec!["test.com".to_string()],
        org: Some("TestOrg".to_string()),
        asn: None,
        isp: None,
        os: None,
        country: Some("US".to_string()),
        city: None,
        services: vec![
            ShodanService {
                port: 80,
                protocol: ShodanProtocol::Http,
                product: None,
                version: None,
                banner: "HTTP/1.1 200 OK".to_string(),
                cpe: vec![],
                vulns: vec![],
                ssl: None,
            },
            ShodanService {
                port: 23,
                protocol: ShodanProtocol::Telnet,
                product: None,
                version: None,
                banner: "Login:".to_string(),
                cpe: vec![],
                vulns: vec![],
                ssl: None,
            },
        ],
        vulns: vec!["CVE-2023-0001".to_string()],
        last_update: None,
        tags: vec![],
    };

    let report = build_shodan_report("test.com", vec![host], vec![]);
    assert_eq!(report.target, "test.com");
    assert_eq!(report.exposed_services_count, 2);
    assert_eq!(report.critical_vulns.len(), 1);
    assert_eq!(report.banner_analyses.len(), 2);
    assert!(report.overall_risk >= ShodanRisk::Medium);
}

#[test]
fn shodan_protocol_display() {
    assert_eq!(ShodanProtocol::Http.to_string(), "HTTP");
    assert_eq!(ShodanProtocol::Modbus.to_string(), "Modbus");
    assert_eq!(ShodanProtocol::Unknown.to_string(), "Unknown");
}

#[test]
fn shodan_risk_ordering() {
    assert!(ShodanRisk::Critical > ShodanRisk::High);
    assert!(ShodanRisk::High > ShodanRisk::Medium);
    assert!(ShodanRisk::Medium > ShodanRisk::Low);
    assert!(ShodanRisk::Low > ShodanRisk::Info);
}
