use super::darkweb_monitor::*;

#[test]
fn extract_onion_urls_v2() {
    let text = "visit http://abcdefghijklmnop.onion/page for info";
    let urls = extract_onion_urls(text);
    assert_eq!(urls.len(), 1);
    assert_eq!(urls[0].domain, "abcdefghijklmnop.onion");
    assert!(!urls[0].is_v3);
}

#[test]
fn extract_onion_urls_v3() {
    let v3_domain = format!("{}.onion", "a".repeat(56));
    let text = format!("hidden service at http://{}/test", v3_domain);
    let urls = extract_onion_urls(&text);
    assert_eq!(urls.len(), 1);
    assert!(urls[0].is_v3);
}

#[test]
fn extract_onion_urls_none_present() {
    let text = "this is a normal text with example.com links";
    let urls = extract_onion_urls(text);
    assert!(urls.is_empty());
}

#[test]
fn detect_hash_type_md5() {
    assert_eq!(
        detect_hash_type("5d41402abc4b2a76b9719d911017c592"),
        CredentialType::Md5Hash
    );
}

#[test]
fn detect_hash_type_sha1() {
    assert_eq!(
        detect_hash_type("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"),
        CredentialType::Sha1Hash
    );
}

#[test]
fn detect_hash_type_sha256() {
    assert_eq!(
        detect_hash_type("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
        CredentialType::Sha256Hash
    );
}

#[test]
fn detect_hash_type_bcrypt() {
    assert_eq!(
        detect_hash_type("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"),
        CredentialType::BcryptHash
    );
}

#[test]
fn detect_hash_type_plaintext() {
    assert_eq!(detect_hash_type("mypassword123"), CredentialType::Plaintext);
}

#[test]
fn parse_credentials_email_password() {
    let content = "user@example.com:password123\nadmin@test.org:hunter2\n";
    let creds = parse_credentials_from_paste(content);
    assert_eq!(creds.len(), 2);
    assert_eq!(creds[0].username_or_email, "user@example.com");
    assert_eq!(creds[0].credential, "password123");
    assert_eq!(creds[0].credential_type, CredentialType::Plaintext);
}

#[test]
fn parse_credentials_email_hash() {
    let content = "user@corp.com:5d41402abc4b2a76b9719d911017c592\n";
    let creds = parse_credentials_from_paste(content);
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].credential_type, CredentialType::Md5Hash);
}

#[test]
fn parse_credentials_pipe_delimiter() {
    let content = "admin@site.com|letmein\n";
    let creds = parse_credentials_from_paste(content);
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].credential, "letmein");
}

#[test]
fn parse_credentials_skips_comments() {
    let content = "# header comment\n// another comment\nuser@x.com:pass\n";
    let creds = parse_credentials_from_paste(content);
    assert_eq!(creds.len(), 1);
}

#[test]
fn parse_credentials_deduplicates() {
    let content = "user@x.com:pass\nuser@x.com:pass\n";
    let creds = parse_credentials_from_paste(content);
    assert_eq!(creds.len(), 1);
}

#[test]
fn extract_domain_emails_filters() {
    let text = "users: admin@target.com, user@other.com, ceo@target.com, dev@target.com";
    let emails = extract_domain_emails(text, "target.com");
    assert_eq!(emails.len(), 3);
    assert!(emails.contains(&"admin@target.com".to_string()));
    assert!(emails.contains(&"ceo@target.com".to_string()));
    assert!(!emails.contains(&"user@other.com".to_string()));
}

#[test]
fn generate_tor_search_queries_multiple() {
    let queries = generate_tor_search_queries("acme.com");
    assert!(queries.len() >= 6);
    assert!(queries.iter().any(|q| q.engine == TorSearchEngine::Ahmia));
    assert!(queries
        .iter()
        .any(|q| q.search_term.contains("credentials")));
    assert!(queries.iter().any(|q| q.search_term.contains("leak")));
}

#[test]
fn classify_paste_content_ransomware() {
    let content = "We have encrypted your files. Pay 5 BTC to restore. Ransom deadline: 48h";
    assert_eq!(
        classify_paste_content(content),
        DarkWebContentType::RansomwareLeak
    );
}

#[test]
fn classify_paste_content_api_key() {
    let content = "api_key=sk-123456789abcdef\nbearer eyJ0eXAi...";
    assert_eq!(
        classify_paste_content(content),
        DarkWebContentType::ApiKeyExposure
    );
}

#[test]
fn classify_paste_content_database_dump() {
    let content = "SELECT email, password FROM users WHERE active = 1";
    assert_eq!(
        classify_paste_content(content),
        DarkWebContentType::DatabaseDump
    );
}

#[test]
fn classify_paste_content_source_code() {
    let content = "function authenticate(user, pass) { return db.query(user); }";
    assert_eq!(
        classify_paste_content(content),
        DarkWebContentType::SourceCodeLeak
    );
}

#[test]
fn classify_paste_content_credentials() {
    let content = "admin@corp.com:password123\nuser@corp.com:hunter2\n";
    assert_eq!(
        classify_paste_content(content),
        DarkWebContentType::PastedCredentials
    );
}

#[test]
fn classify_paste_content_internal_doc() {
    let content = "CONFIDENTIAL - Internal Only - Q3 Revenue Report";
    assert_eq!(
        classify_paste_content(content),
        DarkWebContentType::InternalDocument
    );
}

#[test]
fn parse_paste_full() {
    let content = "admin@acme.com:secretpass\nceo@acme.com:12345\nrandom@other.com:test";
    let entry = parse_paste(
        PasteSource::Pastebin,
        "abc123",
        Some("Acme Corp Leak"),
        content,
        "acme.com",
        Some("2024-01-15"),
    );
    assert_eq!(entry.source, PasteSource::Pastebin);
    assert_eq!(entry.paste_id, "abc123");
    assert_eq!(entry.title, Some("Acme Corp Leak".to_string()));
    assert_eq!(entry.detected_emails.len(), 2);
    assert_eq!(entry.detected_credentials.len(), 3);
    assert_eq!(entry.content_type, DarkWebContentType::PastedCredentials);
}

#[test]
fn finding_from_paste_critical_plaintext() {
    let paste = PasteEntry {
        source: PasteSource::Pastebin,
        paste_id: "xyz".to_string(),
        title: None,
        content_preview: "test".to_string(),
        detected_emails: vec!["admin@corp.com".to_string()],
        detected_credentials: vec![ParsedCredential {
            username_or_email: "admin@corp.com".to_string(),
            credential: "plaintext_pw".to_string(),
            credential_type: CredentialType::Plaintext,
        }],
        content_type: DarkWebContentType::PastedCredentials,
        timestamp: None,
    };

    let finding = finding_from_paste(&paste, "corp.com");
    assert_eq!(finding.risk, DarkWebRisk::Critical);
    assert_eq!(finding.content_type, DarkWebContentType::PastedCredentials);
}

#[test]
fn finding_from_paste_medium_email_only() {
    let paste = PasteEntry {
        source: PasteSource::GhostBin,
        paste_id: "qrs".to_string(),
        title: None,
        content_preview: "emails".to_string(),
        detected_emails: vec!["user@corp.com".to_string()],
        detected_credentials: vec![],
        content_type: DarkWebContentType::ForumPost,
        timestamp: None,
    };

    let finding = finding_from_paste(&paste, "corp.com");
    assert_eq!(finding.risk, DarkWebRisk::Medium);
}

#[test]
fn build_darkweb_report_aggregates() {
    let p1 = PasteEntry {
        source: PasteSource::Pastebin,
        paste_id: "p1".to_string(),
        title: Some("Leak 1".to_string()),
        content_preview: "preview".to_string(),
        detected_emails: vec!["a@target.com".to_string()],
        detected_credentials: vec![
            ParsedCredential {
                username_or_email: "a@target.com".to_string(),
                credential: "pass1".to_string(),
                credential_type: CredentialType::Plaintext,
            },
            ParsedCredential {
                username_or_email: "b@target.com".to_string(),
                credential: "pass2".to_string(),
                credential_type: CredentialType::Plaintext,
            },
        ],
        content_type: DarkWebContentType::PastedCredentials,
        timestamp: Some("2024-01-01".to_string()),
    };

    let p2 = PasteEntry {
        source: PasteSource::Rentry,
        paste_id: "p2".to_string(),
        title: None,
        content_preview: "preview2".to_string(),
        detected_emails: vec!["c@target.com".to_string()],
        detected_credentials: vec![],
        content_type: DarkWebContentType::ForumPost,
        timestamp: None,
    };

    let report = build_darkweb_report("target.com", vec![p1, p2], vec![]);
    assert_eq!(report.target_domain, "target.com");
    assert_eq!(report.findings.len(), 2);
    assert_eq!(report.total_credentials_found, 2);
    assert_eq!(report.overall_risk, DarkWebRisk::Critical);
    assert!(!report.search_queries_generated.is_empty());
}

#[test]
fn build_risk_summary_counts() {
    let findings = vec![
        DarkWebFinding {
            content_type: DarkWebContentType::PastedCredentials,
            risk: DarkWebRisk::Critical,
            source_url: None,
            description: String::new(),
            matched_keywords: vec![],
            detected_data: DetectedData {
                emails: vec![],
                credentials: vec![],
                domains: vec![],
                ip_addresses: vec![],
                onion_urls: vec![],
            },
            timestamp: None,
        },
        DarkWebFinding {
            content_type: DarkWebContentType::ForumPost,
            risk: DarkWebRisk::Low,
            source_url: None,
            description: String::new(),
            matched_keywords: vec![],
            detected_data: DetectedData {
                emails: vec![],
                credentials: vec![],
                domains: vec![],
                ip_addresses: vec![],
                onion_urls: vec![],
            },
            timestamp: None,
        },
        DarkWebFinding {
            content_type: DarkWebContentType::DatabaseDump,
            risk: DarkWebRisk::Critical,
            source_url: None,
            description: String::new(),
            matched_keywords: vec![],
            detected_data: DetectedData {
                emails: vec![],
                credentials: vec![],
                domains: vec![],
                ip_addresses: vec![],
                onion_urls: vec![],
            },
            timestamp: None,
        },
    ];
    let summary = build_risk_summary(&findings);
    assert_eq!(summary[&DarkWebRisk::Critical], 2);
    assert_eq!(summary[&DarkWebRisk::Low], 1);
}

#[test]
fn paste_source_display() {
    assert_eq!(PasteSource::Pastebin.to_string(), "Pastebin");
    assert_eq!(PasteSource::JustPaste.to_string(), "JustPaste.it");
    assert_eq!(PasteSource::Unknown.to_string(), "Unknown");
}

#[test]
fn dark_web_content_type_display() {
    assert_eq!(
        DarkWebContentType::RansomwareLeak.to_string(),
        "Ransomware Leak"
    );
    assert_eq!(
        DarkWebContentType::ApiKeyExposure.to_string(),
        "API Key Exposure"
    );
}
