#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use crate::change_detector::{
        ChangeDetector, ChangeSeverity, ChangeType, ContentLengthBucket, ResponseSignature,
        TargetSnapshot,
    };

    fn empty_snapshot(url: &str, ts: u64) -> TargetSnapshot {
        TargetSnapshot::new(url, ts)
    }

    #[test]
    fn no_changes_produces_empty_report() {
        let baseline = empty_snapshot("http://example.com", 1000);
        let current = empty_snapshot("http://example.com", 2000);
        let detector = ChangeDetector::new();
        let report = detector.detect(&baseline, &current);
        assert!(report.is_empty());
        assert_eq!(report.total_changes, 0);
        assert_eq!(report.max_severity(), None);
    }

    #[test]
    fn new_endpoint_detected() {
        let baseline = empty_snapshot("http://example.com", 1000);
        let mut current = empty_snapshot("http://example.com", 2000);
        current.endpoints.insert("/api/new".to_string());

        let report = ChangeDetector::new().detect(&baseline, &current);
        assert_eq!(report.total_changes, 1);
        assert!(matches!(
            &report.changes[0].change_type,
            ChangeType::EndpointAdded(ep) if ep == "/api/new"
        ));
        assert_eq!(report.changes[0].severity, ChangeSeverity::Medium);
    }

    #[test]
    fn removed_endpoint_detected() {
        let mut baseline = empty_snapshot("http://example.com", 1000);
        baseline.endpoints.insert("/api/old".to_string());
        let current = empty_snapshot("http://example.com", 2000);

        let report = ChangeDetector::new().detect(&baseline, &current);
        assert_eq!(report.total_changes, 1);
        assert!(matches!(
            &report.changes[0].change_type,
            ChangeType::EndpointRemoved(ep) if ep == "/api/old"
        ));
    }

    #[test]
    fn subdomain_added() {
        let baseline = empty_snapshot("http://example.com", 1000);
        let mut current = empty_snapshot("http://example.com", 2000);
        current.subdomains.insert("api.example.com".to_string());

        let report = ChangeDetector::new().detect(&baseline, &current);
        assert_eq!(report.high_count, 1);
        assert!(matches!(
            &report.changes[0].change_type,
            ChangeType::SubdomainAdded(s) if s == "api.example.com"
        ));
    }

    #[test]
    fn subdomain_removed() {
        let mut baseline = empty_snapshot("http://example.com", 1000);
        baseline.subdomains.insert("old.example.com".to_string());
        let current = empty_snapshot("http://example.com", 2000);

        let report = ChangeDetector::new().detect(&baseline, &current);
        assert_eq!(report.medium_count, 1);
        assert!(matches!(
            &report.changes[0].change_type,
            ChangeType::SubdomainRemoved(s) if s == "old.example.com"
        ));
    }

    #[test]
    fn response_signature_status_change_is_high() {
        let mut baseline = empty_snapshot("http://example.com", 1000);
        baseline.response_signatures.insert(
            "/api/login".to_string(),
            ResponseSignature {
                status_code: 200,
                content_length_bucket: ContentLengthBucket::Small,
                header_hash: 12345,
                content_hash: None,
            },
        );
        let mut current = empty_snapshot("http://example.com", 2000);
        current.response_signatures.insert(
            "/api/login".to_string(),
            ResponseSignature {
                status_code: 403,
                content_length_bucket: ContentLengthBucket::Tiny,
                header_hash: 67890,
                content_hash: None,
            },
        );

        let report = ChangeDetector::new().detect(&baseline, &current);
        assert_eq!(report.total_changes, 1);
        assert_eq!(report.changes[0].severity, ChangeSeverity::High);
        assert!(matches!(
            &report.changes[0].change_type,
            ChangeType::ResponseChanged(ep) if ep == "/api/login"
        ));
    }

    #[test]
    fn response_signature_content_change_is_medium() {
        let mut baseline = empty_snapshot("http://example.com", 1000);
        baseline.response_signatures.insert(
            "/".to_string(),
            ResponseSignature {
                status_code: 200,
                content_length_bucket: ContentLengthBucket::Small,
                header_hash: 111,
                content_hash: Some(1000),
            },
        );
        let mut current = empty_snapshot("http://example.com", 2000);
        current.response_signatures.insert(
            "/".to_string(),
            ResponseSignature {
                status_code: 200,
                content_length_bucket: ContentLengthBucket::Medium,
                header_hash: 222,
                content_hash: Some(2000),
            },
        );

        let report = ChangeDetector::new().detect(&baseline, &current);
        assert_eq!(report.changes[0].severity, ChangeSeverity::Medium);
    }

    #[test]
    fn certificate_change_is_critical() {
        let mut baseline = empty_snapshot("http://example.com", 1000);
        baseline.tls_certificate_fingerprint = Some("sha256:old".to_string());
        let mut current = empty_snapshot("http://example.com", 2000);
        current.tls_certificate_fingerprint = Some("sha256:new".to_string());

        let report = ChangeDetector::new().detect(&baseline, &current);
        assert_eq!(report.critical_count, 1);
        assert!(matches!(
            &report.changes[0].change_type,
            ChangeType::CertificateChanged
        ));
    }

    #[test]
    fn certificate_disappeared_is_critical() {
        let mut baseline = empty_snapshot("http://example.com", 1000);
        baseline.tls_certificate_fingerprint = Some("sha256:old".to_string());
        let current = empty_snapshot("http://example.com", 2000);

        let report = ChangeDetector::new().detect(&baseline, &current);
        assert_eq!(report.critical_count, 1);
    }

    #[test]
    fn certificate_appeared_is_high() {
        let baseline = empty_snapshot("http://example.com", 1000);
        let mut current = empty_snapshot("http://example.com", 2000);
        current.tls_certificate_fingerprint = Some("sha256:new".to_string());

        let report = ChangeDetector::new().detect(&baseline, &current);
        assert_eq!(report.high_count, 1);
    }

    #[test]
    fn technology_stack_change() {
        let mut baseline = empty_snapshot("http://example.com", 1000);
        baseline.technology_stack.insert("Express 4.18".to_string());
        let mut current = empty_snapshot("http://example.com", 2000);
        current.technology_stack.insert("Express 5.0".to_string());

        let report = ChangeDetector::new().detect(&baseline, &current);
        assert_eq!(report.total_changes, 2);
        let types: HashSet<_> = report.changes.iter().map(|c| &c.change_type).collect();
        assert!(
            types
                .iter()
                .any(|t| matches!(t, ChangeType::TechnologyAdded(s) if s == "Express 5.0"))
        );
        assert!(
            types
                .iter()
                .any(|t| matches!(t, ChangeType::TechnologyRemoved(s) if s == "Express 4.18"))
        );
    }

    #[test]
    fn dns_record_added() {
        let baseline = empty_snapshot("http://example.com", 1000);
        let mut current = empty_snapshot("http://example.com", 2000);
        current
            .dns_records
            .insert("A".to_string(), vec!["1.2.3.4".to_string()]);

        let report = ChangeDetector::new().detect(&baseline, &current);
        assert_eq!(report.total_changes, 1);
        assert!(matches!(
            &report.changes[0].change_type,
            ChangeType::DnsRecordAdded { record_type, value }
                if record_type == "A" && value == "1.2.3.4"
        ));
    }

    #[test]
    fn dns_record_removed() {
        let mut baseline = empty_snapshot("http://example.com", 1000);
        baseline
            .dns_records
            .insert("CNAME".to_string(), vec!["old.cdn.com".to_string()]);
        let current = empty_snapshot("http://example.com", 2000);

        let report = ChangeDetector::new().detect(&baseline, &current);
        assert_eq!(report.total_changes, 1);
        assert!(matches!(
            &report.changes[0].change_type,
            ChangeType::DnsRecordRemoved { record_type, value }
                if record_type == "CNAME" && value == "old.cdn.com"
        ));
    }

    #[test]
    fn content_length_bucket_ranges() {
        assert_eq!(
            ContentLengthBucket::from_length(0),
            ContentLengthBucket::Empty
        );
        assert_eq!(
            ContentLengthBucket::from_length(500),
            ContentLengthBucket::Tiny
        );
        assert_eq!(
            ContentLengthBucket::from_length(1024),
            ContentLengthBucket::Tiny
        );
        assert_eq!(
            ContentLengthBucket::from_length(1025),
            ContentLengthBucket::Small
        );
        assert_eq!(
            ContentLengthBucket::from_length(10240),
            ContentLengthBucket::Small
        );
        assert_eq!(
            ContentLengthBucket::from_length(10241),
            ContentLengthBucket::Medium
        );
        assert_eq!(
            ContentLengthBucket::from_length(102400),
            ContentLengthBucket::Medium
        );
        assert_eq!(
            ContentLengthBucket::from_length(102401),
            ContentLengthBucket::Large
        );
        assert_eq!(
            ContentLengthBucket::from_length(1048576),
            ContentLengthBucket::Large
        );
        assert_eq!(
            ContentLengthBucket::from_length(1048577),
            ContentLengthBucket::VeryLarge
        );
    }

    #[test]
    fn max_severity_returns_highest() {
        let mut baseline = empty_snapshot("http://example.com", 1000);
        baseline.tls_certificate_fingerprint = Some("sha256:old".to_string());
        let mut current = empty_snapshot("http://example.com", 2000);
        current.tls_certificate_fingerprint = Some("sha256:new".to_string());
        current.endpoints.insert("/new".to_string());

        let report = ChangeDetector::new().detect(&baseline, &current);
        assert_eq!(report.max_severity(), Some(ChangeSeverity::Critical));
    }

    #[test]
    fn multiple_dns_values_for_same_key() {
        let mut baseline = empty_snapshot("http://example.com", 1000);
        baseline.dns_records.insert(
            "A".to_string(),
            vec!["1.1.1.1".to_string(), "2.2.2.2".to_string()],
        );
        let mut current = empty_snapshot("http://example.com", 2000);
        current.dns_records.insert(
            "A".to_string(),
            vec!["1.1.1.1".to_string(), "3.3.3.3".to_string()],
        );

        let report = ChangeDetector::new().detect(&baseline, &current);
        assert_eq!(report.total_changes, 2);
    }

    #[test]
    fn identical_snapshots_no_changes() {
        let mut s1 = empty_snapshot("http://example.com", 1000);
        s1.endpoints.insert("/api".to_string());
        s1.subdomains.insert("api.example.com".to_string());
        s1.technology_stack.insert("nginx".to_string());
        s1.tls_certificate_fingerprint = Some("sha256:same".to_string());

        let mut s2 = empty_snapshot("http://example.com", 2000);
        s2.endpoints.insert("/api".to_string());
        s2.subdomains.insert("api.example.com".to_string());
        s2.technology_stack.insert("nginx".to_string());
        s2.tls_certificate_fingerprint = Some("sha256:same".to_string());

        let report = ChangeDetector::new().detect(&s1, &s2);
        assert!(report.is_empty());
    }
}
