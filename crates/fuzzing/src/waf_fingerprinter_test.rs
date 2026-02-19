#[cfg(test)]
mod tests {
    use aegis_protocol::finding::VulnerabilityClass;

    use crate::defense_profile::WafVendor;
    use crate::waf_fingerprinter::{
        WafFingerprinter, WafProbeResult, build_waf_profile, estimate_paranoia_level,
        identify_blocked_categories, identify_vendor,
    };

    fn probe_with_headers(status: u16, headers: Vec<(&str, &str)>, body: &str) -> WafProbeResult {
        WafProbeResult {
            probe_payload: "test".to_string(),
            response_status: status,
            response_headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            response_body_snippet: body.to_string(),
        }
    }

    fn probe_with_status(status: u16) -> WafProbeResult {
        probe_with_headers(status, vec![], "")
    }

    #[test]
    fn new_fingerprinter_has_no_baseline() {
        let fp = WafFingerprinter::new("http://localhost:8080".to_string());
        assert_eq!(fp.target_url, "http://localhost:8080");
        assert_eq!(fp.baseline_status, None);
    }

    #[test]
    fn identify_vendor_cloudflare_server_header() {
        let responses = vec![probe_with_headers(403, vec![("Server", "cloudflare")], "")];
        assert_eq!(identify_vendor(&responses), WafVendor::Cloudflare);
    }

    #[test]
    fn identify_vendor_cloudflare_cf_ray_header() {
        let responses = vec![probe_with_headers(403, vec![("cf-ray", "abc123")], "")];
        assert_eq!(identify_vendor(&responses), WafVendor::Cloudflare);
    }

    #[test]
    fn identify_vendor_modsecurity_header() {
        let responses = vec![probe_with_headers(
            403,
            vec![("X-Powered-By", "ModSecurity/3.0")],
            "",
        )];
        assert_eq!(identify_vendor(&responses), WafVendor::ModSecurity);
    }

    #[test]
    fn identify_vendor_modsecurity_body() {
        let responses = vec![probe_with_headers(
            403,
            vec![],
            "<html>Blocked by Mod_Security</html>",
        )];
        assert_eq!(identify_vendor(&responses), WafVendor::ModSecurity);
    }

    #[test]
    fn identify_vendor_aws_waf() {
        let responses = vec![probe_with_headers(
            403,
            vec![("X-Amzn-Waf-Action", "BLOCK")],
            "",
        )];
        assert_eq!(identify_vendor(&responses), WafVendor::AwsWaf);
    }

    #[test]
    fn identify_vendor_imperva_body() {
        let responses = vec![probe_with_headers(
            403,
            vec![],
            "<html>Powered by Imperva Incapsula</html>",
        )];
        assert_eq!(identify_vendor(&responses), WafVendor::Imperva);
    }

    #[test]
    fn identify_vendor_imperva_incapsula() {
        let responses = vec![probe_with_headers(
            403,
            vec![],
            "<html>incapsula incident</html>",
        )];
        assert_eq!(identify_vendor(&responses), WafVendor::Imperva);
    }

    #[test]
    fn identify_vendor_akamai_header() {
        let responses = vec![probe_with_headers(
            403,
            vec![("X-Akamai-Transformed", "9 - 0 pmb=mRUM,2")],
            "",
        )];
        assert_eq!(identify_vendor(&responses), WafVendor::Akamai);
    }

    #[test]
    fn identify_vendor_akamai_body() {
        let responses = vec![probe_with_headers(
            403,
            vec![],
            "<html>Reference #akamai.error</html>",
        )];
        assert_eq!(identify_vendor(&responses), WafVendor::Akamai);
    }

    #[test]
    fn identify_vendor_unknown_when_no_signatures() {
        let responses = vec![probe_with_headers(
            403,
            vec![("Server", "nginx")],
            "Forbidden",
        )];
        assert_eq!(identify_vendor(&responses), WafVendor::Unknown);
    }

    #[test]
    fn identify_vendor_empty_responses() {
        assert_eq!(identify_vendor(&[]), WafVendor::Unknown);
    }

    #[test]
    fn identify_vendor_returns_first_match() {
        let responses = vec![
            probe_with_headers(200, vec![], ""),
            probe_with_headers(403, vec![("Server", "cloudflare")], ""),
            probe_with_headers(403, vec![("X-Amzn-Waf-Action", "BLOCK")], ""),
        ];
        assert_eq!(identify_vendor(&responses), WafVendor::Cloudflare);
    }

    #[test]
    fn blocked_categories_identifies_403() {
        let probes = vec![
            (VulnerabilityClass::SqlInjection, probe_with_status(403)),
            (
                VulnerabilityClass::CrossSiteScripting,
                probe_with_status(200),
            ),
        ];
        let blocked = identify_blocked_categories(200, &probes);
        assert_eq!(blocked, vec![VulnerabilityClass::SqlInjection]);
    }

    #[test]
    fn blocked_categories_identifies_multiple_status_codes() {
        let probes = vec![
            (VulnerabilityClass::SqlInjection, probe_with_status(403)),
            (VulnerabilityClass::CommandInjection, probe_with_status(406)),
            (VulnerabilityClass::PathTraversal, probe_with_status(451)),
            (
                VulnerabilityClass::CrossSiteScripting,
                probe_with_status(200),
            ),
        ];
        let blocked = identify_blocked_categories(200, &probes);
        assert_eq!(blocked.len(), 3);
        assert!(blocked.contains(&VulnerabilityClass::SqlInjection));
        assert!(blocked.contains(&VulnerabilityClass::CommandInjection));
        assert!(blocked.contains(&VulnerabilityClass::PathTraversal));
    }

    #[test]
    fn blocked_categories_ignores_baseline_matching_blocked_code() {
        let probes = vec![(VulnerabilityClass::SqlInjection, probe_with_status(403))];
        let blocked = identify_blocked_categories(403, &probes);
        assert!(blocked.is_empty());
    }

    #[test]
    fn blocked_categories_ignores_non_blocked_status() {
        let probes = vec![
            (VulnerabilityClass::SqlInjection, probe_with_status(500)),
            (
                VulnerabilityClass::CrossSiteScripting,
                probe_with_status(302),
            ),
        ];
        let blocked = identify_blocked_categories(200, &probes);
        assert!(blocked.is_empty());
    }

    #[test]
    fn paranoia_level_returns_highest_blocked_subtlety() {
        let probes = vec![
            (1u8, probe_with_status(403)),
            (2, probe_with_status(403)),
            (3, probe_with_status(200)),
            (4, probe_with_status(200)),
        ];
        assert_eq!(estimate_paranoia_level(&probes), Some(2));
    }

    #[test]
    fn paranoia_level_returns_none_when_nothing_blocked() {
        let probes = vec![(1u8, probe_with_status(200)), (2, probe_with_status(200))];
        assert_eq!(estimate_paranoia_level(&probes), None);
    }

    #[test]
    fn paranoia_level_handles_all_blocked() {
        let probes = vec![
            (1u8, probe_with_status(403)),
            (2, probe_with_status(406)),
            (3, probe_with_status(419)),
            (4, probe_with_status(451)),
        ];
        assert_eq!(estimate_paranoia_level(&probes), Some(4));
    }

    #[test]
    fn paranoia_level_handles_empty_input() {
        assert_eq!(estimate_paranoia_level(&[]), None);
    }

    #[test]
    fn build_waf_profile_assembles_correctly() {
        let profile = build_waf_profile(
            WafVendor::ModSecurity,
            vec![
                VulnerabilityClass::SqlInjection,
                VulnerabilityClass::CrossSiteScripting,
            ],
            Some(2),
            403,
        );
        assert_eq!(profile.vendor, WafVendor::ModSecurity);
        assert_eq!(profile.paranoia_level, Some(2));
        assert_eq!(profile.blocked_response_code, 403);
        assert_eq!(profile.blocked_categories.len(), 2);
    }

    #[test]
    fn build_waf_profile_with_no_paranoia() {
        let profile = build_waf_profile(WafVendor::Cloudflare, vec![], None, 403);
        assert_eq!(profile.vendor, WafVendor::Cloudflare);
        assert_eq!(profile.paranoia_level, None);
        assert!(profile.blocked_categories.is_empty());
    }
}
