#[cfg(test)]
mod tests {
    use crate::mutator::{
        BypassPayload, MutationOrigin, MutationStrategy, PayloadMutator, StealthRating,
        load_bypass_corpus, stealth_rating_for_template,
    };
    use aegis_protocol::finding::VulnerabilityClass;
    use std::io::Write;

    #[test]
    fn generate_sqli_payloads() {
        let mutator = PayloadMutator::new();
        let payloads = mutator.generate_payloads(VulnerabilityClass::SqlInjection, 5);
        assert_eq!(payloads.len(), 5);
        for p in &payloads {
            assert_eq!(p.vulnerability_class, VulnerabilityClass::SqlInjection);
            assert!(!p.raw.is_empty());
        }
    }

    #[test]
    fn generate_xss_payloads() {
        let mutator = PayloadMutator::new();
        let payloads = mutator.generate_payloads(VulnerabilityClass::CrossSiteScripting, 3);
        assert_eq!(payloads.len(), 3);
        assert!(payloads[0].raw.contains("script") || payloads[0].raw.contains("alert"));
    }

    #[test]
    fn generate_more_than_templates_uses_bitflip() {
        let mutator = PayloadMutator::new();
        let template_count = mutator.template_count(VulnerabilityClass::CrlfInjection);
        let payloads =
            mutator.generate_payloads(VulnerabilityClass::CrlfInjection, template_count + 5);
        assert_eq!(payloads.len(), template_count + 5);

        let bitflip_count = payloads
            .iter()
            .filter(|p| p.mutation_strategy == MutationStrategy::BitFlip)
            .count();
        assert_eq!(bitflip_count, 5);
    }

    #[test]
    fn boundary_payloads_generated() {
        let mutator = PayloadMutator::new();
        let payloads = mutator.generate_boundary_payloads();
        assert!(payloads.len() >= 10);
        assert!(payloads.iter().any(|p| p.raw.is_empty()));
        assert!(payloads.iter().any(|p| p.raw == "null"));
        assert!(
            payloads
                .iter()
                .any(|p| p.mutation_strategy == MutationStrategy::Boundary)
        );
    }

    #[test]
    fn template_count_for_each_class() {
        let mutator = PayloadMutator::new();
        assert!(mutator.template_count(VulnerabilityClass::SqlInjection) > 0);
        assert!(mutator.template_count(VulnerabilityClass::CrossSiteScripting) > 0);
        assert!(mutator.template_count(VulnerabilityClass::CommandInjection) > 0);
        assert!(mutator.template_count(VulnerabilityClass::PathTraversal) > 0);
        assert!(mutator.template_count(VulnerabilityClass::ServerSideRequestForgery) > 0);
        assert!(mutator.template_count(VulnerabilityClass::ServerSideTemplateInjection) > 0);
        assert!(mutator.template_count(VulnerabilityClass::NoSqlInjection) > 0);
    }

    #[test]
    fn mutation_strategy_display() {
        assert_eq!(MutationStrategy::Template.to_string(), "template");
        assert_eq!(MutationStrategy::Generative.to_string(), "generative");
        assert_eq!(MutationStrategy::BitFlip.to_string(), "bitflip");
        assert_eq!(MutationStrategy::Boundary.to_string(), "boundary");
    }

    #[test]
    fn default_creates_mutator_with_templates() {
        let mutator = PayloadMutator::default();
        assert!(mutator.template_count(VulnerabilityClass::SqlInjection) > 0);
    }

    #[test]
    fn payloads_are_non_empty() {
        let mutator = PayloadMutator::new();
        let all_classes = vec![
            VulnerabilityClass::SqlInjection,
            VulnerabilityClass::CrossSiteScripting,
            VulnerabilityClass::CommandInjection,
            VulnerabilityClass::PathTraversal,
            VulnerabilityClass::ServerSideRequestForgery,
            VulnerabilityClass::ServerSideTemplateInjection,
            VulnerabilityClass::InsecureDeserialization,
            VulnerabilityClass::HeaderInjection,
            VulnerabilityClass::OpenRedirect,
            VulnerabilityClass::CrlfInjection,
            VulnerabilityClass::NoSqlInjection,
        ];

        for class in all_classes {
            let payloads = mutator.generate_payloads(class, 2);
            for p in payloads {
                assert!(!p.raw.is_empty(), "empty payload for {class:?}");
            }
        }
    }

    #[test]
    fn stealth_rating_high_for_time_based_blind_payloads() {
        let class = VulnerabilityClass::SqlInjection;
        assert_eq!(
            stealth_rating_for_template("' WAITFOR DELAY '0:0:5'--", class),
            StealthRating::High
        );
        assert_eq!(
            stealth_rating_for_template("1; SELECT pg_sleep(5)--", class),
            StealthRating::High
        );
        assert_eq!(
            stealth_rating_for_template("sleep(5)", class),
            StealthRating::High
        );
        assert_eq!(
            stealth_rating_for_template("BENCHMARK(10000000,SHA1('test'))", class),
            StealthRating::High
        );
        assert_eq!(
            stealth_rating_for_template("time-based sqli probe", class),
            StealthRating::High
        );
        assert_eq!(
            stealth_rating_for_template("dns exfiltration payload", class),
            StealthRating::High
        );
        assert_eq!(
            stealth_rating_for_template("oob channel test", class),
            StealthRating::High
        );
        assert_eq!(
            stealth_rating_for_template("ping -c 3 attacker.com", class),
            StealthRating::High
        );
    }

    #[test]
    fn stealth_rating_medium_for_url_encoded_payloads() {
        let class = VulnerabilityClass::PathTraversal;
        assert_eq!(
            stealth_rating_for_template("%2e%2e%2f%2e%2e%2fetc%2fpasswd", class),
            StealthRating::Medium
        );
        assert_eq!(
            stealth_rating_for_template("/etc/passwd%00", class),
            StealthRating::Medium
        );
        assert_eq!(
            stealth_rating_for_template("%0d%0aSet-Cookie:evil=true", class),
            StealthRating::Medium
        );
        assert_eq!(
            stealth_rating_for_template("path%25traversal", class),
            StealthRating::Medium
        );
    }

    #[test]
    fn stealth_rating_medium_for_mixed_case_keywords() {
        let class = VulnerabilityClass::SqlInjection;
        assert_eq!(
            stealth_rating_for_template("1 uNiOn SeLeCt null--", class),
            StealthRating::Medium
        );
        assert_eq!(
            stealth_rating_for_template("sElEcT * FROM users", class),
            StealthRating::Medium
        );
        let xss_class = VulnerabilityClass::CrossSiteScripting;
        assert_eq!(
            stealth_rating_for_template("<sCrIpT>alert(1)</sCrIpT>", xss_class),
            StealthRating::Medium
        );
        assert_eq!(
            stealth_rating_for_template("aLeRt(document.cookie)", xss_class),
            StealthRating::Medium
        );
    }

    #[test]
    fn stealth_rating_low_for_obvious_payloads() {
        assert_eq!(
            stealth_rating_for_template(
                "<script>alert(1)</script>",
                VulnerabilityClass::CrossSiteScripting
            ),
            StealthRating::Low
        );
        assert_eq!(
            stealth_rating_for_template("' OR '1'='1", VulnerabilityClass::SqlInjection),
            StealthRating::Low
        );
        assert_eq!(
            stealth_rating_for_template("; id", VulnerabilityClass::CommandInjection),
            StealthRating::Low
        );
        assert_eq!(
            stealth_rating_for_template("../../../etc/passwd", VulnerabilityClass::PathTraversal),
            StealthRating::Low
        );
        assert_eq!(
            stealth_rating_for_template("{{7*7}}", VulnerabilityClass::ServerSideTemplateInjection),
            StealthRating::Low
        );
    }

    #[test]
    fn stealth_payloads_sorted_high_first() {
        let mutator = PayloadMutator::new();
        let payloads = mutator.generate_stealth_payloads(VulnerabilityClass::SqlInjection, 8);
        assert_eq!(payloads.len(), 8);

        let ratings: Vec<StealthRating> = payloads
            .iter()
            .map(|p| stealth_rating_for_template(&p.raw, VulnerabilityClass::SqlInjection))
            .collect();

        let mut seen_medium = false;
        let mut seen_low = false;
        for rating in &ratings {
            match rating {
                StealthRating::High => {
                    assert!(!seen_medium && !seen_low);
                }
                StealthRating::Medium => {
                    assert!(!seen_low);
                    seen_medium = true;
                }
                StealthRating::Low => {
                    seen_low = true;
                }
            }
        }
    }

    #[test]
    fn stealth_payloads_overflow_uses_generative_strategy() {
        let mutator = PayloadMutator::new();
        let template_count = mutator.template_count(VulnerabilityClass::SqlInjection);
        let payloads =
            mutator.generate_stealth_payloads(VulnerabilityClass::SqlInjection, template_count + 5);
        assert_eq!(payloads.len(), template_count + 5);

        let generative_count = payloads
            .iter()
            .filter(|p| p.mutation_strategy == MutationStrategy::Generative)
            .count();
        assert_eq!(generative_count, 5);
    }

    #[test]
    fn stealth_sqli_returns_time_based_payloads_first() {
        let mutator = PayloadMutator::new();
        let payloads = mutator.generate_stealth_payloads(VulnerabilityClass::SqlInjection, 4);

        let first_raw = payloads[0].raw.to_lowercase();
        let second_raw = payloads[1].raw.to_lowercase();
        let has_time_keyword = |s: &str| {
            s.contains("sleep")
                || s.contains("waitfor")
                || s.contains("pg_sleep")
                || s.contains("delay")
        };
        assert!(
            has_time_keyword(&first_raw) || has_time_keyword(&second_raw),
            "expected time-based payloads among the first results, got: {:?}",
            payloads.iter().take(4).map(|p| &p.raw).collect::<Vec<_>>()
        );
    }

    #[test]
    fn stealth_payloads_count_zero_returns_empty() {
        let mutator = PayloadMutator::new();
        let payloads = mutator.generate_stealth_payloads(VulnerabilityClass::SqlInjection, 0);
        assert!(payloads.is_empty());
    }

    #[test]
    fn stealth_payloads_for_class_with_no_templates() {
        let mutator = PayloadMutator::new();
        assert_eq!(
            mutator.template_count(VulnerabilityClass::BrokenAuthentication),
            0
        );
        let payloads =
            mutator.generate_stealth_payloads(VulnerabilityClass::BrokenAuthentication, 3);
        assert_eq!(payloads.len(), 3);
        for p in &payloads {
            assert_eq!(
                p.vulnerability_class,
                VulnerabilityClass::BrokenAuthentication
            );
            assert_eq!(p.mutation_strategy, MutationStrategy::Generative);
        }
    }

    #[test]
    fn stealth_rating_derives_debug_clone_copy_partialeq_eq() {
        let high = StealthRating::High;
        let high_clone = high;
        let high_copy = high;
        assert_eq!(high, high_clone);
        assert_eq!(high, high_copy);
        assert_eq!(format!("{:?}", high), "High");
        assert_ne!(StealthRating::High, StealthRating::Low);
        assert_ne!(StealthRating::Medium, StealthRating::Low);
        assert_ne!(StealthRating::High, StealthRating::Medium);
    }

    #[test]
    fn with_bypass_corpus_sets_corpus() {
        let corpus = vec![(
            VulnerabilityClass::SqlInjection,
            vec![BypassPayload {
                raw: "bypass1".to_string(),
                waf_targets: vec!["modsec".to_string()],
                technique: "double-encoding".to_string(),
                stealth_rating: StealthRating::High,
            }],
        )];
        let mutator = PayloadMutator::new().with_bypass_corpus(corpus);
        assert!(mutator.template_count(VulnerabilityClass::SqlInjection) > 0);
    }

    #[test]
    fn generate_payloads_uses_corpus_before_bitflip() {
        let corpus = vec![(
            VulnerabilityClass::SqlInjection,
            vec![
                BypassPayload {
                    raw: "corpus_payload_1".to_string(),
                    waf_targets: vec![],
                    technique: "t1".to_string(),
                    stealth_rating: StealthRating::High,
                },
                BypassPayload {
                    raw: "corpus_payload_2".to_string(),
                    waf_targets: vec![],
                    technique: "t2".to_string(),
                    stealth_rating: StealthRating::Medium,
                },
            ],
        )];
        let mutator = PayloadMutator::new().with_bypass_corpus(corpus);
        let template_count = mutator.template_count(VulnerabilityClass::SqlInjection);
        let payloads =
            mutator.generate_payloads(VulnerabilityClass::SqlInjection, template_count + 2);
        assert_eq!(payloads.len(), template_count + 2);
        assert!(payloads.iter().any(|p| p.raw == "corpus_payload_1"));
        assert!(payloads.iter().any(|p| p.raw == "corpus_payload_2"));
    }

    #[test]
    fn generate_payloads_corpus_fills_gap_then_bitflip() {
        let corpus = vec![(
            VulnerabilityClass::SqlInjection,
            vec![BypassPayload {
                raw: "single_bypass".to_string(),
                waf_targets: vec![],
                technique: "t".to_string(),
                stealth_rating: StealthRating::Low,
            }],
        )];
        let mutator = PayloadMutator::new().with_bypass_corpus(corpus);
        let template_count = mutator.template_count(VulnerabilityClass::SqlInjection);
        let payloads =
            mutator.generate_payloads(VulnerabilityClass::SqlInjection, template_count + 3);
        assert_eq!(payloads.len(), template_count + 3);
        assert!(payloads.iter().any(|p| p.raw == "single_bypass"));
        let bitflip_count = payloads
            .iter()
            .filter(|p| p.mutation_strategy == MutationStrategy::BitFlip)
            .count();
        assert_eq!(bitflip_count, 2);
    }

    #[test]
    fn generate_payloads_with_empty_corpus_falls_through_to_bitflip() {
        let corpus: Vec<(VulnerabilityClass, Vec<BypassPayload>)> = vec![];
        let mutator = PayloadMutator::new().with_bypass_corpus(corpus);
        let template_count = mutator.template_count(VulnerabilityClass::CrlfInjection);
        let payloads =
            mutator.generate_payloads(VulnerabilityClass::CrlfInjection, template_count + 2);
        assert_eq!(payloads.len(), template_count + 2);
        let bitflip_count = payloads
            .iter()
            .filter(|p| p.mutation_strategy == MutationStrategy::BitFlip)
            .count();
        assert_eq!(bitflip_count, 2);
    }

    #[test]
    fn generate_payloads_for_class_with_no_templates_uses_fuzz_base() {
        let mutator = PayloadMutator::new();
        let payloads = mutator.generate_payloads(VulnerabilityClass::BrokenAuthentication, 3);
        assert_eq!(payloads.len(), 3);
        for p in &payloads {
            assert_eq!(p.mutation_strategy, MutationStrategy::BitFlip);
        }
    }

    #[test]
    fn load_bypass_corpus_valid_json() {
        let json = r#"{
            "payloads": {
                "SqlInjection": [
                    {
                        "raw": "' OR sleep(5)--",
                        "waf_targets": ["modsec", "cloudflare"],
                        "technique": "time-based-blind",
                        "stealth_rating": "high"
                    },
                    {
                        "raw": "1 UNION SELECT null--",
                        "waf_targets": ["modsec"],
                        "technique": "union-based",
                        "stealth_rating": "low"
                    }
                ],
                "CrossSiteScripting": [
                    {
                        "raw": "<svg/onload=alert(1)>",
                        "waf_targets": ["akamai"],
                        "technique": "tag-event",
                        "stealth_rating": "medium"
                    }
                ]
            }
        }"#;
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(json.as_bytes()).unwrap();
        let result = load_bypass_corpus(tmpfile.path());
        assert!(result.is_ok());
        let corpus = result.unwrap();
        assert_eq!(corpus.len(), 2);
        let sqli_entry = corpus
            .iter()
            .find(|(c, _)| *c == VulnerabilityClass::SqlInjection);
        assert!(sqli_entry.is_some());
        let (_, sqli_payloads) = sqli_entry.unwrap();
        assert_eq!(sqli_payloads.len(), 2);
        assert_eq!(sqli_payloads[0].raw, "' OR sleep(5)--");
        assert_eq!(sqli_payloads[0].stealth_rating, StealthRating::High);
        assert_eq!(sqli_payloads[0].waf_targets, vec!["modsec", "cloudflare"]);
        assert_eq!(sqli_payloads[0].technique, "time-based-blind");
        assert_eq!(sqli_payloads[1].stealth_rating, StealthRating::Low);
    }

    #[test]
    fn load_bypass_corpus_all_vulnerability_classes() {
        let json = r#"{
            "payloads": {
                "CommandInjection": [{"raw": "a", "waf_targets": [], "technique": "t", "stealth_rating": "low"}],
                "PathTraversal": [{"raw": "b", "waf_targets": [], "technique": "t", "stealth_rating": "low"}],
                "ServerSideRequestForgery": [{"raw": "c", "waf_targets": [], "technique": "t", "stealth_rating": "low"}],
                "InsecureDeserialization": [{"raw": "d", "waf_targets": [], "technique": "t", "stealth_rating": "low"}],
                "BrokenAuthentication": [{"raw": "e", "waf_targets": [], "technique": "t", "stealth_rating": "low"}],
                "BrokenAuthorization": [{"raw": "f", "waf_targets": [], "technique": "t", "stealth_rating": "low"}],
                "SecurityMisconfiguration": [{"raw": "g", "waf_targets": [], "technique": "t", "stealth_rating": "low"}],
                "SensitiveDataExposure": [{"raw": "h", "waf_targets": [], "technique": "t", "stealth_rating": "low"}],
                "ServerSideTemplateInjection": [{"raw": "i", "waf_targets": [], "technique": "t", "stealth_rating": "low"}],
                "HeaderInjection": [{"raw": "j", "waf_targets": [], "technique": "t", "stealth_rating": "low"}],
                "OpenRedirect": [{"raw": "k", "waf_targets": [], "technique": "t", "stealth_rating": "low"}],
                "CrlfInjection": [{"raw": "l", "waf_targets": [], "technique": "t", "stealth_rating": "low"}],
                "KnownVulnerableDependency": [{"raw": "m", "waf_targets": [], "technique": "t", "stealth_rating": "low"}],
                "InsufficientInputValidation": [{"raw": "n", "waf_targets": [], "technique": "t", "stealth_rating": "medium"}]
            }
        }"#;
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(json.as_bytes()).unwrap();
        let result = load_bypass_corpus(tmpfile.path());
        assert!(result.is_ok());
        let corpus = result.unwrap();
        assert_eq!(corpus.len(), 14);
    }

    #[test]
    fn load_bypass_corpus_missing_file() {
        let result = load_bypass_corpus(std::path::Path::new("/nonexistent/file.json"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to read file"));
    }

    #[test]
    fn load_bypass_corpus_invalid_json() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(b"not json at all").unwrap();
        let result = load_bypass_corpus(tmpfile.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to parse JSON"));
    }

    #[test]
    fn load_bypass_corpus_missing_payloads_key() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(b"{}").unwrap();
        let result = load_bypass_corpus(tmpfile.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing or invalid"));
    }

    #[test]
    fn load_bypass_corpus_unknown_class() {
        let json = r#"{"payloads": {"UnknownClass": []}}"#;
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(json.as_bytes()).unwrap();
        let result = load_bypass_corpus(tmpfile.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown vulnerability class"));
    }

    #[test]
    fn load_bypass_corpus_entries_not_array() {
        let json = r#"{"payloads": {"SqlInjection": "not_an_array"}}"#;
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(json.as_bytes()).unwrap();
        let result = load_bypass_corpus(tmpfile.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected array"));
    }

    #[test]
    fn load_bypass_corpus_missing_raw_field() {
        let json = r#"{"payloads": {"SqlInjection": [{"waf_targets": [], "technique": "t", "stealth_rating": "low"}]}}"#;
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(json.as_bytes()).unwrap();
        let result = load_bypass_corpus(tmpfile.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'raw' field"));
    }

    #[test]
    fn load_bypass_corpus_missing_waf_targets() {
        let json = r#"{"payloads": {"SqlInjection": [{"raw": "x", "technique": "t", "stealth_rating": "low"}]}}"#;
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(json.as_bytes()).unwrap();
        let result = load_bypass_corpus(tmpfile.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'waf_targets' field"));
    }

    #[test]
    fn load_bypass_corpus_missing_technique() {
        let json = r#"{"payloads": {"SqlInjection": [{"raw": "x", "waf_targets": [], "stealth_rating": "low"}]}}"#;
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(json.as_bytes()).unwrap();
        let result = load_bypass_corpus(tmpfile.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'technique' field"));
    }

    #[test]
    fn load_bypass_corpus_missing_stealth_rating() {
        let json = r#"{"payloads": {"SqlInjection": [{"raw": "x", "waf_targets": [], "technique": "t"}]}}"#;
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(json.as_bytes()).unwrap();
        let result = load_bypass_corpus(tmpfile.path());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("missing 'stealth_rating' field")
        );
    }

    #[test]
    fn load_bypass_corpus_unknown_stealth_rating() {
        let json = r#"{"payloads": {"SqlInjection": [{"raw": "x", "waf_targets": [], "technique": "t", "stealth_rating": "extreme"}]}}"#;
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(json.as_bytes()).unwrap();
        let result = load_bypass_corpus(tmpfile.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown stealth_rating"));
    }

    #[test]
    fn stealth_payloads_include_corpus_entries() {
        let corpus = vec![(
            VulnerabilityClass::SqlInjection,
            vec![BypassPayload {
                raw: "corpus_stealth_entry".to_string(),
                waf_targets: vec![],
                technique: "t".to_string(),
                stealth_rating: StealthRating::High,
            }],
        )];
        let mutator = PayloadMutator::new().with_bypass_corpus(corpus);
        let template_count = mutator.template_count(VulnerabilityClass::SqlInjection);
        let payloads =
            mutator.generate_stealth_payloads(VulnerabilityClass::SqlInjection, template_count + 1);
        assert_eq!(payloads.len(), template_count + 1);
        assert!(payloads.iter().any(|p| p.raw == "corpus_stealth_entry"));
    }

    #[test]
    fn stealth_payloads_corpus_high_rated_sorted_first() {
        let corpus = vec![(
            VulnerabilityClass::CommandInjection,
            vec![
                BypassPayload {
                    raw: "low_bypass".to_string(),
                    waf_targets: vec![],
                    technique: "t".to_string(),
                    stealth_rating: StealthRating::Low,
                },
                BypassPayload {
                    raw: "high_bypass".to_string(),
                    waf_targets: vec![],
                    technique: "t".to_string(),
                    stealth_rating: StealthRating::High,
                },
            ],
        )];
        let mutator = PayloadMutator::new().with_bypass_corpus(corpus);
        let template_count = mutator.template_count(VulnerabilityClass::CommandInjection);
        let payloads = mutator
            .generate_stealth_payloads(VulnerabilityClass::CommandInjection, template_count + 2);
        let high_pos = payloads.iter().position(|p| p.raw == "high_bypass");
        let low_pos = payloads.iter().position(|p| p.raw == "low_bypass");
        assert!(high_pos.is_some(), "high_bypass should be present");
        assert!(low_pos.is_some(), "low_bypass should be present");
        assert!(
            high_pos.unwrap() < low_pos.unwrap(),
            "high-stealth corpus entry should appear before low-stealth corpus entry"
        );
    }

    #[test]
    fn bypass_payload_debug_and_clone() {
        let bp = BypassPayload {
            raw: "test".to_string(),
            waf_targets: vec!["waf1".to_string()],
            technique: "encoding".to_string(),
            stealth_rating: StealthRating::Medium,
        };
        let cloned = bp.clone();
        assert_eq!(cloned.raw, "test");
        assert_eq!(cloned.stealth_rating, StealthRating::Medium);
        let debug_str = format!("{:?}", bp);
        assert!(debug_str.contains("BypassPayload"));
    }

    #[test]
    fn tagged_payloads_template_origin() {
        let mutator = PayloadMutator::new();
        let payloads = mutator.generate_tagged_payloads(VulnerabilityClass::SqlInjection, 3);
        assert_eq!(payloads.len(), 3);
        for p in &payloads {
            assert_eq!(p.origin, MutationOrigin::Template);
            assert!(!p.payload.is_empty());
        }
    }

    #[test]
    fn tagged_payloads_bitflip_origin() {
        let mutator = PayloadMutator::new();
        let template_count = mutator.template_count(VulnerabilityClass::CrlfInjection);
        let payloads =
            mutator.generate_tagged_payloads(VulnerabilityClass::CrlfInjection, template_count + 3);
        assert_eq!(payloads.len(), template_count + 3);

        let bitflip_count = payloads
            .iter()
            .filter(|p| p.origin == MutationOrigin::BitFlip)
            .count();
        assert_eq!(bitflip_count, 3);
    }

    #[test]
    fn tagged_payloads_bypass_corpus_origin() {
        let corpus = vec![(
            VulnerabilityClass::SqlInjection,
            vec![
                BypassPayload {
                    raw: "corpus_entry_1".to_string(),
                    waf_targets: vec![],
                    technique: "t".to_string(),
                    stealth_rating: StealthRating::High,
                },
                BypassPayload {
                    raw: "corpus_entry_2".to_string(),
                    waf_targets: vec![],
                    technique: "t".to_string(),
                    stealth_rating: StealthRating::Medium,
                },
            ],
        )];
        let mutator = PayloadMutator::new().with_bypass_corpus(corpus);
        let template_count = mutator.template_count(VulnerabilityClass::SqlInjection);
        let payloads =
            mutator.generate_tagged_payloads(VulnerabilityClass::SqlInjection, template_count + 2);
        assert_eq!(payloads.len(), template_count + 2);

        let corpus_payloads: Vec<_> = payloads
            .iter()
            .filter(|p| p.origin == MutationOrigin::BypassCorpus)
            .collect();
        assert_eq!(corpus_payloads.len(), 2);
        assert_eq!(corpus_payloads[0].payload, "corpus_entry_1");
        assert_eq!(corpus_payloads[1].payload, "corpus_entry_2");
    }

    #[test]
    fn mutation_origin_serde_roundtrip() {
        let variants = [
            MutationOrigin::Template,
            MutationOrigin::Generative,
            MutationOrigin::BitFlip,
            MutationOrigin::Boundary,
            MutationOrigin::BypassCorpus,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let deserialized: MutationOrigin = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, deserialized);
        }
    }

    #[test]
    fn generate_nosql_payloads() {
        let mutator = PayloadMutator::new();
        let payloads = mutator.generate_payloads(VulnerabilityClass::NoSqlInjection, 5);
        assert_eq!(payloads.len(), 5);
        for p in &payloads {
            assert_eq!(p.vulnerability_class, VulnerabilityClass::NoSqlInjection);
            assert!(!p.raw.is_empty());
        }
    }

    #[test]
    fn nosql_payloads_contain_mongo_operators() {
        let mutator = PayloadMutator::new();
        let payloads = mutator.generate_payloads(VulnerabilityClass::NoSqlInjection, 12);
        assert!(payloads.iter().any(|p| p.raw.contains("$ne")));
        assert!(payloads.iter().any(|p| p.raw.contains("$gt")));
        assert!(payloads.iter().any(|p| p.raw.contains("$regex")));
        assert!(payloads.iter().any(|p| p.raw.contains("$where")));
    }

    #[test]
    fn nosql_payloads_contain_url_parameter_form() {
        let mutator = PayloadMutator::new();
        let payloads = mutator.generate_payloads(VulnerabilityClass::NoSqlInjection, 12);
        assert!(payloads.iter().any(|p| p.raw.contains("[$ne]=")));
        assert!(payloads.iter().any(|p| p.raw.contains("[$gt]=")));
    }

    #[test]
    fn nosql_payloads_contain_cql_injection() {
        let mutator = PayloadMutator::new();
        let payloads = mutator.generate_payloads(VulnerabilityClass::NoSqlInjection, 12);
        assert!(payloads.iter().any(|p| p.raw.contains("ALLOW FILTERING")));
    }

    #[test]
    fn nosql_template_count() {
        let mutator = PayloadMutator::new();
        assert_eq!(
            mutator.template_count(VulnerabilityClass::NoSqlInjection),
            12
        );
    }
}
