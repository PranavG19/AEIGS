use super::financial_intel_v2::*;

#[test]
fn test_edgar_filing_type_from_str_standard_forms() {
    assert_eq!(
        EdgarFilingType::from_edgar_str("10-K"),
        EdgarFilingType::Form10K
    );
    assert_eq!(
        EdgarFilingType::from_edgar_str("10-Q"),
        EdgarFilingType::Form10Q
    );
    assert_eq!(
        EdgarFilingType::from_edgar_str("8-K"),
        EdgarFilingType::Form8K
    );
    assert_eq!(
        EdgarFilingType::from_edgar_str("DEF 14A"),
        EdgarFilingType::Def14A
    );
    assert_eq!(
        EdgarFilingType::from_edgar_str("S-1"),
        EdgarFilingType::FormS1
    );
    assert_eq!(
        EdgarFilingType::from_edgar_str("13F-HR"),
        EdgarFilingType::Form13F
    );
    assert_eq!(EdgarFilingType::from_edgar_str("4"), EdgarFilingType::Form4);
    assert_eq!(
        EdgarFilingType::from_edgar_str("SC 13D"),
        EdgarFilingType::Sc13D
    );
    assert_eq!(
        EdgarFilingType::from_edgar_str("SC 13G"),
        EdgarFilingType::Sc13G
    );
    assert_eq!(
        EdgarFilingType::from_edgar_str("DEFA14A"),
        EdgarFilingType::Proxy
    );
}

#[test]
fn test_edgar_filing_type_amendments() {
    assert_eq!(
        EdgarFilingType::from_edgar_str("10-K/A"),
        EdgarFilingType::Form10K
    );
    assert_eq!(
        EdgarFilingType::from_edgar_str("10-Q/A"),
        EdgarFilingType::Form10Q
    );
    assert_eq!(
        EdgarFilingType::from_edgar_str("8-K/A"),
        EdgarFilingType::Form8K
    );
    assert_eq!(
        EdgarFilingType::from_edgar_str("S-1/A"),
        EdgarFilingType::FormS1
    );
    assert_eq!(
        EdgarFilingType::from_edgar_str("4/A"),
        EdgarFilingType::Form4
    );
    assert_eq!(
        EdgarFilingType::from_edgar_str("SC 13D/A"),
        EdgarFilingType::Sc13D
    );
}

#[test]
fn test_edgar_filing_type_unknown_returns_other() {
    assert_eq!(
        EdgarFilingType::from_edgar_str("NPORT-P"),
        EdgarFilingType::Other
    );
    assert_eq!(EdgarFilingType::from_edgar_str(""), EdgarFilingType::Other);
    assert_eq!(
        EdgarFilingType::from_edgar_str("XYZZY"),
        EdgarFilingType::Other
    );
}

#[test]
fn test_edgar_filing_type_display() {
    assert_eq!(EdgarFilingType::Form10K.to_string(), "10-K (Annual Report)");
    assert_eq!(
        EdgarFilingType::Form10Q.to_string(),
        "10-Q (Quarterly Report)"
    );
    assert_eq!(EdgarFilingType::Form8K.to_string(), "8-K (Current Report)");
    assert_eq!(
        EdgarFilingType::Def14A.to_string(),
        "DEF 14A (Proxy Statement)"
    );
    assert_eq!(
        EdgarFilingType::FormS1.to_string(),
        "S-1 (Registration Statement)"
    );
    assert_eq!(
        EdgarFilingType::Form13F.to_string(),
        "13F-HR (Institutional Holdings)"
    );
    assert_eq!(
        EdgarFilingType::Sc13D.to_string(),
        "SC 13D (Beneficial Ownership)"
    );
    assert_eq!(EdgarFilingType::Other.to_string(), "Other Filing");
}

#[test]
fn test_edgar_filing_type_form_str_roundtrip() {
    let types = [
        EdgarFilingType::Form10K,
        EdgarFilingType::Form10Q,
        EdgarFilingType::Form8K,
        EdgarFilingType::Def14A,
        EdgarFilingType::FormS1,
        EdgarFilingType::Form13F,
        EdgarFilingType::Form4,
        EdgarFilingType::Sc13D,
        EdgarFilingType::Sc13G,
    ];
    for ft in types {
        let s = ft.edgar_form_str();
        assert_eq!(
            EdgarFilingType::from_edgar_str(s),
            ft,
            "roundtrip failed for {:?}",
            ft
        );
    }
}

#[test]
fn test_build_edgar_search_url_basic() {
    let url = build_edgar_search_url("Apple Inc");
    assert!(url.contains("efts.sec.gov"));
    assert!(url.contains("Apple"));
    assert!(url.contains("Inc"));
    assert!(url.contains("forms=10-K"));
}

#[test]
fn test_build_edgar_search_url_special_chars() {
    let url = build_edgar_search_url("Johnson & Johnson");
    assert!(url.contains("Johnson"));
    assert!(url.contains("%26"));
}

#[test]
fn test_build_filing_index_url_pads_cik() {
    let url = build_filing_index_url("320193");
    assert!(url.contains("CIK0000320193.json"));
    assert!(url.starts_with("https://data.sec.gov/submissions/"));
}

#[test]
fn test_build_filing_index_url_already_padded() {
    let url = build_filing_index_url("0000320193");
    assert!(url.contains("CIK0000320193.json"));
}

#[test]
fn test_build_xbrl_facts_url() {
    let url = build_xbrl_facts_url("789019");
    assert!(url.contains("CIK0000789019.json"));
    assert!(url.contains("xbrl/companyfacts"));
}

#[test]
fn test_build_filing_document_url() {
    let url = build_filing_document_url("320193", "0000320193-24-000081", "aapl-20240101.htm");
    assert!(url.contains("Archives/edgar/data/0000320193"));
    assert!(url.contains("aapl-20240101.htm"));
    assert!(!url.contains("--"));
}

#[test]
fn test_parse_edgar_company_search_efts_format() {
    let json = r#"{
        "hits": {
            "total": {"value": 1},
            "hits": [
                {
                    "_source": {
                        "entity_id": "320193",
                        "entity_name": "Apple Inc.",
                        "tickers": "AAPL",
                        "sic": "3571",
                        "sic_description": "Electronic Computers",
                        "state_of_incorporation": "CA"
                    }
                }
            ]
        }
    }"#;
    let companies = parse_edgar_company_search(json);
    assert_eq!(companies.len(), 1);
    assert_eq!(companies[0].cik, "320193");
    assert_eq!(companies[0].name, "Apple Inc.");
    assert_eq!(companies[0].ticker, Some("AAPL".to_string()));
    assert_eq!(companies[0].sic_code, Some("3571".to_string()));
    assert_eq!(companies[0].state_of_incorporation, Some("CA".to_string()));
}

#[test]
fn test_parse_edgar_company_search_submissions_format() {
    let json = r#"{
        "cik": "789019",
        "entityName": "MICROSOFT CORP",
        "name": "MICROSOFT CORP",
        "tickers": ["MSFT"],
        "sic": "7372",
        "sicDescription": "Prepackaged Software",
        "stateOfIncorporation": "WA",
        "fiscalYearEnd": "0630",
        "filings": {
            "recent": {
                "form": ["10-K", "10-Q"],
                "filingDate": ["2024-07-30", "2024-04-25"]
            }
        }
    }"#;
    let companies = parse_edgar_company_search(json);
    assert_eq!(companies.len(), 1);
    assert_eq!(companies[0].cik, "789019");
    assert_eq!(companies[0].name, "MICROSOFT CORP");
    assert_eq!(companies[0].ticker, Some("MSFT".to_string()));
    assert_eq!(
        companies[0].sic_description,
        Some("Prepackaged Software".to_string())
    );
    assert_eq!(companies[0].fiscal_year_end, Some("0630".to_string()));
    assert_eq!(companies[0].filing_count, 2);
}

#[test]
fn test_parse_edgar_company_search_invalid_json() {
    let companies = parse_edgar_company_search("this is not json at all");
    assert!(companies.is_empty());
}

#[test]
fn test_parse_edgar_company_search_empty_hits() {
    let json = r#"{"hits": {"total": {"value": 0}, "hits": []}}"#;
    let companies = parse_edgar_company_search(json);
    assert!(companies.is_empty());
}

#[test]
fn test_parse_edgar_company_search_multiple_results() {
    let json = r#"{
        "hits": {
            "total": {"value": 2},
            "hits": [
                {
                    "_source": {
                        "entity_id": "320193",
                        "entity_name": "Apple Inc.",
                        "tickers": "AAPL"
                    }
                },
                {
                    "_source": {
                        "entity_id": "1600033",
                        "entity_name": "Apple Hospitality REIT Inc.",
                        "tickers": "APLE"
                    }
                }
            ]
        }
    }"#;
    let companies = parse_edgar_company_search(json);
    assert_eq!(companies.len(), 2);
    assert_eq!(companies[0].name, "Apple Inc.");
    assert_eq!(companies[1].name, "Apple Hospitality REIT Inc.");
}

#[test]
fn test_parse_filing_index_full() {
    let json = r#"{
        "cik": "320193",
        "entityName": "Apple Inc.",
        "name": "Apple Inc.",
        "filings": {
            "recent": {
                "accessionNumber": ["0000320193-24-000081", "0000320193-24-000050", "0000320193-24-000030"],
                "filingDate": ["2024-11-01", "2024-08-02", "2024-05-03"],
                "form": ["10-K", "10-Q", "8-K"],
                "primaryDocument": ["aapl-20240928.htm", "aapl-20240629.htm", "aapl-20240501.htm"],
                "primaryDocDescription": ["10-K", "10-Q", "8-K"],
                "fileNumber": ["001-36743", "001-36743", "001-36743"],
                "filmNumber": ["", "", ""],
                "items": ["", "", "2.02,9.01"],
                "size": [12345678, 8765432, 654321]
            }
        }
    }"#;
    let filings = parse_filing_index(json, "320193");
    assert_eq!(filings.len(), 3);

    assert_eq!(filings[0].filing_type, EdgarFilingType::Form10K);
    assert_eq!(filings[0].filing_date, "2024-11-01");
    assert_eq!(filings[0].accession_number, "0000320193-24-000081");
    assert_eq!(filings[0].company_name, "Apple Inc.");
    assert_eq!(filings[0].company_cik, "320193");
    assert!(!filings[0].is_amendment);
    assert_eq!(filings[0].size_bytes, Some(12345678));

    assert_eq!(filings[1].filing_type, EdgarFilingType::Form10Q);

    assert_eq!(filings[2].filing_type, EdgarFilingType::Form8K);
    assert_eq!(
        filings[2].items,
        vec!["2.02".to_string(), "9.01".to_string()]
    );
}

#[test]
fn test_parse_filing_index_invalid_json() {
    let filings = parse_filing_index("not json", "320193");
    assert!(filings.is_empty());
}

#[test]
fn test_parse_filing_index_empty_filings() {
    let json = r#"{
        "cik": "320193",
        "name": "Apple Inc.",
        "filings": {
            "recent": {
                "form": [],
                "filingDate": [],
                "accessionNumber": [],
                "primaryDocument": [],
                "primaryDocDescription": []
            }
        }
    }"#;
    let filings = parse_filing_index(json, "320193");
    assert!(filings.is_empty());
}

#[test]
fn test_parse_filing_index_detects_amendments() {
    let json = r#"{
        "name": "Test Corp",
        "filings": {
            "recent": {
                "form": ["10-K/A"],
                "filingDate": ["2024-03-15"],
                "accessionNumber": ["0001234567-24-000001"],
                "primaryDocument": ["test.htm"],
                "primaryDocDescription": ["10-K/A"]
            }
        }
    }"#;
    let filings = parse_filing_index(json, "1234567");
    assert_eq!(filings.len(), 1);
    assert!(filings[0].is_amendment);
    assert_eq!(filings[0].filing_type, EdgarFilingType::Form10K);
}

#[test]
fn test_extract_subsidiaries_tabular_format() {
    let exhibit = r#"
EXHIBIT 21

Subsidiaries of Apple Inc.

Name of Subsidiary                          Jurisdiction of Incorporation
--------------------------                  -----------------------------
Apple Operations International Ltd.         Ireland                        100
Apple Sales International Ltd.              Ireland                        100
Apple Distribution International Ltd.       Ireland
Braeburn Capital Inc.                       Nevada                         100
"#;
    let subs = extract_subsidiaries_from_exhibit21(exhibit);
    assert!(
        subs.len() >= 2,
        "expected at least 2 subsidiaries, got {}",
        subs.len()
    );

    let ireland_subs: Vec<_> = subs
        .iter()
        .filter(|s| {
            s.jurisdiction
                .as_ref()
                .map(|j| j.contains("Ireland"))
                .unwrap_or(false)
        })
        .collect();
    assert!(!ireland_subs.is_empty(), "should find Ireland subsidiaries");
}

#[test]
fn test_extract_subsidiaries_inline_format() {
    let exhibit = r#"
The following is a list of subsidiaries:

Alphabet Holdings LLC, a limited liability company incorporated in Delaware
Google Cloud Japan G.K., a corporation organized in Japan
Waymo LLC, a limited liability company formed in the State of Delaware
Verily Life Sciences LLC, an LLC incorporated in Delaware
"#;
    let subs = extract_subsidiaries_from_exhibit21(exhibit);
    assert!(
        subs.len() >= 2,
        "expected at least 2 subsidiaries from inline format, got {}",
        subs.len()
    );
}

#[test]
fn test_extract_subsidiaries_with_entity_suffixes() {
    let exhibit = r#"
1. Amazon Web Services Inc. (Washington) 100%
2. Whole Foods Market Inc. (Texas) 100%
3. Zappos.com LLC (Nevada) 100%
4. Ring LLC (Delaware) wholly-owned
5. MGM Holdings Inc. (Delaware) 100%
"#;
    let subs = extract_subsidiaries_from_exhibit21(exhibit);
    assert!(
        subs.len() >= 3,
        "expected at least 3 subsidiaries with suffixes, got {}",
        subs.len()
    );

    let wholly_owned: Vec<_> = subs
        .iter()
        .filter(|s| s.ownership_percentage == Some(100.0))
        .collect();
    assert!(
        wholly_owned.len() >= 2,
        "expected at least 2 wholly-owned subsidiaries, got {}",
        wholly_owned.len()
    );
}

#[test]
fn test_extract_subsidiaries_skips_headers() {
    let exhibit = r#"
EXHIBIT 21
Subsidiaries of the Registrant
The following is a list
Name                     Jurisdiction
---                      ---
Acme Corp.               Delaware                100
"#;
    let subs = extract_subsidiaries_from_exhibit21(exhibit);
    let header_as_sub = subs
        .iter()
        .any(|s| s.name.to_lowercase().contains("exhibit") || s.name.to_lowercase() == "name");
    assert!(!header_as_sub, "should not include headers as subsidiaries");
}

#[test]
fn test_extract_subsidiaries_deduplicates() {
    let exhibit = r#"
1. Acme Corp. (Delaware) 100%
2. Acme Corp. (Delaware) 100%
3. Beta LLC (Nevada) 100%
"#;
    let subs = extract_subsidiaries_from_exhibit21(exhibit);
    let acme_count = subs
        .iter()
        .filter(|s| s.name.to_lowercase().contains("acme"))
        .count();
    assert_eq!(acme_count, 1, "duplicate Acme Corp should be deduplicated");
}

#[test]
fn test_extract_subsidiaries_indirect_ownership() {
    let exhibit = r#"
1. Alpha Holdings Inc. (Delaware) 100%
2. Beta Services LLC (Delaware) indirectly owned 80%
"#;
    let subs = extract_subsidiaries_from_exhibit21(exhibit);
    let indirect: Vec<_> = subs.iter().filter(|s| !s.is_direct_subsidiary).collect();
    assert!(
        !indirect.is_empty(),
        "should identify at least one indirect subsidiary"
    );
}

#[test]
fn test_build_ownership_chain_direct_only() {
    let subs = vec![
        SubsidiaryInfo {
            name: "Sub A Inc.".to_string(),
            jurisdiction: Some("Delaware".to_string()),
            ownership_percentage: Some(100.0),
            parent_name: None,
            is_direct_subsidiary: true,
            raw_line: "Sub A Inc. Delaware 100%".to_string(),
        },
        SubsidiaryInfo {
            name: "Sub B LLC".to_string(),
            jurisdiction: Some("Nevada".to_string()),
            ownership_percentage: Some(80.0),
            parent_name: None,
            is_direct_subsidiary: true,
            raw_line: "Sub B LLC Nevada 80%".to_string(),
        },
    ];
    let chains = build_ownership_chain("Parent Corp", &subs);
    assert_eq!(chains.len(), 2);
    assert_eq!(chains[0].ultimate_parent, "Parent Corp");
    assert_eq!(chains[0].chain[0].entity_name, "Sub A Inc.");
    assert_eq!(chains[0].total_effective_ownership, Some(100.0));
    assert_eq!(chains[1].total_effective_ownership, Some(80.0));
}

#[test]
fn test_build_ownership_chain_with_indirect() {
    let subs = vec![
        SubsidiaryInfo {
            name: "Holding Co LLC".to_string(),
            jurisdiction: Some("Delaware".to_string()),
            ownership_percentage: Some(100.0),
            parent_name: None,
            is_direct_subsidiary: true,
            raw_line: "Holding Co LLC".to_string(),
        },
        SubsidiaryInfo {
            name: "Operating Co Inc.".to_string(),
            jurisdiction: Some("California".to_string()),
            ownership_percentage: Some(75.0),
            parent_name: Some("Holding Co LLC".to_string()),
            is_direct_subsidiary: false,
            raw_line: "Operating Co Inc.".to_string(),
        },
    ];
    let chains = build_ownership_chain("Megacorp Inc.", &subs);
    assert_eq!(chains.len(), 1);
    assert_eq!(chains[0].chain.len(), 2);
    assert_eq!(
        chains[0].chain[0].relationship,
        OwnershipRelationship::DirectSubsidiary
    );
    assert_eq!(
        chains[0].chain[1].relationship,
        OwnershipRelationship::IndirectSubsidiary
    );
    let effective = chains[0].total_effective_ownership.unwrap();
    assert!(
        (effective - 75.0).abs() < 0.01,
        "effective ownership should be 100% * 75% = 75%, got {}",
        effective
    );
}

#[test]
fn test_build_ownership_chain_orphan_indirect() {
    let subs = vec![SubsidiaryInfo {
        name: "Orphan Sub Ltd.".to_string(),
        jurisdiction: Some("UK".to_string()),
        ownership_percentage: Some(60.0),
        parent_name: Some("Unknown Intermediate".to_string()),
        is_direct_subsidiary: false,
        raw_line: "Orphan Sub Ltd.".to_string(),
    }];
    let chains = build_ownership_chain("Top Corp", &subs);
    assert_eq!(chains.len(), 1);
    assert_eq!(chains[0].chain[0].entity_name, "Orphan Sub Ltd.");
    assert_eq!(chains[0].total_effective_ownership, Some(60.0));
}

#[test]
fn test_build_ownership_chain_empty_subs() {
    let chains = build_ownership_chain("Solo Corp", &[]);
    assert!(chains.is_empty());
}

#[test]
fn test_classify_filing_risk_routine() {
    let filing = make_test_filing(EdgarFilingType::Form10Q, false, vec![]);
    assert_eq!(classify_filing_risk(&filing), FilingRisk::Routine);

    let filing = make_test_filing(EdgarFilingType::Form13F, false, vec![]);
    assert_eq!(classify_filing_risk(&filing), FilingRisk::Routine);

    let filing = make_test_filing(EdgarFilingType::Other, false, vec![]);
    assert_eq!(classify_filing_risk(&filing), FilingRisk::Routine);
}

#[test]
fn test_classify_filing_risk_informational() {
    let filing = make_test_filing(EdgarFilingType::Form10K, false, vec![]);
    assert_eq!(classify_filing_risk(&filing), FilingRisk::Informational);

    let filing = make_test_filing(EdgarFilingType::Form4, false, vec![]);
    assert_eq!(classify_filing_risk(&filing), FilingRisk::Informational);

    let filing = make_test_filing(EdgarFilingType::Def14A, false, vec![]);
    assert_eq!(classify_filing_risk(&filing), FilingRisk::Informational);
}

#[test]
fn test_classify_filing_risk_elevated_amendments() {
    let filing = make_test_filing(EdgarFilingType::Form10K, true, vec![]);
    assert_eq!(classify_filing_risk(&filing), FilingRisk::Elevated);

    let filing = make_test_filing(EdgarFilingType::Form10Q, true, vec![]);
    assert_eq!(classify_filing_risk(&filing), FilingRisk::Elevated);

    let filing = make_test_filing(EdgarFilingType::Sc13G, false, vec![]);
    assert_eq!(classify_filing_risk(&filing), FilingRisk::Elevated);
}

#[test]
fn test_classify_filing_risk_significant() {
    let filing = make_test_filing(EdgarFilingType::Form8K, false, vec!["1.01".to_string()]);
    assert_eq!(classify_filing_risk(&filing), FilingRisk::Significant);

    let filing = make_test_filing(EdgarFilingType::Form8K, false, vec!["5.02".to_string()]);
    assert_eq!(classify_filing_risk(&filing), FilingRisk::Significant);

    let filing = make_test_filing(EdgarFilingType::FormS1, false, vec![]);
    assert_eq!(classify_filing_risk(&filing), FilingRisk::Significant);
}

#[test]
fn test_classify_filing_risk_critical() {
    let filing = make_test_filing(EdgarFilingType::Sc13D, false, vec![]);
    assert_eq!(classify_filing_risk(&filing), FilingRisk::Critical);
}

#[test]
fn test_filing_risk_ordering() {
    assert!(FilingRisk::Routine < FilingRisk::Informational);
    assert!(FilingRisk::Informational < FilingRisk::Elevated);
    assert!(FilingRisk::Elevated < FilingRisk::Significant);
    assert!(FilingRisk::Significant < FilingRisk::Critical);
}

#[test]
fn test_filing_risk_display() {
    assert_eq!(FilingRisk::Routine.to_string(), "Routine");
    assert_eq!(FilingRisk::Informational.to_string(), "Informational");
    assert_eq!(FilingRisk::Elevated.to_string(), "Elevated");
    assert_eq!(FilingRisk::Significant.to_string(), "Significant");
    assert_eq!(FilingRisk::Critical.to_string(), "Critical");
}

#[test]
fn test_build_financial_intel_report_basic() {
    let company = EdgarCompany {
        cik: "320193".to_string(),
        name: "Apple Inc.".to_string(),
        ticker: Some("AAPL".to_string()),
        sic_code: Some("3571".to_string()),
        sic_description: Some("Electronic Computers".to_string()),
        state_of_incorporation: Some("CA".to_string()),
        fiscal_year_end: Some("0930".to_string()),
        filing_count: 3,
    };
    let filings = vec![
        make_test_filing(EdgarFilingType::Form10K, false, vec![]),
        make_test_filing(EdgarFilingType::Form10Q, false, vec![]),
        make_test_filing(EdgarFilingType::Sc13D, false, vec![]),
    ];
    let report = build_financial_intel_report(company.clone(), filings, None, vec![]);
    assert_eq!(report.company.cik, "320193");
    assert_eq!(report.filings.len(), 3);
    assert!(report.subsidiaries.is_empty());
    assert_eq!(report.overall_risk, FilingRisk::Critical);
    assert!(report.summary.contains("Apple Inc."));
    assert!(report.summary.contains("3 recent filings"));
}

#[test]
fn test_build_financial_intel_report_with_exhibit21() {
    let company = EdgarCompany {
        cik: "1234567".to_string(),
        name: "Test Corp".to_string(),
        ticker: None,
        sic_code: None,
        sic_description: None,
        state_of_incorporation: None,
        fiscal_year_end: None,
        filing_count: 0,
    };
    let exhibit = r#"
1. Test Sub Inc. (Delaware) 100%
2. Test International Ltd. (Ireland) 80%
"#;
    let report = build_financial_intel_report(company, vec![], Some(exhibit), vec![]);
    assert!(!report.subsidiaries.is_empty());
    assert!(!report.ownership_chains.is_empty());
}

#[test]
fn test_build_financial_intel_report_with_holdings() {
    let company = EdgarCompany {
        cik: "789019".to_string(),
        name: "Microsoft Corp".to_string(),
        ticker: Some("MSFT".to_string()),
        sic_code: None,
        sic_description: None,
        state_of_incorporation: None,
        fiscal_year_end: None,
        filing_count: 0,
    };
    let holdings = vec![
        InvestorHolding {
            investor_name: "Vanguard Group".to_string(),
            investor_cik: Some("102909".to_string()),
            shares_held: 500_000_000,
            value_usd: Some(200_000_000_000),
            percentage_of_class: Some(8.5),
            filing_type: EdgarFilingType::Form13F,
            filing_date: "2024-08-14".to_string(),
            is_new_position: false,
        },
        InvestorHolding {
            investor_name: "BlackRock Inc".to_string(),
            investor_cik: Some("1364742".to_string()),
            shares_held: 450_000_000,
            value_usd: Some(180_000_000_000),
            percentage_of_class: Some(7.2),
            filing_type: EdgarFilingType::Form13F,
            filing_date: "2024-08-14".to_string(),
            is_new_position: false,
        },
    ];
    let report = build_financial_intel_report(company, vec![], None, holdings);
    assert_eq!(report.investor_holdings.len(), 2);
    assert!(report.summary.contains("2 investor holdings"));
    assert!(report.summary.contains("950000000 total shares"));
}

#[test]
fn test_edgar_company_display() {
    let company = EdgarCompany {
        cik: "320193".to_string(),
        name: "Apple Inc.".to_string(),
        ticker: Some("AAPL".to_string()),
        sic_code: None,
        sic_description: None,
        state_of_incorporation: None,
        fiscal_year_end: None,
        filing_count: 0,
    };
    let display = format!("{}", company);
    assert!(display.contains("Apple Inc."));
    assert!(display.contains("320193"));
    assert!(display.contains("AAPL"));
}

#[test]
fn test_edgar_company_display_no_ticker() {
    let company = EdgarCompany {
        cik: "1234567".to_string(),
        name: "Private Corp".to_string(),
        ticker: None,
        sic_code: None,
        sic_description: None,
        state_of_incorporation: None,
        fiscal_year_end: None,
        filing_count: 0,
    };
    let display = format!("{}", company);
    assert!(display.contains("Private Corp"));
    assert!(!display.contains("["));
}

#[test]
fn test_edgar_filing_display() {
    let filing = EdgarFiling {
        accession_number: "0000320193-24-000081".to_string(),
        filing_type: EdgarFilingType::Form10K,
        filing_type_raw: "10-K".to_string(),
        filing_date: "2024-11-01".to_string(),
        primary_document: "aapl.htm".to_string(),
        primary_doc_description: "10-K".to_string(),
        company_cik: "320193".to_string(),
        company_name: "Apple Inc.".to_string(),
        file_number: None,
        film_number: None,
        items: vec![],
        size_bytes: None,
        is_amendment: false,
    };
    let display = format!("{}", filing);
    assert!(display.contains("2024-11-01"));
    assert!(display.contains("Apple Inc."));
    assert!(display.contains("10-K"));
}

#[test]
fn test_subsidiary_info_display() {
    let sub = SubsidiaryInfo {
        name: "Acme International Ltd.".to_string(),
        jurisdiction: Some("Cayman Islands".to_string()),
        ownership_percentage: Some(100.0),
        parent_name: None,
        is_direct_subsidiary: true,
        raw_line: "Acme International Ltd.  Cayman Islands  100".to_string(),
    };
    let display = format!("{}", sub);
    assert!(display.contains("Acme International Ltd."));
    assert!(display.contains("100.0%"));
    assert!(display.contains("Cayman Islands"));
}

#[test]
fn test_ownership_chain_display() {
    let chain = OwnershipChain {
        ultimate_parent: "Parent Corp".to_string(),
        chain: vec![
            OwnershipLink {
                entity_name: "Holding LLC".to_string(),
                ownership_percentage: Some(100.0),
                relationship: OwnershipRelationship::DirectSubsidiary,
            },
            OwnershipLink {
                entity_name: "Operating Inc.".to_string(),
                ownership_percentage: Some(75.0),
                relationship: OwnershipRelationship::IndirectSubsidiary,
            },
        ],
        total_effective_ownership: Some(75.0),
    };
    let display = format!("{}", chain);
    assert!(display.contains("Parent Corp"));
    assert!(display.contains("Holding LLC"));
    assert!(display.contains("Operating Inc."));
    assert!(display.contains("effective: 75.0%"));
}

#[test]
fn test_ownership_relationship_display() {
    assert_eq!(
        OwnershipRelationship::DirectSubsidiary.to_string(),
        "direct subsidiary"
    );
    assert_eq!(
        OwnershipRelationship::IndirectSubsidiary.to_string(),
        "indirect subsidiary"
    );
    assert_eq!(
        OwnershipRelationship::JointVenture.to_string(),
        "joint venture"
    );
    assert_eq!(OwnershipRelationship::Affiliate.to_string(), "affiliate");
    assert_eq!(
        OwnershipRelationship::BeneficialOwner.to_string(),
        "beneficial owner"
    );
    assert_eq!(
        OwnershipRelationship::InsiderHolder.to_string(),
        "insider holder"
    );
}

#[test]
fn test_investor_holding_display() {
    let holding = InvestorHolding {
        investor_name: "Vanguard Group".to_string(),
        investor_cik: Some("102909".to_string()),
        shares_held: 500_000_000,
        value_usd: Some(200_000_000_000),
        percentage_of_class: Some(8.5),
        filing_type: EdgarFilingType::Form13F,
        filing_date: "2024-08-14".to_string(),
        is_new_position: false,
    };
    let display = format!("{}", holding);
    assert!(display.contains("Vanguard Group"));
    assert!(display.contains("500000000 shares"));
    assert!(display.contains("8.50%"));
    assert!(display.contains("$200000000000"));
}

#[test]
fn test_financial_intel_report_display() {
    let company = EdgarCompany {
        cik: "320193".to_string(),
        name: "Apple Inc.".to_string(),
        ticker: Some("AAPL".to_string()),
        sic_code: None,
        sic_description: None,
        state_of_incorporation: None,
        fiscal_year_end: None,
        filing_count: 1,
    };
    let report = build_financial_intel_report(company, vec![], None, vec![]);
    let display = format!("{}", report);
    assert!(display.contains("Financial Intelligence Report"));
    assert!(display.contains("Apple Inc."));
    assert!(display.contains("Overall risk:"));
}

fn make_test_filing(
    filing_type: EdgarFilingType,
    is_amendment: bool,
    items: Vec<String>,
) -> EdgarFiling {
    let raw = if is_amendment {
        format!("{}/A", filing_type.edgar_form_str())
    } else {
        filing_type.edgar_form_str().to_string()
    };
    EdgarFiling {
        accession_number: format!("0001234567-24-{:06}", rand_seq()),
        filing_type,
        filing_type_raw: raw,
        filing_date: "2024-06-15".to_string(),
        primary_document: "test.htm".to_string(),
        primary_doc_description: "Test filing".to_string(),
        company_cik: "1234567".to_string(),
        company_name: "Test Corp".to_string(),
        file_number: None,
        film_number: None,
        items,
        size_bytes: Some(1024),
        is_amendment,
    }
}

static TEST_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn rand_seq() -> u64 {
    TEST_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
