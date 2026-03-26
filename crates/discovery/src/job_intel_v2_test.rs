use super::job_intel_v2::*;

#[test]
fn extract_tech_stack_detects_languages() {
    let text =
        "We are looking for a senior engineer with experience in Rust, Python, and TypeScript.";
    let techs = extract_tech_stack(text);
    let names: Vec<&str> = techs.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"Rust"), "expected Rust in {:?}", names);
    assert!(names.contains(&"Python"), "expected Python in {:?}", names);
    assert!(
        names.contains(&"TypeScript"),
        "expected TypeScript in {:?}",
        names
    );
    for t in &techs {
        if t.name == "Rust" || t.name == "Python" || t.name == "TypeScript" {
            assert_eq!(t.category, TechCategory::Language);
        }
    }
}

#[test]
fn extract_tech_stack_detects_frameworks() {
    let text = "Our frontend is built with React and Next.js, backend uses Django and FastAPI.";
    let techs = extract_tech_stack(text);
    let names: Vec<&str> = techs.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"React"), "expected React in {:?}", names);
    assert!(
        names.contains(&"Next.js"),
        "expected Next.js in {:?}",
        names
    );
    assert!(names.contains(&"Django"), "expected Django in {:?}", names);
    assert!(
        names.contains(&"FastAPI"),
        "expected FastAPI in {:?}",
        names
    );
}

#[test]
fn extract_tech_stack_detects_cloud_providers() {
    let text = "Deploy on AWS and Azure with multi-cloud strategy.";
    let techs = extract_tech_stack(text);
    let names: Vec<&str> = techs.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"AWS"), "expected AWS in {:?}", names);
    assert!(names.contains(&"Azure"), "expected Azure in {:?}", names);
    for t in &techs {
        if t.name == "AWS" || t.name == "Azure" {
            assert_eq!(t.category, TechCategory::CloudProvider);
        }
    }
}

#[test]
fn extract_tech_stack_detects_databases() {
    let text =
        "Data layer uses PostgreSQL for OLTP and Redis for caching, with Elasticsearch for search.";
    let techs = extract_tech_stack(text);
    let names: Vec<&str> = techs.iter().map(|t| t.name.as_str()).collect();
    assert!(
        names.contains(&"PostgreSQL"),
        "expected PostgreSQL in {:?}",
        names
    );
    assert!(names.contains(&"Redis"), "expected Redis in {:?}", names);
    assert!(
        names.contains(&"Elasticsearch"),
        "expected Elasticsearch in {:?}",
        names
    );
}

#[test]
fn extract_tech_stack_detects_cicd_and_containers() {
    let text =
        "We use GitHub Actions for CI, Terraform for IaC, Docker and Kubernetes for orchestration.";
    let techs = extract_tech_stack(text);
    let names: Vec<&str> = techs.iter().map(|t| t.name.as_str()).collect();
    assert!(
        names.contains(&"GitHub Actions"),
        "expected GitHub Actions in {:?}",
        names
    );
    assert!(
        names.contains(&"Terraform"),
        "expected Terraform in {:?}",
        names
    );
    assert!(names.contains(&"Docker"), "expected Docker in {:?}", names);
    assert!(
        names.contains(&"Kubernetes"),
        "expected Kubernetes in {:?}",
        names
    );
}

#[test]
fn extract_tech_stack_detects_security_tools() {
    let text = "Experience with Burp Suite, Snyk, and SonarQube required for the AppSec role.";
    let techs = extract_tech_stack(text);
    let names: Vec<&str> = techs.iter().map(|t| t.name.as_str()).collect();
    assert!(
        names.contains(&"Burp Suite"),
        "expected Burp Suite in {:?}",
        names
    );
    assert!(names.contains(&"Snyk"), "expected Snyk in {:?}", names);
    assert!(
        names.contains(&"SonarQube"),
        "expected SonarQube in {:?}",
        names
    );
    for t in &techs {
        if t.name == "Burp Suite" || t.name == "Snyk" || t.name == "SonarQube" {
            assert_eq!(t.category, TechCategory::SecurityTool);
        }
    }
}

#[test]
fn extract_tech_stack_detects_monitoring_and_queues() {
    let text = "Monitoring via Datadog and Grafana. Event streaming with Kafka and RabbitMQ.";
    let techs = extract_tech_stack(text);
    let names: Vec<&str> = techs.iter().map(|t| t.name.as_str()).collect();
    assert!(
        names.contains(&"Datadog"),
        "expected Datadog in {:?}",
        names
    );
    assert!(
        names.contains(&"Grafana"),
        "expected Grafana in {:?}",
        names
    );
    assert!(names.contains(&"Kafka"), "expected Kafka in {:?}", names);
    assert!(
        names.contains(&"RabbitMQ"),
        "expected RabbitMQ in {:?}",
        names
    );
}

#[test]
fn extract_tech_stack_empty_input() {
    let techs = extract_tech_stack("");
    assert!(techs.is_empty());
}

#[test]
fn extract_tech_stack_confidence_higher_for_requirement_language() {
    let strong =
        "Must have strong experience with Rust and deep knowledge of Rust systems programming.";
    let weak = "Nice to have: Rust";
    let strong_techs = extract_tech_stack(strong);
    let weak_techs = extract_tech_stack(weak);
    let strong_conf = strong_techs
        .iter()
        .find(|t| t.name == "Rust")
        .unwrap()
        .confidence;
    let weak_conf = weak_techs
        .iter()
        .find(|t| t.name == "Rust")
        .unwrap()
        .confidence;
    assert!(
        strong_conf > weak_conf,
        "strong context ({}) should yield higher confidence than weak ({})",
        strong_conf,
        weak_conf,
    );
}

#[test]
fn infer_security_maturity_minimal_for_bare_posting() {
    let text = "We are hiring a frontend developer to build pretty web pages.";
    let (level, indicators) = infer_security_maturity(text);
    assert_eq!(level, SecurityMaturityLevel::Minimal);
    assert!(indicators.is_empty());
}

#[test]
fn infer_security_maturity_basic_for_some_signals() {
    let text = "Must understand OWASP Top 10, experience with code review practices.";
    let (level, _indicators) = infer_security_maturity(text);
    assert!(
        level >= SecurityMaturityLevel::Basic,
        "expected at least Basic, got {}",
        level,
    );
}

#[test]
fn infer_security_maturity_advanced_or_mature_for_heavy_signals() {
    let text = "SOC 2 Type II compliant environment. ISO 27001 certified. \
                Dedicated security team with red team and blue team exercises. \
                SIEM, EDR, XDR deployed. SAST and DAST in CI/CD pipeline. \
                Incident response playbooks. Bug bounty program. \
                Vulnerability management with CVSS scoring. \
                Zero trust architecture. Threat intelligence feeds. \
                PCI-DSS compliance required. HIPAA regulated data.";
    let (level, indicators) = infer_security_maturity(text);
    assert!(
        level >= SecurityMaturityLevel::Advanced,
        "expected Advanced or Mature, got {}",
        level,
    );
    assert!(
        indicators.len() >= 10,
        "expected many indicators, got {}",
        indicators.len()
    );
}

#[test]
fn infer_security_maturity_detects_compliance_frameworks() {
    let text = "We maintain SOC2 and GDPR compliance, working toward ISO 27001.";
    let (_level, indicators) = infer_security_maturity(text);
    let compliance: Vec<&SecurityIndicator> = indicators
        .iter()
        .filter(|i| i.category == "Compliance")
        .collect();
    assert!(
        compliance.len() >= 2,
        "expected at least 2 compliance indicators, got {:?}",
        compliance
    );
}

#[test]
fn parse_job_posting_json_valid() {
    let json = r#"{
        "title": "Senior Rust Engineer",
        "company": "CyberDefense Corp",
        "location": "San Francisco, CA",
        "description": "Build security tooling in Rust with AWS and Kubernetes.",
        "requirements": ["5+ years Rust", "AWS experience", "Security background"],
        "source_url": "https://jobs.example.com/123",
        "posted_date": "2026-03-15"
    }"#;
    let posting = parse_job_posting_json(json).unwrap();
    assert_eq!(posting.title, "Senior Rust Engineer");
    assert_eq!(posting.company, "CyberDefense Corp");
    assert_eq!(posting.location, "San Francisco, CA");
    assert!(posting.description.contains("Rust"));
    assert_eq!(posting.requirements.len(), 3);
    assert_eq!(
        posting.source_url.as_deref(),
        Some("https://jobs.example.com/123")
    );
    assert_eq!(posting.posted_date.as_deref(), Some("2026-03-15"));
}

#[test]
fn parse_job_posting_json_minimal_fields() {
    let json = r#"{"title": "SWE", "company": "Acme"}"#;
    let posting = parse_job_posting_json(json).unwrap();
    assert_eq!(posting.title, "SWE");
    assert_eq!(posting.company, "Acme");
    assert_eq!(posting.location, "Remote");
    assert!(posting.description.is_empty());
    assert!(posting.requirements.is_empty());
}

#[test]
fn parse_job_posting_json_invalid() {
    let result = parse_job_posting_json("not json at all");
    assert!(result.is_err());
}

#[test]
fn parse_job_posting_json_missing_title() {
    let json = r#"{"company": "Acme"}"#;
    let result = parse_job_posting_json(json);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("title"));
}

#[test]
fn detect_org_signals_headcount_growth() {
    let postings: Vec<JobPosting> = (0..5)
        .map(|i| JobPosting {
            title: format!("Backend Engineer #{}", i),
            company: "GrowthCo".to_string(),
            location: "Remote".to_string(),
            description: "Join our backend team.".to_string(),
            requirements: vec![],
            source_url: None,
            posted_date: None,
        })
        .collect();
    let signals = detect_org_signals(&postings);
    let growth = signals
        .iter()
        .any(|s| matches!(s, OrgSignal::HeadcountGrowth { .. }));
    assert!(growth, "expected HeadcountGrowth signal in {:?}", signals);
}

#[test]
fn detect_org_signals_restructuring() {
    let postings = vec![JobPosting {
        title: "Director of Engineering".to_string(),
        company: "ReorgInc".to_string(),
        location: "NYC".to_string(),
        description: "Lead our engineering reorganization and transformation initiative."
            .to_string(),
        requirements: vec![],
        source_url: None,
        posted_date: None,
    }];
    let signals = detect_org_signals(&postings);
    let restructuring = signals
        .iter()
        .any(|s| matches!(s, OrgSignal::RestructuringIndicator { .. }));
    assert!(
        restructuring,
        "expected RestructuringIndicator in {:?}",
        signals
    );
}

#[test]
fn detect_org_signals_acquisition_hint() {
    let postings = vec![JobPosting {
        title: "Integration Engineer".to_string(),
        company: "BigCo".to_string(),
        location: "Remote".to_string(),
        description: "Help integrate systems from our recent acquisition into the main platform."
            .to_string(),
        requirements: vec![],
        source_url: None,
        posted_date: None,
    }];
    let signals = detect_org_signals(&postings);
    let acq = signals
        .iter()
        .any(|s| matches!(s, OrgSignal::AcquisitionHint { .. }));
    assert!(acq, "expected AcquisitionHint in {:?}", signals);
}

#[test]
fn detect_org_signals_leadership_change() {
    let postings = vec![JobPosting {
        title: "VP of Engineering".to_string(),
        company: "StartupCo".to_string(),
        location: "Remote".to_string(),
        description: "Lead the engineering org.".to_string(),
        requirements: vec![],
        source_url: None,
        posted_date: None,
    }];
    let signals = detect_org_signals(&postings);
    let leadership = signals
        .iter()
        .any(|s| matches!(s, OrgSignal::LeadershipChange { .. }));
    assert!(leadership, "expected LeadershipChange in {:?}", signals);
}

#[test]
fn detect_org_signals_security_team_build() {
    let postings = vec![JobPosting {
        title: "Security Engineer".to_string(),
        company: "FastGrow".to_string(),
        location: "Remote".to_string(),
        description:
            "Join us to build security from the ground up. This is our first security hire."
                .to_string(),
        requirements: vec![],
        source_url: None,
        posted_date: None,
    }];
    let signals = detect_org_signals(&postings);
    let sec_build = signals
        .iter()
        .any(|s| matches!(s, OrgSignal::SecurityTeamBuild { .. }));
    assert!(sec_build, "expected SecurityTeamBuild in {:?}", signals);
}

#[test]
fn detect_org_signals_tech_migration() {
    let postings = vec![JobPosting {
        title: "Platform Engineer".to_string(),
        company: "MigrateCo".to_string(),
        location: "Remote".to_string(),
        description: "Migrate our monolith to a microservice architecture on the cloud."
            .to_string(),
        requirements: vec![],
        source_url: None,
        posted_date: None,
    }];
    let signals = detect_org_signals(&postings);
    let migration = signals
        .iter()
        .any(|s| matches!(s, OrgSignal::TechStackMigration { .. }));
    assert!(migration, "expected TechStackMigration in {:?}", signals);
}

#[test]
fn build_job_intel_report_end_to_end() {
    let postings = vec![
        JobPosting {
            title: "Senior Rust Engineer".to_string(),
            company: "SecureTech".to_string(),
            location: "Remote".to_string(),
            description: "Build security tooling in Rust. Deploy on AWS with Kubernetes and Docker. \
                          SOC2 compliant. Experience with Burp Suite, SAST, DAST. Incident response experience. \
                          OAuth and MFA integration required.".to_string(),
            requirements: vec![
                "5+ years Rust".to_string(),
                "AWS experience".to_string(),
                "OWASP knowledge".to_string(),
            ],
            source_url: None,
            posted_date: None,
        },
        JobPosting {
            title: "Security Engineer".to_string(),
            company: "SecureTech".to_string(),
            location: "Remote".to_string(),
            description: "Join our first security team. Vulnerability management, threat intelligence, \
                          Snyk, SonarQube. PostgreSQL and Redis. GitHub Actions CI. \
                          Datadog monitoring. Kafka event bus.".to_string(),
            requirements: vec![
                "Security background".to_string(),
                "HIPAA experience".to_string(),
            ],
            source_url: None,
            posted_date: None,
        },
    ];

    let report = build_job_intel_report(&postings);
    assert_eq!(report.postings_analyzed, 2);
    assert!(!report.detected_technologies.is_empty());
    assert!(!report.security_indicators.is_empty());
    assert!(!report.compliance_frameworks.is_empty());
    assert!(!report.summary.is_empty());

    let tech_names: Vec<&str> = report
        .detected_technologies
        .iter()
        .map(|t| t.name.as_str())
        .collect();
    assert!(
        tech_names.contains(&"Rust"),
        "expected Rust in {:?}",
        tech_names
    );
    assert!(
        tech_names.contains(&"AWS"),
        "expected AWS in {:?}",
        tech_names
    );

    assert!(
        report.security_maturity >= SecurityMaturityLevel::Intermediate,
        "expected at least Intermediate maturity, got {}",
        report.security_maturity,
    );
}

#[test]
fn classify_tech_risk_missing_layers() {
    let techs = vec![DetectedTech {
        name: "React".to_string(),
        category: TechCategory::Framework,
        confidence: 0.8,
        context_snippet: None,
    }];
    let indicators: Vec<SecurityIndicator> = vec![];
    let signals: Vec<OrgSignal> = vec![];
    let risks = classify_tech_risk(&techs, &indicators, &signals);
    let has_missing = risks
        .iter()
        .any(|r| matches!(r, IntelRisk::MissingSecurityLayer { .. }));
    let has_no_compliance = risks
        .iter()
        .any(|r| matches!(r, IntelRisk::NoComplianceMentioned));
    let has_no_ir = risks
        .iter()
        .any(|r| matches!(r, IntelRisk::NoIncidentResponseIndicated));
    assert!(has_missing, "expected MissingSecurityLayer in {:?}", risks);
    assert!(
        has_no_compliance,
        "expected NoComplianceMentioned in {:?}",
        risks
    );
    assert!(
        has_no_ir,
        "expected NoIncidentResponseIndicated in {:?}",
        risks
    );
}

#[test]
fn classify_tech_risk_single_cloud_vendor() {
    let techs = vec![DetectedTech {
        name: "AWS".to_string(),
        category: TechCategory::CloudProvider,
        confidence: 0.9,
        context_snippet: None,
    }];
    let risks = classify_tech_risk(&techs, &[], &[]);
    let has_vendor_risk = risks
        .iter()
        .any(|r| matches!(r, IntelRisk::OverRelianceOnSingleVendor { vendor } if vendor == "AWS"));
    assert!(
        has_vendor_risk,
        "expected single vendor risk in {:?}",
        risks
    );
}

#[test]
fn classify_tech_risk_rapid_growth_without_security() {
    let techs: Vec<DetectedTech> = vec![];
    let indicators: Vec<SecurityIndicator> = vec![];
    let signals = vec![OrgSignal::HeadcountGrowth {
        department: "Engineering".to_string(),
        open_roles: 10,
    }];
    let risks = classify_tech_risk(&techs, &indicators, &signals);
    let has_rapid = risks
        .iter()
        .any(|r| matches!(r, IntelRisk::RapidGrowthWithoutSecurity));
    assert!(
        has_rapid,
        "expected RapidGrowthWithoutSecurity in {:?}",
        risks
    );
}

#[test]
fn display_impls_produce_nonempty_strings() {
    assert!(!format!("{}", TechCategory::Language).is_empty());
    assert!(!format!("{}", TechCategory::MessageQueue).is_empty());
    assert!(!format!("{}", SecurityMaturityLevel::Mature).is_empty());
    assert!(!format!("{}", SecurityMaturityLevel::Minimal).is_empty());

    let tech = DetectedTech {
        name: "Rust".to_string(),
        category: TechCategory::Language,
        confidence: 0.95,
        context_snippet: None,
    };
    let displayed = format!("{}", tech);
    assert!(displayed.contains("Rust"));
    assert!(displayed.contains("Language"));

    let indicator = SecurityIndicator {
        category: "Compliance".to_string(),
        detail: "SOC 2 mentioned".to_string(),
        weight: 3.0,
    };
    assert!(format!("{}", indicator).contains("SOC 2"));

    let posting = JobPosting {
        title: "SWE".to_string(),
        company: "Acme".to_string(),
        location: "NYC".to_string(),
        description: String::new(),
        requirements: vec![],
        source_url: None,
        posted_date: None,
    };
    let displayed = format!("{}", posting);
    assert!(displayed.contains("SWE"));
    assert!(displayed.contains("Acme"));

    let sig = OrgSignal::HeadcountGrowth {
        department: "Eng".to_string(),
        open_roles: 5,
    };
    assert!(format!("{}", sig).contains("Eng"));

    let risk = IntelRisk::NoComplianceMentioned;
    assert!(!format!("{}", risk).is_empty());

    let report = JobIntelReport {
        postings_analyzed: 1,
        detected_technologies: vec![],
        security_maturity: SecurityMaturityLevel::Basic,
        security_indicators: vec![],
        org_signals: vec![],
        risks: vec![],
        tech_category_counts: std::collections::HashMap::new(),
        compliance_frameworks: vec![],
        summary: "test".to_string(),
    };
    assert!(format!("{}", report).contains("Basic"));
}

#[test]
fn display_impls_for_all_org_signal_variants() {
    let variants: Vec<OrgSignal> = vec![
        OrgSignal::HeadcountGrowth {
            department: "Eng".to_string(),
            open_roles: 3,
        },
        OrgSignal::RestructuringIndicator {
            detail: "reorg".to_string(),
        },
        OrgSignal::AcquisitionHint {
            detail: "merger".to_string(),
        },
        OrgSignal::NewTeamFormation {
            team_name: "Platform".to_string(),
        },
        OrgSignal::LeadershipChange {
            detail: "CTO hire".to_string(),
        },
        OrgSignal::OffshoreExpansion {
            region: "India".to_string(),
        },
        OrgSignal::SecurityTeamBuild {
            detail: "first hire".to_string(),
        },
        OrgSignal::TechStackMigration {
            from_hint: "monolith".to_string(),
            to_hint: "micro".to_string(),
        },
    ];
    for v in variants {
        let s = format!("{}", v);
        assert!(!s.is_empty(), "display for {:?} was empty", v);
    }
}

#[test]
fn display_impls_for_all_intel_risk_variants() {
    let variants: Vec<IntelRisk> = vec![
        IntelRisk::OutdatedTechnology {
            tech: "PHP".to_string(),
            detail: "old".to_string(),
        },
        IntelRisk::MissingSecurityLayer {
            layer: "WAF".to_string(),
        },
        IntelRisk::OverRelianceOnSingleVendor {
            vendor: "AWS".to_string(),
        },
        IntelRisk::RapidGrowthWithoutSecurity,
        IntelRisk::NoComplianceMentioned,
        IntelRisk::WeakAuthenticationSignals,
        IntelRisk::NoIncidentResponseIndicated,
        IntelRisk::LegacyMigrationRisk {
            detail: "migration".to_string(),
        },
    ];
    for v in variants {
        let s = format!("{}", v);
        assert!(!s.is_empty(), "display for {:?} was empty", v);
    }
}
