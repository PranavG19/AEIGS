use super::*;

fn default_engine() -> InjectionEngine {
    InjectionEngine::new(InjectionConfig::default())
}

#[test]
fn test_default_config_has_all_classes() {
    let config = InjectionConfig::default();
    assert_eq!(config.classes.len(), 7);
    assert!(config.include_time_based);
    assert!(config.include_error_based);
    assert_eq!(config.max_evasion_level, 2);
}

#[test]
fn test_engine_creation() {
    let engine = default_engine();
    assert_eq!(engine.config().classes.len(), 7);
}

#[test]
fn test_generate_all_produces_payloads() {
    let engine = default_engine();
    let payloads = engine.generate_all();
    assert!(
        payloads.len() >= 50,
        "expected 50+ payloads, got {}",
        payloads.len()
    );
}

#[test]
fn test_all_classes_represented() {
    let engine = default_engine();
    let payloads = engine.generate_all();

    let classes: Vec<InjectionClass> = payloads.iter().map(|p| p.class).collect();
    assert!(classes.contains(&InjectionClass::NoSql));
    assert!(classes.contains(&InjectionClass::Ldap));
    assert!(classes.contains(&InjectionClass::Ssti));
    assert!(classes.contains(&InjectionClass::SpEl));
    assert!(classes.contains(&InjectionClass::Ognl));
    assert!(classes.contains(&InjectionClass::JakartaEl));
    assert!(classes.contains(&InjectionClass::Crlf));
}

#[test]
fn test_nosql_payloads() {
    let engine = default_engine();
    let payloads = engine.generate_for_class(InjectionClass::NoSql);

    assert!(payloads.len() >= 10);
    let has_ne = payloads.iter().any(|p| p.payload.contains("$ne"));
    let has_gt = payloads.iter().any(|p| p.payload.contains("$gt"));
    let has_where = payloads.iter().any(|p| p.payload.contains("$where"));
    let has_regex = payloads.iter().any(|p| p.payload.contains("$regex"));
    assert!(has_ne);
    assert!(has_gt);
    assert!(has_where);
    assert!(has_regex);
}

#[test]
fn test_nosql_time_based() {
    let engine = default_engine();
    let payloads = engine.generate_for_class(InjectionClass::NoSql);
    let time_based: Vec<_> = payloads
        .iter()
        .filter(|p| matches!(p.oracle, OracleSignal::TimingDelay(_)))
        .collect();
    assert!(!time_based.is_empty());
}

#[test]
fn test_nosql_no_time_based_when_disabled() {
    let config = InjectionConfig {
        classes: vec![InjectionClass::NoSql],
        include_time_based: false,
        ..Default::default()
    };
    let engine = InjectionEngine::new(config);
    let payloads = engine.generate_for_class(InjectionClass::NoSql);
    let long_sleep = payloads.iter().any(|p| p.variant.contains("sleep-long"));
    assert!(!long_sleep);
}

#[test]
fn test_nosql_query_string_variants() {
    let engine = default_engine();
    let payloads = engine.generate_for_class(InjectionClass::NoSql);
    let query_variants: Vec<_> = payloads
        .iter()
        .filter(|p| p.context_hint.contains("query string"))
        .collect();
    assert!(query_variants.len() >= 3);
}

#[test]
fn test_ldap_payloads() {
    let engine = default_engine();
    let payloads = engine.generate_for_class(InjectionClass::Ldap);

    assert!(payloads.len() >= 7);
    let has_wildcard = payloads.iter().any(|p| p.payload.contains("*)(uid=*)"));
    let has_null = payloads.iter().any(|p| p.payload.contains('\0'));
    let has_blind = payloads.iter().any(|p| p.variant.contains("blind"));
    assert!(has_wildcard);
    assert!(has_null);
    assert!(has_blind);
}

#[test]
fn test_ldap_evasion_variants() {
    let engine = default_engine();
    let payloads = engine.generate_for_class(InjectionClass::Ldap);
    let evasion: Vec<_> = payloads.iter().filter(|p| p.evasion_level >= 1).collect();
    assert!(!evasion.is_empty());
}

#[test]
fn test_ssti_polyglot_probes() {
    let engine = default_engine();
    let payloads = engine.generate_for_class(InjectionClass::Ssti);
    let polyglots: Vec<_> = payloads
        .iter()
        .filter(|p| p.variant.contains("polyglot"))
        .collect();
    assert!(polyglots.len() >= 5);
}

#[test]
fn test_ssti_math_canary() {
    let config = InjectionConfig {
        math_canary_a: 7,
        math_canary_b: 11,
        ..Default::default()
    };
    let engine = InjectionEngine::new(config);
    let payloads = engine.generate_for_class(InjectionClass::Ssti);

    let math_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| matches!(p.oracle, OracleSignal::MathResult(ref v) if v == "77"))
        .collect();
    assert!(!math_payloads.is_empty());
}

#[test]
fn test_ssti_string_concat() {
    let engine = default_engine();
    let payloads = engine.generate_for_class(InjectionClass::Ssti);
    let concat: Vec<_> = payloads
        .iter()
        .filter(|p| p.variant.contains("concat"))
        .collect();
    assert!(concat.len() >= 2);
    for p in &concat {
        assert!(matches!(p.oracle, OracleSignal::StringConcat(_)));
    }
}

#[test]
fn test_ssti_error_based() {
    let engine = default_engine();
    let payloads = engine.generate_for_class(InjectionClass::Ssti);
    let error_based: Vec<_> = payloads
        .iter()
        .filter(|p| matches!(p.oracle, OracleSignal::ErrorMessage(_)))
        .collect();
    assert!(error_based.len() >= 2);
}

#[test]
fn test_ssti_no_error_when_disabled() {
    let config = InjectionConfig {
        classes: vec![InjectionClass::Ssti],
        include_error_based: false,
        ..Default::default()
    };
    let engine = InjectionEngine::new(config);
    let payloads = engine.generate_for_class(InjectionClass::Ssti);
    let error_based: Vec<_> = payloads
        .iter()
        .filter(|p| matches!(p.oracle, OracleSignal::ErrorMessage(_)))
        .collect();
    assert!(error_based.is_empty());
}

#[test]
fn test_ssti_evasion_levels() {
    let config = InjectionConfig {
        classes: vec![InjectionClass::Ssti],
        max_evasion_level: 2,
        ..Default::default()
    };
    let engine = InjectionEngine::new(config);
    let payloads = engine.generate_for_class(InjectionClass::Ssti);
    let level_1: Vec<_> = payloads.iter().filter(|p| p.evasion_level == 1).collect();
    let level_2: Vec<_> = payloads.iter().filter(|p| p.evasion_level == 2).collect();
    assert!(!level_1.is_empty());
    assert!(!level_2.is_empty());
}

#[test]
fn test_ssti_no_high_evasion_when_limited() {
    let config = InjectionConfig {
        classes: vec![InjectionClass::Ssti],
        max_evasion_level: 0,
        ..Default::default()
    };
    let engine = InjectionEngine::new(config);
    let payloads = engine.generate_for_class(InjectionClass::Ssti);
    let high_evasion: Vec<_> = payloads.iter().filter(|p| p.evasion_level > 0).collect();
    assert!(high_evasion.is_empty());
}

#[test]
fn test_spel_payloads() {
    let engine = default_engine();
    let payloads = engine.generate_for_class(InjectionClass::SpEl);

    assert!(payloads.len() >= 6);
    let has_runtime = payloads.iter().any(|p| p.payload.contains("Runtime"));
    let has_processbuilder = payloads
        .iter()
        .any(|p| p.payload.contains("ProcessBuilder"));
    assert!(has_runtime);
    assert!(has_processbuilder);
}

#[test]
fn test_spel_math_canary() {
    let engine = default_engine();
    let payloads = engine.generate_for_class(InjectionClass::SpEl);
    let math: Vec<_> = payloads
        .iter()
        .filter(|p| matches!(p.oracle, OracleSignal::MathResult(_)))
        .collect();
    assert!(math.len() >= 2); // #{} and ${}
}

#[test]
fn test_ognl_payloads() {
    let engine = default_engine();
    let payloads = engine.generate_for_class(InjectionClass::Ognl);

    assert!(payloads.len() >= 5);
    let has_runtime = payloads.iter().any(|p| p.payload.contains("Runtime"));
    let has_context = payloads.iter().any(|p| p.payload.contains("#context"));
    assert!(has_runtime);
    assert!(has_context);
}

#[test]
fn test_jakarta_el_payloads() {
    let engine = default_engine();
    let payloads = engine.generate_for_class(InjectionClass::JakartaEl);

    assert!(payloads.len() >= 4);
    let has_forname = payloads.iter().any(|p| p.payload.contains("forName"));
    assert!(has_forname);
}

#[test]
fn test_crlf_payloads() {
    let engine = default_engine();
    let payloads = engine.generate_for_class(InjectionClass::Crlf);

    assert!(payloads.len() >= 8);
    let has_raw = payloads.iter().any(|p| p.payload.contains("\r\n"));
    let has_encoded = payloads.iter().any(|p| p.payload.contains("%0d%0a"));
    let has_cookie = payloads.iter().any(|p| p.payload.contains("Set-Cookie"));
    let has_xss = payloads.iter().any(|p| p.payload.contains("<script>"));
    assert!(has_raw);
    assert!(has_encoded);
    assert!(has_cookie);
    assert!(has_xss);
}

#[test]
fn test_crlf_canary_in_payloads() {
    let config = InjectionConfig {
        classes: vec![InjectionClass::Crlf],
        string_canary: "test_marker".to_string(),
        ..Default::default()
    };
    let engine = InjectionEngine::new(config);
    let payloads = engine.generate_for_class(InjectionClass::Crlf);
    for p in &payloads {
        assert!(
            p.payload.contains("test_marker"),
            "payload {} missing canary",
            p.variant
        );
    }
}

#[test]
fn test_identify_template_engine_jinja2() {
    assert_eq!(
        InjectionEngine::identify_template_engine("TemplateSyntaxError in /app"),
        Some(TemplateEngine::Jinja2),
    );
}

#[test]
fn test_identify_template_engine_twig() {
    assert_eq!(
        InjectionEngine::identify_template_engine("Twig_Error_Syntax"),
        Some(TemplateEngine::Twig),
    );
}

#[test]
fn test_identify_template_engine_freemarker() {
    assert_eq!(
        InjectionEngine::identify_template_engine("freemarker.core.ParseException"),
        Some(TemplateEngine::Freemarker),
    );
}

#[test]
fn test_identify_template_engine_none() {
    assert_eq!(
        InjectionEngine::identify_template_engine("200 OK no template info"),
        None,
    );
}

#[test]
fn test_identify_template_engine_case_insensitive() {
    assert_eq!(
        InjectionEngine::identify_template_engine("VELOCITY template error"),
        Some(TemplateEngine::Velocity),
    );
}

#[test]
fn test_ssti_for_jinja2() {
    let engine = default_engine();
    let payloads = engine.ssti_for_engine(TemplateEngine::Jinja2);
    assert!(payloads.len() >= 3);
    let has_rce = payloads.iter().any(|p| p.variant.contains("rce"));
    let has_config = payloads.iter().any(|p| p.variant.contains("config"));
    assert!(has_rce);
    assert!(has_config);
}

#[test]
fn test_ssti_for_twig() {
    let engine = default_engine();
    let payloads = engine.ssti_for_engine(TemplateEngine::Twig);
    assert!(payloads.len() >= 2);
    let has_filter = payloads.iter().any(|p| p.payload.contains("filter"));
    assert!(has_filter);
}

#[test]
fn test_ssti_for_freemarker() {
    let engine = default_engine();
    let payloads = engine.ssti_for_engine(TemplateEngine::Freemarker);
    assert!(payloads.len() >= 2);
}

#[test]
fn test_ssti_for_velocity() {
    let engine = default_engine();
    let payloads = engine.ssti_for_engine(TemplateEngine::Velocity);
    assert!(!payloads.is_empty());
    let has_set = payloads.iter().any(|p| p.payload.contains("#set"));
    assert!(has_set);
}

#[test]
fn test_ssti_for_thymeleaf() {
    let engine = default_engine();
    let payloads = engine.ssti_for_engine(TemplateEngine::Thymeleaf);
    assert!(!payloads.is_empty());
    let has_spel = payloads.iter().any(|p| p.payload.contains("__$"));
    assert!(has_spel);
}

#[test]
fn test_ssti_for_erb() {
    let engine = default_engine();
    let payloads = engine.ssti_for_engine(TemplateEngine::Erb);
    assert!(payloads.len() >= 2);
    let has_system = payloads.iter().any(|p| p.payload.contains("system"));
    assert!(has_system);
}

#[test]
fn test_ssti_for_smarty() {
    let engine = default_engine();
    let payloads = engine.ssti_for_engine(TemplateEngine::Smarty);
    assert!(payloads.len() >= 2);
}

#[test]
fn test_ssti_for_handlebars() {
    let engine = default_engine();
    let payloads = engine.ssti_for_engine(TemplateEngine::Handlebars);
    assert!(!payloads.is_empty());
    let has_proto = payloads.iter().any(|p| p.variant.contains("proto"));
    assert!(has_proto);
}

#[test]
fn test_ssti_for_mako() {
    let engine = default_engine();
    let payloads = engine.ssti_for_engine(TemplateEngine::Mako);
    assert!(!payloads.is_empty());
}

#[test]
fn test_ssti_for_pug() {
    let engine = default_engine();
    let payloads = engine.ssti_for_engine(TemplateEngine::Pug);
    assert!(!payloads.is_empty());
    let has_require = payloads.iter().any(|p| p.payload.contains("require"));
    assert!(has_require);
}

#[test]
fn test_analyze_positive_results() {
    let engine = default_engine();
    let payloads = engine.generate_for_class(InjectionClass::Ssti);

    let results: Vec<InjectionProbeResult> = payloads
        .iter()
        .enumerate()
        .map(|(i, _)| InjectionProbeResult {
            oracle_matched: i == 0,
            evidence: if i == 0 {
                "98042249".to_string()
            } else {
                String::new()
            },
            endpoint: "/api/render".to_string(),
            response_time_ms: 50,
        })
        .collect();

    let findings = analyze_injection_results(&payloads, &results);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].class, InjectionClass::Ssti);
    assert_eq!(findings[0].severity, InjectionSeverity::Critical);
}

#[test]
fn test_analyze_no_matches() {
    let engine = default_engine();
    let payloads = engine.generate_for_class(InjectionClass::Ldap);
    let results: Vec<InjectionProbeResult> = payloads
        .iter()
        .map(|_| InjectionProbeResult {
            oracle_matched: false,
            evidence: String::new(),
            endpoint: "/api/search".to_string(),
            response_time_ms: 20,
        })
        .collect();

    let findings = analyze_injection_results(&payloads, &results);
    assert!(findings.is_empty());
}

#[test]
fn test_analyze_nosql_severity() {
    let engine = default_engine();
    let payloads = engine.generate_for_class(InjectionClass::NoSql);

    let results: Vec<InjectionProbeResult> = payloads
        .iter()
        .map(|_| InjectionProbeResult {
            oracle_matched: true,
            evidence: "all matched".to_string(),
            endpoint: "/api/login".to_string(),
            response_time_ms: 50,
        })
        .collect();

    let findings = analyze_injection_results(&payloads, &results);
    let critical: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == InjectionSeverity::Critical)
        .collect();
    let high: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == InjectionSeverity::High)
        .collect();
    assert!(!critical.is_empty(), "should have critical for $where");
    assert!(!high.is_empty(), "should have high for bypass");
}

#[test]
fn test_analyze_crlf_severity() {
    let engine = default_engine();
    let payloads = engine.generate_for_class(InjectionClass::Crlf);

    let results: Vec<InjectionProbeResult> = payloads
        .iter()
        .map(|_| InjectionProbeResult {
            oracle_matched: true,
            evidence: "header injected".to_string(),
            endpoint: "/redirect".to_string(),
            response_time_ms: 10,
        })
        .collect();

    let findings = analyze_injection_results(&payloads, &results);
    let high: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == InjectionSeverity::High)
        .collect();
    let medium: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == InjectionSeverity::Medium)
        .collect();
    let low: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == InjectionSeverity::Low)
        .collect();
    assert!(!high.is_empty(), "XSS via splitting should be high");
    assert!(!medium.is_empty(), "cookie injection should be medium");
    assert!(!low.is_empty(), "basic header inject should be low");
}

#[test]
fn test_injection_class_display() {
    assert_eq!(format!("{}", InjectionClass::NoSql), "NoSQL");
    assert_eq!(format!("{}", InjectionClass::Ldap), "LDAP");
    assert_eq!(format!("{}", InjectionClass::Ssti), "SSTI");
    assert_eq!(format!("{}", InjectionClass::SpEl), "SpEL");
    assert_eq!(format!("{}", InjectionClass::Ognl), "OGNL");
    assert_eq!(format!("{}", InjectionClass::JakartaEl), "Jakarta EL");
    assert_eq!(format!("{}", InjectionClass::Crlf), "CRLF");
}

#[test]
fn test_template_engine_display() {
    assert_eq!(format!("{}", TemplateEngine::Jinja2), "Jinja2");
    assert_eq!(format!("{}", TemplateEngine::Freemarker), "FreeMarker");
    assert_eq!(format!("{}", TemplateEngine::Erb), "ERB");
}

#[test]
fn test_oracle_signal_display() {
    assert_eq!(
        format!("{}", OracleSignal::MathResult("77".into())),
        "math=77"
    );
    assert_eq!(
        format!("{}", OracleSignal::TimingDelay(5000)),
        "delay>=5000ms"
    );
    assert_eq!(
        format!("{}", OracleSignal::StatusCodeChange),
        "status code changed"
    );
}

#[test]
fn test_severity_ordering() {
    assert!(InjectionSeverity::Low < InjectionSeverity::Medium);
    assert!(InjectionSeverity::Medium < InjectionSeverity::High);
    assert!(InjectionSeverity::High < InjectionSeverity::Critical);
}

#[test]
fn test_severity_display() {
    assert_eq!(format!("{}", InjectionSeverity::Critical), "Critical");
    assert_eq!(format!("{}", InjectionSeverity::Low), "Low");
}

#[test]
fn test_single_class_config() {
    let config = InjectionConfig {
        classes: vec![InjectionClass::Crlf],
        ..Default::default()
    };
    let engine = InjectionEngine::new(config);
    let payloads = engine.generate_all();
    for p in &payloads {
        assert_eq!(p.class, InjectionClass::Crlf);
    }
}

#[test]
fn test_payload_has_context_hint() {
    let engine = default_engine();
    let payloads = engine.generate_all();
    for p in &payloads {
        assert!(
            !p.context_hint.is_empty(),
            "payload {} missing context hint",
            p.variant
        );
    }
}

#[test]
fn test_payload_has_variant_name() {
    let engine = default_engine();
    let payloads = engine.generate_all();
    for p in &payloads {
        assert!(!p.variant.is_empty(), "payload missing variant name");
    }
}

#[test]
fn test_all_engines_covered_by_ssti_for() {
    let engine = default_engine();
    let engines = [
        TemplateEngine::Jinja2,
        TemplateEngine::Twig,
        TemplateEngine::Freemarker,
        TemplateEngine::Velocity,
        TemplateEngine::Thymeleaf,
        TemplateEngine::Mako,
        TemplateEngine::Pug,
        TemplateEngine::Erb,
        TemplateEngine::Smarty,
        TemplateEngine::Handlebars,
    ];
    for te in &engines {
        let payloads = engine.ssti_for_engine(*te);
        assert!(!payloads.is_empty(), "no payloads for {te}");
    }
}

#[test]
fn test_spel_evasion_level_1() {
    let config = InjectionConfig {
        classes: vec![InjectionClass::SpEl],
        max_evasion_level: 1,
        ..Default::default()
    };
    let engine = InjectionEngine::new(config);
    let payloads = engine.generate_for_class(InjectionClass::SpEl);
    let evasion: Vec<_> = payloads.iter().filter(|p| p.evasion_level == 1).collect();
    assert!(!evasion.is_empty());
}

#[test]
fn test_spel_no_evasion_when_level_0() {
    let config = InjectionConfig {
        classes: vec![InjectionClass::SpEl],
        max_evasion_level: 0,
        ..Default::default()
    };
    let engine = InjectionEngine::new(config);
    let payloads = engine.generate_for_class(InjectionClass::SpEl);
    let evasion: Vec<_> = payloads.iter().filter(|p| p.evasion_level > 0).collect();
    assert!(evasion.is_empty());
}

#[test]
fn test_total_payload_count() {
    let engine = default_engine();
    let payloads = engine.generate_all();
    // NoSQL(13) + LDAP(9) + SSTI(~14) + SpEL(7) + OGNL(7) + JakartaEL(5) + CRLF(10) = ~65+
    assert!(payloads.len() >= 60, "total payloads: {}", payloads.len());
}
