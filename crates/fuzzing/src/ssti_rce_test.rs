use super::ssti_rce::*;

#[test]
fn polyglot_payloads_contains_string_multiplication() {
    assert!(POLYGLOT_PAYLOADS.contains(&"{{7*'7'}}"));
}

#[test]
fn polyglot_payloads_contains_dollar_brace() {
    assert!(POLYGLOT_PAYLOADS.contains(&"${7*7}"));
}

#[test]
fn polyglot_payloads_contains_erb_tag() {
    assert!(POLYGLOT_PAYLOADS.contains(&"<%= 7*7 %>"));
}

#[test]
fn polyglot_payloads_count() {
    assert_eq!(POLYGLOT_PAYLOADS.len(), 6);
}

#[test]
fn engine_display() {
    assert_eq!(SstiTemplateEngine::Jinja2.to_string(), "Jinja2");
    assert_eq!(SstiTemplateEngine::Twig.to_string(), "Twig");
    assert_eq!(SstiTemplateEngine::Freemarker.to_string(), "Freemarker");
    assert_eq!(SstiTemplateEngine::Mako.to_string(), "Mako");
    assert_eq!(SstiTemplateEngine::Velocity.to_string(), "Velocity");
    assert_eq!(SstiTemplateEngine::Pebble.to_string(), "Pebble");
    assert_eq!(SstiTemplateEngine::Smarty.to_string(), "Smarty");
    assert_eq!(SstiTemplateEngine::Thymeleaf.to_string(), "Thymeleaf");
    assert_eq!(SstiTemplateEngine::ERB.to_string(), "ERB");
    assert_eq!(SstiTemplateEngine::Handlebars.to_string(), "Handlebars");
    assert_eq!(SstiTemplateEngine::Unknown.to_string(), "Unknown");
}

#[test]
fn engine_all_returns_eleven() {
    assert_eq!(SstiTemplateEngine::all().len(), 11);
}

#[test]
fn verification_method_display() {
    assert_eq!(
        VerificationMethod::DirectOutput.to_string(),
        "direct_output"
    );
    assert_eq!(VerificationMethod::TimeBased.to_string(), "time_based");
    assert_eq!(VerificationMethod::OobDns.to_string(), "oob_dns");
    assert_eq!(VerificationMethod::OobHttp.to_string(), "oob_http");
}

#[test]
fn identify_engine_jinja2_from_7777777() {
    assert_eq!(identify_engine("7777777"), SstiTemplateEngine::Jinja2);
}

#[test]
fn identify_engine_jinja2_from_response_containing_7777777() {
    assert_eq!(
        identify_engine("result: 7777777 end"),
        SstiTemplateEngine::Jinja2
    );
}

#[test]
fn identify_engine_twig_from_49() {
    assert_eq!(identify_engine("49"), SstiTemplateEngine::Twig);
}

#[test]
fn identify_engine_freemarker_from_keyword() {
    assert_eq!(
        identify_engine("FreeMarker template error"),
        SstiTemplateEngine::Freemarker
    );
}

#[test]
fn identify_engine_mako_from_keyword() {
    assert_eq!(
        identify_engine("Mako runtime error"),
        SstiTemplateEngine::Mako
    );
}

#[test]
fn identify_engine_velocity_from_keyword() {
    assert_eq!(
        identify_engine("Velocity parse error"),
        SstiTemplateEngine::Velocity
    );
}

#[test]
fn identify_engine_pebble_from_keyword() {
    assert_eq!(
        identify_engine("Pebble template"),
        SstiTemplateEngine::Pebble
    );
}

#[test]
fn identify_engine_smarty_from_keyword() {
    assert_eq!(identify_engine("Smarty error"), SstiTemplateEngine::Smarty);
}

#[test]
fn identify_engine_thymeleaf_from_keyword() {
    assert_eq!(
        identify_engine("Thymeleaf processing failed"),
        SstiTemplateEngine::Thymeleaf
    );
}

#[test]
fn identify_engine_erb_from_keyword() {
    assert_eq!(identify_engine("ERB syntax error"), SstiTemplateEngine::ERB);
}

#[test]
fn identify_engine_handlebars_from_keyword() {
    assert_eq!(
        identify_engine("Handlebars parse error"),
        SstiTemplateEngine::Handlebars
    );
}

#[test]
fn identify_engine_unknown_for_random_text() {
    assert_eq!(identify_engine("hello world"), SstiTemplateEngine::Unknown);
}

#[test]
fn identify_engine_unknown_for_empty_string() {
    assert_eq!(identify_engine(""), SstiTemplateEngine::Unknown);
}

#[test]
fn get_rce_payload_jinja2_contains_command() {
    let payload = get_rce_payload(&SstiTemplateEngine::Jinja2, "whoami");
    assert!(payload.contains("whoami"));
    assert!(payload.contains("popen"));
}

#[test]
fn get_rce_payload_twig_contains_command() {
    let payload = get_rce_payload(&SstiTemplateEngine::Twig, "id");
    assert!(payload.contains("id"));
    assert!(payload.contains("filter"));
}

#[test]
fn get_rce_payload_freemarker_contains_command() {
    let payload = get_rce_payload(&SstiTemplateEngine::Freemarker, "id");
    assert!(payload.contains("id"));
    assert!(payload.contains("Execute"));
}

#[test]
fn get_rce_payload_mako_contains_command() {
    let payload = get_rce_payload(&SstiTemplateEngine::Mako, "id");
    assert!(payload.contains("id"));
    assert!(payload.contains("popen"));
}

#[test]
fn get_rce_payload_velocity_contains_command() {
    let payload = get_rce_payload(&SstiTemplateEngine::Velocity, "id");
    assert!(payload.contains("id"));
    assert!(payload.contains("Runtime"));
}

#[test]
fn get_rce_payload_smarty_contains_command() {
    let payload = get_rce_payload(&SstiTemplateEngine::Smarty, "id");
    assert!(payload.contains("id"));
    assert!(payload.contains("system"));
}

#[test]
fn get_rce_payload_thymeleaf_contains_command() {
    let payload = get_rce_payload(&SstiTemplateEngine::Thymeleaf, "id");
    assert!(payload.contains("id"));
    assert!(payload.contains("Runtime"));
}

#[test]
fn get_rce_payload_erb_contains_command() {
    let payload = get_rce_payload(&SstiTemplateEngine::ERB, "id");
    assert!(payload.contains("id"));
    assert!(payload.contains("system"));
}

#[test]
fn get_rce_payload_handlebars_contains_command() {
    let payload = get_rce_payload(&SstiTemplateEngine::Handlebars, "id");
    assert!(payload.contains("id"));
    assert!(payload.contains("execSync"));
}

#[test]
fn get_rce_payload_pebble_contains_command() {
    let payload = get_rce_payload(&SstiTemplateEngine::Pebble, "id");
    assert!(payload.contains("id"));
}

#[test]
fn get_rce_payload_unknown_includes_command() {
    let payload = get_rce_payload(&SstiTemplateEngine::Unknown, "id");
    assert!(payload.contains("id"));
}

#[test]
fn build_exploit_chain_jinja2_three_steps() {
    let chain = build_exploit_chain(&SstiTemplateEngine::Jinja2);
    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0].step, 1);
    assert_eq!(chain[2].step, 3);
}

#[test]
fn build_exploit_chain_twig_three_steps() {
    let chain = build_exploit_chain(&SstiTemplateEngine::Twig);
    assert_eq!(chain.len(), 3);
}

#[test]
fn build_exploit_chain_freemarker_three_steps() {
    let chain = build_exploit_chain(&SstiTemplateEngine::Freemarker);
    assert_eq!(chain.len(), 3);
}

#[test]
fn build_exploit_chain_all_engines_have_steps() {
    for engine in SstiTemplateEngine::all() {
        let chain = build_exploit_chain(engine);
        assert!(
            !chain.is_empty(),
            "no exploit chain for engine {:?}",
            engine
        );
    }
}

#[test]
fn build_exploit_chain_steps_ascending() {
    for engine in SstiTemplateEngine::all() {
        let chain = build_exploit_chain(engine);
        for window in chain.windows(2) {
            assert!(
                window[1].step > window[0].step,
                "steps not ascending for {:?}",
                engine
            );
        }
    }
}

#[test]
fn build_exploit_chain_no_empty_fields() {
    for engine in SstiTemplateEngine::all() {
        for step in build_exploit_chain(engine) {
            assert!(!step.payload.is_empty(), "empty payload in {:?}", engine);
            assert!(
                !step.description.is_empty(),
                "empty description in {:?}",
                engine
            );
            assert!(
                !step.expected_output.is_empty(),
                "empty expected_output in {:?}",
                engine
            );
        }
    }
}

#[test]
fn detect_finds_jinja2() {
    let config = SstiConfig::new("http://127.0.0.1:3000/page", "name");
    let ssti = SstiRce::new(config);
    let result = ssti.detect("http://127.0.0.1:3000/page", "name");
    assert!(result.vulnerable);
    assert_eq!(result.engine, SstiTemplateEngine::Jinja2);
    assert_eq!(result.detection_payload, "{{7*'7'}}");
    assert_eq!(result.response_indicator, "7777777");
}

#[test]
fn verify_rce_confirms_uid_output() {
    let config = SstiConfig::new("http://127.0.0.1:3000/page", "name");
    let ssti = SstiRce::new(config);
    let payload = get_rce_payload(&SstiTemplateEngine::Jinja2, "id");
    let result = ssti.verify_rce("http://127.0.0.1:3000/page", &payload);
    assert!(result.confirmed);
    assert!(result.output.unwrap().contains("uid="));
    assert_eq!(result.method, VerificationMethod::DirectOutput);
}

#[test]
fn verify_rce_fails_for_benign_payload() {
    let config = SstiConfig::new("http://127.0.0.1:3000/page", "name");
    let ssti = SstiRce::new(config);
    let result = ssti.verify_rce("http://127.0.0.1:3000/page", "{{7*7}}");
    assert!(!result.confirmed);
    assert!(result.output.is_none());
}

#[test]
fn config_builder_timeout() {
    let config = SstiConfig::new("http://127.0.0.1:3000/page", "name").with_timeout_ms(10000);
    assert_eq!(config.timeout_ms, 10000);
}

#[test]
fn config_default_timeout() {
    let config = SstiConfig::new("http://127.0.0.1:3000/page", "name");
    assert_eq!(config.timeout_ms, 5000);
}

#[test]
fn engine_signatures_has_jinja2() {
    let sigs = engine_signatures();
    assert_eq!(sigs[&SstiTemplateEngine::Jinja2], "7777777");
}

#[test]
fn engine_signatures_twig_is_49() {
    let sigs = engine_signatures();
    assert_eq!(sigs[&SstiTemplateEngine::Twig], "49");
}

#[test]
fn engine_signatures_covers_all_non_unknown() {
    let sigs = engine_signatures();
    for engine in SstiTemplateEngine::all() {
        if *engine == SstiTemplateEngine::Unknown {
            continue;
        }
        assert!(sigs.contains_key(engine), "no signature for {:?}", engine);
    }
}

#[test]
fn payload_db_has_all_engines() {
    let db = SstiPayloadDb::new();
    assert_eq!(db.engine_count(), 10);
}

#[test]
fn payload_db_total_payloads_above_twenty() {
    let db = SstiPayloadDb::new();
    assert!(
        db.total_payloads() >= 20,
        "expected 20+ payloads, got {}",
        db.total_payloads()
    );
}

#[test]
fn payload_db_jinja2_has_payloads() {
    let db = SstiPayloadDb::new();
    assert!(db.get(&SstiTemplateEngine::Jinja2).len() >= 3);
}

#[test]
fn payload_db_twig_has_payloads() {
    let db = SstiPayloadDb::new();
    assert!(db.get(&SstiTemplateEngine::Twig).len() >= 2);
}

#[test]
fn payload_db_unknown_returns_empty() {
    let db = SstiPayloadDb::new();
    assert!(db.get(&SstiTemplateEngine::Unknown).is_empty());
}

#[test]
fn payload_db_all_payloads_contain_cmd_placeholder() {
    let db = SstiPayloadDb::new();
    for engine in SstiTemplateEngine::all() {
        if *engine == SstiTemplateEngine::Unknown {
            continue;
        }
        for payload in db.get(engine) {
            assert!(
                payload.contains("CMD"),
                "payload for {:?} missing CMD placeholder: {}",
                engine,
                payload
            );
        }
    }
}

#[test]
fn ssti_rce_config_accessor() {
    let config = SstiConfig::new("http://127.0.0.1:3000/page", "q");
    let ssti = SstiRce::new(config);
    assert_eq!(ssti.config().target_url, "http://127.0.0.1:3000/page");
    assert_eq!(ssti.config().param_name, "q");
}
