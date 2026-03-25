use super::ssti_payloads::*;

#[test]
fn test_total_payload_count() {
    assert!(
        ssti_payload_count() >= 100,
        "Expected 100+ SSTI payloads, got {}",
        ssti_payload_count()
    );
}

#[test]
fn test_all_engines_covered() {
    for engine in TemplateEngine::all() {
        let payloads = ssti_payloads_by_engine(*engine);
        assert!(!payloads.is_empty(), "No payloads for engine {:?}", engine);
    }
}

#[test]
fn test_all_phases_covered() {
    for phase in SstiPhase::all() {
        let payloads = ssti_payloads_by_phase(*phase);
        assert!(!payloads.is_empty(), "No payloads for phase {:?}", phase);
    }
}

#[test]
fn test_jinja2_has_rce_payloads() {
    let jinja = ssti_payloads_by_engine(TemplateEngine::Jinja2);
    let rce = jinja.iter().filter(|p| p.phase == SstiPhase::Rce).count();
    assert!(rce >= 5, "Expected 5+ Jinja2 RCE payloads, got {}", rce);
}

#[test]
fn test_twig_has_rce_payloads() {
    let twig = ssti_payloads_by_engine(TemplateEngine::Twig);
    let rce = twig.iter().filter(|p| p.phase == SstiPhase::Rce).count();
    assert!(rce >= 3, "Expected 3+ Twig RCE payloads, got {}", rce);
}

#[test]
fn test_freemarker_has_rce_payloads() {
    let fm = ssti_payloads_by_engine(TemplateEngine::Freemarker);
    let rce = fm.iter().filter(|p| p.phase == SstiPhase::Rce).count();
    assert!(rce >= 3, "Expected 3+ Freemarker RCE payloads, got {}", rce);
}

#[test]
fn test_velocity_has_rce_payloads() {
    let vel = ssti_payloads_by_engine(TemplateEngine::Velocity);
    let rce = vel.iter().filter(|p| p.phase == SstiPhase::Rce).count();
    assert!(rce >= 3, "Expected 3+ Velocity RCE payloads, got {}", rce);
}

#[test]
fn test_erb_has_rce_payloads() {
    let erb = ssti_payloads_by_engine(TemplateEngine::Erb);
    let rce = erb.iter().filter(|p| p.phase == SstiPhase::Rce).count();
    assert!(rce >= 3, "Expected 3+ ERB RCE payloads, got {}", rce);
}

#[test]
fn test_mako_has_rce_payloads() {
    let mako = ssti_payloads_by_engine(TemplateEngine::Mako);
    let rce = mako.iter().filter(|p| p.phase == SstiPhase::Rce).count();
    assert!(rce >= 2, "Expected 2+ Mako RCE payloads, got {}", rce);
}

#[test]
fn test_handlebars_has_rce_payloads() {
    let hb = ssti_payloads_by_engine(TemplateEngine::Handlebars);
    let rce = hb.iter().filter(|p| p.phase == SstiPhase::Rce).count();
    assert!(rce >= 2, "Expected 2+ Handlebars RCE payloads, got {}", rce);
}

#[test]
fn test_pug_has_rce_payloads() {
    let pug = ssti_payloads_by_engine(TemplateEngine::Pug);
    let rce = pug.iter().filter(|p| p.phase == SstiPhase::Rce).count();
    assert!(rce >= 2, "Expected 2+ Pug RCE payloads, got {}", rce);
}

#[test]
fn test_smarty_has_rce_payloads() {
    let smarty = ssti_payloads_by_engine(TemplateEngine::Smarty);
    let rce = smarty.iter().filter(|p| p.phase == SstiPhase::Rce).count();
    assert!(rce >= 2, "Expected 2+ Smarty RCE payloads, got {}", rce);
}

#[test]
fn test_thymeleaf_has_rce_payloads() {
    let thy = ssti_payloads_by_engine(TemplateEngine::Thymeleaf);
    let rce = thy.iter().filter(|p| p.phase == SstiPhase::Rce).count();
    assert!(rce >= 3, "Expected 3+ Thymeleaf RCE payloads, got {}", rce);
}

#[test]
fn test_detection_polyglots_exist() {
    let polyglot = ssti_payloads_by_engine(TemplateEngine::Polyglot);
    assert!(
        polyglot.len() >= 5,
        "Expected 5+ detection polyglots, got {}",
        polyglot.len()
    );
}

#[test]
fn test_rce_payloads_contain_command() {
    let rce = ssti_rce_payloads();
    let has_id_cmd = rce.iter().any(|p| p.payload.contains("id"));
    assert!(
        has_id_cmd,
        "RCE payloads should reference a command like 'id'"
    );
}

#[test]
fn test_exfiltration_payloads_exist() {
    let exfil = ssti_payloads_by_phase(SstiPhase::Exfiltration);
    assert!(
        exfil.len() >= 10,
        "Expected 10+ exfiltration payloads, got {}",
        exfil.len()
    );
}

#[test]
fn test_no_empty_payloads() {
    for payload in all_ssti_payloads() {
        assert!(!payload.payload.is_empty(), "Empty payload found");
        assert!(
            !payload.description.is_empty(),
            "Empty description for payload: {}",
            payload.payload
        );
    }
}

#[test]
fn test_universal_math_probe_exists() {
    let all = all_ssti_payloads();
    let has_7x7 = all.iter().any(|p| p.payload == "{{7*7}}");
    assert!(has_7x7, "Universal {{7*7}} math probe should exist");
}
