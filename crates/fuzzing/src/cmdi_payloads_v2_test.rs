use super::cmdi_payloads_v2::*;

#[test]
fn test_total_payload_count() {
    assert!(
        cmdi_v2_payload_count() >= 200,
        "Expected 200+ CmdI V2 payloads, got {}",
        cmdi_v2_payload_count()
    );
}

#[test]
fn test_linux_payloads_minimum() {
    let linux = cmdi_v2_payloads_by_os(CmdiOs::Linux);
    assert!(
        linux.len() >= 100,
        "Expected 100+ Linux payloads, got {}",
        linux.len()
    );
}

#[test]
fn test_windows_payloads_minimum() {
    let win = cmdi_v2_payloads_by_os(CmdiOs::Windows);
    assert!(
        win.len() >= 50,
        "Expected 50+ Windows payloads, got {}",
        win.len()
    );
}

#[test]
fn test_macos_payloads_minimum() {
    let mac = cmdi_v2_payloads_by_os(CmdiOs::MacOs);
    assert!(
        mac.len() >= 30,
        "Expected 30+ macOS payloads, got {}",
        mac.len()
    );
}

#[test]
fn test_all_os_covered() {
    for os in CmdiOs::all() {
        let payloads = cmdi_v2_payloads_by_os(*os);
        assert!(!payloads.is_empty(), "No payloads for OS {:?}", os);
    }
}

#[test]
fn test_all_contexts_covered() {
    for ctx in CmdiContext::all() {
        let payloads = cmdi_v2_payloads_by_context(*ctx);
        assert!(!payloads.is_empty(), "No payloads for context {:?}", ctx);
    }
}

#[test]
fn test_all_techniques_covered() {
    for tech in CmdiTechnique::all() {
        let payloads = cmdi_v2_payloads_by_technique(*tech);
        assert!(!payloads.is_empty(), "No payloads for technique {:?}", tech);
    }
}

#[test]
fn test_waf_bypass_payloads_exist() {
    let bypass = cmdi_v2_waf_bypass_payloads();
    assert!(
        bypass.len() >= 25,
        "Expected 25+ WAF bypass payloads, got {}",
        bypass.len()
    );
}

#[test]
fn test_blind_time_payloads_exist() {
    let blind = cmdi_v2_payloads_by_technique(CmdiTechnique::BlindTimeBased);
    assert!(
        blind.len() >= 5,
        "Expected 5+ time-based blind payloads, got {}",
        blind.len()
    );
}

#[test]
fn test_blind_dns_payloads_exist() {
    let dns = cmdi_v2_payloads_by_technique(CmdiTechnique::BlindDns);
    assert!(
        dns.len() >= 5,
        "Expected 5+ DNS-based blind payloads, got {}",
        dns.len()
    );
}

#[test]
fn test_blind_file_write_payloads_exist() {
    let fw = cmdi_v2_payloads_by_technique(CmdiTechnique::BlindFileWrite);
    assert!(
        fw.len() >= 4,
        "Expected 4+ file-write blind payloads, got {}",
        fw.len()
    );
}

#[test]
fn test_ifs_trick_payloads() {
    let ifs = cmdi_v2_payloads_by_technique(CmdiTechnique::WafBypassIfsTrick);
    assert!(
        ifs.len() >= 3,
        "Expected 3+ IFS trick payloads, got {}",
        ifs.len()
    );
}

#[test]
fn test_wildcard_payloads() {
    let wild = cmdi_v2_payloads_by_technique(CmdiTechnique::WafBypassWildcard);
    assert!(
        wild.len() >= 3,
        "Expected 3+ wildcard payloads, got {}",
        wild.len()
    );
}

#[test]
fn test_brace_expansion_payloads() {
    let brace = cmdi_v2_payloads_by_technique(CmdiTechnique::WafBypassBraceExpansion);
    assert!(
        brace.len() >= 3,
        "Expected 3+ brace expansion payloads, got {}",
        brace.len()
    );
}

#[test]
fn test_argument_injection_payloads() {
    let arg = cmdi_v2_payloads_by_technique(CmdiTechnique::ArgumentInjection);
    assert!(
        arg.len() >= 3,
        "Expected 3+ argument injection payloads, got {}",
        arg.len()
    );
}

#[test]
fn test_no_empty_payloads() {
    for payload in all_cmdi_v2_payloads() {
        assert!(!payload.payload.is_empty(), "Empty payload found");
        assert!(
            !payload.description.is_empty(),
            "Empty description for payload: {}",
            payload.payload
        );
    }
}

#[test]
fn test_linux_contains_classic_separators() {
    let linux = cmdi_v2_payloads_by_os(CmdiOs::Linux);
    let payloads: Vec<&str> = linux.iter().map(|p| p.payload).collect();
    assert!(payloads.contains(&"; id"));
    assert!(payloads.contains(&"| id"));
    assert!(payloads.contains(&"`id`"));
    assert!(payloads.contains(&"$(id)"));
}

#[test]
fn test_windows_contains_classic_separators() {
    let win = cmdi_v2_payloads_by_os(CmdiOs::Windows);
    let payloads: Vec<&str> = win.iter().map(|p| p.payload).collect();
    assert!(payloads.contains(&"& whoami"));
    assert!(payloads.contains(&"| whoami"));
}
