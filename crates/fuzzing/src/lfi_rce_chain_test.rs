use super::lfi_rce_chain::*;

#[test]
fn lfi_paths_contains_etc_passwd() {
    assert!(LFI_PATHS.contains(&"/etc/passwd"));
}

#[test]
fn lfi_paths_contains_windows_path() {
    assert!(LFI_PATHS.iter().any(|p| p.contains("Windows")));
}

#[test]
fn lfi_paths_contains_proc_self() {
    assert!(LFI_PATHS.iter().any(|p| p.contains("/proc/self")));
}

#[test]
fn log_paths_contains_apache() {
    assert!(LOG_PATHS.iter().any(|p| p.contains("apache")));
}

#[test]
fn log_paths_contains_nginx() {
    assert!(LOG_PATHS.iter().any(|p| p.contains("nginx")));
}

#[test]
fn log_paths_contains_httpd() {
    assert!(LOG_PATHS.iter().any(|p| p.contains("httpd")));
}

#[test]
fn encoding_bypasses_not_empty() {
    assert!(!ENCODING_BYPASSES.is_empty());
    assert!(ENCODING_BYPASSES.len() >= 10);
}

#[test]
fn encoding_bypasses_contain_double_encode() {
    assert!(ENCODING_BYPASSES
        .iter()
        .any(|b| b.contains("%252f") || b.contains("%252e")));
}

#[test]
fn encoding_bypasses_contain_null_byte() {
    assert!(ENCODING_BYPASSES
        .iter()
        .any(|b| b.contains("%00") || b.contains("\\0")));
}

#[test]
fn tech_stack_display() {
    assert_eq!(TechStack::PHP.to_string(), "PHP");
    assert_eq!(TechStack::Python.to_string(), "Python");
    assert_eq!(TechStack::Java.to_string(), "Java");
    assert_eq!(TechStack::NodeJs.to_string(), "Node.js");
    assert_eq!(TechStack::Ruby.to_string(), "Ruby");
    assert_eq!(TechStack::Unknown.to_string(), "Unknown");
}

#[test]
fn tech_stack_all_returns_six() {
    assert_eq!(TechStack::all().len(), 6);
}

#[test]
fn rce_method_display() {
    assert_eq!(RceMethod::LogPoison.to_string(), "log_poison");
    assert_eq!(RceMethod::ProcSelfFd.to_string(), "proc_self_fd");
    assert_eq!(RceMethod::TmpFile.to_string(), "tmp_file");
    assert_eq!(RceMethod::PhpSession.to_string(), "php_session");
    assert_eq!(RceMethod::PhpFilter.to_string(), "php_filter");
    assert_eq!(
        RceMethod::PharDeserialization.to_string(),
        "phar_deserialization"
    );
}

#[test]
fn config_builder_defaults() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    assert_eq!(config.target_url, "http://127.0.0.1:3000/page");
    assert_eq!(config.param_name, "file");
    assert_eq!(config.max_depth, 10);
    assert_eq!(config.timeout_ms, 5000);
    assert!(config.tech_stack.is_none());
}

#[test]
fn config_builder_with_max_depth() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file").with_max_depth(20);
    assert_eq!(config.max_depth, 20);
}

#[test]
fn config_builder_with_timeout_ms() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file").with_timeout_ms(10000);
    assert_eq!(config.timeout_ms, 10000);
}

#[test]
fn config_builder_with_tech_stack() {
    let config =
        LfiRceConfig::new("http://127.0.0.1:3000/page", "file").with_tech_stack(TechStack::PHP);
    assert_eq!(config.tech_stack, Some(TechStack::PHP));
}

#[test]
fn detect_lfi_finds_etc_passwd() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    let result = chain.detect_lfi("http://127.0.0.1:3000/page", "file");
    assert!(result.vulnerable);
    assert_eq!(result.confirmed_path, Some("/etc/passwd".to_string()));
    assert_eq!(result.os, OsType::Linux);
}

#[test]
fn detect_lfi_returns_os_linux_for_unix_paths() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    let result = chain.detect_lfi("http://127.0.0.1:3000/page", "file");
    assert_eq!(result.os, OsType::Linux);
}

#[test]
fn attempt_log_poison_succeeds_on_access_log() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    let log_paths = &["/var/log/apache2/access.log"];
    let result = chain.attempt_log_poison("http://127.0.0.1:3000/page", log_paths);
    assert!(result.poisoned);
    assert_eq!(result.log_path, "/var/log/apache2/access.log");
    assert!(result.injected_payload.contains("<?php"));
}

#[test]
fn attempt_log_poison_fails_on_unknown_path() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    let log_paths = &["/var/log/custom/app.log"];
    let result = chain.attempt_log_poison("http://127.0.0.1:3000/page", log_paths);
    assert!(!result.poisoned);
}

#[test]
fn attempt_log_poison_payload_contains_system() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    let log_paths = &["/var/log/nginx/access.log"];
    let result = chain.attempt_log_poison("http://127.0.0.1:3000/page", log_paths);
    assert!(result.injected_payload.contains("system"));
}

#[test]
fn include_poisoned_log_returns_rce_result() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    let result =
        chain.include_poisoned_log("http://127.0.0.1:3000/page", "/var/log/apache2/access.log");
    assert!(result.executed);
    assert!(result.output.is_some());
    assert_eq!(result.method, RceMethod::LogPoison);
}

#[test]
fn include_poisoned_log_proc_path_uses_proc_method() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    let result = chain.include_poisoned_log("http://127.0.0.1:3000/page", "/proc/self/fd/2");
    assert_eq!(result.method, RceMethod::ProcSelfFd);
}

#[test]
fn verify_rce_true_for_uid_output() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    let rce = RceResult {
        executed: true,
        output: Some("uid=33(www-data) gid=33(www-data)".into()),
        method: RceMethod::LogPoison,
    };
    assert!(chain.verify_rce(&rce));
}

#[test]
fn verify_rce_false_for_no_output() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    let rce = RceResult {
        executed: false,
        output: None,
        method: RceMethod::LogPoison,
    };
    assert!(!chain.verify_rce(&rce));
}

#[test]
fn verify_rce_false_for_irrelevant_output() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    let rce = RceResult {
        executed: true,
        output: Some("404 Not Found".into()),
        method: RceMethod::LogPoison,
    };
    assert!(!chain.verify_rce(&rce));
}

#[test]
fn select_chain_php_returns_steps() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    let steps = chain.select_chain(&TechStack::PHP);
    assert!(steps.len() >= 3);
    assert_eq!(steps[0].step_number, 1);
}

#[test]
fn select_chain_python_returns_steps() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    let steps = chain.select_chain(&TechStack::Python);
    assert!(!steps.is_empty());
}

#[test]
fn select_chain_java_returns_steps() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    let steps = chain.select_chain(&TechStack::Java);
    assert!(!steps.is_empty());
}

#[test]
fn select_chain_nodejs_returns_steps() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    let steps = chain.select_chain(&TechStack::NodeJs);
    assert!(!steps.is_empty());
}

#[test]
fn select_chain_ruby_returns_steps() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    let steps = chain.select_chain(&TechStack::Ruby);
    assert!(!steps.is_empty());
}

#[test]
fn select_chain_unknown_falls_back_to_php() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    let unknown_steps = chain.select_chain(&TechStack::Unknown);
    let php_steps = chain.select_chain(&TechStack::PHP);
    assert_eq!(unknown_steps.len(), php_steps.len());
}

#[test]
fn select_chain_all_stacks_have_steps() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    for stack in TechStack::all() {
        let steps = chain.select_chain(stack);
        assert!(!steps.is_empty(), "no chain steps for {:?}", stack);
    }
}

#[test]
fn select_chain_step_numbers_ascending() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    for stack in TechStack::all() {
        let steps = chain.select_chain(stack);
        for window in steps.windows(2) {
            assert!(
                window[1].step_number > window[0].step_number,
                "steps not ascending for {:?}",
                stack
            );
        }
    }
}

#[test]
fn select_chain_php_includes_filter_step() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    let steps = chain.select_chain(&TechStack::PHP);
    let has_filter = steps.iter().any(|s| s.payload.contains("php://filter"));
    assert!(has_filter, "PHP chain should include php://filter step");
}

#[test]
fn build_full_chain_detects_lfi() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    let result = chain.build_full_chain("http://127.0.0.1:3000/page", "file");
    assert!(result.lfi_detected);
    assert!(!result.chain_steps.is_empty());
}

#[test]
fn build_full_chain_achieves_rce() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    let result = chain.build_full_chain("http://127.0.0.1:3000/page", "file");
    assert!(result.rce_achieved);
}

#[test]
fn build_full_chain_sets_tech_stack() {
    let config =
        LfiRceConfig::new("http://127.0.0.1:3000/page", "file").with_tech_stack(TechStack::Python);
    let chain = LfiRceChain::new(config);
    let result = chain.build_full_chain("http://127.0.0.1:3000/page", "file");
    assert_eq!(result.tech_stack, TechStack::Python);
}

#[test]
fn generate_bypass_payloads_includes_standard_traversal() {
    let payloads = generate_bypass_payloads("/etc/passwd", 5);
    assert!(payloads[0].contains("../"));
    assert!(payloads[0].ends_with("/etc/passwd"));
}

#[test]
fn generate_bypass_payloads_includes_encoding_variants() {
    let payloads = generate_bypass_payloads("/etc/passwd", 3);
    assert!(payloads.len() > ENCODING_BYPASSES.len());
    assert!(payloads.iter().any(|p| p.contains("%2e%2e")));
}

#[test]
fn generate_bypass_payloads_count() {
    let payloads = generate_bypass_payloads("/etc/passwd", 5);
    assert_eq!(payloads.len(), ENCODING_BYPASSES.len() + 1);
}

#[test]
fn chain_step_fields_not_empty() {
    let config = LfiRceConfig::new("http://127.0.0.1:3000/page", "file");
    let chain = LfiRceChain::new(config);
    for stack in TechStack::all() {
        for step in chain.select_chain(stack) {
            assert!(
                !step.description.is_empty(),
                "empty description in {:?}",
                stack
            );
            assert!(!step.payload.is_empty(), "empty payload in {:?}", stack);
            assert!(
                !step.expected_result.is_empty(),
                "empty expected_result in {:?}",
                stack
            );
        }
    }
}
