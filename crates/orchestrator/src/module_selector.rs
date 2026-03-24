use aegis_protocol::finding::VulnerabilityClass;
use std::collections::HashSet;

/// Detected technology/framework on the target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TechStack {
    Php,
    Node,
    Python,
    Java,
    Ruby,
    DotNet,
    Go,
    Rust,
    WordPress,
    Django,
    Flask,
    Rails,
    Spring,
    Express,
    Laravel,
    Angular,
    React,
    Vue,
    GraphQL,
    Unknown,
}

/// An attack module that can be selected for scanning.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AttackModule {
    pub name: String,
    pub vulnerability_classes: Vec<VulnerabilityClass>,
    pub applicable_tech: Vec<TechStack>,
    pub priority: ModulePriority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ModulePriority {
    Critical,
    High,
    Medium,
    Low,
}

/// Result of module selection.
#[derive(Debug, Clone)]
pub struct ModuleSelection {
    pub selected_modules: Vec<AttackModule>,
    pub skipped_modules: Vec<String>,
    pub tech_detected: Vec<TechStack>,
}

/// Returns all registered attack modules with their tech-stack applicability.
pub fn all_modules() -> Vec<AttackModule> {
    vec![
        // Universal modules (apply to all stacks)
        AttackModule {
            name: "sql_injection".into(),
            vulnerability_classes: vec![VulnerabilityClass::SqlInjection],
            applicable_tech: vec![],
            priority: ModulePriority::Critical,
        },
        AttackModule {
            name: "xss".into(),
            vulnerability_classes: vec![VulnerabilityClass::CrossSiteScripting],
            applicable_tech: vec![],
            priority: ModulePriority::Critical,
        },
        AttackModule {
            name: "broken_auth".into(),
            vulnerability_classes: vec![VulnerabilityClass::BrokenAuthentication],
            applicable_tech: vec![],
            priority: ModulePriority::Critical,
        },
        AttackModule {
            name: "broken_authz".into(),
            vulnerability_classes: vec![VulnerabilityClass::BrokenAuthorization],
            applicable_tech: vec![],
            priority: ModulePriority::High,
        },
        AttackModule {
            name: "ssrf".into(),
            vulnerability_classes: vec![VulnerabilityClass::ServerSideRequestForgery],
            applicable_tech: vec![],
            priority: ModulePriority::High,
        },
        AttackModule {
            name: "open_redirect".into(),
            vulnerability_classes: vec![VulnerabilityClass::OpenRedirect],
            applicable_tech: vec![],
            priority: ModulePriority::Medium,
        },
        AttackModule {
            name: "cors".into(),
            vulnerability_classes: vec![VulnerabilityClass::CrossOriginMisconfiguration],
            applicable_tech: vec![],
            priority: ModulePriority::Medium,
        },
        AttackModule {
            name: "security_misconfig".into(),
            vulnerability_classes: vec![VulnerabilityClass::SecurityMisconfiguration],
            applicable_tech: vec![],
            priority: ModulePriority::Medium,
        },
        // PHP-specific
        AttackModule {
            name: "php_ssti_twig".into(),
            vulnerability_classes: vec![VulnerabilityClass::ServerSideTemplateInjection],
            applicable_tech: vec![TechStack::Php, TechStack::Laravel],
            priority: ModulePriority::High,
        },
        AttackModule {
            name: "php_deserialization".into(),
            vulnerability_classes: vec![VulnerabilityClass::InsecureDeserialization],
            applicable_tech: vec![TechStack::Php, TechStack::Laravel, TechStack::WordPress],
            priority: ModulePriority::High,
        },
        AttackModule {
            name: "php_xxe".into(),
            vulnerability_classes: vec![VulnerabilityClass::XmlExternalEntity],
            applicable_tech: vec![TechStack::Php, TechStack::WordPress],
            priority: ModulePriority::High,
        },
        AttackModule {
            name: "php_lfi".into(),
            vulnerability_classes: vec![VulnerabilityClass::PathTraversal],
            applicable_tech: vec![TechStack::Php, TechStack::WordPress, TechStack::Laravel],
            priority: ModulePriority::Critical,
        },
        AttackModule {
            name: "php_command_injection".into(),
            vulnerability_classes: vec![VulnerabilityClass::CommandInjection],
            applicable_tech: vec![TechStack::Php],
            priority: ModulePriority::Critical,
        },
        // Node.js-specific
        AttackModule {
            name: "node_prototype_pollution".into(),
            vulnerability_classes: vec![VulnerabilityClass::PrototypePollution],
            applicable_tech: vec![TechStack::Node, TechStack::Express],
            priority: ModulePriority::High,
        },
        AttackModule {
            name: "node_ssti_handlebars".into(),
            vulnerability_classes: vec![VulnerabilityClass::ServerSideTemplateInjection],
            applicable_tech: vec![TechStack::Node, TechStack::Express],
            priority: ModulePriority::High,
        },
        AttackModule {
            name: "node_deserialization".into(),
            vulnerability_classes: vec![VulnerabilityClass::InsecureDeserialization],
            applicable_tech: vec![TechStack::Node, TechStack::Express],
            priority: ModulePriority::High,
        },
        AttackModule {
            name: "node_command_injection".into(),
            vulnerability_classes: vec![VulnerabilityClass::CommandInjection],
            applicable_tech: vec![TechStack::Node, TechStack::Express],
            priority: ModulePriority::Critical,
        },
        // Python-specific
        AttackModule {
            name: "python_ssti_jinja".into(),
            vulnerability_classes: vec![VulnerabilityClass::ServerSideTemplateInjection],
            applicable_tech: vec![TechStack::Python, TechStack::Django, TechStack::Flask],
            priority: ModulePriority::High,
        },
        AttackModule {
            name: "python_deserialization".into(),
            vulnerability_classes: vec![VulnerabilityClass::InsecureDeserialization],
            applicable_tech: vec![TechStack::Python, TechStack::Django, TechStack::Flask],
            priority: ModulePriority::High,
        },
        AttackModule {
            name: "python_command_injection".into(),
            vulnerability_classes: vec![VulnerabilityClass::CommandInjection],
            applicable_tech: vec![TechStack::Python, TechStack::Django, TechStack::Flask],
            priority: ModulePriority::Critical,
        },
        // Java-specific
        AttackModule {
            name: "java_deserialization".into(),
            vulnerability_classes: vec![VulnerabilityClass::InsecureDeserialization],
            applicable_tech: vec![TechStack::Java, TechStack::Spring],
            priority: ModulePriority::Critical,
        },
        AttackModule {
            name: "java_xxe".into(),
            vulnerability_classes: vec![VulnerabilityClass::XmlExternalEntity],
            applicable_tech: vec![TechStack::Java, TechStack::Spring],
            priority: ModulePriority::High,
        },
        AttackModule {
            name: "java_ssti".into(),
            vulnerability_classes: vec![VulnerabilityClass::ServerSideTemplateInjection],
            applicable_tech: vec![TechStack::Java, TechStack::Spring],
            priority: ModulePriority::High,
        },
        AttackModule {
            name: "java_el_injection".into(),
            vulnerability_classes: vec![VulnerabilityClass::CommandInjection],
            applicable_tech: vec![TechStack::Java, TechStack::Spring],
            priority: ModulePriority::High,
        },
        // Ruby-specific
        AttackModule {
            name: "ruby_deserialization".into(),
            vulnerability_classes: vec![VulnerabilityClass::InsecureDeserialization],
            applicable_tech: vec![TechStack::Ruby, TechStack::Rails],
            priority: ModulePriority::High,
        },
        AttackModule {
            name: "ruby_ssti_erb".into(),
            vulnerability_classes: vec![VulnerabilityClass::ServerSideTemplateInjection],
            applicable_tech: vec![TechStack::Ruby, TechStack::Rails],
            priority: ModulePriority::High,
        },
        AttackModule {
            name: "ruby_command_injection".into(),
            vulnerability_classes: vec![VulnerabilityClass::CommandInjection],
            applicable_tech: vec![TechStack::Ruby, TechStack::Rails],
            priority: ModulePriority::Critical,
        },
        // .NET-specific
        AttackModule {
            name: "dotnet_deserialization".into(),
            vulnerability_classes: vec![VulnerabilityClass::InsecureDeserialization],
            applicable_tech: vec![TechStack::DotNet],
            priority: ModulePriority::Critical,
        },
        AttackModule {
            name: "dotnet_xxe".into(),
            vulnerability_classes: vec![VulnerabilityClass::XmlExternalEntity],
            applicable_tech: vec![TechStack::DotNet],
            priority: ModulePriority::High,
        },
        // GraphQL-specific
        AttackModule {
            name: "graphql_introspection".into(),
            vulnerability_classes: vec![VulnerabilityClass::SecurityMisconfiguration],
            applicable_tech: vec![TechStack::GraphQL],
            priority: ModulePriority::High,
        },
        AttackModule {
            name: "graphql_injection".into(),
            vulnerability_classes: vec![VulnerabilityClass::SqlInjection],
            applicable_tech: vec![TechStack::GraphQL],
            priority: ModulePriority::Critical,
        },
        // WordPress-specific
        AttackModule {
            name: "wordpress_plugin_vulns".into(),
            vulnerability_classes: vec![VulnerabilityClass::SecurityMisconfiguration],
            applicable_tech: vec![TechStack::WordPress],
            priority: ModulePriority::High,
        },
    ]
}

/// Parse tech stack strings (from tech_detector or headers) into TechStack variants.
pub fn parse_tech_stack(technologies: &[String]) -> Vec<TechStack> {
    let mut result = Vec::new();
    for tech in technologies {
        let lower = tech.to_lowercase();
        let parsed = match lower.as_str() {
            s if s.contains("php") => Some(TechStack::Php),
            s if s.contains("node") || s.contains("nodejs") => Some(TechStack::Node),
            s if s.contains("python") => Some(TechStack::Python),
            s if s.contains("java") && !s.contains("javascript") => Some(TechStack::Java),
            s if s.contains("ruby") => Some(TechStack::Ruby),
            s if s.contains("asp.net") || s.contains("dotnet") || s.contains(".net") => {
                Some(TechStack::DotNet)
            }
            s if s.contains("golang") || (s == "go") => Some(TechStack::Go),
            "rust" => Some(TechStack::Rust),
            s if s.contains("wordpress") || s.contains("wp-") => Some(TechStack::WordPress),
            s if s.contains("django") => Some(TechStack::Django),
            s if s.contains("flask") => Some(TechStack::Flask),
            s if s.contains("rails") => Some(TechStack::Rails),
            s if s.contains("spring") => Some(TechStack::Spring),
            s if s.contains("express") => Some(TechStack::Express),
            s if s.contains("laravel") => Some(TechStack::Laravel),
            s if s.contains("angular") => Some(TechStack::Angular),
            s if s.contains("react") => Some(TechStack::React),
            s if s.contains("vue") => Some(TechStack::Vue),
            s if s.contains("graphql") => Some(TechStack::GraphQL),
            _ => None,
        };
        if let Some(t) = parsed
            && !result.contains(&t)
        {
            result.push(t);
        }
    }
    if result.is_empty() {
        result.push(TechStack::Unknown);
    }
    result
}

/// Select appropriate attack modules given detected technologies.
///
/// Universal modules (empty applicable_tech) are always included.
/// Tech-specific modules are included only when their applicable_tech
/// intersects with the detected stack.
pub fn select_modules(detected_tech: &[TechStack]) -> ModuleSelection {
    let all = all_modules();
    let tech_set: HashSet<&TechStack> = detected_tech.iter().collect();
    let is_unknown = tech_set.contains(&TechStack::Unknown) || tech_set.is_empty();

    let mut selected = Vec::new();
    let mut skipped = Vec::new();

    for module in all {
        let dominated = module.applicable_tech.is_empty()
            || is_unknown
            || module.applicable_tech.iter().any(|t| tech_set.contains(t));
        if dominated {
            selected.push(module);
        } else {
            skipped.push(module.name.clone());
        }
    }

    selected.sort_by_key(|m| m.priority);

    ModuleSelection {
        selected_modules: selected,
        skipped_modules: skipped,
        tech_detected: detected_tech.to_vec(),
    }
}

/// Convenience: parse tech strings and select modules in one call.
pub fn auto_select_modules(technology_strings: &[String]) -> ModuleSelection {
    let tech = parse_tech_stack(technology_strings);
    select_modules(&tech)
}
