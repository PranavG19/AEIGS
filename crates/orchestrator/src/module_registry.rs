use std::collections::HashMap;
use std::time::Duration;

use aegis_protocol::finding::VulnerabilityClass;

use crate::module_selector::{ModulePriority, TechStack};

/// Resource requirements for a scan module.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceRequirements {
    pub needs_network: bool,
    pub needs_auth: bool,
    pub needs_llm: bool,
    pub estimated_duration: Duration,
    pub max_concurrent_requests: u32,
}

impl Default for ResourceRequirements {
    fn default() -> Self {
        Self {
            needs_network: true,
            needs_auth: false,
            needs_llm: false,
            estimated_duration: Duration::from_secs(10),
            max_concurrent_requests: 5,
        }
    }
}

/// Metadata describing a registered scan/attack module.
#[derive(Debug, Clone)]
pub struct ModuleMetadata {
    pub name: String,
    pub crate_name: String,
    pub description: String,
    pub vulnerability_classes: Vec<VulnerabilityClass>,
    pub applicable_tech: Vec<TechStack>,
    pub priority: ModulePriority,
    pub resources: ResourceRequirements,
    pub enabled: bool,
}

/// Central registry of all AEGIS scan modules.
///
/// Provides lookup by name, filtering by tech stack, vulnerability class, and
/// priority. Used by module_selector and full_scan to dynamically compose scan
/// pipelines based on target characteristics.
#[derive(Debug)]
pub struct ModuleRegistry {
    modules: HashMap<String, ModuleMetadata>,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
        }
    }

    /// Build a registry pre-populated with all known modules.
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register_defaults();
        registry
    }

    /// Register a single module.
    pub fn register(&mut self, meta: ModuleMetadata) {
        self.modules.insert(meta.name.clone(), meta);
    }

    /// Remove a module by name. Returns the removed metadata if it existed.
    pub fn unregister(&mut self, name: &str) -> Option<ModuleMetadata> {
        self.modules.remove(name)
    }

    /// Look up a module by name.
    pub fn get(&self, name: &str) -> Option<&ModuleMetadata> {
        self.modules.get(name)
    }

    /// Total registered modules.
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    /// All registered module names, sorted alphabetically.
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<_> = self.modules.keys().cloned().collect();
        names.sort();
        names
    }

    /// Filter modules applicable to a given tech stack.
    /// Universal modules (empty applicable_tech) match every stack.
    pub fn for_tech_stack(&self, tech: &TechStack) -> Vec<&ModuleMetadata> {
        self.modules
            .values()
            .filter(|m| m.enabled)
            .filter(|m| m.applicable_tech.is_empty() || m.applicable_tech.contains(tech))
            .collect()
    }

    /// Filter modules that test a specific vulnerability class.
    pub fn for_vulnerability_class(&self, class: &VulnerabilityClass) -> Vec<&ModuleMetadata> {
        self.modules
            .values()
            .filter(|m| m.enabled)
            .filter(|m| m.vulnerability_classes.contains(class))
            .collect()
    }

    /// Return modules at or above a given priority threshold.
    pub fn at_priority_or_above(&self, threshold: ModulePriority) -> Vec<&ModuleMetadata> {
        self.modules
            .values()
            .filter(|m| m.enabled && m.priority <= threshold)
            .collect()
    }

    /// Estimated total scan duration if all enabled modules run sequentially.
    pub fn estimated_total_duration(&self) -> Duration {
        self.modules
            .values()
            .filter(|m| m.enabled)
            .map(|m| m.resources.estimated_duration)
            .sum()
    }

    /// Enable or disable a module by name. Returns false if the module was not found.
    pub fn set_enabled(&mut self, name: &str, enabled: bool) -> bool {
        if let Some(meta) = self.modules.get_mut(name) {
            meta.enabled = enabled;
            true
        } else {
            false
        }
    }

    /// Disable all modules that require LLM access.
    pub fn disable_llm_modules(&mut self) {
        for meta in self.modules.values_mut() {
            if meta.resources.needs_llm {
                meta.enabled = false;
            }
        }
    }

    fn register_defaults(&mut self) {
        let defaults = vec![
            ModuleMetadata {
                name: "sql_injection".into(),
                crate_name: "aegis-fuzzing".into(),
                description:
                    "SQL injection detection via error-based, blind, and time-based payloads".into(),
                vulnerability_classes: vec![VulnerabilityClass::SqlInjection],
                applicable_tech: vec![],
                priority: ModulePriority::Critical,
                resources: ResourceRequirements {
                    estimated_duration: Duration::from_secs(30),
                    ..Default::default()
                },
                enabled: true,
            },
            ModuleMetadata {
                name: "xss".into(),
                crate_name: "aegis-fuzzing".into(),
                description: "Cross-site scripting via reflected, stored, and DOM-based vectors"
                    .into(),
                vulnerability_classes: vec![VulnerabilityClass::CrossSiteScripting],
                applicable_tech: vec![],
                priority: ModulePriority::Critical,
                resources: ResourceRequirements {
                    estimated_duration: Duration::from_secs(25),
                    ..Default::default()
                },
                enabled: true,
            },
            ModuleMetadata {
                name: "broken_auth".into(),
                crate_name: "aegis-orchestrator".into(),
                description: "Authentication bypass and weak credential detection".into(),
                vulnerability_classes: vec![VulnerabilityClass::BrokenAuthentication],
                applicable_tech: vec![],
                priority: ModulePriority::Critical,
                resources: ResourceRequirements {
                    needs_auth: true,
                    estimated_duration: Duration::from_secs(20),
                    ..Default::default()
                },
                enabled: true,
            },
            ModuleMetadata {
                name: "ssrf".into(),
                crate_name: "aegis-orchestrator".into(),
                description: "Server-side request forgery via callback and DNS rebinding".into(),
                vulnerability_classes: vec![VulnerabilityClass::ServerSideRequestForgery],
                applicable_tech: vec![],
                priority: ModulePriority::High,
                resources: ResourceRequirements {
                    estimated_duration: Duration::from_secs(15),
                    ..Default::default()
                },
                enabled: true,
            },
            ModuleMetadata {
                name: "open_redirect".into(),
                crate_name: "aegis-orchestrator".into(),
                description: "Open redirect parameter detection".into(),
                vulnerability_classes: vec![VulnerabilityClass::OpenRedirect],
                applicable_tech: vec![],
                priority: ModulePriority::Medium,
                resources: ResourceRequirements {
                    estimated_duration: Duration::from_secs(10),
                    ..Default::default()
                },
                enabled: true,
            },
            ModuleMetadata {
                name: "cors".into(),
                crate_name: "aegis-orchestrator".into(),
                description: "Cross-origin resource sharing misconfiguration".into(),
                vulnerability_classes: vec![VulnerabilityClass::CrossOriginMisconfiguration],
                applicable_tech: vec![],
                priority: ModulePriority::Medium,
                resources: ResourceRequirements {
                    estimated_duration: Duration::from_secs(8),
                    ..Default::default()
                },
                enabled: true,
            },
            ModuleMetadata {
                name: "ssti".into(),
                crate_name: "aegis-orchestrator".into(),
                description: "Server-side template injection across Jinja2, Twig, ERB, Handlebars"
                    .into(),
                vulnerability_classes: vec![VulnerabilityClass::ServerSideTemplateInjection],
                applicable_tech: vec![
                    TechStack::Python,
                    TechStack::Flask,
                    TechStack::Django,
                    TechStack::Php,
                    TechStack::Laravel,
                    TechStack::Ruby,
                    TechStack::Rails,
                    TechStack::Node,
                    TechStack::Express,
                ],
                priority: ModulePriority::High,
                resources: ResourceRequirements {
                    estimated_duration: Duration::from_secs(20),
                    ..Default::default()
                },
                enabled: true,
            },
            ModuleMetadata {
                name: "command_injection".into(),
                crate_name: "aegis-fuzzing".into(),
                description: "OS command injection via parameter tampering".into(),
                vulnerability_classes: vec![VulnerabilityClass::CommandInjection],
                applicable_tech: vec![],
                priority: ModulePriority::Critical,
                resources: ResourceRequirements {
                    estimated_duration: Duration::from_secs(15),
                    ..Default::default()
                },
                enabled: true,
            },
            ModuleMetadata {
                name: "path_traversal".into(),
                crate_name: "aegis-orchestrator".into(),
                description: "Path traversal and local file inclusion".into(),
                vulnerability_classes: vec![VulnerabilityClass::PathTraversal],
                applicable_tech: vec![],
                priority: ModulePriority::Critical,
                resources: ResourceRequirements {
                    estimated_duration: Duration::from_secs(12),
                    ..Default::default()
                },
                enabled: true,
            },
            ModuleMetadata {
                name: "graphql_introspection".into(),
                crate_name: "aegis-orchestrator".into(),
                description: "GraphQL introspection and query depth analysis".into(),
                vulnerability_classes: vec![VulnerabilityClass::SecurityMisconfiguration],
                applicable_tech: vec![TechStack::GraphQL],
                priority: ModulePriority::High,
                resources: ResourceRequirements {
                    estimated_duration: Duration::from_secs(10),
                    ..Default::default()
                },
                enabled: true,
            },
            ModuleMetadata {
                name: "hypothesis_generator".into(),
                crate_name: "hypothesis-engine".into(),
                description: "LLM-driven hypothesis generation for novel attack vectors".into(),
                vulnerability_classes: vec![],
                applicable_tech: vec![],
                priority: ModulePriority::Medium,
                resources: ResourceRequirements {
                    needs_llm: true,
                    estimated_duration: Duration::from_secs(45),
                    max_concurrent_requests: 1,
                    ..Default::default()
                },
                enabled: true,
            },
            ModuleMetadata {
                name: "deserialization".into(),
                crate_name: "aegis-orchestrator".into(),
                description: "Insecure deserialization across Java, PHP, Python, .NET".into(),
                vulnerability_classes: vec![VulnerabilityClass::InsecureDeserialization],
                applicable_tech: vec![
                    TechStack::Java,
                    TechStack::Spring,
                    TechStack::Php,
                    TechStack::Laravel,
                    TechStack::Python,
                    TechStack::Django,
                    TechStack::Flask,
                    TechStack::DotNet,
                    TechStack::Node,
                    TechStack::Express,
                    TechStack::Ruby,
                    TechStack::Rails,
                ],
                priority: ModulePriority::High,
                resources: ResourceRequirements {
                    estimated_duration: Duration::from_secs(18),
                    ..Default::default()
                },
                enabled: true,
            },
            ModuleMetadata {
                name: "xxe".into(),
                crate_name: "aegis-orchestrator".into(),
                description: "XML external entity injection".into(),
                vulnerability_classes: vec![VulnerabilityClass::XmlExternalEntity],
                applicable_tech: vec![
                    TechStack::Java,
                    TechStack::Spring,
                    TechStack::Php,
                    TechStack::DotNet,
                ],
                priority: ModulePriority::High,
                resources: ResourceRequirements {
                    estimated_duration: Duration::from_secs(12),
                    ..Default::default()
                },
                enabled: true,
            },
        ];

        for meta in defaults {
            self.register(meta);
        }
    }
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}
