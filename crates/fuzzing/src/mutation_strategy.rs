use std::collections::HashMap;

use rand::Rng;

/// The mutation strategy that produced a given payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SmartMutationKind {
    StructureAware,
    TypeAware,
    BoundaryFocused,
    FormatPreserving,
    DictionaryBased,
    GeneticCrossover,
}

/// A payload produced by a smart mutation strategy.
#[derive(Debug, Clone)]
pub struct SmartMutatedPayload {
    pub value: String,
    pub kind: SmartMutationKind,
    pub parent_indices: Vec<usize>,
}

/// Detected JSON value type for type-aware mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonValueType {
    String,
    Integer,
    Float,
    Boolean,
    Null,
    Array,
    Object,
}

/// Fitness record for a payload in the genetic pool.
#[derive(Debug, Clone)]
pub struct FitnessRecord {
    pub payload: String,
    pub fitness: f64,
    pub generation: u32,
}

/// Dictionary of known-bad values organized by vulnerability category.
#[derive(Debug, Clone)]
pub struct VulnDictionary {
    entries: HashMap<String, Vec<String>>,
}

impl VulnDictionary {
    pub fn new() -> Self {
        let mut entries = HashMap::new();
        entries.insert(
            "sqli".to_string(),
            vec![
                "' OR '1'='1".to_string(),
                "'; DROP TABLE--".to_string(),
                "1 UNION SELECT NULL--".to_string(),
                "' AND 1=1--".to_string(),
                "' WAITFOR DELAY '0:0:5'--".to_string(),
            ],
        );
        entries.insert(
            "xss".to_string(),
            vec![
                "<script>alert(1)</script>".to_string(),
                "<img src=x onerror=alert(1)>".to_string(),
                "javascript:alert(1)".to_string(),
                "<svg/onload=alert(1)>".to_string(),
                "'\"><script>alert(1)</script>".to_string(),
            ],
        );
        entries.insert(
            "cmdi".to_string(),
            vec![
                "; id".to_string(),
                "| cat /etc/passwd".to_string(),
                "$(sleep 5)".to_string(),
                "`id`".to_string(),
                "& whoami".to_string(),
            ],
        );
        entries.insert(
            "traversal".to_string(),
            vec![
                "../../../etc/passwd".to_string(),
                "..\\..\\..\\windows\\win.ini".to_string(),
                "%2e%2e%2fetc%2fpasswd".to_string(),
                "....//....//etc/passwd".to_string(),
            ],
        );
        entries.insert(
            "ssti".to_string(),
            vec![
                "{{7*7}}".to_string(),
                "${7*7}".to_string(),
                "<%= 7*7 %>".to_string(),
                "#{7*7}".to_string(),
            ],
        );
        Self { entries }
    }

    pub fn with_category(mut self, category: &str, values: Vec<String>) -> Self {
        self.entries.insert(category.to_string(), values);
        self
    }

    pub fn get_category(&self, category: &str) -> Option<&[String]> {
        self.entries.get(category).map(|v| v.as_slice())
    }

    pub fn categories(&self) -> Vec<&str> {
        self.entries.keys().map(|k| k.as_str()).collect()
    }
}

impl Default for VulnDictionary {
    fn default() -> Self {
        Self::new()
    }
}

/// Smart mutation engine that applies structure-aware, type-aware, boundary,
/// format-preserving, dictionary-based, and genetic crossover strategies.
pub struct MutationStrategyEngine {
    dictionary: VulnDictionary,
    genetic_pool: Vec<FitnessRecord>,
    max_pool_size: usize,
    generation: u32,
    crossover_rate: f64,
    mutation_rate: f64,
}

impl MutationStrategyEngine {
    pub fn new() -> Self {
        Self {
            dictionary: VulnDictionary::new(),
            genetic_pool: Vec::new(),
            max_pool_size: 500,
            generation: 0,
            crossover_rate: 0.7,
            mutation_rate: 0.3,
        }
    }

    pub fn with_dictionary(mut self, dictionary: VulnDictionary) -> Self {
        self.dictionary = dictionary;
        self
    }

    pub fn with_max_pool_size(mut self, size: usize) -> Self {
        self.max_pool_size = size;
        self
    }

    pub fn with_crossover_rate(mut self, rate: f64) -> Self {
        self.crossover_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Mutate a JSON string preserving its structure but changing values.
    pub fn mutate_structure_aware(&self, json_input: &str) -> Vec<SmartMutatedPayload> {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(json_input);
        let value = match parsed {
            Ok(v) => v,
            Err(_) => return vec![],
        };

        let mut results = Vec::new();
        mutate_json_value(&value, &mut results, &[]);
        results
    }

    /// Mutate values respecting their detected type.
    pub fn mutate_type_aware(&self, input: &str) -> Vec<SmartMutatedPayload> {
        let detected_type = detect_type(input);
        let mutations = match detected_type {
            JsonValueType::String => mutate_as_string(input),
            JsonValueType::Integer => mutate_as_integer(input),
            JsonValueType::Float => mutate_as_float(input),
            JsonValueType::Boolean => mutate_as_boolean(),
            JsonValueType::Null => mutate_as_null(),
            JsonValueType::Array => vec![input.to_string()],
            JsonValueType::Object => vec![input.to_string()],
        };
        mutations
            .into_iter()
            .map(|value| SmartMutatedPayload {
                value,
                kind: SmartMutationKind::TypeAware,
                parent_indices: vec![],
            })
            .collect()
    }

    /// Generate boundary-focused payloads targeting edge cases.
    pub fn generate_boundary_payloads(&self) -> Vec<SmartMutatedPayload> {
        let a255 = "A".repeat(255);
        let a256 = "A".repeat(256);
        let a1024 = "A".repeat(1024);
        let a4096 = "A".repeat(4096);
        let a65535 = "A".repeat(65535);
        let boundaries: Vec<&str> = vec![
            "",
            " ",
            "\0",
            "\n",
            "\r\n",
            "\t",
            "A",
            &a255,
            &a256,
            &a1024,
            &a4096,
            &a65535,
            "0",
            "-1",
            "1",
            "-2147483648",
            "2147483647",
            "-9223372036854775808",
            "9223372036854775807",
            "NaN",
            "Infinity",
            "-Infinity",
            "0.0",
            "-0.0",
            "1e308",
            "1e-308",
            "null",
            "undefined",
            "nil",
            "None",
            "true",
            "false",
            "[]",
            "{}",
            "[null]",
            "{\"\":\"\"}",
            "[[[[[[]]]]]]",
        ];
        boundaries
            .into_iter()
            .map(|b| SmartMutatedPayload {
                value: b.to_string(),
                kind: SmartMutationKind::BoundaryFocused,
                parent_indices: vec![],
            })
            .collect()
    }

    /// Mutate format-specific strings preserving their format but introducing subtle invalidity.
    pub fn mutate_format_preserving(&self, input: &str) -> Vec<SmartMutatedPayload> {
        let mut results = Vec::new();

        if looks_like_email(input) {
            results.extend(mutate_email(input));
        }
        if looks_like_url(input) {
            results.extend(mutate_url(input));
        }
        if looks_like_uuid(input) {
            results.extend(mutate_uuid(input));
        }
        if looks_like_ip(input) {
            results.extend(mutate_ip(input));
        }
        if looks_like_date(input) {
            results.extend(mutate_date(input));
        }

        if results.is_empty() {
            results.push(SmartMutatedPayload {
                value: format!("{}\x00suffix", input),
                kind: SmartMutationKind::FormatPreserving,
                parent_indices: vec![],
            });
        }

        results
    }

    /// Inject payloads from the vulnerability dictionary for a category.
    pub fn inject_from_dictionary(&self, category: &str) -> Vec<SmartMutatedPayload> {
        match self.dictionary.get_category(category) {
            Some(entries) => entries
                .iter()
                .map(|value| SmartMutatedPayload {
                    value: value.clone(),
                    kind: SmartMutationKind::DictionaryBased,
                    parent_indices: vec![],
                })
                .collect(),
            None => vec![],
        }
    }

    /// Add a payload with its fitness score to the genetic pool.
    pub fn record_fitness(&mut self, payload: &str, fitness: f64) {
        if self.genetic_pool.len() >= self.max_pool_size {
            self.genetic_pool.sort_by(|a, b| {
                b.fitness
                    .partial_cmp(&a.fitness)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            self.genetic_pool.truncate(self.max_pool_size / 2);
        }
        self.genetic_pool.push(FitnessRecord {
            payload: payload.to_string(),
            fitness,
            generation: self.generation,
        });
    }

    /// Breed new payloads by crossing over high-fitness parents.
    pub fn breed_generation(&mut self, count: usize) -> Vec<SmartMutatedPayload> {
        if self.genetic_pool.len() < 2 {
            return vec![];
        }

        self.generation += 1;
        let mut rng = rand::rng();
        let mut offspring = Vec::new();

        let mut sorted_pool: Vec<(usize, &FitnessRecord)> =
            self.genetic_pool.iter().enumerate().collect();
        sorted_pool.sort_by(|a, b| {
            b.1.fitness
                .partial_cmp(&a.1.fitness)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        for _ in 0..count {
            let parent_a_idx = tournament_select(&sorted_pool, &mut rng);
            let parent_b_idx = tournament_select(&sorted_pool, &mut rng);
            let parent_a = &sorted_pool[parent_a_idx].1.payload;
            let parent_b = &sorted_pool[parent_b_idx].1.payload;
            let orig_a = sorted_pool[parent_a_idx].0;
            let orig_b = sorted_pool[parent_b_idx].0;

            let child = if rng.random_range(0.0..1.0) < self.crossover_rate {
                crossover(parent_a, parent_b, &mut rng)
            } else {
                parent_a.clone()
            };

            let child = if rng.random_range(0.0..1.0) < self.mutation_rate {
                point_mutate(&child, &mut rng)
            } else {
                child
            };

            offspring.push(SmartMutatedPayload {
                value: child,
                kind: SmartMutationKind::GeneticCrossover,
                parent_indices: vec![orig_a, orig_b],
            });
        }

        offspring
    }

    pub fn genetic_pool_size(&self) -> usize {
        self.genetic_pool.len()
    }

    pub fn current_generation(&self) -> u32 {
        self.generation
    }

    pub fn dictionary(&self) -> &VulnDictionary {
        &self.dictionary
    }
}

impl Default for MutationStrategyEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn detect_type(input: &str) -> JsonValueType {
    let trimmed = input.trim();
    if trimmed == "null" || trimmed == "nil" || trimmed == "None" {
        return JsonValueType::Null;
    }
    if trimmed == "true" || trimmed == "false" {
        return JsonValueType::Boolean;
    }
    if trimmed.parse::<i64>().is_ok() {
        return JsonValueType::Integer;
    }
    if trimmed.parse::<f64>().is_ok() {
        return JsonValueType::Float;
    }
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        return JsonValueType::Array;
    }
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        return JsonValueType::Object;
    }
    JsonValueType::String
}

fn mutate_as_string(input: &str) -> Vec<String> {
    vec![
        String::new(),
        " ".to_string(),
        format!("{}' OR '1'='1", input),
        format!("{}<script>alert(1)</script>", input),
        format!("{}\x00", input),
        "A".repeat(input.len().max(1) * 10),
        input.to_uppercase(),
        input.chars().rev().collect(),
    ]
}

fn mutate_as_integer(input: &str) -> Vec<String> {
    let base: i64 = input.parse().unwrap_or(0);
    vec![
        "0".to_string(),
        "-1".to_string(),
        (base + 1).to_string(),
        (base.wrapping_sub(1)).to_string(),
        i64::MAX.to_string(),
        i64::MIN.to_string(),
        "2147483647".to_string(),
        "-2147483648".to_string(),
        "NaN".to_string(),
        "Infinity".to_string(),
        "99999999999999999999".to_string(),
    ]
}

fn mutate_as_float(input: &str) -> Vec<String> {
    let base: f64 = input.parse().unwrap_or(0.0);
    vec![
        "0.0".to_string(),
        "-0.0".to_string(),
        (base + 0.0001).to_string(),
        (base - 0.0001).to_string(),
        "NaN".to_string(),
        "Infinity".to_string(),
        "-Infinity".to_string(),
        "1e308".to_string(),
        "1e-308".to_string(),
    ]
}

fn mutate_as_boolean() -> Vec<String> {
    vec![
        "true".to_string(),
        "false".to_string(),
        "1".to_string(),
        "0".to_string(),
        "yes".to_string(),
        "no".to_string(),
        "null".to_string(),
        "\"true\"".to_string(),
    ]
}

fn mutate_as_null() -> Vec<String> {
    vec![
        "null".to_string(),
        "nil".to_string(),
        "None".to_string(),
        "undefined".to_string(),
        "0".to_string(),
        "\"\"".to_string(),
        "false".to_string(),
        "[]".to_string(),
    ]
}

fn mutate_json_value(
    value: &serde_json::Value,
    results: &mut Vec<SmartMutatedPayload>,
    _path: &[String],
) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                let mut mutated = map.clone();

                mutated.insert(
                    key.clone(),
                    serde_json::Value::String("' OR '1'='1".to_string()),
                );
                results.push(SmartMutatedPayload {
                    value: serde_json::to_string(&serde_json::Value::Object(mutated))
                        .unwrap_or_default(),
                    kind: SmartMutationKind::StructureAware,
                    parent_indices: vec![],
                });

                let mut mutated = map.clone();
                mutated.insert(key.clone(), serde_json::Value::Null);
                results.push(SmartMutatedPayload {
                    value: serde_json::to_string(&serde_json::Value::Object(mutated))
                        .unwrap_or_default(),
                    kind: SmartMutationKind::StructureAware,
                    parent_indices: vec![],
                });

                let mut mutated = map.clone();
                mutated.remove(key);
                results.push(SmartMutatedPayload {
                    value: serde_json::to_string(&serde_json::Value::Object(mutated))
                        .unwrap_or_default(),
                    kind: SmartMutationKind::StructureAware,
                    parent_indices: vec![],
                });

                if val.is_string() {
                    let mut mutated = map.clone();
                    mutated.insert(key.clone(), serde_json::Value::from(42));
                    results.push(SmartMutatedPayload {
                        value: serde_json::to_string(&serde_json::Value::Object(mutated))
                            .unwrap_or_default(),
                        kind: SmartMutationKind::StructureAware,
                        parent_indices: vec![],
                    });
                }
            }
        }
        serde_json::Value::Array(arr) => {
            results.push(SmartMutatedPayload {
                value: "[]".to_string(),
                kind: SmartMutationKind::StructureAware,
                parent_indices: vec![],
            });

            if !arr.is_empty() {
                let mut big = arr.clone();
                for _ in 0..100 {
                    big.push(arr[0].clone());
                }
                results.push(SmartMutatedPayload {
                    value: serde_json::to_string(&serde_json::Value::Array(big))
                        .unwrap_or_default(),
                    kind: SmartMutationKind::StructureAware,
                    parent_indices: vec![],
                });
            }
        }
        _ => {}
    }
}

fn looks_like_email(s: &str) -> bool {
    let parts: Vec<&str> = s.split('@').collect();
    parts.len() == 2 && !parts[0].is_empty() && parts[1].contains('.')
}

fn looks_like_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

fn looks_like_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts[0].len() == 8
        && parts[1].len() == 4
        && parts[2].len() == 4
        && parts[3].len() == 4
        && parts[4].len() == 12
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

fn looks_like_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn looks_like_date(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 3
        && parts[0].len() == 4
        && parts[1].len() == 2
        && parts[2].len() == 2
        && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()))
}

fn mutate_email(input: &str) -> Vec<SmartMutatedPayload> {
    let parts: Vec<&str> = input.split('@').collect();
    if parts.len() != 2 {
        return vec![];
    }
    let (local, domain) = (parts[0], parts[1]);
    vec![
        format!("{}@", local),
        format!("@{}", domain),
        format!("{}@{}..", local, domain),
        format!("{}+injection@{}", local, domain),
        format!("{}<script>@{}", local, domain),
        format!("{}@localhost", local),
        format!("{}@127.0.0.1", local),
        format!("{}@{}{}", local, domain, "\x00.evil.com"),
    ]
    .into_iter()
    .map(|value| SmartMutatedPayload {
        value,
        kind: SmartMutationKind::FormatPreserving,
        parent_indices: vec![],
    })
    .collect()
}

fn mutate_url(input: &str) -> Vec<SmartMutatedPayload> {
    vec![
        format!("{}/../../../etc/passwd", input),
        input.replace("https://", "http://"),
        format!("{}%00", input),
        format!("{}\r\nX-Injected: true", input),
        format!("javascript:alert(1)//"),
        format!("{}@evil.com", input),
    ]
    .into_iter()
    .map(|value| SmartMutatedPayload {
        value,
        kind: SmartMutationKind::FormatPreserving,
        parent_indices: vec![],
    })
    .collect()
}

fn mutate_uuid(input: &str) -> Vec<SmartMutatedPayload> {
    vec![
        "00000000-0000-0000-0000-000000000000".to_string(),
        "ffffffff-ffff-ffff-ffff-ffffffffffff".to_string(),
        input.replace('-', ""),
        format!("{}{}", input, input),
        format!("{}' OR '1'='1", input),
    ]
    .into_iter()
    .map(|value| SmartMutatedPayload {
        value,
        kind: SmartMutationKind::FormatPreserving,
        parent_indices: vec![],
    })
    .collect()
}

fn mutate_ip(input: &str) -> Vec<SmartMutatedPayload> {
    vec![
        "127.0.0.1".to_string(),
        "0.0.0.0".to_string(),
        "255.255.255.255".to_string(),
        "169.254.169.254".to_string(),
        "256.256.256.256".to_string(),
        format!("{}:8080", input),
        "0x7f000001".to_string(),
    ]
    .into_iter()
    .map(|value| SmartMutatedPayload {
        value,
        kind: SmartMutationKind::FormatPreserving,
        parent_indices: vec![],
    })
    .collect()
}

fn mutate_date(input: &str) -> Vec<SmartMutatedPayload> {
    vec![
        "0000-00-00".to_string(),
        "9999-12-31".to_string(),
        "2024-13-01".to_string(),
        "2024-02-30".to_string(),
        format!("{}T00:00:00Z", input),
        format!("{}'--", input),
    ]
    .into_iter()
    .map(|value| SmartMutatedPayload {
        value,
        kind: SmartMutationKind::FormatPreserving,
        parent_indices: vec![],
    })
    .collect()
}

fn tournament_select(sorted_pool: &[(usize, &FitnessRecord)], rng: &mut impl Rng) -> usize {
    let a = rng.random_range(0..sorted_pool.len());
    let b = rng.random_range(0..sorted_pool.len());
    if sorted_pool[a].1.fitness >= sorted_pool[b].1.fitness {
        a
    } else {
        b
    }
}

fn crossover(parent_a: &str, parent_b: &str, rng: &mut impl Rng) -> String {
    if parent_a.is_empty() || parent_b.is_empty() {
        return format!("{}{}", parent_a, parent_b);
    }

    let split_a = rng.random_range(0..parent_a.len());
    let split_b = rng.random_range(0..parent_b.len());

    let prefix = &parent_a[..split_a];
    let suffix = &parent_b[split_b..];
    format!("{}{}", prefix, suffix)
}

fn point_mutate(input: &str, rng: &mut impl Rng) -> String {
    if input.is_empty() {
        return "X".to_string();
    }

    let mut chars: Vec<char> = input.chars().collect();
    let idx = rng.random_range(0..chars.len());
    let mutation_type = rng.random_range(0..4);

    match mutation_type {
        0 => {
            chars[idx] = rng.random_range(32u8..127) as char;
        }
        1 => {
            chars.insert(idx, rng.random_range(32u8..127) as char);
        }
        2 => {
            chars.remove(idx);
            if chars.is_empty() {
                chars.push('X');
            }
        }
        _ => {
            let special = [
                '\'', '"', '<', '>', '&', ';', '|', '`', '$', '{', '}', '(', ')',
            ];
            chars[idx] = special[rng.random_range(0..special.len())];
        }
    }

    chars.into_iter().collect()
}
