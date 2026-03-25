use std::collections::{HashMap, HashSet};
use std::fmt;

const COMMON_TLDS: &[&str] = &["com", "net", "org", "io", "co", "biz", "info", "dev", "app"];

const MULTI_PART_TLDS: &[&str] = &[
    "co.uk", "co.jp", "co.kr", "co.in", "co.nz", "co.za", "com.au", "com.br", "com.cn", "com.mx",
    "com.tw", "org.uk", "net.au", "ac.uk", "gov.uk",
];

/// Category of domain impersonation technique.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ImpersonationType {
    Homoglyph,
    IdnHomograph,
    Typosquat,
    Bitsquat,
    SubdomainAbuse,
    TldSwap,
}

impl fmt::Display for ImpersonationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Homoglyph => write!(f, "Homoglyph"),
            Self::IdnHomograph => write!(f, "IDN Homograph"),
            Self::Typosquat => write!(f, "Typosquat"),
            Self::Bitsquat => write!(f, "Bitsquat"),
            Self::SubdomainAbuse => write!(f, "Subdomain Abuse"),
            Self::TldSwap => write!(f, "TLD Swap"),
        }
    }
}

/// A single domain that may impersonate the target.
#[derive(Debug, Clone, PartialEq)]
pub struct ImpersonationCandidate {
    pub domain: String,
    pub impersonation_type: ImpersonationType,
    pub similarity_score: f64,
    pub registered: Option<bool>,
    pub description: String,
}

/// Aggregated impersonation analysis results for a target domain.
#[derive(Debug, Clone, PartialEq)]
pub struct ImpersonationReport {
    pub target_domain: String,
    pub candidates: Vec<ImpersonationCandidate>,
    pub total_generated: usize,
}

/// WHOIS-like registration data for a candidate domain.
#[derive(Debug, Clone, PartialEq)]
pub struct RegistrationStatus {
    pub domain: String,
    pub registered: bool,
    pub registrar: Option<String>,
    pub creation_date: Option<String>,
}

/// Split a domain into (name, tld) handling multi-part TLDs.
pub fn split_domain(domain: &str) -> (String, String) {
    let lower = domain.to_lowercase();
    for tld in MULTI_PART_TLDS {
        if let Some(prefix) = lower.strip_suffix(&format!(".{tld}")) {
            return (prefix.to_string(), tld.to_string());
        }
    }
    match lower.rsplit_once('.') {
        Some((name, tld)) => (name.to_string(), tld.to_string()),
        None => (lower, String::new()),
    }
}

fn homoglyph_single_char_map() -> Vec<(char, char)> {
    vec![
        ('o', '0'),
        ('l', '1'),
        ('i', '1'),
        ('e', '3'),
        ('a', '4'),
        ('s', '5'),
        ('g', '9'),
        ('b', '6'),
        ('t', '7'),
    ]
}

fn homoglyph_digraph_map() -> Vec<(&'static str, &'static str)> {
    vec![("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m")]
}

/// Generate lookalike domains using ASCII character substitution.
pub fn generate_homoglyphs(domain: &str) -> Vec<ImpersonationCandidate> {
    let (name, tld) = split_domain(domain);
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    for (original, replacement) in homoglyph_single_char_map() {
        for (idx, ch) in name.char_indices() {
            if ch == original {
                let variant = format!(
                    "{}{}{}",
                    &name[..idx],
                    replacement,
                    &name[idx + ch.len_utf8()..]
                );
                let full = format_domain(&variant, &tld);
                if full != domain && seen.insert(full.clone()) {
                    let score = 0.85 + 0.10 * visual_closeness(original, replacement);
                    candidates.push(ImpersonationCandidate {
                        domain: full,
                        impersonation_type: ImpersonationType::Homoglyph,
                        similarity_score: score.min(0.95),
                        registered: None,
                        description: format!(
                            "Replaced '{original}' with '{replacement}' at position {idx}"
                        ),
                    });
                }
            }
        }
    }

    for (pattern, replacement) in homoglyph_digraph_map() {
        let mut start = 0;
        while let Some(pos) = name[start..].find(pattern) {
            let abs_pos = start + pos;
            let variant = format!(
                "{}{}{}",
                &name[..abs_pos],
                replacement,
                &name[abs_pos + pattern.len()..]
            );
            let full = format_domain(&variant, &tld);
            if full != domain && seen.insert(full.clone()) {
                candidates.push(ImpersonationCandidate {
                    domain: full,
                    impersonation_type: ImpersonationType::Homoglyph,
                    similarity_score: 0.92,
                    registered: None,
                    description: format!(
                        "Replaced '{pattern}' with '{replacement}' at position {abs_pos}"
                    ),
                });
            }
            start = abs_pos + 1;
        }
    }

    candidates
}

fn idn_char_map() -> Vec<(char, char)> {
    vec![
        ('a', '\u{0430}'),
        ('e', '\u{0435}'),
        ('o', '\u{043E}'),
        ('p', '\u{0440}'),
        ('c', '\u{0441}'),
        ('s', '\u{0455}'),
        ('x', '\u{0445}'),
        ('y', '\u{0443}'),
    ]
}

/// Generate IDN/Unicode homograph lookalikes using Cyrillic substitution.
pub fn generate_idn_homographs(domain: &str) -> Vec<ImpersonationCandidate> {
    let (name, tld) = split_domain(domain);
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    for (latin, cyrillic) in idn_char_map() {
        for (idx, ch) in name.char_indices() {
            if ch == latin {
                let variant = format!(
                    "{}{}{}",
                    &name[..idx],
                    cyrillic,
                    &name[idx + ch.len_utf8()..]
                );
                let full = format_domain(&variant, &tld);
                if seen.insert(full.clone()) {
                    let score = 0.95 + 0.04 * idn_closeness(latin);
                    candidates.push(ImpersonationCandidate {
                        domain: full,
                        impersonation_type: ImpersonationType::IdnHomograph,
                        similarity_score: score.min(0.99),
                        registered: None,
                        description: format!(
                            "Replaced Latin '{latin}' with Cyrillic equivalent at position {idx}"
                        ),
                    });
                }
            }
        }
    }

    candidates
}

fn qwerty_adjacency() -> HashMap<char, Vec<char>> {
    let mut map = HashMap::new();
    map.insert('q', vec!['w', 'a']);
    map.insert('w', vec!['q', 'e', 's']);
    map.insert('e', vec!['w', 'r', 'd']);
    map.insert('r', vec!['e', 't', 'f']);
    map.insert('t', vec!['r', 'y', 'g']);
    map.insert('y', vec!['t', 'u', 'h']);
    map.insert('u', vec!['y', 'i', 'j']);
    map.insert('i', vec!['u', 'o', 'k']);
    map.insert('o', vec!['i', 'p', 'l']);
    map.insert('p', vec!['o']);
    map.insert('a', vec!['q', 's', 'z']);
    map.insert('s', vec!['a', 'd', 'w', 'x']);
    map.insert('d', vec!['s', 'f', 'e', 'c']);
    map.insert('f', vec!['d', 'g', 'r', 'v']);
    map.insert('g', vec!['f', 'h', 't', 'b']);
    map.insert('h', vec!['g', 'j', 'y', 'n']);
    map.insert('j', vec!['h', 'k', 'u', 'm']);
    map.insert('k', vec!['j', 'l', 'i']);
    map.insert('l', vec!['k', 'o', 'p']);
    map.insert('z', vec!['a', 'x']);
    map.insert('x', vec!['z', 's', 'c']);
    map.insert('c', vec!['x', 'd', 'v']);
    map.insert('v', vec!['c', 'f', 'b']);
    map.insert('b', vec!['v', 'g', 'n']);
    map.insert('n', vec!['b', 'h', 'm']);
    map.insert('m', vec!['n', 'j']);
    map
}

/// Generate typosquat domains from character swaps, omissions, doubles, and adjacent-key hits.
pub fn generate_typosquats(domain: &str) -> Vec<ImpersonationCandidate> {
    let (name, tld) = split_domain(domain);
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();
    let chars: Vec<char> = name.chars().collect();

    generate_char_swaps(&chars, &tld, domain, &mut candidates, &mut seen);
    generate_missing_chars(&chars, &tld, domain, &mut candidates, &mut seen);
    generate_double_chars(&chars, &tld, domain, &mut candidates, &mut seen);
    generate_adjacent_key_subs(&chars, &tld, domain, &mut candidates, &mut seen);

    candidates
}

fn generate_char_swaps(
    chars: &[char],
    tld: &str,
    original_domain: &str,
    candidates: &mut Vec<ImpersonationCandidate>,
    seen: &mut HashSet<String>,
) {
    for i in 0..chars.len().saturating_sub(1) {
        let mut swapped = chars.to_vec();
        swapped.swap(i, i + 1);
        let variant: String = swapped.into_iter().collect();
        let full = format_domain(&variant, tld);
        if full != original_domain && seen.insert(full.clone()) {
            candidates.push(ImpersonationCandidate {
                domain: full,
                impersonation_type: ImpersonationType::Typosquat,
                similarity_score: 0.85,
                registered: None,
                description: format!("Swapped characters at positions {i} and {}", i + 1),
            });
        }
    }
}

fn generate_missing_chars(
    chars: &[char],
    tld: &str,
    original_domain: &str,
    candidates: &mut Vec<ImpersonationCandidate>,
    seen: &mut HashSet<String>,
) {
    for i in 0..chars.len() {
        let variant: String = chars
            .iter()
            .enumerate()
            .filter(|(idx, _)| *idx != i)
            .map(|(_, ch)| *ch)
            .collect();
        if variant.is_empty() {
            continue;
        }
        let full = format_domain(&variant, tld);
        if full != original_domain && seen.insert(full.clone()) {
            candidates.push(ImpersonationCandidate {
                domain: full,
                impersonation_type: ImpersonationType::Typosquat,
                similarity_score: 0.78,
                registered: None,
                description: format!("Removed character '{}' at position {i}", chars[i]),
            });
        }
    }
}

fn generate_double_chars(
    chars: &[char],
    tld: &str,
    original_domain: &str,
    candidates: &mut Vec<ImpersonationCandidate>,
    seen: &mut HashSet<String>,
) {
    for i in 0..chars.len() {
        let mut doubled: Vec<char> = chars.to_vec();
        doubled.insert(i, chars[i]);
        let variant: String = doubled.into_iter().collect();
        let full = format_domain(&variant, tld);
        if full != original_domain && seen.insert(full.clone()) {
            candidates.push(ImpersonationCandidate {
                domain: full,
                impersonation_type: ImpersonationType::Typosquat,
                similarity_score: 0.82,
                registered: None,
                description: format!("Doubled character '{}' at position {i}", chars[i]),
            });
        }
    }
}

fn generate_adjacent_key_subs(
    chars: &[char],
    tld: &str,
    original_domain: &str,
    candidates: &mut Vec<ImpersonationCandidate>,
    seen: &mut HashSet<String>,
) {
    let adjacency = qwerty_adjacency();
    for (i, &ch) in chars.iter().enumerate() {
        if let Some(neighbors) = adjacency.get(&ch) {
            for &neighbor in neighbors {
                let mut replaced = chars.to_vec();
                replaced[i] = neighbor;
                let variant: String = replaced.into_iter().collect();
                let full = format_domain(&variant, tld);
                if full != original_domain && seen.insert(full.clone()) {
                    candidates.push(ImpersonationCandidate {
                        domain: full,
                        impersonation_type: ImpersonationType::Typosquat,
                        similarity_score: 0.75,
                        registered: None,
                        description: format!(
                            "Replaced '{ch}' with adjacent key '{neighbor}' at position {i}"
                        ),
                    });
                }
            }
        }
    }
}

fn is_valid_domain_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

/// Generate single bit-flip variants that remain valid domain characters.
pub fn generate_bitsquats(domain: &str) -> Vec<ImpersonationCandidate> {
    let (name, tld) = split_domain(domain);
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    for (idx, original_byte) in name.bytes().enumerate() {
        for bit in 0..8u8 {
            let flipped = original_byte ^ (1 << bit);
            let flipped_char = flipped as char;
            if flipped == original_byte {
                continue;
            }
            if !is_valid_domain_char(flipped_char) {
                continue;
            }
            let variant = format!("{}{}{}", &name[..idx], flipped_char, &name[idx + 1..]);
            let full = format_domain(&variant, &tld);
            if full != domain && seen.insert(full.clone()) {
                let score = 0.80 + 0.10 * bitsquat_plausibility(original_byte, flipped);
                candidates.push(ImpersonationCandidate {
                    domain: full,
                    impersonation_type: ImpersonationType::Bitsquat,
                    similarity_score: score.min(0.90),
                    registered: None,
                    description: format!(
                        "Bit flip at byte position {idx}, bit {bit}: '{}' -> '{flipped_char}'",
                        original_byte as char
                    ),
                });
            }
        }
    }

    candidates
}

/// Swap the TLD with common alternatives.
pub fn generate_tld_swaps(domain: &str) -> Vec<ImpersonationCandidate> {
    let (name, original_tld) = split_domain(domain);
    let mut candidates = Vec::new();

    for &tld in COMMON_TLDS {
        if tld == original_tld {
            continue;
        }
        let full = format_domain(&name, tld);
        let score = 0.85 + 0.10 * tld_similarity(&original_tld, tld);
        candidates.push(ImpersonationCandidate {
            domain: full,
            impersonation_type: ImpersonationType::TldSwap,
            similarity_score: score.min(0.95),
            registered: None,
            description: format!("Swapped TLD from '.{original_tld}' to '.{tld}'"),
        });
    }

    candidates
}

/// Run all impersonation generators against the target domain and deduplicate.
pub fn analyze_domain_impersonation(domain: &str) -> ImpersonationReport {
    let mut all_candidates = Vec::new();
    all_candidates.extend(generate_homoglyphs(domain));
    all_candidates.extend(generate_idn_homographs(domain));
    all_candidates.extend(generate_typosquats(domain));
    all_candidates.extend(generate_bitsquats(domain));
    all_candidates.extend(generate_tld_swaps(domain));

    let total_generated = all_candidates.len();
    let mut seen = HashSet::new();
    all_candidates.retain(|c| seen.insert(c.domain.clone()));

    all_candidates.sort_by(|a, b| {
        b.similarity_score
            .partial_cmp(&a.similarity_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    ImpersonationReport {
        target_domain: domain.to_string(),
        candidates: all_candidates,
        total_generated,
    }
}

fn format_domain(name: &str, tld: &str) -> String {
    if tld.is_empty() {
        name.to_string()
    } else {
        format!("{name}.{tld}")
    }
}

fn visual_closeness(original: char, replacement: char) -> f64 {
    match (original, replacement) {
        ('o', '0') | ('l', '1') | ('i', '1') => 0.9,
        ('e', '3') | ('s', '5') => 0.5,
        ('a', '4') | ('g', '9') | ('b', '6') | ('t', '7') => 0.3,
        _ => 0.5,
    }
}

fn idn_closeness(latin: char) -> f64 {
    match latin {
        'a' | 'e' | 'o' | 'c' | 'p' => 1.0,
        's' | 'x' | 'y' => 0.8,
        _ => 0.5,
    }
}

fn bitsquat_plausibility(original: u8, flipped: u8) -> f64 {
    if original.is_ascii_lowercase() && flipped.is_ascii_lowercase() {
        1.0
    } else if original.is_ascii_alphabetic() && flipped.is_ascii_alphabetic() {
        0.8
    } else {
        0.3
    }
}

fn tld_similarity(original: &str, candidate: &str) -> f64 {
    let len_diff = (original.len() as f64 - candidate.len() as f64).abs();
    let shared_prefix = original
        .chars()
        .zip(candidate.chars())
        .take_while(|(a, b)| a == b)
        .count();
    let max_len = original.len().max(candidate.len()) as f64;
    if max_len == 0.0 {
        return 0.0;
    }
    let prefix_ratio = shared_prefix as f64 / max_len;
    let length_penalty = 1.0 / (1.0 + len_diff);
    (prefix_ratio + length_penalty) / 2.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_simple_domain() {
        let (name, tld) = split_domain("example.com");
        assert_eq!(name, "example");
        assert_eq!(tld, "com");
    }

    #[test]
    fn split_multi_part_tld() {
        let (name, tld) = split_domain("example.co.uk");
        assert_eq!(name, "example");
        assert_eq!(tld, "co.uk");
    }

    #[test]
    fn split_no_tld() {
        let (name, tld) = split_domain("localhost");
        assert_eq!(name, "localhost");
        assert_eq!(tld, "");
    }

    #[test]
    fn split_subdomain() {
        let (name, tld) = split_domain("sub.example.com");
        assert_eq!(name, "sub.example");
        assert_eq!(tld, "com");
    }

    #[test]
    fn homoglyphs_produces_candidates() {
        let results = generate_homoglyphs("google.com");
        assert!(!results.is_empty());
        assert!(
            results
                .iter()
                .all(|c| c.impersonation_type == ImpersonationType::Homoglyph)
        );
        assert!(
            results
                .iter()
                .all(|c| c.similarity_score >= 0.85 && c.similarity_score <= 0.95)
        );
        let domains: Vec<&str> = results.iter().map(|c| c.domain.as_str()).collect();
        assert!(domains.contains(&"g0ogle.com") || domains.contains(&"go0gle.com"));
        assert!(results.iter().all(|c| c.domain != "google.com"));
    }

    #[test]
    fn homoglyphs_digraph_rn_to_m() {
        let results = generate_homoglyphs("barn.com");
        let domains: Vec<&str> = results.iter().map(|c| c.domain.as_str()).collect();
        assert!(domains.contains(&"bam.com"));
    }

    #[test]
    fn homoglyphs_no_duplicates() {
        let results = generate_homoglyphs("google.com");
        let mut domains: Vec<String> = results.iter().map(|c| c.domain.clone()).collect();
        let before = domains.len();
        domains.sort();
        domains.dedup();
        assert_eq!(before, domains.len());
    }

    #[test]
    fn idn_homographs_produces_candidates() {
        let results = generate_idn_homographs("apple.com");
        assert!(!results.is_empty());
        assert!(
            results
                .iter()
                .all(|c| c.impersonation_type == ImpersonationType::IdnHomograph)
        );
        assert!(
            results
                .iter()
                .all(|c| c.similarity_score >= 0.95 && c.similarity_score <= 0.99)
        );
    }

    #[test]
    fn idn_homographs_contains_cyrillic_a() {
        let results = generate_idn_homographs("example.com");
        let has_cyrillic = results.iter().any(|c| c.domain.contains('\u{0430}'));
        assert!(has_cyrillic);
    }

    #[test]
    fn typosquats_character_swap() {
        let results = generate_typosquats("example.com");
        let domains: Vec<&str> = results.iter().map(|c| c.domain.as_str()).collect();
        assert!(domains.contains(&"xeample.com") || domains.contains(&"eaxmple.com"));
    }

    #[test]
    fn typosquats_missing_character() {
        let results = generate_typosquats("test.com");
        let domains: Vec<&str> = results.iter().map(|c| c.domain.as_str()).collect();
        assert!(domains.contains(&"tst.com"));
    }

    #[test]
    fn typosquats_double_character() {
        let results = generate_typosquats("test.com");
        let domains: Vec<&str> = results.iter().map(|c| c.domain.as_str()).collect();
        assert!(domains.contains(&"ttest.com"));
    }

    #[test]
    fn typosquats_all_in_score_range() {
        let results = generate_typosquats("example.com");
        assert!(
            results
                .iter()
                .all(|c| c.similarity_score >= 0.70 && c.similarity_score <= 0.90)
        );
    }

    #[test]
    fn bitsquats_produces_valid_chars_only() {
        let results = generate_bitsquats("test.com");
        assert!(!results.is_empty());
        for candidate in &results {
            let (name, _) = split_domain(&candidate.domain);
            assert!(name.chars().all(is_valid_domain_char));
        }
    }

    #[test]
    fn bitsquats_score_range() {
        let results = generate_bitsquats("example.com");
        assert!(
            results
                .iter()
                .all(|c| c.similarity_score >= 0.80 && c.similarity_score <= 0.90)
        );
    }

    #[test]
    fn bitsquats_no_self_reference() {
        let results = generate_bitsquats("test.com");
        assert!(results.iter().all(|c| c.domain != "test.com"));
    }

    #[test]
    fn tld_swaps_produces_alternatives() {
        let results = generate_tld_swaps("example.com");
        assert!(!results.is_empty());
        let domains: Vec<&str> = results.iter().map(|c| c.domain.as_str()).collect();
        assert!(domains.contains(&"example.net"));
        assert!(domains.contains(&"example.org"));
        assert!(domains.contains(&"example.io"));
        assert!(!domains.contains(&"example.com"));
    }

    #[test]
    fn tld_swaps_score_range() {
        let results = generate_tld_swaps("example.com");
        assert!(
            results
                .iter()
                .all(|c| c.similarity_score >= 0.85 && c.similarity_score <= 0.95)
        );
    }

    #[test]
    fn analyze_combines_all_generators() {
        let report = analyze_domain_impersonation("test.com");
        assert_eq!(report.target_domain, "test.com");
        assert!(!report.candidates.is_empty());
        assert!(report.total_generated >= report.candidates.len());

        let types: HashSet<&ImpersonationType> = report
            .candidates
            .iter()
            .map(|c| &c.impersonation_type)
            .collect();
        assert!(types.contains(&ImpersonationType::Homoglyph));
        assert!(types.contains(&ImpersonationType::Typosquat));
        assert!(types.contains(&ImpersonationType::Bitsquat));
        assert!(types.contains(&ImpersonationType::TldSwap));
    }

    #[test]
    fn analyze_deduplicates() {
        let report = analyze_domain_impersonation("example.com");
        let mut domains: Vec<String> = report.candidates.iter().map(|c| c.domain.clone()).collect();
        let before = domains.len();
        domains.sort();
        domains.dedup();
        assert_eq!(before, domains.len());
    }

    #[test]
    fn analyze_sorted_by_similarity_descending() {
        let report = analyze_domain_impersonation("example.com");
        for window in report.candidates.windows(2) {
            assert!(window[0].similarity_score >= window[1].similarity_score);
        }
    }

    #[test]
    fn registered_defaults_to_none() {
        let report = analyze_domain_impersonation("test.com");
        assert!(report.candidates.iter().all(|c| c.registered.is_none()));
    }

    #[test]
    fn impersonation_type_display() {
        assert_eq!(ImpersonationType::Homoglyph.to_string(), "Homoglyph");
        assert_eq!(ImpersonationType::IdnHomograph.to_string(), "IDN Homograph");
        assert_eq!(ImpersonationType::Typosquat.to_string(), "Typosquat");
        assert_eq!(ImpersonationType::Bitsquat.to_string(), "Bitsquat");
        assert_eq!(
            ImpersonationType::SubdomainAbuse.to_string(),
            "Subdomain Abuse"
        );
        assert_eq!(ImpersonationType::TldSwap.to_string(), "TLD Swap");
    }

    #[test]
    fn format_domain_empty_tld() {
        assert_eq!(format_domain("localhost", ""), "localhost");
    }

    #[test]
    fn format_domain_with_tld() {
        assert_eq!(format_domain("example", "com"), "example.com");
    }
}
