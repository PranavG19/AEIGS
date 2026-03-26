use std::collections::HashMap;
use std::fmt;

use regex::Regex;

/// Social platform identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocialPlatform {
    Twitter,
    LinkedIn,
    GitHub,
    Reddit,
    Facebook,
    Instagram,
    Medium,
    StackOverflow,
    HackerNews,
    Mastodon,
    Telegram,
    Discord,
}

impl fmt::Display for SocialPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Twitter => write!(f, "Twitter/X"),
            Self::LinkedIn => write!(f, "LinkedIn"),
            Self::GitHub => write!(f, "GitHub"),
            Self::Reddit => write!(f, "Reddit"),
            Self::Facebook => write!(f, "Facebook"),
            Self::Instagram => write!(f, "Instagram"),
            Self::Medium => write!(f, "Medium"),
            Self::StackOverflow => write!(f, "Stack Overflow"),
            Self::HackerNews => write!(f, "Hacker News"),
            Self::Mastodon => write!(f, "Mastodon"),
            Self::Telegram => write!(f, "Telegram"),
            Self::Discord => write!(f, "Discord"),
        }
    }
}

/// Confidence level for correlations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CorrelationConfidence {
    Low,
    Medium,
    High,
    VeryHigh,
}

impl fmt::Display for CorrelationConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::VeryHigh => write!(f, "Very High"),
        }
    }
}

/// A social media post for timing analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct SocialPost {
    pub platform: SocialPlatform,
    pub username: String,
    pub timestamp_unix: u64,
    pub content: String,
    pub hour_of_day: u8,
    pub day_of_week: u8,
}

/// Post timing pattern analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct TimingPattern {
    pub username: String,
    pub platform: SocialPlatform,
    pub most_active_hours: Vec<u8>,
    pub most_active_days: Vec<u8>,
    pub avg_posts_per_day: f64,
    pub timezone_estimate: Option<String>,
    pub total_posts_analyzed: usize,
}

/// Stylometric features extracted from text.
#[derive(Debug, Clone, PartialEq)]
pub struct StylometricProfile {
    pub username: String,
    pub avg_word_length: f64,
    pub avg_sentence_length: f64,
    pub vocabulary_richness: f64,
    pub punctuation_frequency: HashMap<char, f64>,
    pub function_word_frequency: HashMap<String, f64>,
    pub capitalization_rate: f64,
    pub emoji_usage_rate: f64,
    pub total_samples: usize,
}

/// Content reuse detection result.
#[derive(Debug, Clone, PartialEq)]
pub struct ContentReuseMatch {
    pub source_platform: SocialPlatform,
    pub source_username: String,
    pub target_platform: SocialPlatform,
    pub target_username: String,
    pub similarity_score: f64,
    pub matching_phrases: Vec<String>,
    pub is_likely_same_person: bool,
}

/// Cross-platform correlation finding.
#[derive(Debug, Clone, PartialEq)]
pub struct CrossPlatformCorrelation {
    pub account_a: (SocialPlatform, String),
    pub account_b: (SocialPlatform, String),
    pub timing_similarity: f64,
    pub stylometric_similarity: f64,
    pub content_reuse_score: f64,
    pub overall_score: f64,
    pub confidence: CorrelationConfidence,
    pub evidence: Vec<String>,
}

/// Full social correlation report.
#[derive(Debug, Clone, PartialEq)]
pub struct SocialCorrelationReport {
    pub target: String,
    pub timing_patterns: Vec<TimingPattern>,
    pub stylometric_profiles: Vec<StylometricProfile>,
    pub content_reuse: Vec<ContentReuseMatch>,
    pub correlations: Vec<CrossPlatformCorrelation>,
    pub total_accounts_analyzed: usize,
    pub high_confidence_links: usize,
}

/// Analyzes posting time patterns from a set of posts.
pub fn analyze_timing_patterns(
    username: &str,
    platform: SocialPlatform,
    posts: &[SocialPost],
) -> TimingPattern {
    let mut hour_counts = [0usize; 24];
    let mut day_counts = [0usize; 7];

    for post in posts {
        if post.hour_of_day < 24 {
            hour_counts[post.hour_of_day as usize] += 1;
        }
        if post.day_of_week < 7 {
            day_counts[post.day_of_week as usize] += 1;
        }
    }

    let max_hour_count = hour_counts.iter().max().copied().unwrap_or(0);
    let threshold = (max_hour_count as f64 * 0.6) as usize;
    let most_active_hours: Vec<u8> = hour_counts
        .iter()
        .enumerate()
        .filter(|(_, count)| **count > threshold)
        .map(|(h, _)| h as u8)
        .collect();

    let max_day_count = day_counts.iter().max().copied().unwrap_or(0);
    let day_threshold = (max_day_count as f64 * 0.6) as usize;
    let most_active_days: Vec<u8> = day_counts
        .iter()
        .enumerate()
        .filter(|(_, count)| **count > day_threshold)
        .map(|(d, _)| d as u8)
        .collect();

    let unique_days: std::collections::HashSet<u64> =
        posts.iter().map(|p| p.timestamp_unix / 86400).collect();
    let avg_posts_per_day = if !unique_days.is_empty() {
        posts.len() as f64 / unique_days.len() as f64
    } else {
        0.0
    };

    let timezone_estimate = estimate_timezone(&most_active_hours);

    TimingPattern {
        username: username.to_string(),
        platform,
        most_active_hours,
        most_active_days,
        avg_posts_per_day,
        timezone_estimate,
        total_posts_analyzed: posts.len(),
    }
}

fn estimate_timezone(active_hours: &[u8]) -> Option<String> {
    if active_hours.is_empty() {
        return None;
    }
    let avg_hour: f64 =
        active_hours.iter().map(|&h| h as f64).sum::<f64>() / active_hours.len() as f64;

    if (9.0..=17.0).contains(&avg_hour) {
        Some("UTC-5 to UTC-8 (Americas)".to_string())
    } else if (1.0..=9.0).contains(&avg_hour) {
        Some("UTC+5 to UTC+9 (Asia)".to_string())
    } else {
        Some("UTC+0 to UTC+3 (Europe/Africa)".to_string())
    }
}

/// Computes stylometric features from text samples.
pub fn build_stylometric_profile(username: &str, text_samples: &[&str]) -> StylometricProfile {
    let mut total_words = 0usize;
    let mut total_word_len = 0usize;
    let mut total_sentences = 0usize;
    let mut words_in_sentences = 0usize;
    let mut total_chars = 0usize;
    let mut upper_chars = 0usize;
    let mut emoji_count = 0usize;
    let mut punctuation_counts: HashMap<char, usize> = HashMap::new();
    let mut word_counts: HashMap<String, usize> = HashMap::new();

    let function_words = [
        "the", "a", "an", "is", "was", "are", "were", "be", "been", "being", "have", "has", "had",
        "do", "does", "did", "will", "would", "could", "should", "may", "might", "can", "shall",
        "to", "of", "in", "for", "on", "with", "at", "by", "from", "but", "and", "or", "not", "no",
        "so", "if", "then", "that", "this", "it", "i", "you", "he", "she", "we", "they",
    ];

    for sample in text_samples {
        for ch in sample.chars() {
            total_chars += 1;
            if ch.is_uppercase() {
                upper_chars += 1;
            }
            if ".,;:!?-()\"'".contains(ch) {
                *punctuation_counts.entry(ch).or_insert(0) += 1;
            }
            if ch as u32 > 0x1F600 {
                emoji_count += 1;
            }
        }

        let words: Vec<&str> = sample.split_whitespace().collect();
        total_words += words.len();
        for w in &words {
            total_word_len += w.len();
            let lower = w
                .to_lowercase()
                .trim_matches(|c: char| !c.is_alphanumeric())
                .to_string();
            if !lower.is_empty() {
                *word_counts.entry(lower).or_insert(0) += 1;
            }
        }

        let sentences: Vec<&str> = sample
            .split(|c| c == '.' || c == '!' || c == '?')
            .filter(|s| !s.trim().is_empty())
            .collect();
        total_sentences += sentences.len();
        for s in &sentences {
            words_in_sentences += s.split_whitespace().count();
        }
    }

    let avg_word_length = if total_words > 0 {
        total_word_len as f64 / total_words as f64
    } else {
        0.0
    };

    let avg_sentence_length = if total_sentences > 0 {
        words_in_sentences as f64 / total_sentences as f64
    } else {
        0.0
    };

    let vocabulary_richness = if total_words > 0 {
        word_counts.len() as f64 / total_words as f64
    } else {
        0.0
    };

    let capitalization_rate = if total_chars > 0 {
        upper_chars as f64 / total_chars as f64
    } else {
        0.0
    };

    let emoji_usage_rate = if total_words > 0 {
        emoji_count as f64 / total_words as f64
    } else {
        0.0
    };

    let total_punct: usize = punctuation_counts.values().sum();
    let punctuation_frequency: HashMap<char, f64> = punctuation_counts
        .iter()
        .map(|(&c, &count)| {
            (
                c,
                if total_punct > 0 {
                    count as f64 / total_punct as f64
                } else {
                    0.0
                },
            )
        })
        .collect();

    let mut function_word_freq: HashMap<String, f64> = HashMap::new();
    for fw in &function_words {
        let count = word_counts.get(*fw).copied().unwrap_or(0);
        if total_words > 0 {
            function_word_freq.insert(fw.to_string(), count as f64 / total_words as f64);
        }
    }

    StylometricProfile {
        username: username.to_string(),
        avg_word_length,
        avg_sentence_length,
        vocabulary_richness,
        punctuation_frequency,
        function_word_frequency: function_word_freq,
        capitalization_rate,
        emoji_usage_rate,
        total_samples: text_samples.len(),
    }
}

/// Compares timing patterns for similarity (0.0 to 1.0).
pub fn compare_timing_patterns(a: &TimingPattern, b: &TimingPattern) -> f64 {
    let hour_overlap = set_overlap(&a.most_active_hours, &b.most_active_hours);
    let day_overlap = set_overlap(&a.most_active_days, &b.most_active_days);
    0.7 * hour_overlap + 0.3 * day_overlap
}

fn set_overlap<T: PartialEq>(a: &[T], b: &[T]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let intersection = a.iter().filter(|x| b.contains(x)).count();
    let union = a.len() + b.len() - intersection;
    if union == 0 {
        1.0
    } else {
        intersection as f64 / union as f64
    }
}

/// Compares stylometric profiles (0.0 to 1.0).
pub fn compare_stylometric_profiles(a: &StylometricProfile, b: &StylometricProfile) -> f64 {
    let word_len_sim = 1.0 - (a.avg_word_length - b.avg_word_length).abs() / 10.0;
    let sent_len_sim = 1.0 - (a.avg_sentence_length - b.avg_sentence_length).abs() / 50.0;
    let vocab_sim = 1.0 - (a.vocabulary_richness - b.vocabulary_richness).abs();
    let cap_sim = 1.0 - (a.capitalization_rate - b.capitalization_rate).abs();

    let scores = [word_len_sim, sent_len_sim, vocab_sim, cap_sim];
    let avg: f64 = scores.iter().sum::<f64>() / scores.len() as f64;
    avg.clamp(0.0, 1.0)
}

/// Detects content reuse between posts using n-gram comparison.
pub fn detect_content_reuse(
    source_posts: &[(SocialPlatform, &str, &str)],
    target_posts: &[(SocialPlatform, &str, &str)],
    threshold: f64,
) -> Vec<ContentReuseMatch> {
    let mut matches = Vec::new();

    for (sp, su, sc) in source_posts {
        let source_ngrams = extract_ngrams(sc, 3);
        for (tp, tu, tc) in target_posts {
            if sp == tp && su == tu {
                continue;
            }
            let target_ngrams = extract_ngrams(tc, 3);
            let similarity = ngram_similarity(&source_ngrams, &target_ngrams);
            if similarity >= threshold {
                let matching_phrases = find_matching_phrases(sc, tc);
                matches.push(ContentReuseMatch {
                    source_platform: *sp,
                    source_username: su.to_string(),
                    target_platform: *tp,
                    target_username: tu.to_string(),
                    similarity_score: similarity,
                    matching_phrases,
                    is_likely_same_person: similarity > 0.7,
                });
            }
        }
    }

    matches
}

fn extract_ngrams(text: &str, n: usize) -> Vec<String> {
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.len() < n {
        return vec![words.join(" ").to_lowercase()];
    }
    words
        .windows(n)
        .map(|w| w.join(" ").to_lowercase())
        .collect()
}

fn ngram_similarity(a: &[String], b: &[String]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let intersection = a.iter().filter(|x| b.contains(x)).count();
    let union = a.len() + b.len() - intersection;
    if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    }
}

fn find_matching_phrases(a: &str, b: &str) -> Vec<String> {
    let a_words: Vec<&str> = a.split_whitespace().collect();
    let b_lower = b.to_lowercase();
    let mut phrases = Vec::new();

    for window in a_words.windows(4) {
        let phrase = window.join(" ").to_lowercase();
        if b_lower.contains(&phrase) {
            phrases.push(phrase);
        }
    }

    phrases.truncate(5);
    phrases
}

/// Builds a cross-platform correlation.
pub fn correlate_accounts(
    account_a: (SocialPlatform, &str),
    account_b: (SocialPlatform, &str),
    timing_sim: f64,
    stylometric_sim: f64,
    content_sim: f64,
) -> CrossPlatformCorrelation {
    let overall = 0.3 * timing_sim + 0.4 * stylometric_sim + 0.3 * content_sim;

    let confidence = if overall > 0.8 {
        CorrelationConfidence::VeryHigh
    } else if overall > 0.6 {
        CorrelationConfidence::High
    } else if overall > 0.4 {
        CorrelationConfidence::Medium
    } else {
        CorrelationConfidence::Low
    };

    let mut evidence = Vec::new();
    if timing_sim > 0.7 {
        evidence.push("Strong posting time correlation".to_string());
    }
    if stylometric_sim > 0.7 {
        evidence.push("Similar writing style detected".to_string());
    }
    if content_sim > 0.5 {
        evidence.push("Content reuse detected".to_string());
    }

    CrossPlatformCorrelation {
        account_a: (account_a.0, account_a.1.to_string()),
        account_b: (account_b.0, account_b.1.to_string()),
        timing_similarity: timing_sim,
        stylometric_similarity: stylometric_sim,
        content_reuse_score: content_sim,
        overall_score: overall,
        confidence,
        evidence,
    }
}

/// Builds a full social correlation report.
pub fn build_social_correlation_report(
    target: &str,
    timing_patterns: Vec<TimingPattern>,
    stylometric_profiles: Vec<StylometricProfile>,
    content_reuse: Vec<ContentReuseMatch>,
    correlations: Vec<CrossPlatformCorrelation>,
) -> SocialCorrelationReport {
    let total = timing_patterns.len();
    let high_confidence = correlations
        .iter()
        .filter(|c| c.confidence >= CorrelationConfidence::High)
        .count();

    SocialCorrelationReport {
        target: target.to_string(),
        timing_patterns,
        stylometric_profiles,
        content_reuse,
        correlations,
        total_accounts_analyzed: total,
        high_confidence_links: high_confidence,
    }
}
