use super::social_correlator::*;
use std::collections::HashMap;

#[test]
fn analyze_timing_patterns_basic() {
    let posts: Vec<SocialPost> = (0..20)
        .map(|i| SocialPost {
            platform: SocialPlatform::Twitter,
            username: "testuser".to_string(),
            timestamp_unix: 1700000000 + i * 3600,
            content: "test post".to_string(),
            hour_of_day: (10 + i % 4) as u8,
            day_of_week: (i % 5) as u8,
        })
        .collect();

    let pattern = analyze_timing_patterns("testuser", SocialPlatform::Twitter, &posts);
    assert_eq!(pattern.username, "testuser");
    assert_eq!(pattern.total_posts_analyzed, 20);
    assert!(!pattern.most_active_hours.is_empty());
    assert!(pattern.avg_posts_per_day > 0.0);
    assert!(pattern.timezone_estimate.is_some());
}

#[test]
fn analyze_timing_patterns_empty() {
    let pattern = analyze_timing_patterns("nobody", SocialPlatform::Reddit, &[]);
    assert_eq!(pattern.total_posts_analyzed, 0);
    assert!(pattern.most_active_hours.is_empty());
    assert_eq!(pattern.avg_posts_per_day, 0.0);
}

#[test]
fn build_stylometric_profile_basic() {
    let samples = vec![
        "The quick brown fox jumps over the lazy dog. It was a beautiful day.",
        "She said that the project would be completed by Friday. Everyone agreed.",
        "I think we should consider the implications. But what do I know!",
    ];
    let profile = build_stylometric_profile("writer1", &samples);
    assert_eq!(profile.username, "writer1");
    assert_eq!(profile.total_samples, 3);
    assert!(profile.avg_word_length > 2.0);
    assert!(profile.avg_sentence_length > 3.0);
    assert!(profile.vocabulary_richness > 0.0);
    assert!(!profile.punctuation_frequency.is_empty());
    assert!(!profile.function_word_frequency.is_empty());
}

#[test]
fn build_stylometric_profile_empty() {
    let profile = build_stylometric_profile("empty", &[]);
    assert_eq!(profile.total_samples, 0);
    assert_eq!(profile.avg_word_length, 0.0);
}

#[test]
fn compare_timing_patterns_identical() {
    let pattern = TimingPattern {
        username: "test".into(),
        platform: SocialPlatform::Twitter,
        most_active_hours: vec![9, 10, 11, 14, 15],
        most_active_days: vec![1, 2, 3, 4, 5],
        avg_posts_per_day: 3.0,
        timezone_estimate: None,
        total_posts_analyzed: 100,
    };
    let sim = compare_timing_patterns(&pattern, &pattern);
    assert!((sim - 1.0).abs() < 0.01);
}

#[test]
fn compare_timing_patterns_different() {
    let a = TimingPattern {
        username: "morning".into(),
        platform: SocialPlatform::Twitter,
        most_active_hours: vec![6, 7, 8, 9],
        most_active_days: vec![1, 2, 3, 4, 5],
        avg_posts_per_day: 2.0,
        timezone_estimate: None,
        total_posts_analyzed: 50,
    };
    let b = TimingPattern {
        username: "night".into(),
        platform: SocialPlatform::Reddit,
        most_active_hours: vec![22, 23, 0, 1],
        most_active_days: vec![5, 6],
        avg_posts_per_day: 5.0,
        timezone_estimate: None,
        total_posts_analyzed: 50,
    };
    let sim = compare_timing_patterns(&a, &b);
    assert!(sim < 0.3);
}

#[test]
fn compare_stylometric_profiles_similar() {
    let a = StylometricProfile {
        username: "a".into(),
        avg_word_length: 5.0,
        avg_sentence_length: 15.0,
        vocabulary_richness: 0.7,
        punctuation_frequency: HashMap::new(),
        function_word_frequency: HashMap::new(),
        capitalization_rate: 0.05,
        emoji_usage_rate: 0.0,
        total_samples: 10,
    };
    let b = StylometricProfile {
        username: "b".into(),
        avg_word_length: 5.2,
        avg_sentence_length: 14.5,
        vocabulary_richness: 0.68,
        punctuation_frequency: HashMap::new(),
        function_word_frequency: HashMap::new(),
        capitalization_rate: 0.06,
        emoji_usage_rate: 0.0,
        total_samples: 10,
    };
    let sim = compare_stylometric_profiles(&a, &b);
    assert!(sim > 0.8);
}

#[test]
fn detect_content_reuse_match() {
    let source = vec![(
        SocialPlatform::Twitter,
        "user1",
        "I believe that artificial intelligence will fundamentally transform our society",
    )];
    let target = vec![(
        SocialPlatform::LinkedIn,
        "user2",
        "I believe that artificial intelligence will fundamentally change the world",
    )];
    let matches = detect_content_reuse(&source, &target, 0.1);
    assert!(!matches.is_empty());
    assert!(matches[0].similarity_score > 0.0);
}

#[test]
fn detect_content_reuse_no_match() {
    let source = vec![(
        SocialPlatform::Twitter,
        "user1",
        "the cat sat on a mat today",
    )];
    let target = vec![(
        SocialPlatform::Reddit,
        "user2",
        "quantum physics describes wave particle duality",
    )];
    let matches = detect_content_reuse(&source, &target, 0.5);
    assert!(matches.is_empty());
}

#[test]
fn detect_content_reuse_same_user_skipped() {
    let source = vec![(SocialPlatform::Twitter, "user1", "same exact content here")];
    let target = vec![(SocialPlatform::Twitter, "user1", "same exact content here")];
    let matches = detect_content_reuse(&source, &target, 0.1);
    assert!(matches.is_empty());
}

#[test]
fn correlate_accounts_high() {
    let corr = correlate_accounts(
        (SocialPlatform::Twitter, "alice_t"),
        (SocialPlatform::GitHub, "alice_gh"),
        0.9,
        0.85,
        0.8,
    );
    assert_eq!(corr.confidence, CorrelationConfidence::VeryHigh);
    assert!(corr.overall_score > 0.8);
    assert!(!corr.evidence.is_empty());
}

#[test]
fn correlate_accounts_low() {
    let corr = correlate_accounts(
        (SocialPlatform::Twitter, "bob"),
        (SocialPlatform::Reddit, "charlie"),
        0.1,
        0.2,
        0.1,
    );
    assert_eq!(corr.confidence, CorrelationConfidence::Low);
    assert!(corr.overall_score < 0.4);
}

#[test]
fn build_social_correlation_report_counts() {
    let timing = vec![TimingPattern {
        username: "test".into(),
        platform: SocialPlatform::Twitter,
        most_active_hours: vec![10],
        most_active_days: vec![1],
        avg_posts_per_day: 1.0,
        timezone_estimate: None,
        total_posts_analyzed: 10,
    }];
    let corr = vec![CrossPlatformCorrelation {
        account_a: (SocialPlatform::Twitter, "a".into()),
        account_b: (SocialPlatform::GitHub, "b".into()),
        timing_similarity: 0.9,
        stylometric_similarity: 0.8,
        content_reuse_score: 0.7,
        overall_score: 0.85,
        confidence: CorrelationConfidence::VeryHigh,
        evidence: vec!["Strong match".into()],
    }];
    let report = build_social_correlation_report("target", timing, vec![], vec![], corr);
    assert_eq!(report.total_accounts_analyzed, 1);
    assert_eq!(report.high_confidence_links, 1);
}

#[test]
fn social_platform_display() {
    assert_eq!(SocialPlatform::Twitter.to_string(), "Twitter/X");
    assert_eq!(SocialPlatform::HackerNews.to_string(), "Hacker News");
}

#[test]
fn correlation_confidence_ordering() {
    assert!(CorrelationConfidence::VeryHigh > CorrelationConfidence::High);
    assert!(CorrelationConfidence::High > CorrelationConfidence::Medium);
}
