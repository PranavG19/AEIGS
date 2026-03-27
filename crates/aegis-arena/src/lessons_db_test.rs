use super::*;
use crate::red_agent::RedRoundResult;

fn mock_red_capture() -> RedRoundResult {
    RedRoundResult {
        flag_captured: true,
        flag_value: Some("CTF{test}".to_string()),
        requests_sent: 5,
        vulns_found: vec!["sqli_search_0".to_string()],
        blocked_count: 0,
        request_log: Vec::new(),
        techniques_used: vec!["sqli_search_0".to_string()],
        raw_output: String::new(),
    }
}

fn mock_red_blocked() -> RedRoundResult {
    RedRoundResult {
        flag_captured: false,
        flag_value: None,
        requests_sent: 10,
        vulns_found: Vec::new(),
        blocked_count: 5,
        request_log: Vec::new(),
        techniques_used: vec!["sqli_search_0".to_string(), "lfi_file_0".to_string()],
        raw_output: String::new(),
    }
}

#[test]
fn extract_lessons_from_red_capture() {
    let mut db = LessonsDb::new();
    let red = mock_red_capture();

    db.extract_lessons(1, "match_1", &red, &[], &[]);

    assert!(!db.is_empty());
    let lesson = &db.lessons[0];
    assert_eq!(lesson.source, LessonSource::RedSuccess);
    assert!(lesson.description.contains("captured the flag"));
    assert_eq!(lesson.endpoint, "/search");
    assert_eq!(lesson.weight, 1.0);
}

#[test]
fn extract_lessons_from_blocked_attacks() {
    let mut db = LessonsDb::new();
    let red = mock_red_blocked();

    db.extract_lessons(2, "match_1", &red, &[], &[]);

    let failure_lessons: Vec<_> = db
        .lessons
        .iter()
        .filter(|l| l.source == LessonSource::RedFailure)
        .collect();
    assert!(!failure_lessons.is_empty());
    assert!(failure_lessons[0].description.contains("blocked"));
}

#[test]
fn extract_lessons_from_effective_patches() {
    let mut db = LessonsDb::new();
    let red = mock_red_blocked();

    db.extract_lessons(
        1,
        "match_1",
        &red,
        &["OR on /search".to_string()],
        &[],
    );

    let patch_lessons: Vec<_> = db
        .lessons
        .iter()
        .filter(|l| l.source == LessonSource::BluePatchWorked)
        .collect();
    assert!(!patch_lessons.is_empty());
    assert!(patch_lessons[0].description.contains("successfully blocked"));
}

#[test]
fn extract_lessons_from_failed_patches() {
    let mut db = LessonsDb::new();
    let red = mock_red_capture();

    db.extract_lessons(
        1,
        "match_1",
        &red,
        &[],
        &[".. on /file".to_string()],
    );

    let failed_lessons: Vec<_> = db
        .lessons
        .iter()
        .filter(|l| l.source == LessonSource::BluePatchFailed)
        .collect();
    assert!(!failed_lessons.is_empty());
    assert!(failed_lessons[0].description.contains("bypassed"));
}

#[test]
fn duplicate_lessons_merge() {
    let mut db = LessonsDb::new();
    let red = mock_red_capture();

    db.extract_lessons(1, "match_1", &red, &[], &[]);
    let initial_count = db.len();

    // Same technique/endpoint/source — should merge, not duplicate
    db.extract_lessons(2, "match_1", &red, &[], &[]);
    assert_eq!(db.len(), initial_count, "Should merge duplicate lessons");

    // Weight should be reinforced
    let lesson = &db.lessons[0];
    assert!(lesson.weight > 1.0, "Merged lesson should have higher weight");
}

#[test]
fn decay_reduces_weights() {
    let mut db = LessonsDb::new();
    let red = mock_red_capture();
    db.extract_lessons(1, "match_1", &red, &[], &[]);

    let original_weight = db.lessons[0].weight;
    db.apply_decay();
    assert!(
        db.lessons[0].weight < original_weight,
        "Decay should reduce weight"
    );
    assert!(
        (db.lessons[0].weight - original_weight * 0.8).abs() < f64::EPSILON,
        "Should decay by factor 0.8"
    );
}

#[test]
fn decay_removes_low_weight_lessons() {
    let mut db = LessonsDb::new();
    db.lessons.push(Lesson {
        technique: "old_technique".to_string(),
        endpoint: "/old".to_string(),
        description: "very old lesson".to_string(),
        source: LessonSource::RedSuccess,
        weight: 0.05,
        round: 1,
        match_id: "old_match".to_string(),
    });

    db.apply_decay();
    assert!(db.is_empty(), "Lessons below 0.1 should be removed after decay");
}

#[test]
fn top_lessons_sorted_by_weight() {
    let mut db = LessonsDb::new();
    db.lessons.push(Lesson {
        technique: "low".to_string(),
        endpoint: "/a".to_string(),
        description: "low weight".to_string(),
        source: LessonSource::RedSuccess,
        weight: 0.3,
        round: 1,
        match_id: "m1".to_string(),
    });
    db.lessons.push(Lesson {
        technique: "high".to_string(),
        endpoint: "/b".to_string(),
        description: "high weight".to_string(),
        source: LessonSource::RedSuccess,
        weight: 1.5,
        round: 2,
        match_id: "m1".to_string(),
    });
    db.lessons.push(Lesson {
        technique: "mid".to_string(),
        endpoint: "/c".to_string(),
        description: "mid weight".to_string(),
        source: LessonSource::RedFailure,
        weight: 0.8,
        round: 1,
        match_id: "m1".to_string(),
    });

    let top = db.top_lessons(2);
    assert_eq!(top.len(), 2);
    assert_eq!(top[0].technique, "high");
    assert_eq!(top[1].technique, "mid");
}

#[test]
fn briefing_text_formats_correctly() {
    let mut db = LessonsDb::new();
    let red = mock_red_capture();
    db.extract_lessons(1, "match_1", &red, &[], &[]);

    let text = db.briefing_text(5);
    assert!(text.contains("Lessons from Previous Matches"));
    assert!(text.contains("1."));
    assert!(text.contains("sqli_search_0"));
}

#[test]
fn briefing_text_empty_when_no_lessons() {
    let db = LessonsDb::new();
    let text = db.briefing_text(5);
    assert!(text.is_empty());
}

#[test]
fn cross_match_persistence_concept() {
    let mut db = LessonsDb::new();

    // Match 1
    let red1 = mock_red_capture();
    db.extract_lessons(1, "match_1", &red1, &[], &[]);

    // Decay between matches
    db.apply_decay();

    // Match 2 — lessons from match 1 should still be present
    assert!(!db.is_empty(), "Lessons should persist across matches");
    assert!(
        db.lessons[0].weight < 1.0,
        "Lessons from previous match should be decayed"
    );

    // New lessons in match 2
    let red2 = mock_red_blocked();
    db.extract_lessons(1, "match_2", &red2, &["OR on /search".to_string()], &[]);

    // Should have lessons from both matches
    assert!(db.len() > 1, "Should accumulate lessons across matches");
}

#[tokio::test]
async fn save_and_load_lessons() {
    let mut db = LessonsDb::new();
    let red = mock_red_capture();
    db.extract_lessons(1, "match_1", &red, &[], &[]);

    let path = std::env::temp_dir().join("aegis_test_lessons.json");
    db.save(&path).await.expect("save lessons");

    let loaded = LessonsDb::load(&path).await;
    assert_eq!(loaded.len(), db.len());
    assert_eq!(loaded.lessons[0].technique, "sqli_search_0");

    let _ = tokio::fs::remove_file(&path).await;
}

#[tokio::test]
async fn load_missing_file_returns_empty() {
    let db = LessonsDb::load(Path::new("/tmp/nonexistent_lessons_xyz.json")).await;
    assert!(db.is_empty());
}

#[test]
fn endpoint_extraction_from_technique() {
    assert_eq!(extract_endpoint_from_technique("sqli_search_0"), "/search");
    assert_eq!(extract_endpoint_from_technique("lfi_file_2"), "/file");
    assert_eq!(extract_endpoint_from_technique("ssti_template_1"), "/template");
    assert_eq!(extract_endpoint_from_technique("jwt_alg_none_admin"), "/admin");
    assert_eq!(extract_endpoint_from_technique("idor_profile_1"), "/profile");
    assert_eq!(extract_endpoint_from_technique("sqli_login_0"), "/login");
    assert_eq!(extract_endpoint_from_technique("unknown_thing"), "/unknown");
}
