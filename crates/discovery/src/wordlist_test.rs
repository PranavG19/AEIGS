use crate::wordlist::{
    default_wordlist, load_wordlist_from_path, parse_wordlist, seclists_directories,
    seclists_params,
};
use std::path::Path;

#[test]
fn default_wordlist_is_non_empty() {
    let words = default_wordlist();
    assert!(
        words.len() > 1500,
        "expected >1500 words, got {}",
        words.len()
    );
}

#[test]
fn default_wordlist_contains_no_blank_lines() {
    let words = default_wordlist();
    for word in &words {
        assert!(!word.is_empty(), "found empty entry in default wordlist");
        assert!(
            !word.contains('\n'),
            "found newline in wordlist entry: {word:?}"
        );
    }
}

#[test]
fn default_wordlist_contains_expected_paths() {
    let words = default_wordlist();
    let expected = vec![
        "admin",
        ".env",
        ".git/config",
        "backup",
        "actuator",
        "robots.txt",
    ];
    for expected_word in expected {
        assert!(
            words.contains(&expected_word.to_string()),
            "default wordlist missing expected entry: {expected_word}"
        );
    }
}

#[test]
fn parse_wordlist_skips_comments_and_blanks() {
    let input = "# comment\nadmin\n\n  backup  \n# another comment\n.env\n";
    let words = parse_wordlist(input);
    assert_eq!(words, vec!["admin", "backup", ".env"]);
}

#[test]
fn parse_wordlist_empty_input() {
    let words = parse_wordlist("");
    assert!(words.is_empty());
}

#[test]
fn parse_wordlist_all_comments() {
    let input = "# comment 1\n# comment 2\n";
    let words = parse_wordlist(input);
    assert!(words.is_empty());
}

#[test]
fn default_wordlist_has_no_duplicates() {
    let words = default_wordlist();
    let unique: std::collections::HashSet<_> = words.iter().collect();
    assert_eq!(
        words.len(),
        unique.len(),
        "default wordlist contains duplicates"
    );
}

#[test]
fn load_wordlist_from_path_nonexistent_returns_empty() {
    let words = load_wordlist_from_path(Path::new("/nonexistent/wordlist.txt"));
    assert!(words.is_empty());
}

#[test]
fn load_wordlist_from_path_valid_file() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("test.txt");
    std::fs::write(&file_path, "# comment\nadmin\nbackup\n\n.env\n").unwrap();
    let words = load_wordlist_from_path(&file_path);
    assert_eq!(words, vec!["admin", "backup", ".env"]);
}

#[test]
fn load_wordlist_from_path_filters_comments_and_blanks() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("filtered.txt");
    std::fs::write(&file_path, "# header\n\nfoo\n# middle\nbar\n").unwrap();
    let words = load_wordlist_from_path(&file_path);
    assert_eq!(words, vec!["foo", "bar"]);
}

#[test]
fn seclists_directories_nonexistent_base_returns_empty() {
    let words = seclists_directories(Path::new("/nonexistent/seclists"));
    assert!(words.is_empty());
}

#[test]
fn seclists_params_nonexistent_base_returns_empty() {
    let words = seclists_params(Path::new("/nonexistent/seclists"));
    assert!(words.is_empty());
}

#[test]
fn seclists_directories_reads_correct_path() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("Discovery").join("Web-Content");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("raft-large-directories.txt"), "admin\napi\n").unwrap();
    let words = seclists_directories(dir.path());
    assert_eq!(words, vec!["admin", "api"]);
}

#[test]
fn seclists_params_reads_correct_path() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("Discovery").join("Web-Content");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("burp-parameter-names.txt"), "id\nname\nq\n").unwrap();
    let words = seclists_params(dir.path());
    assert_eq!(words, vec!["id", "name", "q"]);
}
