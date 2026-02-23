use crate::wordlist::{default_wordlist, parse_wordlist};

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
