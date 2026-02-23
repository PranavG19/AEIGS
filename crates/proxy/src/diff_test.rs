use super::*;

#[test]
fn identical_strings_all_equal() {
    let text = "line one\nline two\nline three";
    let result = compute_line_diff(text, text);
    assert_eq!(
        result,
        vec![
            DiffChunk::Equal("line one".into()),
            DiffChunk::Equal("line two".into()),
            DiffChunk::Equal("line three".into()),
        ]
    );
}

#[test]
fn completely_different() {
    let result = compute_line_diff("alpha\nbeta", "gamma\ndelta");
    assert_eq!(
        result,
        vec![
            DiffChunk::Removed("alpha".into()),
            DiffChunk::Removed("beta".into()),
            DiffChunk::Added("gamma".into()),
            DiffChunk::Added("delta".into()),
        ]
    );
}

#[test]
fn line_inserted_in_middle() {
    let left = "aaa\nccc";
    let right = "aaa\nbbb\nccc";
    let result = compute_line_diff(left, right);
    assert_eq!(
        result,
        vec![
            DiffChunk::Equal("aaa".into()),
            DiffChunk::Added("bbb".into()),
            DiffChunk::Equal("ccc".into()),
        ]
    );
}

#[test]
fn line_removed_from_middle() {
    let left = "aaa\nbbb\nccc";
    let right = "aaa\nccc";
    let result = compute_line_diff(left, right);
    assert_eq!(
        result,
        vec![
            DiffChunk::Equal("aaa".into()),
            DiffChunk::Removed("bbb".into()),
            DiffChunk::Equal("ccc".into()),
        ]
    );
}

#[test]
fn empty_left() {
    let result = compute_line_diff("", "foo\nbar");
    assert_eq!(
        result,
        vec![
            DiffChunk::Added("foo".into()),
            DiffChunk::Added("bar".into()),
        ]
    );
}

#[test]
fn empty_right() {
    let result = compute_line_diff("foo\nbar", "");
    assert_eq!(
        result,
        vec![
            DiffChunk::Removed("foo".into()),
            DiffChunk::Removed("bar".into()),
        ]
    );
}

#[test]
fn both_empty() {
    let result = compute_line_diff("", "");
    assert!(result.is_empty());
}

#[test]
fn word_diff_detects_changed_words() {
    let left = "the quick brown fox";
    let right = "the slow brown cat";
    let result = compute_word_diff(left, right);
    assert_eq!(
        result,
        vec![
            WordDiff::Equal("the".into()),
            WordDiff::Removed("quick".into()),
            WordDiff::Added("slow".into()),
            WordDiff::Equal("brown".into()),
            WordDiff::Removed("fox".into()),
            WordDiff::Added("cat".into()),
        ]
    );
}

#[test]
fn compare_headers_added() {
    let old: Vec<(String, String)> = vec![];
    let new = vec![("x-new".into(), "val".into())];
    let result = compare_headers(&old, &new);
    assert_eq!(
        result,
        vec![HeaderDiff::Added("x-new".into(), "val".into())]
    );
}

#[test]
fn compare_headers_removed() {
    let old = vec![("x-old".into(), "val".into())];
    let new: Vec<(String, String)> = vec![];
    let result = compare_headers(&old, &new);
    assert_eq!(
        result,
        vec![HeaderDiff::Removed("x-old".into(), "val".into())]
    );
}

#[test]
fn compare_headers_changed() {
    let old = vec![("content-type".into(), "text/plain".into())];
    let new = vec![("content-type".into(), "text/html".into())];
    let result = compare_headers(&old, &new);
    assert_eq!(
        result,
        vec![HeaderDiff::Changed(
            "content-type".into(),
            "text/plain".into(),
            "text/html".into()
        )]
    );
}

#[test]
fn compare_headers_unchanged() {
    let headers = vec![
        ("content-type".into(), "text/plain".into()),
        ("x-custom".into(), "123".into()),
    ];
    let result = compare_headers(&headers, &headers);
    assert!(result.is_empty());
}

#[test]
fn compare_responses_status_change() {
    let result = compare_responses(200, &[], b"ok", 100, 404, &[], b"not found", 150);
    assert!(result.status_changed);
    assert_eq!(result.old_status, 200);
    assert_eq!(result.new_status, 404);
}

#[test]
fn compare_responses_identical() {
    let headers = vec![("content-type".to_string(), "text/plain".to_string())];
    let body = b"hello world";
    let result = compare_responses(200, &headers, body, 50, 200, &headers, body, 50);
    assert!(!result.status_changed);
    assert!(result.header_diffs.is_empty());
    assert_eq!(result.body_length_delta, 0);
    assert!(
        result
            .body_diff
            .iter()
            .all(|c| matches!(c, DiffChunk::Equal(_)))
    );
}

#[test]
fn compare_responses_body_length_delta() {
    let old_body = b"short";
    let new_body = b"a much longer body here";
    let result = compare_responses(200, &[], old_body, 10, 200, &[], new_body, 20);
    assert_eq!(
        result.body_length_delta,
        new_body.len() as i64 - old_body.len() as i64
    );
    assert_eq!(result.duration_delta_ms, 10);
}
