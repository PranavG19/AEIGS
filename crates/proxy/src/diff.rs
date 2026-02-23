/// A chunk in a line-level diff result.
#[derive(Debug, Clone, PartialEq)]
pub enum DiffChunk {
    Equal(String),
    Added(String),
    Removed(String),
}

/// A chunk in a word-level diff result.
#[derive(Debug, Clone, PartialEq)]
pub enum WordDiff {
    Equal(String),
    Added(String),
    Removed(String),
}

/// A difference between two sets of HTTP headers.
#[derive(Debug, Clone, PartialEq)]
pub enum HeaderDiff {
    Added(String, String),
    Removed(String, String),
    Changed(String, String, String),
}

/// Full comparison result between two HTTP responses.
#[derive(Debug, Clone)]
pub struct DiffResult {
    pub status_changed: bool,
    pub old_status: u16,
    pub new_status: u16,
    pub header_diffs: Vec<HeaderDiff>,
    pub body_diff: Vec<DiffChunk>,
    pub body_length_delta: i64,
    pub duration_delta_ms: i64,
}

/// Computes a line-level diff between two strings using LCS.
pub fn compute_line_diff(left: &str, right: &str) -> Vec<DiffChunk> {
    let left_lines: Vec<&str> = if left.is_empty() {
        vec![]
    } else {
        left.split('\n').collect()
    };
    let right_lines: Vec<&str> = if right.is_empty() {
        vec![]
    } else {
        right.split('\n').collect()
    };
    lcs_diff(
        &left_lines,
        &right_lines,
        DiffChunk::Equal,
        DiffChunk::Removed,
        DiffChunk::Added,
    )
}

/// Computes a word-level diff between two strings using LCS.
pub fn compute_word_diff(left: &str, right: &str) -> Vec<WordDiff> {
    let left_words: Vec<&str> = left.split_whitespace().collect();
    let right_words: Vec<&str> = right.split_whitespace().collect();
    lcs_diff(
        &left_words,
        &right_words,
        WordDiff::Equal,
        WordDiff::Removed,
        WordDiff::Added,
    )
}

fn lcs_diff<T: PartialEq + Clone>(
    left: &[&str],
    right: &[&str],
    eq: fn(String) -> T,
    rem: fn(String) -> T,
    add: fn(String) -> T,
) -> Vec<T> {
    let n = left.len();
    let m = right.len();
    let mut table = vec![vec![0u32; m + 1]; n + 1];
    for i in 1..=n {
        for j in 1..=m {
            table[i][j] = if left[i - 1] == right[j - 1] {
                table[i - 1][j - 1] + 1
            } else {
                table[i - 1][j].max(table[i][j - 1])
            };
        }
    }
    let mut result = Vec::new();
    let (mut i, mut j) = (n, m);
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && left[i - 1] == right[j - 1] {
            result.push(eq(left[i - 1].to_string()));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || table[i][j - 1] >= table[i - 1][j]) {
            result.push(add(right[j - 1].to_string()));
            j -= 1;
        } else {
            result.push(rem(left[i - 1].to_string()));
            i -= 1;
        }
    }
    result.reverse();
    result
}

/// Compares two sets of HTTP headers, returning additions, removals, and changes.
pub fn compare_headers(old: &[(String, String)], new: &[(String, String)]) -> Vec<HeaderDiff> {
    let mut diffs = Vec::new();
    for (name, old_val) in old {
        match new.iter().find(|(n, _)| n == name) {
            Some((_, new_val)) if new_val != old_val => {
                diffs.push(HeaderDiff::Changed(
                    name.clone(),
                    old_val.clone(),
                    new_val.clone(),
                ));
            }
            None => diffs.push(HeaderDiff::Removed(name.clone(), old_val.clone())),
            _ => {}
        }
    }
    for (name, val) in new {
        if !old.iter().any(|(n, _)| n == name) {
            diffs.push(HeaderDiff::Added(name.clone(), val.clone()));
        }
    }
    diffs
}

/// Compares two HTTP responses, producing a full diff result.
#[allow(clippy::too_many_arguments)]
pub fn compare_responses(
    old_status: u16,
    old_headers: &[(String, String)],
    old_body: &[u8],
    old_duration: u64,
    new_status: u16,
    new_headers: &[(String, String)],
    new_body: &[u8],
    new_duration: u64,
) -> DiffResult {
    let old_text = String::from_utf8_lossy(old_body);
    let new_text = String::from_utf8_lossy(new_body);
    DiffResult {
        status_changed: old_status != new_status,
        old_status,
        new_status,
        header_diffs: compare_headers(old_headers, new_headers),
        body_diff: compute_line_diff(&old_text, &new_text),
        body_length_delta: new_body.len() as i64 - old_body.len() as i64,
        duration_delta_ms: new_duration as i64 - old_duration as i64,
    }
}

#[cfg(test)]
#[path = "diff_test.rs"]
mod diff_test;
