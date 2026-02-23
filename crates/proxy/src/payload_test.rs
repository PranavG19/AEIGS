use super::*;
use std::io::Write;

#[test]
fn simple_list_generates_items() {
    let source = PayloadSource::SimpleList(vec!["alpha".into(), "beta".into(), "gamma".into()]);
    let result = source.generate().unwrap();
    assert_eq!(result, vec!["alpha", "beta", "gamma"]);
}

#[test]
fn number_range_generates_sequence() {
    let source = PayloadSource::NumberRange {
        start: 1,
        end: 5,
        step: 1,
    };
    let result = source.generate().unwrap();
    assert_eq!(result, vec!["1", "2", "3", "4", "5"]);
}

#[test]
fn number_range_with_step() {
    let source = PayloadSource::NumberRange {
        start: 0,
        end: 10,
        step: 3,
    };
    let result = source.generate().unwrap();
    assert_eq!(result, vec!["0", "3", "6", "9"]);
}

#[test]
fn null_payloads_generates_empties() {
    let source = PayloadSource::NullPayloads(3);
    let result = source.generate().unwrap();
    assert_eq!(result, vec!["", "", ""]);
}

#[test]
fn brute_force_generates_combinations() {
    let source = PayloadSource::BruteForce {
        charset: "ab".into(),
        min_length: 1,
        max_length: 2,
    };
    let result = source.generate().unwrap();
    assert_eq!(result.len(), 6);
    assert_eq!(result, vec!["a", "b", "aa", "ab", "ba", "bb"]);
}

#[test]
fn from_file_reads_lines() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmp, "line1").unwrap();
    writeln!(tmp, "line2").unwrap();
    writeln!(tmp, "line3").unwrap();
    tmp.flush().unwrap();
    let source = PayloadSource::FromFile(tmp.path().to_path_buf());
    let result = source.generate().unwrap();
    assert_eq!(result, vec!["line1", "line2", "line3"]);
}

#[test]
fn add_prefix() {
    let proc = PayloadProcessor::AddPrefix("x".into());
    assert_eq!(proc.apply("y").unwrap(), Some("xy".into()));
}

#[test]
fn add_suffix() {
    let proc = PayloadProcessor::AddSuffix("!".into());
    assert_eq!(proc.apply("y").unwrap(), Some("y!".into()));
}

#[test]
fn reverse() {
    let proc = PayloadProcessor::Reverse;
    assert_eq!(proc.apply("abc").unwrap(), Some("cba".into()));
}

#[test]
fn change_case_upper() {
    let proc = PayloadProcessor::ChangeCase(CaseMode::Upper);
    assert_eq!(proc.apply("abc").unwrap(), Some("ABC".into()));
}

#[test]
fn change_case_lower() {
    let proc = PayloadProcessor::ChangeCase(CaseMode::Lower);
    assert_eq!(proc.apply("ABC").unwrap(), Some("abc".into()));
}

#[test]
fn skip_if_filters() {
    let proc = PayloadProcessor::SkipIf("bad".into());
    assert_eq!(proc.apply("bad").unwrap(), None);
    assert_eq!(proc.apply("good").unwrap(), Some("good".into()));
}

#[test]
fn match_only_keeps() {
    let proc = PayloadProcessor::MatchOnly("good".into());
    assert_eq!(proc.apply("good").unwrap(), Some("good".into()));
    assert_eq!(proc.apply("bad").unwrap(), None);
}

#[test]
fn substring() {
    let proc = PayloadProcessor::Substring {
        start: 1,
        length: Some(2),
    };
    assert_eq!(proc.apply("abcde").unwrap(), Some("bc".into()));
}

#[test]
fn regex_replace() {
    let proc = PayloadProcessor::RegexReplace {
        pattern: r"\d+".into(),
        replacement: "N".into(),
    };
    assert_eq!(proc.apply("abc123").unwrap(), Some("abcN".into()));
}

#[test]
fn url_encode() {
    let enc = PayloadEncoding::UrlEncode;
    assert_eq!(enc.encode("a b&c").unwrap(), "a%20b%26c");
}

#[test]
fn double_url_encode() {
    let enc = PayloadEncoding::DoubleUrlEncode;
    assert_eq!(enc.encode("a b").unwrap(), "a%2520b");
}

#[test]
fn base64_encode() {
    let enc = PayloadEncoding::Base64Encode;
    assert_eq!(enc.encode("hello").unwrap(), "aGVsbG8=");
}

#[test]
fn base64_decode() {
    let enc = PayloadEncoding::Base64Decode;
    assert_eq!(enc.encode("aGVsbG8=").unwrap(), "hello");
}

#[test]
fn hex_encode() {
    let enc = PayloadEncoding::Hex;
    assert_eq!(enc.encode("AB").unwrap(), "4142");
}

#[test]
fn sha256_hash() {
    let enc = PayloadEncoding::Sha256;
    let result = enc.encode("test").unwrap();
    assert!(result.starts_with("9f86d081"));
}

#[test]
fn html_encode() {
    let enc = PayloadEncoding::HtmlEncode;
    assert_eq!(enc.encode("<script>").unwrap(), "&lt;script&gt;");
}

#[test]
fn chain_encoding() {
    let enc = PayloadEncoding::Chain(vec![
        PayloadEncoding::UrlEncode,
        PayloadEncoding::Base64Encode,
    ]);
    let url_encoded = PayloadEncoding::UrlEncode.encode("a b").unwrap();
    let expected = PayloadEncoding::Base64Encode.encode(&url_encoded).unwrap();
    assert_eq!(enc.encode("a b").unwrap(), expected);
}

#[test]
fn full_pipeline_integration() {
    let pipeline = PayloadPipeline {
        source: PayloadSource::NumberRange {
            start: 1,
            end: 3,
            step: 1,
        },
        processors: vec![PayloadProcessor::AddPrefix("id=".into())],
        encoding: PayloadEncoding::UrlEncode,
    };
    let result = pipeline.generate().unwrap();
    assert_eq!(result, vec!["id%3D1", "id%3D2", "id%3D3"]);
}

#[test]
fn pipeline_with_filter() {
    let pipeline = PayloadPipeline {
        source: PayloadSource::SimpleList(vec!["good1".into(), "bad_item".into(), "good2".into()]),
        processors: vec![PayloadProcessor::SkipIf("bad".into())],
        encoding: PayloadEncoding::Base64Encode,
    };
    let result = pipeline.generate().unwrap();
    assert_eq!(result.len(), 2);
    let decoded_0 = PayloadEncoding::Base64Decode.encode(&result[0]).unwrap();
    let decoded_1 = PayloadEncoding::Base64Decode.encode(&result[1]).unwrap();
    assert_eq!(decoded_0, "good1");
    assert_eq!(decoded_1, "good2");
}
