use crate::speech_api_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_speech_api("");
    assert!(issues.is_empty());
}

#[test]
fn no_speech_api_no_issues() {
    let body = "<html><body>Hello</body></html>";
    let issues = analyze_speech_api(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_speech_recognition() {
    let body = "var rec = new SpeechRecognition();";
    let issues = analyze_speech_api(body);
    assert!(issues.contains(&SpeechApiIssue::SpeechRecognitionUsage));
}

#[test]
fn detects_webkit_speech_recognition() {
    let body = "var rec = new webkitSpeechRecognition();";
    let issues = analyze_speech_api(body);
    assert!(issues.contains(&SpeechApiIssue::SpeechRecognitionUsage));
}

#[test]
fn detects_continuous_listening() {
    let body = r#"
        var rec = new SpeechRecognition();
        rec.continuous = true;
        rec.start();
    "#;
    let issues = analyze_speech_api(body);
    assert!(issues.contains(&SpeechApiIssue::ContinuousListening));
}

#[test]
fn detects_speech_exfiltration() {
    let body = r#"
        var rec = new SpeechRecognition();
        rec.onresult = function(e) {
            fetch('/collect', {method:'POST', body: e.results[0][0].transcript});
        };
    "#;
    let issues = analyze_speech_api(body);
    assert!(issues.contains(&SpeechApiIssue::SpeechDataExfiltration));
}

#[test]
fn detects_speech_synthesis_fingerprint() {
    let body = "var voices = speechSynthesis.getVoices();";
    let issues = analyze_speech_api(body);
    assert!(issues.contains(&SpeechApiIssue::SpeechSynthesisFingerprint));
}

#[test]
fn detects_voices_changed_event() {
    let body = "speechSynthesis.onvoiceschanged = function() { track(); };";
    let issues = analyze_speech_api(body);
    assert!(issues.contains(&SpeechApiIssue::SpeechSynthesisFingerprint));
}

#[test]
fn detects_speech_grammar_list() {
    let body = "var grammar = new SpeechGrammarList();";
    let issues = analyze_speech_api(body);
    assert!(issues.contains(&SpeechApiIssue::SpeechGrammarList));
}

#[test]
fn detects_webkit_grammar_list() {
    let body = "var grammar = new webkitSpeechGrammarList();";
    let issues = analyze_speech_api(body);
    assert!(issues.contains(&SpeechApiIssue::SpeechGrammarList));
}

#[test]
fn detects_interim_results() {
    let body = r#"
        var rec = new SpeechRecognition();
        rec.interimResults = true;
    "#;
    let issues = analyze_speech_api(body);
    assert!(issues.contains(&SpeechApiIssue::InterimResultsCapture));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        speech_api_severity(&SpeechApiIssue::SpeechDataExfiltration),
        8.0
    );
}

#[test]
fn severity_synthesis_fingerprint_lowest() {
    assert_eq!(
        speech_api_severity(&SpeechApiIssue::SpeechSynthesisFingerprint),
        5.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        SpeechApiIssue::SpeechRecognitionUsage,
        SpeechApiIssue::ContinuousListening,
    ];
    let mut seq = 0;
    let ops = speech_api_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        SpeechApiIssue::SpeechRecognitionUsage.to_string(),
        "speech_recognition_usage"
    );
    assert_eq!(
        SpeechApiIssue::ContinuousListening.to_string(),
        "continuous_listening"
    );
    assert_eq!(
        SpeechApiIssue::SpeechSynthesisFingerprint.to_string(),
        "speech_synthesis_fingerprint"
    );
    assert_eq!(
        SpeechApiIssue::InterimResultsCapture.to_string(),
        "interim_results_capture"
    );
}
