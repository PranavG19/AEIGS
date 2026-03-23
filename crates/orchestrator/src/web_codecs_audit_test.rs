use crate::web_codecs_audit::*;

#[test]
fn no_codecs_no_issues() {
    assert!(analyze_web_codecs("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_video_encoder() {
    let body = r#"<script>const enc = new VideoEncoder({output: cb, error: err});</script>"#;
    let issues = analyze_web_codecs(body);
    assert!(issues.contains(&WebCodecsIssue::ApiDetected));
}

#[test]
fn detects_api_audio_decoder() {
    let body = r#"<script>const dec = new AudioDecoder({output: cb, error: err});</script>"#;
    let issues = analyze_web_codecs(body);
    assert!(issues.contains(&WebCodecsIssue::ApiDetected));
}

#[test]
fn detects_api_video_frame() {
    let body = r#"<script>const frame = new VideoFrame(canvas);</script>"#;
    let issues = analyze_web_codecs(body);
    assert!(issues.contains(&WebCodecsIssue::ApiDetected));
}

#[test]
fn detects_video_capture() {
    let body = r#"<script>
        const stream = await navigator.mediaDevices.getUserMedia({video: true});
        const enc = new VideoEncoder({output: cb, error: err});
    </script>"#;
    let issues = analyze_web_codecs(body);
    assert!(issues.contains(&WebCodecsIssue::VideoCapture));
}

#[test]
fn no_video_capture_without_media() {
    let body = r#"<script>const enc = new VideoEncoder({output: cb, error: err});</script>"#;
    let issues = analyze_web_codecs(body);
    assert!(!issues.contains(&WebCodecsIssue::VideoCapture));
}

#[test]
fn detects_audio_capture() {
    let body = r#"<script>
        const stream = await navigator.mediaDevices.getUserMedia({audio: true});
        const enc = new AudioEncoder({output: cb, error: err});
    </script>"#;
    let issues = analyze_web_codecs(body);
    assert!(issues.contains(&WebCodecsIssue::AudioCapture));
}

#[test]
fn detects_raw_frame_access() {
    let body = r#"<script>
        const frame = new VideoFrame(canvas);
        const buf = new ArrayBuffer(frame.allocationSize());
        await frame.copyTo(buf);
    </script>"#;
    let issues = analyze_web_codecs(body);
    assert!(issues.contains(&WebCodecsIssue::RawFrameAccess));
}

#[test]
fn no_raw_without_copy() {
    let body = r#"<script>const frame = new VideoFrame(canvas);</script>"#;
    let issues = analyze_web_codecs(body);
    assert!(!issues.contains(&WebCodecsIssue::RawFrameAccess));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        const enc = new VideoEncoder({output: chunk => {
            fetch("/upload", {body: chunk.data});
        }, error: err});
    </script>"#;
    let issues = analyze_web_codecs(body);
    assert!(issues.contains(&WebCodecsIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_send() {
    let body = r#"<script>
        const enc = new VideoEncoder({output: chunk => {
            console.log(chunk);
        }, error: err});
    </script>"#;
    let issues = analyze_web_codecs(body);
    assert!(!issues.contains(&WebCodecsIssue::DataExfiltration));
}

#[test]
fn detects_continuous_encoding() {
    let body = r#"<script>
        const enc = new VideoEncoder({output: cb, error: err});
        requestAnimationFrame(function encode() {
            enc.encode(frame);
            requestAnimationFrame(encode);
        });
    </script>"#;
    let issues = analyze_web_codecs(body);
    assert!(issues.contains(&WebCodecsIssue::ContinuousEncoding));
}

#[test]
fn severity_exfil_highest() {
    assert_eq!(web_codecs_severity(&WebCodecsIssue::DataExfiltration), 7.5);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(web_codecs_severity(&WebCodecsIssue::ApiDetected), 2.5);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![WebCodecsIssue::ApiDetected, WebCodecsIssue::VideoCapture];
    let mut seq = 0;
    let ops = web_codecs_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(WebCodecsIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(WebCodecsIssue::VideoCapture.to_string(), "video_capture");
    assert_eq!(WebCodecsIssue::AudioCapture.to_string(), "audio_capture");
    assert_eq!(
        WebCodecsIssue::RawFrameAccess.to_string(),
        "raw_frame_access"
    );
    assert_eq!(
        WebCodecsIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
    assert_eq!(
        WebCodecsIssue::ContinuousEncoding.to_string(),
        "continuous_encoding"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_web_codecs("").is_empty());
}
