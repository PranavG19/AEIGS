use crate::media_capabilities_audit::*;

#[test]
fn test_empty_body() {
    let issues = analyze_media_capabilities("");
    assert_eq!(issues, vec![]);
}

#[test]
fn test_no_api() {
    let body = r#"
        <script>
            const video = document.querySelector('video');
            video.play();
        </script>
    "#;
    let issues = analyze_media_capabilities(body);
    assert_eq!(issues, vec![]);
}

#[test]
fn test_api_detected_only() {
    let body = r#"
        <script>
            if (navigator.mediaCapabilities) {
                console.log('Media Capabilities API supported');
            }
        </script>
    "#;
    let issues = analyze_media_capabilities(body);
    assert_eq!(issues, vec![MediaCapabilitiesIssue::ApiDetected]);
}

#[test]
fn test_codec_fingerprinting_with_navigator() {
    let body = r#"
        <script>
            navigator.mediaCapabilities.decodingInfo({
                type: 'file',
                video: {
                    contentType: 'video/mp4; codecs="avc1.42E01E"',
                }
            });
        </script>
    "#;
    let issues = analyze_media_capabilities(body);
    assert!(issues.contains(&MediaCapabilitiesIssue::ApiDetected));
    assert!(issues.contains(&MediaCapabilitiesIssue::CodecFingerprinting));
}

#[test]
fn test_codec_fingerprinting_multiple_codecs() {
    let body = r#"
        <script>
            mediaCapabilities.decodingInfo({
                video: { codec: 'vp8' }
            }).then(() => {
                return mediaCapabilities.decodingInfo({
                    video: { codec: 'h264' }
                });
            });
        </script>
    "#;
    let issues = analyze_media_capabilities(body);
    assert!(issues.contains(&MediaCapabilitiesIssue::CodecFingerprinting));
}

#[test]
fn test_codec_without_fingerprinting_context() {
    let body = r#"
        <script>
            mediaCapabilities.decodingInfo({
                video: { contentType: 'video/mp4' }
            });
        </script>
    "#;
    let issues = analyze_media_capabilities(body);
    assert!(!issues.contains(&MediaCapabilitiesIssue::CodecFingerprinting));
}

#[test]
fn test_hardware_fingerprinting() {
    let body = r#"
        <script>
            navigator.mediaCapabilities.decodingInfo(config).then(result => {
                if (result.powerEfficient) {
                    console.log('Hardware acceleration available');
                }
            });
        </script>
    "#;
    let issues = analyze_media_capabilities(body);
    assert!(issues.contains(&MediaCapabilitiesIssue::ApiDetected));
    assert!(issues.contains(&MediaCapabilitiesIssue::HardwareFingerprinting));
}

#[test]
fn test_hardware_fingerprinting_gpu() {
    let body = r#"
        <script>
            encodingInfo(config).then(info => {
                const gpuAccelerated = info.hardwareAcceleration;
            });
        </script>
    "#;
    let issues = analyze_media_capabilities(body);
    assert!(issues.contains(&MediaCapabilitiesIssue::HardwareFingerprinting));
}

#[test]
fn test_performance_probing() {
    let body = r#"
        <script>
            navigator.mediaCapabilities.decodingInfo(config).then(result => {
                if (result.smooth && result.supported) {
                    performance.measure('decode-test');
                }
            });
        </script>
    "#;
    let issues = analyze_media_capabilities(body);
    assert!(issues.contains(&MediaCapabilitiesIssue::ApiDetected));
    assert!(issues.contains(&MediaCapabilitiesIssue::PerformanceProbing));
}

#[test]
fn test_performance_without_measure() {
    let body = r#"
        <script>
            mediaCapabilities.decodingInfo(config).then(result => {
                if (result.smooth) {
                    console.log('Smooth playback');
                }
            });
        </script>
    "#;
    let issues = analyze_media_capabilities(body);
    assert!(!issues.contains(&MediaCapabilitiesIssue::PerformanceProbing));
}

#[test]
fn test_data_exfiltration_fetch() {
    let body = r#"
        <script>
            navigator.mediaCapabilities.decodingInfo(config).then(result => {
                fetch('/api/capabilities', {
                    method: 'POST',
                    body: JSON.stringify(result)
                });
            });
        </script>
    "#;
    let issues = analyze_media_capabilities(body);
    assert!(issues.contains(&MediaCapabilitiesIssue::ApiDetected));
    assert!(issues.contains(&MediaCapabilitiesIssue::DataExfiltration));
}

#[test]
fn test_data_exfiltration_beacon() {
    let body = r#"
        <script>
            decodingInfo(config).then(info => {
                navigator.sendBeacon('/track', JSON.stringify(info));
            });
        </script>
    "#;
    let issues = analyze_media_capabilities(body);
    assert!(issues.contains(&MediaCapabilitiesIssue::DataExfiltration));
}

#[test]
fn test_data_exfiltration_xhr() {
    let body = r#"
        <script>
            encodingInfo(config).then(info => {
                const xhr = new XMLHttpRequest();
                xhr.open('POST', '/api/track');
                xhr.send(JSON.stringify(info));
            });
        </script>
    "#;
    let issues = analyze_media_capabilities(body);
    assert!(issues.contains(&MediaCapabilitiesIssue::DataExfiltration));
}

#[test]
fn test_all_issues_detected() {
    let body = r#"
        <script>
            navigator.mediaCapabilities.decodingInfo({
                type: 'file',
                video: {
                    contentType: 'video/mp4; codecs="avc1.42E01E"',
                }
            }).then(result => {
                if (result.supported && result.smooth && result.powerEfficient) {
                    performance.measure('capability-test');
                    fetch('/api/track', {
                        method: 'POST',
                        body: JSON.stringify(result)
                    });
                }
            });
        </script>
    "#;
    let issues = analyze_media_capabilities(body);
    assert_eq!(issues.len(), 5);
    assert!(issues.contains(&MediaCapabilitiesIssue::ApiDetected));
    assert!(issues.contains(&MediaCapabilitiesIssue::CodecFingerprinting));
    assert!(issues.contains(&MediaCapabilitiesIssue::HardwareFingerprinting));
    assert!(issues.contains(&MediaCapabilitiesIssue::PerformanceProbing));
    assert!(issues.contains(&MediaCapabilitiesIssue::DataExfiltration));
}

#[test]
fn test_severity_values() {
    assert_eq!(media_capabilities_severity(&MediaCapabilitiesIssue::ApiDetected), 2.0);
    assert_eq!(media_capabilities_severity(&MediaCapabilitiesIssue::CodecFingerprinting), 7.0);
    assert_eq!(media_capabilities_severity(&MediaCapabilitiesIssue::HardwareFingerprinting), 7.5);
    assert_eq!(media_capabilities_severity(&MediaCapabilitiesIssue::PerformanceProbing), 6.0);
    assert_eq!(media_capabilities_severity(&MediaCapabilitiesIssue::DataExfiltration), 6.5);
}

#[test]
fn test_to_operations_count() {
    let issues = vec![
        MediaCapabilitiesIssue::ApiDetected,
        MediaCapabilitiesIssue::CodecFingerprinting,
        MediaCapabilitiesIssue::HardwareFingerprinting,
    ];
    let mut seq = 100;
    let ops = media_capabilities_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 103);
}

#[test]
fn test_to_operations_empty() {
    let issues = vec![];
    let mut seq = 50;
    let ops = media_capabilities_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 50);
}

#[test]
fn test_display_strings() {
    assert_eq!(MediaCapabilitiesIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(MediaCapabilitiesIssue::CodecFingerprinting.to_string(), "codec_fingerprinting");
    assert_eq!(MediaCapabilitiesIssue::HardwareFingerprinting.to_string(), "hardware_fingerprinting");
    assert_eq!(MediaCapabilitiesIssue::PerformanceProbing.to_string(), "performance_probing");
    assert_eq!(MediaCapabilitiesIssue::DataExfiltration.to_string(), "data_exfiltration");
}

#[test]
fn test_case_sensitivity() {
    let body_lower = r#"
        <script>
            mediacapabilities.decodinginfo();
        </script>
    "#;
    let issues = analyze_media_capabilities(body_lower);
    assert_eq!(issues, vec![]);
}

#[test]
fn test_media_decoding_configuration() {
    let body = r#"
        <script>
            const config = {
                type: 'file',
                video: new MediaDecodingConfiguration()
            };
            navigator.mediaCapabilities.decodingInfo(config);
        </script>
    "#;
    let issues = analyze_media_capabilities(body);
    assert!(issues.contains(&MediaCapabilitiesIssue::CodecFingerprinting));
}
