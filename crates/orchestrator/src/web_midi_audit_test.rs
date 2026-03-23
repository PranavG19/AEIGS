use crate::web_midi_audit::*;

#[test]
fn test_no_api_detected() {
    let body = r#"
        <html>
        <body>
            <script>
                console.log("Regular web app");
            </script>
        </body>
        </html>
    "#;
    let issues = analyze_web_midi(body);
    assert!(issues.is_empty());
}

#[test]
fn test_api_detected_basic() {
    let body = r#"
        <script>
            navigator.requestMIDIAccess().then(access => {
                console.log("MIDI ready");
            });
        </script>
    "#;
    let issues = analyze_web_midi(body);
    assert_eq!(issues.len(), 2);
    assert!(issues.contains(&WebMidiIssue::ApiDetected));
    assert!(issues.contains(&WebMidiIssue::NoUserActivation));
}

#[test]
fn test_api_detected_midi_access_class() {
    let body = r#"
        <script>
            const access = new MIDIAccess();
        </script>
    "#;
    let issues = analyze_web_midi(body);
    assert!(!issues.is_empty());
    assert!(issues.contains(&WebMidiIssue::ApiDetected));
}

#[test]
fn test_api_detected_midi_input() {
    let body = r#"
        <script>
            const input = new MIDIInput();
        </script>
    "#;
    let issues = analyze_web_midi(body);
    assert!(issues.contains(&WebMidiIssue::ApiDetected));
}

#[test]
fn test_api_detected_midi_output() {
    let body = r#"
        <script>
            const output = new MIDIOutput();
        </script>
    "#;
    let issues = analyze_web_midi(body);
    assert!(issues.contains(&WebMidiIssue::ApiDetected));
}

#[test]
fn test_sysex_access() {
    let body = r#"
        <script>
            navigator.requestMIDIAccess({ sysex: true }).then(access => {
                console.log("SysEx enabled");
            });
        </script>
    "#;
    let issues = analyze_web_midi(body);
    assert!(issues.contains(&WebMidiIssue::ApiDetected));
    assert!(issues.contains(&WebMidiIssue::SysexAccess));
}

#[test]
fn test_sysex_false_not_flagged() {
    let body = r#"
        <script>
            navigator.requestMIDIAccess({ sysex: false }).then(access => {
                console.log("No SysEx");
            });
        </script>
    "#;
    let issues = analyze_web_midi(body);
    assert!(issues.contains(&WebMidiIssue::ApiDetected));
    assert!(!issues.contains(&WebMidiIssue::SysexAccess));
}

#[test]
fn test_device_fingerprinting_inputs_foreach() {
    let body = r#"
        <script>
            navigator.requestMIDIAccess().then(access => {
                access.inputs.forEach(input => {
                    console.log(input.name, input.manufacturer);
                });
            });
        </script>
    "#;
    let issues = analyze_web_midi(body);
    assert!(issues.contains(&WebMidiIssue::ApiDetected));
    assert!(issues.contains(&WebMidiIssue::DeviceFingerprinting));
}

#[test]
fn test_device_fingerprinting_outputs_entries() {
    let body = r#"
        <script>
            navigator.requestMIDIAccess().then(access => {
                for (const [id, output] of access.outputs.entries()) {
                    console.log(id, output);
                }
            });
        </script>
    "#;
    let issues = analyze_web_midi(body);
    assert!(issues.contains(&WebMidiIssue::DeviceFingerprinting));
}

#[test]
fn test_device_fingerprinting_values() {
    let body = r#"
        <script>
            const access = await navigator.requestMIDIAccess();
            const devices = access.inputs.values();
        </script>
    "#;
    let issues = analyze_web_midi(body);
    assert!(issues.contains(&WebMidiIssue::DeviceFingerprinting));
}

#[test]
fn test_device_fingerprinting_size() {
    let body = r#"
        <script>
            navigator.requestMIDIAccess().then(access => {
                const count = access.outputs.size;
            });
        </script>
    "#;
    let issues = analyze_web_midi(body);
    assert!(issues.contains(&WebMidiIssue::DeviceFingerprinting));
}

#[test]
fn test_data_exfiltration_fetch() {
    let body = r#"
        <script>
            navigator.requestMIDIAccess().then(access => {
                access.inputs.forEach(input => {
                    input.onmidimessage = (msg) => {
                        fetch('/log', {
                            method: 'POST',
                            body: JSON.stringify(msg.data)
                        });
                    };
                });
            });
        </script>
    "#;
    let issues = analyze_web_midi(body);
    assert!(issues.contains(&WebMidiIssue::DataExfiltration));
}

#[test]
fn test_data_exfiltration_sendbeacon() {
    let body = r#"
        <script>
            const access = await navigator.requestMIDIAccess();
            access.inputs.forEach(input => {
                input.addEventListener('midimessage', (event) => {
                    navigator.sendBeacon('/track', JSON.stringify(event.data));
                });
            });
        </script>
    "#;
    let issues = analyze_web_midi(body);
    assert!(issues.contains(&WebMidiIssue::DataExfiltration));
}

#[test]
fn test_data_exfiltration_xhr() {
    let body = r#"
        <script>
            navigator.requestMIDIAccess().then(access => {
                access.inputs.forEach(input => {
                    input.onmidimessage = (msg) => {
                        const xhr = new XMLHttpRequest();
                        xhr.open('POST', '/collect');
                        xhr.send(JSON.stringify(msg.data));
                    };
                });
            });
        </script>
    "#;
    let issues = analyze_web_midi(body);
    assert!(issues.contains(&WebMidiIssue::DataExfiltration));
}

#[test]
fn test_user_activation_click() {
    let body = r#"
        <script>
            document.getElementById('midiBtn').addEventListener('click', () => {
                navigator.requestMIDIAccess().then(access => {
                    console.log("MIDI ready");
                });
            });
        </script>
    "#;
    let issues = analyze_web_midi(body);
    assert!(issues.contains(&WebMidiIssue::ApiDetected));
    assert!(!issues.contains(&WebMidiIssue::NoUserActivation));
}

#[test]
fn test_user_activation_keydown() {
    let body = r#"
        <script>
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    navigator.requestMIDIAccess();
                }
            });
        </script>
    "#;
    let issues = analyze_web_midi(body);
    assert!(!issues.contains(&WebMidiIssue::NoUserActivation));
}

#[test]
fn test_user_activation_pointerdown() {
    let body = r#"
        <script>
            element.addEventListener('pointerdown', () => {
                navigator.requestMIDIAccess();
            });
        </script>
    "#;
    let issues = analyze_web_midi(body);
    assert!(!issues.contains(&WebMidiIssue::NoUserActivation));
}

#[test]
fn test_user_activation_touchstart() {
    let body = r#"
        <script>
            element.addEventListener('touchstart', () => {
                navigator.requestMIDIAccess();
            });
        </script>
    "#;
    let issues = analyze_web_midi(body);
    assert!(!issues.contains(&WebMidiIssue::NoUserActivation));
}

#[test]
fn test_no_user_activation() {
    let body = r#"
        <script>
            window.onload = () => {
                navigator.requestMIDIAccess();
            };
        </script>
    "#;
    let issues = analyze_web_midi(body);
    assert!(issues.contains(&WebMidiIssue::NoUserActivation));
}

#[test]
fn test_display_impl() {
    assert_eq!(WebMidiIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(WebMidiIssue::SysexAccess.to_string(), "sysex_access");
    assert_eq!(
        WebMidiIssue::DeviceFingerprinting.to_string(),
        "device_fingerprinting"
    );
    assert_eq!(
        WebMidiIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
    assert_eq!(
        WebMidiIssue::NoUserActivation.to_string(),
        "no_user_activation"
    );
}

#[test]
fn test_severity_values() {
    assert_eq!(web_midi_severity(&WebMidiIssue::ApiDetected), 2.0);
    assert_eq!(web_midi_severity(&WebMidiIssue::SysexAccess), 8.0);
    assert_eq!(web_midi_severity(&WebMidiIssue::DeviceFingerprinting), 7.0);
    assert_eq!(web_midi_severity(&WebMidiIssue::DataExfiltration), 7.5);
    assert_eq!(web_midi_severity(&WebMidiIssue::NoUserActivation), 5.5);
}

#[test]
fn test_to_operations() {
    let issues = vec![
        WebMidiIssue::ApiDetected,
        WebMidiIssue::SysexAccess,
        WebMidiIssue::DeviceFingerprinting,
    ];
    let mut seq = 100;
    let ops = web_midi_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 103);
}

#[test]
fn test_complex_scenario_all_issues() {
    let body = r#"
        <script>
            window.onload = () => {
                navigator.requestMIDIAccess({ sysex: true }).then(access => {
                    access.inputs.forEach(input => {
                        input.onmidimessage = (msg) => {
                            fetch('/collect', {
                                method: 'POST',
                                body: JSON.stringify({
                                    data: msg.data,
                                    timestamp: msg.timeStamp,
                                    deviceId: input.id,
                                    deviceName: input.name
                                })
                            });
                        };
                    });
                });
            };
        </script>
    "#;
    let issues = analyze_web_midi(body);
    assert_eq!(issues.len(), 5);
    assert!(issues.contains(&WebMidiIssue::ApiDetected));
    assert!(issues.contains(&WebMidiIssue::SysexAccess));
    assert!(issues.contains(&WebMidiIssue::DeviceFingerprinting));
    assert!(issues.contains(&WebMidiIssue::DataExfiltration));
    assert!(issues.contains(&WebMidiIssue::NoUserActivation));
}

#[test]
fn test_case_sensitivity() {
    let body_wrong_case = r#"
        <script>
            navigator.requestmidiaccess();
            MIDIACCESS();
        </script>
    "#;
    let issues = analyze_web_midi(body_wrong_case);
    assert!(issues.is_empty());
}
