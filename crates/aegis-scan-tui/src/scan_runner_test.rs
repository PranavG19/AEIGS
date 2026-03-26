use std::sync::mpsc;
use std::time::Duration;

use crate::app::ScanProfile;
use crate::event::TuiEvent;

#[test]
fn demo_scan_emits_events() {
    let (tx, rx) = mpsc::channel();
    let handle = super::spawn_scan(
        "http://demo-target.local".to_string(),
        ScanProfile::Quick,
        true,
        tx,
    );

    let mut event_count = 0;
    let mut got_phase_changed = false;
    let mut got_finding = false;
    let mut got_complete = false;

    let timeout = Duration::from_secs(120);
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            break;
        }
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(evt) => {
                event_count += 1;
                match &evt {
                    TuiEvent::PhaseChanged { .. } => got_phase_changed = true,
                    TuiEvent::FindingConfirmed(_) => got_finding = true,
                    TuiEvent::ScanComplete => {
                        got_complete = true;
                        break;
                    }
                    _ => {}
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    handle.join().unwrap();

    assert!(event_count > 10, "expected many events, got {event_count}");
    assert!(got_phase_changed, "expected PhaseChanged events");
    assert!(got_finding, "expected FindingConfirmed events");
    assert!(got_complete, "expected ScanComplete event");
}
