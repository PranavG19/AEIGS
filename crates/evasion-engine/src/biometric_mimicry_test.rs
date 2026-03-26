use super::biometric_mimicry::*;

#[test]
fn bezier_interpolate_at_zero_returns_start() {
    let curve = BezierCurve::new((0.0, 0.0), (25.0, 50.0), (75.0, 50.0), (100.0, 100.0));
    let (x, y) = curve.interpolate(0.0);
    assert!((x - 0.0).abs() < 1e-9);
    assert!((y - 0.0).abs() < 1e-9);
}

#[test]
fn bezier_interpolate_at_one_returns_end() {
    let curve = BezierCurve::new((10.0, 20.0), (30.0, 80.0), (70.0, 80.0), (200.0, 300.0));
    let (x, y) = curve.interpolate(1.0);
    assert!((x - 200.0).abs() < 1e-9);
    assert!((y - 300.0).abs() < 1e-9);
}

#[test]
fn generated_path_has_correct_point_count() {
    let path = BezierCurve::generate_path((0.0, 0.0), (500.0, 500.0), 20);
    assert_eq!(path.len(), 20);

    let path_small = BezierCurve::generate_path((0.0, 0.0), (100.0, 100.0), 2);
    assert_eq!(path_small.len(), 2);
}

#[test]
fn keystroke_timing_correct_length_and_reasonable_values() {
    let profile = KeystrokeProfile::human_typist();
    let timings = profile.generate_timing(50);
    assert_eq!(timings.len(), 50);
    for &t in &timings {
        assert!(t >= 10, "keystroke delay too low: {t}");
        assert!(t < 2000, "keystroke delay unreasonably high: {t}");
    }
}

#[test]
fn scroll_events_have_nonzero_deltas() {
    let scroll = ScrollBehavior::casual();
    let events = scroll.generate_scroll_events(2000);
    assert!(!events.is_empty());
    for ev in &events {
        assert!(ev.delta_y > 0, "scroll delta_y must be positive");
        assert!(ev.velocity > 0.0, "scroll velocity must be positive");
    }
}

#[test]
fn click_dwell_times_are_positive() {
    let click_beh = ClickBehavior::human();
    for _ in 0..100 {
        let ev = click_beh.generate_click(512.0, 384.0);
        assert!(
            ev.press_duration_ms >= 15,
            "press too short: {}",
            ev.press_duration_ms
        );
        assert!(ev.pre_move_ms >= 30);
    }
}

#[test]
fn focus_blur_events_alternate_correctly() {
    let sim = FocusBlurSimulator::default_human();
    let events = sim.generate_session_events(60);
    assert!(!events.is_empty());

    let mut expect_focus = true;
    for ev in &events {
        match ev {
            BrowserEvent::Focus => {
                assert!(expect_focus, "expected Blur but got Focus");
                expect_focus = false;
            }
            BrowserEvent::Blur => {
                assert!(!expect_focus, "expected Focus but got Blur");
                expect_focus = true;
            }
            _ => panic!("focus/blur simulator emitted unexpected event type"),
        }
    }
}

#[test]
fn human_profile_generates_varied_timing() {
    let profile = KeystrokeProfile::human_typist();
    let timings = profile.generate_timing(30);
    let all_same = timings.windows(2).all(|w| w[0] == w[1]);
    assert!(
        !all_same,
        "human keystroke timings should not all be identical"
    );
}

#[test]
fn bot_profile_differs_from_human() {
    let human = BiometricProfile::human();
    let bot = BiometricProfile::bot();
    assert_ne!(human.preset, bot.preset);
    assert!(
        bot.keystroke.mean_ms < human.keystroke.mean_ms,
        "bot should type faster than human"
    );
    assert!(
        bot.click.mean_press_duration_ms < human.click.mean_press_duration_ms,
        "bot clicks should be shorter than human clicks"
    );
}

#[test]
fn full_browsing_session_generates_events() {
    let mimicry = BiometricMimicry::new(BiometricProfile::human());
    let session = mimicry.generate_browsing_session(10);
    assert!(
        session.len() > 5,
        "10-second session must produce a nontrivial event stream"
    );

    let has_mouse = session
        .iter()
        .any(|e| matches!(e, BrowserEvent::MouseMove { .. }));
    let has_key = session
        .iter()
        .any(|e| matches!(e, BrowserEvent::KeyPress { .. }));
    let has_focus = session.iter().any(|e| matches!(e, BrowserEvent::Focus));
    assert!(has_mouse, "session should contain mouse moves");
    assert!(has_key, "session should contain key presses");
    assert!(has_focus, "session should contain at least one focus event");
}

#[test]
fn bezier_path_produces_smooth_trajectory() {
    let path = BezierCurve::generate_path((0.0, 0.0), (1000.0, 500.0), 50);
    assert_eq!(path.len(), 50);

    let first = path.first().unwrap();
    let last = path.last().unwrap();
    assert!(
        (first.0 - 0.0).abs() < 1e-9,
        "path must start at start point"
    );
    assert!((last.0 - 1000.0).abs() < 1e-9, "path must end at end point");

    let mut increasing_count = 0;
    for w in path.windows(2) {
        if w[1].0 >= w[0].0 {
            increasing_count += 1;
        }
    }
    let ratio = increasing_count as f64 / (path.len() - 1) as f64;
    assert!(
        ratio > 0.7,
        "x values should be mostly non-decreasing for left-to-right paths, ratio={ratio}"
    );
}

#[test]
fn scroll_slow_reader_is_slower_than_fast_scanner() {
    let slow = ScrollBehavior::slow_reader().generate_scroll_events(3000);
    let fast = ScrollBehavior::fast_scanner().generate_scroll_events(3000);

    let slow_total: u64 = slow
        .iter()
        .map(|e| e.timestamp_offset_ms)
        .max()
        .unwrap_or(0);
    let fast_total: u64 = fast
        .iter()
        .map(|e| e.timestamp_offset_ms)
        .max()
        .unwrap_or(0);
    assert!(
        slow_total > fast_total,
        "slow reader should take longer: slow={slow_total}, fast={fast_total}"
    );
}

#[test]
fn custom_profile_preserves_preset_tag() {
    let profile = BiometricProfile::custom(
        KeystrokeProfile::new(200.0, 50.0),
        ScrollBehavior::casual(),
        ClickBehavior::new(100.0),
        FocusBlurSimulator::new(30_000, 10_000),
    );
    assert_eq!(profile.preset, ProfilePreset::Custom);
}
