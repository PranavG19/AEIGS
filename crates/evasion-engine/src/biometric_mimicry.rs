use rand::Rng;
use serde::{Deserialize, Serialize};

/// Cubic Bezier curve for generating naturalistic mouse movement paths.
/// Four control points define the curve shape: P0 (start), P1, P2, P3 (end).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BezierCurve {
    pub p0: (f64, f64),
    pub p1: (f64, f64),
    pub p2: (f64, f64),
    pub p3: (f64, f64),
}

impl BezierCurve {
    pub fn new(p0: (f64, f64), p1: (f64, f64), p2: (f64, f64), p3: (f64, f64)) -> Self {
        Self { p0, p1, p2, p3 }
    }

    /// Evaluate the cubic Bezier at parameter t in [0, 1].
    pub fn interpolate(&self, t: f64) -> (f64, f64) {
        let t = t.clamp(0.0, 1.0);
        let u = 1.0 - t;
        let uu = u * u;
        let uuu = uu * u;
        let tt = t * t;
        let ttt = tt * t;

        let x =
            uuu * self.p0.0 + 3.0 * uu * t * self.p1.0 + 3.0 * u * tt * self.p2.0 + ttt * self.p3.0;
        let y =
            uuu * self.p0.1 + 3.0 * uu * t * self.p1.1 + 3.0 * u * tt * self.p2.1 + ttt * self.p3.1;

        (x, y)
    }

    /// Generate a path of `num_points` evenly-spaced samples along the curve.
    /// Control points are placed with random jitter to mimic organic hand motion.
    pub fn generate_path(start: (f64, f64), end: (f64, f64), num_points: usize) -> Vec<(f64, f64)> {
        let mut rng = rand::rng();

        let dx = end.0 - start.0;
        let dy = end.1 - start.1;
        let jitter_x = dx.abs().max(50.0) * 0.3;
        let jitter_y = dy.abs().max(50.0) * 0.3;

        let p1 = (
            start.0 + dx * 0.25 + rng.random_range(-jitter_x..jitter_x),
            start.1 + dy * 0.25 + rng.random_range(-jitter_y..jitter_y),
        );
        let p2 = (
            start.0 + dx * 0.75 + rng.random_range(-jitter_x..jitter_x),
            start.1 + dy * 0.75 + rng.random_range(-jitter_y..jitter_y),
        );

        let curve = BezierCurve::new(start, p1, p2, end);
        let count = num_points.max(2);
        (0..count)
            .map(|i| {
                let t = i as f64 / (count - 1) as f64;
                curve.interpolate(t)
            })
            .collect()
    }
}

/// Gaussian-distributed keystroke inter-arrival time generator.
/// Models the cadence of a real typist with configurable mean and variance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystrokeProfile {
    pub mean_ms: f64,
    pub std_dev_ms: f64,
}

impl KeystrokeProfile {
    pub fn new(mean_ms: f64, std_dev_ms: f64) -> Self {
        Self {
            mean_ms,
            std_dev_ms,
        }
    }

    /// Comfortable touch-typist: ~80 WPM.
    pub fn human_typist() -> Self {
        Self::new(120.0, 35.0)
    }

    /// Hunt-and-peck beginner.
    pub fn slow_typist() -> Self {
        Self::new(280.0, 90.0)
    }

    /// Generate `text_len` inter-key delays in milliseconds using Box-Muller.
    pub fn generate_timing(&self, text_len: usize) -> Vec<u64> {
        let mut rng = rand::rng();
        (0..text_len)
            .map(|_| {
                let u1: f64 = rng.random_range(0.0001..1.0);
                let u2: f64 = rng.random_range(0.0..std::f64::consts::TAU);
                let z = (-2.0 * u1.ln()).sqrt() * u2.cos();
                let val = self.mean_ms + z * self.std_dev_ms;
                val.max(10.0) as u64
            })
            .collect()
    }
}

/// A single scroll wheel / touchpad scroll event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrollEvent {
    pub delta_y: i32,
    pub velocity: f64,
    pub timestamp_offset_ms: u64,
}

/// Scroll velocity profile presets modelling different reading styles.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScrollPreset {
    SlowReader,
    FastScanner,
    Casual,
}

/// Generates scroll event sequences that match real-user scroll patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrollBehavior {
    pub preset: ScrollPreset,
}

impl ScrollBehavior {
    pub fn slow_reader() -> Self {
        Self {
            preset: ScrollPreset::SlowReader,
        }
    }

    pub fn fast_scanner() -> Self {
        Self {
            preset: ScrollPreset::FastScanner,
        }
    }

    pub fn casual() -> Self {
        Self {
            preset: ScrollPreset::Casual,
        }
    }

    /// Produce a realistic scroll event stream covering `page_height` pixels.
    pub fn generate_scroll_events(&self, page_height: u32) -> Vec<ScrollEvent> {
        let mut rng = rand::rng();
        let mut events = Vec::new();
        let mut scrolled: i64 = 0;
        let mut time_ms: u64 = 0;

        let (base_delta, base_pause, velocity_range): (i32, u64, (f64, f64)) = match self.preset {
            ScrollPreset::SlowReader => (40, 800, (0.3, 0.8)),
            ScrollPreset::FastScanner => (180, 150, (2.0, 5.0)),
            ScrollPreset::Casual => (90, 400, (0.8, 2.0)),
        };

        while scrolled < page_height as i64 {
            let delta = rng.random_range(base_delta / 2..=base_delta * 2).max(1);
            let velocity = rng.random_range(velocity_range.0..velocity_range.1);
            let pause = rng.random_range(base_pause / 2..=base_pause * 2);

            time_ms += pause;
            scrolled += delta as i64;

            events.push(ScrollEvent {
                delta_y: delta,
                velocity,
                timestamp_offset_ms: time_ms,
            });
        }

        events
    }
}

/// A single mouse click event with realistic press timing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickEvent {
    pub x: f64,
    pub y: f64,
    pub press_duration_ms: u64,
    pub pre_move_ms: u64,
}

/// Models human click behaviour: dwell time, pre-click hesitation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickBehavior {
    pub mean_press_duration_ms: f64,
}

impl ClickBehavior {
    pub fn new(mean_press_duration_ms: f64) -> Self {
        Self {
            mean_press_duration_ms,
        }
    }

    pub fn human() -> Self {
        Self::new(85.0)
    }

    /// Generate a single click at the target coordinates.
    pub fn generate_click(&self, x: f64, y: f64) -> ClickEvent {
        let mut rng = rand::rng();
        let u1: f64 = rng.random_range(0.0001..1.0);
        let u2: f64 = rng.random_range(0.0..std::f64::consts::TAU);
        let z = (-2.0 * u1.ln()).sqrt() * u2.cos();
        let press = (self.mean_press_duration_ms + z * 20.0).max(15.0) as u64;
        let pre_move = rng.random_range(30..250);

        ClickEvent {
            x,
            y,
            press_duration_ms: press,
            pre_move_ms: pre_move,
        }
    }
}

/// All browser-observable events produced by the mimicry engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BrowserEvent {
    Focus,
    Blur,
    MouseMove { x: f64, y: f64 },
    KeyPress { delay_ms: u64 },
    Scroll { delta_y: i32 },
    Click { x: f64, y: f64, duration_ms: u64 },
}

/// Generates window focus / blur event pairs to defeat headless-browser detection
/// that checks for missing visibilitychange / focus / blur events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FocusBlurSimulator {
    /// Mean duration of focused window span in milliseconds.
    pub mean_focus_ms: u64,
    /// Mean duration of blurred (tab-switched) span in milliseconds.
    pub mean_blur_ms: u64,
}

impl FocusBlurSimulator {
    pub fn new(mean_focus_ms: u64, mean_blur_ms: u64) -> Self {
        Self {
            mean_focus_ms,
            mean_blur_ms,
        }
    }

    pub fn default_human() -> Self {
        Self::new(25_000, 8_000)
    }

    /// Generate a focus/blur timeline spanning `duration_secs`.
    /// Always starts with Focus and alternates.
    pub fn generate_session_events(&self, duration_secs: u64) -> Vec<BrowserEvent> {
        let mut rng = rand::rng();
        let mut events = Vec::new();
        let total_ms = duration_secs * 1000;
        let mut elapsed: u64 = 0;
        let mut focused = true;

        events.push(BrowserEvent::Focus);

        while elapsed < total_ms {
            let span = if focused {
                rng.random_range(self.mean_focus_ms / 2..=self.mean_focus_ms * 2)
            } else {
                rng.random_range(self.mean_blur_ms / 2..=self.mean_blur_ms * 2)
            };
            elapsed += span;
            if elapsed >= total_ms {
                break;
            }
            focused = !focused;
            events.push(if focused {
                BrowserEvent::Focus
            } else {
                BrowserEvent::Blur
            });
        }

        events
    }
}

/// Behavioural archetype preset for the combined biometric profile.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProfilePreset {
    Human,
    Bot,
    Custom,
}

/// Aggregates all biometric sub-profiles into a single configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricProfile {
    pub preset: ProfilePreset,
    pub keystroke: KeystrokeProfile,
    pub scroll: ScrollBehavior,
    pub click: ClickBehavior,
    pub focus_blur: FocusBlurSimulator,
}

impl BiometricProfile {
    pub fn human() -> Self {
        Self {
            preset: ProfilePreset::Human,
            keystroke: KeystrokeProfile::human_typist(),
            scroll: ScrollBehavior::casual(),
            click: ClickBehavior::human(),
            focus_blur: FocusBlurSimulator::default_human(),
        }
    }

    pub fn bot() -> Self {
        Self {
            preset: ProfilePreset::Bot,
            keystroke: KeystrokeProfile::new(5.0, 0.5),
            scroll: ScrollBehavior::fast_scanner(),
            click: ClickBehavior::new(10.0),
            focus_blur: FocusBlurSimulator::new(600_000, 0),
        }
    }

    pub fn custom(
        keystroke: KeystrokeProfile,
        scroll: ScrollBehavior,
        click: ClickBehavior,
        focus_blur: FocusBlurSimulator,
    ) -> Self {
        Self {
            preset: ProfilePreset::Custom,
            keystroke,
            scroll,
            click,
            focus_blur,
        }
    }
}

/// Top-level engine that weaves sub-profiles into coherent browsing sessions.
#[derive(Debug, Clone)]
pub struct BiometricMimicry {
    profile: BiometricProfile,
}

impl BiometricMimicry {
    pub fn new(profile: BiometricProfile) -> Self {
        Self { profile }
    }

    /// Synthesise a plausible browser event stream lasting `duration_secs`.
    ///
    /// Interleaves mouse movements, keystrokes, scrolls, clicks, and focus/blur
    /// events so anti-bot heuristics see a realistic activity fingerprint.
    pub fn generate_browsing_session(&self, duration_secs: u64) -> Vec<BrowserEvent> {
        let mut rng = rand::rng();
        let mut events: Vec<BrowserEvent> = Vec::new();
        let total_ms = duration_secs * 1000;
        let mut elapsed: u64 = 0;

        let focus_events = self
            .profile
            .focus_blur
            .generate_session_events(duration_secs);
        for ev in &focus_events {
            events.push(ev.clone());
        }

        while elapsed < total_ms {
            let action: u8 = rng.random_range(0..4);
            match action {
                0 => {
                    let start = (rng.random_range(0.0..1920.0), rng.random_range(0.0..1080.0));
                    let end = (rng.random_range(0.0..1920.0), rng.random_range(0.0..1080.0));
                    let path = BezierCurve::generate_path(start, end, rng.random_range(5..15));
                    for (x, y) in path {
                        events.push(BrowserEvent::MouseMove { x, y });
                    }
                    elapsed += rng.random_range(200..800);
                }
                1 => {
                    let timings = self
                        .profile
                        .keystroke
                        .generate_timing(rng.random_range(1..8));
                    for delay in timings {
                        events.push(BrowserEvent::KeyPress { delay_ms: delay });
                        elapsed += delay;
                    }
                }
                2 => {
                    let scroll_evts = self
                        .profile
                        .scroll
                        .generate_scroll_events(rng.random_range(100..600));
                    for se in &scroll_evts {
                        events.push(BrowserEvent::Scroll {
                            delta_y: se.delta_y,
                        });
                        elapsed += se.timestamp_offset_ms.min(500);
                    }
                }
                3 => {
                    let click = self.profile.click.generate_click(
                        rng.random_range(0.0..1920.0),
                        rng.random_range(0.0..1080.0),
                    );
                    events.push(BrowserEvent::Click {
                        x: click.x,
                        y: click.y,
                        duration_ms: click.press_duration_ms,
                    });
                    elapsed += click.press_duration_ms + click.pre_move_ms;
                }
                _ => unreachable!(),
            }
        }

        events
    }
}
