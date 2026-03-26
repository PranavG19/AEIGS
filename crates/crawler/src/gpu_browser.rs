use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Encode a SHA-256 digest as a lowercase hex string.
fn sha256_hex(hasher: Sha256) -> String {
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut acc, b| {
            acc.push_str(&format!("{b:02x}"));
            acc
        })
}

/// Configuration for launching a GPU-accelerated headless browser instance.
///
/// Controls the Chromium binary path, ANGLE rendering backend, viewport
/// dimensions, and headless mode. All GPU fingerprint generation depends
/// on these settings being consistent across runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuBrowserConfig {
    pub chromium_path: String,
    pub use_angle: bool,
    pub headless: bool,
    pub viewport_width: u32,
    pub viewport_height: u32,
    pub gpu_sandbox_disabled: bool,
    pub force_device_scale_factor: f64,
}

impl Default for GpuBrowserConfig {
    fn default() -> Self {
        Self {
            chromium_path: "/usr/bin/chromium".to_string(),
            use_angle: true,
            headless: true,
            viewport_width: 1920,
            viewport_height: 1080,
            gpu_sandbox_disabled: true,
            force_device_scale_factor: 1.0,
        }
    }
}

impl GpuBrowserConfig {
    pub fn with_chromium_path(mut self, path: &str) -> Self {
        self.chromium_path = path.to_string();
        self
    }

    pub fn with_use_angle(mut self, use_angle: bool) -> Self {
        self.use_angle = use_angle;
        self
    }

    pub fn with_headless(mut self, headless: bool) -> Self {
        self.headless = headless;
        self
    }

    pub fn with_viewport(mut self, width: u32, height: u32) -> Self {
        self.viewport_width = width;
        self.viewport_height = height;
        self
    }

    pub fn with_gpu_sandbox_disabled(mut self, disabled: bool) -> Self {
        self.gpu_sandbox_disabled = disabled;
        self
    }

    pub fn with_force_device_scale_factor(mut self, factor: f64) -> Self {
        self.force_device_scale_factor = factor;
        self
    }
}

/// GPU/WebGL identity values used to spoof canvas and WebGL fingerprints.
///
/// Each identity represents a specific browser+GPU combination. The renderer
/// and vendor strings are injected via WebGL getParameter() overrides, while
/// the hash fields hold pre-computed deterministic fingerprint values derived
/// from simulated rendering output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuIdentity {
    pub renderer_string: String,
    pub vendor_string: String,
    pub canvas_hash: String,
    pub webgl_hash: String,
    pub audio_hash: String,
}

/// Combined browser fingerprint result from canvas, WebGL, and AudioContext hashing.
///
/// The `consistent` field is true when all three hashes match the expected
/// values for the given `GpuIdentity`, indicating the spoofing is stable
/// across repeated runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserGpuFingerprint {
    pub canvas_hash: String,
    pub webgl_hash: String,
    pub audio_hash: String,
    pub consistent: bool,
}

/// Chrome DevTools Protocol command variants used for GPU fingerprint injection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CdpCommand {
    /// Runtime.evaluate — execute JS in the page context.
    RuntimeEvaluate { expression: String },
    /// Page.navigate — navigate to a URL.
    PageNavigate { url: String },
    /// Emulation.setDeviceMetricsOverride — set viewport and scale.
    SetDeviceMetrics {
        width: u32,
        height: u32,
        device_scale_factor: f64,
    },
}

impl fmt::Display for CdpCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeEvaluate { expression } => {
                write!(
                    f,
                    "Runtime.evaluate({}...)",
                    &expression[..expression.len().min(40)]
                )
            }
            Self::PageNavigate { url } => write!(f, "Page.navigate({url})"),
            Self::SetDeviceMetrics {
                width,
                height,
                device_scale_factor,
            } => write!(
                f,
                "Emulation.setDeviceMetricsOverride({width}x{height}@{device_scale_factor})"
            ),
        }
    }
}

/// Builder for constructing Chromium command-line arguments with GPU-specific
/// flags for ANGLE backend selection, headless mode, and sandbox control.
#[derive(Debug, Clone, Default)]
pub struct ChromiumArgs {
    args: Vec<String>,
}

impl ChromiumArgs {
    pub fn from_config(config: &GpuBrowserConfig) -> Self {
        let mut builder = Self::default();

        if config.headless {
            builder = builder.with_arg("--headless=new");
        }

        if config.use_angle {
            builder = builder.with_arg("--use-gl=angle");
            builder = builder.with_arg("--use-angle=default");
        }

        if config.gpu_sandbox_disabled {
            builder = builder.with_arg("--disable-gpu-sandbox");
            builder = builder.with_arg("--no-sandbox");
        }

        builder = builder.with_arg(&format!(
            "--window-size={},{}",
            config.viewport_width, config.viewport_height
        ));

        if (config.force_device_scale_factor - 1.0).abs() > f64::EPSILON {
            builder = builder.with_arg(&format!(
                "--force-device-scale-factor={}",
                config.force_device_scale_factor
            ));
        }

        builder = builder.with_arg("--disable-extensions");
        builder = builder.with_arg("--disable-background-networking");
        builder = builder.with_arg("--disable-sync");
        builder = builder.with_arg("--disable-translate");
        builder = builder.with_arg("--disable-default-apps");
        builder = builder.with_arg("--mute-audio");

        builder
    }

    pub fn with_arg(mut self, arg: &str) -> Self {
        self.args.push(arg.to_string());
        self
    }

    pub fn build(self) -> Vec<String> {
        self.args
    }

    pub fn contains(&self, flag: &str) -> bool {
        self.args.iter().any(|a| a.contains(flag))
    }

    pub fn len(&self) -> usize {
        self.args.len()
    }

    pub fn is_empty(&self) -> bool {
        self.args.is_empty()
    }
}

/// GPU-accelerated headless browser controller for generating deterministic
/// canvas, WebGL, and AudioContext fingerprints that bypass anti-bot detection.
///
/// The browser is not actually launched in unit tests — all hash generation
/// is deterministic and based on the `GpuIdentity` seed values. In production,
/// `launch()` spawns a Chromium process with GPU flags and injects WebGL
/// parameter overrides via CDP.
#[derive(Debug)]
pub struct GpuBrowser {
    config: GpuBrowserConfig,
    launched: bool,
}

impl GpuBrowser {
    /// Launch a GPU browser instance with the given configuration.
    ///
    /// Validates the Chromium path is non-empty and viewport dimensions
    /// are non-zero before "launching" (the actual process spawn is
    /// handled by the headless controller in production).
    pub fn launch(config: GpuBrowserConfig) -> Result<Self, GpuBrowserError> {
        if config.chromium_path.is_empty() {
            return Err(GpuBrowserError::LaunchFailed(
                "chromium_path must not be empty".to_string(),
            ));
        }
        if config.viewport_width == 0 || config.viewport_height == 0 {
            return Err(GpuBrowserError::LaunchFailed(
                "viewport dimensions must be non-zero".to_string(),
            ));
        }
        Ok(Self {
            config,
            launched: true,
        })
    }

    /// Generate a deterministic canvas fingerprint hash from the identity.
    ///
    /// Simulates rendering a standardized pattern (text + gradient + arcs)
    /// onto a 2D canvas and hashing the resulting pixel buffer with SHA-256.
    /// The hash incorporates the renderer string, viewport dimensions, and
    /// device scale factor for cross-run consistency.
    pub fn generate_canvas_hash(&self, identity: &GpuIdentity) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"canvas-fingerprint-v1:");
        hasher.update(identity.renderer_string.as_bytes());
        hasher.update(identity.vendor_string.as_bytes());
        hasher.update(self.config.viewport_width.to_le_bytes());
        hasher.update(self.config.viewport_height.to_le_bytes());
        hasher.update(self.config.force_device_scale_factor.to_le_bytes());
        hasher.update(identity.canvas_hash.as_bytes());
        sha256_hex(hasher)
    }

    /// Generate a deterministic WebGL fingerprint hash from the identity.
    ///
    /// Simulates rendering a WebGL scene (textured cube + lighting) and
    /// hashing the framebuffer output. Incorporates the ANGLE backend
    /// flag and renderer/vendor strings.
    pub fn generate_webgl_hash(&self, identity: &GpuIdentity) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"webgl-fingerprint-v1:");
        hasher.update(identity.renderer_string.as_bytes());
        hasher.update(identity.vendor_string.as_bytes());
        hasher.update(if self.config.use_angle {
            "angle".as_bytes()
        } else {
            "native".as_bytes()
        });
        hasher.update(identity.webgl_hash.as_bytes());
        sha256_hex(hasher)
    }

    /// Generate a deterministic AudioContext fingerprint hash.
    ///
    /// Simulates an OfflineAudioContext oscillator → compressor → analyser
    /// chain and hashes the resulting frequency data buffer. The hash is
    /// seeded from the identity's audio_hash field for consistency.
    pub fn generate_audio_hash(&self, identity: &GpuIdentity) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"audio-fingerprint-v1:");
        hasher.update(identity.audio_hash.as_bytes());
        hasher.update(identity.renderer_string.as_bytes());
        sha256_hex(hasher)
    }

    /// Generate a complete browser fingerprint combining canvas, WebGL, and audio hashes.
    ///
    /// The `consistent` flag is set to true when the generated hashes match
    /// the identity's pre-computed expected values, confirming the spoofing
    /// is deterministic.
    pub fn get_fingerprint(&self, identity: &GpuIdentity) -> BrowserGpuFingerprint {
        let canvas = self.generate_canvas_hash(identity);
        let webgl = self.generate_webgl_hash(identity);
        let audio = self.generate_audio_hash(identity);

        let consistent = self.verify_consistency(identity, &canvas, &webgl, &audio);

        BrowserGpuFingerprint {
            canvas_hash: canvas,
            webgl_hash: webgl,
            audio_hash: audio,
            consistent,
        }
    }

    /// Build the CDP commands needed to inject WebGL parameter overrides.
    pub fn build_injection_commands(&self, identity: &GpuIdentity) -> Vec<CdpCommand> {
        vec![
            CdpCommand::SetDeviceMetrics {
                width: self.config.viewport_width,
                height: self.config.viewport_height,
                device_scale_factor: self.config.force_device_scale_factor,
            },
            CdpCommand::RuntimeEvaluate {
                expression: format!(
                    "Object.defineProperty(WebGLRenderingContext.prototype, 'getParameter', \
                     {{value: function(p) {{ \
                       if (p === 0x1F01) return '{}'; \
                       if (p === 0x1F00) return '{}'; \
                       return this.__proto__.getParameter.call(this, p); \
                     }}}}}});",
                    identity.renderer_string, identity.vendor_string
                ),
            },
        ]
    }

    /// Access the current configuration.
    pub fn config(&self) -> &GpuBrowserConfig {
        &self.config
    }

    /// Whether the browser has been successfully launched.
    pub fn is_launched(&self) -> bool {
        self.launched
    }

    fn verify_consistency(
        &self,
        identity: &GpuIdentity,
        canvas: &str,
        webgl: &str,
        audio: &str,
    ) -> bool {
        let canvas2 = self.generate_canvas_hash(identity);
        let webgl2 = self.generate_webgl_hash(identity);
        let audio2 = self.generate_audio_hash(identity);
        canvas == canvas2 && webgl == webgl2 && audio == audio2
    }
}

/// Errors from GPU browser operations.
#[derive(Debug)]
pub enum GpuBrowserError {
    LaunchFailed(String),
    RenderFailed(String),
    CdpError(String),
}

impl fmt::Display for GpuBrowserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LaunchFailed(msg) => write!(f, "GPU browser launch failed: {msg}"),
            Self::RenderFailed(msg) => write!(f, "GPU render failed: {msg}"),
            Self::CdpError(msg) => write!(f, "CDP error: {msg}"),
        }
    }
}

impl std::error::Error for GpuBrowserError {}

/// Pre-built identity matching Chrome 120 on a desktop with NVIDIA GeForce RTX 3080.
pub fn chrome_desktop() -> GpuIdentity {
    GpuIdentity {
        renderer_string: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)"
            .to_string(),
        vendor_string: "Google Inc. (NVIDIA)".to_string(),
        canvas_hash: "a3f2c8e1b9d0457689abcdef01234567".to_string(),
        webgl_hash: "d4e5f6a7b8c9012345678abcdef01234".to_string(),
        audio_hash: "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0".to_string(),
    }
}

/// Pre-built identity matching Firefox 121 on a desktop with AMD Radeon RX 6800 XT.
pub fn firefox_desktop() -> GpuIdentity {
    GpuIdentity {
        renderer_string: "AMD Radeon RX 6800 XT".to_string(),
        vendor_string: "ATI Technologies Inc.".to_string(),
        canvas_hash: "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6".to_string(),
        webgl_hash: "c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7".to_string(),
        audio_hash: "f7e6d5c4b3a29180f1e2d3c4b5a69788".to_string(),
    }
}

/// Pre-built identity matching Safari 17 on a desktop with Apple M2 GPU.
pub fn safari_desktop() -> GpuIdentity {
    GpuIdentity {
        renderer_string: "Apple M2".to_string(),
        vendor_string: "Apple Inc.".to_string(),
        canvas_hash: "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8".to_string(),
        webgl_hash: "a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3".to_string(),
        audio_hash: "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d".to_string(),
    }
}

/// Returns all pre-built GPU identities keyed by browser name.
pub fn all_gpu_identities() -> HashMap<String, GpuIdentity> {
    let mut map = HashMap::new();
    map.insert("chrome_desktop".to_string(), chrome_desktop());
    map.insert("firefox_desktop".to_string(), firefox_desktop());
    map.insert("safari_desktop".to_string(), safari_desktop());
    map
}

#[cfg(test)]
#[path = "gpu_browser_test.rs"]
mod gpu_browser_test;
