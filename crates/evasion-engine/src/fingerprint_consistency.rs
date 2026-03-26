use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::PersonaId;

/// Deterministic browser fingerprint components tied to a specific persona identity.
///
/// Each field corresponds to a browser API surface that anti-bot systems correlate:
/// canvas hash, WebGL renderer/vendor, AudioContext fingerprint, and installed font list.
/// All values are derived deterministically from the persona seed so repeated visits
/// within a session produce identical fingerprints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserFingerprint {
    pub persona: PersonaId,
    pub canvas_hash: String,
    pub webgl_renderer: String,
    pub webgl_vendor: String,
    pub audio_context_hash: String,
    pub font_list: Vec<String>,
    pub gpu_renderer_string: String,
}

/// Operating system family used to select platform-appropriate font lists and GPU strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OsFamily {
    Windows,
    MacOs,
    Linux,
    Android,
    Ios,
}

impl OsFamily {
    /// Map a persona to its expected OS family.
    pub fn from_persona(persona: PersonaId) -> Self {
        match persona {
            PersonaId::ChromeDesktop | PersonaId::EdgeDesktop | PersonaId::OperaDesktop => {
                OsFamily::Windows
            }
            PersonaId::SafariDesktop => OsFamily::MacOs,
            PersonaId::FirefoxDesktop => OsFamily::Linux,
            PersonaId::ChromeMobile => OsFamily::Android,
            PersonaId::SafariMobile => OsFamily::Ios,
            PersonaId::Googlebot | PersonaId::CurlClient | PersonaId::PythonRequests => {
                OsFamily::Linux
            }
        }
    }
}

/// WebGL renderer/vendor pairs that match real GPU hardware per OS.
const WEBGL_PAIRS: &[(OsFamily, &str, &str)] = &[
    (
        OsFamily::Windows,
        "ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)",
        "Google Inc. (NVIDIA)",
    ),
    (
        OsFamily::Windows,
        "ANGLE (Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0)",
        "Google Inc. (Intel)",
    ),
    (
        OsFamily::Windows,
        "ANGLE (AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0)",
        "Google Inc. (AMD)",
    ),
    (OsFamily::MacOs, "Apple M1 Pro", "Apple"),
    (OsFamily::MacOs, "Apple M2", "Apple"),
    (
        OsFamily::Linux,
        "Mesa Intel(R) UHD Graphics 630 (CFL GT2)",
        "Intel Open Source Technology Center",
    ),
    (
        OsFamily::Linux,
        "llvmpipe (LLVM 15.0.7, 256 bits)",
        "Mesa/X.org",
    ),
    (OsFamily::Android, "Adreno (TM) 660", "Qualcomm"),
    (OsFamily::Android, "Mali-G78", "ARM"),
    (OsFamily::Ios, "Apple GPU", "Apple Inc."),
];

/// GPU renderer strings returned by the WEBGL_debug_renderer_info extension.
const GPU_RENDERER_STRINGS: &[(OsFamily, &str)] = &[
    (OsFamily::Windows, "NVIDIA GeForce RTX 3060"),
    (OsFamily::Windows, "Intel(R) UHD Graphics 630"),
    (OsFamily::Windows, "AMD Radeon RX 580"),
    (OsFamily::MacOs, "Apple M1 Pro"),
    (OsFamily::MacOs, "Apple M2"),
    (OsFamily::Linux, "Mesa Intel(R) UHD Graphics 630 (CFL GT2)"),
    (OsFamily::Android, "Adreno (TM) 660"),
    (OsFamily::Android, "Mali-G78"),
    (OsFamily::Ios, "Apple GPU"),
];

/// System font lists per OS matching what `document.fonts` would enumerate.
const WINDOWS_FONTS: &[&str] = &[
    "Arial",
    "Calibri",
    "Cambria",
    "Consolas",
    "Courier New",
    "Georgia",
    "Impact",
    "Lucida Console",
    "Segoe UI",
    "Tahoma",
    "Times New Roman",
    "Trebuchet MS",
    "Verdana",
    "Wingdings",
    "Comic Sans MS",
];

const MACOS_FONTS: &[&str] = &[
    "Arial",
    "Avenir",
    "Courier New",
    "Futura",
    "Geneva",
    "Georgia",
    "Helvetica",
    "Helvetica Neue",
    "Lucida Grande",
    "Menlo",
    "Monaco",
    "Optima",
    "Palatino",
    "San Francisco",
    "Times New Roman",
];

const LINUX_FONTS: &[&str] = &[
    "Arial",
    "Cantarell",
    "Courier New",
    "DejaVu Sans",
    "DejaVu Sans Mono",
    "DejaVu Serif",
    "Droid Sans",
    "FreeMono",
    "FreeSans",
    "FreeSerif",
    "Liberation Mono",
    "Liberation Sans",
    "Liberation Serif",
    "Noto Sans",
    "Ubuntu",
];

const ANDROID_FONTS: &[&str] = &[
    "Droid Sans",
    "Droid Sans Mono",
    "Droid Serif",
    "Noto Sans",
    "Noto Serif",
    "Roboto",
    "Roboto Condensed",
    "Roboto Mono",
];

const IOS_FONTS: &[&str] = &[
    "Academy Engraved LET",
    "American Typewriter",
    "Arial",
    "Avenir",
    "Avenir Next",
    "Courier New",
    "Georgia",
    "Helvetica",
    "Helvetica Neue",
    "Menlo",
    "San Francisco",
    "Times New Roman",
];

/// Generates a deterministic browser fingerprint for the given persona and seed.
///
/// The seed value selects among multiple plausible configurations for the persona's
/// OS family, ensuring that different sessions can use different-but-valid fingerprints
/// while remaining internally consistent within a single session.
pub fn generate_fingerprint(persona: PersonaId, seed: u64) -> BrowserFingerprint {
    let os = OsFamily::from_persona(persona);

    let os_webgl: Vec<_> = WEBGL_PAIRS.iter().filter(|(o, _, _)| *o == os).collect();
    let (webgl_renderer, webgl_vendor) = if os_webgl.is_empty() {
        ("Generic Renderer".to_string(), "Generic Vendor".to_string())
    } else {
        let idx = (seed as usize) % os_webgl.len();
        (os_webgl[idx].1.to_string(), os_webgl[idx].2.to_string())
    };

    let os_gpu: Vec<_> = GPU_RENDERER_STRINGS
        .iter()
        .filter(|(o, _)| *o == os)
        .collect();
    let gpu_renderer_string = if os_gpu.is_empty() {
        "Generic GPU".to_string()
    } else {
        let idx = (seed as usize) % os_gpu.len();
        os_gpu[idx].1.to_string()
    };

    let font_list = font_list_for_os(os);
    let canvas_hash = deterministic_hash(persona, seed, "canvas");
    let audio_context_hash = deterministic_hash(persona, seed, "audio");

    BrowserFingerprint {
        persona,
        canvas_hash,
        webgl_renderer,
        webgl_vendor,
        audio_context_hash,
        font_list,
        gpu_renderer_string,
    }
}

/// Returns the font list appropriate for the given OS family.
pub fn font_list_for_os(os: OsFamily) -> Vec<String> {
    let fonts = match os {
        OsFamily::Windows => WINDOWS_FONTS,
        OsFamily::MacOs => MACOS_FONTS,
        OsFamily::Linux => LINUX_FONTS,
        OsFamily::Android => ANDROID_FONTS,
        OsFamily::Ios => IOS_FONTS,
    };
    fonts.iter().map(|f| f.to_string()).collect()
}

/// Deterministic hash generation using a simple but stable mixing function.
///
/// Produces a hex string that remains identical across calls with the same inputs.
/// Not cryptographically secure — designed for fingerprint consistency, not secrecy.
fn deterministic_hash(persona: PersonaId, seed: u64, domain: &str) -> String {
    let persona_byte = persona as u8;
    let domain_bytes: u64 = domain
        .bytes()
        .fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));

    let mut h = seed
        .wrapping_mul(0x517cc1b727220a95)
        .wrapping_add(persona_byte as u64)
        .wrapping_mul(0x6c62272e07bb0142)
        .wrapping_add(domain_bytes);

    for _ in 0..4 {
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51afd7ed558ccd);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
        h ^= h >> 33;
    }

    format!("{:016x}", h)
}

/// Validates that a fingerprint is internally consistent:
/// WebGL pair matches OS, fonts match OS, no empty fields.
pub fn validate_fingerprint(fp: &BrowserFingerprint) -> Vec<String> {
    let mut errors = Vec::new();
    let os = OsFamily::from_persona(fp.persona);

    if fp.canvas_hash.is_empty() {
        errors.push("canvas_hash is empty".to_string());
    }
    if fp.audio_context_hash.is_empty() {
        errors.push("audio_context_hash is empty".to_string());
    }
    if fp.webgl_renderer.is_empty() {
        errors.push("webgl_renderer is empty".to_string());
    }
    if fp.webgl_vendor.is_empty() {
        errors.push("webgl_vendor is empty".to_string());
    }
    if fp.font_list.is_empty() {
        errors.push("font_list is empty".to_string());
    }

    let valid_renderer = WEBGL_PAIRS
        .iter()
        .any(|(o, r, _)| *o == os && *r == fp.webgl_renderer);
    if !valid_renderer {
        errors.push(format!(
            "webgl_renderer '{}' not valid for {:?}",
            fp.webgl_renderer, os
        ));
    }

    let expected_fonts = font_list_for_os(os);
    if fp.font_list != expected_fonts {
        errors.push(format!(
            "font_list does not match expected fonts for {:?}",
            os
        ));
    }

    errors
}

/// Pre-built fingerprint database mapping persona+seed to consistent fingerprints.
///
/// Caches generated fingerprints so repeated lookups within a session are O(1).
pub struct FingerprintDatabase {
    cache: HashMap<(PersonaId, u64), BrowserFingerprint>,
}

impl FingerprintDatabase {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Get or generate a fingerprint for the given persona and seed.
    pub fn get_or_generate(&mut self, persona: PersonaId, seed: u64) -> &BrowserFingerprint {
        self.cache
            .entry((persona, seed))
            .or_insert_with(|| generate_fingerprint(persona, seed))
    }

    /// Number of cached fingerprints.
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }

    /// Clear all cached fingerprints.
    pub fn clear(&mut self) {
        self.cache.clear();
    }
}

impl Default for FingerprintDatabase {
    fn default() -> Self {
        Self::new()
    }
}
