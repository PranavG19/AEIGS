use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::persona::PersonaId;

/// HTTP/2 SETTINGS frame parameter identifiers (RFC 7540 §6.5.2).
///
/// Akamai, Cloudflare, and PerimeterX fingerprint clients by the exact combination
/// of SETTINGS values sent in the connection preface. Real browsers send characteristic
/// values that differ by vendor and version. Automated tools (curl, python-httpx, go-net/http)
/// send library defaults that are trivially distinguishable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Http2Setting {
    HeaderTableSize,
    EnablePush,
    MaxConcurrentStreams,
    InitialWindowSize,
    MaxFrameSize,
    MaxHeaderListSize,
}

impl Http2Setting {
    /// Wire identifier per RFC 7540 §6.5.2.
    pub fn wire_id(self) -> u16 {
        match self {
            Self::HeaderTableSize => 0x1,
            Self::EnablePush => 0x2,
            Self::MaxConcurrentStreams => 0x3,
            Self::InitialWindowSize => 0x4,
            Self::MaxFrameSize => 0x5,
            Self::MaxHeaderListSize => 0x6,
        }
    }
}

impl fmt::Display for Http2Setting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderTableSize => write!(f, "HEADER_TABLE_SIZE"),
            Self::EnablePush => write!(f, "ENABLE_PUSH"),
            Self::MaxConcurrentStreams => write!(f, "MAX_CONCURRENT_STREAMS"),
            Self::InitialWindowSize => write!(f, "INITIAL_WINDOW_SIZE"),
            Self::MaxFrameSize => write!(f, "MAX_FRAME_SIZE"),
            Self::MaxHeaderListSize => write!(f, "MAX_HEADER_LIST_SIZE"),
        }
    }
}

/// Ordering of HTTP/2 pseudo-headers in HEADERS frames.
///
/// Browsers send pseudo-headers (:method, :authority, :scheme, :path) in a specific
/// order that fingerprinting systems check. Chrome uses m/a/s/p, Firefox uses m/p/a/s,
/// Safari uses m/s/p/a. Getting this wrong is a dead giveaway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PseudoHeaderOrder {
    /// :method, :authority, :scheme, :path — Chrome/Edge/Opera
    MethodAuthoritySchemePathChromium,
    /// :method, :path, :authority, :scheme — Firefox
    MethodPathAuthoritySchemeMozilla,
    /// :method, :scheme, :path, :authority — Safari
    MethodSchemePathAuthorityWebkit,
    /// Custom ordering for unusual clients
    Custom(Vec<String>),
}

impl PseudoHeaderOrder {
    /// Returns the ordered pseudo-header names for this ordering.
    pub fn header_names(&self) -> Vec<&str> {
        match self {
            Self::MethodAuthoritySchemePathChromium => {
                vec![":method", ":authority", ":scheme", ":path"]
            }
            Self::MethodPathAuthoritySchemeMozilla => {
                vec![":method", ":path", ":authority", ":scheme"]
            }
            Self::MethodSchemePathAuthorityWebkit => {
                vec![":method", ":scheme", ":path", ":authority"]
            }
            Self::Custom(names) => names.iter().map(|s| s.as_str()).collect(),
        }
    }
}

/// HTTP/2 PRIORITY frame weight and dependency pattern.
///
/// Browsers use characteristic priority tree structures. Chrome uses weighted
/// priorities with exclusive dependencies, Firefox uses a complex priority tree
/// with group streams, Safari uses a flatter structure. The priority frame
/// pattern is part of the Akamai HTTP/2 fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorityFrame {
    pub stream_dependency: u32,
    pub weight: u8,
    pub exclusive: bool,
}

/// Complete HTTP/2 connection fingerprint for a specific browser version.
///
/// Combines SETTINGS frame values, WINDOW_UPDATE size, PRIORITY frames,
/// and pseudo-header ordering into a single coherent identity. All values
/// are captured from real browser traffic using Wireshark/tshark against
/// h2o and nginx test servers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Fingerprint {
    pub browser_id: Http2BrowserId,
    pub settings_order: Vec<Http2Setting>,
    pub settings_values: HashMap<Http2Setting, u32>,
    pub connection_window_update: u32,
    pub priority_frames: Vec<PriorityFrame>,
    pub pseudo_header_order: PseudoHeaderOrder,
    pub header_table_size_update: Option<u32>,
}

impl Http2Fingerprint {
    /// Serializes SETTINGS to the Akamai fingerprint format: "id:value;id:value|window|priority_list"
    ///
    /// This matches the format used by Akamai's passive fingerprinting sensors.
    /// The SETTINGS are emitted in the order they appear in `settings_order`,
    /// which itself is characteristic of the browser.
    pub fn akamai_fingerprint(&self) -> String {
        let settings: Vec<String> = self
            .settings_order
            .iter()
            .filter_map(|s| {
                self.settings_values
                    .get(s)
                    .map(|v| format!("{}:{}", s.wire_id(), v))
            })
            .collect();

        let priorities: Vec<String> = self
            .priority_frames
            .iter()
            .map(|p| {
                let excl = if p.exclusive { 1 } else { 0 };
                format!("{}:{}:{}:{}", 0, p.stream_dependency, excl, p.weight)
            })
            .collect();

        format!(
            "{}|{}|{}",
            settings.join(";"),
            self.connection_window_update,
            priorities.join(",")
        )
    }
}

/// Browser identifiers for HTTP/2 fingerprint profiles.
///
/// Version ranges rather than exact versions because most SETTINGS values
/// remain stable across minor releases. The range indicates the captures
/// used to build the profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Http2BrowserId {
    Chrome120_125,
    Firefox120_125,
    Safari17,
    Edge120_125,
    Curl,
    GoNetHttp,
    PythonHttpx,
}

impl fmt::Display for Http2BrowserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chrome120_125 => write!(f, "Chrome 120-125"),
            Self::Firefox120_125 => write!(f, "Firefox 120-125"),
            Self::Safari17 => write!(f, "Safari 17+"),
            Self::Edge120_125 => write!(f, "Edge 120-125 (Chromium)"),
            Self::Curl => write!(f, "curl/libcurl"),
            Self::GoNetHttp => write!(f, "Go net/http"),
            Self::PythonHttpx => write!(f, "Python httpx/aiohttp"),
        }
    }
}

/// Chrome 120-125 HTTP/2 fingerprint.
///
/// Captured via tshark against h2o test server. Chrome sends SETTINGS in a
/// specific order with specific values that have been stable since Chrome 106.
/// The WINDOW_UPDATE of 15663105 (15MB - 65535) is Chrome's signature.
fn chrome_120_fingerprint() -> Http2Fingerprint {
    let mut settings = HashMap::new();
    settings.insert(Http2Setting::HeaderTableSize, 65536);
    settings.insert(Http2Setting::MaxConcurrentStreams, 1000);
    settings.insert(Http2Setting::InitialWindowSize, 6291456);
    settings.insert(Http2Setting::MaxHeaderListSize, 262144);

    Http2Fingerprint {
        browser_id: Http2BrowserId::Chrome120_125,
        settings_order: vec![
            Http2Setting::HeaderTableSize,
            Http2Setting::EnablePush,
            Http2Setting::MaxConcurrentStreams,
            Http2Setting::InitialWindowSize,
            Http2Setting::MaxHeaderListSize,
        ],
        settings_values: {
            let mut s = settings;
            s.insert(Http2Setting::EnablePush, 0);
            s
        },
        connection_window_update: 15663105,
        priority_frames: vec![
            PriorityFrame {
                stream_dependency: 0,
                weight: 255,
                exclusive: true,
            },
            PriorityFrame {
                stream_dependency: 0,
                weight: 241,
                exclusive: false,
            },
            PriorityFrame {
                stream_dependency: 0,
                weight: 1,
                exclusive: false,
            },
        ],
        pseudo_header_order: PseudoHeaderOrder::MethodAuthoritySchemePathChromium,
        header_table_size_update: Some(65536),
    }
}

/// Firefox 120-125 HTTP/2 fingerprint.
///
/// Firefox uses a distinct SETTINGS order and values. The WINDOW_UPDATE of
/// 12517377 (12MB - 65535) is Firefox's signature. Firefox enables push (1)
/// unlike Chrome. Priority frames use stream group dependencies.
fn firefox_120_fingerprint() -> Http2Fingerprint {
    let mut settings = HashMap::new();
    settings.insert(Http2Setting::HeaderTableSize, 65536);
    settings.insert(Http2Setting::InitialWindowSize, 131072);
    settings.insert(Http2Setting::MaxFrameSize, 16384);

    Http2Fingerprint {
        browser_id: Http2BrowserId::Firefox120_125,
        settings_order: vec![
            Http2Setting::HeaderTableSize,
            Http2Setting::InitialWindowSize,
            Http2Setting::MaxFrameSize,
        ],
        settings_values: settings,
        connection_window_update: 12517377,
        priority_frames: vec![
            PriorityFrame {
                stream_dependency: 0,
                weight: 255,
                exclusive: false,
            },
            PriorityFrame {
                stream_dependency: 0,
                weight: 241,
                exclusive: false,
            },
            PriorityFrame {
                stream_dependency: 0,
                weight: 1,
                exclusive: false,
            },
            PriorityFrame {
                stream_dependency: 7,
                weight: 1,
                exclusive: false,
            },
            PriorityFrame {
                stream_dependency: 3,
                weight: 1,
                exclusive: false,
            },
        ],
        pseudo_header_order: PseudoHeaderOrder::MethodPathAuthoritySchemeMozilla,
        header_table_size_update: Some(65536),
    }
}

/// Safari 17+ HTTP/2 fingerprint.
///
/// Safari uses Apple's Network.framework which has unique SETTINGS ordering.
/// WINDOW_UPDATE of 10485760 (10MB) is Safari's signature. Safari keeps
/// ENABLE_PUSH=1 and uses a high MAX_CONCURRENT_STREAMS of 100.
fn safari_17_fingerprint() -> Http2Fingerprint {
    let mut settings = HashMap::new();
    settings.insert(Http2Setting::EnablePush, 1);
    settings.insert(Http2Setting::MaxConcurrentStreams, 100);
    settings.insert(Http2Setting::InitialWindowSize, 2097152);
    settings.insert(Http2Setting::MaxHeaderListSize, 0);

    Http2Fingerprint {
        browser_id: Http2BrowserId::Safari17,
        settings_order: vec![
            Http2Setting::EnablePush,
            Http2Setting::MaxConcurrentStreams,
            Http2Setting::InitialWindowSize,
            Http2Setting::MaxHeaderListSize,
        ],
        settings_values: settings,
        connection_window_update: 10485760,
        priority_frames: vec![PriorityFrame {
            stream_dependency: 0,
            weight: 255,
            exclusive: false,
        }],
        pseudo_header_order: PseudoHeaderOrder::MethodSchemePathAuthorityWebkit,
        header_table_size_update: None,
    }
}

/// Edge 120-125 HTTP/2 fingerprint.
///
/// Edge is Chromium-based and sends identical SETTINGS to Chrome.
/// Same WINDOW_UPDATE, same pseudo-header ordering, same priority frames.
/// The only difference is the User-Agent string (handled elsewhere).
fn edge_120_fingerprint() -> Http2Fingerprint {
    let mut base = chrome_120_fingerprint();
    base.browser_id = Http2BrowserId::Edge120_125;
    base
}

/// curl/libcurl HTTP/2 fingerprint.
///
/// nghttp2-based. Sends a minimal SETTINGS with default values.
/// WINDOW_UPDATE of 33488897 is nghttp2's default (32MB - 65535).
/// No priority frames. Dead giveaway for automated tools.
fn curl_fingerprint() -> Http2Fingerprint {
    let mut settings = HashMap::new();
    settings.insert(Http2Setting::MaxConcurrentStreams, 100);
    settings.insert(Http2Setting::InitialWindowSize, 33554432);
    settings.insert(Http2Setting::EnablePush, 0);

    Http2Fingerprint {
        browser_id: Http2BrowserId::Curl,
        settings_order: vec![
            Http2Setting::MaxConcurrentStreams,
            Http2Setting::InitialWindowSize,
            Http2Setting::EnablePush,
        ],
        settings_values: settings,
        connection_window_update: 33488897,
        priority_frames: vec![],
        pseudo_header_order: PseudoHeaderOrder::MethodAuthoritySchemePathChromium,
        header_table_size_update: None,
    }
}

/// Go net/http HTTP/2 fingerprint.
///
/// Go's http2 package sends very recognizable SETTINGS. The combination
/// of ENABLE_PUSH=0 + MAX_HEADER_LIST_SIZE=10485760 is unique to Go.
fn go_net_http_fingerprint() -> Http2Fingerprint {
    let mut settings = HashMap::new();
    settings.insert(Http2Setting::EnablePush, 0);
    settings.insert(Http2Setting::InitialWindowSize, 4194304);
    settings.insert(Http2Setting::MaxHeaderListSize, 10485760);

    Http2Fingerprint {
        browser_id: Http2BrowserId::GoNetHttp,
        settings_order: vec![
            Http2Setting::EnablePush,
            Http2Setting::InitialWindowSize,
            Http2Setting::MaxHeaderListSize,
        ],
        settings_values: settings,
        connection_window_update: 1073741824,
        priority_frames: vec![],
        pseudo_header_order: PseudoHeaderOrder::MethodAuthoritySchemePathChromium,
        header_table_size_update: None,
    }
}

/// Python httpx/aiohttp HTTP/2 fingerprint.
///
/// Python h2 library defaults. Recognizable by the hyper-h2 default SETTINGS
/// with HEADER_TABLE_SIZE=4096 and INITIAL_WINDOW_SIZE=65535.
fn python_httpx_fingerprint() -> Http2Fingerprint {
    let mut settings = HashMap::new();
    settings.insert(Http2Setting::HeaderTableSize, 4096);
    settings.insert(Http2Setting::EnablePush, 0);
    settings.insert(Http2Setting::MaxConcurrentStreams, 100);
    settings.insert(Http2Setting::InitialWindowSize, 65535);
    settings.insert(Http2Setting::MaxFrameSize, 16384);
    settings.insert(Http2Setting::MaxHeaderListSize, 65536);

    Http2Fingerprint {
        browser_id: Http2BrowserId::PythonHttpx,
        settings_order: vec![
            Http2Setting::HeaderTableSize,
            Http2Setting::EnablePush,
            Http2Setting::MaxConcurrentStreams,
            Http2Setting::InitialWindowSize,
            Http2Setting::MaxFrameSize,
            Http2Setting::MaxHeaderListSize,
        ],
        settings_values: settings,
        connection_window_update: 65535,
        priority_frames: vec![],
        pseudo_header_order: PseudoHeaderOrder::MethodAuthoritySchemePathChromium,
        header_table_size_update: None,
    }
}

/// Complete HTTP/2 fingerprint database.
///
/// Provides lookup by browser ID or persona, and matching logic
/// for identifying unknown fingerprints against the database.
pub struct Http2FingerprintDb {
    fingerprints: HashMap<Http2BrowserId, Http2Fingerprint>,
    persona_mapping: HashMap<PersonaId, Http2BrowserId>,
}

impl Http2FingerprintDb {
    /// Loads the full fingerprint database with all known browser profiles.
    pub fn new() -> Self {
        let fingerprints: HashMap<Http2BrowserId, Http2Fingerprint> = [
            (Http2BrowserId::Chrome120_125, chrome_120_fingerprint()),
            (Http2BrowserId::Firefox120_125, firefox_120_fingerprint()),
            (Http2BrowserId::Safari17, safari_17_fingerprint()),
            (Http2BrowserId::Edge120_125, edge_120_fingerprint()),
            (Http2BrowserId::Curl, curl_fingerprint()),
            (Http2BrowserId::GoNetHttp, go_net_http_fingerprint()),
            (Http2BrowserId::PythonHttpx, python_httpx_fingerprint()),
        ]
        .into_iter()
        .collect();

        let persona_mapping: HashMap<PersonaId, Http2BrowserId> = [
            (PersonaId::ChromeDesktop, Http2BrowserId::Chrome120_125),
            (PersonaId::ChromeMobile, Http2BrowserId::Chrome120_125),
            (PersonaId::FirefoxDesktop, Http2BrowserId::Firefox120_125),
            (PersonaId::SafariDesktop, Http2BrowserId::Safari17),
            (PersonaId::SafariMobile, Http2BrowserId::Safari17),
            (PersonaId::EdgeDesktop, Http2BrowserId::Edge120_125),
            (PersonaId::OperaDesktop, Http2BrowserId::Chrome120_125),
            (PersonaId::Googlebot, Http2BrowserId::Chrome120_125),
            (PersonaId::CurlClient, Http2BrowserId::Curl),
            (PersonaId::PythonRequests, Http2BrowserId::PythonHttpx),
        ]
        .into_iter()
        .collect();

        Self {
            fingerprints,
            persona_mapping,
        }
    }

    /// Returns the HTTP/2 fingerprint for a given browser ID, if known.
    pub fn get(&self, browser_id: &Http2BrowserId) -> Option<&Http2Fingerprint> {
        self.fingerprints.get(browser_id)
    }

    /// Returns the HTTP/2 fingerprint that matches a given persona.
    pub fn for_persona(&self, persona_id: PersonaId) -> Option<&Http2Fingerprint> {
        self.persona_mapping
            .get(&persona_id)
            .and_then(|bid| self.fingerprints.get(bid))
    }

    /// Returns the browser ID mapped to a persona.
    pub fn browser_id_for_persona(&self, persona_id: PersonaId) -> Option<Http2BrowserId> {
        self.persona_mapping.get(&persona_id).copied()
    }

    /// Returns all stored fingerprints.
    pub fn all(&self) -> impl Iterator<Item = &Http2Fingerprint> {
        self.fingerprints.values()
    }

    /// Returns the number of fingerprint profiles in the database.
    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }

    /// Returns true if the database contains no fingerprints.
    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }

    /// Attempts to identify a client's browser by matching observed HTTP/2 parameters.
    ///
    /// Computes a similarity score against each known profile and returns
    /// the best match if it exceeds the confidence threshold. Matching is
    /// based on: SETTINGS values (exact), WINDOW_UPDATE (exact), pseudo-header
    /// ordering (exact), and priority frame count (fuzzy).
    pub fn identify(&self, observed: &ObservedHttp2Params) -> Option<(Http2BrowserId, f64)> {
        let mut best_match: Option<(Http2BrowserId, f64)> = None;

        for (browser_id, fingerprint) in &self.fingerprints {
            let score = compute_match_score(fingerprint, observed);
            if score > 0.6 && best_match.as_ref().is_none_or(|(_, s)| score > *s) {
                best_match = Some((*browser_id, score));
            }
        }

        best_match
    }
}

impl Default for Http2FingerprintDb {
    fn default() -> Self {
        Self::new()
    }
}

/// Observed HTTP/2 connection parameters extracted from a live connection.
///
/// Used by `Http2FingerprintDb::identify()` to match unknown clients
/// against the fingerprint database.
#[derive(Debug, Clone, Default)]
pub struct ObservedHttp2Params {
    pub settings: HashMap<Http2Setting, u32>,
    pub settings_order: Vec<Http2Setting>,
    pub connection_window_update: Option<u32>,
    pub priority_frame_count: usize,
    pub pseudo_header_order: Option<PseudoHeaderOrder>,
}

/// Computes a normalized similarity score [0.0, 1.0] between a known fingerprint
/// and observed parameters.
///
/// Scoring weights:
///  - SETTINGS values match: 40% (each matching value contributes equally)
///  - SETTINGS order match: 15% (exact order comparison)
///  - WINDOW_UPDATE match: 20% (exact value)
///  - Pseudo-header ordering: 15% (exact enum match)
///  - Priority frame count: 10% (tolerance of ±1)
fn compute_match_score(known: &Http2Fingerprint, observed: &ObservedHttp2Params) -> f64 {
    let mut score = 0.0;

    let total_settings = known.settings_values.len().max(1);
    let mut settings_matches = 0;
    for (setting, expected_value) in &known.settings_values {
        if observed.settings.get(setting) == Some(expected_value) {
            settings_matches += 1;
        }
    }
    score += 0.40 * (settings_matches as f64 / total_settings as f64);

    if !known.settings_order.is_empty()
        && !observed.settings_order.is_empty()
        && known.settings_order == observed.settings_order
    {
        score += 0.15;
    }

    if let Some(observed_wu) = observed.connection_window_update
        && observed_wu == known.connection_window_update
    {
        score += 0.20;
    }

    if let Some(ref observed_pho) = observed.pseudo_header_order
        && *observed_pho == known.pseudo_header_order
    {
        score += 0.15;
    }

    let known_priority_count = known.priority_frames.len();
    let diff = (known_priority_count as i64 - observed.priority_frame_count as i64).unsigned_abs();
    if diff == 0 {
        score += 0.10;
    } else if diff == 1 {
        score += 0.05;
    }

    score
}

/// Serializes an HTTP/2 fingerprint's SETTINGS into the wire-format order
/// for use in connection preface construction.
///
/// Returns (setting_id, value) pairs in the order the browser sends them.
pub fn settings_to_wire(fingerprint: &Http2Fingerprint) -> Vec<(u16, u32)> {
    fingerprint
        .settings_order
        .iter()
        .filter_map(|s| {
            fingerprint
                .settings_values
                .get(s)
                .map(|v| (s.wire_id(), *v))
        })
        .collect()
}

/// Returns the HTTP/2 fingerprint for a persona, suitable for configuring
/// an HTTP/2 connection to match the persona's browser identity.
pub fn h2_fingerprint_for_persona(persona_id: PersonaId) -> Http2Fingerprint {
    let db = Http2FingerprintDb::new();
    db.for_persona(persona_id)
        .cloned()
        .unwrap_or_else(chrome_120_fingerprint)
}

#[cfg(test)]
#[path = "http2_fingerprint_test.rs"]
mod http2_fingerprint_test;
