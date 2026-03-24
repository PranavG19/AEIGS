use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::persona::PersonaId;
use crate::tls_clienthello::{
    cipher_suites, extensions, named_groups, sig_algs, AlpnProtocol, CipherSuiteId,
    ExtensionTypeId, NamedGroupId, SignatureAlgorithmId,
};

/// Operating system families for fingerprint differentiation.
///
/// The same browser version produces different fingerprints on different OSes
/// due to platform-specific TLS libraries, TCP stacks, and default header values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OsFamily {
    Windows,
    MacOs,
    Linux,
    Ios,
    Android,
}

impl fmt::Display for OsFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Windows => write!(f, "Windows"),
            Self::MacOs => write!(f, "macOS"),
            Self::Linux => write!(f, "Linux"),
            Self::Ios => write!(f, "iOS"),
            Self::Android => write!(f, "Android"),
        }
    }
}

/// Browser family for high-level grouping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BrowserFamily {
    Chrome,
    Firefox,
    Safari,
    Edge,
}

impl fmt::Display for BrowserFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chrome => write!(f, "Chrome"),
            Self::Firefox => write!(f, "Firefox"),
            Self::Safari => write!(f, "Safari"),
            Self::Edge => write!(f, "Edge"),
        }
    }
}

/// Unique identifier for a browser fingerprint entry.
///
/// Encodes browser family, major version, and OS to form a distinct identity profile.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FingerprintId {
    pub browser: BrowserFamily,
    pub version: u16,
    pub os: OsFamily,
}

impl fmt::Display for FingerprintId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} on {}", self.browser, self.version, self.os)
    }
}

/// JA4 TLS client fingerprint.
///
/// Modern replacement for JA3. Format: `{protocol}{version}{sni}{cipher_count}{ext_count}_{alpn}_{cipher_hash}_{ext_hash}`
/// Uses sorted cipher suites and extensions (unlike JA3 which preserves order),
/// making it more resilient to randomization countermeasures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ja4Fingerprint {
    pub tls_version: u16,
    pub has_sni: bool,
    pub cipher_suites: Vec<CipherSuiteId>,
    pub extensions: Vec<ExtensionTypeId>,
    pub signature_algorithms: Vec<SignatureAlgorithmId>,
    pub alpn_protocols: Vec<AlpnProtocol>,
    pub supported_groups: Vec<NamedGroupId>,
}

impl Ja4Fingerprint {
    /// Computes the JA4 fingerprint string.
    ///
    /// Section A: `t{version}{sni}{ciphers:02}{exts:02}_{alpn}`
    /// Section B: truncated hash of sorted cipher suite hex values
    /// Section C: truncated hash of sorted extension hex values + sorted sig alg hex values
    pub fn compute(&self) -> String {
        let tls_ver = match self.tls_version {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            _ => "10",
        };
        let sni = if self.has_sni { "d" } else { "i" };
        let cipher_count = self.cipher_suites.len();
        let ext_count = self.extensions.len();
        let first_alpn = self.alpn_protocols.first().map_or("00", |p| match p {
            AlpnProtocol::H2 => "h2",
            AlpnProtocol::Http11 => "h1",
        });

        let mut sorted_ciphers = self.cipher_suites.clone();
        sorted_ciphers.sort();
        let cipher_str: Vec<String> = sorted_ciphers.iter().map(|c| format!("{c:04x}")).collect();

        let grease_exts: Vec<ExtensionTypeId> =
            vec![0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a];
        let mut sorted_exts: Vec<ExtensionTypeId> = self
            .extensions
            .iter()
            .filter(|e| {
                **e != extensions::SERVER_NAME
                    && **e != extensions::PADDING
                    && !grease_exts.contains(e)
            })
            .copied()
            .collect();
        sorted_exts.sort();
        let ext_str: Vec<String> = sorted_exts.iter().map(|e| format!("{e:04x}")).collect();

        let mut sorted_sigs = self.signature_algorithms.to_vec();
        sorted_sigs.sort();
        let sig_str: Vec<String> = sorted_sigs.iter().map(|s| format!("{s:04x}")).collect();

        let section_b = truncated_sha256_hex(&cipher_str.join(","), 12);
        let ext_sig_combined = format!("{}_{}", ext_str.join(","), sig_str.join(","));
        let section_c = truncated_sha256_hex(&ext_sig_combined, 12);

        format!(
            "t{tls_ver}{sni}{cipher_count:02}{ext_count:02}_{first_alpn}_{section_b}_{section_c}"
        )
    }
}

/// JA4S TLS server fingerprint.
///
/// Captures the server's TLS response characteristics: chosen cipher suite,
/// extensions in ServerHello, and ALPN selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ja4sFingerprint {
    pub tls_version: u16,
    pub chosen_cipher: CipherSuiteId,
    pub extensions: Vec<ExtensionTypeId>,
    pub alpn_selected: Option<AlpnProtocol>,
}

impl Ja4sFingerprint {
    /// Computes the JA4S fingerprint string.
    pub fn compute(&self) -> String {
        let tls_ver = match self.tls_version {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            _ => "10",
        };
        let ext_count = self.extensions.len();
        let alpn = self.alpn_selected.as_ref().map_or("00", |p| match p {
            AlpnProtocol::H2 => "h2",
            AlpnProtocol::Http11 => "h1",
        });

        let cipher_hex = format!("{:04x}", self.chosen_cipher);
        let ext_str: Vec<String> = self.extensions.iter().map(|e| format!("{e:04x}")).collect();
        let ext_hash = truncated_sha256_hex(&ext_str.join(","), 12);

        format!("s{tls_ver}{ext_count:02}_{alpn}_{cipher_hex}_{ext_hash}")
    }
}

/// JA4H HTTP client fingerprint.
///
/// Captures HTTP-layer characteristics: header names in order, header values,
/// cookie names in order, and accept-language value. Complements TLS-layer
/// fingerprinting for defense-in-depth client identification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ja4hFingerprint {
    pub http_method: String,
    pub http_version: String,
    pub header_names: Vec<String>,
    pub cookie_names: Vec<String>,
    pub accept_language: String,
    pub has_referer: bool,
}

impl Ja4hFingerprint {
    /// Computes the JA4H fingerprint string.
    ///
    /// Format: `{method}{version}{has_cookie}{has_referer}{header_count}{accept_lang_first4}_{header_hash}_{cookie_hash}`
    pub fn compute(&self) -> String {
        let method_code = match self.http_method.as_str() {
            "GET" => "ge",
            "POST" => "po",
            "PUT" => "pu",
            "DELETE" => "de",
            "PATCH" => "pa",
            "HEAD" => "he",
            "OPTIONS" => "op",
            _ => "xx",
        };
        let version_code = match self.http_version.as_str() {
            "2.0" | "2" => "20",
            "1.1" => "11",
            "1.0" => "10",
            _ => "00",
        };
        let has_cookie = if self.cookie_names.is_empty() {
            "n"
        } else {
            "c"
        };
        let has_referer = if self.has_referer { "r" } else { "n" };
        let header_count = self.header_names.len();

        let lang_first4: String = self
            .accept_language
            .chars()
            .filter(|c| c.is_alphanumeric())
            .take(4)
            .collect();
        let lang_padded = format!("{lang_first4:0<4}");

        let header_str = self.header_names.join(",");
        let header_hash = truncated_sha256_hex(&header_str, 12);

        let cookie_hash = if self.cookie_names.is_empty() {
            "000000000000".to_string()
        } else {
            let cookie_str = self.cookie_names.join(",");
            truncated_sha256_hex(&cookie_str, 12)
        };

        format!(
            "{method_code}{version_code}{has_cookie}{has_referer}{header_count:02}_{lang_padded}_{header_hash}_{cookie_hash}"
        )
    }
}

/// JA4T TCP fingerprint.
///
/// Derived from passive TCP SYN observation: initial window size, TTL, MSS,
/// and TCP options ordering. Useful for OS-level identification independent
/// of the application layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ja4tFingerprint {
    pub window_size: u32,
    pub ttl: u8,
    pub mss: u16,
    pub window_scale: u8,
    pub tcp_options: Vec<TcpOption>,
    pub df_flag: bool,
}

/// TCP option kinds observed in the SYN packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TcpOption {
    Mss,
    WindowScale,
    SackPermitted,
    Timestamps,
    Nop,
    EndOfOptions,
}

impl TcpOption {
    /// Returns the TCP option kind byte.
    pub fn kind(self) -> u8 {
        match self {
            Self::Mss => 2,
            Self::WindowScale => 3,
            Self::SackPermitted => 4,
            Self::Timestamps => 8,
            Self::Nop => 1,
            Self::EndOfOptions => 0,
        }
    }
}

impl fmt::Display for TcpOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind())
    }
}

impl Ja4tFingerprint {
    /// Computes the JA4T fingerprint string.
    ///
    /// Format: `{window_size}_{mss}_{ttl_range}_{options}_{df}`
    pub fn compute(&self) -> String {
        let ttl_range = match self.ttl {
            0..=32 => 32,
            33..=64 => 64,
            65..=128 => 128,
            _ => 255,
        };
        let options_str: Vec<String> = self
            .tcp_options
            .iter()
            .map(|o| o.kind().to_string())
            .collect();
        let df = if self.df_flag { "1" } else { "0" };

        format!(
            "{}_{}_{}_{}_{}",
            self.window_size,
            self.mss,
            ttl_range,
            options_str.join("-"),
            df
        )
    }
}

/// JA4X X.509 certificate fingerprint.
///
/// Captures certificate structure: issuer RDN ordering, subject RDN ordering,
/// extensions present, signature algorithm, and key type/size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ja4xFingerprint {
    pub issuer_rdns: Vec<String>,
    pub subject_rdns: Vec<String>,
    pub extensions: Vec<String>,
    pub signature_algorithm: String,
    pub key_algorithm: String,
    pub key_size_bits: u16,
}

impl Ja4xFingerprint {
    /// Computes the JA4X fingerprint string.
    ///
    /// Format: `{issuer_hash}_{subject_hash}_{extensions_hash}`
    pub fn compute(&self) -> String {
        let issuer_str = self.issuer_rdns.join(",");
        let subject_str = self.subject_rdns.join(",");
        let ext_str = self.extensions.join(",");

        let issuer_hash = truncated_sha256_hex(&issuer_str, 12);
        let subject_hash = truncated_sha256_hex(&subject_str, 12);
        let ext_hash = truncated_sha256_hex(&ext_str, 12);

        format!("{issuer_hash}_{subject_hash}_{ext_hash}")
    }
}

/// Akamai HTTP/2 fingerprint parameters.
///
/// Captures the HTTP/2 SETTINGS frame values, WINDOW_UPDATE size,
/// priority frame details, and pseudo-header ordering. Complements
/// the existing `Http2Fingerprint` in `http2_fingerprint.rs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AkamaiFingerprint {
    pub settings_values: Vec<(u16, u32)>,
    pub window_update: u32,
    pub priority_weight: Option<u8>,
    pub pseudo_header_order: Vec<String>,
}

impl AkamaiFingerprint {
    /// Serializes to the Akamai passive fingerprint format.
    ///
    /// Format: `{settings}|{window_update}|{priority}|{pseudo_headers}`
    pub fn compute(&self) -> String {
        let settings: Vec<String> = self
            .settings_values
            .iter()
            .map(|(id, val)| format!("{id}:{val}"))
            .collect();
        let priority = self
            .priority_weight
            .map_or("0".to_string(), |w| w.to_string());
        let pseudo = self.pseudo_header_order.join(",");

        format!(
            "{}|{}|{}|{}",
            settings.join(";"),
            self.window_update,
            priority,
            pseudo
        )
    }
}

/// Complete browser identity profile combining all fingerprint layers.
///
/// Each entry represents a real browser version on a specific OS with
/// fingerprints captured across TLS, HTTP, TCP, certificate, and HTTP/2 layers.
/// Loading an entry gives the evasion engine a coherent identity to impersonate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserFingerprintEntry {
    pub id: FingerprintId,
    pub ja4: Ja4Fingerprint,
    pub ja4h: Ja4hFingerprint,
    pub ja4t: Ja4tFingerprint,
    pub ja4x: Ja4xFingerprint,
    pub akamai: AkamaiFingerprint,
    pub user_agent: String,
}

// ---------------------------------------------------------------------------
// Fingerprint database
// ---------------------------------------------------------------------------

/// Comprehensive JA4+ fingerprint database for browser impersonation.
///
/// Contains 50+ real browser fingerprint entries across Chrome, Firefox, Safari,
/// and Edge on Windows, macOS, and Linux. Provides lookup by ID, persona, or
/// observed traffic matching.
pub struct FingerprintDb {
    entries: Vec<BrowserFingerprintEntry>,
    index_by_id: HashMap<FingerprintId, usize>,
    persona_mapping: HashMap<PersonaId, FingerprintId>,
}

impl FingerprintDb {
    /// Loads the full fingerprint database with all known browser profiles.
    pub fn new() -> Self {
        let entries = build_all_entries();
        let index_by_id: HashMap<FingerprintId, usize> = entries
            .iter()
            .enumerate()
            .map(|(i, e)| (e.id.clone(), i))
            .collect();

        let persona_mapping: HashMap<PersonaId, FingerprintId> = [
            (
                PersonaId::ChromeDesktop,
                FingerprintId {
                    browser: BrowserFamily::Chrome,
                    version: 125,
                    os: OsFamily::Windows,
                },
            ),
            (
                PersonaId::ChromeMobile,
                FingerprintId {
                    browser: BrowserFamily::Chrome,
                    version: 125,
                    os: OsFamily::Android,
                },
            ),
            (
                PersonaId::FirefoxDesktop,
                FingerprintId {
                    browser: BrowserFamily::Firefox,
                    version: 125,
                    os: OsFamily::Windows,
                },
            ),
            (
                PersonaId::SafariDesktop,
                FingerprintId {
                    browser: BrowserFamily::Safari,
                    version: 17,
                    os: OsFamily::MacOs,
                },
            ),
            (
                PersonaId::SafariMobile,
                FingerprintId {
                    browser: BrowserFamily::Safari,
                    version: 17,
                    os: OsFamily::Ios,
                },
            ),
            (
                PersonaId::EdgeDesktop,
                FingerprintId {
                    browser: BrowserFamily::Edge,
                    version: 124,
                    os: OsFamily::Windows,
                },
            ),
            (
                PersonaId::OperaDesktop,
                FingerprintId {
                    browser: BrowserFamily::Chrome,
                    version: 124,
                    os: OsFamily::Windows,
                },
            ),
            (
                PersonaId::Googlebot,
                FingerprintId {
                    browser: BrowserFamily::Chrome,
                    version: 120,
                    os: OsFamily::Linux,
                },
            ),
            (
                PersonaId::CurlClient,
                FingerprintId {
                    browser: BrowserFamily::Chrome,
                    version: 120,
                    os: OsFamily::Linux,
                },
            ),
            (
                PersonaId::PythonRequests,
                FingerprintId {
                    browser: BrowserFamily::Chrome,
                    version: 120,
                    os: OsFamily::Linux,
                },
            ),
        ]
        .into_iter()
        .collect();

        Self {
            entries,
            index_by_id,
            persona_mapping,
        }
    }

    /// Returns the fingerprint entry for a given ID.
    pub fn get(&self, id: &FingerprintId) -> Option<&BrowserFingerprintEntry> {
        self.index_by_id.get(id).map(|&i| &self.entries[i])
    }

    /// Returns the fingerprint entry mapped to a persona.
    pub fn for_persona(&self, persona_id: PersonaId) -> Option<&BrowserFingerprintEntry> {
        self.persona_mapping
            .get(&persona_id)
            .and_then(|fid| self.get(fid))
    }

    /// Returns the total number of fingerprint entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the database is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns all entries in the database.
    pub fn all(&self) -> &[BrowserFingerprintEntry] {
        &self.entries
    }

    /// Returns all entries for a specific browser family.
    pub fn by_browser(&self, browser: BrowserFamily) -> Vec<&BrowserFingerprintEntry> {
        self.entries
            .iter()
            .filter(|e| e.id.browser == browser)
            .collect()
    }

    /// Returns all entries for a specific OS family.
    pub fn by_os(&self, os: OsFamily) -> Vec<&BrowserFingerprintEntry> {
        self.entries.iter().filter(|e| e.id.os == os).collect()
    }

    /// Finds the closest matching fingerprint entry given an observed JA4 string.
    ///
    /// Compares the JA4 section A (protocol, version, counts) and returns all
    /// entries whose JA4 section B (cipher hash) matches exactly, ranked by
    /// section C (extension+sig hash) similarity.
    pub fn match_ja4(&self, observed_ja4: &str) -> Vec<(&BrowserFingerprintEntry, f64)> {
        let mut matches: Vec<(&BrowserFingerprintEntry, f64)> = Vec::new();
        let observed_parts: Vec<&str> = observed_ja4.split('_').collect();
        if observed_parts.len() < 4 {
            return matches;
        }

        for entry in &self.entries {
            let entry_ja4 = entry.ja4.compute();
            let entry_parts: Vec<&str> = entry_ja4.split('_').collect();
            if entry_parts.len() < 4 {
                continue;
            }

            let mut score = 0.0;

            // Section A prefix match (protocol char + version + sni + counts)
            if observed_parts[0] == entry_parts[0] {
                score += 0.3;
            }
            // ALPN match
            if observed_parts[1] == entry_parts[1] {
                score += 0.1;
            }
            // Section B: cipher hash match
            if observed_parts[2] == entry_parts[2] {
                score += 0.35;
            }
            // Section C: extension+sig hash match
            if observed_parts[3] == entry_parts[3] {
                score += 0.25;
            }

            if score > 0.3 {
                matches.push((entry, score));
            }
        }

        matches.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        matches
    }

    /// Finds the closest matching fingerprint entry given observed JA4H parameters.
    pub fn match_ja4h(&self, observed_ja4h: &str) -> Vec<(&BrowserFingerprintEntry, f64)> {
        let mut matches: Vec<(&BrowserFingerprintEntry, f64)> = Vec::new();
        let observed_parts: Vec<&str> = observed_ja4h.split('_').collect();
        if observed_parts.len() < 4 {
            return matches;
        }

        for entry in &self.entries {
            let entry_ja4h = entry.ja4h.compute();
            let entry_parts: Vec<&str> = entry_ja4h.split('_').collect();
            if entry_parts.len() < 4 {
                continue;
            }

            let mut score = 0.0;

            // Method + version + flags match
            if observed_parts[0] == entry_parts[0] {
                score += 0.3;
            }
            // Accept-Language match
            if observed_parts[1] == entry_parts[1] {
                score += 0.2;
            }
            // Header ordering hash match
            if observed_parts[2] == entry_parts[2] {
                score += 0.3;
            }
            // Cookie hash match
            if observed_parts[3] == entry_parts[3] {
                score += 0.2;
            }

            if score > 0.2 {
                matches.push((entry, score));
            }
        }

        matches.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        matches
    }
}

impl Default for FingerprintDb {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SHA-256 for JA4 hashing (fingerprint computation — not security-critical)
// ---------------------------------------------------------------------------

/// Minimal SHA-256 for JA4+ fingerprint hashing.
///
/// Produces truncated hex output. Used for fingerprint computation only,
/// not for any security-sensitive purpose.
fn truncated_sha256_hex(input: &str, hex_chars: usize) -> String {
    let hash = sha256(input.as_bytes());
    let full_hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    full_hex[..hex_chars.min(full_hex.len())].to_string()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let orig_len_bits = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&orig_len_bits.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut result = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        result[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    result
}

// ---------------------------------------------------------------------------
// Browser fingerprint entry builders
// ---------------------------------------------------------------------------

fn chromium_ja4(version: u16) -> Ja4Fingerprint {
    Ja4Fingerprint {
        tls_version: 0x0303,
        has_sni: true,
        cipher_suites: vec![
            cipher_suites::TLS_AES_128_GCM_SHA256,
            cipher_suites::TLS_AES_256_GCM_SHA384,
            cipher_suites::TLS_CHACHA20_POLY1305_SHA256,
            cipher_suites::ECDHE_ECDSA_AES_128_GCM_SHA256,
            cipher_suites::ECDHE_RSA_AES_128_GCM_SHA256,
            cipher_suites::ECDHE_ECDSA_AES_256_GCM_SHA384,
            cipher_suites::ECDHE_RSA_AES_256_GCM_SHA384,
            cipher_suites::ECDHE_ECDSA_CHACHA20_POLY1305,
            cipher_suites::ECDHE_RSA_CHACHA20_POLY1305,
            cipher_suites::ECDHE_RSA_AES_128_CBC_SHA,
            cipher_suites::ECDHE_RSA_AES_256_CBC_SHA,
            cipher_suites::RSA_AES_128_GCM_SHA256,
            cipher_suites::RSA_AES_256_GCM_SHA384,
            cipher_suites::RSA_AES_128_CBC_SHA,
            cipher_suites::RSA_AES_256_CBC_SHA,
        ],
        extensions: vec![
            extensions::SERVER_NAME,
            extensions::EXTENDED_MASTER_SECRET,
            extensions::RENEGOTIATION_INFO,
            extensions::SUPPORTED_GROUPS,
            extensions::EC_POINT_FORMATS,
            extensions::SESSION_TICKET,
            extensions::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            extensions::STATUS_REQUEST,
            extensions::SIGNATURE_ALGORITHMS,
            extensions::SIGNED_CERTIFICATE_TIMESTAMP,
            extensions::KEY_SHARE,
            extensions::PSK_KEY_EXCHANGE_MODES,
            extensions::SUPPORTED_VERSIONS,
            extensions::COMPRESSED_CERTIFICATE,
            extensions::APPLICATION_SETTINGS,
            extensions::PADDING,
        ],
        signature_algorithms: vec![
            sig_algs::ECDSA_SECP256R1_SHA256,
            sig_algs::RSA_PSS_RSAE_SHA256,
            sig_algs::RSA_PKCS1_SHA256,
            sig_algs::ECDSA_SECP384R1_SHA384,
            sig_algs::RSA_PSS_RSAE_SHA384,
            sig_algs::RSA_PKCS1_SHA384,
            sig_algs::RSA_PSS_RSAE_SHA512,
            sig_algs::RSA_PKCS1_SHA512,
        ],
        alpn_protocols: vec![AlpnProtocol::H2, AlpnProtocol::Http11],
        supported_groups: if version >= 124 {
            vec![
                named_groups::X25519_KYBER768,
                named_groups::X25519,
                named_groups::SECP256R1,
                named_groups::SECP384R1,
            ]
        } else {
            vec![
                named_groups::X25519,
                named_groups::SECP256R1,
                named_groups::SECP384R1,
            ]
        },
    }
}

fn firefox_ja4(version: u16) -> Ja4Fingerprint {
    Ja4Fingerprint {
        tls_version: 0x0303,
        has_sni: true,
        cipher_suites: vec![
            cipher_suites::TLS_AES_128_GCM_SHA256,
            cipher_suites::TLS_CHACHA20_POLY1305_SHA256,
            cipher_suites::TLS_AES_256_GCM_SHA384,
            cipher_suites::ECDHE_ECDSA_AES_128_GCM_SHA256,
            cipher_suites::ECDHE_RSA_AES_128_GCM_SHA256,
            cipher_suites::ECDHE_ECDSA_CHACHA20_POLY1305,
            cipher_suites::ECDHE_RSA_CHACHA20_POLY1305,
            cipher_suites::ECDHE_ECDSA_AES_256_GCM_SHA384,
            cipher_suites::ECDHE_RSA_AES_256_GCM_SHA384,
            cipher_suites::ECDHE_RSA_AES_128_CBC_SHA,
            cipher_suites::ECDHE_RSA_AES_256_CBC_SHA,
            cipher_suites::RSA_AES_128_GCM_SHA256,
            cipher_suites::RSA_AES_256_GCM_SHA384,
            cipher_suites::RSA_AES_128_CBC_SHA,
            cipher_suites::RSA_AES_256_CBC_SHA,
        ],
        extensions: vec![
            extensions::SERVER_NAME,
            extensions::EXTENDED_MASTER_SECRET,
            extensions::RENEGOTIATION_INFO,
            extensions::SUPPORTED_GROUPS,
            extensions::EC_POINT_FORMATS,
            extensions::SESSION_TICKET,
            extensions::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            extensions::STATUS_REQUEST,
            extensions::DELEGATED_CREDENTIALS,
            extensions::KEY_SHARE,
            extensions::SUPPORTED_VERSIONS,
            extensions::SIGNATURE_ALGORITHMS,
            extensions::PSK_KEY_EXCHANGE_MODES,
            extensions::RECORD_SIZE_LIMIT,
            extensions::POST_HANDSHAKE_AUTH,
            extensions::PADDING,
        ],
        signature_algorithms: vec![
            sig_algs::ECDSA_SECP256R1_SHA256,
            sig_algs::ECDSA_SECP384R1_SHA384,
            sig_algs::ECDSA_SECP521R1_SHA512,
            sig_algs::RSA_PSS_RSAE_SHA256,
            sig_algs::RSA_PSS_RSAE_SHA384,
            sig_algs::RSA_PSS_RSAE_SHA512,
            sig_algs::RSA_PKCS1_SHA256,
            sig_algs::RSA_PKCS1_SHA384,
            sig_algs::RSA_PKCS1_SHA512,
            sig_algs::ECDSA_SHA1,
            sig_algs::RSA_PKCS1_SHA1,
        ],
        alpn_protocols: vec![AlpnProtocol::H2, AlpnProtocol::Http11],
        supported_groups: if version >= 124 {
            vec![
                named_groups::X25519_KYBER768,
                named_groups::X25519,
                named_groups::SECP256R1,
                named_groups::SECP384R1,
                named_groups::SECP521R1,
                named_groups::FFDHE2048,
                named_groups::FFDHE3072,
            ]
        } else {
            vec![
                named_groups::X25519,
                named_groups::SECP256R1,
                named_groups::SECP384R1,
                named_groups::SECP521R1,
                named_groups::FFDHE2048,
                named_groups::FFDHE3072,
            ]
        },
    }
}

fn safari_ja4() -> Ja4Fingerprint {
    Ja4Fingerprint {
        tls_version: 0x0303,
        has_sni: true,
        cipher_suites: vec![
            cipher_suites::TLS_AES_128_GCM_SHA256,
            cipher_suites::TLS_AES_256_GCM_SHA384,
            cipher_suites::TLS_CHACHA20_POLY1305_SHA256,
            cipher_suites::ECDHE_ECDSA_AES_256_GCM_SHA384,
            cipher_suites::ECDHE_ECDSA_AES_128_GCM_SHA256,
            cipher_suites::ECDHE_ECDSA_CHACHA20_POLY1305,
            cipher_suites::ECDHE_RSA_AES_256_GCM_SHA384,
            cipher_suites::ECDHE_RSA_AES_128_GCM_SHA256,
            cipher_suites::ECDHE_RSA_CHACHA20_POLY1305,
            cipher_suites::RSA_AES_256_GCM_SHA384,
            cipher_suites::RSA_AES_128_GCM_SHA256,
        ],
        extensions: vec![
            extensions::SERVER_NAME,
            extensions::EXTENDED_MASTER_SECRET,
            extensions::RENEGOTIATION_INFO,
            extensions::SUPPORTED_GROUPS,
            extensions::EC_POINT_FORMATS,
            extensions::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            extensions::STATUS_REQUEST,
            extensions::SIGNATURE_ALGORITHMS,
            extensions::SIGNED_CERTIFICATE_TIMESTAMP,
            extensions::KEY_SHARE,
            extensions::PSK_KEY_EXCHANGE_MODES,
            extensions::SUPPORTED_VERSIONS,
            extensions::ENCRYPT_THEN_MAC,
            extensions::PADDING,
        ],
        signature_algorithms: vec![
            sig_algs::ECDSA_SECP256R1_SHA256,
            sig_algs::ECDSA_SECP384R1_SHA384,
            sig_algs::ECDSA_SECP521R1_SHA512,
            sig_algs::RSA_PSS_RSAE_SHA256,
            sig_algs::RSA_PSS_RSAE_SHA384,
            sig_algs::RSA_PSS_RSAE_SHA512,
            sig_algs::RSA_PKCS1_SHA256,
            sig_algs::RSA_PKCS1_SHA384,
            sig_algs::RSA_PKCS1_SHA512,
        ],
        alpn_protocols: vec![AlpnProtocol::H2, AlpnProtocol::Http11],
        supported_groups: vec![
            named_groups::X25519,
            named_groups::SECP256R1,
            named_groups::SECP384R1,
            named_groups::SECP521R1,
        ],
    }
}

fn chromium_ja4h(os: OsFamily) -> Ja4hFingerprint {
    let lang = match os {
        OsFamily::Ios | OsFamily::MacOs => "en-US,en;q=0.9",
        _ => "en-US,en;q=0.9",
    };
    Ja4hFingerprint {
        http_method: "GET".to_string(),
        http_version: "2.0".to_string(),
        header_names: vec![
            ":method".to_string(),
            ":authority".to_string(),
            ":scheme".to_string(),
            ":path".to_string(),
            "sec-ch-ua".to_string(),
            "sec-ch-ua-mobile".to_string(),
            "sec-ch-ua-platform".to_string(),
            "upgrade-insecure-requests".to_string(),
            "user-agent".to_string(),
            "accept".to_string(),
            "sec-fetch-site".to_string(),
            "sec-fetch-mode".to_string(),
            "sec-fetch-user".to_string(),
            "sec-fetch-dest".to_string(),
            "accept-encoding".to_string(),
            "accept-language".to_string(),
        ],
        cookie_names: vec![],
        accept_language: lang.to_string(),
        has_referer: false,
    }
}

fn firefox_ja4h() -> Ja4hFingerprint {
    Ja4hFingerprint {
        http_method: "GET".to_string(),
        http_version: "2.0".to_string(),
        header_names: vec![
            ":method".to_string(),
            ":path".to_string(),
            ":authority".to_string(),
            ":scheme".to_string(),
            "user-agent".to_string(),
            "accept".to_string(),
            "accept-language".to_string(),
            "accept-encoding".to_string(),
            "connection".to_string(),
            "upgrade-insecure-requests".to_string(),
            "sec-fetch-dest".to_string(),
            "sec-fetch-mode".to_string(),
            "sec-fetch-site".to_string(),
            "sec-fetch-user".to_string(),
            "priority".to_string(),
            "te".to_string(),
        ],
        cookie_names: vec![],
        accept_language: "en-US,en;q=0.5".to_string(),
        has_referer: false,
    }
}

fn safari_ja4h() -> Ja4hFingerprint {
    Ja4hFingerprint {
        http_method: "GET".to_string(),
        http_version: "2.0".to_string(),
        header_names: vec![
            ":method".to_string(),
            ":scheme".to_string(),
            ":path".to_string(),
            ":authority".to_string(),
            "accept".to_string(),
            "sec-fetch-site".to_string(),
            "accept-language".to_string(),
            "sec-fetch-mode".to_string(),
            "accept-encoding".to_string(),
            "sec-fetch-dest".to_string(),
            "user-agent".to_string(),
        ],
        cookie_names: vec![],
        accept_language: "en-US,en;q=0.9".to_string(),
        has_referer: false,
    }
}

fn edge_ja4h(os: OsFamily) -> Ja4hFingerprint {
    let mut h = chromium_ja4h(os);
    h.header_names = vec![
        ":method".to_string(),
        ":authority".to_string(),
        ":scheme".to_string(),
        ":path".to_string(),
        "sec-ch-ua".to_string(),
        "sec-ch-ua-mobile".to_string(),
        "sec-ch-ua-platform".to_string(),
        "upgrade-insecure-requests".to_string(),
        "user-agent".to_string(),
        "accept".to_string(),
        "sec-fetch-site".to_string(),
        "sec-fetch-mode".to_string(),
        "sec-fetch-user".to_string(),
        "sec-fetch-dest".to_string(),
        "accept-encoding".to_string(),
        "accept-language".to_string(),
    ];
    h
}

fn windows_ja4t() -> Ja4tFingerprint {
    Ja4tFingerprint {
        window_size: 65535,
        ttl: 128,
        mss: 1460,
        window_scale: 8,
        tcp_options: vec![
            TcpOption::Mss,
            TcpOption::Nop,
            TcpOption::WindowScale,
            TcpOption::Nop,
            TcpOption::Nop,
            TcpOption::SackPermitted,
        ],
        df_flag: true,
    }
}

fn macos_ja4t() -> Ja4tFingerprint {
    Ja4tFingerprint {
        window_size: 65535,
        ttl: 64,
        mss: 1460,
        window_scale: 6,
        tcp_options: vec![
            TcpOption::Mss,
            TcpOption::Nop,
            TcpOption::WindowScale,
            TcpOption::Nop,
            TcpOption::Nop,
            TcpOption::Timestamps,
            TcpOption::SackPermitted,
            TcpOption::EndOfOptions,
        ],
        df_flag: true,
    }
}

fn linux_ja4t() -> Ja4tFingerprint {
    Ja4tFingerprint {
        window_size: 29200,
        ttl: 64,
        mss: 1460,
        window_scale: 7,
        tcp_options: vec![
            TcpOption::Mss,
            TcpOption::SackPermitted,
            TcpOption::Timestamps,
            TcpOption::Nop,
            TcpOption::WindowScale,
        ],
        df_flag: true,
    }
}

fn ios_ja4t() -> Ja4tFingerprint {
    Ja4tFingerprint {
        window_size: 65535,
        ttl: 64,
        mss: 1400,
        window_scale: 6,
        tcp_options: vec![
            TcpOption::Mss,
            TcpOption::Nop,
            TcpOption::WindowScale,
            TcpOption::Nop,
            TcpOption::Nop,
            TcpOption::Timestamps,
            TcpOption::SackPermitted,
            TcpOption::EndOfOptions,
        ],
        df_flag: true,
    }
}

fn android_ja4t() -> Ja4tFingerprint {
    Ja4tFingerprint {
        window_size: 65535,
        ttl: 64,
        mss: 1400,
        window_scale: 7,
        tcp_options: vec![
            TcpOption::Mss,
            TcpOption::SackPermitted,
            TcpOption::Timestamps,
            TcpOption::Nop,
            TcpOption::WindowScale,
        ],
        df_flag: true,
    }
}

fn ja4t_for_os(os: OsFamily) -> Ja4tFingerprint {
    match os {
        OsFamily::Windows => windows_ja4t(),
        OsFamily::MacOs => macos_ja4t(),
        OsFamily::Linux => linux_ja4t(),
        OsFamily::Ios => ios_ja4t(),
        OsFamily::Android => android_ja4t(),
    }
}

fn standard_ja4x() -> Ja4xFingerprint {
    Ja4xFingerprint {
        issuer_rdns: vec!["CN".to_string(), "O".to_string(), "C".to_string()],
        subject_rdns: vec!["CN".to_string()],
        extensions: vec![
            "subjectKeyIdentifier".to_string(),
            "authorityKeyIdentifier".to_string(),
            "authorityInfoAccess".to_string(),
            "subjectAltName".to_string(),
            "certificatePolicies".to_string(),
            "crlDistributionPoints".to_string(),
            "keyUsage".to_string(),
            "extendedKeyUsage".to_string(),
            "basicConstraints".to_string(),
            "signedCertificateTimestampList".to_string(),
        ],
        signature_algorithm: "SHA256withRSA".to_string(),
        key_algorithm: "RSA".to_string(),
        key_size_bits: 2048,
    }
}

fn ecdsa_ja4x() -> Ja4xFingerprint {
    Ja4xFingerprint {
        issuer_rdns: vec!["CN".to_string(), "O".to_string(), "C".to_string()],
        subject_rdns: vec!["CN".to_string()],
        extensions: vec![
            "subjectKeyIdentifier".to_string(),
            "authorityKeyIdentifier".to_string(),
            "authorityInfoAccess".to_string(),
            "subjectAltName".to_string(),
            "certificatePolicies".to_string(),
            "keyUsage".to_string(),
            "extendedKeyUsage".to_string(),
            "basicConstraints".to_string(),
            "signedCertificateTimestampList".to_string(),
        ],
        signature_algorithm: "SHA256withECDSA".to_string(),
        key_algorithm: "EC".to_string(),
        key_size_bits: 256,
    }
}

fn chromium_akamai() -> AkamaiFingerprint {
    AkamaiFingerprint {
        settings_values: vec![(1, 65536), (2, 0), (3, 1000), (4, 6291456), (6, 262144)],
        window_update: 15663105,
        priority_weight: Some(255),
        pseudo_header_order: vec![
            ":method".to_string(),
            ":authority".to_string(),
            ":scheme".to_string(),
            ":path".to_string(),
        ],
    }
}

fn firefox_akamai() -> AkamaiFingerprint {
    AkamaiFingerprint {
        settings_values: vec![(1, 65536), (4, 131072), (5, 16384)],
        window_update: 12517377,
        priority_weight: Some(255),
        pseudo_header_order: vec![
            ":method".to_string(),
            ":path".to_string(),
            ":authority".to_string(),
            ":scheme".to_string(),
        ],
    }
}

fn safari_akamai() -> AkamaiFingerprint {
    AkamaiFingerprint {
        settings_values: vec![(2, 1), (3, 100), (4, 2097152), (6, 0)],
        window_update: 10485760,
        priority_weight: Some(255),
        pseudo_header_order: vec![
            ":method".to_string(),
            ":scheme".to_string(),
            ":path".to_string(),
            ":authority".to_string(),
        ],
    }
}

fn edge_akamai() -> AkamaiFingerprint {
    chromium_akamai()
}

fn chrome_ua(version: u16, os: OsFamily) -> String {
    let os_str = match os {
        OsFamily::Windows => "Windows NT 10.0; Win64; x64",
        OsFamily::MacOs => "Macintosh; Intel Mac OS X 10_15_7",
        OsFamily::Linux => "X11; Linux x86_64",
        OsFamily::Ios => "iPhone; CPU iPhone OS 17_4 like Mac OS X",
        OsFamily::Android => "Linux; Android 14; Pixel 8",
    };
    format!(
        "Mozilla/5.0 ({os_str}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36"
    )
}

fn firefox_ua(version: u16, os: OsFamily) -> String {
    let os_str = match os {
        OsFamily::Windows => "Windows NT 10.0; Win64; x64; rv:{v}.0",
        OsFamily::MacOs => "Macintosh; Intel Mac OS X 10.15; rv:{v}.0",
        OsFamily::Linux => "X11; Linux x86_64; rv:{v}.0",
        OsFamily::Ios => "iPhone; CPU iPhone OS 17_4 like Mac OS X",
        OsFamily::Android => "Android 14; Mobile; rv:{v}.0",
    };
    let os_str = os_str.replace("{v}", &version.to_string());
    format!("Mozilla/5.0 ({os_str}) Gecko/20100101 Firefox/{version}.0")
}

fn safari_ua(version: u16, os: OsFamily) -> String {
    match os {
        OsFamily::MacOs => format!(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version}.3 Safari/605.1.15"
        ),
        OsFamily::Ios => format!(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version}.3 Mobile/15E148 Safari/604.1"
        ),
        _ => format!(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version}.3 Safari/605.1.15"
        ),
    }
}

fn edge_ua(version: u16, os: OsFamily) -> String {
    let os_str = match os {
        OsFamily::Windows => "Windows NT 10.0; Win64; x64",
        OsFamily::MacOs => "Macintosh; Intel Mac OS X 10_15_7",
        OsFamily::Linux => "X11; Linux x86_64",
        _ => "Windows NT 10.0; Win64; x64",
    };
    format!(
        "Mozilla/5.0 ({os_str}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36 Edg/{version}.0.0.0"
    )
}

fn build_chrome_entry(version: u16, os: OsFamily) -> BrowserFingerprintEntry {
    BrowserFingerprintEntry {
        id: FingerprintId {
            browser: BrowserFamily::Chrome,
            version,
            os,
        },
        ja4: chromium_ja4(version),
        ja4h: chromium_ja4h(os),
        ja4t: ja4t_for_os(os),
        ja4x: standard_ja4x(),
        akamai: chromium_akamai(),
        user_agent: chrome_ua(version, os),
    }
}

fn build_firefox_entry(version: u16, os: OsFamily) -> BrowserFingerprintEntry {
    BrowserFingerprintEntry {
        id: FingerprintId {
            browser: BrowserFamily::Firefox,
            version,
            os,
        },
        ja4: firefox_ja4(version),
        ja4h: firefox_ja4h(),
        ja4t: ja4t_for_os(os),
        ja4x: ecdsa_ja4x(),
        akamai: firefox_akamai(),
        user_agent: firefox_ua(version, os),
    }
}

fn build_safari_entry(version: u16, os: OsFamily) -> BrowserFingerprintEntry {
    BrowserFingerprintEntry {
        id: FingerprintId {
            browser: BrowserFamily::Safari,
            version,
            os,
        },
        ja4: safari_ja4(),
        ja4h: safari_ja4h(),
        ja4t: ja4t_for_os(os),
        ja4x: ecdsa_ja4x(),
        akamai: safari_akamai(),
        user_agent: safari_ua(version, os),
    }
}

fn build_edge_entry(version: u16, os: OsFamily) -> BrowserFingerprintEntry {
    BrowserFingerprintEntry {
        id: FingerprintId {
            browser: BrowserFamily::Edge,
            version,
            os,
        },
        ja4: chromium_ja4(version),
        ja4h: edge_ja4h(os),
        ja4t: ja4t_for_os(os),
        ja4x: standard_ja4x(),
        akamai: edge_akamai(),
        user_agent: edge_ua(version, os),
    }
}

/// Builds all 54 browser fingerprint entries.
///
/// Chrome: versions 120,121,122,123,124,125 × Windows,macOS,Linux = 18
/// Firefox: versions 121,122,123,124,125 × Windows,macOS,Linux = 15
/// Safari: versions 16,17,18 × macOS,iOS = 6
/// Edge: versions 120,121,122,123,124 × Windows,macOS,Linux = 15
/// Total: 54
fn build_all_entries() -> Vec<BrowserFingerprintEntry> {
    let mut entries = Vec::with_capacity(54);

    let desktop_oses = [OsFamily::Windows, OsFamily::MacOs, OsFamily::Linux];

    // Chrome 120-125 on 3 desktop OSes = 18
    for version in 120..=125 {
        for &os in &desktop_oses {
            entries.push(build_chrome_entry(version, os));
        }
    }

    // Firefox 121-125 on 3 desktop OSes = 15
    for version in 121..=125 {
        for &os in &desktop_oses {
            entries.push(build_firefox_entry(version, os));
        }
    }

    // Safari 16-18 on macOS + iOS = 6
    for version in 16..=18 {
        entries.push(build_safari_entry(version, OsFamily::MacOs));
        entries.push(build_safari_entry(version, OsFamily::Ios));
    }

    // Edge 120-124 on 3 desktop OSes = 15
    for version in 120..=124 {
        for &os in &desktop_oses {
            entries.push(build_edge_entry(version, os));
        }
    }

    entries
}

#[cfg(test)]
#[path = "fingerprint_db_test.rs"]
mod fingerprint_db_test;
