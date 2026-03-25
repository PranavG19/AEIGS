use std::collections::{HashMap, HashSet};
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};

/// Result of validating an email address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmailValidationStatus {
    Valid,
    Invalid,
    CatchAll,
    Unknown,
    SmtpError(String),
}

impl std::fmt::Display for EmailValidationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid => write!(f, "Valid"),
            Self::Invalid => write!(f, "Invalid"),
            Self::CatchAll => write!(f, "Catch-All"),
            Self::Unknown => write!(f, "Unknown"),
            Self::SmtpError(e) => write!(f, "SMTP Error: {e}"),
        }
    }
}

/// Information about a breach from HIBP-style lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachInfo {
    pub source: String,
    pub date: Option<String>,
    pub data_types: Vec<String>,
    pub is_verified: bool,
    pub password_included: bool,
}

/// Result of a HaveIBeenPwned-style password check using k-anonymity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PwnedPasswordResult {
    pub is_pwned: bool,
    pub occurrence_count: u64,
    pub sha1_prefix: String,
}

/// Generated email permutation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EmailPermutation {
    pub email: String,
    pub format_label: String,
}

/// A domain known to provide disposable email addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisposableCheckResult {
    pub domain: String,
    pub is_disposable: bool,
}

/// MX record information for an email domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MxRecord {
    pub hostname: String,
    pub priority: u16,
}

/// Full intelligence gathered on a single email address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailIntelligence {
    pub email: String,
    pub domain: String,
    pub validation_status: EmailValidationStatus,
    pub mx_records: Vec<MxRecord>,
    pub is_disposable: bool,
    pub is_free_provider: bool,
    pub breaches: Vec<BreachInfo>,
    pub pwned_password: Option<PwnedPasswordResult>,
    pub permutations: Vec<EmailPermutation>,
    pub gravatar_exists: bool,
}

/// Configuration for the email intelligence engine.
#[derive(Debug, Clone)]
pub struct EmailIntelConfig {
    pub check_breaches: bool,
    pub generate_permutations: bool,
    pub check_disposable: bool,
    pub check_gravatar: bool,
    pub timeout_secs: u64,
    pub user_agent: String,
}

impl Default for EmailIntelConfig {
    fn default() -> Self {
        Self {
            check_breaches: true,
            generate_permutations: true,
            check_disposable: true,
            check_gravatar: true,
            timeout_secs: 10,
            user_agent: "Mozilla/5.0 (compatible; OSINT-EmailIntel/1.0)".into(),
        }
    }
}

/// The main email intelligence engine.
pub struct EmailIntelligenceEngine {
    pub client: reqwest::Client,
    pub config: EmailIntelConfig,
    pub disposable_domains: HashSet<String>,
    pub free_providers: HashSet<String>,
}

impl EmailIntelligenceEngine {
    pub fn new(config: EmailIntelConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .expect("failed to build HTTP client");

        Self {
            client,
            config,
            disposable_domains: build_disposable_domains(),
            free_providers: build_free_providers(),
        }
    }

    /// Gather full intelligence on an email address.
    pub async fn investigate(&self, email: &str) -> EmailIntelligence {
        let domain = extract_domain(email);
        let is_disposable = self.config.check_disposable && self.disposable_domains.contains(&domain);
        let is_free_provider = self.free_providers.contains(&domain);

        let mx_records = self.lookup_mx(&domain).await;
        let validation_status = self.validate_via_mx(email, &mx_records).await;

        let breaches = if self.config.check_breaches {
            self.check_hibp_breaches(email).await.unwrap_or_default()
        } else {
            Vec::new()
        };

        let pwned_password = None;

        let permutations = if self.config.generate_permutations {
            generate_email_permutations(email)
        } else {
            Vec::new()
        };

        let gravatar_exists = if self.config.check_gravatar {
            self.check_gravatar(email).await
        } else {
            false
        };

        EmailIntelligence {
            email: email.to_string(),
            domain,
            validation_status,
            mx_records,
            is_disposable,
            is_free_provider,
            breaches,
            pwned_password,
            permutations,
            gravatar_exists,
        }
    }

    /// Check if a password has been seen in breaches using HIBP k-anonymity API.
    pub async fn check_pwned_password(&self, password: &str) -> Result<PwnedPasswordResult, String> {
        let sha1_full = sha1_hex(password);
        let prefix = &sha1_full[..5];
        let suffix = &sha1_full[5..];

        let url = format!("https://api.pwnedpasswords.com/range/{prefix}");
        let resp = self.client.get(&url).send().await.map_err(|e| e.to_string())?;
        let body = resp.text().await.map_err(|e| e.to_string())?;

        let suffix_upper = suffix.to_uppercase();
        let mut count = 0u64;
        let mut found = false;

        for line in body.lines() {
            if let Some((hash_suffix, cnt)) = line.split_once(':') {
                if hash_suffix.trim().eq_ignore_ascii_case(&suffix_upper) {
                    count = cnt.trim().parse().unwrap_or(0);
                    found = true;
                    break;
                }
            }
        }

        Ok(PwnedPasswordResult {
            is_pwned: found,
            occurrence_count: count,
            sha1_prefix: prefix.to_string(),
        })
    }

    async fn lookup_mx(&self, domain: &str) -> Vec<MxRecord> {
        let url = format!("https://dns.google/resolve?name={domain}&type=MX");
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_str(&self.config.user_agent)
            .unwrap_or_else(|_| HeaderValue::from_static("Mozilla/5.0")));

        let resp = match self.client.get(&url).headers(headers).send().await {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        let json: serde_json::Value = match resp.json().await {
            Ok(j) => j,
            Err(_) => return Vec::new(),
        };

        let answers = match json.get("Answer").and_then(|a| a.as_array()) {
            Some(a) => a,
            None => return Vec::new(),
        };

        let mut records: Vec<MxRecord> = answers
            .iter()
            .filter_map(|entry| {
                let data = entry.get("data")?.as_str()?;
                let parts: Vec<&str> = data.split_whitespace().collect();
                if parts.len() >= 2 {
                    let priority: u16 = parts[0].parse().ok()?;
                    let hostname = parts[1].trim_end_matches('.').to_string();
                    Some(MxRecord { hostname, priority })
                } else {
                    None
                }
            })
            .collect();

        records.sort_by_key(|r| r.priority);
        records
    }

    async fn validate_via_mx(&self, _email: &str, mx_records: &[MxRecord]) -> EmailValidationStatus {
        if mx_records.is_empty() {
            return EmailValidationStatus::Unknown;
        }
        EmailValidationStatus::Unknown
    }

    async fn check_hibp_breaches(&self, email: &str) -> Result<Vec<BreachInfo>, String> {
        let encoded = url::form_urlencoded::byte_serialize(email.as_bytes()).collect::<String>();
        let url = format!("https://haveibeenpwned.com/api/v3/breachedaccount/{encoded}?truncateResponse=false");
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_str(&self.config.user_agent)
            .unwrap_or_else(|_| HeaderValue::from_static("Mozilla/5.0")));

        let resp = match self.client.get(&url).headers(headers).send().await {
            Ok(r) => r,
            Err(e) => return Err(e.to_string()),
        };

        if resp.status().as_u16() == 404 {
            return Ok(Vec::new());
        }

        if resp.status().as_u16() == 401 {
            return Err("HIBP API requires an API key for breach lookups".to_string());
        }

        let json: Vec<serde_json::Value> = match resp.json().await {
            Ok(j) => j,
            Err(e) => return Err(e.to_string()),
        };

        Ok(json
            .iter()
            .map(|entry| {
                let data_types = entry
                    .get("DataClasses")
                    .and_then(|d| d.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default();

                BreachInfo {
                    source: entry.get("Name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    date: entry.get("BreachDate").and_then(|v| v.as_str()).map(String::from),
                    data_types,
                    is_verified: entry.get("IsVerified").and_then(|v| v.as_bool()).unwrap_or(false),
                    password_included: entry
                        .get("DataClasses")
                        .and_then(|d| d.as_array())
                        .map(|arr| arr.iter().any(|v| v.as_str().map_or(false, |s| s == "Passwords")))
                        .unwrap_or(false),
                }
            })
            .collect())
    }

    async fn check_gravatar(&self, email: &str) -> bool {
        let hash = md5_hex(email.trim().to_lowercase().as_str());
        let url = format!("https://en.gravatar.com/{hash}.json");
        match self.client.get(&url).send().await {
            Ok(resp) => resp.status().as_u16() == 200,
            Err(_) => false,
        }
    }
}

/// Generate all common email permutations from a given email address.
pub fn generate_email_permutations(email: &str) -> Vec<EmailPermutation> {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return Vec::new();
    }
    let local = parts[0];
    let domain = parts[1];

    let (first, last) = guess_name_from_local(local);

    let mut perms = Vec::new();

    if let (Some(f), Some(l)) = (&first, &last) {
        let fl = f.to_lowercase();
        let ll = l.to_lowercase();
        let fi = &fl[..1.min(fl.len())];
        let li = &ll[..1.min(ll.len())];

        let formats: Vec<(&str, String)> = vec![
            ("first.last", format!("{fl}.{ll}@{domain}")),
            ("last.first", format!("{ll}.{fl}@{domain}")),
            ("firstlast", format!("{fl}{ll}@{domain}")),
            ("lastfirst", format!("{ll}{fl}@{domain}")),
            ("f.last", format!("{fi}.{ll}@{domain}")),
            ("first.l", format!("{fl}.{li}@{domain}")),
            ("flast", format!("{fi}{ll}@{domain}")),
            ("firstl", format!("{fl}{li}@{domain}")),
            ("first_last", format!("{fl}_{ll}@{domain}")),
            ("first-last", format!("{fl}-{ll}@{domain}")),
            ("last_first", format!("{ll}_{fl}@{domain}")),
            ("first", format!("{fl}@{domain}")),
            ("last", format!("{ll}@{domain}")),
        ];

        for (label, addr) in formats {
            if addr != email {
                perms.push(EmailPermutation {
                    email: addr,
                    format_label: label.to_string(),
                });
            }
        }
    }

    perms
}

/// Attempt to split a local part into first/last name components.
pub fn guess_name_from_local(local: &str) -> (Option<String>, Option<String>) {
    let separators = ['.', '_', '-'];
    for sep in &separators {
        if local.contains(*sep) {
            let parts: Vec<&str> = local.splitn(2, *sep).collect();
            if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
                return (Some(parts[0].to_string()), Some(parts[1].to_string()));
            }
        }
    }

    if local.len() >= 4 {
        let chars: Vec<char> = local.chars().collect();
        for i in 1..chars.len() {
            if chars[i].is_uppercase() {
                let first: String = chars[..i].iter().collect();
                let last: String = chars[i..].iter().collect();
                return (Some(first), Some(last));
            }
        }
    }

    (None, None)
}

/// Extract the domain part from an email address.
pub fn extract_domain(email: &str) -> String {
    email
        .split('@')
        .nth(1)
        .unwrap_or("")
        .to_lowercase()
}

/// SHA-1 hex digest (for HIBP k-anonymity).
pub fn sha1_hex(input: &str) -> String {
    use std::fmt::Write;
    let mut hasher = Sha1State::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(40);
    for byte in &digest {
        write!(hex, "{:02X}", byte).unwrap();
    }
    hex
}

/// MD5 hex digest (for Gravatar).
pub fn md5_hex(input: &str) -> String {
    use std::fmt::Write;
    let digest = md5_hash(input.as_bytes());
    let mut hex = String::with_capacity(32);
    for byte in &digest {
        write!(hex, "{:02x}", byte).unwrap();
    }
    hex
}

/// Minimal SHA-1 implementation for k-anonymity prefix matching.
struct Sha1State {
    h: [u32; 5],
    data: Vec<u8>,
}

impl Sha1State {
    fn new() -> Self {
        Self {
            h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            data: Vec::new(),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    fn finalize(mut self) -> [u8; 20] {
        let bit_len = (self.data.len() as u64) * 8;
        self.data.push(0x80);
        while self.data.len() % 64 != 56 {
            self.data.push(0);
        }
        self.data.extend_from_slice(&bit_len.to_be_bytes());

        for chunk in self.data.chunks_exact(64) {
            let mut w = [0u32; 80];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    chunk[i * 4],
                    chunk[i * 4 + 1],
                    chunk[i * 4 + 2],
                    chunk[i * 4 + 3],
                ]);
            }
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }

            let (mut a, mut b, mut c, mut d, mut e) =
                (self.h[0], self.h[1], self.h[2], self.h[3], self.h[4]);

            for i in 0..80 {
                let (f, k) = match i {
                    0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                    20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                    _ => (b ^ c ^ d, 0xCA62C1D6u32),
                };
                let temp = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(w[i]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }

            self.h[0] = self.h[0].wrapping_add(a);
            self.h[1] = self.h[1].wrapping_add(b);
            self.h[2] = self.h[2].wrapping_add(c);
            self.h[3] = self.h[3].wrapping_add(d);
            self.h[4] = self.h[4].wrapping_add(e);
        }

        let mut result = [0u8; 20];
        for (i, h) in self.h.iter().enumerate() {
            result[i * 4..i * 4 + 4].copy_from_slice(&h.to_be_bytes());
        }
        result
    }
}

/// Minimal MD5 implementation for Gravatar hash.
fn md5_hash(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    let mut data = input.to_vec();
    let bit_len = (input.len() as u64) * 8;
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_le_bytes());

    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    for chunk in data.chunks_exact(64) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }

        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&a0.to_le_bytes());
    result[4..8].copy_from_slice(&b0.to_le_bytes());
    result[8..12].copy_from_slice(&c0.to_le_bytes());
    result[12..16].copy_from_slice(&d0.to_le_bytes());
    result
}

pub fn build_disposable_domains() -> HashSet<String> {
    let domains = [
        "mailinator.com", "guerrillamail.com", "tempmail.com", "throwaway.email",
        "yopmail.com", "10minutemail.com", "trashmail.com", "fakeinbox.com",
        "sharklasers.com", "guerrillamailblock.com", "grr.la", "dispostable.com",
        "mailnesia.com", "maildrop.cc", "discard.email", "tempr.email",
        "temp-mail.org", "emailondeck.com", "getnada.com", "mohmal.com",
        "harakirimail.com", "burner.kiwi", "guerrillamail.info", "jetable.org",
        "mailcatch.com", "meltmail.com", "mytemp.email", "spamgourmet.com",
        "safetymail.info", "trashmail.me", "getairmail.com", "mailnull.com",
        "tempail.com", "tempmailaddress.com", "disposableemailaddress.com",
        "33mail.com", "mailsac.com", "inboxbear.com", "tempmailo.com",
        "minutemail.com", "temp-mail.io", "emailfake.com", "guerrillamail.de",
        "crazymailing.com", "tempinbox.com", "armyspy.com", "fleckens.hu",
        "dayrep.com", "superrito.com", "teleworm.us",
    ];
    domains.iter().map(|d| d.to_string()).collect()
}

pub fn build_free_providers() -> HashSet<String> {
    let providers = [
        "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
        "icloud.com", "mail.com", "protonmail.com", "proton.me", "zoho.com",
        "yandex.com", "gmx.com", "gmx.net", "tutanota.com", "tuta.com",
        "fastmail.com", "hushmail.com", "live.com", "msn.com", "me.com",
        "mac.com", "yahoo.co.uk", "yahoo.co.jp", "mail.ru", "163.com",
        "qq.com", "naver.com", "daum.net", "web.de", "t-online.de",
    ];
    providers.iter().map(|p| p.to_string()).collect()
}

/// Errors from the email intelligence engine.
#[derive(Debug, Clone)]
pub enum EmailIntelError {
    InvalidEmail(String),
    Network(String),
    ApiError(String),
}

impl std::fmt::Display for EmailIntelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEmail(e) => write!(f, "Invalid email: {e}"),
            Self::Network(e) => write!(f, "Network error: {e}"),
            Self::ApiError(e) => write!(f, "API error: {e}"),
        }
    }
}

impl std::error::Error for EmailIntelError {}
