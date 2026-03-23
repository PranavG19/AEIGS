use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum JwtIssue {
    AlgNone,
    WeakHmac { algorithm: String },
    MissingExpClaim,
    ExposedInUrl,
    ExposedInCookie { cookie_name: String },
    SensitivePayloadData { field: String },
}

impl std::fmt::Display for JwtIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlgNone => write!(f, "jwt_alg_none"),
            Self::WeakHmac { algorithm } => write!(f, "jwt_weak_hmac:{algorithm}"),
            Self::MissingExpClaim => write!(f, "jwt_missing_exp"),
            Self::ExposedInUrl => write!(f, "jwt_exposed_in_url"),
            Self::ExposedInCookie { cookie_name } => write!(f, "jwt_in_cookie:{cookie_name}"),
            Self::SensitivePayloadData { field } => write!(f, "jwt_sensitive_data:{field}"),
        }
    }
}

const SENSITIVE_FIELDS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "credit_card",
    "ssn",
    "social_security",
];

pub fn audit_jwt_headers(target: &str) -> Vec<JwtIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client_no_redirect() else {
        return Vec::new();
    };

    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut issues = Vec::new();

    let set_cookies: Vec<String> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .collect();

    for sc in &set_cookies {
        if let Some((name, token)) = extract_jwt_from_cookie(sc) {
            issues.push(JwtIssue::ExposedInCookie {
                cookie_name: name.to_string(),
            });
            issues.extend(analyze_jwt_token(token));
        }
    }

    if let Some(auth) = resp
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        && let Some(token) = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
    {
        issues.extend(analyze_jwt_token(token.trim()));
    }

    issues
}

pub(crate) fn extract_jwt_from_cookie(set_cookie: &str) -> Option<(&str, &str)> {
    let name_value = set_cookie.split(';').next()?;
    let (name, value) = name_value.split_once('=')?;
    let name = name.trim();
    let value = value.trim();
    if is_jwt_format(value) {
        Some((name, value))
    } else {
        None
    }
}

pub(crate) fn is_jwt_format(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3
        && parts[0].len() >= 4
        && parts[1].len() >= 4
        && parts.iter().all(|p| {
            p.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
        })
}

pub(crate) fn analyze_jwt_token(token: &str) -> Vec<JwtIssue> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if let Some(header) = decode_base64url(parts[0]) {
        let header_lower = header.to_ascii_lowercase();
        if header_lower.contains("\"alg\"") && header_lower.contains("\"none\"") {
            issues.push(JwtIssue::AlgNone);
        }
        if header_lower.contains("\"hs256\"") || header_lower.contains("\"hs384\"") {
            let alg = if header_lower.contains("\"hs256\"") {
                "HS256"
            } else {
                "HS384"
            };
            issues.push(JwtIssue::WeakHmac {
                algorithm: alg.to_string(),
            });
        }
    }

    if let Some(payload) = decode_base64url(parts[1]) {
        let payload_lower = payload.to_ascii_lowercase();
        if !payload_lower.contains("\"exp\"") {
            issues.push(JwtIssue::MissingExpClaim);
        }
        for field in SENSITIVE_FIELDS {
            if payload_lower.contains(&format!("\"{field}\"")) {
                issues.push(JwtIssue::SensitivePayloadData {
                    field: field.to_string(),
                });
            }
        }
    }

    issues
}

fn decode_base64url(encoded: &str) -> Option<String> {
    let standard: String = encoded
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let padded = match standard.len() % 4 {
        2 => format!("{standard}=="),
        3 => format!("{standard}="),
        _ => standard,
    };

    let mut bytes = Vec::new();
    let chars: Vec<u8> = padded.bytes().collect();
    for chunk in chars.chunks(4) {
        if chunk.len() != 4 {
            break;
        }
        let vals: Vec<Option<u8>> = chunk.iter().map(|&b| b64_val(b)).collect();
        let a = vals[0]?;
        let b = vals[1]?;
        bytes.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            let c = vals[2]?;
            bytes.push((b << 4) | (c >> 2));
            if chunk[3] != b'=' {
                let d = vals[3]?;
                bytes.push((c << 6) | d);
            }
        }
    }
    String::from_utf8(bytes).ok()
}

fn b64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

pub(crate) fn jwt_severity(issue: &JwtIssue) -> f64 {
    match issue {
        JwtIssue::AlgNone => 9.0,
        JwtIssue::SensitivePayloadData { .. } => 7.0,
        JwtIssue::WeakHmac { .. } => 6.0,
        JwtIssue::ExposedInUrl => 5.5,
        JwtIssue::MissingExpClaim => 4.0,
        JwtIssue::ExposedInCookie { .. } => 3.0,
    }
}

pub fn jwt_header_to_operations(issues: &[JwtIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::JwtVulnerability,
                jwt_severity(issue),
                0.85,
            )
        })
        .collect()
}
