use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetValidationError {
    NonLocalhostTarget { host: String },
    InvalidUrl { url: String },
}

impl std::fmt::Display for TargetValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonLocalhostTarget { host } => {
                write!(f, "target host is not localhost: {host}")
            }
            Self::InvalidUrl { url } => {
                write!(f, "invalid URL: {url}")
            }
        }
    }
}

impl std::error::Error for TargetValidationError {}

pub fn validate_target_is_localhost(url: &str) -> Result<(), TargetValidationError> {
    if url.is_empty() {
        return Err(TargetValidationError::InvalidUrl {
            url: url.to_string(),
        });
    }

    let (parsed, effective_input) =
        parse_url(url).ok_or_else(|| TargetValidationError::InvalidUrl {
            url: url.to_string(),
        })?;

    let host = parsed
        .host_str()
        .ok_or_else(|| TargetValidationError::InvalidUrl {
            url: url.to_string(),
        })?;

    if !is_allowed_localhost(host) {
        return Err(TargetValidationError::NonLocalhostTarget {
            host: host.to_string(),
        });
    }

    reject_obfuscated_host(&effective_input, host)
}

/// Parse a URL, prepending `http://` for schemeless inputs.
///
/// Returns the parsed URL and the effective input string used for parsing.
/// Falls back to prefixed parsing when the input lacks a recognized scheme
/// (e.g. `localhost:8080` where `Url::parse` misinterprets `localhost` as a scheme).
fn parse_url(url: &str) -> Option<(Url, String)> {
    if let Ok(parsed) = Url::parse(url)
        && parsed.host_str().is_some()
    {
        return Some((parsed, url.to_string()));
    }
    let prefixed = format!("http://{url}");
    Url::parse(&prefixed).ok().map(|p| (p, prefixed))
}

fn is_allowed_localhost(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    matches!(lower.as_str(), "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// Reject URLs where the original host text doesn't match the canonical form.
///
/// The `url` crate normalizes hex/octal/decimal/shortened IP encodings
/// (e.g. `0x7f000001` -> `127.0.0.1`). These obfuscated forms are SSRF bypass
/// techniques and must be rejected even though they resolve to localhost.
fn reject_obfuscated_host(
    effective_input: &str,
    normalized_host: &str,
) -> Result<(), TargetValidationError> {
    let raw_host = extract_raw_host(effective_input);
    let raw_lower = raw_host.to_ascii_lowercase();
    let normalized_lower = normalized_host.to_ascii_lowercase();

    if raw_lower == normalized_lower {
        return Ok(());
    }

    Err(TargetValidationError::NonLocalhostTarget {
        host: raw_host.to_string(),
    })
}

/// Extract the raw host text from a URL string that has a scheme.
///
/// Expects input in the form `scheme://[user@]host[:port][/path]`.
fn extract_raw_host(url: &str) -> &str {
    let after_scheme = url.find("://").map(|i| &url[i + 3..]).unwrap_or(url);

    let after_userinfo = if let Some(at_pos) = after_scheme.find('@') {
        let before_at = &after_scheme[..at_pos];
        if !before_at.contains('/') && !before_at.contains('[') {
            &after_scheme[at_pos + 1..]
        } else {
            after_scheme
        }
    } else {
        after_scheme
    };

    if after_userinfo.starts_with('[') {
        let bracket_end = after_userinfo.find(']').unwrap_or(after_userinfo.len());
        &after_userinfo[..=bracket_end]
    } else {
        let end = after_userinfo
            .find([':', '/', '?', '#'])
            .unwrap_or(after_userinfo.len());
        &after_userinfo[..end]
    }
}
