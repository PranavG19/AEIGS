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
    let host = extract_host(url).ok_or_else(|| TargetValidationError::InvalidUrl {
        url: url.to_string(),
    })?;

    match host {
        "localhost" | "127.0.0.1" | "::1" | "[::1]" => Ok(()),
        _ => Err(TargetValidationError::NonLocalhostTarget {
            host: host.to_string(),
        }),
    }
}

fn extract_host(url: &str) -> Option<&str> {
    if url.is_empty() {
        return None;
    }

    let after_scheme = if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else {
        url
    };

    let authority = after_scheme.split('/').next()?;

    if authority.is_empty() {
        return None;
    }

    if authority.starts_with('[') {
        let bracket_end = authority.find(']')?;
        Some(&authority[..=bracket_end])
    } else {
        Some(authority.split(':').next().unwrap_or(authority))
    }
}
