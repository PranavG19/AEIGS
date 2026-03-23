use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum CacheIssue {
    MissingCacheControl,
    PublicWithoutRevalidation,
    NoNoStore,
    LongMaxAge { seconds: u64 },
    StaleWhileRevalidate { seconds: u64 },
    NoPragmaNoCache,
    VaryMissing,
    VaryWildcard,
    EtagWeakHash { etag: String },
    CacheControlConflict { directives: String },
    SensitiveHeaderCached,
}

impl std::fmt::Display for CacheIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCacheControl => write!(f, "missing_cache_control"),
            Self::PublicWithoutRevalidation => write!(f, "public_without_revalidation"),
            Self::NoNoStore => write!(f, "no_no_store"),
            Self::LongMaxAge { seconds } => write!(f, "long_max_age_{seconds}"),
            Self::StaleWhileRevalidate { seconds } => {
                write!(f, "stale_while_revalidate_{seconds}")
            }
            Self::NoPragmaNoCache => write!(f, "no_pragma_no_cache"),
            Self::VaryMissing => write!(f, "vary_missing"),
            Self::VaryWildcard => write!(f, "vary_wildcard"),
            Self::EtagWeakHash { etag } => write!(f, "etag_weak_hash_{etag}"),
            Self::CacheControlConflict { directives } => {
                write!(f, "cache_control_conflict_{directives}")
            }
            Self::SensitiveHeaderCached => write!(f, "sensitive_header_cached"),
        }
    }
}

pub fn cache_severity(issue: &CacheIssue) -> f64 {
    match issue {
        CacheIssue::MissingCacheControl => 3.0,
        CacheIssue::PublicWithoutRevalidation => 4.0,
        CacheIssue::NoNoStore => 2.5,
        CacheIssue::LongMaxAge { .. } => 2.0,
        CacheIssue::StaleWhileRevalidate { .. } => 1.5,
        CacheIssue::NoPragmaNoCache => 1.5,
        CacheIssue::VaryMissing => 2.0,
        CacheIssue::VaryWildcard => 2.5,
        CacheIssue::EtagWeakHash { .. } => 1.5,
        CacheIssue::CacheControlConflict { .. } => 3.0,
        CacheIssue::SensitiveHeaderCached => 5.0,
    }
}

pub fn audit_cache_headers(target: &str) -> Vec<CacheIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };

    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let header_pairs: Vec<(&str, String)> = resp
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            let val = value.to_str().ok()?;
            Some((name.as_str(), val.to_ascii_lowercase()))
        })
        .collect();

    let borrowed: Vec<(&str, &str)> = header_pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();

    analyze_cache_security(&borrowed)
}

pub fn analyze_cache_security(headers: &[(&str, &str)]) -> Vec<CacheIssue> {
    let mut issues = Vec::new();

    let cache_control = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("cache-control"))
        .map(|(_, val)| val.to_ascii_lowercase());

    let pragma = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("pragma"))
        .map(|(_, val)| val.to_ascii_lowercase());

    let vary = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("vary"))
        .map(|(_, val)| val.to_ascii_lowercase());

    let etag = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("etag"))
        .map(|(_, val)| val.to_string());

    let has_set_cookie = headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("set-cookie"));

    let Some(cc) = cache_control else {
        if pragma.is_none() {
            issues.push(CacheIssue::MissingCacheControl);
        }
        return issues;
    };

    if cc.contains("public") && !cc.contains("no-cache") && !cc.contains("must-revalidate") {
        issues.push(CacheIssue::PublicWithoutRevalidation);
    }

    if !cc.contains("no-store") && !cc.contains("private") {
        issues.push(CacheIssue::NoNoStore);
    }

    if let Some(seconds) = extract_directive_seconds(&cc, "max-age")
        && seconds > 31_536_000
    {
        issues.push(CacheIssue::LongMaxAge { seconds });
    }

    if let Some(seconds) = extract_directive_seconds(&cc, "stale-while-revalidate")
        && seconds > 86_400
    {
        issues.push(CacheIssue::StaleWhileRevalidate { seconds });
    }

    if (cc.contains("public") && cc.contains("private"))
        || (cc.contains("no-cache") && extract_directive_seconds(&cc, "max-age").is_some())
    {
        issues.push(CacheIssue::CacheControlConflict {
            directives: cc.clone(),
        });
    }

    if has_set_cookie && cc.contains("public") {
        issues.push(CacheIssue::SensitiveHeaderCached);
    }

    if pragma.is_none() && !cc.contains("no-cache") && !cc.contains("no-store") {
        issues.push(CacheIssue::NoPragmaNoCache);
    }

    match vary.as_deref() {
        None => issues.push(CacheIssue::VaryMissing),
        Some(v) if v.trim() == "*" => issues.push(CacheIssue::VaryWildcard),
        _ => {}
    }

    if let Some(etag_val) = etag
        && (etag_val.starts_with("W/") || etag_val.starts_with("w/"))
    {
        issues.push(CacheIssue::EtagWeakHash {
            etag: etag_val.to_string(),
        });
    }

    issues
}

pub fn cache_to_operations(issues: &[CacheIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            let vuln_class = match issue {
                CacheIssue::MissingCacheControl => VulnerabilityClass::MissingSecurityHeader,
                _ => VulnerabilityClass::SecurityMisconfiguration,
            };
            recon_client::finding_entry(seq, vuln_class, cache_severity(issue), 0.5)
        })
        .collect()
}

fn extract_directive_seconds(cc: &str, directive: &str) -> Option<u64> {
    cc.split(',')
        .map(|part| part.trim())
        .find(|part| part.starts_with(directive))
        .and_then(|part| part.split('=').nth(1))
        .and_then(|val| val.trim().parse::<u64>().ok())
}
