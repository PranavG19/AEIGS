use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum SensitiveFileIssue {
    GitExposed,
    EnvFileExposed,
    DsStoreExposed,
    HtaccessExposed,
    ServerStatusExposed,
    PhpInfoExposed,
}

impl std::fmt::Display for SensitiveFileIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GitExposed => write!(f, "git_repo_exposed"),
            Self::EnvFileExposed => write!(f, "env_file_exposed"),
            Self::DsStoreExposed => write!(f, "ds_store_exposed"),
            Self::HtaccessExposed => write!(f, "htaccess_exposed"),
            Self::ServerStatusExposed => write!(f, "server_status_exposed"),
            Self::PhpInfoExposed => write!(f, "phpinfo_exposed"),
        }
    }
}

struct Probe {
    path: &'static str,
    validator: fn(&str) -> bool,
    issue: SensitiveFileIssue,
}

const PROBES: &[Probe] = &[
    Probe {
        path: ".git/HEAD",
        validator: validate_git_head,
        issue: SensitiveFileIssue::GitExposed,
    },
    Probe {
        path: ".env",
        validator: validate_env_file,
        issue: SensitiveFileIssue::EnvFileExposed,
    },
    Probe {
        path: ".DS_Store",
        validator: validate_ds_store,
        issue: SensitiveFileIssue::DsStoreExposed,
    },
    Probe {
        path: ".htaccess",
        validator: validate_htaccess,
        issue: SensitiveFileIssue::HtaccessExposed,
    },
    Probe {
        path: "server-status",
        validator: validate_server_status,
        issue: SensitiveFileIssue::ServerStatusExposed,
    },
    Probe {
        path: "phpinfo.php",
        validator: validate_phpinfo,
        issue: SensitiveFileIssue::PhpInfoExposed,
    },
];

pub fn audit_sensitive_files(target: &str) -> Vec<SensitiveFileIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };

    let base = target.trim_end_matches('/');
    let mut issues = Vec::new();

    for probe in PROBES {
        let url = format!("{base}/{}", probe.path);
        if let Ok(resp) = client.get(&url).send()
            && resp.status().as_u16() == 200
            && let Ok(body) = resp.text()
            && (probe.validator)(&body)
        {
            issues.push(probe.issue.clone());
        }
    }

    issues
}

const fn validate_git_head(body: &str) -> bool {
    // Valid .git/HEAD starts with "ref: refs/" or is a raw SHA hash
    body.len() < 256
        && (const_starts_with(body.as_bytes(), b"ref: refs/")
            || (body.len() >= 40 && is_hex_prefix(body.as_bytes())))
}

const fn const_starts_with(haystack: &[u8], needle: &[u8]) -> bool {
    if haystack.len() < needle.len() {
        return false;
    }
    let mut i = 0;
    while i < needle.len() {
        if haystack[i] != needle[i] {
            return false;
        }
        i += 1;
    }
    true
}

const fn is_hex_prefix(bytes: &[u8]) -> bool {
    let mut i = 0;
    let limit = if bytes.len() < 40 { bytes.len() } else { 40 };
    while i < limit {
        let b = bytes[i];
        if !((b >= b'0' && b <= b'9') || (b >= b'a' && b <= b'f') || (b >= b'A' && b <= b'F')) {
            return false;
        }
        i += 1;
    }
    true
}

fn validate_env_file(body: &str) -> bool {
    if body.len() > 100_000 {
        return false;
    }
    let env_markers = [
        "DB_PASSWORD",
        "DB_HOST",
        "SECRET_KEY",
        "API_KEY",
        "AWS_ACCESS",
        "DATABASE_URL",
        "REDIS_URL",
        "SMTP_",
        "MAIL_",
        "APP_KEY",
    ];
    let has_assignments = body.lines().any(|l| {
        let trimmed = l.trim();
        !trimmed.is_empty()
            && !trimmed.starts_with('#')
            && trimmed.contains('=')
            && trimmed.split('=').next().is_some_and(|k| {
                let k = k.trim();
                !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            })
    });
    let has_marker = env_markers.iter().any(|m| body.contains(m));
    has_assignments && has_marker
}

fn validate_ds_store(body: &str) -> bool {
    body.len() >= 8 && body.contains("Bud1")
}

fn validate_htaccess(body: &str) -> bool {
    let markers = [
        "RewriteEngine",
        "RewriteRule",
        "RewriteCond",
        "Order ",
        "Deny from",
        "Allow from",
        "AuthType",
        "Require ",
        "DirectoryIndex",
    ];
    markers.iter().any(|m| body.contains(m))
}

fn validate_server_status(body: &str) -> bool {
    body.contains("Apache Server Status") || body.contains("Server uptime:")
}

fn validate_phpinfo(body: &str) -> bool {
    body.contains("phpinfo()") || body.contains("PHP Version")
}

#[cfg(test)]
pub(crate) fn analyze_sensitive_file(body: &str, probe_index: usize) -> bool {
    PROBES.get(probe_index).is_some_and(|p| (p.validator)(body))
}

#[cfg(test)]
pub(crate) fn probe_count() -> usize {
    PROBES.len()
}

pub(crate) fn sensitive_file_severity(issue: &SensitiveFileIssue) -> f64 {
    match issue {
        SensitiveFileIssue::EnvFileExposed => 9.0,
        SensitiveFileIssue::GitExposed => 8.0,
        SensitiveFileIssue::PhpInfoExposed => 6.0,
        SensitiveFileIssue::ServerStatusExposed => 5.5,
        SensitiveFileIssue::HtaccessExposed => 5.0,
        SensitiveFileIssue::DsStoreExposed => 3.0,
    }
}

pub fn sensitive_file_to_operations(
    issues: &[SensitiveFileIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                sensitive_file_severity(issue),
                0.95,
            )
        })
        .collect()
}
