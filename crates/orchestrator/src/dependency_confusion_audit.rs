use std::collections::HashSet;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum DepConfusionIssue {
    InternalScopedPackage { scope: String },
    PrivateRegistryUrl { url: String },
    LockfileExposed { path: String },
    InternalPackageName { name: String },
}

impl std::fmt::Display for DepConfusionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InternalScopedPackage { scope } => {
                write!(f, "internal_scope:{scope}")
            }
            Self::PrivateRegistryUrl { url } => write!(f, "private_registry:{url}"),
            Self::LockfileExposed { path } => write!(f, "lockfile_exposed:{path}"),
            Self::InternalPackageName { name } => write!(f, "internal_package:{name}"),
        }
    }
}

const PRIVATE_REGISTRY_PATTERNS: &[&str] = &[
    "registry.npmjs.org",
    "npm.pkg.github.com",
    "registry.yarnpkg.com",
    ".jfrog.io",
    "artifactory",
    "nexus",
    "verdaccio",
    "npm.fontawesome.com",
    "npm.greensock.com",
    "registry.npmmirror.com",
];

const LOCKFILE_PATHS: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "shrinkwrap.json",
    "npm-shrinkwrap.json",
    "composer.lock",
    "Gemfile.lock",
    "Pipfile.lock",
    "poetry.lock",
    "cargo.lock",
    "go.sum",
    "requirements.txt",
];

const INTERNAL_NAME_PATTERNS: &[&str] = &[
    "-internal",
    "-private",
    "-core-lib",
    "-shared-lib",
    "-platform-",
    "-infra-",
    "-common-lib",
];

pub fn audit_dependency_confusion(target: &str) -> Vec<DepConfusionIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    analyze_dependency_confusion(&body)
}

pub fn analyze_dependency_confusion(body: &str) -> Vec<DepConfusionIssue> {
    let mut issues = Vec::new();
    let mut seen_scopes = HashSet::new();

    find_scoped_packages(body, &mut issues, &mut seen_scopes);
    find_private_registries(body, &mut issues);
    find_lockfile_references(body, &mut issues);
    find_internal_package_names(body, &mut issues);

    issues
}

fn find_scoped_packages(
    body: &str,
    issues: &mut Vec<DepConfusionIssue>,
    seen: &mut HashSet<String>,
) {
    let mut pos = 0;
    while let Some(idx) = body[pos..].find("@") {
        let abs = pos + idx;
        if abs > 0 {
            let prev = body.as_bytes()[abs - 1];
            if prev != b'"' && prev != b'\'' && prev != b'/' && prev != b' ' && prev != b'\n' {
                pos = abs + 1;
                continue;
            }
        }

        let rest = &body[abs + 1..];
        let end = rest
            .find(|c: char| !c.is_alphanumeric() && c != '-' && c != '_' && c != '/')
            .unwrap_or(rest.len().min(100));
        let scope_and_pkg = &rest[..end];

        if let Some(slash_pos) = scope_and_pkg.find('/') {
            let scope = &scope_and_pkg[..slash_pos];
            if scope.len() >= 2 && !is_public_scope(scope) && seen.insert(scope.to_string()) {
                issues.push(DepConfusionIssue::InternalScopedPackage {
                    scope: format!("@{scope}"),
                });
            }
        }

        pos = abs + 1;
    }
}

fn is_public_scope(scope: &str) -> bool {
    const PUBLIC_SCOPES: &[&str] = &[
        "angular",
        "babel",
        "types",
        "typescript-eslint",
        "eslint",
        "vue",
        "react",
        "svelte",
        "nestjs",
        "next",
        "nuxt",
        "rollup",
        "vitejs",
        "testing-library",
        "storybook",
        "tailwindcss",
        "fontsource",
        "sentry",
        "aws-sdk",
        "aws-cdk",
        "azure",
        "google-cloud",
        "firebase",
        "octokit",
        "fortawesome",
        "emotion",
        "tanstack",
        "reduxjs",
        "mui",
        "radix-ui",
        "floating-ui",
        "headlessui",
        "prisma",
        "trpc",
        "hono",
        "fastify",
        "graphql-tools",
        "apollo",
    ];
    PUBLIC_SCOPES.iter().any(|s| scope.eq_ignore_ascii_case(s))
}

fn find_private_registries(body: &str, issues: &mut Vec<DepConfusionIssue>) {
    let mut seen = HashSet::new();
    for pattern in PRIVATE_REGISTRY_PATTERNS {
        if body.contains(pattern) {
            let lower = pattern.to_ascii_lowercase();
            if lower != "registry.npmjs.org"
                && lower != "registry.yarnpkg.com"
                && lower != "registry.npmmirror.com"
                && seen.insert(pattern.to_string())
            {
                issues.push(DepConfusionIssue::PrivateRegistryUrl {
                    url: pattern.to_string(),
                });
            }
        }
    }
}

fn find_lockfile_references(body: &str, issues: &mut Vec<DepConfusionIssue>) {
    let lower = body.to_ascii_lowercase();
    for &lockfile in LOCKFILE_PATHS {
        if lower.contains(lockfile) {
            issues.push(DepConfusionIssue::LockfileExposed {
                path: lockfile.to_string(),
            });
        }
    }
}

fn find_internal_package_names(body: &str, issues: &mut Vec<DepConfusionIssue>) {
    let lower = body.to_ascii_lowercase();
    let mut seen = HashSet::new();
    for &pattern in INTERNAL_NAME_PATTERNS {
        if lower.contains(pattern) && seen.insert(pattern.to_string()) {
            issues.push(DepConfusionIssue::InternalPackageName {
                name: pattern.to_string(),
            });
        }
    }
}

pub fn dep_confusion_severity(issue: &DepConfusionIssue) -> f64 {
    match issue {
        DepConfusionIssue::InternalScopedPackage { .. } => 7.0,
        DepConfusionIssue::PrivateRegistryUrl { .. } => 6.0,
        DepConfusionIssue::LockfileExposed { .. } => 5.5,
        DepConfusionIssue::InternalPackageName { .. } => 4.0,
    }
}

pub fn dep_confusion_to_operations(
    issues: &[DepConfusionIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                dep_confusion_severity(issue),
                0.65,
            )
        })
        .collect()
}
