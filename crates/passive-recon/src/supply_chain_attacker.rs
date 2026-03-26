use std::collections::HashMap;
use std::fmt;

/// Attack vector for supply chain compromise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SupplyChainAttackVector {
    AbandonedMaintainer,
    ExpiredDomain,
    Typosquatting,
    DependencyConfusion,
    MaliciousUpdate,
    CompromisedBuildSystem,
    NamespaceHijack,
    StarjackingRepo,
}

impl fmt::Display for SupplyChainAttackVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AbandonedMaintainer => write!(f, "Abandoned Maintainer"),
            Self::ExpiredDomain => write!(f, "Expired Domain"),
            Self::Typosquatting => write!(f, "Typosquatting"),
            Self::DependencyConfusion => write!(f, "Dependency Confusion"),
            Self::MaliciousUpdate => write!(f, "Malicious Update"),
            Self::CompromisedBuildSystem => write!(f, "Compromised Build System"),
            Self::NamespaceHijack => write!(f, "Namespace Hijack"),
            Self::StarjackingRepo => write!(f, "Starjacking"),
        }
    }
}

/// Risk level for supply chain attack findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AttackRisk {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for AttackRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// Package ecosystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PackageEcosystem {
    Npm,
    PyPi,
    RubyGems,
    CratesIo,
    Maven,
    NuGet,
    Go,
    Packagist,
}

impl fmt::Display for PackageEcosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Npm => write!(f, "npm"),
            Self::PyPi => write!(f, "PyPI"),
            Self::RubyGems => write!(f, "RubyGems"),
            Self::CratesIo => write!(f, "crates.io"),
            Self::Maven => write!(f, "Maven"),
            Self::NuGet => write!(f, "NuGet"),
            Self::Go => write!(f, "Go"),
            Self::Packagist => write!(f, "Packagist"),
        }
    }
}

/// Maintainer status for a package.
#[derive(Debug, Clone, PartialEq)]
pub struct MaintainerStatus {
    pub package_name: String,
    pub ecosystem: PackageEcosystem,
    pub maintainer_email: Option<String>,
    pub last_publish_days_ago: u64,
    pub total_downloads: u64,
    pub is_abandoned: bool,
    pub abandonment_signals: Vec<String>,
    pub risk: AttackRisk,
}

/// Expired domain finding.
#[derive(Debug, Clone, PartialEq)]
pub struct ExpiredDomainFinding {
    pub domain: String,
    pub associated_package: String,
    pub ecosystem: PackageEcosystem,
    pub domain_status: DomainStatus,
    pub registrar: Option<String>,
    pub expiry_date: Option<String>,
    pub risk: AttackRisk,
}

/// Domain registration status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainStatus {
    Active,
    Expired,
    PendingDelete,
    Redeemable,
    Available,
    Unknown,
}

impl fmt::Display for DomainStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Expired => write!(f, "Expired"),
            Self::PendingDelete => write!(f, "Pending Delete"),
            Self::Redeemable => write!(f, "Redeemable"),
            Self::Available => write!(f, "Available"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Typosquat candidate.
#[derive(Debug, Clone, PartialEq)]
pub struct TyposquatCandidate {
    pub original_name: String,
    pub squatted_name: String,
    pub technique: TyposquatTechnique,
    pub edit_distance: usize,
    pub similarity_score: f64,
    pub ecosystem: PackageEcosystem,
    pub exists_in_registry: bool,
    pub risk: AttackRisk,
}

/// Typosquatting technique used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TyposquatTechnique {
    CharacterSwap,
    CharacterOmission,
    CharacterInsertion,
    CharacterSubstitution,
    HyphenManipulation,
    HomoglyphAttack,
    ScopeConfusion,
    PluralSingular,
    CommonMisspelling,
}

impl fmt::Display for TyposquatTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CharacterSwap => write!(f, "Character Swap"),
            Self::CharacterOmission => write!(f, "Character Omission"),
            Self::CharacterInsertion => write!(f, "Character Insertion"),
            Self::CharacterSubstitution => write!(f, "Character Substitution"),
            Self::HyphenManipulation => write!(f, "Hyphen Manipulation"),
            Self::HomoglyphAttack => write!(f, "Homoglyph Attack"),
            Self::ScopeConfusion => write!(f, "Scope Confusion"),
            Self::PluralSingular => write!(f, "Plural/Singular"),
            Self::CommonMisspelling => write!(f, "Common Misspelling"),
        }
    }
}

/// Full supply chain attack report.
#[derive(Debug, Clone, PartialEq)]
pub struct SupplyChainAttackReport {
    pub target_packages: Vec<String>,
    pub abandoned_maintainers: Vec<MaintainerStatus>,
    pub expired_domains: Vec<ExpiredDomainFinding>,
    pub typosquat_candidates: Vec<TyposquatCandidate>,
    pub risk_summary: HashMap<AttackRisk, usize>,
    pub overall_risk: AttackRisk,
    pub total_findings: usize,
}

/// Checks if a package appears abandoned based on publish age and signals.
pub fn check_maintainer_abandonment(
    package_name: &str,
    ecosystem: PackageEcosystem,
    last_publish_days_ago: u64,
    total_downloads: u64,
    maintainer_email: Option<&str>,
    open_issues: u64,
    open_prs: u64,
) -> MaintainerStatus {
    let mut signals = Vec::new();
    let mut risk = AttackRisk::Low;

    if last_publish_days_ago > 730 {
        signals.push(format!("No updates in {} days", last_publish_days_ago));
        risk = AttackRisk::High;
    } else if last_publish_days_ago > 365 {
        signals.push(format!("No updates in {} days", last_publish_days_ago));
        risk = AttackRisk::Medium;
    }

    if open_issues > 50 {
        signals.push(format!("{} open issues unaddressed", open_issues));
        if risk < AttackRisk::Medium {
            risk = AttackRisk::Medium;
        }
    }

    if open_prs > 20 {
        signals.push(format!("{} open PRs unmerged", open_prs));
        if risk < AttackRisk::Medium {
            risk = AttackRisk::Medium;
        }
    }

    if total_downloads > 1_000_000 && last_publish_days_ago > 365 {
        signals.push("High-download package with stale maintenance".to_string());
        risk = AttackRisk::Critical;
    }

    if let Some(email) = maintainer_email {
        if email.contains("noreply") || email.contains("defunct") {
            signals.push("Maintainer email appears inactive".to_string());
            if risk < AttackRisk::Medium {
                risk = AttackRisk::Medium;
            }
        }
    }

    let is_abandoned = last_publish_days_ago > 365 && !signals.is_empty();

    MaintainerStatus {
        package_name: package_name.to_string(),
        ecosystem,
        maintainer_email: maintainer_email.map(String::from),
        last_publish_days_ago,
        total_downloads,
        is_abandoned,
        abandonment_signals: signals,
        risk,
    }
}

/// Checks if a domain associated with a package is expired or available.
pub fn check_domain_expiry(
    domain: &str,
    package_name: &str,
    ecosystem: PackageEcosystem,
    whois_text: &str,
) -> ExpiredDomainFinding {
    let lower = whois_text.to_lowercase();

    let domain_status =
        if lower.contains("no match") || lower.contains("not found") || lower.contains("available")
        {
            DomainStatus::Available
        } else if lower.contains("pendingdelete") || lower.contains("pending delete") {
            DomainStatus::PendingDelete
        } else if lower.contains("redemptionperiod") || lower.contains("redemption period") {
            DomainStatus::Redeemable
        } else if lower.contains("expired") {
            DomainStatus::Expired
        } else if lower.contains("registrar") {
            DomainStatus::Active
        } else {
            DomainStatus::Unknown
        };

    let registrar = extract_whois_field(whois_text, "Registrar");
    let expiry_date = extract_whois_field(whois_text, "Expiry Date")
        .or_else(|| extract_whois_field(whois_text, "Registry Expiry Date"))
        .or_else(|| extract_whois_field(whois_text, "Expiration Date"));

    let risk = match domain_status {
        DomainStatus::Available => AttackRisk::Critical,
        DomainStatus::PendingDelete => AttackRisk::Critical,
        DomainStatus::Redeemable => AttackRisk::High,
        DomainStatus::Expired => AttackRisk::High,
        DomainStatus::Active => AttackRisk::Low,
        DomainStatus::Unknown => AttackRisk::Medium,
    };

    ExpiredDomainFinding {
        domain: domain.to_string(),
        associated_package: package_name.to_string(),
        ecosystem,
        domain_status,
        registrar,
        expiry_date,
        risk,
    }
}

/// Extracts a field value from WHOIS text.
fn extract_whois_field(whois_text: &str, field_name: &str) -> Option<String> {
    for line in whois_text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(field_name) {
            let rest = rest.trim_start_matches(':').trim();
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
    }
    None
}

/// Generates typosquat candidates for a package name.
pub fn generate_typosquats(
    package_name: &str,
    ecosystem: PackageEcosystem,
) -> Vec<TyposquatCandidate> {
    let mut candidates = Vec::new();
    let chars: Vec<char> = package_name.chars().collect();

    for i in 0..chars.len().saturating_sub(1) {
        let mut swapped = chars.clone();
        swapped.swap(i, i + 1);
        let name: String = swapped.into_iter().collect();
        if name != package_name {
            candidates.push(build_candidate(
                package_name,
                &name,
                TyposquatTechnique::CharacterSwap,
                ecosystem,
            ));
        }
    }

    for i in 0..chars.len() {
        let name: String = chars
            .iter()
            .enumerate()
            .filter(|&(j, _)| j != i)
            .map(|(_, &c)| c)
            .collect();
        if name.len() >= 2 {
            candidates.push(build_candidate(
                package_name,
                &name,
                TyposquatTechnique::CharacterOmission,
                ecosystem,
            ));
        }
    }

    if package_name.contains('-') {
        let no_hyphen = package_name.replace('-', "");
        candidates.push(build_candidate(
            package_name,
            &no_hyphen,
            TyposquatTechnique::HyphenManipulation,
            ecosystem,
        ));
        let underscore = package_name.replace('-', "_");
        candidates.push(build_candidate(
            package_name,
            &underscore,
            TyposquatTechnique::HyphenManipulation,
            ecosystem,
        ));
    }

    if package_name.ends_with('s') {
        let singular = &package_name[..package_name.len() - 1];
        candidates.push(build_candidate(
            package_name,
            singular,
            TyposquatTechnique::PluralSingular,
            ecosystem,
        ));
    } else {
        let plural = format!("{}s", package_name);
        candidates.push(build_candidate(
            package_name,
            &plural,
            TyposquatTechnique::PluralSingular,
            ecosystem,
        ));
    }

    let homoglyphs: &[(&str, &str)] = &[
        ("o", "0"),
        ("l", "1"),
        ("i", "1"),
        ("e", "3"),
        ("a", "4"),
        ("s", "5"),
        ("rn", "m"),
    ];
    for &(original, replacement) in homoglyphs {
        if package_name.contains(original) {
            let squatted = package_name.replacen(original, replacement, 1);
            candidates.push(build_candidate(
                package_name,
                &squatted,
                TyposquatTechnique::HomoglyphAttack,
                ecosystem,
            ));
        }
    }

    candidates
}

/// Computes edit distance between two strings.
pub fn edit_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let m = a_chars.len();
    let n = b_chars.len();

    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 0..=m {
        dp[i][0] = i;
    }
    for j in 0..=n {
        dp[0][j] = j;
    }

    for i in 1..=m {
        for j in 1..=n {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };
            dp[i][j] = (dp[i - 1][j] + 1)
                .min(dp[i][j - 1] + 1)
                .min(dp[i - 1][j - 1] + cost);
        }
    }

    dp[m][n]
}

/// Computes similarity score (0.0 to 1.0) between two strings.
pub fn similarity_score(a: &str, b: &str) -> f64 {
    let dist = edit_distance(a, b);
    let max_len = a.len().max(b.len());
    if max_len == 0 {
        return 1.0;
    }
    1.0 - (dist as f64 / max_len as f64)
}

fn build_candidate(
    original: &str,
    squatted: &str,
    technique: TyposquatTechnique,
    ecosystem: PackageEcosystem,
) -> TyposquatCandidate {
    let dist = edit_distance(original, squatted);
    let sim = similarity_score(original, squatted);

    let risk = if sim > 0.9 {
        AttackRisk::High
    } else if sim > 0.7 {
        AttackRisk::Medium
    } else {
        AttackRisk::Low
    };

    TyposquatCandidate {
        original_name: original.to_string(),
        squatted_name: squatted.to_string(),
        technique,
        edit_distance: dist,
        similarity_score: sim,
        ecosystem,
        exists_in_registry: false,
        risk,
    }
}

/// Builds a full supply chain attack report.
pub fn build_attack_report(
    target_packages: Vec<String>,
    abandoned: Vec<MaintainerStatus>,
    expired: Vec<ExpiredDomainFinding>,
    typosquats: Vec<TyposquatCandidate>,
) -> SupplyChainAttackReport {
    let mut risk_summary: HashMap<AttackRisk, usize> = HashMap::new();

    for m in &abandoned {
        *risk_summary.entry(m.risk).or_insert(0) += 1;
    }
    for e in &expired {
        *risk_summary.entry(e.risk).or_insert(0) += 1;
    }
    for t in &typosquats {
        *risk_summary.entry(t.risk).or_insert(0) += 1;
    }

    let total = abandoned.len() + expired.len() + typosquats.len();
    let overall_risk = risk_summary
        .keys()
        .max()
        .copied()
        .unwrap_or(AttackRisk::Low);

    SupplyChainAttackReport {
        target_packages,
        abandoned_maintainers: abandoned,
        expired_domains: expired,
        typosquat_candidates: typosquats,
        risk_summary,
        overall_risk,
        total_findings: total,
    }
}
