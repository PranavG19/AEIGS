use super::supply_chain_attacker::*;

#[test]
fn check_abandoned_maintainer_high_risk() {
    let status = check_maintainer_abandonment(
        "old-package",
        PackageEcosystem::Npm,
        800,
        50_000,
        Some("dev@example.com"),
        60,
        25,
    );
    assert!(status.is_abandoned);
    assert_eq!(status.risk, AttackRisk::High);
    assert!(!status.abandonment_signals.is_empty());
}

#[test]
fn check_abandoned_maintainer_critical_high_downloads() {
    let status = check_maintainer_abandonment(
        "popular-lib",
        PackageEcosystem::Npm,
        400,
        2_000_000,
        None,
        10,
        5,
    );
    assert!(status.is_abandoned);
    assert_eq!(status.risk, AttackRisk::Critical);
}

#[test]
fn check_maintained_package_low_risk() {
    let status = check_maintainer_abandonment(
        "fresh-package",
        PackageEcosystem::CratesIo,
        30,
        10_000,
        Some("active@dev.com"),
        5,
        2,
    );
    assert!(!status.is_abandoned);
    assert_eq!(status.risk, AttackRisk::Low);
    assert!(status.abandonment_signals.is_empty());
}

#[test]
fn check_noreply_email_medium() {
    let status = check_maintainer_abandonment(
        "semi-old",
        PackageEcosystem::PyPi,
        180,
        5_000,
        Some("noreply@github.com"),
        3,
        1,
    );
    assert_eq!(status.risk, AttackRisk::Medium);
}

#[test]
fn check_domain_expiry_available() {
    let whois = "No match for domain \"abandoned-dev.com\".\n";
    let finding = check_domain_expiry(
        "abandoned-dev.com",
        "my-package",
        PackageEcosystem::Npm,
        whois,
    );
    assert_eq!(finding.domain_status, DomainStatus::Available);
    assert_eq!(finding.risk, AttackRisk::Critical);
}

#[test]
fn check_domain_expiry_active() {
    let whois =
        "Domain Name: active.com\nRegistrar: GoDaddy\nExpiry Date: 2026-01-01\nStatus: ok\n";
    let finding = check_domain_expiry("active.com", "pkg", PackageEcosystem::Npm, whois);
    assert_eq!(finding.domain_status, DomainStatus::Active);
    assert_eq!(finding.risk, AttackRisk::Low);
    assert_eq!(finding.registrar, Some("GoDaddy".to_string()));
    assert_eq!(finding.expiry_date, Some("2026-01-01".to_string()));
}

#[test]
fn check_domain_expiry_pending_delete() {
    let whois = "Domain Name: dying.com\nStatus: pendingDelete\n";
    let finding = check_domain_expiry("dying.com", "pkg", PackageEcosystem::PyPi, whois);
    assert_eq!(finding.domain_status, DomainStatus::PendingDelete);
    assert_eq!(finding.risk, AttackRisk::Critical);
}

#[test]
fn check_domain_expiry_redeemable() {
    let whois = "Domain Name: rescue.com\nStatus: redemptionPeriod\n";
    let finding = check_domain_expiry("rescue.com", "pkg", PackageEcosystem::RubyGems, whois);
    assert_eq!(finding.domain_status, DomainStatus::Redeemable);
    assert_eq!(finding.risk, AttackRisk::High);
}

#[test]
fn generate_typosquats_swaps() {
    let candidates = generate_typosquats("lodash", PackageEcosystem::Npm);
    let swaps: Vec<&TyposquatCandidate> = candidates
        .iter()
        .filter(|c| c.technique == TyposquatTechnique::CharacterSwap)
        .collect();
    assert!(!swaps.is_empty());
    assert!(swaps
        .iter()
        .any(|c| c.squatted_name == "oldash" || c.squatted_name == "ldoash"));
}

#[test]
fn generate_typosquats_omissions() {
    let candidates = generate_typosquats("react", PackageEcosystem::Npm);
    let omissions: Vec<&TyposquatCandidate> = candidates
        .iter()
        .filter(|c| c.technique == TyposquatTechnique::CharacterOmission)
        .collect();
    assert!(!omissions.is_empty());
    assert!(omissions
        .iter()
        .any(|c| c.squatted_name == "eact" || c.squatted_name == "ract"));
}

#[test]
fn generate_typosquats_hyphen_manipulation() {
    let candidates = generate_typosquats("my-package", PackageEcosystem::Npm);
    let hyphen: Vec<&TyposquatCandidate> = candidates
        .iter()
        .filter(|c| c.technique == TyposquatTechnique::HyphenManipulation)
        .collect();
    assert!(hyphen.len() >= 2);
    assert!(hyphen.iter().any(|c| c.squatted_name == "mypackage"));
    assert!(hyphen.iter().any(|c| c.squatted_name == "my_package"));
}

#[test]
fn generate_typosquats_plural_singular() {
    let candidates = generate_typosquats("colors", PackageEcosystem::Npm);
    let plural = candidates
        .iter()
        .find(|c| c.technique == TyposquatTechnique::PluralSingular);
    assert!(plural.is_some());
    assert_eq!(plural.unwrap().squatted_name, "color");
}

#[test]
fn generate_typosquats_homoglyph() {
    let candidates = generate_typosquats("lodash", PackageEcosystem::Npm);
    let homo: Vec<&TyposquatCandidate> = candidates
        .iter()
        .filter(|c| c.technique == TyposquatTechnique::HomoglyphAttack)
        .collect();
    assert!(!homo.is_empty());
    assert!(homo.iter().any(|c| c.squatted_name == "l0dash"));
}

#[test]
fn edit_distance_identical() {
    assert_eq!(edit_distance("hello", "hello"), 0);
}

#[test]
fn edit_distance_one_swap() {
    assert_eq!(edit_distance("abc", "acb"), 2);
}

#[test]
fn edit_distance_insertion() {
    assert_eq!(edit_distance("abc", "abcd"), 1);
}

#[test]
fn edit_distance_empty() {
    assert_eq!(edit_distance("", "abc"), 3);
    assert_eq!(edit_distance("abc", ""), 3);
}

#[test]
fn similarity_score_identical() {
    assert!((similarity_score("test", "test") - 1.0).abs() < f64::EPSILON);
}

#[test]
fn similarity_score_close() {
    let score = similarity_score("lodash", "l0dash");
    assert!(score > 0.7);
}

#[test]
fn similarity_score_empty() {
    assert!((similarity_score("", "") - 1.0).abs() < f64::EPSILON);
}

#[test]
fn build_attack_report_aggregates() {
    let abandoned = vec![MaintainerStatus {
        package_name: "old-pkg".to_string(),
        ecosystem: PackageEcosystem::Npm,
        maintainer_email: None,
        last_publish_days_ago: 900,
        total_downloads: 500_000,
        is_abandoned: true,
        abandonment_signals: vec!["stale".into()],
        risk: AttackRisk::High,
    }];
    let expired = vec![ExpiredDomainFinding {
        domain: "gone.com".to_string(),
        associated_package: "pkg".to_string(),
        ecosystem: PackageEcosystem::Npm,
        domain_status: DomainStatus::Available,
        registrar: None,
        expiry_date: None,
        risk: AttackRisk::Critical,
    }];
    let typosquats = vec![TyposquatCandidate {
        original_name: "lodash".to_string(),
        squatted_name: "l0dash".to_string(),
        technique: TyposquatTechnique::HomoglyphAttack,
        edit_distance: 1,
        similarity_score: 0.83,
        ecosystem: PackageEcosystem::Npm,
        exists_in_registry: false,
        risk: AttackRisk::High,
    }];

    let report = build_attack_report(vec!["lodash".to_string()], abandoned, expired, typosquats);
    assert_eq!(report.total_findings, 3);
    assert_eq!(report.overall_risk, AttackRisk::Critical);
    assert_eq!(report.abandoned_maintainers.len(), 1);
    assert_eq!(report.expired_domains.len(), 1);
    assert_eq!(report.typosquat_candidates.len(), 1);
}

#[test]
fn attack_vector_display() {
    assert_eq!(
        SupplyChainAttackVector::Typosquatting.to_string(),
        "Typosquatting"
    );
    assert_eq!(
        SupplyChainAttackVector::ExpiredDomain.to_string(),
        "Expired Domain"
    );
}

#[test]
fn domain_status_display() {
    assert_eq!(DomainStatus::Available.to_string(), "Available");
    assert_eq!(DomainStatus::PendingDelete.to_string(), "Pending Delete");
}

#[test]
fn package_ecosystem_display() {
    assert_eq!(PackageEcosystem::Npm.to_string(), "npm");
    assert_eq!(PackageEcosystem::CratesIo.to_string(), "crates.io");
}
