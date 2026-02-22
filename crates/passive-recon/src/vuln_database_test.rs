#[cfg(test)]
mod tests {
    use crate::dependency_parser::{Ecosystem, ParsedDependency};
    use crate::vuln_database::{
        VulnDatabase, VulnDatabaseError, VulnerabilityRecord, version_in_range,
    };

    fn sample_vuln(cve: &str, package: &str, start: &str, end: &str) -> VulnerabilityRecord {
        VulnerabilityRecord {
            cve_id: cve.to_string(),
            package_name: package.to_string(),
            ecosystem: "npm".to_string(),
            vulnerable_version_start: start.to_string(),
            vulnerable_version_end: end.to_string(),
            severity: 7.5,
            description: format!("Vulnerability in {package}"),
        }
    }

    #[test]
    fn create_in_memory_database() {
        let db = VulnDatabase::open_in_memory().unwrap();
        assert_eq!(db.vulnerability_count().unwrap(), 0);
    }

    #[test]
    fn insert_and_count_vulnerabilities() {
        let db = VulnDatabase::open_in_memory().unwrap();
        db.insert_vulnerability(&sample_vuln("CVE-2024-001", "lodash", "4.0.0", "4.17.20"))
            .unwrap();
        db.insert_vulnerability(&sample_vuln("CVE-2024-002", "express", "4.0.0", "4.18.1"))
            .unwrap();
        assert_eq!(db.vulnerability_count().unwrap(), 2);
    }

    #[test]
    fn find_vulnerabilities_for_package() {
        let db = VulnDatabase::open_in_memory().unwrap();
        db.insert_vulnerability(&sample_vuln("CVE-2024-001", "lodash", "4.0.0", "4.17.20"))
            .unwrap();
        db.insert_vulnerability(&sample_vuln("CVE-2024-002", "lodash", "3.0.0", "3.10.1"))
            .unwrap();
        db.insert_vulnerability(&sample_vuln("CVE-2024-003", "express", "4.0.0", "4.18.1"))
            .unwrap();

        let results = db
            .find_vulnerabilities_for_package("lodash", "npm")
            .unwrap();
        assert_eq!(results.len(), 2);

        let results = db
            .find_vulnerabilities_for_package("express", "npm")
            .unwrap();
        assert_eq!(results.len(), 1);

        let results = db
            .find_vulnerabilities_for_package("nonexistent", "npm")
            .unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn check_dependency_finds_matching_vulnerabilities() {
        let db = VulnDatabase::open_in_memory().unwrap();
        db.insert_vulnerability(&sample_vuln("CVE-2024-001", "lodash", "4.0.0", "4.17.20"))
            .unwrap();

        let dep = ParsedDependency {
            name: "lodash".to_string(),
            version: "4.17.15".to_string(),
            ecosystem: Ecosystem::Npm,
        };

        let matches = db.check_dependency(&dep).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].cve_id, "CVE-2024-001");
        assert_eq!(matches[0].severity, 7.5);
    }

    #[test]
    fn check_dependency_skips_non_matching_versions() {
        let db = VulnDatabase::open_in_memory().unwrap();
        db.insert_vulnerability(&sample_vuln("CVE-2024-001", "lodash", "4.0.0", "4.17.20"))
            .unwrap();

        let dep = ParsedDependency {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            ecosystem: Ecosystem::Npm,
        };

        let matches = db.check_dependency(&dep).unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn check_all_dependencies() {
        let db = VulnDatabase::open_in_memory().unwrap();
        db.insert_vulnerability(&sample_vuln("CVE-2024-001", "lodash", "4.0.0", "4.17.20"))
            .unwrap();
        db.insert_vulnerability(&sample_vuln("CVE-2024-002", "express", "4.0.0", "4.18.1"))
            .unwrap();

        let deps = vec![
            ParsedDependency {
                name: "lodash".to_string(),
                version: "4.17.15".to_string(),
                ecosystem: Ecosystem::Npm,
            },
            ParsedDependency {
                name: "express".to_string(),
                version: "4.18.2".to_string(),
                ecosystem: Ecosystem::Npm,
            },
            ParsedDependency {
                name: "safe-pkg".to_string(),
                version: "1.0.0".to_string(),
                ecosystem: Ecosystem::Npm,
            },
        ];

        let matches = db.check_all_dependencies(&deps).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].dependency.name, "lodash");
    }

    #[test]
    fn version_in_range_with_semver() {
        assert!(version_in_range("4.17.15", "4.0.0", "4.17.20"));
        assert!(version_in_range("4.0.0", "4.0.0", "4.17.20"));
        assert!(version_in_range("4.17.20", "4.0.0", "4.17.20"));
        assert!(!version_in_range("4.17.21", "4.0.0", "4.17.20"));
        assert!(!version_in_range("3.10.0", "4.0.0", "4.17.20"));
    }

    #[test]
    fn version_in_range_naive_fallback() {
        assert!(version_in_range("1.2.3-beta", "1.2.3-alpha", "1.2.3-gamma"));
    }

    #[test]
    fn version_in_range_boundary_exact_match() {
        assert!(version_in_range("1.0.0", "1.0.0", "1.0.0"));
    }

    #[test]
    fn different_ecosystem_no_cross_match() {
        let db = VulnDatabase::open_in_memory().unwrap();
        db.insert_vulnerability(&VulnerabilityRecord {
            cve_id: "CVE-2024-001".to_string(),
            package_name: "requests".to_string(),
            ecosystem: "pypi".to_string(),
            vulnerable_version_start: "2.0.0".to_string(),
            vulnerable_version_end: "2.31.0".to_string(),
            severity: 8.0,
            description: "SSRF in requests".to_string(),
        })
        .unwrap();

        let npm_dep = ParsedDependency {
            name: "requests".to_string(),
            version: "2.25.0".to_string(),
            ecosystem: Ecosystem::Npm,
        };
        let matches = db.check_dependency(&npm_dep).unwrap();
        assert!(matches.is_empty());

        let pypi_dep = ParsedDependency {
            name: "requests".to_string(),
            version: "2.25.0".to_string(),
            ecosystem: Ecosystem::PyPi,
        };
        let matches = db.check_dependency(&pypi_dep).unwrap();
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn multiple_vulns_for_same_dependency() {
        let db = VulnDatabase::open_in_memory().unwrap();
        db.insert_vulnerability(&sample_vuln("CVE-2024-001", "lodash", "4.0.0", "4.17.20"))
            .unwrap();
        db.insert_vulnerability(&sample_vuln("CVE-2024-005", "lodash", "4.10.0", "4.17.18"))
            .unwrap();

        let dep = ParsedDependency {
            name: "lodash".to_string(),
            version: "4.17.15".to_string(),
            ecosystem: Ecosystem::Npm,
        };

        let matches = db.check_dependency(&dep).unwrap();
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn open_file_based_database() {
        let dir = std::env::temp_dir().join("aegis-vuln-test");
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join(format!("test-{}.db", std::process::id()));

        {
            let db = VulnDatabase::open(&db_path).unwrap();
            db.insert_vulnerability(&sample_vuln("CVE-2024-001", "express", "4.0.0", "4.18.1"))
                .unwrap();
            assert_eq!(db.vulnerability_count().unwrap(), 1);
        }

        {
            let db = VulnDatabase::open(&db_path).unwrap();
            assert_eq!(db.vulnerability_count().unwrap(), 1);
        }

        std::fs::remove_file(&db_path).ok();
    }

    #[test]
    fn error_display_is_descriptive() {
        let err = VulnDatabaseError::SemverError("bad version".to_string());
        assert!(err.to_string().contains("semver error"));

        let sqlite_err = rusqlite::Error::QueryReturnedNoRows;
        let err = VulnDatabaseError::SqliteError(sqlite_err);
        assert!(err.to_string().contains("sqlite error"));
    }

    #[test]
    fn insert_returns_row_id() {
        let db = VulnDatabase::open_in_memory().unwrap();
        let id1 = db
            .insert_vulnerability(&sample_vuln("CVE-2024-001", "a", "1.0.0", "2.0.0"))
            .unwrap();
        let id2 = db
            .insert_vulnerability(&sample_vuln("CVE-2024-002", "b", "1.0.0", "2.0.0"))
            .unwrap();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }

    /// Semver spec: release > pre-release, so "1.0.0-rc1" < "1.0.0".
    /// The old numeric-split fallback dropped the pre-release suffix and compared them equal,
    /// causing a false negative (rc1 appeared outside the vulnerable range).
    #[test]
    fn version_in_range_prerelease_not_equal_to_release() {
        // "1.0.0-rc1" should be less than "1.0.0" per semver.
        // If the range end is "1.0.0-rc1", version "1.0.0" must NOT be considered in-range.
        assert!(!version_in_range("1.0.0", "1.0.0-alpha", "1.0.0-rc1"));
    }

    /// Pre-release strings in lexicographic order: "beta" < "rc1" because 'b' < 'r'.
    #[test]
    fn version_in_range_prerelease_lexicographic_ordering() {
        assert!(version_in_range("1.0.0-beta", "1.0.0-alpha", "1.0.0-rc1"));
        assert!(!version_in_range("1.0.0-rc2", "1.0.0-alpha", "1.0.0-rc1"));
    }

    /// Semver numeric patch: "2.1.10" > "2.1.3" (numeric, not lexicographic digit order).
    #[test]
    fn version_in_range_semver_numeric_patch_ordering() {
        // 2.1.5 falls in [2.1.3, 2.1.10]
        assert!(version_in_range("2.1.5", "2.1.3", "2.1.10"));
        // 2.1.11 is above end
        assert!(!version_in_range("2.1.11", "2.1.3", "2.1.10"));
    }

    /// Non-semver strings like MATLAB-style release names fall through to lexicographic fallback.
    #[test]
    fn version_in_range_non_semver_lexicographic_fallback() {
        assert!(version_in_range("r2022b", "r2022a", "r2023b"));
        assert!(!version_in_range("r2024a", "r2022a", "r2023b"));
    }

    /// Mixed semver/non-semver tuple: only the version fails to parse, forcing the `_` arm.
    /// Also exercises compare_versions with the lexicographic fallback branch.
    #[test]
    fn version_in_range_mixed_semver_forces_fallback() {
        // "aaa-beta" fails semver parse; "1.0.0" and "2.0.0" succeed — tuple is (Err, Ok, Ok),
        // which matches `_` and falls through to compare_versions lexicographic path.
        // Lexicographically: "1.0.0" <= "aaa-beta" <= "zzz" so this is in range.
        assert!(version_in_range("aaa-beta", "1.0.0", "zzz"));
        // "0.0.1" < "1.0.0" lexicographically so this is out of range.
        assert!(!version_in_range("0.0.1", "aaa", "zzz"));
    }

    /// compare_versions with two non-semver strings uses lexicographic comparison.
    /// Exercises the tracing::debug! branch inside compare_versions.
    #[test]
    fn version_in_range_both_non_semver_compare_versions_fallback() {
        // All three fail semver parse — the `_` arm calls compare_versions("alpha", "aaa", "zzz").
        assert!(version_in_range("alpha", "aaa", "zzz"));
        assert!(!version_in_range("zzz1", "aaa", "zzz"));
    }

    /// From<rusqlite::Error> impl converts a rusqlite error into VulnDatabaseError::SqliteError.
    #[test]
    fn from_rusqlite_error_converts_to_vuln_db_error() {
        let sqlite_err = rusqlite::Error::QueryReturnedNoRows;
        let err: VulnDatabaseError = sqlite_err.into();
        assert!(matches!(err, VulnDatabaseError::SqliteError(_)));
        assert!(err.to_string().contains("sqlite error"));
    }

    fn sample_vuln_eco(
        cve: &str,
        package: &str,
        ecosystem: &str,
        start: &str,
        end: &str,
    ) -> VulnerabilityRecord {
        VulnerabilityRecord {
            cve_id: cve.to_string(),
            package_name: package.to_string(),
            ecosystem: ecosystem.to_string(),
            vulnerable_version_start: start.to_string(),
            vulnerable_version_end: end.to_string(),
            severity: 7.5,
            description: format!("Vulnerability in {package}"),
        }
    }

    #[test]
    fn upsert_inserts_new() {
        let db = VulnDatabase::open_in_memory().unwrap();
        let record = sample_vuln("CVE-2024-0001", "tokio", "1.0.0", "1.5.0");
        assert!(db.upsert_vulnerability(&record).unwrap());
        assert_eq!(db.vulnerability_count().unwrap(), 1);
    }

    #[test]
    fn upsert_skips_duplicate() {
        let db = VulnDatabase::open_in_memory().unwrap();
        let record = sample_vuln("CVE-2024-0001", "tokio", "1.0.0", "1.5.0");
        assert!(db.upsert_vulnerability(&record).unwrap());
        assert!(!db.upsert_vulnerability(&record).unwrap());
        assert_eq!(db.vulnerability_count().unwrap(), 1);
    }

    #[test]
    fn insert_batch_deduplicates() {
        let db = VulnDatabase::open_in_memory().unwrap();
        let r1 = sample_vuln("CVE-2024-0001", "tokio", "1.0.0", "1.5.0");
        let r2 = sample_vuln("CVE-2024-0001", "tokio", "1.0.0", "1.5.0");
        let r3 = sample_vuln("CVE-2024-0002", "serde", "0.9.0", "1.0.0");
        let inserted = db.insert_batch(&[r1, r2, r3]).unwrap();
        assert_eq!(inserted, 2);
        assert_eq!(db.vulnerability_count().unwrap(), 2);
    }

    #[test]
    fn insert_batch_returns_new_count() {
        let db = VulnDatabase::open_in_memory().unwrap();
        let r1 = sample_vuln("CVE-2024-0001", "tokio", "1.0.0", "1.5.0");
        db.upsert_vulnerability(&r1).unwrap();

        let r2 = sample_vuln("CVE-2024-0001", "tokio", "1.0.0", "1.5.0");
        let r3 = sample_vuln("CVE-2024-0002", "serde", "0.9.0", "1.0.0");
        let inserted = db.insert_batch(&[r2, r3]).unwrap();
        assert_eq!(inserted, 1);
        assert_eq!(db.vulnerability_count().unwrap(), 2);
    }

    #[test]
    fn metadata_get_set_roundtrip() {
        let db = VulnDatabase::open_in_memory().unwrap();
        db.set_last_updated("cargo", 1700000000000).unwrap();
        assert_eq!(db.get_last_updated("cargo").unwrap(), Some(1700000000000));
    }

    #[test]
    fn metadata_returns_none_when_unset() {
        let db = VulnDatabase::open_in_memory().unwrap();
        assert_eq!(db.get_last_updated("cargo").unwrap(), None);
    }

    #[test]
    fn clear_ecosystem_removes_only_target() {
        let db = VulnDatabase::open_in_memory().unwrap();
        let r1 = sample_vuln_eco("CVE-2024-0001", "tokio", "cargo", "1.0.0", "1.5.0");
        let r2 = sample_vuln_eco("CVE-2024-0002", "express", "npm", "4.0.0", "4.17.0");
        db.insert_batch(&[r1, r2]).unwrap();
        assert_eq!(db.vulnerability_count().unwrap(), 2);

        let deleted = db.clear_ecosystem("cargo").unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(db.vulnerability_count().unwrap(), 1);

        let remaining = db
            .find_vulnerabilities_for_package("express", "npm")
            .unwrap();
        assert_eq!(remaining.len(), 1);
    }
}
