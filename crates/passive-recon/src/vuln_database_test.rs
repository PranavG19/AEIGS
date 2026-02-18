#[cfg(test)]
mod tests {
    use crate::dependency_parser::{Ecosystem, ParsedDependency};
    use crate::vuln_database::{
        version_in_range, VulnDatabase, VulnDatabaseError, VulnerabilityRecord,
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

        let results = db.find_vulnerabilities_for_package("lodash", "npm").unwrap();
        assert_eq!(results.len(), 2);

        let results = db.find_vulnerabilities_for_package("express", "npm").unwrap();
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
            db.insert_vulnerability(&sample_vuln(
                "CVE-2024-001",
                "express",
                "4.0.0",
                "4.18.1",
            ))
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
}
