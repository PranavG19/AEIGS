use aegis_passive_recon::dependency_parser::{
    Ecosystem, ParsedDependency, detect_ecosystem, parse_lock_file, parse_lock_file_content,
};
use aegis_passive_recon::filesystem_walker::{FileClassification, walk_directory};
use aegis_passive_recon::vuln_database::{VulnDatabase, VulnerabilityRecord};
use aegis_test_support::fixture_data;
use std::fs;
use tempfile::TempDir;

fn create_tempdir_with_files(files: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().expect("failed to create temp directory");
    for (rel_path, content) in files {
        let full_path = dir.path().join(rel_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).expect("failed to create parent directories");
        }
        fs::write(&full_path, content).expect("failed to write fixture file");
    }
    dir
}

#[test]
fn parse_real_cargo_lock() {
    let content = fixture_data::cargo_lock_with_vuln();
    let deps = parse_lock_file_content("Cargo.lock", content).unwrap();

    assert!(
        !deps.is_empty(),
        "expected at least one dependency from Cargo.lock"
    );

    for dep in &deps {
        assert_eq!(dep.ecosystem, Ecosystem::Cargo);
    }

    let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
    assert!(names.contains(&"hyper"), "expected hyper in parsed deps");
    assert!(names.contains(&"bytes"), "expected bytes in parsed deps");
    assert!(names.contains(&"http"), "expected http in parsed deps");
    assert!(names.contains(&"tokio"), "expected tokio in parsed deps");

    assert!(
        !names.contains(&"my-app"),
        "my-app has no registry source and should be filtered out"
    );
}

#[test]
fn parse_real_package_lock_v2() {
    let content = fixture_data::package_lock_v2();
    let deps = parse_lock_file_content("package-lock.json", content).unwrap();

    assert_eq!(deps.len(), 2, "expected 2 npm dependencies");

    for dep in &deps {
        assert_eq!(dep.ecosystem, Ecosystem::Npm);
        assert!(
            !dep.name.contains("node_modules/"),
            "node_modules/ prefix should be stripped from '{}'",
            dep.name
        );
    }

    let express = deps.iter().find(|d| d.name == "express").unwrap();
    assert_eq!(express.version, "4.18.2");

    let lodash = deps.iter().find(|d| d.name == "lodash").unwrap();
    assert_eq!(lodash.version, "4.17.20");
}

#[test]
fn parse_real_package_lock_v1_fallback() {
    let v1_content = r#"{
        "name": "legacy-app",
        "version": "0.5.0",
        "lockfileVersion": 1,
        "requires": true,
        "dependencies": {
            "react": { "version": "18.2.0" },
            "react-dom": { "version": "18.2.0" },
            "webpack": { "version": "5.89.0" }
        }
    }"#;

    let deps = parse_lock_file_content("package-lock.json", v1_content).unwrap();

    assert_eq!(deps.len(), 3, "expected 3 dependencies from v1 fallback");

    for dep in &deps {
        assert_eq!(dep.ecosystem, Ecosystem::Npm);
    }

    let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
    assert!(names.contains(&"react"));
    assert!(names.contains(&"react-dom"));
    assert!(names.contains(&"webpack"));

    let react = deps.iter().find(|d| d.name == "react").unwrap();
    assert_eq!(react.version, "18.2.0");
}

#[test]
fn parse_real_poetry_lock() {
    assert_eq!(
        detect_ecosystem("poetry.lock"),
        Some(Ecosystem::PyPi),
        "poetry.lock should be detected as PyPi ecosystem"
    );

    let content = fixture_data::poetry_lock();
    let result = parse_lock_file_content("poetry.lock", content);
    assert!(
        result.is_err(),
        "poetry.lock parsing is not yet implemented; expected UnsupportedFormat"
    );
}

#[test]
fn parse_real_gemfile_lock() {
    let content = fixture_data::gemfile_lock();
    let deps = parse_lock_file_content("Gemfile.lock", content).unwrap();

    assert!(
        !deps.is_empty(),
        "expected at least one dependency from Gemfile.lock"
    );

    for dep in &deps {
        assert_eq!(dep.ecosystem, Ecosystem::RubyGems);
    }

    let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
    assert!(
        names.contains(&"actionpack"),
        "expected actionpack as direct dep"
    );
    assert!(names.contains(&"rails"), "expected rails as direct dep");
    assert!(
        names.contains(&"nokogiri"),
        "expected nokogiri as direct dep"
    );
    assert!(names.contains(&"rack"), "expected rack as direct dep");

    for dep in &deps {
        assert!(
            !dep.name.contains(' '),
            "dep name '{}' should not contain spaces (sub-deps should be excluded)",
            dep.name
        );
        assert!(
            !dep.version.is_empty(),
            "dep '{}' should have a non-empty version",
            dep.name
        );
    }
}

#[test]
fn parse_real_go_sum() {
    let content = fixture_data::go_sum();
    let deps = parse_lock_file_content("go.sum", content).unwrap();

    assert!(
        !deps.is_empty(),
        "expected at least one dependency from go.sum"
    );

    for dep in &deps {
        assert_eq!(dep.ecosystem, Ecosystem::Go);
        assert!(
            !dep.version.starts_with('v'),
            "version '{}' should have v-prefix stripped for dep '{}'",
            dep.version,
            dep.name
        );
    }

    let gin_entries: Vec<&ParsedDependency> = deps
        .iter()
        .filter(|d| d.name == "github.com/gin-gonic/gin")
        .collect();
    assert_eq!(
        gin_entries.len(),
        1,
        "go.sum duplicate entries (h1 + go.mod) should be deduped"
    );
    assert_eq!(gin_entries[0].version, "1.7.0");

    let crypto_entries: Vec<&ParsedDependency> = deps
        .iter()
        .filter(|d| d.name == "golang.org/x/crypto")
        .collect();
    assert_eq!(
        crypto_entries.len(),
        1,
        "golang.org/x/crypto should appear only once after dedup"
    );
}

#[test]
fn vuln_database_lookup_known_cve() {
    let db = VulnDatabase::open_in_memory().unwrap();

    let record = VulnerabilityRecord {
        cve_id: "CVE-2021-23337".to_string(),
        package_name: "lodash".to_string(),
        ecosystem: "npm".to_string(),
        vulnerable_version_start: "0.0.0".to_string(),
        vulnerable_version_end: "4.17.21".to_string(),
        severity: 7.2,
        description: "Prototype pollution in lodash".to_string(),
    };
    db.insert_vulnerability(&record).unwrap();

    let dep = ParsedDependency {
        name: "lodash".to_string(),
        version: "4.17.20".to_string(),
        ecosystem: Ecosystem::Npm,
    };

    let matches = db.check_dependency(&dep).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].cve_id, "CVE-2021-23337");
    assert_eq!(matches[0].severity, 7.2);
    assert_eq!(matches[0].dependency.name, "lodash");
    assert_eq!(matches[0].dependency.version, "4.17.20");
}

#[test]
fn vuln_database_no_match_returns_empty() {
    let db = VulnDatabase::open_in_memory().unwrap();

    let record = VulnerabilityRecord {
        cve_id: "CVE-2021-23337".to_string(),
        package_name: "lodash".to_string(),
        ecosystem: "npm".to_string(),
        vulnerable_version_start: "0.0.0".to_string(),
        vulnerable_version_end: "4.17.21".to_string(),
        severity: 7.2,
        description: "Prototype pollution".to_string(),
    };
    db.insert_vulnerability(&record).unwrap();

    let dep = ParsedDependency {
        name: "nonexistent-package".to_string(),
        version: "1.0.0".to_string(),
        ecosystem: Ecosystem::Npm,
    };

    let matches = db.check_dependency(&dep).unwrap();
    assert!(
        matches.is_empty(),
        "lookup for non-existent package should return no matches"
    );
}

#[test]
fn filesystem_walker_finds_lock_files() {
    let dir = create_tempdir_with_files(&[
        ("Cargo.lock", "version = 3\n"),
        ("frontend/package-lock.json", "{}"),
        ("services/go.sum", ""),
        ("ruby-app/Gemfile.lock", "GEM\n"),
    ]);

    let result = walk_directory(dir.path()).unwrap();

    let lock_files: Vec<_> = result
        .files
        .iter()
        .filter(|f| f.classification == FileClassification::LockFile)
        .collect();

    assert_eq!(
        lock_files.len(),
        4,
        "expected 4 lock files, found: {:?}",
        lock_files
            .iter()
            .map(|f| f.path.display().to_string())
            .collect::<Vec<_>>()
    );

    let lock_count = result
        .classification_counts
        .get(&FileClassification::LockFile)
        .copied()
        .unwrap_or(0);
    assert_eq!(lock_count, 4);
}

#[test]
fn filesystem_walker_classifies_source_files() {
    let dir = create_tempdir_with_files(&[
        ("src/main.rs", "fn main() {}"),
        ("src/app.js", "console.log('hi')"),
        ("src/utils.py", "def hello(): pass"),
    ]);

    let result = walk_directory(dir.path()).unwrap();

    let source_files: Vec<_> = result
        .files
        .iter()
        .filter(|f| f.classification == FileClassification::SourceCode)
        .collect();

    assert_eq!(
        source_files.len(),
        3,
        "expected 3 source files (.rs, .js, .py)"
    );

    let extensions: Vec<&str> = source_files
        .iter()
        .filter_map(|f| f.path.extension().and_then(|e| e.to_str()))
        .collect();
    assert!(extensions.contains(&"rs"));
    assert!(extensions.contains(&"js"));
    assert!(extensions.contains(&"py"));
}

#[test]
fn filesystem_walker_skips_hidden_dirs() {
    let dir = create_tempdir_with_files(&[
        ("visible.rs", "fn main() {}"),
        (".git/HEAD", "ref: refs/heads/main"),
        (".git/config", "[core]"),
        ("node_modules/lodash/index.js", "module.exports = {}"),
        ("node_modules/express/index.js", "module.exports = {}"),
    ]);

    let result = walk_directory(dir.path()).unwrap();

    assert_eq!(
        result.files.len(),
        1,
        "only visible.rs should be found; .git/ and node_modules/ should be skipped"
    );
    assert_eq!(
        result.files[0].classification,
        FileClassification::SourceCode
    );

    let found_names: Vec<String> = result
        .files
        .iter()
        .map(|f| f.path.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    assert_eq!(found_names, vec!["visible.rs"]);
}

#[test]
fn recon_end_to_end_tempdir() {
    let cargo_lock_content = fixture_data::cargo_lock_with_vuln();
    let dir = create_tempdir_with_files(&[("Cargo.lock", cargo_lock_content)]);

    let walk_result = walk_directory(dir.path()).unwrap();
    let lock_files: Vec<_> = walk_result
        .files
        .iter()
        .filter(|f| f.classification == FileClassification::LockFile)
        .collect();
    assert_eq!(lock_files.len(), 1, "expected exactly 1 lock file");

    let deps = parse_lock_file(&lock_files[0].path).unwrap();
    assert!(
        !deps.is_empty(),
        "expected parsed dependencies from Cargo.lock"
    );

    let hyper_dep = deps.iter().find(|d| d.name == "hyper");
    assert!(hyper_dep.is_some(), "expected hyper in parsed deps");
    assert_eq!(hyper_dep.unwrap().version, "0.14.0");

    let db = VulnDatabase::open_in_memory().unwrap();
    db.insert_vulnerability(&VulnerabilityRecord {
        cve_id: "CVE-2021-32714".to_string(),
        package_name: "hyper".to_string(),
        ecosystem: "cargo".to_string(),
        vulnerable_version_start: "0.12.0".to_string(),
        vulnerable_version_end: "0.14.10".to_string(),
        severity: 9.1,
        description: "Integer overflow in hyper's header parsing".to_string(),
    })
    .unwrap();

    let matches = db.check_all_dependencies(&deps).unwrap();
    assert_eq!(matches.len(), 1, "expected exactly 1 vulnerability match");
    assert_eq!(matches[0].cve_id, "CVE-2021-32714");
    assert_eq!(matches[0].dependency.name, "hyper");
    assert_eq!(matches[0].dependency.version, "0.14.0");
    assert_eq!(matches[0].severity, 9.1);
}
