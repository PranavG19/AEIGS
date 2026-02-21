use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Creates a temporary directory populated with the given files.
///
/// Each entry in `files` is a `(relative_path, content)` pair. Parent
/// directories are created automatically.
pub fn create_source_tree(files: &[(&str, &str)]) -> TempDir {
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

/// Creates a temporary workspace pre-populated with a Cargo.lock and
/// package-lock.json containing known vulnerable dependencies.
///
/// Suitable for testing passive recon / dependency parsing pipelines.
pub fn create_recon_workspace() -> TempDir {
    create_source_tree(&[
        ("Cargo.lock", crate::fixture_data::cargo_lock_with_vuln()),
        ("package-lock.json", crate::fixture_data::package_lock_v2()),
    ])
}

/// Creates a temporary workspace with a variety of source files for
/// route discovery testing across multiple frameworks.
pub fn create_route_discovery_workspace() -> TempDir {
    create_source_tree(&[
        ("src/app.js", crate::fixture_data::express_source()),
        ("src/app.py", crate::fixture_data::flask_source()),
        ("src/main.py", crate::fixture_data::fastapi_source()),
        ("src/urls.py", crate::fixture_data::django_source()),
        (
            "src/UserController.java",
            crate::fixture_data::spring_source(),
        ),
    ])
}

/// Writes a file into an existing directory, creating parent dirs as needed.
pub fn write_fixture_file(base: &Path, rel_path: &str, content: &str) {
    let full_path = base.join(rel_path);
    if let Some(parent) = full_path.parent() {
        fs::create_dir_all(parent).expect("failed to create parent directories");
    }
    fs::write(&full_path, content).expect("failed to write fixture file");
}
