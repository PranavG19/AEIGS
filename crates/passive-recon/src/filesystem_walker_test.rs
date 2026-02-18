#[cfg(test)]
mod tests {
    use crate::filesystem_walker::{
        FileClassification, WalkerError, classify_file, walk_directory,
    };
    use std::fs;
    use std::path::{Path, PathBuf};

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("aegis-walker-tests")
            .join(format!("{name}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn create_file(dir: &Path, name: &str, content: &str) {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    #[test]
    fn classify_lock_files() {
        assert_eq!(
            classify_file(Path::new("package-lock.json")),
            FileClassification::LockFile
        );
        assert_eq!(
            classify_file(Path::new("Cargo.lock")),
            FileClassification::LockFile
        );
        assert_eq!(
            classify_file(Path::new("yarn.lock")),
            FileClassification::LockFile
        );
        assert_eq!(
            classify_file(Path::new("Gemfile.lock")),
            FileClassification::LockFile
        );
        assert_eq!(
            classify_file(Path::new("go.sum")),
            FileClassification::LockFile
        );
        assert_eq!(
            classify_file(Path::new("requirements.txt")),
            FileClassification::LockFile
        );
    }

    #[test]
    fn classify_source_code() {
        assert_eq!(
            classify_file(Path::new("main.rs")),
            FileClassification::SourceCode
        );
        assert_eq!(
            classify_file(Path::new("app.py")),
            FileClassification::SourceCode
        );
        assert_eq!(
            classify_file(Path::new("index.ts")),
            FileClassification::SourceCode
        );
        assert_eq!(
            classify_file(Path::new("server.go")),
            FileClassification::SourceCode
        );
        assert_eq!(
            classify_file(Path::new("Main.java")),
            FileClassification::SourceCode
        );
    }

    #[test]
    fn classify_config_files() {
        assert_eq!(
            classify_file(Path::new("config.json")),
            FileClassification::ConfigFile
        );
        assert_eq!(
            classify_file(Path::new("settings.toml")),
            FileClassification::ConfigFile
        );
        assert_eq!(
            classify_file(Path::new("app.ini")),
            FileClassification::ConfigFile
        );
        assert_eq!(
            classify_file(Path::new("application.properties")),
            FileClassification::ConfigFile
        );
    }

    #[test]
    fn classify_env_files() {
        assert_eq!(
            classify_file(Path::new(".env")),
            FileClassification::EnvFile
        );
        assert_eq!(
            classify_file(Path::new(".env.production")),
            FileClassification::EnvFile
        );
    }

    #[test]
    fn classify_dockerfile() {
        assert_eq!(
            classify_file(Path::new("Dockerfile")),
            FileClassification::Dockerfile
        );
        assert_eq!(
            classify_file(Path::new("Dockerfile.production")),
            FileClassification::Dockerfile
        );
        assert_eq!(
            classify_file(Path::new("docker-compose.yml")),
            FileClassification::Dockerfile
        );
    }

    #[test]
    fn classify_terraform() {
        assert_eq!(
            classify_file(Path::new("main.tf")),
            FileClassification::TerraformFile
        );
        assert_eq!(
            classify_file(Path::new("vars.tfvars")),
            FileClassification::TerraformFile
        );
    }

    #[test]
    fn classify_webserver_config() {
        assert_eq!(
            classify_file(Path::new("nginx.conf")),
            FileClassification::WebServerConfig
        );
        assert_eq!(
            classify_file(Path::new(".htaccess")),
            FileClassification::WebServerConfig
        );
    }

    #[test]
    fn classify_kubernetes_by_parent_dir() {
        assert_eq!(
            classify_file(Path::new("k8s/app.yaml")),
            FileClassification::KubernetesManifest
        );
        assert_eq!(
            classify_file(Path::new("kubernetes/service.yml")),
            FileClassification::KubernetesManifest
        );
    }

    #[test]
    fn classify_kubernetes_by_filename() {
        assert_eq!(
            classify_file(Path::new("deployment.yaml")),
            FileClassification::KubernetesManifest
        );
        assert_eq!(
            classify_file(Path::new("my-service.yml")),
            FileClassification::KubernetesManifest
        );
    }

    #[test]
    fn classify_unknown_extension() {
        assert_eq!(
            classify_file(Path::new("readme.md")),
            FileClassification::Unknown
        );
        assert_eq!(
            classify_file(Path::new("image.png")),
            FileClassification::Unknown
        );
    }

    #[test]
    fn walk_simple_directory() {
        let dir = test_dir("simple");
        create_file(&dir, "main.rs", "fn main() {}");
        create_file(&dir, "Cargo.toml", "[package]");
        create_file(&dir, ".env", "SECRET=abc");

        let result = walk_directory(&dir).unwrap();
        assert_eq!(result.files.len(), 3);
        assert!(result.total_size_bytes > 0);
        assert_eq!(
            result
                .classification_counts
                .get(&FileClassification::SourceCode),
            Some(&1)
        );
        assert_eq!(
            result
                .classification_counts
                .get(&FileClassification::ConfigFile),
            Some(&1)
        );
        assert_eq!(
            result
                .classification_counts
                .get(&FileClassification::EnvFile),
            Some(&1)
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn walk_recursive_subdirectories() {
        let dir = test_dir("recursive");
        create_file(&dir, "src/main.rs", "fn main() {}");
        create_file(&dir, "src/lib.rs", "pub mod foo;");
        create_file(&dir, "config/app.toml", "[server]");

        let result = walk_directory(&dir).unwrap();
        assert_eq!(result.files.len(), 3);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn walk_skips_node_modules_and_git() {
        let dir = test_dir("skip-dirs");
        create_file(&dir, "app.js", "console.log('hi')");
        create_file(&dir, "node_modules/lodash/index.js", "module.exports = {}");
        create_file(&dir, ".git/HEAD", "ref: refs/heads/main");

        let result = walk_directory(&dir).unwrap();
        assert_eq!(result.files.len(), 1);
        assert_eq!(
            result.files[0].classification,
            FileClassification::SourceCode
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn walk_nonexistent_directory_returns_error() {
        let result = walk_directory(Path::new("/nonexistent/aegis-test-dir"));
        assert!(matches!(result, Err(WalkerError::RootNotFound(_))));
    }

    #[test]
    fn walk_empty_directory() {
        let dir = test_dir("empty");
        let result = walk_directory(&dir).unwrap();
        assert!(result.files.is_empty());
        assert_eq!(result.total_size_bytes, 0);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn classification_display() {
        assert_eq!(FileClassification::LockFile.to_string(), "lock-file");
        assert_eq!(FileClassification::ConfigFile.to_string(), "config-file");
        assert_eq!(FileClassification::SourceCode.to_string(), "source-code");
        assert_eq!(FileClassification::Dockerfile.to_string(), "dockerfile");
        assert_eq!(
            FileClassification::KubernetesManifest.to_string(),
            "kubernetes-manifest"
        );
        assert_eq!(FileClassification::TerraformFile.to_string(), "terraform");
        assert_eq!(FileClassification::EnvFile.to_string(), "env-file");
        assert_eq!(
            FileClassification::WebServerConfig.to_string(),
            "webserver-config"
        );
        assert_eq!(FileClassification::Unknown.to_string(), "unknown");
    }

    #[test]
    fn error_display_is_descriptive() {
        let err = WalkerError::RootNotFound(PathBuf::from("/missing"));
        assert!(err.to_string().contains("root directory not found"));

        let err = WalkerError::IoError(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied",
        ));
        assert!(err.to_string().contains("io error"));
    }

    #[test]
    fn walk_counts_file_sizes_correctly() {
        let dir = test_dir("sizes");
        create_file(&dir, "a.rs", "12345");
        create_file(&dir, "b.rs", "1234567890");

        let result = walk_directory(&dir).unwrap();
        assert_eq!(result.total_size_bytes, 15);

        fs::remove_dir_all(&dir).ok();
    }
}
