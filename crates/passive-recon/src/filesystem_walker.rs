use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileClassification {
    LockFile,
    ConfigFile,
    SourceCode,
    Dockerfile,
    KubernetesManifest,
    TerraformFile,
    EnvFile,
    WebServerConfig,
    Unknown,
}

impl std::fmt::Display for FileClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::LockFile => "lock-file",
            Self::ConfigFile => "config-file",
            Self::SourceCode => "source-code",
            Self::Dockerfile => "dockerfile",
            Self::KubernetesManifest => "kubernetes-manifest",
            Self::TerraformFile => "terraform",
            Self::EnvFile => "env-file",
            Self::WebServerConfig => "webserver-config",
            Self::Unknown => "unknown",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone)]
pub struct ClassifiedFile {
    pub path: PathBuf,
    pub classification: FileClassification,
    pub size_bytes: u64,
}

#[derive(Debug)]
pub enum WalkerError {
    IoError(std::io::Error),
    RootNotFound(PathBuf),
}

impl std::fmt::Display for WalkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "io error: {e}"),
            Self::RootNotFound(path) => write!(f, "root directory not found: {}", path.display()),
        }
    }
}

impl std::error::Error for WalkerError {}

impl From<std::io::Error> for WalkerError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

pub struct WalkResult {
    pub files: Vec<ClassifiedFile>,
    pub total_size_bytes: u64,
    pub classification_counts: HashMap<FileClassification, usize>,
}

pub fn walk_directory(root: &Path) -> Result<WalkResult, WalkerError> {
    if !root.exists() {
        return Err(WalkerError::RootNotFound(root.to_path_buf()));
    }

    let mut files = Vec::new();
    let mut total_size = 0u64;
    let mut counts: HashMap<FileClassification, usize> = HashMap::new();

    walk_recursive(root, &mut files)?;

    for file in &files {
        total_size += file.size_bytes;
        *counts.entry(file.classification).or_insert(0) += 1;
    }

    Ok(WalkResult {
        files,
        total_size_bytes: total_size,
        classification_counts: counts,
    })
}

fn walk_recursive(dir: &Path, files: &mut Vec<ClassifiedFile>) -> Result<(), WalkerError> {
    let entries = std::fs::read_dir(dir)?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if should_skip_directory(&path) {
            continue;
        }

        if path.is_dir() {
            walk_recursive(&path, files)?;
        } else if path.is_file() {
            let metadata = std::fs::metadata(&path)?;
            let classification = classify_file(&path);
            files.push(ClassifiedFile {
                path,
                classification,
                size_bytes: metadata.len(),
            });
        }
    }

    Ok(())
}

fn should_skip_directory(path: &Path) -> bool {
    let skip_dirs = [
        "node_modules",
        ".git",
        "__pycache__",
        "target",
        ".venv",
        "venv",
        ".tox",
        "dist",
        "build",
        ".next",
    ];

    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| skip_dirs.contains(&name))
}

pub fn classify_file(path: &Path) -> FileClassification {
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if is_lock_file(filename) {
        return FileClassification::LockFile;
    }

    if is_env_file(filename) {
        return FileClassification::EnvFile;
    }

    if is_dockerfile(filename) {
        return FileClassification::Dockerfile;
    }

    if is_webserver_config(filename) {
        return FileClassification::WebServerConfig;
    }

    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match extension {
        "tf" | "tfvars" => FileClassification::TerraformFile,
        "rs" | "py" | "js" | "ts" | "jsx" | "tsx" | "go" | "java" | "rb" | "cpp" | "c"
        | "h" | "hpp" | "cs" | "swift" | "kt" | "scala" | "php" => {
            FileClassification::SourceCode
        }
        "yaml" | "yml" => classify_yaml_file(path, filename),
        "json" | "toml" | "ini" | "cfg" | "conf" | "properties" | "xml" => {
            FileClassification::ConfigFile
        }
        _ => FileClassification::Unknown,
    }
}

fn is_lock_file(filename: &str) -> bool {
    matches!(
        filename,
        "package-lock.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "Cargo.lock"
            | "Gemfile.lock"
            | "Pipfile.lock"
            | "poetry.lock"
            | "go.sum"
            | "composer.lock"
            | "requirements.txt"
    )
}

fn is_env_file(filename: &str) -> bool {
    filename == ".env"
        || filename.starts_with(".env.")
        || filename == "env"
        || filename == ".envrc"
}

fn is_dockerfile(filename: &str) -> bool {
    filename == "Dockerfile"
        || filename.starts_with("Dockerfile.")
        || filename == "docker-compose.yml"
        || filename == "docker-compose.yaml"
}

fn is_webserver_config(filename: &str) -> bool {
    matches!(
        filename,
        "nginx.conf" | "httpd.conf" | "apache2.conf" | ".htaccess"
    )
}

fn classify_yaml_file(path: &Path, filename: &str) -> FileClassification {
    if filename.contains("docker-compose") {
        return FileClassification::Dockerfile;
    }

    let parent_name = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if parent_name == "k8s"
        || parent_name == "kubernetes"
        || parent_name == "manifests"
        || parent_name == "deploy"
    {
        return FileClassification::KubernetesManifest;
    }

    if filename.contains("deployment")
        || filename.contains("service")
        || filename.contains("ingress")
        || filename.contains("pod")
    {
        return FileClassification::KubernetesManifest;
    }

    FileClassification::ConfigFile
}
