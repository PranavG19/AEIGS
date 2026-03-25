/// Category of shadow supply chain dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShadowDependencyType {
    BuildPlugin,
    CiCdAction,
    DockerBaseImage,
    CdnScript,
    GitSubmodule,
    NpmPostInstall,
    MavenPlugin,
    GradlePlugin,
    WebpackLoader,
    BabelPlugin,
    GithubAction,
    TerraformProvider,
    HelmChart,
    BrewFormula,
}

impl std::fmt::Display for ShadowDependencyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BuildPlugin => write!(f, "Build Plugin"),
            Self::CiCdAction => write!(f, "CI/CD Action"),
            Self::DockerBaseImage => write!(f, "Docker Base Image"),
            Self::CdnScript => write!(f, "CDN Script"),
            Self::GitSubmodule => write!(f, "Git Submodule"),
            Self::NpmPostInstall => write!(f, "npm Post-Install Script"),
            Self::MavenPlugin => write!(f, "Maven Plugin"),
            Self::GradlePlugin => write!(f, "Gradle Plugin"),
            Self::WebpackLoader => write!(f, "Webpack Loader"),
            Self::BabelPlugin => write!(f, "Babel Plugin"),
            Self::GithubAction => write!(f, "GitHub Action"),
            Self::TerraformProvider => write!(f, "Terraform Provider"),
            Self::HelmChart => write!(f, "Helm Chart"),
            Self::BrewFormula => write!(f, "Brew Formula"),
        }
    }
}

/// Risk level for supply chain findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SupplyChainRisk {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for SupplyChainRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// Maintainer security posture assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MaintainerSecurity {
    Unknown,
    Weak,
    Moderate,
    Strong,
}

impl std::fmt::Display for MaintainerSecurity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::Weak => write!(f, "Weak"),
            Self::Moderate => write!(f, "Moderate"),
            Self::Strong => write!(f, "Strong"),
        }
    }
}

/// A shadow dependency not captured in standard lockfiles.
#[derive(Debug, Clone, PartialEq)]
pub struct ShadowDependency {
    pub name: String,
    pub version: Option<String>,
    pub dep_type: ShadowDependencyType,
    pub source_url: Option<String>,
    pub pinned: bool,
    pub sri_hash: Option<String>,
    pub maintainer_count: Option<usize>,
    pub last_update: Option<String>,
    pub transitive_depth: u32,
    pub evidence_location: String,
}

/// A CDN-hosted script with SRI tracking.
#[derive(Debug, Clone, PartialEq)]
pub struct CdnScriptEntry {
    pub url: String,
    pub sri_hash: Option<String>,
    pub sri_algorithm: Option<String>,
    pub library_name: Option<String>,
    pub version: Option<String>,
    pub cdn_provider: String,
    pub crossorigin_set: bool,
    pub source_page: String,
}

/// Docker base image lineage node.
#[derive(Debug, Clone, PartialEq)]
pub struct DockerImageLineage {
    pub image: String,
    pub tag: String,
    pub digest: Option<String>,
    pub parent_image: Option<String>,
    pub registry: String,
    pub last_updated: Option<String>,
    pub known_vulns: Vec<String>,
    pub source_dockerfile: String,
}

/// GitHub Action / CI dependency.
#[derive(Debug, Clone, PartialEq)]
pub struct CiDependency {
    pub action_ref: String,
    pub owner: String,
    pub repo: String,
    pub version_ref: String,
    pub pinned_to_sha: bool,
    pub marketplace_verified: bool,
    pub source_workflow: String,
}

/// Maintainer account change event.
#[derive(Debug, Clone, PartialEq)]
pub struct MaintainerChangeEvent {
    pub package_name: String,
    pub event_type: MaintainerEventType,
    pub old_maintainer: Option<String>,
    pub new_maintainer: Option<String>,
    pub timestamp: Option<String>,
    pub risk: SupplyChainRisk,
}

/// Type of maintainer change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MaintainerEventType {
    OwnershipTransfer,
    NewMaintainerAdded,
    MaintainerRemoved,
    RepoTransfer,
    NamespaceChange,
}

impl std::fmt::Display for MaintainerEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OwnershipTransfer => write!(f, "Ownership Transfer"),
            Self::NewMaintainerAdded => write!(f, "New Maintainer Added"),
            Self::MaintainerRemoved => write!(f, "Maintainer Removed"),
            Self::RepoTransfer => write!(f, "Repository Transfer"),
            Self::NamespaceChange => write!(f, "Namespace Change"),
        }
    }
}

/// Typosquat detection result.
#[derive(Debug, Clone, PartialEq)]
pub struct TyposquatCandidate {
    pub legitimate_package: String,
    pub suspicious_package: String,
    pub distance: usize,
    pub technique: TyposquatTechnique,
    pub risk: SupplyChainRisk,
}

/// Typosquat technique classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TyposquatTechnique {
    CharacterSwap,
    MissingCharacter,
    ExtraCharacter,
    HomoglyphSubstitution,
    ScopeConfusion,
    HyphenOmission,
}

impl std::fmt::Display for TyposquatTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CharacterSwap => write!(f, "Character Swap"),
            Self::MissingCharacter => write!(f, "Missing Character"),
            Self::ExtraCharacter => write!(f, "Extra Character"),
            Self::HomoglyphSubstitution => write!(f, "Homoglyph Substitution"),
            Self::ScopeConfusion => write!(f, "Scope Confusion"),
            Self::HyphenOmission => write!(f, "Hyphen Omission"),
        }
    }
}

/// Blast radius assessment for a dependency.
#[derive(Debug, Clone, PartialEq)]
pub struct BlastRadiusAssessment {
    pub dependency_name: String,
    pub blast_radius_score: f64,
    pub maintainer_security: MaintainerSecurity,
    pub dependency_depth: u32,
    pub composite_risk: f64,
    pub downstream_count: usize,
    pub has_install_scripts: bool,
    pub factors: Vec<String>,
}

/// Full shadow supply chain mapping result.
#[derive(Debug, Clone)]
pub struct ShadowSupplyChainResult {
    pub shadow_deps: Vec<ShadowDependency>,
    pub cdn_scripts: Vec<CdnScriptEntry>,
    pub docker_lineage: Vec<DockerImageLineage>,
    pub ci_deps: Vec<CiDependency>,
    pub maintainer_events: Vec<MaintainerChangeEvent>,
    pub typosquat_candidates: Vec<TyposquatCandidate>,
    pub blast_radius: Vec<BlastRadiusAssessment>,
    pub summary: String,
}

/// Configuration for the supply chain shadow mapper.
#[derive(Debug, Clone)]
pub struct ShadowMapperConfig {
    pub scan_dockerfiles: bool,
    pub scan_ci_workflows: bool,
    pub scan_cdn_scripts: bool,
    pub scan_build_plugins: bool,
    pub detect_typosquats: bool,
    pub levenshtein_threshold: usize,
    pub known_packages: Vec<String>,
}

impl Default for ShadowMapperConfig {
    fn default() -> Self {
        Self {
            scan_dockerfiles: true,
            scan_ci_workflows: true,
            scan_cdn_scripts: true,
            scan_build_plugins: true,
            detect_typosquats: true,
            levenshtein_threshold: 2,
            known_packages: default_known_packages(),
        }
    }
}

impl ShadowMapperConfig {
    pub fn with_scan_dockerfiles(mut self, enabled: bool) -> Self {
        self.scan_dockerfiles = enabled;
        self
    }

    pub fn with_scan_ci_workflows(mut self, enabled: bool) -> Self {
        self.scan_ci_workflows = enabled;
        self
    }

    pub fn with_detect_typosquats(mut self, enabled: bool) -> Self {
        self.detect_typosquats = enabled;
        self
    }

    pub fn with_levenshtein_threshold(mut self, threshold: usize) -> Self {
        self.levenshtein_threshold = threshold;
        self
    }
}

/// Maps the shadow supply chain beyond lockfiles.
pub struct SupplyChainShadowMapper {
    config: ShadowMapperConfig,
}

impl SupplyChainShadowMapper {
    pub fn new(config: ShadowMapperConfig) -> Self {
        Self { config }
    }

    /// Parse Dockerfiles to extract base image lineage.
    pub fn parse_dockerfiles(&self, dockerfiles: &[(&str, &str)]) -> Vec<DockerImageLineage> {
        if !self.config.scan_dockerfiles {
            return Vec::new();
        }
        let mut lineage = Vec::new();
        for (path, content) in dockerfiles {
            let mut parent: Option<String> = None;
            for line in content.lines() {
                let trimmed = line.trim();
                if let Some(from_clause) = trimmed.strip_prefix("FROM ") {
                    let from_clause = from_clause.split_whitespace().next().unwrap_or("");
                    let (image_tag, digest) = Self::parse_docker_image_ref(from_clause);
                    let (image, tag) = Self::split_image_tag(&image_tag);
                    let registry = Self::infer_registry(&image);

                    lineage.push(DockerImageLineage {
                        image: image.clone(),
                        tag,
                        digest,
                        parent_image: parent.clone(),
                        registry,
                        last_updated: None,
                        known_vulns: Vec::new(),
                        source_dockerfile: path.to_string(),
                    });
                    parent = Some(image);
                }
            }
        }
        lineage
    }

    /// Parse CI/CD workflow files (GitHub Actions YAML).
    pub fn parse_ci_workflows(&self, workflows: &[(&str, &str)]) -> Vec<CiDependency> {
        if !self.config.scan_ci_workflows {
            return Vec::new();
        }
        let mut deps = Vec::new();
        for (path, content) in workflows {
            for line in content.lines() {
                let trimmed = line.trim();
                if let Some(uses_clause) = trimmed
                    .strip_prefix("- uses: ")
                    .or_else(|| trimmed.strip_prefix("uses: "))
                {
                    let uses_ref = uses_clause.trim().trim_matches('"').trim_matches('\'');
                    if let Some(dep) = self.parse_action_ref(uses_ref, path) {
                        deps.push(dep);
                    }
                }
            }
        }
        deps
    }

    /// Extract CDN-hosted scripts from HTML content.
    pub fn extract_cdn_scripts(&self, pages: &[(&str, &str)]) -> Vec<CdnScriptEntry> {
        if !self.config.scan_cdn_scripts {
            return Vec::new();
        }
        let mut scripts = Vec::new();
        let re = regex::Regex::new(r#"<script[^>]*\ssrc\s*=\s*["']([^"']+)["'][^>]*>"#)
            .unwrap_or_else(|_| regex::Regex::new(r"$^").unwrap());
        let sri_re = regex::Regex::new(
            r#"integrity\s*=\s*["']((?:sha256|sha384|sha512)-[A-Za-z0-9+/=]+)["']"#,
        )
        .unwrap_or_else(|_| regex::Regex::new(r"$^").unwrap());
        let crossorigin_re = regex::Regex::new(r#"crossorigin\s*=\s*["']?anonymous"#)
            .unwrap_or_else(|_| regex::Regex::new(r"$^").unwrap());

        for (page_url, content) in pages {
            for cap in re.captures_iter(content) {
                let src = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                if !self.is_cdn_url(src) {
                    continue;
                }
                let tag_match = cap.get(0).map(|m| m.as_str()).unwrap_or("");
                let sri = sri_re
                    .captures(tag_match)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string());
                let algo = sri
                    .as_ref()
                    .and_then(|s| s.split('-').next().map(|a| a.to_string()));
                let crossorigin = crossorigin_re.is_match(tag_match);
                let cdn_provider = self.identify_cdn_provider(src);
                let (lib_name, version) = self.parse_cdn_url_metadata(src);

                scripts.push(CdnScriptEntry {
                    url: src.to_string(),
                    sri_hash: sri,
                    sri_algorithm: algo,
                    library_name: lib_name,
                    version,
                    cdn_provider,
                    crossorigin_set: crossorigin,
                    source_page: page_url.to_string(),
                });
            }
        }
        scripts
    }

    /// Parse build configuration files for plugin dependencies.
    pub fn parse_build_plugins(&self, build_files: &[(&str, &str)]) -> Vec<ShadowDependency> {
        if !self.config.scan_build_plugins {
            return Vec::new();
        }
        let mut deps = Vec::new();
        for (path, content) in build_files {
            if path.contains("webpack") || path.ends_with(".config.js") {
                deps.extend(self.extract_webpack_plugins(content, path));
            }
            if path.contains(".babelrc") || path.contains("babel.config") {
                deps.extend(self.extract_babel_plugins(content, path));
            }
            if path.contains("pom.xml") {
                deps.extend(self.extract_maven_plugins(content, path));
            }
            if path.contains("build.gradle") {
                deps.extend(self.extract_gradle_plugins(content, path));
            }
        }
        deps
    }

    /// Detect typosquat candidates against known package names.
    pub fn detect_typosquats(&self, package_names: &[&str]) -> Vec<TyposquatCandidate> {
        if !self.config.detect_typosquats {
            return Vec::new();
        }
        let mut candidates = Vec::new();
        for pkg in package_names {
            for known in &self.config.known_packages {
                if pkg == known {
                    continue;
                }
                let dist = levenshtein(pkg, known);
                if dist > 0 && dist <= self.config.levenshtein_threshold {
                    let technique = Self::classify_typosquat(pkg, known);
                    let risk = if dist == 1 {
                        SupplyChainRisk::Critical
                    } else {
                        SupplyChainRisk::High
                    };
                    candidates.push(TyposquatCandidate {
                        legitimate_package: known.clone(),
                        suspicious_package: pkg.to_string(),
                        distance: dist,
                        technique,
                        risk,
                    });
                }
            }
        }
        candidates
    }

    /// Assess blast radius for a set of shadow dependencies.
    pub fn assess_blast_radius(&self, deps: &[ShadowDependency]) -> Vec<BlastRadiusAssessment> {
        deps.iter()
            .map(|dep| {
                let maintainer_security = match dep.maintainer_count {
                    Some(1) => MaintainerSecurity::Weak,
                    Some(2..=3) => MaintainerSecurity::Moderate,
                    Some(4..) => MaintainerSecurity::Strong,
                    _ => MaintainerSecurity::Unknown,
                };

                let depth_factor = 1.0 + (dep.transitive_depth as f64 * 0.3);
                let pin_factor = if dep.pinned { 0.5 } else { 1.5 };
                let maint_factor = match maintainer_security {
                    MaintainerSecurity::Unknown => 1.2,
                    MaintainerSecurity::Weak => 1.5,
                    MaintainerSecurity::Moderate => 0.8,
                    MaintainerSecurity::Strong => 0.5,
                };

                let blast_radius = (depth_factor * pin_factor * maint_factor).min(10.0);
                let composite = blast_radius * maint_factor;

                let mut factors = Vec::new();
                if !dep.pinned {
                    factors.push("Not pinned to specific version".to_string());
                }
                if dep.transitive_depth > 2 {
                    factors.push(format!(
                        "Deep transitive dependency (depth {})",
                        dep.transitive_depth
                    ));
                }
                if matches!(
                    maintainer_security,
                    MaintainerSecurity::Weak | MaintainerSecurity::Unknown
                ) {
                    factors.push("Low maintainer security posture".to_string());
                }

                BlastRadiusAssessment {
                    dependency_name: dep.name.clone(),
                    blast_radius_score: blast_radius,
                    maintainer_security,
                    dependency_depth: dep.transitive_depth,
                    composite_risk: composite.min(10.0),
                    downstream_count: 0,
                    has_install_scripts: false,
                    factors,
                }
            })
            .collect()
    }

    /// Run full shadow supply chain analysis.
    pub fn analyze(
        &self,
        dockerfiles: &[(&str, &str)],
        ci_workflows: &[(&str, &str)],
        html_pages: &[(&str, &str)],
        build_files: &[(&str, &str)],
        package_names: &[&str],
    ) -> ShadowSupplyChainResult {
        let docker_lineage = self.parse_dockerfiles(dockerfiles);
        let ci_deps = self.parse_ci_workflows(ci_workflows);
        let cdn_scripts = self.extract_cdn_scripts(html_pages);
        let build_deps = self.parse_build_plugins(build_files);
        let typosquats = self.detect_typosquats(package_names);

        let mut all_shadow_deps = build_deps;
        for img in &docker_lineage {
            all_shadow_deps.push(ShadowDependency {
                name: img.image.clone(),
                version: Some(img.tag.clone()),
                dep_type: ShadowDependencyType::DockerBaseImage,
                source_url: None,
                pinned: img.digest.is_some(),
                sri_hash: img.digest.clone(),
                maintainer_count: None,
                last_update: img.last_updated.clone(),
                transitive_depth: 0,
                evidence_location: img.source_dockerfile.clone(),
            });
        }
        for ci in &ci_deps {
            all_shadow_deps.push(ShadowDependency {
                name: ci.action_ref.clone(),
                version: Some(ci.version_ref.clone()),
                dep_type: ShadowDependencyType::GithubAction,
                source_url: Some(format!("https://github.com/{}/{}", ci.owner, ci.repo)),
                pinned: ci.pinned_to_sha,
                sri_hash: None,
                maintainer_count: None,
                last_update: None,
                transitive_depth: 0,
                evidence_location: ci.source_workflow.clone(),
            });
        }

        let blast_radius = self.assess_blast_radius(&all_shadow_deps);

        let critical_count = blast_radius
            .iter()
            .filter(|b| b.composite_risk > 5.0)
            .count();
        let summary = format!(
            "Shadow supply chain: {} deps, {} CDN scripts, {} Docker images, {} CI actions, {} typosquats, {} critical-risk",
            all_shadow_deps.len(),
            cdn_scripts.len(),
            docker_lineage.len(),
            ci_deps.len(),
            typosquats.len(),
            critical_count,
        );

        ShadowSupplyChainResult {
            shadow_deps: all_shadow_deps,
            cdn_scripts,
            docker_lineage,
            ci_deps,
            maintainer_events: Vec::new(),
            typosquat_candidates: typosquats,
            blast_radius,
            summary,
        }
    }

    fn parse_docker_image_ref(reference: &str) -> (String, Option<String>) {
        if let Some((image, digest)) = reference.split_once('@') {
            (image.to_string(), Some(digest.to_string()))
        } else {
            (reference.to_string(), None)
        }
    }

    fn split_image_tag(image_tag: &str) -> (String, String) {
        if let Some((image, tag)) = image_tag.rsplit_once(':') {
            (image.to_string(), tag.to_string())
        } else {
            (image_tag.to_string(), "latest".to_string())
        }
    }

    fn infer_registry(image: &str) -> String {
        if image.contains("gcr.io") {
            "Google Container Registry".to_string()
        } else if image.contains("ecr.") || image.contains("amazonaws.com") {
            "AWS ECR".to_string()
        } else if image.contains("azurecr.io") {
            "Azure Container Registry".to_string()
        } else if image.contains("ghcr.io") {
            "GitHub Container Registry".to_string()
        } else {
            "Docker Hub".to_string()
        }
    }

    fn parse_action_ref(&self, uses_ref: &str, workflow_path: &str) -> Option<CiDependency> {
        let (repo_part, version) = uses_ref.split_once('@')?;
        let (owner, repo) = repo_part.split_once('/')?;
        let repo = repo.split('/').next().unwrap_or(repo);
        let pinned = version.len() == 40 && version.chars().all(|c| c.is_ascii_hexdigit());

        Some(CiDependency {
            action_ref: uses_ref.to_string(),
            owner: owner.to_string(),
            repo: repo.to_string(),
            version_ref: version.to_string(),
            pinned_to_sha: pinned,
            marketplace_verified: false,
            source_workflow: workflow_path.to_string(),
        })
    }

    fn is_cdn_url(&self, url: &str) -> bool {
        let cdn_domains = [
            "cdn.jsdelivr.net",
            "cdnjs.cloudflare.com",
            "unpkg.com",
            "ajax.googleapis.com",
            "code.jquery.com",
            "stackpath.bootstrapcdn.com",
            "cdn.bootcss.com",
            "fonts.googleapis.com",
            "maxcdn.bootstrapcdn.com",
        ];
        cdn_domains.iter().any(|d| url.contains(d))
    }

    fn identify_cdn_provider(&self, url: &str) -> String {
        if url.contains("jsdelivr") {
            "jsDelivr".to_string()
        } else if url.contains("cloudflare") || url.contains("cdnjs") {
            "Cloudflare CDNJS".to_string()
        } else if url.contains("unpkg") {
            "unpkg".to_string()
        } else if url.contains("googleapis") {
            "Google CDN".to_string()
        } else if url.contains("jquery.com") {
            "jQuery CDN".to_string()
        } else if url.contains("bootstrapcdn") {
            "Bootstrap CDN".to_string()
        } else {
            "Unknown CDN".to_string()
        }
    }

    fn parse_cdn_url_metadata(&self, url: &str) -> (Option<String>, Option<String>) {
        let parts: Vec<&str> = url.split('/').collect();
        let version = parts.iter().find(|p| {
            p.starts_with('v')
                && p[1..]
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false)
                || p.chars()
                    .next()
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false)
                    && p.contains('.')
        });
        let name = parts
            .iter()
            .rev()
            .find(|p| !p.is_empty() && !p.contains('.') && !p.starts_with('v') && p.len() > 1);
        (name.map(|s| s.to_string()), version.map(|s| s.to_string()))
    }

    fn extract_webpack_plugins(&self, content: &str, path: &str) -> Vec<ShadowDependency> {
        let mut deps = Vec::new();
        let re = regex::Regex::new(r#"require\(\s*['"]([^'"]+)['"]\s*\)"#)
            .unwrap_or_else(|_| regex::Regex::new(r"$^").unwrap());
        for cap in re.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                let name = m.as_str();
                if name.contains("plugin") || name.contains("loader") {
                    deps.push(ShadowDependency {
                        name: name.to_string(),
                        version: None,
                        dep_type: if name.contains("loader") {
                            ShadowDependencyType::WebpackLoader
                        } else {
                            ShadowDependencyType::BuildPlugin
                        },
                        source_url: None,
                        pinned: false,
                        sri_hash: None,
                        maintainer_count: None,
                        last_update: None,
                        transitive_depth: 1,
                        evidence_location: path.to_string(),
                    });
                }
            }
        }
        deps
    }

    fn extract_babel_plugins(&self, content: &str, path: &str) -> Vec<ShadowDependency> {
        let mut deps = Vec::new();
        let re = regex::Regex::new(r#"["'](@babel/plugin-[^"']+|babel-plugin-[^"']+)["']"#)
            .unwrap_or_else(|_| regex::Regex::new(r"$^").unwrap());
        for cap in re.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                deps.push(ShadowDependency {
                    name: m.as_str().to_string(),
                    version: None,
                    dep_type: ShadowDependencyType::BabelPlugin,
                    source_url: None,
                    pinned: false,
                    sri_hash: None,
                    maintainer_count: None,
                    last_update: None,
                    transitive_depth: 1,
                    evidence_location: path.to_string(),
                });
            }
        }
        deps
    }

    fn extract_maven_plugins(&self, content: &str, path: &str) -> Vec<ShadowDependency> {
        let mut deps = Vec::new();
        let mut in_plugin = false;
        let mut artifact_id = None;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.contains("<plugin>") {
                in_plugin = true;
            }
            if in_plugin {
                if let Some(aid) = Self::extract_xml_value(trimmed, "artifactId") {
                    artifact_id = Some(aid);
                }
                if trimmed.contains("</plugin>") {
                    if let Some(name) = artifact_id.take() {
                        deps.push(ShadowDependency {
                            name,
                            version: None,
                            dep_type: ShadowDependencyType::MavenPlugin,
                            source_url: None,
                            pinned: false,
                            sri_hash: None,
                            maintainer_count: None,
                            last_update: None,
                            transitive_depth: 1,
                            evidence_location: path.to_string(),
                        });
                    }
                    in_plugin = false;
                }
            }
        }
        deps
    }

    fn extract_gradle_plugins(&self, content: &str, path: &str) -> Vec<ShadowDependency> {
        let mut deps = Vec::new();
        let re = regex::Regex::new(r#"id\s*\(\s*['"]([^'"]+)['"]"#)
            .unwrap_or_else(|_| regex::Regex::new(r"$^").unwrap());
        for cap in re.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                deps.push(ShadowDependency {
                    name: m.as_str().to_string(),
                    version: None,
                    dep_type: ShadowDependencyType::GradlePlugin,
                    source_url: None,
                    pinned: false,
                    sri_hash: None,
                    maintainer_count: None,
                    last_update: None,
                    transitive_depth: 1,
                    evidence_location: path.to_string(),
                });
            }
        }
        deps
    }

    fn extract_xml_value(line: &str, tag: &str) -> Option<String> {
        let open = format!("<{}>", tag);
        let close = format!("</{}>", tag);
        if let Some(start) = line.find(&open) {
            if let Some(end) = line.find(&close) {
                let val_start = start + open.len();
                if val_start < end {
                    return Some(line[val_start..end].to_string());
                }
            }
        }
        None
    }

    fn classify_typosquat(suspicious: &str, legitimate: &str) -> TyposquatTechnique {
        if suspicious.len() == legitimate.len() - 1 {
            TyposquatTechnique::MissingCharacter
        } else if suspicious.len() == legitimate.len() + 1 {
            TyposquatTechnique::ExtraCharacter
        } else if suspicious.replace('-', "") == legitimate.replace('-', "") {
            TyposquatTechnique::HyphenOmission
        } else if suspicious.contains('/') != legitimate.contains('/') {
            TyposquatTechnique::ScopeConfusion
        } else {
            TyposquatTechnique::CharacterSwap
        }
    }
}

/// Levenshtein distance between two strings.
fn levenshtein(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();
    let mut matrix = vec![vec![0usize; b_len + 1]; a_len + 1];

    for i in 0..=a_len {
        matrix[i][0] = i;
    }
    for j in 0..=b_len {
        matrix[0][j] = j;
    }

    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    for i in 1..=a_len {
        for j in 1..=b_len {
            let cost = if a_bytes[i - 1] == b_bytes[j - 1] {
                0
            } else {
                1
            };
            matrix[i][j] = (matrix[i - 1][j] + 1)
                .min(matrix[i][j - 1] + 1)
                .min(matrix[i - 1][j - 1] + cost);
        }
    }
    matrix[a_len][b_len]
}

fn default_known_packages() -> Vec<String> {
    vec![
        "lodash",
        "express",
        "react",
        "webpack",
        "babel-core",
        "typescript",
        "eslint",
        "prettier",
        "jest",
        "mocha",
        "axios",
        "moment",
        "chalk",
        "commander",
        "debug",
        "async",
        "request",
        "underscore",
        "bluebird",
        "uuid",
        "minimist",
        "glob",
        "rimraf",
        "mkdirp",
        "yargs",
        "semver",
        "dotenv",
        "cors",
        "body-parser",
        "passport",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}
