use super::supply_chain_shadow::*;

#[test]
fn test_shadow_dependency_type_display() {
    assert_eq!(
        ShadowDependencyType::BuildPlugin.to_string(),
        "Build Plugin"
    );
    assert_eq!(
        ShadowDependencyType::DockerBaseImage.to_string(),
        "Docker Base Image"
    );
    assert_eq!(
        ShadowDependencyType::GithubAction.to_string(),
        "GitHub Action"
    );
    assert_eq!(ShadowDependencyType::CdnScript.to_string(), "CDN Script");
}

#[test]
fn test_supply_chain_risk_ordering() {
    assert!(SupplyChainRisk::Low < SupplyChainRisk::Medium);
    assert!(SupplyChainRisk::Medium < SupplyChainRisk::High);
    assert!(SupplyChainRisk::High < SupplyChainRisk::Critical);
}

#[test]
fn test_maintainer_security_ordering() {
    assert!(MaintainerSecurity::Unknown < MaintainerSecurity::Weak);
    assert!(MaintainerSecurity::Weak < MaintainerSecurity::Strong);
}

#[test]
fn test_maintainer_event_type_display() {
    assert_eq!(
        MaintainerEventType::OwnershipTransfer.to_string(),
        "Ownership Transfer"
    );
    assert_eq!(
        MaintainerEventType::RepoTransfer.to_string(),
        "Repository Transfer"
    );
}

#[test]
fn test_typosquat_technique_display() {
    assert_eq!(
        TyposquatTechnique::CharacterSwap.to_string(),
        "Character Swap"
    );
    assert_eq!(
        TyposquatTechnique::HyphenOmission.to_string(),
        "Hyphen Omission"
    );
}

#[test]
fn test_default_config() {
    let config = ShadowMapperConfig::default();
    assert!(config.scan_dockerfiles);
    assert!(config.scan_ci_workflows);
    assert!(config.scan_cdn_scripts);
    assert!(config.detect_typosquats);
    assert_eq!(config.levenshtein_threshold, 2);
    assert!(!config.known_packages.is_empty());
}

#[test]
fn test_config_builder() {
    let config = ShadowMapperConfig::default()
        .with_scan_dockerfiles(false)
        .with_detect_typosquats(false)
        .with_levenshtein_threshold(3);
    assert!(!config.scan_dockerfiles);
    assert!(!config.detect_typosquats);
    assert_eq!(config.levenshtein_threshold, 3);
}

#[test]
fn test_parse_dockerfile_simple() {
    let mapper = SupplyChainShadowMapper::new(ShadowMapperConfig::default());
    let dockerfiles = vec![(
        "Dockerfile",
        "FROM node:18-alpine\nRUN npm install\nCOPY . .\n",
    )];
    let lineage = mapper.parse_dockerfiles(&dockerfiles);
    assert_eq!(lineage.len(), 1);
    assert_eq!(lineage[0].image, "node");
    assert_eq!(lineage[0].tag, "18-alpine");
    assert_eq!(lineage[0].registry, "Docker Hub");
    assert!(lineage[0].digest.is_none());
}

#[test]
fn test_parse_dockerfile_with_digest() {
    let mapper = SupplyChainShadowMapper::new(ShadowMapperConfig::default());
    let dockerfiles = vec![("Dockerfile", "FROM node:18@sha256:abc123def456\n")];
    let lineage = mapper.parse_dockerfiles(&dockerfiles);
    assert_eq!(lineage.len(), 1);
    assert!(lineage[0].digest.is_some());
    assert!(lineage[0].digest.is_some());
}

#[test]
fn test_parse_dockerfile_multistage() {
    let mapper = SupplyChainShadowMapper::new(ShadowMapperConfig::default());
    let dockerfiles = vec![(
        "Dockerfile",
        "FROM golang:1.21 AS builder\nRUN go build\nFROM alpine:3.18\nCOPY --from=builder /app /app\n",
    )];
    let lineage = mapper.parse_dockerfiles(&dockerfiles);
    assert_eq!(lineage.len(), 2);
    assert_eq!(lineage[0].image, "golang");
    assert_eq!(lineage[1].image, "alpine");
    assert_eq!(lineage[1].parent_image.as_deref(), Some("golang"));
}

#[test]
fn test_parse_dockerfile_disabled() {
    let config = ShadowMapperConfig::default().with_scan_dockerfiles(false);
    let mapper = SupplyChainShadowMapper::new(config);
    let result = mapper.parse_dockerfiles(&[("Dockerfile", "FROM node:18\n")]);
    assert!(result.is_empty());
}

#[test]
fn test_parse_ci_workflows_github_actions() {
    let mapper = SupplyChainShadowMapper::new(ShadowMapperConfig::default());
    let workflows = vec![(
        ".github/workflows/ci.yml",
        r#"
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v3
      - uses: some-org/custom-action@abc123def456abc123def456abc123def456abcd
"#,
    )];
    let deps = mapper.parse_ci_workflows(&workflows);
    assert_eq!(deps.len(), 3);
    assert_eq!(deps[0].owner, "actions");
    assert_eq!(deps[0].repo, "checkout");
    assert_eq!(deps[0].version_ref, "v4");
    assert!(!deps[0].pinned_to_sha);
    assert!(deps[2].pinned_to_sha);
}

#[test]
fn test_parse_ci_workflows_disabled() {
    let config = ShadowMapperConfig::default().with_scan_ci_workflows(false);
    let mapper = SupplyChainShadowMapper::new(config);
    let result =
        mapper.parse_ci_workflows(&[(".github/workflows/ci.yml", "- uses: actions/checkout@v4")]);
    assert!(result.is_empty());
}

#[test]
fn test_extract_cdn_scripts() {
    let mapper = SupplyChainShadowMapper::new(ShadowMapperConfig::default());
    let pages = vec![(
        "https://example.com",
        r#"<html>
<head>
<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js" integrity="sha384-abc123" crossorigin="anonymous"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.29.4/moment.min.js"></script>
<script src="/local/app.js"></script>
</head></html>"#,
    )];
    let scripts = mapper.extract_cdn_scripts(&pages);
    assert_eq!(scripts.len(), 2);
    assert_eq!(scripts[0].cdn_provider, "jsDelivr");
    assert!(scripts[0].sri_hash.is_some());
    assert!(scripts[0].crossorigin_set);
    assert_eq!(scripts[1].cdn_provider, "Cloudflare CDNJS");
    assert!(scripts[1].sri_hash.is_none());
}

#[test]
fn test_detect_typosquats() {
    let mapper = SupplyChainShadowMapper::new(ShadowMapperConfig::default());
    let candidates = mapper.detect_typosquats(&["loodash", "expresss", "react"]);
    let lodash_typo = candidates
        .iter()
        .find(|c| c.suspicious_package == "loodash");
    assert!(
        lodash_typo.is_some(),
        "Should detect loodash as typosquat of lodash"
    );
    let express_typo = candidates
        .iter()
        .find(|c| c.suspicious_package == "expresss");
    assert!(
        express_typo.is_some(),
        "Should detect expresss as typosquat"
    );
    let react_match = candidates.iter().find(|c| c.suspicious_package == "react");
    assert!(react_match.is_none(), "Exact match should not be flagged");
}

#[test]
fn test_detect_typosquats_disabled() {
    let config = ShadowMapperConfig::default().with_detect_typosquats(false);
    let mapper = SupplyChainShadowMapper::new(config);
    let candidates = mapper.detect_typosquats(&["loodash"]);
    assert!(candidates.is_empty());
}

#[test]
fn test_blast_radius_assessment() {
    let mapper = SupplyChainShadowMapper::new(ShadowMapperConfig::default());
    let deps = vec![
        ShadowDependency {
            name: "unpinned-dep".to_string(),
            version: None,
            dep_type: ShadowDependencyType::BuildPlugin,
            source_url: None,
            pinned: false,
            sri_hash: None,
            maintainer_count: Some(1),
            last_update: None,
            transitive_depth: 4,
            evidence_location: "webpack.config.js".to_string(),
        },
        ShadowDependency {
            name: "pinned-dep".to_string(),
            version: Some("1.2.3".to_string()),
            dep_type: ShadowDependencyType::GithubAction,
            source_url: None,
            pinned: true,
            sri_hash: None,
            maintainer_count: Some(10),
            last_update: None,
            transitive_depth: 0,
            evidence_location: ".github/workflows/ci.yml".to_string(),
        },
    ];
    let assessments = mapper.assess_blast_radius(&deps);
    assert_eq!(assessments.len(), 2);
    assert!(
        assessments[0].blast_radius_score > assessments[1].blast_radius_score,
        "Unpinned, single-maintainer, deep dep should have higher blast radius"
    );
    assert_eq!(assessments[0].maintainer_security, MaintainerSecurity::Weak);
    assert_eq!(
        assessments[1].maintainer_security,
        MaintainerSecurity::Strong
    );
}

#[test]
fn test_parse_webpack_plugins() {
    let mapper = SupplyChainShadowMapper::new(ShadowMapperConfig::default());
    let build_files = vec![(
        "webpack.config.js",
        r#"
const HtmlPlugin = require('html-webpack-plugin');
const TerserPlugin = require('terser-webpack-plugin');
const CssLoader = require('css-loader');
"#,
    )];
    let deps = mapper.parse_build_plugins(&build_files);
    assert!(!deps.is_empty());
    assert!(deps.iter().any(|d| d.name == "html-webpack-plugin"));
}

#[test]
fn test_parse_babel_plugins() {
    let mapper = SupplyChainShadowMapper::new(ShadowMapperConfig::default());
    let build_files = vec![(
        ".babelrc",
        r#"{ "plugins": ["@babel/plugin-transform-runtime", "babel-plugin-styled-components"] }"#,
    )];
    let deps = mapper.parse_build_plugins(&build_files);
    assert_eq!(deps.len(), 2);
    assert!(deps
        .iter()
        .all(|d| d.dep_type == ShadowDependencyType::BabelPlugin));
}

#[test]
fn test_parse_maven_plugins() {
    let mapper = SupplyChainShadowMapper::new(ShadowMapperConfig::default());
    let build_files = vec![(
        "pom.xml",
        r#"<project>
  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
      </plugin>
    </plugins>
  </build>
</project>"#,
    )];
    let deps = mapper.parse_build_plugins(&build_files);
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "maven-compiler-plugin");
    assert_eq!(deps[0].dep_type, ShadowDependencyType::MavenPlugin);
}

#[test]
fn test_parse_gradle_plugins() {
    let mapper = SupplyChainShadowMapper::new(ShadowMapperConfig::default());
    let build_files = vec![(
        "build.gradle",
        r#"plugins {
    id("org.springframework.boot") version "3.1.0"
    id("com.github.node-gradle.node") version "5.0.0"
}"#,
    )];
    let deps = mapper.parse_build_plugins(&build_files);
    assert_eq!(deps.len(), 2);
    assert!(deps
        .iter()
        .all(|d| d.dep_type == ShadowDependencyType::GradlePlugin));
}

#[test]
fn test_full_analysis() {
    let mapper = SupplyChainShadowMapper::new(ShadowMapperConfig::default());
    let dockerfiles = vec![(
        "Dockerfile",
        "FROM python:3.11-slim\nRUN pip install flask\n",
    )];
    let ci_workflows = vec![(
        ".github/workflows/ci.yml",
        "    steps:\n      - uses: actions/checkout@v4\n",
    )];
    let html_pages = vec![(
        "https://example.com",
        r#"<script src="https://cdn.jsdelivr.net/npm/vue@3.3.4/dist/vue.global.min.js"></script>"#,
    )];
    let build_files: Vec<(&str, &str)> = vec![];
    let packages: Vec<&str> = vec!["loodash"];

    let result = mapper.analyze(
        &dockerfiles,
        &ci_workflows,
        &html_pages,
        &build_files,
        &packages,
    );
    assert!(!result.shadow_deps.is_empty());
    assert!(!result.cdn_scripts.is_empty());
    assert!(!result.docker_lineage.is_empty());
    assert!(!result.ci_deps.is_empty());
    assert!(!result.typosquat_candidates.is_empty());
    assert!(!result.summary.is_empty());
}

#[test]
fn test_empty_analysis() {
    let mapper = SupplyChainShadowMapper::new(ShadowMapperConfig::default());
    let result = mapper.analyze(&[], &[], &[], &[], &[]);
    assert!(result.shadow_deps.is_empty());
    assert!(result.cdn_scripts.is_empty());
    assert!(result.docker_lineage.is_empty());
    assert!(result.ci_deps.is_empty());
}

#[test]
fn test_docker_registry_detection() {
    let mapper = SupplyChainShadowMapper::new(ShadowMapperConfig::default());
    let dockerfiles = vec![
        ("Dockerfile.gcr", "FROM gcr.io/project/image:v1\n"),
        ("Dockerfile.ghcr", "FROM ghcr.io/owner/image:latest\n"),
        (
            "Dockerfile.ecr",
            "FROM 123456789.dkr.ecr.us-east-1.amazonaws.com/app:v2\n",
        ),
    ];
    let lineage = mapper.parse_dockerfiles(&dockerfiles);
    assert_eq!(lineage[0].registry, "Google Container Registry");
    assert_eq!(lineage[1].registry, "GitHub Container Registry");
    assert_eq!(lineage[2].registry, "AWS ECR");
}
