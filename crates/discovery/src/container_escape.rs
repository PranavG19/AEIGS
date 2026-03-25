/// Container escape detection for Docker and Kubernetes misconfigurations.
///
/// Parses K8s YAML manifests, Docker Compose files, and Dockerfiles to identify
/// configurations that allow container breakout: privileged mode, mounted sockets,
/// dangerous capabilities, namespace sharing, writable host mounts, exposed service
/// account tokens, kubelet API exposure, missing RBAC, and known CVE patterns.
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum ContainerConfigType {
    KubernetesManifest,
    DockerCompose,
    Dockerfile,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EscapeCategory {
    PrivilegedContainer,
    MountedDockerSocket,
    DangerousCapability,
    HostNamespaceSharing,
    WritableHostMount,
    ServiceAccountTokenExposure,
    ExposedKubeletApi,
    DefaultNamespaceNoRbac,
    KnownCvePattern,
    InsecureDockerfile,
}

impl std::fmt::Display for EscapeCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrivilegedContainer => write!(f, "Privileged Container"),
            Self::MountedDockerSocket => write!(f, "Mounted Docker Socket"),
            Self::DangerousCapability => write!(f, "Dangerous Capability"),
            Self::HostNamespaceSharing => write!(f, "Host Namespace Sharing"),
            Self::WritableHostMount => write!(f, "Writable Host Mount"),
            Self::ServiceAccountTokenExposure => write!(f, "Service Account Token Exposure"),
            Self::ExposedKubeletApi => write!(f, "Exposed Kubelet API"),
            Self::DefaultNamespaceNoRbac => write!(f, "Default Namespace Without RBAC"),
            Self::KnownCvePattern => write!(f, "Known CVE Pattern"),
            Self::InsecureDockerfile => write!(f, "Insecure Dockerfile"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ContainerEscapeFinding {
    pub category: EscapeCategory,
    pub description: String,
    pub severity: f64,
    pub container_name: Option<String>,
    pub resource_name: Option<String>,
    pub remediation: String,
}

#[derive(Debug, Clone)]
pub struct ContainerEscapeScanner {
    findings: Vec<ContainerEscapeFinding>,
}

const DANGEROUS_CAPABILITIES: &[&str] = &[
    "SYS_ADMIN",
    "SYS_PTRACE",
    "NET_ADMIN",
    "NET_RAW",
    "SYS_RAWIO",
    "DAC_OVERRIDE",
    "SETUID",
    "SETGID",
    "SYS_MODULE",
    "MKNOD",
    "SYS_CHROOT",
];

const DANGEROUS_HOST_PATHS: &[&str] = &[
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/var/run/crio/crio.sock",
    "/proc",
    "/sys",
    "/etc/shadow",
    "/etc/passwd",
    "/root",
    "/",
];

const KNOWN_CVE_PATTERNS: &[(&str, &str, f64)] = &[
    (
        "runc",
        "CVE-2024-21626: runc working directory breakout via leaked fd",
        10.0,
    ),
    (
        "cve-2020-15257",
        "CVE-2020-15257: containerd-shim host network access",
        8.5,
    ),
    (
        "cve-2019-5736",
        "CVE-2019-5736: runc container breakout via /proc/self/exe overwrite",
        9.8,
    ),
    (
        "cve-2022-0185",
        "CVE-2022-0185: Linux kernel heap overflow in legacy_parse_param",
        8.4,
    ),
    (
        "cve-2022-0492",
        "CVE-2022-0492: cgroups v1 escape via release_agent",
        7.8,
    ),
];

fn severity_for_capability(cap: &str) -> f64 {
    match cap {
        "SYS_ADMIN" => 9.5,
        "SYS_PTRACE" => 8.5,
        "NET_ADMIN" => 7.5,
        "NET_RAW" => 6.5,
        "SYS_RAWIO" => 8.0,
        "DAC_OVERRIDE" => 7.0,
        "SETUID" | "SETGID" => 6.0,
        "SYS_MODULE" => 9.0,
        "MKNOD" => 5.5,
        "SYS_CHROOT" => 6.0,
        _ => 4.0,
    }
}

fn severity_for_host_path(path: &str) -> f64 {
    match path {
        "/var/run/docker.sock" | "/run/containerd/containerd.sock" | "/var/run/crio/crio.sock" => {
            9.5
        }
        "/" => 9.0,
        "/proc" | "/sys" => 8.5,
        "/etc/shadow" | "/etc/passwd" | "/root" => 7.5,
        _ => 5.0,
    }
}

impl ContainerEscapeScanner {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }

    pub fn scan_yaml(&mut self, yaml_content: &str) -> &[ContainerEscapeFinding] {
        self.findings.clear();
        let docs = split_yaml_documents(yaml_content);
        for doc in &docs {
            let kind = detect_config_type(doc);
            match kind {
                ContainerConfigType::KubernetesManifest => self.scan_k8s_manifest(doc),
                ContainerConfigType::DockerCompose => self.scan_docker_compose(doc),
                ContainerConfigType::Dockerfile => {}
            }
        }
        &self.findings
    }

    pub fn scan_dockerfile(&mut self, dockerfile_content: &str) -> &[ContainerEscapeFinding] {
        self.findings.clear();
        self.check_dockerfile(dockerfile_content);
        &self.findings
    }

    pub fn findings(&self) -> &[ContainerEscapeFinding] {
        &self.findings
    }

    fn scan_k8s_manifest(&mut self, doc: &str) {
        let lines: Vec<&str> = doc.lines().collect();
        let resource_name = extract_yaml_value(&lines, "name");
        let containers = extract_containers(&lines);

        for container in &containers {
            self.check_privileged(container, &resource_name);
            self.check_capabilities(container, &resource_name);
            self.check_host_mounts(container, &resource_name);
            self.check_docker_socket_mount(container, &resource_name);
        }

        self.check_host_namespaces(&lines, &resource_name);
        self.check_service_account_token(&lines, &resource_name);
        self.check_kubelet_exposure(&lines, &resource_name);
        self.check_default_namespace_rbac(&lines, &resource_name);
        self.check_known_cves(doc, &resource_name);
    }

    fn scan_docker_compose(&mut self, doc: &str) {
        let lines: Vec<&str> = doc.lines().collect();
        let services = extract_compose_services(&lines);

        for (service_name, service_lines) in &services {
            let refs: Vec<&str> = service_lines.iter().map(|s| s.as_str()).collect();
            self.check_compose_privileged(&refs, service_name);
            self.check_compose_volumes(&refs, service_name);
            self.check_compose_cap_add(&refs, service_name);
            self.check_compose_pid_network(&refs, service_name);
            self.check_compose_security_opt(&refs, service_name);
        }

        self.check_known_cves(doc, &None);
    }

    fn check_privileged(&mut self, container: &ContainerBlock, resource_name: &Option<String>) {
        for line in &container.lines {
            let trimmed = line.trim();
            if trimmed.starts_with("privileged:")
                && (trimmed.contains("true") || trimmed.contains("True"))
            {
                self.findings.push(ContainerEscapeFinding {
                    category: EscapeCategory::PrivilegedContainer,
                    description: format!(
                        "Container '{}' runs in privileged mode, granting full host access",
                        container.name.as_deref().unwrap_or("unknown")
                    ),
                    severity: 9.8,
                    container_name: container.name.clone(),
                    resource_name: resource_name.clone(),
                    remediation:
                        "Remove 'privileged: true' and grant only specific capabilities needed"
                            .to_string(),
                });
            }
        }
    }

    fn check_capabilities(&mut self, container: &ContainerBlock, resource_name: &Option<String>) {
        let mut in_add_block = false;
        for line in &container.lines {
            let trimmed = line.trim();
            if trimmed == "add:" || trimmed.starts_with("add:") {
                in_add_block = true;
                let inline = trimmed.trim_start_matches("add:").trim();
                if inline.starts_with('[') {
                    self.parse_inline_caps(inline, container, resource_name);
                    in_add_block = false;
                }
                continue;
            }
            if in_add_block {
                if trimmed.starts_with("- ") {
                    let cap = trimmed
                        .trim_start_matches("- ")
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'');
                    self.check_single_capability(cap, container, resource_name);
                } else if trimmed.starts_with("drop:") || !trimmed.starts_with('-') {
                    in_add_block = false;
                }
            }
        }
    }

    fn parse_inline_caps(
        &mut self,
        inline: &str,
        container: &ContainerBlock,
        resource_name: &Option<String>,
    ) {
        let inner = inline.trim_start_matches('[').trim_end_matches(']').trim();
        for cap in inner.split(',') {
            let cap = cap.trim().trim_matches('"').trim_matches('\'');
            if !cap.is_empty() {
                self.check_single_capability(cap, container, resource_name);
            }
        }
    }

    fn check_single_capability(
        &mut self,
        cap: &str,
        container: &ContainerBlock,
        resource_name: &Option<String>,
    ) {
        let cap_upper = cap.to_uppercase();
        if DANGEROUS_CAPABILITIES.contains(&cap_upper.as_str()) {
            self.findings.push(ContainerEscapeFinding {
                category: EscapeCategory::DangerousCapability,
                description: format!(
                    "Container '{}' granted dangerous capability {}",
                    container.name.as_deref().unwrap_or("unknown"),
                    cap_upper
                ),
                severity: severity_for_capability(&cap_upper),
                container_name: container.name.clone(),
                resource_name: resource_name.clone(),
                remediation: format!(
                    "Remove {} capability; use least-privilege approach",
                    cap_upper
                ),
            });
        }
    }

    fn check_host_mounts(&mut self, container: &ContainerBlock, resource_name: &Option<String>) {
        let mut in_volume_mounts = false;
        let mut current_mount_path: Option<String> = None;
        let mut current_readonly = false;

        for line in &container.lines {
            let trimmed = line.trim();
            if trimmed == "volumeMounts:" {
                in_volume_mounts = true;
                continue;
            }
            if in_volume_mounts {
                if trimmed.starts_with("- ") && trimmed.contains("mountPath:") {
                    if let Some(path) = &current_mount_path {
                        self.emit_host_mount_finding(
                            path,
                            current_readonly,
                            container,
                            resource_name,
                        );
                    }
                    let mp = extract_after_key(trimmed, "mountPath:");
                    current_mount_path = Some(mp);
                    current_readonly = false;
                } else if trimmed.starts_with("mountPath:") {
                    let mp = extract_after_key(trimmed, "mountPath:");
                    current_mount_path = Some(mp);
                } else if trimmed.starts_with("readOnly:") {
                    current_readonly = trimmed.contains("true");
                } else if trimmed.starts_with("- name:")
                    || (!trimmed.starts_with("name:")
                        && !trimmed.starts_with("readOnly:")
                        && !trimmed.starts_with("mountPath:")
                        && !trimmed.starts_with("subPath:")
                        && !trimmed.starts_with("- ")
                        && !trimmed.is_empty()
                        && !trimmed.starts_with('#'))
                {
                    if let Some(path) = &current_mount_path {
                        self.emit_host_mount_finding(
                            path,
                            current_readonly,
                            container,
                            resource_name,
                        );
                    }
                    current_mount_path = None;
                    in_volume_mounts = false;
                }
            }
        }
        if let Some(path) = &current_mount_path {
            self.emit_host_mount_finding(path, current_readonly, container, resource_name);
        }
    }

    fn emit_host_mount_finding(
        &mut self,
        path: &str,
        readonly: bool,
        container: &ContainerBlock,
        resource_name: &Option<String>,
    ) {
        if DANGEROUS_HOST_PATHS.iter().any(|hp| path.starts_with(hp)) && !readonly {
            self.findings.push(ContainerEscapeFinding {
                category: EscapeCategory::WritableHostMount,
                description: format!(
                    "Container '{}' has writable mount to sensitive host path '{}'",
                    container.name.as_deref().unwrap_or("unknown"),
                    path
                ),
                severity: severity_for_host_path(path),
                container_name: container.name.clone(),
                resource_name: resource_name.clone(),
                remediation: format!(
                    "Set readOnly: true for '{}' or remove the mount entirely",
                    path
                ),
            });
        }
    }

    fn check_docker_socket_mount(
        &mut self,
        container: &ContainerBlock,
        resource_name: &Option<String>,
    ) {
        for line in &container.lines {
            let trimmed = line.trim();
            if trimmed.contains("/var/run/docker.sock")
                || trimmed.contains("/run/containerd/containerd.sock")
            {
                let already = self.findings.iter().any(|f| {
                    f.category == EscapeCategory::MountedDockerSocket
                        && f.container_name == container.name
                });
                if !already {
                    self.findings.push(ContainerEscapeFinding {
                        category: EscapeCategory::MountedDockerSocket,
                        description: format!(
                            "Container '{}' has container runtime socket mounted, enabling full host control",
                            container.name.as_deref().unwrap_or("unknown")
                        ),
                        severity: 9.5,
                        container_name: container.name.clone(),
                        resource_name: resource_name.clone(),
                        remediation: "Remove the Docker/containerd socket mount; use a dedicated container management API if needed".to_string(),
                    });
                }
            }
        }
    }

    fn check_host_namespaces(&mut self, lines: &[&str], resource_name: &Option<String>) {
        for line in lines {
            let trimmed = line.trim();
            if trimmed.starts_with("hostPID:")
                && (trimmed.contains("true") || trimmed.contains("True"))
            {
                self.findings.push(ContainerEscapeFinding {
                    category: EscapeCategory::HostNamespaceSharing,
                    description: "Pod shares host PID namespace, enabling process visibility and ptrace attacks".to_string(),
                    severity: 8.5,
                    container_name: None,
                    resource_name: resource_name.clone(),
                    remediation: "Set hostPID: false".to_string(),
                });
            }
            if trimmed.starts_with("hostNetwork:")
                && (trimmed.contains("true") || trimmed.contains("True"))
            {
                self.findings.push(ContainerEscapeFinding {
                    category: EscapeCategory::HostNamespaceSharing,
                    description: "Pod shares host network namespace, bypassing network policies"
                        .to_string(),
                    severity: 8.0,
                    container_name: None,
                    resource_name: resource_name.clone(),
                    remediation:
                        "Set hostNetwork: false and use Kubernetes Services for networking"
                            .to_string(),
                });
            }
            if trimmed.starts_with("hostIPC:")
                && (trimmed.contains("true") || trimmed.contains("True"))
            {
                self.findings.push(ContainerEscapeFinding {
                    category: EscapeCategory::HostNamespaceSharing,
                    description: "Pod shares host IPC namespace, enabling inter-process communication attacks".to_string(),
                    severity: 7.0,
                    container_name: None,
                    resource_name: resource_name.clone(),
                    remediation: "Set hostIPC: false".to_string(),
                });
            }
        }
    }

    fn check_service_account_token(&mut self, lines: &[&str], resource_name: &Option<String>) {
        let mut automount_found = false;
        let mut automount_true = false;
        for line in lines {
            let trimmed = line.trim();
            if trimmed.starts_with("automountServiceAccountToken:") {
                automount_found = true;
                automount_true = trimmed.contains("true") || trimmed.contains("True");
            }
        }
        if !automount_found || automount_true {
            let has_spec = lines.iter().any(|l| l.trim().starts_with("spec:"));
            let is_pod_or_deployment = lines.iter().any(|l| {
                let t = l.trim();
                t.starts_with("kind:")
                    && (t.contains("Pod")
                        || t.contains("Deployment")
                        || t.contains("StatefulSet")
                        || t.contains("DaemonSet")
                        || t.contains("ReplicaSet")
                        || t.contains("Job")
                        || t.contains("CronJob"))
            });
            if has_spec && is_pod_or_deployment {
                self.findings.push(ContainerEscapeFinding {
                    category: EscapeCategory::ServiceAccountTokenExposure,
                    description: "Service account token auto-mounted; if compromised, grants API server access".to_string(),
                    severity: 7.0,
                    container_name: None,
                    resource_name: resource_name.clone(),
                    remediation: "Set automountServiceAccountToken: false unless the pod requires API access".to_string(),
                });
            }
        }
    }

    fn check_kubelet_exposure(&mut self, lines: &[&str], resource_name: &Option<String>) {
        for line in lines {
            let trimmed = line.trim();
            if (trimmed.contains("10250") || trimmed.contains("10255"))
                && (trimmed.contains("containerPort")
                    || trimmed.contains("hostPort")
                    || trimmed.contains("port"))
            {
                self.findings.push(ContainerEscapeFinding {
                    category: EscapeCategory::ExposedKubeletApi,
                    description: "Kubelet API port exposed; unauthenticated access enables command execution on nodes".to_string(),
                    severity: 9.0,
                    container_name: None,
                    resource_name: resource_name.clone(),
                    remediation: "Do not expose kubelet ports (10250/10255); restrict with NetworkPolicy".to_string(),
                });
                break;
            }
        }
    }

    fn check_default_namespace_rbac(&mut self, lines: &[&str], resource_name: &Option<String>) {
        let mut namespace = None;
        let mut has_service_account = false;

        for line in lines {
            let trimmed = line.trim();
            if trimmed.starts_with("namespace:") {
                let ns = trimmed
                    .trim_start_matches("namespace:")
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'');
                namespace = Some(ns.to_string());
            }
            if trimmed.starts_with("serviceAccountName:") || trimmed.starts_with("serviceAccount:")
            {
                let sa = trimmed
                    .split(':')
                    .nth(1)
                    .unwrap_or("")
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'');
                if sa != "default" && !sa.is_empty() {
                    has_service_account = true;
                }
            }
        }

        let in_default = namespace.is_none() || namespace.as_deref() == Some("default");
        let is_workload = lines.iter().any(|l| {
            let t = l.trim();
            t.starts_with("kind:")
                && (t.contains("Pod")
                    || t.contains("Deployment")
                    || t.contains("StatefulSet")
                    || t.contains("DaemonSet"))
        });

        if in_default && is_workload && !has_service_account {
            self.findings.push(ContainerEscapeFinding {
                category: EscapeCategory::DefaultNamespaceNoRbac,
                description: "Workload in default namespace with default service account; broad permissions likely".to_string(),
                severity: 6.5,
                container_name: None,
                resource_name: resource_name.clone(),
                remediation: "Deploy to a dedicated namespace with a least-privilege service account and RBAC bindings".to_string(),
            });
        }
    }

    fn check_known_cves(&mut self, doc: &str, resource_name: &Option<String>) {
        let lower = doc.to_lowercase();
        for (pattern, description, severity) in KNOWN_CVE_PATTERNS {
            if lower.contains(pattern) {
                self.findings.push(ContainerEscapeFinding {
                    category: EscapeCategory::KnownCvePattern,
                    description: description.to_string(),
                    severity: *severity,
                    container_name: None,
                    resource_name: resource_name.clone(),
                    remediation: format!(
                        "Upgrade container runtime to a version patched against {}",
                        description.split(':').next().unwrap_or("this CVE")
                    ),
                });
            }
        }
    }

    fn check_dockerfile(&mut self, content: &str) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("USER root") || trimmed == "USER 0" {
                self.findings.push(ContainerEscapeFinding {
                    category: EscapeCategory::InsecureDockerfile,
                    description: "Container runs as root user".to_string(),
                    severity: 7.0,
                    container_name: None,
                    resource_name: None,
                    remediation: "Add 'USER <non-root-uid>' to Dockerfile".to_string(),
                });
            }
            if trimmed.starts_with("RUN") && trimmed.contains("--privileged") {
                self.findings.push(ContainerEscapeFinding {
                    category: EscapeCategory::PrivilegedContainer,
                    description: "Dockerfile uses --privileged flag in RUN instruction".to_string(),
                    severity: 9.0,
                    container_name: None,
                    resource_name: None,
                    remediation: "Remove --privileged from RUN instructions".to_string(),
                });
            }
            if (trimmed.starts_with("COPY") || trimmed.starts_with("ADD"))
                && trimmed.contains("/var/run/docker.sock")
            {
                self.findings.push(ContainerEscapeFinding {
                    category: EscapeCategory::MountedDockerSocket,
                    description: "Dockerfile copies Docker socket into image".to_string(),
                    severity: 9.5,
                    container_name: None,
                    resource_name: None,
                    remediation: "Do not copy the Docker socket into images".to_string(),
                });
            }
            if trimmed.starts_with("ENV")
                && (trimmed.contains("PASSWORD")
                    || trimmed.contains("SECRET")
                    || trimmed.contains("API_KEY"))
            {
                self.findings.push(ContainerEscapeFinding {
                    category: EscapeCategory::InsecureDockerfile,
                    description: format!("Secrets hardcoded in ENV instruction: {}", trimmed),
                    severity: 6.5,
                    container_name: None,
                    resource_name: None,
                    remediation:
                        "Use build-time secrets or runtime secret injection instead of ENV"
                            .to_string(),
                });
            }
            if trimmed.starts_with("EXPOSE")
                && (trimmed.contains("10250") || trimmed.contains("10255"))
            {
                self.findings.push(ContainerEscapeFinding {
                    category: EscapeCategory::ExposedKubeletApi,
                    description: "Dockerfile exposes kubelet API port".to_string(),
                    severity: 8.0,
                    container_name: None,
                    resource_name: None,
                    remediation: "Do not expose kubelet ports in Dockerfiles".to_string(),
                });
            }
        }
        let has_user_switch = content.lines().any(|l| {
            let t = l.trim();
            t.starts_with("USER ") && !t.starts_with("USER root") && t != "USER 0"
        });
        let has_from = content.lines().any(|l| l.trim().starts_with("FROM"));
        if has_from && !has_user_switch {
            let already_root_finding = self
                .findings
                .iter()
                .any(|f| f.description.contains("runs as root"));
            if !already_root_finding {
                self.findings.push(ContainerEscapeFinding {
                    category: EscapeCategory::InsecureDockerfile,
                    description:
                        "Dockerfile has no USER instruction; container will run as root by default"
                            .to_string(),
                    severity: 6.0,
                    container_name: None,
                    resource_name: None,
                    remediation: "Add a non-root USER instruction before the CMD/ENTRYPOINT"
                        .to_string(),
                });
            }
        }
    }

    fn check_compose_privileged(&mut self, lines: &[&str], service_name: &str) {
        for line in lines.iter() {
            let trimmed = line.trim();
            if trimmed.starts_with("privileged:")
                && (trimmed.contains("true") || trimmed.contains("True"))
            {
                self.findings.push(ContainerEscapeFinding {
                    category: EscapeCategory::PrivilegedContainer,
                    description: format!(
                        "Compose service '{}' runs in privileged mode",
                        service_name
                    ),
                    severity: 9.8,
                    container_name: Some(service_name.to_string()),
                    resource_name: None,
                    remediation: "Remove 'privileged: true' from the service definition"
                        .to_string(),
                });
            }
        }
    }

    fn check_compose_volumes(&mut self, lines: &[&str], service_name: &str) {
        let mut in_volumes = false;
        for line in lines.iter() {
            let trimmed = line.trim();
            if trimmed == "volumes:" {
                in_volumes = true;
                continue;
            }
            if in_volumes {
                if trimmed.starts_with("- ") {
                    let vol = trimmed
                        .trim_start_matches("- ")
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'');
                    if vol.contains("/var/run/docker.sock") {
                        self.findings.push(ContainerEscapeFinding {
                            category: EscapeCategory::MountedDockerSocket,
                            description: format!(
                                "Compose service '{}' mounts Docker socket",
                                service_name
                            ),
                            severity: 9.5,
                            container_name: Some(service_name.to_string()),
                            resource_name: None,
                            remediation: "Remove the Docker socket volume mount".to_string(),
                        });
                    }
                    for hp in DANGEROUS_HOST_PATHS {
                        if vol.starts_with(hp) && !vol.contains(":ro") {
                            let is_socket = *hp == "/var/run/docker.sock"
                                || *hp == "/run/containerd/containerd.sock";
                            if !is_socket {
                                self.findings.push(ContainerEscapeFinding {
                                    category: EscapeCategory::WritableHostMount,
                                    description: format!(
                                        "Compose service '{}' has writable mount to '{}'",
                                        service_name, hp
                                    ),
                                    severity: severity_for_host_path(hp),
                                    container_name: Some(service_name.to_string()),
                                    resource_name: None,
                                    remediation: format!(
                                        "Add ':ro' to the volume mount or remove it: {}",
                                        vol
                                    ),
                                });
                            }
                        }
                    }
                } else if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    in_volumes = false;
                }
            }
        }
    }

    fn check_compose_cap_add(&mut self, lines: &[&str], service_name: &str) {
        let mut in_cap_add = false;
        for line in lines.iter() {
            let trimmed = line.trim();
            if trimmed == "cap_add:" {
                in_cap_add = true;
                continue;
            }
            if in_cap_add {
                if trimmed.starts_with("- ") {
                    let cap = trimmed
                        .trim_start_matches("- ")
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'');
                    let cap_upper = cap.to_uppercase();
                    if DANGEROUS_CAPABILITIES.contains(&cap_upper.as_str()) {
                        self.findings.push(ContainerEscapeFinding {
                            category: EscapeCategory::DangerousCapability,
                            description: format!(
                                "Compose service '{}' granted dangerous capability {}",
                                service_name, cap_upper
                            ),
                            severity: severity_for_capability(&cap_upper),
                            container_name: Some(service_name.to_string()),
                            resource_name: None,
                            remediation: format!("Remove {} from cap_add", cap_upper),
                        });
                    }
                } else if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    in_cap_add = false;
                }
            }
        }
    }

    fn check_compose_pid_network(&mut self, lines: &[&str], service_name: &str) {
        for line in lines.iter() {
            let trimmed = line.trim();
            if trimmed.starts_with("pid:") && trimmed.contains("host") {
                self.findings.push(ContainerEscapeFinding {
                    category: EscapeCategory::HostNamespaceSharing,
                    description: format!(
                        "Compose service '{}' shares host PID namespace",
                        service_name
                    ),
                    severity: 8.5,
                    container_name: Some(service_name.to_string()),
                    resource_name: None,
                    remediation: "Remove 'pid: host' from the service definition".to_string(),
                });
            }
            if trimmed.starts_with("network_mode:") && trimmed.contains("host") {
                self.findings.push(ContainerEscapeFinding {
                    category: EscapeCategory::HostNamespaceSharing,
                    description: format!(
                        "Compose service '{}' uses host network mode",
                        service_name
                    ),
                    severity: 8.0,
                    container_name: Some(service_name.to_string()),
                    resource_name: None,
                    remediation: "Use a dedicated Docker network instead of 'network_mode: host'"
                        .to_string(),
                });
            }
        }
    }

    fn check_compose_security_opt(&mut self, lines: &[&str], service_name: &str) {
        let mut in_security_opt = false;
        for line in lines.iter() {
            let trimmed = line.trim();
            if trimmed == "security_opt:" {
                in_security_opt = true;
                continue;
            }
            if in_security_opt {
                if trimmed.starts_with("- ") {
                    let opt = trimmed
                        .trim_start_matches("- ")
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'');
                    if opt.contains("apparmor:unconfined")
                        || opt.contains("seccomp:unconfined")
                        || opt == "no-new-privileges:false"
                    {
                        self.findings.push(ContainerEscapeFinding {
                            category: EscapeCategory::PrivilegedContainer,
                            description: format!(
                                "Compose service '{}' disables security profile: {}",
                                service_name, opt
                            ),
                            severity: 8.5,
                            container_name: Some(service_name.to_string()),
                            resource_name: None,
                            remediation: format!("Remove '{}' from security_opt", opt),
                        });
                    }
                } else if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    in_security_opt = false;
                }
            }
        }
    }
}

impl Default for ContainerEscapeScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct ContainerBlock {
    name: Option<String>,
    lines: Vec<String>,
}

fn split_yaml_documents(content: &str) -> Vec<String> {
    let mut docs = Vec::new();
    let mut current = String::new();
    for line in content.lines() {
        if line.starts_with("---") && !current.trim().is_empty() {
            docs.push(current.clone());
            current.clear();
        }
        current.push_str(line);
        current.push('\n');
    }
    if !current.trim().is_empty() {
        docs.push(current);
    }
    docs
}

fn detect_config_type(doc: &str) -> ContainerConfigType {
    let has_api_version = doc.lines().any(|l| l.trim().starts_with("apiVersion:"));
    let has_kind = doc.lines().any(|l| l.trim().starts_with("kind:"));
    if has_api_version && has_kind {
        return ContainerConfigType::KubernetesManifest;
    }
    let has_services = doc
        .lines()
        .any(|l| l.trim() == "services:" || l.trim().starts_with("services:"));
    let has_version = doc.lines().any(|l| l.trim().starts_with("version:"));
    if has_services || (has_version && !has_api_version) {
        return ContainerConfigType::DockerCompose;
    }
    ContainerConfigType::KubernetesManifest
}

fn extract_yaml_value(lines: &[&str], key: &str) -> Option<String> {
    let search = format!("{}:", key);
    for line in lines {
        let trimmed = line.trim();
        if trimmed.starts_with(&search) {
            let val = trimmed[search.len()..]
                .trim()
                .trim_matches('"')
                .trim_matches('\'');
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

fn extract_after_key(line: &str, key: &str) -> String {
    if let Some(idx) = line.find(key) {
        line[idx + key.len()..]
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string()
    } else {
        String::new()
    }
}

fn extract_containers(lines: &[&str]) -> Vec<ContainerBlock> {
    let mut containers = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed == "containers:" || trimmed == "initContainers:" {
            i += 1;
            while i < lines.len() {
                let t = lines[i].trim();
                if t.starts_with("- name:") || t.starts_with("- image:") {
                    let name = if t.starts_with("- name:") {
                        Some(
                            t.trim_start_matches("- name:")
                                .trim()
                                .trim_matches('"')
                                .trim_matches('\'')
                                .to_string(),
                        )
                    } else {
                        None
                    };
                    let mut block_lines = vec![lines[i].to_string()];
                    i += 1;
                    while i < lines.len() {
                        let inner = lines[i];
                        let inner_trimmed = inner.trim();
                        if inner_trimmed.starts_with("- name:")
                            || inner_trimmed.starts_with("- image:")
                        {
                            break;
                        }
                        let indent_level = inner.len() - inner.trim_start().len();
                        if indent_level == 0
                            && !inner_trimmed.is_empty()
                            && !inner_trimmed.starts_with('#')
                            && !inner_trimmed.starts_with('-')
                        {
                            let is_container_sub = [
                                "name:",
                                "image:",
                                "command:",
                                "args:",
                                "env:",
                                "ports:",
                                "volumeMounts:",
                                "securityContext:",
                                "privileged:",
                                "capabilities:",
                                "resources:",
                                "readinessProbe:",
                                "livenessProbe:",
                                "lifecycle:",
                                "terminationMessagePath:",
                                "terminationMessagePolicy:",
                                "imagePullPolicy:",
                                "stdin:",
                                "tty:",
                                "workingDir:",
                            ];
                            if !is_container_sub
                                .iter()
                                .any(|s| inner_trimmed.starts_with(s))
                            {
                                break;
                            }
                        }
                        block_lines.push(inner.to_string());
                        i += 1;
                    }
                    containers.push(ContainerBlock {
                        name,
                        lines: block_lines,
                    });
                } else if t.is_empty() || t.starts_with('#') {
                    i += 1;
                } else {
                    break;
                }
            }
        } else {
            i += 1;
        }
    }
    containers
}

fn extract_compose_services(lines: &[&str]) -> HashMap<String, Vec<String>> {
    let mut services: HashMap<String, Vec<String>> = HashMap::new();
    let mut in_services = false;
    let mut current_service: Option<String> = None;
    let mut service_indent = 0;

    for line in lines {
        let trimmed = line.trim();
        if trimmed == "services:" {
            in_services = true;
            continue;
        }
        if !in_services {
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            if let Some(ref svc) = current_service {
                services
                    .entry(svc.clone())
                    .or_default()
                    .push(line.to_string());
            }
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent == 0 && trimmed != "services:" {
            in_services = false;
            current_service = None;
            continue;
        }
        if current_service.is_some()
            && indent <= service_indent
            && trimmed.ends_with(':')
            && !trimmed.starts_with('-')
        {
            let name = trimmed.trim_end_matches(':').trim().to_string();
            service_indent = indent;
            current_service = Some(name.clone());
            services.entry(name).or_default();
            continue;
        }
        if current_service.is_none()
            || (indent <= service_indent
                && trimmed.ends_with(':')
                && !trimmed.starts_with('-')
                && !trimmed.contains(": "))
        {
            let name = trimmed.trim_end_matches(':').trim().to_string();
            service_indent = indent;
            current_service = Some(name.clone());
            services.entry(name).or_default();
            continue;
        }
        if let Some(ref svc) = current_service {
            services
                .entry(svc.clone())
                .or_default()
                .push(line.to_string());
        }
    }
    services
}
