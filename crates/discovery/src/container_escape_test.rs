use crate::container_escape::{ContainerEscapeScanner, EscapeCategory};

fn k8s_pod(spec_body: &str) -> String {
    format!(
        r#"apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
spec:
  containers:
{}"#,
        spec_body
    )
}

fn compose(services_body: &str) -> String {
    format!(
        r#"version: "3"
services:
{}"#,
        services_body
    )
}

#[test]
fn detects_privileged_container() {
    let yaml = k8s_pod(
        r#"    - name: evil
      image: alpine
      securityContext:
        privileged: true"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(&yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.category == EscapeCategory::PrivilegedContainer)
    );
    let priv_finding = findings
        .iter()
        .find(|f| f.category == EscapeCategory::PrivilegedContainer)
        .unwrap();
    assert!(priv_finding.severity >= 9.0);
    assert!(priv_finding.container_name.as_deref() == Some("evil"));
}

#[test]
fn no_false_positive_privileged_false() {
    let yaml = k8s_pod(
        r#"    - name: safe
      image: alpine
      securityContext:
        privileged: false"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(&yaml);
    assert!(
        !findings
            .iter()
            .any(|f| f.category == EscapeCategory::PrivilegedContainer)
    );
}

#[test]
fn detects_docker_socket_mount_k8s() {
    let yaml = r#"apiVersion: v1
kind: Pod
metadata:
  name: socket-pod
spec:
  volumes:
    - name: docker-sock
      hostPath:
        path: /var/run/docker.sock
  containers:
    - name: dind
      image: docker:latest
      volumeMounts:
        - name: docker-sock
          mountPath: /var/run/docker.sock"#;
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.category == EscapeCategory::MountedDockerSocket)
    );
}

#[test]
fn detects_sys_admin_capability() {
    let yaml = k8s_pod(
        r#"    - name: admin-pod
      image: alpine
      securityContext:
        capabilities:
          add:
            - SYS_ADMIN"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(&yaml);
    assert!(findings.iter().any(|f| {
        f.category == EscapeCategory::DangerousCapability && f.description.contains("SYS_ADMIN")
    }));
}

#[test]
fn detects_sys_ptrace_capability() {
    let yaml = k8s_pod(
        r#"    - name: debugger
      image: alpine
      securityContext:
        capabilities:
          add:
            - SYS_PTRACE"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(&yaml);
    let f = findings
        .iter()
        .find(|f| f.description.contains("SYS_PTRACE"))
        .unwrap();
    assert_eq!(f.category, EscapeCategory::DangerousCapability);
    assert!(f.severity >= 8.0);
}

#[test]
fn detects_net_admin_capability() {
    let yaml = k8s_pod(
        r#"    - name: netadmin
      image: alpine
      securityContext:
        capabilities:
          add:
            - NET_ADMIN"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(&yaml);
    assert!(findings.iter().any(|f| f.description.contains("NET_ADMIN")));
}

#[test]
fn detects_multiple_capabilities() {
    let yaml = k8s_pod(
        r#"    - name: multi-cap
      image: alpine
      securityContext:
        capabilities:
          add:
            - SYS_ADMIN
            - SYS_PTRACE
            - NET_RAW"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(&yaml);
    let cap_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == EscapeCategory::DangerousCapability)
        .collect();
    assert!(cap_findings.len() >= 3);
}

#[test]
fn detects_host_pid_namespace() {
    let yaml = r#"apiVersion: v1
kind: Pod
metadata:
  name: hostpid-pod
spec:
  hostPID: true
  containers:
    - name: spy
      image: alpine"#;
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(yaml);
    assert!(findings.iter().any(|f| {
        f.category == EscapeCategory::HostNamespaceSharing && f.description.contains("PID")
    }));
}

#[test]
fn detects_host_network_namespace() {
    let yaml = r#"apiVersion: v1
kind: Pod
metadata:
  name: hostnet-pod
spec:
  hostNetwork: true
  containers:
    - name: netspy
      image: alpine"#;
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(yaml);
    assert!(findings.iter().any(|f| {
        f.category == EscapeCategory::HostNamespaceSharing && f.description.contains("network")
    }));
}

#[test]
fn detects_host_ipc_namespace() {
    let yaml = r#"apiVersion: v1
kind: Pod
metadata:
  name: hostipc-pod
spec:
  hostIPC: true
  containers:
    - name: ipcspy
      image: alpine"#;
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(yaml);
    assert!(findings.iter().any(|f| {
        f.category == EscapeCategory::HostNamespaceSharing && f.description.contains("IPC")
    }));
}

#[test]
fn detects_writable_proc_mount() {
    let yaml = k8s_pod(
        r#"    - name: proc-reader
      image: alpine
      volumeMounts:
        - name: host-proc
          mountPath: /proc"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(&yaml);
    assert!(findings.iter().any(|f| {
        f.category == EscapeCategory::WritableHostMount && f.description.contains("/proc")
    }));
}

#[test]
fn readonly_mount_no_finding() {
    let yaml = k8s_pod(
        r#"    - name: safe-reader
      image: alpine
      volumeMounts:
        - name: host-proc
          mountPath: /proc
          readOnly: true"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(&yaml);
    assert!(!findings.iter().any(|f| {
        f.category == EscapeCategory::WritableHostMount && f.description.contains("/proc")
    }));
}

#[test]
fn detects_writable_root_mount() {
    let yaml = k8s_pod(
        r#"    - name: root-mounter
      image: alpine
      volumeMounts:
        - name: host-root
          mountPath: /"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(&yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.category == EscapeCategory::WritableHostMount)
    );
}

#[test]
fn detects_service_account_token_automounted() {
    let yaml = r#"apiVersion: v1
kind: Pod
metadata:
  name: sa-pod
spec:
  automountServiceAccountToken: true
  containers:
    - name: app
      image: alpine"#;
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.category == EscapeCategory::ServiceAccountTokenExposure)
    );
}

#[test]
fn detects_service_account_token_default() {
    let yaml = r#"apiVersion: v1
kind: Pod
metadata:
  name: sa-default-pod
spec:
  containers:
    - name: app
      image: alpine"#;
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.category == EscapeCategory::ServiceAccountTokenExposure)
    );
}

#[test]
fn no_sa_finding_when_disabled() {
    let yaml = r#"apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: production
spec:
  serviceAccountName: custom-sa
  automountServiceAccountToken: false
  containers:
    - name: app
      image: alpine"#;
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(yaml);
    assert!(
        !findings
            .iter()
            .any(|f| f.category == EscapeCategory::ServiceAccountTokenExposure)
    );
}

#[test]
fn detects_exposed_kubelet_port() {
    let yaml = r#"apiVersion: v1
kind: Pod
metadata:
  name: kubelet-exposed
spec:
  containers:
    - name: proxy
      image: nginx
      ports:
        - containerPort: 10250"#;
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.category == EscapeCategory::ExposedKubeletApi)
    );
}

#[test]
fn detects_default_namespace_no_rbac() {
    let yaml = r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-deploy
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: app
          image: alpine"#;
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.category == EscapeCategory::DefaultNamespaceNoRbac)
    );
}

#[test]
fn no_default_ns_finding_with_custom_sa() {
    let yaml = r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-deploy
  namespace: production
spec:
  replicas: 1
  template:
    spec:
      serviceAccountName: app-sa
      containers:
        - name: app
          image: alpine"#;
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(yaml);
    assert!(
        !findings
            .iter()
            .any(|f| f.category == EscapeCategory::DefaultNamespaceNoRbac)
    );
}

#[test]
fn detects_known_cve_runc() {
    let yaml = r#"apiVersion: v1
kind: Pod
metadata:
  name: runc-vuln
  annotations:
    runtime: runc
spec:
  containers:
    - name: app
      image: alpine"#;
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(yaml);
    assert!(findings.iter().any(|f| {
        f.category == EscapeCategory::KnownCvePattern && f.description.contains("CVE-2024-21626")
    }));
}

#[test]
fn detects_compose_privileged() {
    let yaml = compose(
        r#"  web:
    image: nginx
    privileged: true"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(&yaml);
    assert!(findings.iter().any(|f| {
        f.category == EscapeCategory::PrivilegedContainer
            && f.container_name.as_deref() == Some("web")
    }));
}

#[test]
fn detects_compose_docker_socket() {
    let yaml = compose(
        r#"  portainer:
    image: portainer/portainer
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(&yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.category == EscapeCategory::MountedDockerSocket)
    );
}

#[test]
fn detects_compose_cap_add() {
    let yaml = compose(
        r#"  nettools:
    image: alpine
    cap_add:
      - SYS_ADMIN
      - NET_ADMIN"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(&yaml);
    let cap_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == EscapeCategory::DangerousCapability)
        .collect();
    assert!(cap_findings.len() >= 2);
}

#[test]
fn detects_compose_host_pid() {
    let yaml = compose(
        r#"  debugger:
    image: alpine
    pid: host"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(&yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.category == EscapeCategory::HostNamespaceSharing)
    );
}

#[test]
fn detects_compose_host_network() {
    let yaml = compose(
        r#"  proxy:
    image: nginx
    network_mode: host"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(&yaml);
    assert!(findings.iter().any(|f| {
        f.category == EscapeCategory::HostNamespaceSharing && f.description.contains("host network")
    }));
}

#[test]
fn detects_compose_writable_host_mount() {
    let yaml = compose(
        r#"  mounter:
    image: alpine
    volumes:
      - /etc/shadow:/shadow"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(&yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.category == EscapeCategory::WritableHostMount)
    );
}

#[test]
fn compose_readonly_volume_no_finding() {
    let yaml = compose(
        r#"  reader:
    image: alpine
    volumes:
      - /etc/shadow:/shadow:ro"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(&yaml);
    assert!(!findings.iter().any(|f| {
        f.category == EscapeCategory::WritableHostMount && f.description.contains("/etc/shadow")
    }));
}

#[test]
fn detects_compose_security_opt_apparmor_unconfined() {
    let yaml = compose(
        r#"  risky:
    image: alpine
    security_opt:
      - apparmor:unconfined"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(&yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.description.contains("apparmor:unconfined"))
    );
}

#[test]
fn detects_compose_security_opt_seccomp_unconfined() {
    let yaml = compose(
        r#"  risky:
    image: alpine
    security_opt:
      - seccomp:unconfined"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(&yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.description.contains("seccomp:unconfined"))
    );
}

#[test]
fn detects_dockerfile_root_user() {
    let dockerfile = "FROM ubuntu:22.04\nUSER root\nCMD /app/start";
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_dockerfile(dockerfile);
    assert!(findings.iter().any(|f| {
        f.category == EscapeCategory::InsecureDockerfile && f.description.contains("root")
    }));
}

#[test]
fn detects_dockerfile_no_user() {
    let dockerfile = "FROM ubuntu:22.04\nRUN apt-get update\nCMD /app/start";
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_dockerfile(dockerfile);
    assert!(findings.iter().any(|f| {
        f.category == EscapeCategory::InsecureDockerfile
            && f.description.contains("no USER instruction")
    }));
}

#[test]
fn dockerfile_nonroot_user_no_finding() {
    let dockerfile = "FROM ubuntu:22.04\nRUN apt-get update\nUSER 1000\nCMD /app/start";
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_dockerfile(dockerfile);
    assert!(
        !findings
            .iter()
            .any(|f| f.description.contains("no USER instruction"))
    );
    assert!(
        !findings
            .iter()
            .any(|f| f.description.contains("runs as root"))
    );
}

#[test]
fn detects_dockerfile_hardcoded_secrets() {
    let dockerfile = "FROM node:18\nENV API_KEY=sk-12345\nCMD node server.js";
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_dockerfile(dockerfile);
    assert!(
        findings
            .iter()
            .any(|f| f.description.contains("Secrets hardcoded"))
    );
}

#[test]
fn detects_dockerfile_docker_socket_copy() {
    let dockerfile = "FROM alpine\nCOPY /var/run/docker.sock /docker.sock\nCMD sh";
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_dockerfile(dockerfile);
    assert!(
        findings
            .iter()
            .any(|f| f.category == EscapeCategory::MountedDockerSocket)
    );
}

#[test]
fn detects_dockerfile_exposed_kubelet() {
    let dockerfile = "FROM nginx\nEXPOSE 10250\nCMD nginx -g 'daemon off;'";
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_dockerfile(dockerfile);
    assert!(
        findings
            .iter()
            .any(|f| f.category == EscapeCategory::ExposedKubeletApi)
    );
}

#[test]
fn multi_document_yaml_scan() {
    let yaml = r#"apiVersion: v1
kind: Pod
metadata:
  name: pod-one
spec:
  hostPID: true
  containers:
    - name: first
      image: alpine
---
apiVersion: v1
kind: Pod
metadata:
  name: pod-two
spec:
  containers:
    - name: second
      image: alpine
      securityContext:
        privileged: true"#;
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.category == EscapeCategory::HostNamespaceSharing)
    );
    assert!(
        findings
            .iter()
            .any(|f| f.category == EscapeCategory::PrivilegedContainer)
    );
}

#[test]
fn severity_ordering_privileged_highest() {
    let yaml = k8s_pod(
        r#"    - name: everything-bad
      image: alpine
      securityContext:
        privileged: true
        capabilities:
          add:
            - NET_RAW"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(&yaml);
    let priv_sev = findings
        .iter()
        .find(|f| f.category == EscapeCategory::PrivilegedContainer)
        .map(|f| f.severity)
        .unwrap_or(0.0);
    let cap_sev = findings
        .iter()
        .find(|f| f.category == EscapeCategory::DangerousCapability)
        .map(|f| f.severity)
        .unwrap_or(0.0);
    assert!(priv_sev > cap_sev);
}

#[test]
fn scanner_resets_between_scans() {
    let yaml_one = k8s_pod(
        r#"    - name: evil
      image: alpine
      securityContext:
        privileged: true"#,
    );
    let yaml_two = k8s_pod(
        r#"    - name: safe
      image: alpine"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let first = scanner.scan_yaml(&yaml_one);
    assert!(!first.is_empty());
    let second = scanner.scan_yaml(&yaml_two);
    assert!(
        !second
            .iter()
            .any(|f| f.category == EscapeCategory::PrivilegedContainer)
    );
}

#[test]
fn all_findings_have_remediation() {
    let yaml = r#"apiVersion: v1
kind: Pod
metadata:
  name: terrible-pod
spec:
  hostPID: true
  hostNetwork: true
  containers:
    - name: bad
      image: alpine
      securityContext:
        privileged: true
        capabilities:
          add:
            - SYS_ADMIN
      volumeMounts:
        - name: docker-sock
          mountPath: /var/run/docker.sock"#;
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(yaml);
    assert!(findings.len() >= 4);
    for finding in findings {
        assert!(
            !finding.remediation.is_empty(),
            "Finding missing remediation: {:?}",
            finding
        );
    }
}

#[test]
fn escape_category_display() {
    assert_eq!(
        format!("{}", EscapeCategory::PrivilegedContainer),
        "Privileged Container"
    );
    assert_eq!(
        format!("{}", EscapeCategory::MountedDockerSocket),
        "Mounted Docker Socket"
    );
    assert_eq!(
        format!("{}", EscapeCategory::KnownCvePattern),
        "Known CVE Pattern"
    );
}

#[test]
fn default_constructor_works() {
    let scanner = ContainerEscapeScanner::default();
    assert!(scanner.findings().is_empty());
}

#[test]
fn detects_containerd_socket_mount() {
    let yaml = k8s_pod(
        r#"    - name: cri-pod
      image: alpine
      volumeMounts:
        - name: cri-sock
          mountPath: /run/containerd/containerd.sock"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(&yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.category == EscapeCategory::MountedDockerSocket)
    );
}

#[test]
fn inline_capability_list() {
    let yaml = k8s_pod(
        r#"    - name: inline-caps
      image: alpine
      securityContext:
        capabilities:
          add: [SYS_ADMIN, NET_RAW]"#,
    );
    let mut scanner = ContainerEscapeScanner::new();
    let findings = scanner.scan_yaml(&yaml);
    assert!(findings.iter().any(|f| f.description.contains("SYS_ADMIN")));
    assert!(findings.iter().any(|f| f.description.contains("NET_RAW")));
}
