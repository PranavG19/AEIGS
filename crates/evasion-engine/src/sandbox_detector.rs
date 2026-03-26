use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Recommendation based on sandbox analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SandboxRecommendation {
    Proceed,
    Abort,
    Deceive,
}

impl std::fmt::Display for SandboxRecommendation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proceed => write!(f, "proceed"),
            Self::Abort => write!(f, "abort"),
            Self::Deceive => write!(f, "deceive"),
        }
    }
}

/// Categories of sandbox/VM detection checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectionCategory {
    VmHypervisor,
    SandboxEnvironment,
    DebuggerPresence,
    AnalysisTool,
    TimingAnomaly,
    MouseEntropy,
}

impl std::fmt::Display for DetectionCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VmHypervisor => write!(f, "vm-hypervisor"),
            Self::SandboxEnvironment => write!(f, "sandbox-environment"),
            Self::DebuggerPresence => write!(f, "debugger-presence"),
            Self::AnalysisTool => write!(f, "analysis-tool"),
            Self::TimingAnomaly => write!(f, "timing-anomaly"),
            Self::MouseEntropy => write!(f, "mouse-entropy"),
        }
    }
}

/// Known hypervisor vendors detectable via CPUID or DMI strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HypervisorVendor {
    VMware,
    VirtualBox,
    HyperV,
    Kvm,
    Xen,
    Qemu,
    Parallels,
    Unknown,
}

impl std::fmt::Display for HypervisorVendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VMware => write!(f, "VMware"),
            Self::VirtualBox => write!(f, "VirtualBox"),
            Self::HyperV => write!(f, "Hyper-V"),
            Self::Kvm => write!(f, "KVM"),
            Self::Xen => write!(f, "Xen"),
            Self::Qemu => write!(f, "QEMU"),
            Self::Parallels => write!(f, "Parallels"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Known sandbox products.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SandboxProduct {
    Cuckoo,
    AnyRun,
    JoeSandbox,
    Triage,
    CAPEv2,
    ThreatGrid,
    WindowsSandbox,
    Unknown,
}

impl std::fmt::Display for SandboxProduct {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cuckoo => write!(f, "Cuckoo"),
            Self::AnyRun => write!(f, "Any.run"),
            Self::JoeSandbox => write!(f, "Joe Sandbox"),
            Self::Triage => write!(f, "Triage"),
            Self::CAPEv2 => write!(f, "CAPEv2"),
            Self::ThreatGrid => write!(f, "Threat Grid"),
            Self::WindowsSandbox => write!(f, "Windows Sandbox"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Individual detection indicator with confidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionIndicator {
    pub category: DetectionCategory,
    pub description: String,
    pub confidence: f64,
    pub evidence: String,
}

/// Aggregated sandbox detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxScore {
    pub score: u8,
    pub recommendation: SandboxRecommendation,
    pub indicators: Vec<DetectionIndicator>,
    pub detected_hypervisor: Option<HypervisorVendor>,
    pub detected_sandbox: Option<SandboxProduct>,
    pub category_scores: HashMap<DetectionCategory, f64>,
}

/// CPUID leaf 0x40000000 vendor string signatures for hypervisor detection.
const CPUID_SIGNATURES: &[(&str, HypervisorVendor)] = &[
    ("VMwareVMware", HypervisorVendor::VMware),
    ("VBoxVBoxVBox", HypervisorVendor::VirtualBox),
    ("Microsoft Hv", HypervisorVendor::HyperV),
    ("KVMKVMKVM", HypervisorVendor::Kvm),
    ("XenVMMXenVMM", HypervisorVendor::Xen),
    ("TCGTCGTCGTCG", HypervisorVendor::Qemu),
    ("prl hyperv", HypervisorVendor::Parallels),
];

/// DMI (SMBIOS) strings that leak VM identity.
const DMI_STRINGS: &[(&str, HypervisorVendor)] = &[
    ("VMware", HypervisorVendor::VMware),
    ("VirtualBox", HypervisorVendor::VirtualBox),
    ("VBOX", HypervisorVendor::VirtualBox),
    ("Microsoft Corporation Virtual", HypervisorVendor::HyperV),
    ("QEMU", HypervisorVendor::Qemu),
    ("KVM", HypervisorVendor::Kvm),
    ("Xen", HypervisorVendor::Xen),
    ("Parallels", HypervisorVendor::Parallels),
    ("innotek", HypervisorVendor::VirtualBox),
];

/// MAC OUI (first 3 bytes) patterns assigned to VM vendors.
const VM_MAC_OUIS: &[(&str, HypervisorVendor)] = &[
    ("00:50:56", HypervisorVendor::VMware),
    ("00:0C:29", HypervisorVendor::VMware),
    ("00:05:69", HypervisorVendor::VMware),
    ("08:00:27", HypervisorVendor::VirtualBox),
    ("00:15:5D", HypervisorVendor::HyperV),
    ("52:54:00", HypervisorVendor::Kvm),
    ("00:16:3E", HypervisorVendor::Xen),
    ("00:1C:42", HypervisorVendor::Parallels),
];

/// Process names associated with analysis/debugging tools.
const ANALYSIS_PROCESSES: &[&str] = &[
    "wireshark",
    "fiddler",
    "burpsuite",
    "ida",
    "ida64",
    "idaq",
    "idaq64",
    "x64dbg",
    "x32dbg",
    "ollydbg",
    "windbg",
    "ghidra",
    "processhacker",
    "procmon",
    "procexp",
    "tcpdump",
    "strace",
    "ltrace",
    "gdb",
    "lldb",
    "radare2",
    "r2",
    "volatility",
    "autoruns",
    "regmon",
    "filemon",
    "apimonitor",
    "pestudio",
    "die",
    "peid",
    "dnspy",
    "dumpcap",
    "tshark",
    "fakenet",
    "noriben",
    "sysmon",
];

/// Filesystem paths that indicate sandbox environments.
const SANDBOX_PATHS: &[(&str, SandboxProduct)] = &[
    ("/opt/cuckoo", SandboxProduct::Cuckoo),
    ("/home/cuckoo", SandboxProduct::Cuckoo),
    ("C:\\cuckoo", SandboxProduct::Cuckoo),
    ("C:\\agent\\agent.py", SandboxProduct::Cuckoo),
    ("C:\\strawberry", SandboxProduct::Cuckoo),
    ("C:\\Users\\anyrun", SandboxProduct::AnyRun),
    ("C:\\Users\\JobeUser", SandboxProduct::JoeSandbox),
    ("C:\\Users\\Joe", SandboxProduct::JoeSandbox),
    ("C:\\Users\\triage", SandboxProduct::Triage),
    ("C:\\cape", SandboxProduct::CAPEv2),
    ("C:\\threat_grid", SandboxProduct::ThreatGrid),
];

/// Registry keys that indicate sandbox/VM presence (Windows).
const SANDBOX_REGISTRY_KEYS: &[(&str, &str)] = &[
    ("HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools", "VMware"),
    (
        "HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "VirtualBox",
    ),
    ("HKLM\\HARDWARE\\ACPI\\DSDT\\VBOX__", "VirtualBox"),
    (
        "HKLM\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
        "Hyper-V",
    ),
    (
        "HKLM\\HARDWARE\\Description\\System\\SystemBiosVersion",
        "BIOS",
    ),
];

/// Environment variables commonly set in sandbox environments.
const SANDBOX_ENV_VARS: &[(&str, SandboxProduct)] = &[
    ("CUCKOO", SandboxProduct::Cuckoo),
    ("CUCKOO_ROOT", SandboxProduct::Cuckoo),
    ("CAPE_ROOT", SandboxProduct::CAPEv2),
    ("SANDBOX", SandboxProduct::Unknown),
    ("MALWARE_ANALYSIS", SandboxProduct::Unknown),
];

/// Simulated system environment for sandbox detection analysis.
#[derive(Debug, Clone, Default)]
pub struct SystemEnvironment {
    pub cpuid_vendor_string: Option<String>,
    pub dmi_strings: Vec<String>,
    pub mac_addresses: Vec<String>,
    pub running_processes: Vec<String>,
    pub filesystem_paths: Vec<String>,
    pub registry_keys: Vec<(String, String)>,
    pub environment_variables: HashMap<String, String>,
    pub tracer_pid: Option<u32>,
    pub rdtsc_delta_ns: Option<u64>,
    pub sleep_requested_ms: Option<u64>,
    pub sleep_actual_ms: Option<u64>,
    pub mouse_positions: Vec<(i32, i32)>,
    pub uptime_seconds: Option<u64>,
    pub total_ram_mb: Option<u64>,
    pub disk_size_gb: Option<u64>,
    pub cpu_core_count: Option<u32>,
    pub screen_resolution: Option<(u32, u32)>,
    pub username: Option<String>,
    pub hostname: Option<String>,
}

/// Configuration for the sandbox detector.
#[derive(Debug, Clone)]
pub struct SandboxDetectorConfig {
    pub abort_threshold: u8,
    pub deceive_threshold: u8,
    pub enable_timing_checks: bool,
    pub enable_mouse_entropy: bool,
    pub min_mouse_samples: usize,
    pub rdtsc_anomaly_threshold_ns: u64,
    pub sleep_acceleration_tolerance_pct: f64,
    pub min_uptime_seconds: u64,
    pub min_ram_mb: u64,
    pub min_disk_gb: u64,
    pub min_cpu_cores: u32,
}

impl Default for SandboxDetectorConfig {
    fn default() -> Self {
        Self {
            abort_threshold: 70,
            deceive_threshold: 40,
            enable_timing_checks: true,
            enable_mouse_entropy: true,
            min_mouse_samples: 10,
            rdtsc_anomaly_threshold_ns: 500_000,
            sleep_acceleration_tolerance_pct: 20.0,
            min_uptime_seconds: 600,
            min_ram_mb: 2048,
            min_disk_gb: 50,
            min_cpu_cores: 2,
        }
    }
}

/// Detects sandbox, VM, and analysis environments.
pub struct SandboxDetector {
    config: SandboxDetectorConfig,
}

impl SandboxDetector {
    pub fn new(config: SandboxDetectorConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(SandboxDetectorConfig::default())
    }

    /// Run all detection checks against the provided environment snapshot.
    pub fn analyze(&self, env: &SystemEnvironment) -> SandboxScore {
        let mut indicators = Vec::new();
        let mut category_scores: HashMap<DetectionCategory, f64> = HashMap::new();
        let mut detected_hypervisor: Option<HypervisorVendor> = None;
        let mut detected_sandbox: Option<SandboxProduct> = None;

        let vm_indicators = self.check_vm_hypervisor(env);
        for ind in &vm_indicators {
            if ind.confidence > 0.7 {
                if let Some(hv) = self.extract_hypervisor_from_evidence(&ind.evidence) {
                    detected_hypervisor = Some(hv);
                }
            }
        }
        Self::merge_category(
            &mut category_scores,
            DetectionCategory::VmHypervisor,
            &vm_indicators,
        );
        indicators.extend(vm_indicators);

        let sandbox_indicators = self.check_sandbox_environment(env);
        for ind in &sandbox_indicators {
            if ind.confidence > 0.7 {
                if let Some(sb) = self.extract_sandbox_from_evidence(&ind.evidence) {
                    detected_sandbox = Some(sb);
                }
            }
        }
        Self::merge_category(
            &mut category_scores,
            DetectionCategory::SandboxEnvironment,
            &sandbox_indicators,
        );
        indicators.extend(sandbox_indicators);

        let debug_indicators = self.check_debugger_presence(env);
        Self::merge_category(
            &mut category_scores,
            DetectionCategory::DebuggerPresence,
            &debug_indicators,
        );
        indicators.extend(debug_indicators);

        let tool_indicators = self.check_analysis_tools(env);
        Self::merge_category(
            &mut category_scores,
            DetectionCategory::AnalysisTool,
            &tool_indicators,
        );
        indicators.extend(tool_indicators);

        if self.config.enable_timing_checks {
            let timing_indicators = self.check_timing_anomalies(env);
            Self::merge_category(
                &mut category_scores,
                DetectionCategory::TimingAnomaly,
                &timing_indicators,
            );
            indicators.extend(timing_indicators);
        }

        if self.config.enable_mouse_entropy {
            let mouse_indicators = self.check_mouse_entropy(env);
            Self::merge_category(
                &mut category_scores,
                DetectionCategory::MouseEntropy,
                &mouse_indicators,
            );
            indicators.extend(mouse_indicators);
        }

        let raw_score = self.compute_composite_score(&category_scores);
        let score = raw_score.min(100).max(0) as u8;

        let recommendation = if score >= self.config.abort_threshold {
            SandboxRecommendation::Abort
        } else if score >= self.config.deceive_threshold {
            SandboxRecommendation::Deceive
        } else {
            SandboxRecommendation::Proceed
        };

        SandboxScore {
            score,
            recommendation,
            indicators,
            detected_hypervisor,
            detected_sandbox,
            category_scores,
        }
    }

    fn check_vm_hypervisor(&self, env: &SystemEnvironment) -> Vec<DetectionIndicator> {
        let mut indicators = Vec::new();

        if let Some(ref cpuid) = env.cpuid_vendor_string {
            for (sig, vendor) in CPUID_SIGNATURES {
                if cpuid.contains(sig) {
                    indicators.push(DetectionIndicator {
                        category: DetectionCategory::VmHypervisor,
                        description: format!("CPUID leaf 0x40000000 matches {vendor}"),
                        confidence: 0.95,
                        evidence: format!("cpuid:{vendor}"),
                    });
                    break;
                }
            }
        }

        for dmi in &env.dmi_strings {
            let dmi_lower = dmi.to_lowercase();
            for (pattern, vendor) in DMI_STRINGS {
                if dmi_lower.contains(&pattern.to_lowercase()) {
                    indicators.push(DetectionIndicator {
                        category: DetectionCategory::VmHypervisor,
                        description: format!("DMI string contains {vendor} signature: {dmi}"),
                        confidence: 0.9,
                        evidence: format!("dmi:{vendor}"),
                    });
                }
            }
        }

        for mac in &env.mac_addresses {
            let mac_upper = mac.to_uppercase();
            for (oui, vendor) in VM_MAC_OUIS {
                if mac_upper.starts_with(&oui.to_uppercase()) {
                    indicators.push(DetectionIndicator {
                        category: DetectionCategory::VmHypervisor,
                        description: format!("MAC OUI {oui} assigned to {vendor}"),
                        confidence: 0.85,
                        evidence: format!("mac:{vendor}"),
                    });
                }
            }
        }

        if let Some(cores) = env.cpu_core_count {
            if cores < self.config.min_cpu_cores {
                indicators.push(DetectionIndicator {
                    category: DetectionCategory::VmHypervisor,
                    description: format!("Low CPU core count: {cores} (typical VM allocation)"),
                    confidence: 0.4,
                    evidence: format!("cpu_cores:{cores}"),
                });
            }
        }

        if let Some(ram) = env.total_ram_mb {
            if ram < self.config.min_ram_mb {
                indicators.push(DetectionIndicator {
                    category: DetectionCategory::VmHypervisor,
                    description: format!("Low RAM: {ram}MB (typical VM allocation)"),
                    confidence: 0.35,
                    evidence: format!("ram:{ram}"),
                });
            }
        }

        if let Some(disk) = env.disk_size_gb {
            if disk < self.config.min_disk_gb {
                indicators.push(DetectionIndicator {
                    category: DetectionCategory::VmHypervisor,
                    description: format!("Small disk: {disk}GB (typical VM allocation)"),
                    confidence: 0.35,
                    evidence: format!("disk:{disk}"),
                });
            }
        }

        if let Some(ref resolution) = env.screen_resolution {
            let (w, h) = *resolution;
            if (w == 1024 && h == 768) || (w == 800 && h == 600) {
                indicators.push(DetectionIndicator {
                    category: DetectionCategory::VmHypervisor,
                    description: format!("Default VM screen resolution: {w}x{h}"),
                    confidence: 0.3,
                    evidence: format!("resolution:{w}x{h}"),
                });
            }
        }

        indicators
    }

    fn check_sandbox_environment(&self, env: &SystemEnvironment) -> Vec<DetectionIndicator> {
        let mut indicators = Vec::new();

        for path in &env.filesystem_paths {
            for (sandbox_path, product) in SANDBOX_PATHS {
                if path.to_lowercase().contains(&sandbox_path.to_lowercase()) {
                    indicators.push(DetectionIndicator {
                        category: DetectionCategory::SandboxEnvironment,
                        description: format!("Sandbox path detected: {path} ({product})"),
                        confidence: 0.9,
                        evidence: format!("path:{product}"),
                    });
                }
            }
        }

        for (key, _value) in &env.registry_keys {
            for (reg_key, label) in SANDBOX_REGISTRY_KEYS {
                if key.to_lowercase().contains(&reg_key.to_lowercase()) {
                    indicators.push(DetectionIndicator {
                        category: DetectionCategory::SandboxEnvironment,
                        description: format!("Sandbox registry key: {key} ({label})"),
                        confidence: 0.85,
                        evidence: format!("registry:{label}"),
                    });
                }
            }
        }

        for (var, product) in SANDBOX_ENV_VARS {
            if env.environment_variables.contains_key(*var) {
                indicators.push(DetectionIndicator {
                    category: DetectionCategory::SandboxEnvironment,
                    description: format!("Sandbox env var present: {var} ({product})"),
                    confidence: 0.8,
                    evidence: format!("env:{product}"),
                });
            }
        }

        if let Some(ref user) = env.username {
            let suspicious_users = [
                "sandbox", "malware", "virus", "sample", "test", "cuckoo", "admin", "user",
                "analyst", "lab",
            ];
            let user_lower = user.to_lowercase();
            for suspect in &suspicious_users {
                if user_lower == *suspect {
                    indicators.push(DetectionIndicator {
                        category: DetectionCategory::SandboxEnvironment,
                        description: format!("Suspicious username: {user}"),
                        confidence: 0.5,
                        evidence: format!("username:{user}"),
                    });
                    break;
                }
            }
        }

        if let Some(ref host) = env.hostname {
            let suspicious_hosts = ["sandbox", "maltest", "cuckoo", "analysis", "lab"];
            let host_lower = host.to_lowercase();
            for suspect in &suspicious_hosts {
                if host_lower.contains(suspect) {
                    indicators.push(DetectionIndicator {
                        category: DetectionCategory::SandboxEnvironment,
                        description: format!("Suspicious hostname: {host}"),
                        confidence: 0.5,
                        evidence: format!("hostname:{host}"),
                    });
                    break;
                }
            }
        }

        if let Some(uptime) = env.uptime_seconds {
            if uptime < self.config.min_uptime_seconds {
                indicators.push(DetectionIndicator {
                    category: DetectionCategory::SandboxEnvironment,
                    description: format!(
                        "Low uptime: {uptime}s (sandbox VMs often freshly booted)"
                    ),
                    confidence: 0.45,
                    evidence: format!("uptime:{uptime}"),
                });
            }
        }

        indicators
    }

    fn check_debugger_presence(&self, env: &SystemEnvironment) -> Vec<DetectionIndicator> {
        let mut indicators = Vec::new();

        if let Some(pid) = env.tracer_pid {
            if pid != 0 {
                indicators.push(DetectionIndicator {
                    category: DetectionCategory::DebuggerPresence,
                    description: format!(
                        "TracerPid={pid} in /proc/self/status (active debugger attached)"
                    ),
                    confidence: 0.95,
                    evidence: format!("tracerpid:{pid}"),
                });
            }
        }

        let debugger_processes = [
            "gdb", "lldb", "strace", "ltrace", "x64dbg", "x32dbg", "ollydbg", "windbg", "ida",
            "ida64",
        ];
        for proc in &env.running_processes {
            let proc_lower = proc.to_lowercase();
            for dbg in &debugger_processes {
                if proc_lower == *dbg {
                    indicators.push(DetectionIndicator {
                        category: DetectionCategory::DebuggerPresence,
                        description: format!("Debugger process running: {proc}"),
                        confidence: 0.85,
                        evidence: format!("debugger_proc:{proc}"),
                    });
                }
            }
        }

        indicators
    }

    fn check_analysis_tools(&self, env: &SystemEnvironment) -> Vec<DetectionIndicator> {
        let mut indicators = Vec::new();

        for proc in &env.running_processes {
            let proc_lower = proc.to_lowercase();
            for tool in ANALYSIS_PROCESSES {
                if proc_lower == *tool {
                    indicators.push(DetectionIndicator {
                        category: DetectionCategory::AnalysisTool,
                        description: format!("Analysis tool running: {proc}"),
                        confidence: 0.8,
                        evidence: format!("tool:{proc}"),
                    });
                }
            }
        }

        indicators
    }

    fn check_timing_anomalies(&self, env: &SystemEnvironment) -> Vec<DetectionIndicator> {
        let mut indicators = Vec::new();

        if let Some(delta) = env.rdtsc_delta_ns {
            if delta > self.config.rdtsc_anomaly_threshold_ns {
                indicators.push(DetectionIndicator {
                    category: DetectionCategory::TimingAnomaly,
                    description: format!(
                        "RDTSC delta {delta}ns exceeds threshold {}ns (VM exit overhead or instrumentation)",
                        self.config.rdtsc_anomaly_threshold_ns
                    ),
                    confidence: 0.75,
                    evidence: format!("rdtsc:{delta}"),
                });
            }
        }

        if let (Some(requested), Some(actual)) = (env.sleep_requested_ms, env.sleep_actual_ms) {
            if requested > 0 {
                let diff_pct = if actual < requested {
                    ((requested - actual) as f64 / requested as f64) * 100.0
                } else {
                    0.0
                };
                if diff_pct > self.config.sleep_acceleration_tolerance_pct {
                    indicators.push(DetectionIndicator {
                        category: DetectionCategory::TimingAnomaly,
                        description: format!(
                            "Sleep acceleration detected: requested {requested}ms, got {actual}ms ({diff_pct:.1}% faster)"
                        ),
                        confidence: 0.85,
                        evidence: format!("sleep_accel:{diff_pct:.1}"),
                    });
                }
            }
        }

        indicators
    }

    fn check_mouse_entropy(&self, env: &SystemEnvironment) -> Vec<DetectionIndicator> {
        let mut indicators = Vec::new();

        if env.mouse_positions.len() < self.config.min_mouse_samples {
            if !env.mouse_positions.is_empty() {
                indicators.push(DetectionIndicator {
                    category: DetectionCategory::MouseEntropy,
                    description: format!(
                        "Insufficient mouse samples: {} (need {})",
                        env.mouse_positions.len(),
                        self.config.min_mouse_samples
                    ),
                    confidence: 0.3,
                    evidence: "low_samples".to_string(),
                });
            }
            return indicators;
        }

        let entropy = Self::compute_mouse_entropy(&env.mouse_positions);

        if entropy < 1.0 {
            indicators.push(DetectionIndicator {
                category: DetectionCategory::MouseEntropy,
                description: format!(
                    "Very low mouse entropy: {entropy:.2} (likely automated/no human interaction)"
                ),
                confidence: 0.8,
                evidence: format!("mouse_entropy:{entropy:.2}"),
            });
        } else if entropy < 2.5 {
            indicators.push(DetectionIndicator {
                category: DetectionCategory::MouseEntropy,
                description: format!(
                    "Low mouse entropy: {entropy:.2} (possible scripted movement)"
                ),
                confidence: 0.5,
                evidence: format!("mouse_entropy:{entropy:.2}"),
            });
        }

        let all_same = env
            .mouse_positions
            .windows(2)
            .all(|w| w[0].0 == w[1].0 && w[0].1 == w[1].1);
        if all_same && env.mouse_positions.len() >= 2 {
            indicators.push(DetectionIndicator {
                category: DetectionCategory::MouseEntropy,
                description: "Mouse position never changed (no human present)".to_string(),
                confidence: 0.9,
                evidence: "mouse_static".to_string(),
            });
        }

        let all_linear = Self::check_linear_movement(&env.mouse_positions);
        if all_linear && !all_same {
            indicators.push(DetectionIndicator {
                category: DetectionCategory::MouseEntropy,
                description: "Mouse moves in perfect linear pattern (scripted)".to_string(),
                confidence: 0.7,
                evidence: "mouse_linear".to_string(),
            });
        }

        indicators
    }

    /// Shannon entropy of mouse movement deltas.
    fn compute_mouse_entropy(positions: &[(i32, i32)]) -> f64 {
        if positions.len() < 2 {
            return 0.0;
        }

        let deltas: Vec<(i32, i32)> = positions
            .windows(2)
            .map(|w| (w[1].0 - w[0].0, w[1].1 - w[0].1))
            .collect();

        let mut freq: HashMap<(i32, i32), usize> = HashMap::new();
        for d in &deltas {
            *freq.entry(*d).or_insert(0) += 1;
        }

        let total = deltas.len() as f64;
        let mut entropy = 0.0;
        for count in freq.values() {
            let p = *count as f64 / total;
            if p > 0.0 {
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Detect if all movements are along a single line.
    fn check_linear_movement(positions: &[(i32, i32)]) -> bool {
        if positions.len() < 3 {
            return false;
        }

        let (x0, y0) = positions[0];
        let (x1, y1) = positions[1];
        let dx_base = x1 - x0;
        let dy_base = y1 - y0;

        for i in 2..positions.len() {
            let dx = positions[i].0 - x0;
            let dy = positions[i].1 - y0;
            let cross = dx_base * dy - dy_base * dx;
            if cross != 0 {
                return false;
            }
        }
        true
    }

    fn compute_composite_score(&self, category_scores: &HashMap<DetectionCategory, f64>) -> i32 {
        let weights: &[(DetectionCategory, f64)] = &[
            (DetectionCategory::VmHypervisor, 30.0),
            (DetectionCategory::SandboxEnvironment, 25.0),
            (DetectionCategory::DebuggerPresence, 20.0),
            (DetectionCategory::AnalysisTool, 10.0),
            (DetectionCategory::TimingAnomaly, 10.0),
            (DetectionCategory::MouseEntropy, 5.0),
        ];

        let mut score = 0.0;
        for (cat, weight) in weights {
            if let Some(cat_score) = category_scores.get(cat) {
                score += cat_score * weight;
            }
        }
        score as i32
    }

    fn merge_category(
        scores: &mut HashMap<DetectionCategory, f64>,
        category: DetectionCategory,
        indicators: &[DetectionIndicator],
    ) {
        if indicators.is_empty() {
            return;
        }
        let max_conf = indicators
            .iter()
            .map(|i| i.confidence)
            .fold(0.0_f64, f64::max);
        scores.insert(category, max_conf);
    }

    fn extract_hypervisor_from_evidence(&self, evidence: &str) -> Option<HypervisorVendor> {
        let after_colon = evidence.split(':').nth(1)?;
        match after_colon {
            "VMware" => Some(HypervisorVendor::VMware),
            "VirtualBox" => Some(HypervisorVendor::VirtualBox),
            "Hyper-V" | "HyperV" => Some(HypervisorVendor::HyperV),
            "KVM" | "Kvm" => Some(HypervisorVendor::Kvm),
            "Xen" => Some(HypervisorVendor::Xen),
            "QEMU" | "Qemu" => Some(HypervisorVendor::Qemu),
            "Parallels" => Some(HypervisorVendor::Parallels),
            _ => None,
        }
    }

    fn extract_sandbox_from_evidence(&self, evidence: &str) -> Option<SandboxProduct> {
        let after_colon = evidence.split(':').nth(1)?;
        match after_colon {
            "Cuckoo" => Some(SandboxProduct::Cuckoo),
            "Any.run" | "AnyRun" => Some(SandboxProduct::AnyRun),
            "Joe Sandbox" | "JoeSandbox" => Some(SandboxProduct::JoeSandbox),
            "Triage" => Some(SandboxProduct::Triage),
            "CAPEv2" => Some(SandboxProduct::CAPEv2),
            "Threat Grid" | "ThreatGrid" => Some(SandboxProduct::ThreatGrid),
            _ => None,
        }
    }

    /// Generate a set of CPUID check instructions for inline assembly.
    pub fn cpuid_check_payload() -> String {
        let mut payload = String::new();
        payload.push_str("// CPUID-based hypervisor detection\n");
        payload.push_str("// Leaf 0x1 ECX bit 31 = hypervisor present\n");
        payload.push_str("mov eax, 1\n");
        payload.push_str("cpuid\n");
        payload.push_str("bt ecx, 31\n");
        payload.push_str("jc hypervisor_detected\n\n");
        payload.push_str("// Leaf 0x40000000 = hypervisor vendor string\n");
        payload.push_str("mov eax, 0x40000000\n");
        payload.push_str("cpuid\n");
        payload.push_str("// EBX:ECX:EDX = 12-char vendor string\n");
        payload
    }

    /// Generate RDTSC timing check shellcode pattern.
    pub fn rdtsc_timing_check_pattern() -> String {
        let mut pattern = String::new();
        pattern.push_str("// RDTSC timing anomaly detection\n");
        pattern.push_str("rdtsc\n");
        pattern.push_str("shl rdx, 32\n");
        pattern.push_str("or rax, rdx\n");
        pattern.push_str("mov rbx, rax    ; save first reading\n");
        pattern.push_str("// Execute target instruction(s)\n");
        pattern.push_str("cpuid           ; serializing instruction\n");
        pattern.push_str("rdtsc\n");
        pattern.push_str("shl rdx, 32\n");
        pattern.push_str("or rax, rdx\n");
        pattern.push_str("sub rax, rbx    ; delta = second - first\n");
        pattern.push_str("cmp rax, 500000 ; threshold for VM exit overhead\n");
        pattern.push_str("ja vm_detected\n");
        pattern
    }
}
