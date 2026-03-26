use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Virtual machine detection via CPUID, DMI strings, MAC OUI, and device enumeration.
///
/// Aggregates multiple VM detection heuristics into a composite score with
/// per-hypervisor identification. Used to decide whether to abort, deceive,
/// or proceed with operations.

/// Known hypervisor vendors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VmVendor {
    VMware,
    VirtualBox,
    HyperV,
    Kvm,
    Xen,
    Qemu,
    Parallels,
    Bhyve,
    None,
}

impl std::fmt::Display for VmVendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VMware => write!(f, "VMware"),
            Self::VirtualBox => write!(f, "VirtualBox"),
            Self::HyperV => write!(f, "Hyper-V"),
            Self::Kvm => write!(f, "KVM"),
            Self::Xen => write!(f, "Xen"),
            Self::Qemu => write!(f, "QEMU"),
            Self::Parallels => write!(f, "Parallels"),
            Self::Bhyve => write!(f, "bhyve"),
            Self::None => write!(f, "None"),
        }
    }
}

/// Detection method that identified the VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectionMethod {
    CpuidLeaf,
    CpuidHypervisorBit,
    DmiString,
    MacOui,
    DeviceDriver,
    RegistryKey,
    FilesystemArtifact,
    ProcessName,
    HardwareModel,
}

/// Individual VM detection indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmIndicator {
    pub method: DetectionMethod,
    pub vendor: VmVendor,
    pub confidence: f64,
    pub evidence: String,
}

/// Action recommendation based on VM detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmAction {
    Proceed,
    Caution,
    Abort,
}

/// Aggregated VM detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmDetectionResult {
    pub is_vm: bool,
    pub vendor: VmVendor,
    pub action: VmAction,
    pub confidence: f64,
    pub indicators: Vec<VmIndicator>,
    pub method_scores: HashMap<DetectionMethod, f64>,
}

/// Simulated hardware environment for VM detection.
#[derive(Debug, Clone, Default)]
pub struct HardwareEnvironment {
    pub cpuid_leaf1_ecx: Option<u32>,
    pub cpuid_leaf40_vendor: Option<String>,
    pub dmi_system_manufacturer: Option<String>,
    pub dmi_system_product: Option<String>,
    pub dmi_bios_vendor: Option<String>,
    pub dmi_board_product: Option<String>,
    pub mac_addresses: Vec<String>,
    pub device_drivers: Vec<String>,
    pub registry_keys: Vec<String>,
    pub filesystem_paths: Vec<String>,
    pub running_processes: Vec<String>,
    pub hardware_model: Option<String>,
}

/// VM detector configuration.
#[derive(Debug, Clone)]
pub struct VmDetectorConfig {
    pub abort_confidence: f64,
    pub caution_confidence: f64,
    pub enable_cpuid_checks: bool,
    pub enable_dmi_checks: bool,
    pub enable_mac_checks: bool,
    pub enable_driver_checks: bool,
}

impl Default for VmDetectorConfig {
    fn default() -> Self {
        Self {
            abort_confidence: 0.8,
            caution_confidence: 0.4,
            enable_cpuid_checks: true,
            enable_dmi_checks: true,
            enable_mac_checks: true,
            enable_driver_checks: true,
        }
    }
}

/// CPUID leaf 0x40000000 vendor string signatures.
const CPUID_VENDORS: &[(&str, VmVendor)] = &[
    ("VMwareVMware", VmVendor::VMware),
    ("VBoxVBoxVBox", VmVendor::VirtualBox),
    ("Microsoft Hv", VmVendor::HyperV),
    ("KVMKVMKVM", VmVendor::Kvm),
    ("XenVMMXenVMM", VmVendor::Xen),
    ("TCGTCGTCGTCG", VmVendor::Qemu),
    ("prl hyperv", VmVendor::Parallels),
    ("bhyve bhyve", VmVendor::Bhyve),
];

/// DMI manufacturer strings that identify VMs.
const DMI_MANUFACTURERS: &[(&str, VmVendor)] = &[
    ("vmware", VmVendor::VMware),
    ("innotek", VmVendor::VirtualBox),
    ("virtualbox", VmVendor::VirtualBox),
    ("microsoft corporation", VmVendor::HyperV),
    ("qemu", VmVendor::Qemu),
    ("kvm", VmVendor::Kvm),
    ("xen", VmVendor::Xen),
    ("parallels", VmVendor::Parallels),
    ("bochs", VmVendor::Qemu),
];

/// DMI product name strings.
const DMI_PRODUCTS: &[(&str, VmVendor)] = &[
    ("vmware virtual platform", VmVendor::VMware),
    ("virtualbox", VmVendor::VirtualBox),
    ("virtual machine", VmVendor::HyperV),
    ("standard pc", VmVendor::Qemu),
    ("kvm", VmVendor::Kvm),
    ("hvm domu", VmVendor::Xen),
];

/// MAC OUI prefixes assigned to VM vendors.
const MAC_OUIS: &[(&str, VmVendor)] = &[
    ("00:50:56", VmVendor::VMware),
    ("00:0c:29", VmVendor::VMware),
    ("00:05:69", VmVendor::VMware),
    ("08:00:27", VmVendor::VirtualBox),
    ("00:15:5d", VmVendor::HyperV),
    ("52:54:00", VmVendor::Kvm),
    ("00:16:3e", VmVendor::Xen),
    ("00:1c:42", VmVendor::Parallels),
];

/// Device driver names indicative of VM guest additions.
const VM_DRIVERS: &[(&str, VmVendor)] = &[
    ("vmhgfs", VmVendor::VMware),
    ("vmxnet", VmVendor::VMware),
    ("vmci", VmVendor::VMware),
    ("vboxguest", VmVendor::VirtualBox),
    ("vboxsf", VmVendor::VirtualBox),
    ("vboxvideo", VmVendor::VirtualBox),
    ("hv_vmbus", VmVendor::HyperV),
    ("hv_utils", VmVendor::HyperV),
    ("virtio", VmVendor::Kvm),
    ("virtio_net", VmVendor::Kvm),
    ("virtio_blk", VmVendor::Kvm),
    ("xen_blkfront", VmVendor::Xen),
    ("xen_netfront", VmVendor::Xen),
    ("prl_fs", VmVendor::Parallels),
];

/// VM detection engine.
pub struct VmDetector {
    config: VmDetectorConfig,
}

impl VmDetector {
    pub fn new(config: VmDetectorConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(VmDetectorConfig::default())
    }

    /// Analyze the hardware environment for VM indicators.
    pub fn detect(&self, env: &HardwareEnvironment) -> VmDetectionResult {
        let mut indicators = Vec::new();
        let mut method_scores: HashMap<DetectionMethod, f64> = HashMap::new();

        if self.config.enable_cpuid_checks {
            self.check_cpuid(env, &mut indicators, &mut method_scores);
        }

        if self.config.enable_dmi_checks {
            self.check_dmi(env, &mut indicators, &mut method_scores);
        }

        if self.config.enable_mac_checks {
            self.check_mac(env, &mut indicators, &mut method_scores);
        }

        if self.config.enable_driver_checks {
            self.check_drivers(env, &mut indicators, &mut method_scores);
        }

        let confidence = indicators
            .iter()
            .map(|i| i.confidence)
            .fold(0.0_f64, f64::max);

        let vendor = indicators
            .iter()
            .filter(|i| i.confidence >= 0.7)
            .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap())
            .map(|i| i.vendor)
            .unwrap_or(VmVendor::None);

        let is_vm = confidence >= self.config.caution_confidence;
        let action = if confidence >= self.config.abort_confidence {
            VmAction::Abort
        } else if confidence >= self.config.caution_confidence {
            VmAction::Caution
        } else {
            VmAction::Proceed
        };

        VmDetectionResult {
            is_vm,
            vendor,
            action,
            confidence,
            indicators,
            method_scores,
        }
    }

    fn check_cpuid(
        &self,
        env: &HardwareEnvironment,
        indicators: &mut Vec<VmIndicator>,
        scores: &mut HashMap<DetectionMethod, f64>,
    ) {
        if let Some(ecx) = env.cpuid_leaf1_ecx {
            let hypervisor_bit = (ecx >> 31) & 1;
            if hypervisor_bit == 1 {
                indicators.push(VmIndicator {
                    method: DetectionMethod::CpuidHypervisorBit,
                    vendor: VmVendor::None,
                    confidence: 0.95,
                    evidence: "CPUID leaf 1 ECX bit 31 set".to_string(),
                });
                scores.insert(DetectionMethod::CpuidHypervisorBit, 0.95);
            }
        }

        if let Some(ref vendor_str) = env.cpuid_leaf40_vendor {
            for (sig, vendor) in CPUID_VENDORS {
                if vendor_str.contains(sig) {
                    indicators.push(VmIndicator {
                        method: DetectionMethod::CpuidLeaf,
                        vendor: *vendor,
                        confidence: 0.98,
                        evidence: format!("CPUID leaf 0x40000000 matches {vendor}: {sig}"),
                    });
                    scores.insert(DetectionMethod::CpuidLeaf, 0.98);
                    break;
                }
            }
        }
    }

    fn check_dmi(
        &self,
        env: &HardwareEnvironment,
        indicators: &mut Vec<VmIndicator>,
        scores: &mut HashMap<DetectionMethod, f64>,
    ) {
        let dmi_fields = [
            &env.dmi_system_manufacturer,
            &env.dmi_system_product,
            &env.dmi_bios_vendor,
            &env.dmi_board_product,
        ];

        for field in &dmi_fields {
            if let Some(val) = field {
                let val_lower = val.to_lowercase();
                for (pattern, vendor) in DMI_MANUFACTURERS.iter().chain(DMI_PRODUCTS.iter()) {
                    if val_lower.contains(pattern) {
                        let conf = 0.9;
                        indicators.push(VmIndicator {
                            method: DetectionMethod::DmiString,
                            vendor: *vendor,
                            confidence: conf,
                            evidence: format!("DMI string '{val}' contains '{pattern}'"),
                        });
                        let existing = scores
                            .get(&DetectionMethod::DmiString)
                            .copied()
                            .unwrap_or(0.0);
                        scores.insert(DetectionMethod::DmiString, existing.max(conf));
                        break;
                    }
                }
            }
        }
    }

    fn check_mac(
        &self,
        env: &HardwareEnvironment,
        indicators: &mut Vec<VmIndicator>,
        scores: &mut HashMap<DetectionMethod, f64>,
    ) {
        for mac in &env.mac_addresses {
            let mac_lower = mac.to_lowercase();
            for (oui, vendor) in MAC_OUIS {
                if mac_lower.starts_with(oui) {
                    indicators.push(VmIndicator {
                        method: DetectionMethod::MacOui,
                        vendor: *vendor,
                        confidence: 0.85,
                        evidence: format!("MAC {mac} matches OUI {oui} ({vendor})"),
                    });
                    let existing = scores.get(&DetectionMethod::MacOui).copied().unwrap_or(0.0);
                    scores.insert(DetectionMethod::MacOui, existing.max(0.85));
                }
            }
        }
    }

    fn check_drivers(
        &self,
        env: &HardwareEnvironment,
        indicators: &mut Vec<VmIndicator>,
        scores: &mut HashMap<DetectionMethod, f64>,
    ) {
        for driver in &env.device_drivers {
            let driver_lower = driver.to_lowercase();
            for (name, vendor) in VM_DRIVERS {
                if driver_lower.contains(name) {
                    indicators.push(VmIndicator {
                        method: DetectionMethod::DeviceDriver,
                        vendor: *vendor,
                        confidence: 0.88,
                        evidence: format!("VM driver loaded: {driver} ({vendor})"),
                    });
                    let existing = scores
                        .get(&DetectionMethod::DeviceDriver)
                        .copied()
                        .unwrap_or(0.0);
                    scores.insert(DetectionMethod::DeviceDriver, existing.max(0.88));
                }
            }
        }
    }
}
