use super::vm_detector::*;

#[test]
fn clean_hardware_returns_not_vm() {
    let detector = VmDetector::with_defaults();
    let env = HardwareEnvironment::default();
    let result = detector.detect(&env);
    assert!(!result.is_vm);
    assert_eq!(result.vendor, VmVendor::None);
    assert_eq!(result.action, VmAction::Proceed);
}

#[test]
fn cpuid_hypervisor_bit_detected() {
    let detector = VmDetector::with_defaults();
    let env = HardwareEnvironment {
        cpuid_leaf1_ecx: Some(0x80000000),
        ..Default::default()
    };
    let result = detector.detect(&env);
    assert!(result.is_vm);
    assert!(result.confidence >= 0.9);
}

#[test]
fn cpuid_vmware_vendor_detected() {
    let detector = VmDetector::with_defaults();
    let env = HardwareEnvironment {
        cpuid_leaf40_vendor: Some("VMwareVMware".to_string()),
        ..Default::default()
    };
    let result = detector.detect(&env);
    assert!(result.is_vm);
    assert_eq!(result.vendor, VmVendor::VMware);
}

#[test]
fn cpuid_kvm_vendor_detected() {
    let detector = VmDetector::with_defaults();
    let env = HardwareEnvironment {
        cpuid_leaf40_vendor: Some("KVMKVMKVM\0\0\0".to_string()),
        ..Default::default()
    };
    let result = detector.detect(&env);
    assert!(result.is_vm);
    assert_eq!(result.vendor, VmVendor::Kvm);
}

#[test]
fn dmi_vmware_manufacturer_detected() {
    let detector = VmDetector::with_defaults();
    let env = HardwareEnvironment {
        dmi_system_manufacturer: Some("VMware, Inc.".to_string()),
        ..Default::default()
    };
    let result = detector.detect(&env);
    assert!(result.is_vm);
    assert_eq!(result.vendor, VmVendor::VMware);
}

#[test]
fn dmi_virtualbox_product_detected() {
    let detector = VmDetector::with_defaults();
    let env = HardwareEnvironment {
        dmi_system_product: Some("VirtualBox".to_string()),
        ..Default::default()
    };
    let result = detector.detect(&env);
    assert!(result.is_vm);
    assert_eq!(result.vendor, VmVendor::VirtualBox);
}

#[test]
fn dmi_hyperv_detected() {
    let detector = VmDetector::with_defaults();
    let env = HardwareEnvironment {
        dmi_system_manufacturer: Some("Microsoft Corporation".to_string()),
        dmi_system_product: Some("Virtual Machine".to_string()),
        ..Default::default()
    };
    let result = detector.detect(&env);
    assert!(result.is_vm);
    assert_eq!(result.vendor, VmVendor::HyperV);
}

#[test]
fn mac_oui_vmware_detected() {
    let detector = VmDetector::with_defaults();
    let env = HardwareEnvironment {
        mac_addresses: vec!["00:50:56:ab:cd:ef".to_string()],
        ..Default::default()
    };
    let result = detector.detect(&env);
    assert!(result.is_vm);
    assert_eq!(result.vendor, VmVendor::VMware);
}

#[test]
fn mac_oui_virtualbox_detected() {
    let detector = VmDetector::with_defaults();
    let env = HardwareEnvironment {
        mac_addresses: vec!["08:00:27:ab:cd:ef".to_string()],
        ..Default::default()
    };
    let result = detector.detect(&env);
    assert!(result.is_vm);
    assert_eq!(result.vendor, VmVendor::VirtualBox);
}

#[test]
fn mac_oui_kvm_detected() {
    let detector = VmDetector::with_defaults();
    let env = HardwareEnvironment {
        mac_addresses: vec!["52:54:00:12:34:56".to_string()],
        ..Default::default()
    };
    let result = detector.detect(&env);
    assert!(result.is_vm);
    assert_eq!(result.vendor, VmVendor::Kvm);
}

#[test]
fn vm_driver_vmhgfs_detected() {
    let detector = VmDetector::with_defaults();
    let env = HardwareEnvironment {
        device_drivers: vec!["vmhgfs".to_string()],
        ..Default::default()
    };
    let result = detector.detect(&env);
    assert!(result.is_vm);
}

#[test]
fn vm_driver_virtio_detected() {
    let detector = VmDetector::with_defaults();
    let env = HardwareEnvironment {
        device_drivers: vec!["virtio_net".to_string()],
        ..Default::default()
    };
    let result = detector.detect(&env);
    assert!(result.is_vm);
}

#[test]
fn abort_action_on_high_confidence() {
    let detector = VmDetector::with_defaults();
    let env = HardwareEnvironment {
        cpuid_leaf40_vendor: Some("VMwareVMware".to_string()),
        dmi_system_manufacturer: Some("VMware, Inc.".to_string()),
        mac_addresses: vec!["00:0c:29:ab:cd:ef".to_string()],
        ..Default::default()
    };
    let result = detector.detect(&env);
    assert_eq!(result.action, VmAction::Abort);
}

#[test]
fn caution_on_moderate_confidence() {
    let detector = VmDetector::new(VmDetectorConfig {
        abort_confidence: 0.95,
        caution_confidence: 0.4,
        ..Default::default()
    });
    let env = HardwareEnvironment {
        mac_addresses: vec!["08:00:27:ab:cd:ef".to_string()],
        ..Default::default()
    };
    let result = detector.detect(&env);
    assert_eq!(result.action, VmAction::Caution);
}

#[test]
fn vendor_display_formatting() {
    assert_eq!(format!("{}", VmVendor::VMware), "VMware");
    assert_eq!(format!("{}", VmVendor::Kvm), "KVM");
    assert_eq!(format!("{}", VmVendor::HyperV), "Hyper-V");
    assert_eq!(format!("{}", VmVendor::None), "None");
}

#[test]
fn multiple_indicators_aggregate_correctly() {
    let detector = VmDetector::with_defaults();
    let env = HardwareEnvironment {
        cpuid_leaf40_vendor: Some("VMwareVMware".to_string()),
        mac_addresses: vec!["00:50:56:aa:bb:cc".to_string()],
        device_drivers: vec!["vmxnet".to_string()],
        ..Default::default()
    };
    let result = detector.detect(&env);
    assert!(result.indicators.len() >= 3);
    assert!(result.confidence >= 0.85);
}
