use super::memory_loader::*;

#[test]
fn test_reflective_pe_allocation() {
    let payload = vec![0x4D, 0x5A, 0x90, 0x00]; // MZ header stub
    let mut padded = vec![0u8; 0x200];
    padded[..payload.len()].copy_from_slice(&payload);
    padded.extend_from_slice(&[0xCC; 0x400]);

    let result = MemoryLoader::generate_reflective_pe_steps(&padded, 0);

    assert!(result.regions.len() >= 4);
    assert_eq!(result.regions[0].permissions, MemoryPermissions::readonly());
    assert_eq!(result.regions[1].permissions, MemoryPermissions::rx());
    assert_eq!(result.regions[2].permissions, MemoryPermissions::rw());
    assert_eq!(result.regions[3].permissions, MemoryPermissions::rw());
    assert!(result.entry_point >= result.regions[1].base_address);
    assert!(!result.cleanup_actions.is_empty());
}

#[test]
fn test_memfd_steps() {
    let payload = b"#!/bin/sh\necho hello\n";
    let result = MemoryLoader::generate_memfd_steps(payload, 0);

    assert!(result.regions.len() >= 2);
    assert_eq!(result.regions[0].contents, payload.to_vec());
    assert!(result.regions[0].permissions.write);
    assert!(result
        .cleanup_actions
        .iter()
        .any(|a| a.contains("close_memfd")));
    assert!(result
        .cleanup_actions
        .iter()
        .any(|a| a.contains("unlink_proc_fd")));
}

#[test]
fn test_packed_payload_roundtrip() {
    let original = b"secret_payload_data_here";
    let encrypted: Vec<u8> = original.iter().map(|b| b ^ 0xAA).collect();

    let result = MemoryLoader::generate_packed_steps(&encrypted, 0);

    let exec_region = result.regions.last().unwrap();
    assert_eq!(exec_region.contents, original.to_vec());

    assert!(result
        .cleanup_actions
        .iter()
        .any(|a| a.contains("wipe_decrypt_buffer")));
    assert!(result
        .cleanup_actions
        .iter()
        .any(|a| a.contains("wipe_decompress_buffer")));
}

#[test]
fn test_module_stomping() {
    let shellcode = vec![0x90; 256];
    let result = MemoryLoader::generate_module_stomp_steps(&shellcode, "ntdll.dll");

    assert_eq!(result.regions.len(), 2);
    let stomped = &result.regions[1];
    assert_eq!(&stomped.contents[..256], &shellcode[..]);
    assert!(result
        .cleanup_actions
        .iter()
        .any(|a| a.contains("restore_original_module:ntdll.dll")));
}

#[test]
fn test_shellcode_exec_permissions() {
    let shellcode = vec![0xCC; 128];
    let result = MemoryLoader::generate_shellcode_steps(&shellcode);

    assert_eq!(result.regions.len(), 1);
    let region = &result.regions[0];
    assert!(region.permissions.read);
    assert!(region.permissions.write);
    assert!(region.permissions.execute);
    assert_eq!(region.contents, shellcode);
}

#[test]
fn test_cleanup_sequence() {
    let payload = vec![0x90; 64];
    let result = MemoryLoader::generate_shellcode_steps(&payload);

    let cleanup = MemoryLoader::generate_cleanup_sequence(&result);
    assert_eq!(cleanup.len(), result.regions.len());
    for action in &cleanup {
        assert!(action.starts_with("zero_and_free:0x"));
    }
}

#[test]
fn test_plan_load_dispatches_correctly() {
    let loader = MemoryLoader::new();

    let desc = PayloadDescriptor {
        technique: LoadTechnique::ShellcodeExec,
        payload_data: vec![0xCC; 32],
        entry_offset: 0,
    };
    let result = loader.plan_load(&desc);
    assert_eq!(result.regions[0].permissions, MemoryPermissions::rwx());

    let desc_memfd = PayloadDescriptor {
        technique: LoadTechnique::LinuxMemfd,
        payload_data: vec![0x7F, 0x45, 0x4C, 0x46],
        entry_offset: 0,
    };
    let result_memfd = loader.plan_load(&desc_memfd);
    assert!(result_memfd.regions[0].permissions.write);
}
