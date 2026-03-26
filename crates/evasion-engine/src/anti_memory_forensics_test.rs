use super::anti_memory_forensics::*;

#[test]
fn test_string_obfuscation_roundtrip() {
    let original = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQ";
    let obs = AntiMemoryForensics::obfuscate_string(original);
    let recovered = AntiMemoryForensics::deobfuscate_string(&obs);
    assert_eq!(recovered, original);
}

#[test]
fn test_obfuscated_not_plaintext() {
    let original = "supersecretpassword123";
    let obs = AntiMemoryForensics::obfuscate_string(original);
    assert_ne!(obs.ciphertext, original.as_bytes());
}

#[test]
fn test_heap_allocation_randomness() {
    let a1 = AntiMemoryForensics::generate_heap_allocation(0x2000);
    let a2 = AntiMemoryForensics::generate_heap_allocation(0x2000);
    let a3 = AntiMemoryForensics::generate_heap_allocation(0x2000);

    let addresses = [a1.address, a2.address, a3.address];
    let unique: std::collections::HashSet<_> = addresses.iter().collect();
    assert!(unique.len() >= 2, "Expected randomized base addresses");
    assert_eq!(a1.address & 0xFFF, 0, "Address must be page-aligned");
}

#[test]
fn test_pool_tag_replacements() {
    let replacements = AntiMemoryForensics::generate_pool_tag_replacements();
    assert!(!replacements.is_empty());
    for entry in &replacements {
        assert_ne!(entry.original_tag, entry.replacement_tag);
    }

    let forensic_tags = AntiMemoryForensics::common_forensic_pool_tags();
    let originals: Vec<[u8; 4]> = replacements.iter().map(|e| e.original_tag).collect();
    for tag in &forensic_tags {
        assert!(originals.contains(tag));
    }
}

#[test]
fn test_vad_operations_generated() {
    let regions = vec![(0x0040_0000u64, 0x1000usize), (0x0080_0000, 0x2000)];
    let ops = AntiMemoryForensics::generate_vad_hide_operations(&regions);
    assert_eq!(ops.len(), 2);
    assert!(ops[0].hide);
    assert_eq!(ops[0].region_base, 0x0040_0000);
    assert_eq!(ops[1].region_size, 0x2000);
    assert_eq!(ops[0].original_protection, 0x40);
}

#[test]
fn test_dkom_operations() {
    let targets = [
        DkomTarget::ProcessList,
        DkomTarget::ThreadList,
        DkomTarget::HandleTable,
        DkomTarget::ModuleList,
    ];
    for target in &targets {
        let ops = AntiMemoryForensics::generate_dkom_operations(*target);
        assert!(!ops.is_empty(), "No operations for {:?}", target);
        for op in &ops {
            assert_eq!(op.target, *target);
            assert!(!op.action.is_empty());
            assert!(!op.description.is_empty());
        }
    }
}

#[test]
fn test_different_keys_per_string() {
    let obs1 = AntiMemoryForensics::obfuscate_string("same_input");
    let obs2 = AntiMemoryForensics::obfuscate_string("same_input");
    assert_ne!(
        obs1.key, obs2.key,
        "Each encryption should use a unique random key"
    );
    assert_eq!(obs1.decrypt(), obs2.decrypt());
}

#[test]
fn test_common_forensic_pool_tags_known() {
    let tags = AntiMemoryForensics::common_forensic_pool_tags();
    assert!(tags.len() >= 10);
    assert!(tags.contains(b"Proc"));
    assert!(tags.contains(b"Thre"));
    assert!(tags.contains(b"File"));
}
