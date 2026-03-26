use serde::{Deserialize, Serialize};

/// Technique used to load a payload entirely in memory without touching disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LoadTechnique {
    ReflectivePe,
    LinuxMemfd,
    PackedPayload,
    ModuleStomping,
    ShellcodeExec,
}

impl std::fmt::Display for LoadTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReflectivePe => write!(f, "reflective-pe"),
            Self::LinuxMemfd => write!(f, "linux-memfd"),
            Self::PackedPayload => write!(f, "packed-payload"),
            Self::ModuleStomping => write!(f, "module-stomping"),
            Self::ShellcodeExec => write!(f, "shellcode-exec"),
        }
    }
}

/// Permission flags for a virtual memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl MemoryPermissions {
    pub fn rwx() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
        }
    }

    pub fn rw() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
        }
    }

    pub fn rx() -> Self {
        Self {
            read: true,
            write: false,
            execute: true,
        }
    }

    pub fn readonly() -> Self {
        Self {
            read: true,
            write: false,
            execute: false,
        }
    }
}

/// A contiguous region of virtual memory with associated permissions and contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub base_address: u64,
    pub size: usize,
    pub permissions: MemoryPermissions,
    pub contents: Vec<u8>,
}

/// Descriptor specifying what payload to load and how.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadDescriptor {
    pub technique: LoadTechnique,
    pub payload_data: Vec<u8>,
    pub entry_offset: usize,
}

/// Result of planning a memory load operation, containing allocated
/// regions, the computed entry point, and cleanup steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadResult {
    pub regions: Vec<MemoryRegion>,
    pub entry_point: u64,
    pub cleanup_actions: Vec<String>,
}

const PE_IMAGE_BASE: u64 = 0x1000_0000;
const MEMFD_BASE: u64 = 0x7F00_0000_0000;
const SHELLCODE_BASE: u64 = 0x0040_0000;
const MODULE_STOMP_BASE: u64 = 0x7FFE_0000;
const PACKED_BASE: u64 = 0x0060_0000;

const PE_HEADER_SIZE: usize = 0x200;
const PE_SECTION_ALIGNMENT: usize = 0x1000;

/// Plans in-memory payload loading across multiple techniques without
/// performing actual OS calls, producing a deterministic sequence of
/// memory regions and cleanup actions suitable for simulation or replay.
pub struct MemoryLoader {
    _rng_seed: u64,
}

impl MemoryLoader {
    pub fn new() -> Self {
        Self {
            _rng_seed: 0xDEAD_BEEF,
        }
    }

    pub fn with_seed(seed: u64) -> Self {
        Self { _rng_seed: seed }
    }

    pub fn plan_load(&self, desc: &PayloadDescriptor) -> LoadResult {
        match desc.technique {
            LoadTechnique::ReflectivePe => {
                Self::generate_reflective_pe_steps(&desc.payload_data, desc.entry_offset)
            }
            LoadTechnique::LinuxMemfd => {
                Self::generate_memfd_steps(&desc.payload_data, desc.entry_offset)
            }
            LoadTechnique::PackedPayload => {
                Self::generate_packed_steps(&desc.payload_data, desc.entry_offset)
            }
            LoadTechnique::ModuleStomping => {
                Self::generate_module_stomp_steps(&desc.payload_data, "ntdll.dll")
            }
            LoadTechnique::ShellcodeExec => Self::generate_shellcode_steps(&desc.payload_data),
        }
    }

    /// Parse PE headers, allocate virtual sections, copy section data,
    /// apply relocations, and resolve import thunks.
    pub fn generate_reflective_pe_steps(payload: &[u8], entry_offset: usize) -> LoadResult {
        let header_region = MemoryRegion {
            base_address: PE_IMAGE_BASE,
            size: PE_HEADER_SIZE,
            permissions: MemoryPermissions::readonly(),
            contents: payload
                .get(..PE_HEADER_SIZE.min(payload.len()))
                .unwrap_or(payload)
                .to_vec(),
        };

        let text_size = payload.len().saturating_sub(PE_HEADER_SIZE);
        let text_base = PE_IMAGE_BASE + PE_SECTION_ALIGNMENT as u64;
        let text_data: Vec<u8> = payload.get(PE_HEADER_SIZE..).unwrap_or(&[]).to_vec();

        let text_region = MemoryRegion {
            base_address: text_base,
            size: align_up(text_size, PE_SECTION_ALIGNMENT),
            permissions: MemoryPermissions::rx(),
            contents: text_data,
        };

        let data_base = text_base + align_up(text_size, PE_SECTION_ALIGNMENT) as u64;
        let data_region = MemoryRegion {
            base_address: data_base,
            size: PE_SECTION_ALIGNMENT,
            permissions: MemoryPermissions::rw(),
            contents: vec![0u8; PE_SECTION_ALIGNMENT],
        };

        let iat_base = data_base + PE_SECTION_ALIGNMENT as u64;
        let iat_region = MemoryRegion {
            base_address: iat_base,
            size: PE_SECTION_ALIGNMENT,
            permissions: MemoryPermissions::rw(),
            contents: vec![0u8; PE_SECTION_ALIGNMENT],
        };

        let entry_point = text_base + entry_offset as u64;

        let mut result = LoadResult {
            regions: vec![header_region, text_region, data_region, iat_region],
            entry_point,
            cleanup_actions: Vec::new(),
        };
        result.cleanup_actions = Self::generate_cleanup_sequence(&result);
        result
    }

    /// Create a memfd anonymous file descriptor, write the payload,
    /// and prepare fexecve arguments.
    pub fn generate_memfd_steps(payload: &[u8], entry_offset: usize) -> LoadResult {
        let fd_region = MemoryRegion {
            base_address: MEMFD_BASE,
            size: payload.len(),
            permissions: MemoryPermissions::rw(),
            contents: payload.to_vec(),
        };

        let exec_region = MemoryRegion {
            base_address: MEMFD_BASE + align_up(payload.len(), 0x1000) as u64,
            size: 0x1000,
            permissions: MemoryPermissions::rx(),
            contents: payload
                .get(entry_offset..entry_offset.saturating_add(0x1000).min(payload.len()))
                .unwrap_or(&[])
                .to_vec(),
        };

        let mut result = LoadResult {
            regions: vec![fd_region, exec_region],
            entry_point: MEMFD_BASE + entry_offset as u64,
            cleanup_actions: Vec::new(),
        };
        result.cleanup_actions = Self::generate_cleanup_sequence(&result);
        result.cleanup_actions.push("close_memfd".to_string());
        result.cleanup_actions.push("unlink_proc_fd".to_string());
        result
    }

    /// Decrypt the packed payload, decompress it, execute from memory,
    /// then wipe all intermediary buffers.
    pub fn generate_packed_steps(payload: &[u8], entry_offset: usize) -> LoadResult {
        let decrypted = xor_transform(payload, 0xAA);

        let decrypt_region = MemoryRegion {
            base_address: PACKED_BASE,
            size: decrypted.len(),
            permissions: MemoryPermissions::rw(),
            contents: decrypted.clone(),
        };

        let decompress_region = MemoryRegion {
            base_address: PACKED_BASE + align_up(decrypted.len(), 0x1000) as u64,
            size: decrypted.len(),
            permissions: MemoryPermissions::rw(),
            contents: decrypted.clone(),
        };

        let exec_region = MemoryRegion {
            base_address: PACKED_BASE + 2 * align_up(decrypted.len(), 0x1000) as u64,
            size: decrypted.len(),
            permissions: MemoryPermissions::rx(),
            contents: decrypted,
        };

        let mut result = LoadResult {
            regions: vec![decrypt_region, decompress_region, exec_region],
            entry_point: PACKED_BASE
                + 2 * align_up(payload.len(), 0x1000) as u64
                + entry_offset as u64,
            cleanup_actions: Vec::new(),
        };
        result.cleanup_actions = Self::generate_cleanup_sequence(&result);
        result
            .cleanup_actions
            .push("wipe_decrypt_buffer".to_string());
        result
            .cleanup_actions
            .push("wipe_decompress_buffer".to_string());
        result
    }

    /// Load a legitimate DLL, then overwrite its .text section with
    /// payload shellcode to hide inside a known module.
    pub fn generate_module_stomp_steps(payload: &[u8], target_dll: &str) -> LoadResult {
        let dll_region = MemoryRegion {
            base_address: MODULE_STOMP_BASE,
            size: 0x10000,
            permissions: MemoryPermissions::rx(),
            contents: vec![0xCC; 0x10000],
        };

        let stomp_size = payload.len().min(0x10000);
        let mut stomped_contents = vec![0xCC; 0x10000];
        stomped_contents[..stomp_size].copy_from_slice(&payload[..stomp_size]);

        let stomped_region = MemoryRegion {
            base_address: MODULE_STOMP_BASE,
            size: 0x10000,
            permissions: MemoryPermissions::rx(),
            contents: stomped_contents,
        };

        let mut result = LoadResult {
            regions: vec![dll_region, stomped_region],
            entry_point: MODULE_STOMP_BASE,
            cleanup_actions: Vec::new(),
        };
        result.cleanup_actions = Self::generate_cleanup_sequence(&result);
        result
            .cleanup_actions
            .push(format!("restore_original_module:{}", target_dll));
        result
    }

    /// Allocate RWX memory via VirtualAlloc, write shellcode, and
    /// start execution via CreateThread.
    pub fn generate_shellcode_steps(payload: &[u8]) -> LoadResult {
        let region = MemoryRegion {
            base_address: SHELLCODE_BASE,
            size: align_up(payload.len(), 0x1000),
            permissions: MemoryPermissions::rwx(),
            contents: payload.to_vec(),
        };

        let mut result = LoadResult {
            regions: vec![region],
            entry_point: SHELLCODE_BASE,
            cleanup_actions: Vec::new(),
        };
        result.cleanup_actions = Self::generate_cleanup_sequence(&result);
        result
    }

    /// Produce cleanup steps that zero and free every allocated region.
    pub fn generate_cleanup_sequence(result: &LoadResult) -> Vec<String> {
        result
            .regions
            .iter()
            .map(|r| format!("zero_and_free:0x{:X}:{}", r.base_address, r.size))
            .collect()
    }
}

impl Default for MemoryLoader {
    fn default() -> Self {
        Self::new()
    }
}

fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

fn xor_transform(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|b| b ^ key).collect()
}
