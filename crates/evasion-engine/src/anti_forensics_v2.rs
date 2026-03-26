use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Anti-forensic technique categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AntiForensicCategory {
    Timestomping,
    SlackSpaceHiding,
    MftManipulation,
    InodeReuse,
    SteganographicHiding,
    EncryptedContainerEvasion,
    SwapManipulation,
}

impl std::fmt::Display for AntiForensicCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timestomping => write!(f, "timestomping"),
            Self::SlackSpaceHiding => write!(f, "slack-space-hiding"),
            Self::MftManipulation => write!(f, "mft-manipulation"),
            Self::InodeReuse => write!(f, "inode-reuse"),
            Self::SteganographicHiding => write!(f, "steganographic-hiding"),
            Self::EncryptedContainerEvasion => write!(f, "encrypted-container-evasion"),
            Self::SwapManipulation => write!(f, "swap-manipulation"),
        }
    }
}

/// Filesystem types supported for anti-forensic operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FilesystemType {
    Ntfs,
    Ext4,
    Ext3,
    Xfs,
    Btrfs,
    Apfs,
    Hfs,
    Fat32,
    Exfat,
}

impl std::fmt::Display for FilesystemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ntfs => write!(f, "NTFS"),
            Self::Ext4 => write!(f, "ext4"),
            Self::Ext3 => write!(f, "ext3"),
            Self::Xfs => write!(f, "XFS"),
            Self::Btrfs => write!(f, "btrfs"),
            Self::Apfs => write!(f, "APFS"),
            Self::Hfs => write!(f, "HFS+"),
            Self::Fat32 => write!(f, "FAT32"),
            Self::Exfat => write!(f, "exFAT"),
        }
    }
}

/// Steganographic embedding formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StegoFormat {
    PngMetadata,
    JpegExif,
    PngLsb,
    JpegDct,
    PdfMetadata,
    Mp3Id3,
    ZipComment,
}

impl std::fmt::Display for StegoFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PngMetadata => write!(f, "PNG-metadata"),
            Self::JpegExif => write!(f, "JPEG-EXIF"),
            Self::PngLsb => write!(f, "PNG-LSB"),
            Self::JpegDct => write!(f, "JPEG-DCT"),
            Self::PdfMetadata => write!(f, "PDF-metadata"),
            Self::Mp3Id3 => write!(f, "MP3-ID3"),
            Self::ZipComment => write!(f, "ZIP-comment"),
        }
    }
}

/// File timestamp set (mtime, atime, ctime/birth).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTimestamps {
    pub mtime_epoch: u64,
    pub atime_epoch: u64,
    pub ctime_epoch: Option<u64>,
    pub birth_epoch: Option<u64>,
}

/// Timestomping operation specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestompOperation {
    pub target_path: String,
    pub original_timestamps: FileTimestamps,
    pub desired_timestamps: FileTimestamps,
    pub reference_file: Option<String>,
    pub command: String,
    pub detection_risk: f64,
}

/// Slack space hiding operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackSpaceOperation {
    pub target_path: String,
    pub filesystem: FilesystemType,
    pub file_size_bytes: u64,
    pub cluster_size_bytes: u64,
    pub slack_bytes_available: u64,
    pub payload_size: u64,
    pub can_hide: bool,
    pub command: String,
}

/// NTFS MFT manipulation pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MftManipulation {
    pub operation: MftOperation,
    pub target_entry: String,
    pub description: String,
    pub command: String,
    pub requires_raw_disk: bool,
    pub detection_risk: f64,
}

/// Types of MFT manipulation operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MftOperation {
    HideEntry,
    ModifyTimestamps,
    MarkDeleted,
    SwapEntries,
    InsertOrphan,
    ModifyFileName,
}

impl std::fmt::Display for MftOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HideEntry => write!(f, "hide-entry"),
            Self::ModifyTimestamps => write!(f, "modify-timestamps"),
            Self::MarkDeleted => write!(f, "mark-deleted"),
            Self::SwapEntries => write!(f, "swap-entries"),
            Self::InsertOrphan => write!(f, "insert-orphan"),
            Self::ModifyFileName => write!(f, "modify-filename"),
        }
    }
}

/// Inode reuse pattern for ext-family filesystems.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InodeReusePattern {
    pub filesystem: FilesystemType,
    pub target_inode: u64,
    pub original_file: String,
    pub replacement_file: String,
    pub description: String,
    pub command: String,
}

/// Steganographic payload embedding result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StegoOperation {
    pub format: StegoFormat,
    pub carrier_path: String,
    pub payload_size_bytes: u64,
    pub max_capacity_bytes: u64,
    pub encoding_method: String,
    pub detection_risk: f64,
    pub command: String,
}

/// Encrypted container evasion configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerEvasionConfig {
    pub container_type: EncryptedContainerType,
    pub outer_volume_size_mb: u64,
    pub hidden_volume_size_mb: u64,
    pub plausible_deniability: bool,
    pub decoy_files: Vec<String>,
    pub description: String,
    pub command: String,
}

/// Types of encrypted containers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EncryptedContainerType {
    VeraCrypt,
    TrueCrypt,
    Luks,
    BitLocker,
    FileVault,
    DmCrypt,
}

impl std::fmt::Display for EncryptedContainerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VeraCrypt => write!(f, "VeraCrypt"),
            Self::TrueCrypt => write!(f, "TrueCrypt"),
            Self::Luks => write!(f, "LUKS"),
            Self::BitLocker => write!(f, "BitLocker"),
            Self::FileVault => write!(f, "FileVault"),
            Self::DmCrypt => write!(f, "dm-crypt"),
        }
    }
}

/// Swap/pagefile manipulation operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapManipulation {
    pub swap_type: SwapType,
    pub swap_path: String,
    pub operation: String,
    pub command: String,
    pub requires_root: bool,
}

/// Types of swap space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SwapType {
    LinuxSwapPartition,
    LinuxSwapFile,
    WindowsPagefile,
    MacOsSwap,
}

impl std::fmt::Display for SwapType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LinuxSwapPartition => write!(f, "linux-swap-partition"),
            Self::LinuxSwapFile => write!(f, "linux-swap-file"),
            Self::WindowsPagefile => write!(f, "windows-pagefile"),
            Self::MacOsSwap => write!(f, "macos-swap"),
        }
    }
}

/// Complete anti-forensics analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiForensicsReport {
    pub timestomp_operations: Vec<TimestompOperation>,
    pub slack_space_operations: Vec<SlackSpaceOperation>,
    pub mft_manipulations: Vec<MftManipulation>,
    pub inode_reuse_patterns: Vec<InodeReusePattern>,
    pub stego_operations: Vec<StegoOperation>,
    pub container_configs: Vec<ContainerEvasionConfig>,
    pub swap_manipulations: Vec<SwapManipulation>,
    pub category_coverage: HashMap<AntiForensicCategory, usize>,
}

/// Target filesystem environment for anti-forensic analysis.
#[derive(Debug, Clone, Default)]
pub struct ForensicEnvironment {
    pub filesystem: Option<FilesystemType>,
    pub cluster_size_bytes: u64,
    pub target_files: Vec<ForensicTargetFile>,
    pub reference_files: Vec<(String, FileTimestamps)>,
    pub carrier_files: Vec<CarrierFile>,
    pub is_windows: bool,
    pub has_raw_disk_access: bool,
    pub swap_enabled: bool,
    pub swap_path: Option<String>,
}

/// A file targeted for anti-forensic manipulation.
#[derive(Debug, Clone)]
pub struct ForensicTargetFile {
    pub path: String,
    pub size_bytes: u64,
    pub timestamps: FileTimestamps,
    pub inode: Option<u64>,
}

/// A carrier file for steganographic embedding.
#[derive(Debug, Clone)]
pub struct CarrierFile {
    pub path: String,
    pub format: StegoFormat,
    pub size_bytes: u64,
}

/// Configuration for the anti-forensics toolkit.
#[derive(Debug, Clone)]
pub struct AntiForensicsV2Config {
    pub enable_timestomping: bool,
    pub enable_slack_space: bool,
    pub enable_mft_manipulation: bool,
    pub enable_inode_reuse: bool,
    pub enable_steganography: bool,
    pub enable_container_evasion: bool,
    pub enable_swap_manipulation: bool,
    pub max_detection_risk: f64,
    pub stomp_to_reference: bool,
}

impl Default for AntiForensicsV2Config {
    fn default() -> Self {
        Self {
            enable_timestomping: true,
            enable_slack_space: true,
            enable_mft_manipulation: true,
            enable_inode_reuse: true,
            enable_steganography: true,
            enable_container_evasion: true,
            enable_swap_manipulation: true,
            max_detection_risk: 1.0,
            stomp_to_reference: true,
        }
    }
}

/// Advanced anti-forensics toolkit for evidence concealment.
pub struct AntiForensicsToolkit {
    config: AntiForensicsV2Config,
}

impl AntiForensicsToolkit {
    pub fn new(config: AntiForensicsV2Config) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(AntiForensicsV2Config::default())
    }

    /// Analyze the filesystem environment and produce a full anti-forensics report.
    pub fn analyze(&self, env: &ForensicEnvironment) -> AntiForensicsReport {
        let mut category_coverage: HashMap<AntiForensicCategory, usize> = HashMap::new();

        let timestomp_operations = if self.config.enable_timestomping {
            let ops = self.generate_timestomp_operations(env);
            *category_coverage
                .entry(AntiForensicCategory::Timestomping)
                .or_insert(0) += ops.len();
            ops
        } else {
            Vec::new()
        };

        let slack_space_operations = if self.config.enable_slack_space {
            let ops = self.generate_slack_space_operations(env);
            *category_coverage
                .entry(AntiForensicCategory::SlackSpaceHiding)
                .or_insert(0) += ops.len();
            ops
        } else {
            Vec::new()
        };

        let mft_manipulations = if self.config.enable_mft_manipulation
            && env.filesystem == Some(FilesystemType::Ntfs)
        {
            let ops = self.generate_mft_manipulations(env);
            *category_coverage
                .entry(AntiForensicCategory::MftManipulation)
                .or_insert(0) += ops.len();
            ops
        } else {
            Vec::new()
        };

        let inode_reuse_patterns = if self.config.enable_inode_reuse
            && matches!(
                env.filesystem,
                Some(FilesystemType::Ext4) | Some(FilesystemType::Ext3)
            ) {
            let ops = self.generate_inode_reuse_patterns(env);
            *category_coverage
                .entry(AntiForensicCategory::InodeReuse)
                .or_insert(0) += ops.len();
            ops
        } else {
            Vec::new()
        };

        let stego_operations = if self.config.enable_steganography {
            let ops = self.generate_stego_operations(env);
            *category_coverage
                .entry(AntiForensicCategory::SteganographicHiding)
                .or_insert(0) += ops.len();
            ops
        } else {
            Vec::new()
        };

        let container_configs = if self.config.enable_container_evasion {
            let ops = self.generate_container_configs(env);
            *category_coverage
                .entry(AntiForensicCategory::EncryptedContainerEvasion)
                .or_insert(0) += ops.len();
            ops
        } else {
            Vec::new()
        };

        let swap_manipulations = if self.config.enable_swap_manipulation && env.swap_enabled {
            let ops = self.generate_swap_manipulations(env);
            *category_coverage
                .entry(AntiForensicCategory::SwapManipulation)
                .or_insert(0) += ops.len();
            ops
        } else {
            Vec::new()
        };

        AntiForensicsReport {
            timestomp_operations,
            slack_space_operations,
            mft_manipulations,
            inode_reuse_patterns,
            stego_operations,
            container_configs,
            swap_manipulations,
            category_coverage,
        }
    }

    /// Generate timestomping operations to blend files with surrounding timestamps.
    fn generate_timestomp_operations(&self, env: &ForensicEnvironment) -> Vec<TimestompOperation> {
        let mut operations = Vec::new();

        let reference_ts = if let Some(ref_file) = env.reference_files.first() {
            ref_file.1.clone()
        } else {
            FileTimestamps {
                mtime_epoch: 1609459200,
                atime_epoch: 1609459200,
                ctime_epoch: Some(1609459200),
                birth_epoch: Some(1609459200),
            }
        };

        for target in &env.target_files {
            let ref_name = env
                .reference_files
                .first()
                .map(|(p, _)| p.as_str())
                .unwrap_or("/bin/ls");

            if env.is_windows {
                operations.push(TimestompOperation {
                    target_path: target.path.clone(),
                    original_timestamps: target.timestamps.clone(),
                    desired_timestamps: reference_ts.clone(),
                    reference_file: Some(ref_name.to_string()),
                    command: format!(
                        "powershell -c \"$(Get-Item '{}').LastWriteTime = $(Get-Item '{}').LastWriteTime; \
                         $(Get-Item '{}').LastAccessTime = $(Get-Item '{}').LastAccessTime; \
                         $(Get-Item '{}').CreationTime = $(Get-Item '{}').CreationTime\"",
                        target.path, ref_name, target.path, ref_name, target.path, ref_name
                    ),
                    detection_risk: 0.4,
                });
            } else {
                operations.push(TimestompOperation {
                    target_path: target.path.clone(),
                    original_timestamps: target.timestamps.clone(),
                    desired_timestamps: reference_ts.clone(),
                    reference_file: Some(ref_name.to_string()),
                    command: format!("touch -r {} {}", ref_name, target.path),
                    detection_risk: 0.3,
                });
            }

            operations.push(TimestompOperation {
                target_path: target.path.clone(),
                original_timestamps: target.timestamps.clone(),
                desired_timestamps: FileTimestamps {
                    mtime_epoch: reference_ts.mtime_epoch,
                    atime_epoch: reference_ts.atime_epoch,
                    ctime_epoch: reference_ts.ctime_epoch,
                    birth_epoch: reference_ts.birth_epoch,
                },
                reference_file: None,
                command: format!(
                    "touch -t {} {}",
                    Self::epoch_to_touch_format(reference_ts.mtime_epoch),
                    target.path
                ),
                detection_risk: 0.35,
            });
        }

        operations
            .into_iter()
            .filter(|o| o.detection_risk <= self.config.max_detection_risk)
            .collect()
    }

    /// Generate slack space hiding operations.
    fn generate_slack_space_operations(
        &self,
        env: &ForensicEnvironment,
    ) -> Vec<SlackSpaceOperation> {
        let mut operations = Vec::new();
        let cluster = if env.cluster_size_bytes > 0 {
            env.cluster_size_bytes
        } else {
            4096
        };

        for target in &env.target_files {
            let used_clusters = (target.size_bytes + cluster - 1) / cluster;
            let allocated = used_clusters * cluster;
            let slack = allocated - target.size_bytes;

            if slack > 0 {
                let fs_label = env
                    .filesystem
                    .map(|f| f.to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                operations.push(SlackSpaceOperation {
                    target_path: target.path.clone(),
                    filesystem: env.filesystem.unwrap_or(FilesystemType::Ext4),
                    file_size_bytes: target.size_bytes,
                    cluster_size_bytes: cluster,
                    slack_bytes_available: slack,
                    payload_size: slack,
                    can_hide: true,
                    command: format!(
                        "# Write to slack space of {} ({} filesystem)\n\
                         # File size: {} bytes, cluster size: {} bytes, slack: {} bytes\n\
                         dd if=payload.bin of={} bs=1 seek={} count={} conv=notrunc",
                        target.path,
                        fs_label,
                        target.size_bytes,
                        cluster,
                        slack,
                        target.path,
                        target.size_bytes,
                        slack
                    ),
                });
            }
        }

        operations
    }

    /// Generate NTFS MFT manipulation patterns.
    fn generate_mft_manipulations(&self, env: &ForensicEnvironment) -> Vec<MftManipulation> {
        let mut manipulations = Vec::new();

        for target in &env.target_files {
            manipulations.push(MftManipulation {
                operation: MftOperation::HideEntry,
                target_entry: target.path.clone(),
                description: format!(
                    "Set MFT entry IN_USE flag to 0 for {}, making it appear deleted to standard tools",
                    target.path
                ),
                command: format!(
                    "# Requires raw NTFS access (e.g., nfi.exe or custom tool)\n\
                     # Locate MFT entry for {path}\n\
                     # Clear IN_USE flag (byte offset 0x16, bit 0)\n\
                     # Entry becomes invisible to dir/FindFirstFile but data remains",
                    path = target.path
                ),
                requires_raw_disk: true,
                detection_risk: 0.5,
            });

            manipulations.push(MftManipulation {
                operation: MftOperation::ModifyTimestamps,
                target_entry: target.path.clone(),
                description: format!(
                    "Modify $STANDARD_INFORMATION and $FILE_NAME timestamps in MFT for {}",
                    target.path
                ),
                command: format!(
                    "# Both $STANDARD_INFORMATION (offset 0x10) and $FILE_NAME (offset 0x30)\n\
                     # must be modified to avoid timestamp inconsistency detection\n\
                     # Target: {path}\n\
                     # Tools: SetMACE, timestomp, NtSetInformationFile(FileBasicInformation)",
                    path = target.path
                ),
                requires_raw_disk: false,
                detection_risk: 0.6,
            });

            if env.has_raw_disk_access {
                manipulations.push(MftManipulation {
                    operation: MftOperation::InsertOrphan,
                    target_entry: target.path.clone(),
                    description: format!(
                        "Create orphan MFT entry with no parent directory link for {} data",
                        target.path
                    ),
                    command: "# Allocate new MFT entry\n\
                              # Copy file data to allocated clusters\n\
                              # Set MFT entry but do not create $INDEX_ALLOCATION entry in parent\n\
                              # File exists on disk but is not traversable via directory tree"
                        .to_string(),
                    requires_raw_disk: true,
                    detection_risk: 0.4,
                });
            }
        }

        manipulations
            .into_iter()
            .filter(|m| m.detection_risk <= self.config.max_detection_risk)
            .collect()
    }

    /// Generate inode reuse patterns for ext filesystems.
    fn generate_inode_reuse_patterns(&self, env: &ForensicEnvironment) -> Vec<InodeReusePattern> {
        let mut patterns = Vec::new();
        let fs = env.filesystem.unwrap_or(FilesystemType::Ext4);

        for target in &env.target_files {
            if let Some(inode) = target.inode {
                patterns.push(InodeReusePattern {
                    filesystem: fs,
                    target_inode: inode,
                    original_file: target.path.clone(),
                    replacement_file: format!("{}.clean", target.path),
                    description: format!(
                        "Delete {} and immediately create new file to reuse inode {}, overwriting forensic metadata",
                        target.path, inode
                    ),
                    command: format!(
                        "# Inode reuse attack on {} filesystem\n\
                         rm -f {path} && \\\n\
                         # Race to allocate same inode\n\
                         dd if=/dev/urandom of={path} bs=1 count={size} && \\\n\
                         sync",
                        fs,
                        path = target.path,
                        size = target.size_bytes
                    ),
                });
            }
        }

        patterns
    }

    /// Generate steganographic embedding operations.
    fn generate_stego_operations(&self, env: &ForensicEnvironment) -> Vec<StegoOperation> {
        let mut operations = Vec::new();

        for carrier in &env.carrier_files {
            let (capacity, method, command) = match carrier.format {
                StegoFormat::PngMetadata => (
                    carrier.size_bytes / 20,
                    "Embed in PNG tEXt/zTXt/iTXt ancillary chunks".to_string(),
                    format!(
                        "# Inject payload into PNG metadata chunks\n\
                         python3 -c \"\n\
                         import struct, zlib\n\
                         with open('{}', 'r+b') as f:\n\
                             # Seek to end of IDAT chunks\n\
                             # Insert tEXt chunk with base64-encoded payload\n\
                             pass\n\
                         \"",
                        carrier.path
                    ),
                ),
                StegoFormat::JpegExif => (
                    65535,
                    "Embed in JPEG EXIF APP1 marker (max 64KB per segment)".to_string(),
                    format!("exiftool -Comment='<base64_payload>' {}", carrier.path),
                ),
                StegoFormat::PngLsb => (
                    carrier.size_bytes / 8,
                    "LSB (Least Significant Bit) embedding in RGB pixel data".to_string(),
                    format!(
                        "# LSB steganography on {}\n\
                         # Capacity: ~{} bytes (1 bit per color channel per pixel)\n\
                         python3 -c \"\n\
                         from PIL import Image\n\
                         img = Image.open('{path}')\n\
                         pixels = list(img.getdata())\n\
                         # Embed payload in LSBs of R,G,B channels\n\
                         \"",
                        carrier.path,
                        carrier.size_bytes / 8,
                        path = carrier.path
                    ),
                ),
                StegoFormat::JpegDct => (
                    carrier.size_bytes / 16,
                    "DCT coefficient modification in JPEG quantization tables".to_string(),
                    format!(
                        "# Modify DCT coefficients in {}\n\
                         # Tools: jsteg, stegano, outguess\n\
                         jsteg hide {} payload.bin output.jpg",
                        carrier.path, carrier.path
                    ),
                ),
                StegoFormat::PdfMetadata => (
                    carrier.size_bytes / 50,
                    "Embed in PDF metadata streams and cross-reference table gaps".to_string(),
                    format!("exiftool -Author='<base64_payload>' {}", carrier.path),
                ),
                StegoFormat::Mp3Id3 => (
                    262144,
                    "Embed in MP3 ID3v2 APIC or TXXX frames (up to 256KB per frame)".to_string(),
                    format!(
                        "# Embed payload in ID3v2 tag of {}\n\
                         python3 -c \"\n\
                         from mutagen.id3 import ID3, TXXX\n\
                         tag = ID3('{path}')\n\
                         tag.add(TXXX(encoding=3, desc='data', text=['<base64_payload>']))\n\
                         tag.save()\n\
                         \"",
                        carrier.path,
                        path = carrier.path
                    ),
                ),
                StegoFormat::ZipComment => (
                    65535,
                    "Embed in ZIP end-of-central-directory comment field (max 64KB)".to_string(),
                    format!(
                        "python3 -c \"\n\
                         import zipfile\n\
                         with zipfile.ZipFile('{}', 'a') as zf:\n\
                             zf.comment = b'<payload_bytes>'\n\
                         \"",
                        carrier.path
                    ),
                ),
            };

            operations.push(StegoOperation {
                format: carrier.format,
                carrier_path: carrier.path.clone(),
                payload_size_bytes: carrier.size_bytes,
                max_capacity_bytes: capacity,
                encoding_method: method,
                detection_risk: Self::stego_detection_risk(carrier.format),
                command,
            });
        }

        operations
    }

    /// Generate encrypted container configurations with plausible deniability.
    fn generate_container_configs(&self, env: &ForensicEnvironment) -> Vec<ContainerEvasionConfig> {
        let mut configs = Vec::new();

        configs.push(ContainerEvasionConfig {
            container_type: EncryptedContainerType::VeraCrypt,
            outer_volume_size_mb: 1024,
            hidden_volume_size_mb: 256,
            plausible_deniability: true,
            decoy_files: vec![
                "financial_records.xlsx".to_string(),
                "tax_returns_2023.pdf".to_string(),
                "family_photos/".to_string(),
            ],
            description: "VeraCrypt hidden volume: outer volume contains plausible decoy files, \
                           hidden volume at end of outer volume space contains real payload. \
                           Under coercion, reveal outer password; hidden volume is statistically \
                           indistinguishable from random free-space fill."
                .to_string(),
            command: "veracrypt -t -c --volume-type=hidden --size=256M \
                      --encryption=AES-Twofish-Serpent --hash=whirlpool \
                      --filesystem=NTFS --random-source=/dev/urandom container.vc"
                .to_string(),
        });

        if !env.is_windows {
            configs.push(ContainerEvasionConfig {
                container_type: EncryptedContainerType::DmCrypt,
                outer_volume_size_mb: 512,
                hidden_volume_size_mb: 128,
                plausible_deniability: false,
                decoy_files: vec![],
                description:
                    "dm-crypt/LUKS container with detached header stored on removable media. \
                              Without the header, the volume is indistinguishable from random data."
                        .to_string(),
                command: "dd if=/dev/urandom of=container.img bs=1M count=512 && \\\n\
                          cryptsetup luksFormat --header header.img container.img && \\\n\
                          cryptsetup luksOpen --header header.img container.img hidden_vol"
                    .to_string(),
            });
        }

        if env.is_windows {
            configs.push(ContainerEvasionConfig {
                container_type: EncryptedContainerType::BitLocker,
                outer_volume_size_mb: 2048,
                hidden_volume_size_mb: 0,
                plausible_deniability: false,
                decoy_files: vec![],
                description: "BitLocker-encrypted VHD: create a VHD, enable BitLocker, \
                              mount as needed. Legitimate Windows feature, less suspicious than \
                              third-party encryption tools."
                    .to_string(),
                command: "powershell -c \"New-VHD -Path C:\\data.vhdx -SizeBytes 2GB -Dynamic; \
                          Mount-VHD -Path C:\\data.vhdx; \
                          Enable-BitLocker -MountPoint D: -EncryptionMethod XtsAes256 \
                          -RecoveryPasswordProtector\""
                    .to_string(),
            });
        }

        configs
    }

    /// Generate swap/pagefile manipulation operations.
    fn generate_swap_manipulations(&self, env: &ForensicEnvironment) -> Vec<SwapManipulation> {
        let mut manipulations = Vec::new();

        if env.is_windows {
            manipulations.push(SwapManipulation {
                swap_type: SwapType::WindowsPagefile,
                swap_path: "C:\\pagefile.sys".to_string(),
                operation: "Disable pagefile to prevent memory artifacts paging to disk"
                    .to_string(),
                command: "wmic computersystem set AutomaticManagedPagefile=False && \\\n\
                          wmic pagefileset delete"
                    .to_string(),
                requires_root: true,
            });

            manipulations.push(SwapManipulation {
                swap_type: SwapType::WindowsPagefile,
                swap_path: "C:\\pagefile.sys".to_string(),
                operation: "Configure pagefile clearing on shutdown via registry".to_string(),
                command: "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" \
                          /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f"
                    .to_string(),
                requires_root: true,
            });
        } else {
            let swap_path = env
                .swap_path
                .clone()
                .unwrap_or_else(|| "/swapfile".to_string());

            manipulations.push(SwapManipulation {
                swap_type: SwapType::LinuxSwapFile,
                swap_path: swap_path.clone(),
                operation: "Disable swap, overwrite with random data, re-enable".to_string(),
                command: format!(
                    "swapoff -a && \\\n\
                     dd if=/dev/urandom of={path} bs=4096 count=$(stat -c%s {path} 2>/dev/null | awk '{{print int($1/4096)}}') 2>/dev/null && \\\n\
                     mkswap {path} && \\\n\
                     swapon {path}",
                    path = swap_path
                ),
                requires_root: true,
            });

            manipulations.push(SwapManipulation {
                swap_type: SwapType::LinuxSwapFile,
                swap_path: swap_path,
                operation: "Set swappiness to 0 to minimize swap usage".to_string(),
                command: "echo 0 > /proc/sys/vm/swappiness".to_string(),
                requires_root: true,
            });
        }

        manipulations
    }

    /// Detection risk for steganographic formats.
    fn stego_detection_risk(format: StegoFormat) -> f64 {
        match format {
            StegoFormat::PngMetadata => 0.2,
            StegoFormat::JpegExif => 0.3,
            StegoFormat::PngLsb => 0.5,
            StegoFormat::JpegDct => 0.4,
            StegoFormat::PdfMetadata => 0.2,
            StegoFormat::Mp3Id3 => 0.15,
            StegoFormat::ZipComment => 0.25,
        }
    }

    /// Convert epoch seconds to `touch -t` format (YYYYMMDDhhmm.ss).
    fn epoch_to_touch_format(epoch: u64) -> String {
        let secs = epoch % 60;
        let mins = (epoch / 60) % 60;
        let hours = (epoch / 3600) % 24;
        let days = epoch / 86400;
        let year = 1970 + days / 365;
        let remaining_days = days % 365;
        let month = remaining_days / 30 + 1;
        let day = remaining_days % 30 + 1;
        format!(
            "{:04}{:02}{:02}{:02}{:02}.{:02}",
            year, month, day, hours, mins, secs
        )
    }

    /// Return common timestomping tool references.
    pub fn timestomping_tools() -> Vec<(&'static str, &'static str)> {
        vec![
            ("touch", "Unix: modify mtime/atime via -t or -r flags"),
            (
                "timestomp",
                "Metasploit Meterpreter: modify all NTFS timestamps including $MFT",
            ),
            (
                "SetMACE",
                "Windows: modify all four NTFS timestamps (Modified/Accessed/Created/Entry)",
            ),
            (
                "NtSetInformationFile",
                "Windows API: FileBasicInformation class modifies $STANDARD_INFORMATION timestamps",
            ),
            (
                "PowerShell",
                "Set-ItemProperty / (Get-Item).LastWriteTime for basic timestamp modification",
            ),
            (
                "debugfs",
                "Linux: direct ext2/3/4 inode timestamp manipulation via filesystem debugger",
            ),
        ]
    }
}
