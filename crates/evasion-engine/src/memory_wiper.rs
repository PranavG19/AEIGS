use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Classification of sensitive data types that need secure wiping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SensitiveDataType {
    Credential,
    CryptoKey,
    Plaintext,
    SessionToken,
    PrivateKey,
    ApiSecret,
    DatabasePassword,
}

impl std::fmt::Display for SensitiveDataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Credential => write!(f, "credential"),
            Self::CryptoKey => write!(f, "crypto-key"),
            Self::Plaintext => write!(f, "plaintext"),
            Self::SessionToken => write!(f, "session-token"),
            Self::PrivateKey => write!(f, "private-key"),
            Self::ApiSecret => write!(f, "api-secret"),
            Self::DatabasePassword => write!(f, "database-password"),
        }
    }
}

/// DoD 5220.22-M compliant overwrite pass patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WipePattern {
    ZeroFill,
    OneFill,
    RandomFill,
    DoD522022M,
    GutmannThreePass,
    VolatileZero,
}

impl std::fmt::Display for WipePattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroFill => write!(f, "zero-fill"),
            Self::OneFill => write!(f, "one-fill"),
            Self::RandomFill => write!(f, "random-fill"),
            Self::DoD522022M => write!(f, "DoD-5220.22-M"),
            Self::GutmannThreePass => write!(f, "gutmann-3pass"),
            Self::VolatileZero => write!(f, "volatile-zero"),
        }
    }
}

/// Result of a memory wipe operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WipeResult {
    Success,
    PartialSuccess,
    Failed,
    Skipped,
}

impl std::fmt::Display for WipeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::PartialSuccess => write!(f, "partial-success"),
            Self::Failed => write!(f, "failed"),
            Self::Skipped => write!(f, "skipped"),
        }
    }
}

/// Shell history sources that may contain sensitive commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ShellHistorySource {
    BashHistory,
    ZshHistory,
    FishHistory,
    PowerShellHistory,
    CmdHistory,
    PythonHistory,
    SqliteHistory,
}

impl std::fmt::Display for ShellHistorySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BashHistory => write!(f, "bash-history"),
            Self::ZshHistory => write!(f, "zsh-history"),
            Self::FishHistory => write!(f, "fish-history"),
            Self::PowerShellHistory => write!(f, "powershell-history"),
            Self::CmdHistory => write!(f, "cmd-history"),
            Self::PythonHistory => write!(f, "python-history"),
            Self::SqliteHistory => write!(f, "sqlite-history"),
        }
    }
}

/// Represents a buffer region targeted for secure wiping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WipeTarget {
    pub label: String,
    pub data_type: SensitiveDataType,
    pub size_bytes: usize,
    pub address_hint: u64,
    pub locked: bool,
}

/// Record of a completed wipe operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WipeRecord {
    pub target: WipeTarget,
    pub pattern_used: WipePattern,
    pub passes: u32,
    pub result: WipeResult,
    pub verification_passed: bool,
}

/// Sensitive environment variable detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveEnvVar {
    pub name: String,
    pub data_type: SensitiveDataType,
    pub value_length: usize,
    pub cleared: bool,
}

/// Shell history wipe result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryWipeResult {
    pub source: ShellHistorySource,
    pub path: String,
    pub entries_found: usize,
    pub entries_wiped: usize,
    pub result: WipeResult,
}

/// Temp file wipe result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempFileWipeResult {
    pub path: String,
    pub size_bytes: u64,
    pub passes: u32,
    pub pattern_used: WipePattern,
    pub result: WipeResult,
}

/// Aggregated report of all memory/forensic wiping operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryWipeReport {
    pub buffer_wipes: Vec<WipeRecord>,
    pub env_var_wipes: Vec<SensitiveEnvVar>,
    pub history_wipes: Vec<HistoryWipeResult>,
    pub temp_file_wipes: Vec<TempFileWipeResult>,
    pub total_bytes_wiped: u64,
    pub total_passes: u32,
    pub all_verified: bool,
}

/// Simulated system memory state for wipe analysis.
#[derive(Debug, Clone, Default)]
pub struct MemoryEnvironment {
    pub buffers: Vec<BufferDescriptor>,
    pub environment_variables: HashMap<String, String>,
    pub shell_history_files: Vec<(ShellHistorySource, String, Vec<String>)>,
    pub temp_files: Vec<(String, u64)>,
    pub mlock_available: bool,
    pub volatile_write_available: bool,
    pub swap_enabled: bool,
    pub swap_path: Option<String>,
}

/// Describes a memory buffer that may contain sensitive data.
#[derive(Debug, Clone)]
pub struct BufferDescriptor {
    pub label: String,
    pub data_type: SensitiveDataType,
    pub size_bytes: usize,
    pub address: u64,
    pub contents_pattern: BufferContentsPattern,
}

/// Pattern describing what a buffer contains for detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferContentsPattern {
    HighEntropy,
    AsciiPrintable,
    MixedBinary,
    AllZeros,
    Structured,
}

/// Configuration for the memory wiper.
#[derive(Debug, Clone)]
pub struct MemoryWiperConfig {
    pub default_pattern: WipePattern,
    pub dod_passes: u32,
    pub verify_after_wipe: bool,
    pub wipe_env_vars: bool,
    pub wipe_shell_history: bool,
    pub wipe_temp_files: bool,
    pub use_mlock: bool,
    pub disable_swap: bool,
    pub sensitive_env_patterns: Vec<String>,
}

impl Default for MemoryWiperConfig {
    fn default() -> Self {
        Self {
            default_pattern: WipePattern::DoD522022M,
            dod_passes: 3,
            verify_after_wipe: true,
            wipe_env_vars: true,
            wipe_shell_history: true,
            wipe_temp_files: true,
            use_mlock: true,
            disable_swap: true,
            sensitive_env_patterns: vec![
                "PASSWORD".to_string(),
                "SECRET".to_string(),
                "TOKEN".to_string(),
                "KEY".to_string(),
                "API_KEY".to_string(),
                "PRIVATE".to_string(),
                "CREDENTIAL".to_string(),
                "AUTH".to_string(),
                "AWS_SECRET".to_string(),
                "AWS_ACCESS_KEY".to_string(),
                "DB_PASSWORD".to_string(),
                "MYSQL_PASSWORD".to_string(),
                "POSTGRES_PASSWORD".to_string(),
                "REDIS_PASSWORD".to_string(),
                "ENCRYPTION_KEY".to_string(),
                "JWT_SECRET".to_string(),
                "SESSION_SECRET".to_string(),
                "COOKIE_SECRET".to_string(),
                "HMAC".to_string(),
                "PASSPHRASE".to_string(),
            ],
        }
    }
}

/// DoD 5220.22-M pass sequence: pass1=0x00, pass2=0xFF, pass3=random, verify.
const DOD_PASS_VALUES: &[(u8, &str)] = &[
    (0x00, "zero-fill"),
    (0xFF, "one-fill"),
    (0x00, "random-fill-placeholder"),
];

/// Known shell history file paths per shell type.
const HISTORY_PATHS: &[(ShellHistorySource, &[&str])] = &[
    (
        ShellHistorySource::BashHistory,
        &[
            "~/.bash_history",
            "/root/.bash_history",
            "/home/*/.bash_history",
        ],
    ),
    (
        ShellHistorySource::ZshHistory,
        &[
            "~/.zsh_history",
            "/root/.zsh_history",
            "/home/*/.zsh_history",
        ],
    ),
    (
        ShellHistorySource::FishHistory,
        &[
            "~/.local/share/fish/fish_history",
            "/root/.local/share/fish/fish_history",
        ],
    ),
    (
        ShellHistorySource::PowerShellHistory,
        &[
            "~/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
            "~/.local/share/powershell/PSReadLine/ConsoleHost_history.txt",
        ],
    ),
    (
        ShellHistorySource::PythonHistory,
        &["~/.python_history", "/root/.python_history"],
    ),
    (
        ShellHistorySource::SqliteHistory,
        &["~/.sqlite_history", "/root/.sqlite_history"],
    ),
];

/// Common temp directory paths to scan for sensitive temp files.
const TEMP_DIRECTORIES: &[&str] = &[
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "C:\\Windows\\Temp",
    "C:\\Users\\*\\AppData\\Local\\Temp",
];

/// Securely wipes forensic evidence from memory, environment, and disk.
pub struct MemoryWiper {
    config: MemoryWiperConfig,
}

impl MemoryWiper {
    pub fn new(config: MemoryWiperConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(MemoryWiperConfig::default())
    }

    /// Execute full memory wipe operation against the provided environment.
    pub fn execute(&self, env: &MemoryEnvironment) -> MemoryWipeReport {
        let mut report = MemoryWipeReport {
            buffer_wipes: Vec::new(),
            env_var_wipes: Vec::new(),
            history_wipes: Vec::new(),
            temp_file_wipes: Vec::new(),
            total_bytes_wiped: 0,
            total_passes: 0,
            all_verified: true,
        };

        for buffer in &env.buffers {
            let record =
                self.wipe_buffer(buffer, env.mlock_available, env.volatile_write_available);
            report.total_bytes_wiped += record.target.size_bytes as u64 * record.passes as u64;
            report.total_passes += record.passes;
            if !record.verification_passed {
                report.all_verified = false;
            }
            report.buffer_wipes.push(record);
        }

        if self.config.wipe_env_vars {
            let env_results = self.scan_and_clear_env_vars(&env.environment_variables);
            report.env_var_wipes = env_results;
        }

        if self.config.wipe_shell_history {
            let history_results = self.wipe_shell_histories(&env.shell_history_files);
            for hr in &history_results {
                report.total_bytes_wiped += hr.entries_wiped as u64 * 64;
            }
            report.history_wipes = history_results;
        }

        if self.config.wipe_temp_files {
            let temp_results = self.wipe_temp_files(&env.temp_files);
            for tr in &temp_results {
                if tr.result == WipeResult::Success {
                    report.total_bytes_wiped += tr.size_bytes * tr.passes as u64;
                    report.total_passes += tr.passes;
                }
            }
            report.temp_file_wipes = temp_results;
        }

        report
    }

    /// Wipe a single sensitive buffer with the configured pattern.
    fn wipe_buffer(
        &self,
        buffer: &BufferDescriptor,
        mlock_available: bool,
        volatile_available: bool,
    ) -> WipeRecord {
        let pattern = self.select_pattern_for_type(buffer.data_type);
        let passes = self.passes_for_pattern(pattern);

        let locked = self.config.use_mlock && mlock_available;

        let result = if buffer.size_bytes == 0 {
            WipeResult::Skipped
        } else if volatile_available || pattern != WipePattern::VolatileZero {
            WipeResult::Success
        } else {
            WipeResult::PartialSuccess
        };

        let verification_passed = result == WipeResult::Success && self.config.verify_after_wipe;

        WipeRecord {
            target: WipeTarget {
                label: buffer.label.clone(),
                data_type: buffer.data_type,
                size_bytes: buffer.size_bytes,
                address_hint: buffer.address,
                locked,
            },
            pattern_used: pattern,
            passes,
            result,
            verification_passed,
        }
    }

    /// Select the appropriate wipe pattern based on data sensitivity.
    fn select_pattern_for_type(&self, data_type: SensitiveDataType) -> WipePattern {
        match data_type {
            SensitiveDataType::CryptoKey | SensitiveDataType::PrivateKey => WipePattern::DoD522022M,
            SensitiveDataType::Credential | SensitiveDataType::DatabasePassword => {
                WipePattern::GutmannThreePass
            }
            SensitiveDataType::SessionToken | SensitiveDataType::ApiSecret => {
                WipePattern::VolatileZero
            }
            SensitiveDataType::Plaintext => self.config.default_pattern,
        }
    }

    /// Number of overwrite passes for a given pattern.
    fn passes_for_pattern(&self, pattern: WipePattern) -> u32 {
        match pattern {
            WipePattern::ZeroFill => 1,
            WipePattern::OneFill => 1,
            WipePattern::RandomFill => 1,
            WipePattern::DoD522022M => self.config.dod_passes,
            WipePattern::GutmannThreePass => 3,
            WipePattern::VolatileZero => 1,
        }
    }

    /// Scan environment variables for sensitive values and produce clearance records.
    fn scan_and_clear_env_vars(&self, env_vars: &HashMap<String, String>) -> Vec<SensitiveEnvVar> {
        let mut results = Vec::new();

        for (name, value) in env_vars {
            let name_upper = name.to_uppercase();
            let is_sensitive = self
                .config
                .sensitive_env_patterns
                .iter()
                .any(|pattern| name_upper.contains(&pattern.to_uppercase()));

            if is_sensitive {
                results.push(SensitiveEnvVar {
                    name: name.clone(),
                    data_type: Self::classify_env_var(name),
                    value_length: value.len(),
                    cleared: true,
                });
            }
        }

        results
    }

    /// Classify an environment variable name into a sensitive data type.
    fn classify_env_var(name: &str) -> SensitiveDataType {
        let upper = name.to_uppercase();
        if upper.contains("KEY") || upper.contains("ENCRYPTION") || upper.contains("HMAC") {
            SensitiveDataType::CryptoKey
        } else if upper.contains("PASSWORD") || upper.contains("PASSPHRASE") {
            SensitiveDataType::Credential
        } else if upper.contains("TOKEN") || upper.contains("SESSION") || upper.contains("COOKIE") {
            SensitiveDataType::SessionToken
        } else if upper.contains("PRIVATE") {
            SensitiveDataType::PrivateKey
        } else if upper.contains("SECRET") || upper.contains("AUTH") {
            SensitiveDataType::ApiSecret
        } else if upper.contains("DB_PASSWORD")
            || upper.contains("MYSQL")
            || upper.contains("POSTGRES")
            || upper.contains("REDIS")
        {
            SensitiveDataType::DatabasePassword
        } else {
            SensitiveDataType::Plaintext
        }
    }

    /// Wipe shell history files.
    fn wipe_shell_histories(
        &self,
        histories: &[(ShellHistorySource, String, Vec<String>)],
    ) -> Vec<HistoryWipeResult> {
        let mut results = Vec::new();

        for (source, path, entries) in histories {
            let entries_found = entries.len();
            let entries_wiped = entries_found;
            let result = if entries_found == 0 {
                WipeResult::Skipped
            } else {
                WipeResult::Success
            };

            results.push(HistoryWipeResult {
                source: *source,
                path: path.clone(),
                entries_found,
                entries_wiped,
                result,
            });
        }

        results
    }

    /// Wipe temp files with DoD 5220.22-M multi-pass overwrite.
    fn wipe_temp_files(&self, temp_files: &[(String, u64)]) -> Vec<TempFileWipeResult> {
        let mut results = Vec::new();

        for (path, size) in temp_files {
            let passes = self.passes_for_pattern(WipePattern::DoD522022M);
            let result = if *size == 0 {
                WipeResult::Skipped
            } else {
                WipeResult::Success
            };

            results.push(TempFileWipeResult {
                path: path.clone(),
                size_bytes: *size,
                passes,
                pattern_used: WipePattern::DoD522022M,
                result,
            });
        }

        results
    }

    /// Generate secure_zero implementation that prevents compiler optimization.
    pub fn secure_zero_pattern() -> String {
        let mut code = String::new();
        code.push_str("// Volatile write pattern to prevent compiler optimization of zeroing\n");
        code.push_str("// The compiler cannot remove volatile stores even if the buffer is\n");
        code.push_str("// never read again before deallocation.\n\n");
        code.push_str("fn secure_zero(buf: &mut [u8]) {\n");
        code.push_str("    for byte in buf.iter_mut() {\n");
        code.push_str("        unsafe {\n");
        code.push_str("            std::ptr::write_volatile(byte as *mut u8, 0x00);\n");
        code.push_str("        }\n");
        code.push_str("    }\n");
        code.push_str("    // Memory fence to ensure writes complete before return\n");
        code.push_str("    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);\n");
        code.push_str("}\n");
        code
    }

    /// Generate mlock pattern to prevent paging sensitive data to disk.
    pub fn mlock_pattern() -> String {
        let mut code = String::new();
        code.push_str("// Lock memory pages to prevent swap-out of sensitive data\n");
        code.push_str("// Requires CAP_IPC_LOCK or RLIMIT_MEMLOCK sufficient allocation\n\n");
        code.push_str("#[cfg(unix)]\n");
        code.push_str("fn lock_memory(ptr: *const u8, len: usize) -> Result<(), i32> {\n");
        code.push_str(
            "    let result = unsafe { libc::mlock(ptr as *const libc::c_void, len) };\n",
        );
        code.push_str("    if result == 0 { Ok(()) } else { Err(result) }\n");
        code.push_str("}\n\n");
        code.push_str("#[cfg(unix)]\n");
        code.push_str("fn unlock_memory(ptr: *const u8, len: usize) -> Result<(), i32> {\n");
        code.push_str(
            "    let result = unsafe { libc::munlock(ptr as *const libc::c_void, len) };\n",
        );
        code.push_str("    if result == 0 { Ok(()) } else { Err(result) }\n");
        code.push_str("}\n");
        code
    }

    /// Generate DoD 5220.22-M compliant multi-pass overwrite pattern.
    pub fn dod_522022m_pattern() -> String {
        let mut code = String::new();
        code.push_str("// DoD 5220.22-M Standard Wipe (3-pass minimum)\n");
        code.push_str("// Pass 1: Write 0x00 to all bytes\n");
        code.push_str("// Pass 2: Write 0xFF to all bytes\n");
        code.push_str("// Pass 3: Write cryptographically random bytes\n");
        code.push_str("// Verify: Read back and confirm random pattern persists\n\n");
        code.push_str("fn dod_wipe(buf: &mut [u8]) {\n");
        code.push_str("    // Pass 1: Zero fill\n");
        code.push_str("    for byte in buf.iter_mut() {\n");
        code.push_str("        unsafe { std::ptr::write_volatile(byte as *mut u8, 0x00); }\n");
        code.push_str("    }\n");
        code.push_str("    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);\n\n");
        code.push_str("    // Pass 2: One fill\n");
        code.push_str("    for byte in buf.iter_mut() {\n");
        code.push_str("        unsafe { std::ptr::write_volatile(byte as *mut u8, 0xFF); }\n");
        code.push_str("    }\n");
        code.push_str("    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);\n\n");
        code.push_str("    // Pass 3: Random fill\n");
        code.push_str("    use rand::RngCore;\n");
        code.push_str("    let mut rng = rand::thread_rng();\n");
        code.push_str("    rng.fill_bytes(buf);\n");
        code.push_str("    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);\n");
        code.push_str("}\n");
        code
    }

    /// Generate HISTFILE manipulation commands for bash/zsh history evasion.
    pub fn histfile_manipulation_commands() -> Vec<String> {
        vec![
            "unset HISTFILE".to_string(),
            "export HISTSIZE=0".to_string(),
            "export HISTFILESIZE=0".to_string(),
            "set +o history".to_string(),
            "kill -9 $$".to_string(),
            "ln -sf /dev/null ~/.bash_history".to_string(),
            "ln -sf /dev/null ~/.zsh_history".to_string(),
            "history -c && history -w".to_string(),
            "cat /dev/null > ~/.bash_history".to_string(),
            "rm -f ~/.python_history".to_string(),
            "unset HISTCONTROL".to_string(),
            "export HISTIGNORE='*'".to_string(),
        ]
    }

    /// Generate swap space disablement commands.
    pub fn swap_disable_commands() -> Vec<String> {
        vec![
            "swapoff -a".to_string(),
            "dd if=/dev/urandom of=/swapfile bs=4096 count=$(stat -c%s /swapfile 2>/dev/null | awk '{print int($1/4096)}') 2>/dev/null".to_string(),
            "swapon -a".to_string(),
            "echo 0 > /proc/sys/vm/swappiness".to_string(),
        ]
    }

    /// Return known history file path templates.
    pub fn known_history_paths() -> &'static [(ShellHistorySource, &'static [&'static str])] {
        HISTORY_PATHS
    }

    /// Return known temp directory paths.
    pub fn known_temp_directories() -> &'static [&'static str] {
        TEMP_DIRECTORIES
    }

    /// Return DoD pass value definitions.
    pub fn dod_pass_values() -> &'static [(u8, &'static str)] {
        DOD_PASS_VALUES
    }
}
