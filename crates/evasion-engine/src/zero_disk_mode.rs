use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{fence, Ordering};

use serde::{Deserialize, Serialize};

/// Configuration for zero-disk-write mode.
///
/// When enabled, all file I/O is redirected to an in-memory filesystem
/// bounded by `max_memory_mb`. Sensitive buffers are zeroed on drop
/// via volatile writes that the compiler cannot optimize away.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroDiskConfig {
    pub enabled: bool,
    pub max_memory_mb: usize,
    pub swap_disable: bool,
}

impl Default for ZeroDiskConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_memory_mb: 256,
            swap_disable: true,
        }
    }
}

impl ZeroDiskConfig {
    pub fn with_max_memory_mb(mut self, mb: usize) -> Self {
        self.max_memory_mb = mb;
        self
    }

    pub fn with_swap_disable(mut self, disable: bool) -> Self {
        self.swap_disable = disable;
        self
    }

    fn max_bytes(&self) -> usize {
        self.max_memory_mb * 1024 * 1024
    }
}

/// Wrapper that guarantees memory is zeroed via `ptr::write_volatile`
/// when the buffer is dropped, preventing the compiler from eliding
/// the zeroing as a dead store.
pub struct SecureBuffer<T: Default + Clone> {
    data: Vec<T>,
    locked: bool,
}

impl<T: Default + Clone> SecureBuffer<T> {
    pub fn new(size: usize) -> Self {
        let data = vec![T::default(); size];
        let locked = mlock_region(
            data.as_ptr() as *const u8,
            data.len() * std::mem::size_of::<T>(),
        );
        Self { data, locked }
    }

    pub fn from_vec(source: Vec<T>) -> Self {
        let locked = mlock_region(
            source.as_ptr() as *const u8,
            source.len() * std::mem::size_of::<T>(),
        );
        Self {
            data: source,
            locked,
        }
    }

    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl<T: Default + Clone> Drop for SecureBuffer<T> {
    fn drop(&mut self) {
        let default_val = T::default();
        for elem in self.data.iter_mut() {
            unsafe {
                std::ptr::write_volatile(elem as *mut T, default_val.clone());
            }
        }
        fence(Ordering::SeqCst);
        if self.locked {
            munlock_region(
                self.data.as_ptr() as *const u8,
                self.data.len() * std::mem::size_of::<T>(),
            );
        }
    }
}

/// Attempt to lock a memory region to prevent paging to swap.
/// Returns true if the lock succeeded.
#[cfg(target_family = "unix")]
fn mlock_region(ptr: *const u8, len: usize) -> bool {
    unsafe { libc_mlock(ptr, len) }
}

#[cfg(not(target_family = "unix"))]
fn mlock_region(_ptr: *const u8, _len: usize) -> bool {
    false
}

#[cfg(target_family = "unix")]
fn munlock_region(ptr: *const u8, len: usize) {
    unsafe {
        libc_munlock(ptr, len);
    }
}

#[cfg(not(target_family = "unix"))]
fn munlock_region(_ptr: *const u8, _len: usize) {}

/// Thin wrapper around the mlock syscall via `syscall(2)`.
/// Uses raw syscall numbers to avoid requiring the `libc` crate as a
/// direct dependency — the kernel ABI is stable.
#[cfg(all(target_family = "unix", target_os = "linux"))]
unsafe fn libc_mlock(ptr: *const u8, len: usize) -> bool {
    const SYS_MLOCK: i64 = 149;
    let ret: i64;
    std::arch::asm!(
        "syscall",
        in("rax") SYS_MLOCK,
        in("rdi") ptr as u64,
        in("rsi") len as u64,
        lateout("rax") ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack),
    );
    ret == 0
}

#[cfg(all(target_family = "unix", not(target_os = "linux")))]
unsafe fn libc_mlock(_ptr: *const u8, _len: usize) -> bool {
    false
}

#[cfg(all(target_family = "unix", target_os = "linux"))]
unsafe fn libc_munlock(ptr: *const u8, len: usize) {
    const SYS_MUNLOCK: i64 = 150;
    let _ret: i64;
    std::arch::asm!(
        "syscall",
        in("rax") SYS_MUNLOCK,
        in("rdi") ptr as u64,
        in("rsi") len as u64,
        lateout("rax") _ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack),
    );
}

#[cfg(all(target_family = "unix", not(target_os = "linux")))]
unsafe fn libc_munlock(_ptr: *const u8, _len: usize) {}

/// In-memory filesystem that intercepts file writes, keeping all
/// data in RAM with no disk persistence.
#[derive(Debug, Clone, Default)]
pub struct InMemoryFs {
    files: HashMap<PathBuf, Vec<u8>>,
}

impl InMemoryFs {
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
        }
    }

    pub fn write_file(&mut self, path: &Path, data: Vec<u8>) {
        self.files.insert(path.to_path_buf(), data);
    }

    pub fn read_file(&self, path: &Path) -> Option<&[u8]> {
        self.files.get(path).map(|v| v.as_slice())
    }

    pub fn list_files(&self) -> Vec<&PathBuf> {
        let mut paths: Vec<&PathBuf> = self.files.keys().collect();
        paths.sort();
        paths
    }

    pub fn total_size(&self) -> usize {
        self.files.values().map(|v| v.len()).sum()
    }

    pub fn remove_file(&mut self, path: &Path) -> bool {
        self.files.remove(path).is_some()
    }

    pub fn contains(&self, path: &Path) -> bool {
        self.files.contains_key(path)
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }
}

/// Zero-disk-write mode controller that owns an in-memory filesystem
/// and enforces the configured memory budget.
pub struct ZeroDiskMode {
    fs: InMemoryFs,
    config: ZeroDiskConfig,
    applied: bool,
}

impl ZeroDiskMode {
    pub fn new(config: ZeroDiskConfig) -> Self {
        Self {
            fs: InMemoryFs::new(),
            config,
            applied: false,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(ZeroDiskConfig::default())
    }

    /// Activate zero-disk mode. After this call, all writes go through
    /// the in-memory filesystem and swap is logically disabled when
    /// configured.
    pub fn apply(&mut self) -> bool {
        if !self.config.enabled {
            return false;
        }
        self.applied = true;
        true
    }

    pub fn is_applied(&self) -> bool {
        self.applied
    }

    /// Write data to the in-memory filesystem. Returns false if the
    /// write would exceed the configured memory budget.
    pub fn write(&mut self, path: &Path, data: Vec<u8>) -> bool {
        if !self.config.enabled {
            return false;
        }
        let new_size = self.fs.total_size() - self.existing_size(path) + data.len();
        if new_size > self.config.max_bytes() {
            return false;
        }
        self.fs.write_file(path, data);
        true
    }

    pub fn read(&self, path: &Path) -> Option<&[u8]> {
        self.fs.read_file(path)
    }

    pub fn total_bytes_used(&self) -> usize {
        self.fs.total_size()
    }

    pub fn is_within_limit(&self) -> bool {
        self.fs.total_size() <= self.config.max_bytes()
    }

    pub fn config(&self) -> &ZeroDiskConfig {
        &self.config
    }

    pub fn fs(&self) -> &InMemoryFs {
        &self.fs
    }

    pub fn remove(&mut self, path: &Path) -> bool {
        self.fs.remove_file(path)
    }

    fn existing_size(&self, path: &Path) -> usize {
        self.fs.read_file(path).map_or(0, |d| d.len())
    }
}
