use super::*;
use std::path::{Path, PathBuf};

#[test]
fn test_secure_buffer_zeroes_on_drop() {
    let ptr: *const u8;
    let len: usize;
    {
        let mut buf = SecureBuffer::<u8>::from_vec(vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
        assert_eq!(buf.len(), 6);
        assert_eq!(buf.as_slice(), &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
        ptr = buf.as_slice().as_ptr();
        len = buf.len();
        buf.as_mut_slice()[0] = 0xFF;
        assert_eq!(buf.as_slice()[0], 0xFF);
    }

    let zeroed = unsafe { std::slice::from_raw_parts(ptr, len) };
    for byte in zeroed {
        assert_eq!(*byte, 0u8);
    }
}

#[test]
fn test_secure_buffer_empty() {
    let buf = SecureBuffer::<u8>::new(0);
    assert!(buf.is_empty());
    assert_eq!(buf.len(), 0);
}

#[test]
fn test_secure_buffer_new_default_filled() {
    let buf = SecureBuffer::<u8>::new(128);
    assert_eq!(buf.len(), 128);
    assert!(buf.as_slice().iter().all(|&b| b == 0));
}

#[test]
fn test_in_memory_fs_write_read() {
    let mut fs = InMemoryFs::new();
    let path_a = PathBuf::from("/virtual/scan_results.json");
    let path_b = PathBuf::from("/virtual/payloads.bin");

    fs.write_file(&path_a, b"{ \"findings\": [] }".to_vec());
    fs.write_file(&path_b, vec![0x41, 0x42, 0x43]);

    assert_eq!(
        fs.read_file(&path_a),
        Some(b"{ \"findings\": [] }".as_slice())
    );
    assert_eq!(fs.read_file(&path_b), Some(&[0x41, 0x42, 0x43][..]));
    assert_eq!(fs.file_count(), 2);
    assert!(fs.contains(&path_a));
}

#[test]
fn test_in_memory_fs_overwrite() {
    let mut fs = InMemoryFs::new();
    let path = PathBuf::from("/data/report.txt");
    fs.write_file(&path, b"version 1".to_vec());
    fs.write_file(&path, b"version 2".to_vec());
    assert_eq!(fs.read_file(&path), Some(b"version 2".as_slice()));
    assert_eq!(fs.file_count(), 1);
}

#[test]
fn test_in_memory_fs_remove() {
    let mut fs = InMemoryFs::new();
    let path = PathBuf::from("/tmp/ephemeral");
    fs.write_file(&path, b"data".to_vec());
    assert!(fs.contains(&path));
    assert!(fs.remove_file(&path));
    assert!(!fs.contains(&path));
    assert!(!fs.remove_file(&path));
}

#[test]
fn test_in_memory_fs_total_size() {
    let mut fs = InMemoryFs::new();
    fs.write_file(Path::new("/a"), vec![0u8; 100]);
    fs.write_file(Path::new("/b"), vec![0u8; 200]);
    fs.write_file(Path::new("/c"), vec![0u8; 300]);
    assert_eq!(fs.total_size(), 600);
}

#[test]
fn test_in_memory_fs_list_files_sorted() {
    let mut fs = InMemoryFs::new();
    fs.write_file(Path::new("/z/last"), vec![]);
    fs.write_file(Path::new("/a/first"), vec![]);
    fs.write_file(Path::new("/m/middle"), vec![]);
    let listed = fs.list_files();
    assert_eq!(listed.len(), 3);
    assert!(listed[0] < listed[1]);
    assert!(listed[1] < listed[2]);
}

#[test]
fn test_in_memory_fs_read_nonexistent() {
    let fs = InMemoryFs::new();
    assert!(fs.read_file(Path::new("/does/not/exist")).is_none());
}

#[test]
fn test_memory_limit_enforcement() {
    let config = ZeroDiskConfig {
        enabled: true,
        max_memory_mb: 1,
        swap_disable: false,
    };
    let mut zdm = ZeroDiskMode::new(config);
    zdm.apply();

    let one_mb = 1024 * 1024;
    let half_mb_data = vec![0xABu8; one_mb / 2];
    assert!(zdm.write(Path::new("/first_half"), half_mb_data.clone()));
    assert_eq!(zdm.total_bytes_used(), one_mb / 2);
    assert!(zdm.is_within_limit());

    assert!(zdm.write(Path::new("/second_half"), half_mb_data));
    assert_eq!(zdm.total_bytes_used(), one_mb);
    assert!(zdm.is_within_limit());

    let overflow = vec![0xFFu8; 1];
    assert!(!zdm.write(Path::new("/overflow"), overflow));
    assert_eq!(zdm.total_bytes_used(), one_mb);
}

#[test]
fn test_memory_limit_overwrite_reclaims() {
    let config = ZeroDiskConfig {
        enabled: true,
        max_memory_mb: 1,
        swap_disable: false,
    };
    let mut zdm = ZeroDiskMode::new(config);
    zdm.apply();

    let path = Path::new("/resizable");
    let big = vec![0u8; 512 * 1024];
    assert!(zdm.write(path, big));
    assert_eq!(zdm.total_bytes_used(), 512 * 1024);

    let small = vec![0u8; 100];
    assert!(zdm.write(path, small));
    assert_eq!(zdm.total_bytes_used(), 100);
}

#[test]
fn test_zero_disk_mode_apply() {
    let mut zdm = ZeroDiskMode::new(ZeroDiskConfig::default());
    assert!(!zdm.is_applied());
    assert!(zdm.apply());
    assert!(zdm.is_applied());

    assert!(zdm.write(Path::new("/test"), b"hello".to_vec()));
    assert_eq!(zdm.read(Path::new("/test")), Some(b"hello".as_slice()));
}

#[test]
fn test_zero_disk_mode_disabled() {
    let config = ZeroDiskConfig {
        enabled: false,
        max_memory_mb: 256,
        swap_disable: false,
    };
    let mut zdm = ZeroDiskMode::new(config);
    assert!(!zdm.apply());
    assert!(!zdm.is_applied());
    assert!(!zdm.write(Path::new("/blocked"), b"data".to_vec()));
}

#[test]
fn test_no_disk_writes() {
    let tempdir = tempfile::tempdir().unwrap();
    let real_path = tempdir.path().join("should_not_exist.bin");

    let mut zdm = ZeroDiskMode::with_defaults();
    zdm.apply();

    zdm.write(&real_path, b"sensitive payload data".to_vec());

    assert!(!real_path.exists());

    assert_eq!(
        zdm.read(&real_path),
        Some(b"sensitive payload data".as_slice())
    );
}

#[test]
fn test_zero_disk_config_serialization() {
    let config = ZeroDiskConfig {
        enabled: true,
        max_memory_mb: 512,
        swap_disable: true,
    };
    let json = serde_json::to_string(&config).unwrap();
    let restored: ZeroDiskConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.enabled, config.enabled);
    assert_eq!(restored.max_memory_mb, config.max_memory_mb);
    assert_eq!(restored.swap_disable, config.swap_disable);
}

#[test]
fn test_zero_disk_mode_remove() {
    let mut zdm = ZeroDiskMode::with_defaults();
    zdm.apply();

    let path = Path::new("/removable");
    zdm.write(path, b"temp".to_vec());
    assert_eq!(zdm.total_bytes_used(), 4);
    assert!(zdm.remove(path));
    assert_eq!(zdm.total_bytes_used(), 0);
    assert!(zdm.read(path).is_none());
}

#[test]
fn test_zero_disk_config_builder() {
    let config = ZeroDiskConfig::default()
        .with_max_memory_mb(128)
        .with_swap_disable(false);
    assert_eq!(config.max_memory_mb, 128);
    assert!(!config.swap_disable);
}
