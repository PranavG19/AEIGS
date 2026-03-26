use super::tcpip_spoofer::*;

#[test]
fn test_windows_11_profile() {
    let fp = TcpIpSpoofer::windows_11_fingerprint();
    assert_eq!(fp.ttl, 128);
    assert_eq!(fp.window_size, 65535);
    assert!(fp.df_bit);
    assert_eq!(fp.mss, 1460);
    assert_eq!(fp.options.len(), 6);
    assert_eq!(fp.options[0], TcpOption::Mss(1460));
}

#[test]
fn test_linux_6x_profile() {
    let fp = TcpIpSpoofer::linux_6x_fingerprint();
    assert_eq!(fp.ttl, 64);
    assert_eq!(fp.window_size, 29200);
    assert!(fp.df_bit);
    assert_eq!(fp.mss, 1460);
    assert_eq!(fp.options.len(), 5);
    assert_eq!(fp.options[0], TcpOption::Mss(1460));
    assert_eq!(fp.options[1], TcpOption::SackPermitted);
    assert_eq!(fp.options[2], TcpOption::Timestamps);
}

#[test]
fn test_macos_14_profile() {
    let fp = TcpIpSpoofer::macos_14_fingerprint();
    assert_eq!(fp.ttl, 64);
    assert_eq!(fp.window_size, 65535);
    assert!(fp.df_bit);
    assert_eq!(fp.mss, 1460);
    assert_eq!(fp.options.len(), 7);
    assert_eq!(fp.options[0], TcpOption::Mss(1460));
    assert_eq!(fp.options[5], TcpOption::Timestamps);
    assert_eq!(fp.options[6], TcpOption::SackPermitted);
}

#[test]
fn test_socket_config_generation() {
    let fp = TcpIpSpoofer::windows_11_fingerprint();
    let config = TcpIpSpoofer::generate_socket_config(&fp);
    assert_eq!(config.so_ttl, 128);
    assert!(config.so_rcvbuf > 0);
    assert!(config.tcp_nodelay);

    let linux_fp = TcpIpSpoofer::linux_6x_fingerprint();
    let linux_config = TcpIpSpoofer::generate_socket_config(&linux_fp);
    assert_eq!(linux_config.so_ttl, 64);
    assert!(!linux_config.tcp_nodelay);
}

#[test]
fn test_raw_packet_structure() {
    let fp = TcpIpSpoofer::windows_11_fingerprint();
    let packet = TcpIpSpoofer::generate_raw_packet_bytes(&fp, 12345, 80);

    assert_eq!(packet[0] >> 4, 4, "IP version must be 4");
    assert_eq!(packet[0] & 0x0F, 5, "IHL must be 5 (20 bytes)");
    assert_eq!(packet[8], 128, "TTL must match Windows 11");
    assert_eq!(packet[9], 6, "Protocol must be TCP");

    let src_port = u16::from_be_bytes([packet[20], packet[21]]);
    let dst_port = u16::from_be_bytes([packet[22], packet[23]]);
    assert_eq!(src_port, 12345);
    assert_eq!(dst_port, 80);

    let flags = u16::from_be_bytes([packet[6], packet[7]]);
    assert_eq!(flags & 0x4000, 0x4000, "DF bit must be set");

    let tcp_flags_byte = u16::from_be_bytes([packet[32], packet[33]]);
    assert_eq!(tcp_flags_byte & 0x003F, 0x0002, "SYN flag must be set");
}

#[test]
fn test_p0f_validation() {
    let win = TcpIpSpoofer::windows_11_fingerprint();
    assert!(TcpIpSpoofer::validate_against_p0f(
        &win,
        OsProfile::Windows11
    ));
    assert!(!TcpIpSpoofer::validate_against_p0f(
        &win,
        OsProfile::Linux6x
    ));

    let linux = TcpIpSpoofer::linux_6x_fingerprint();
    assert!(TcpIpSpoofer::validate_against_p0f(
        &linux,
        OsProfile::Linux6x
    ));
    assert!(!TcpIpSpoofer::validate_against_p0f(
        &linux,
        OsProfile::Windows11
    ));

    let mac = TcpIpSpoofer::macos_14_fingerprint();
    assert!(TcpIpSpoofer::validate_against_p0f(&mac, OsProfile::MacOs14));
    assert!(!TcpIpSpoofer::validate_against_p0f(
        &mac,
        OsProfile::Linux6x
    ));
}

#[test]
fn test_ttl_values_correct() {
    assert_eq!(TcpIpSpoofer::windows_11_fingerprint().ttl, 128);
    assert_eq!(TcpIpSpoofer::linux_6x_fingerprint().ttl, 64);
    assert_eq!(TcpIpSpoofer::macos_14_fingerprint().ttl, 64);
}

#[test]
fn test_option_ordering_per_os() {
    let win = TcpIpSpoofer::windows_11_fingerprint();
    assert!(matches!(win.options[0], TcpOption::Mss(_)));
    assert!(matches!(win.options[1], TcpOption::Nop));
    assert!(matches!(win.options[2], TcpOption::WindowScale(_)));
    assert!(matches!(win.options[3], TcpOption::Nop));
    assert!(matches!(win.options[4], TcpOption::Nop));
    assert!(matches!(win.options[5], TcpOption::SackPermitted));

    let linux = TcpIpSpoofer::linux_6x_fingerprint();
    assert!(matches!(linux.options[0], TcpOption::Mss(_)));
    assert!(matches!(linux.options[1], TcpOption::SackPermitted));
    assert!(matches!(linux.options[2], TcpOption::Timestamps));
    assert!(matches!(linux.options[3], TcpOption::Nop));
    assert!(matches!(linux.options[4], TcpOption::WindowScale(_)));

    let mac = TcpIpSpoofer::macos_14_fingerprint();
    assert!(matches!(mac.options[0], TcpOption::Mss(_)));
    assert!(matches!(mac.options[1], TcpOption::Nop));
    assert!(matches!(mac.options[2], TcpOption::WindowScale(_)));
    assert!(matches!(mac.options[3], TcpOption::Nop));
    assert!(matches!(mac.options[4], TcpOption::Nop));
    assert!(matches!(mac.options[5], TcpOption::Timestamps));
    assert!(matches!(mac.options[6], TcpOption::SackPermitted));
}

#[test]
fn test_get_profile_dispatches() {
    let win = TcpIpSpoofer::get_profile(OsProfile::Windows11);
    assert_eq!(win.ttl, 128);

    let linux = TcpIpSpoofer::get_profile(OsProfile::Linux6x);
    assert_eq!(linux.ttl, 64);
    assert_eq!(linux.window_size, 29200);

    let mac = TcpIpSpoofer::get_profile(OsProfile::MacOs14);
    assert_eq!(mac.ttl, 64);
    assert_eq!(mac.window_size, 65535);
}
