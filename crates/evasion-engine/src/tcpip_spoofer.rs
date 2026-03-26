use serde::{Deserialize, Serialize};

/// Operating system profile for TCP/IP stack fingerprint generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OsProfile {
    Windows11,
    Linux6x,
    MacOs14,
}

impl std::fmt::Display for OsProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Windows11 => write!(f, "Windows 11"),
            Self::Linux6x => write!(f, "Linux 6.x"),
            Self::MacOs14 => write!(f, "macOS 14"),
        }
    }
}

/// TCP option found in the SYN packet's options field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpOption {
    Mss(u16),
    Nop,
    WindowScale(u8),
    SackPermitted,
    Timestamps,
}

impl TcpOption {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::Mss(val) => {
                vec![2, 4, (val >> 8) as u8, *val as u8]
            }
            Self::Nop => vec![1],
            Self::WindowScale(shift) => vec![3, 3, *shift],
            Self::SackPermitted => vec![4, 2],
            Self::Timestamps => {
                let mut buf = vec![8, 10];
                buf.extend_from_slice(&[0u8; 8]);
                buf
            }
        }
    }
}

/// TCP SYN fingerprint capturing OS-specific stack behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpFingerprint {
    pub ttl: u8,
    pub window_size: u16,
    pub options: Vec<TcpOption>,
    pub df_bit: bool,
    pub mss: u16,
}

/// Socket-level configuration derived from a TCP fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketConfig {
    pub so_ttl: u8,
    pub so_rcvbuf: u32,
    pub so_sndbuf: u32,
    pub tcp_nodelay: bool,
}

/// Generates OS-accurate TCP/IP stack fingerprints and raw SYN packets
/// to defeat passive OS fingerprinting tools such as p0f and nmap.
pub struct TcpIpSpoofer;

impl TcpIpSpoofer {
    pub fn new() -> Self {
        Self
    }

    pub fn get_profile(os: OsProfile) -> TcpFingerprint {
        match os {
            OsProfile::Windows11 => Self::windows_11_fingerprint(),
            OsProfile::Linux6x => Self::linux_6x_fingerprint(),
            OsProfile::MacOs14 => Self::macos_14_fingerprint(),
        }
    }

    /// Windows 11: TTL 128, window 65535, MSS 1460, options MSS+NOP+WS+NOP+NOP+SACK
    pub fn windows_11_fingerprint() -> TcpFingerprint {
        TcpFingerprint {
            ttl: 128,
            window_size: 65535,
            options: vec![
                TcpOption::Mss(1460),
                TcpOption::Nop,
                TcpOption::WindowScale(8),
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::SackPermitted,
            ],
            df_bit: true,
            mss: 1460,
        }
    }

    /// Linux 6.x: TTL 64, window 29200, MSS 1460, options MSS+SACK+TS+NOP+WS
    pub fn linux_6x_fingerprint() -> TcpFingerprint {
        TcpFingerprint {
            ttl: 64,
            window_size: 29200,
            options: vec![
                TcpOption::Mss(1460),
                TcpOption::SackPermitted,
                TcpOption::Timestamps,
                TcpOption::Nop,
                TcpOption::WindowScale(7),
            ],
            df_bit: true,
            mss: 1460,
        }
    }

    /// macOS 14: TTL 64, window 65535, MSS 1460, options MSS+NOP+WS+NOP+NOP+TS+SACK
    pub fn macos_14_fingerprint() -> TcpFingerprint {
        TcpFingerprint {
            ttl: 64,
            window_size: 65535,
            options: vec![
                TcpOption::Mss(1460),
                TcpOption::Nop,
                TcpOption::WindowScale(6),
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::Timestamps,
                TcpOption::SackPermitted,
            ],
            df_bit: true,
            mss: 1460,
        }
    }

    pub fn generate_socket_config(fp: &TcpFingerprint) -> SocketConfig {
        let window_scale = fp.options.iter().find_map(|o| match o {
            TcpOption::WindowScale(s) => Some(*s),
            _ => None,
        });
        let scaled_window = (fp.window_size as u32) << window_scale.unwrap_or(0) as u32;

        SocketConfig {
            so_ttl: fp.ttl,
            so_rcvbuf: scaled_window,
            so_sndbuf: scaled_window,
            tcp_nodelay: !fp
                .options
                .iter()
                .any(|o| matches!(o, TcpOption::Timestamps)),
        }
    }

    /// Generate a raw TCP SYN packet with correct IP and TCP headers
    /// reflecting the given fingerprint.
    pub fn generate_raw_packet_bytes(fp: &TcpFingerprint, src_port: u16, dst_port: u16) -> Vec<u8> {
        let options_bytes: Vec<u8> = fp.options.iter().flat_map(|o| o.encode()).collect();
        let options_len = options_bytes.len();
        let padding = (4 - (options_len % 4)) % 4;
        let tcp_header_len = 20 + options_len + padding;
        let data_offset = (tcp_header_len / 4) as u8;
        let total_len = 20 + tcp_header_len;

        let mut packet = Vec::with_capacity(total_len);

        let version_ihl: u8 = 0x45;
        packet.push(version_ihl);
        packet.push(0x00);
        packet.extend_from_slice(&(total_len as u16).to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]);
        let flags_frag: u16 = if fp.df_bit { 0x4000 } else { 0x0000 };
        packet.extend_from_slice(&flags_frag.to_be_bytes());
        packet.push(fp.ttl);
        packet.push(6);
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[127, 0, 0, 1]);
        packet.extend_from_slice(&[127, 0, 0, 1]);

        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        packet.extend_from_slice(&0x00000001u32.to_be_bytes());
        packet.extend_from_slice(&0x00000000u32.to_be_bytes());
        let data_offset_flags: u16 = (data_offset as u16) << 12 | 0x0002;
        packet.extend_from_slice(&data_offset_flags.to_be_bytes());
        packet.extend_from_slice(&fp.window_size.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00]);

        packet.extend_from_slice(&options_bytes);
        for _ in 0..padding {
            packet.push(0x00);
        }

        let ip_checksum = compute_ip_checksum(&packet[..20]);
        packet[10] = (ip_checksum >> 8) as u8;
        packet[11] = ip_checksum as u8;

        packet
    }

    /// Validate that a fingerprint matches the expected OS profile
    /// according to p0f-style heuristics.
    pub fn validate_against_p0f(fp: &TcpFingerprint, expected_os: OsProfile) -> bool {
        match expected_os {
            OsProfile::Windows11 => {
                fp.ttl == 128
                    && fp.window_size == 65535
                    && fp.df_bit
                    && fp.options.len() == 6
                    && matches!(fp.options[0], TcpOption::Mss(1460))
                    && matches!(fp.options[1], TcpOption::Nop)
                    && matches!(fp.options[2], TcpOption::WindowScale(8))
                    && matches!(fp.options[5], TcpOption::SackPermitted)
            }
            OsProfile::Linux6x => {
                fp.ttl == 64
                    && fp.window_size == 29200
                    && fp.df_bit
                    && fp.options.len() == 5
                    && matches!(fp.options[0], TcpOption::Mss(1460))
                    && matches!(fp.options[1], TcpOption::SackPermitted)
                    && matches!(fp.options[2], TcpOption::Timestamps)
                    && matches!(fp.options[4], TcpOption::WindowScale(7))
            }
            OsProfile::MacOs14 => {
                fp.ttl == 64
                    && fp.window_size == 65535
                    && fp.df_bit
                    && fp.options.len() == 7
                    && matches!(fp.options[0], TcpOption::Mss(1460))
                    && matches!(fp.options[1], TcpOption::Nop)
                    && matches!(fp.options[2], TcpOption::WindowScale(6))
                    && matches!(fp.options[5], TcpOption::Timestamps)
                    && matches!(fp.options[6], TcpOption::SackPermitted)
            }
        }
    }
}

impl Default for TcpIpSpoofer {
    fn default() -> Self {
        Self::new()
    }
}

fn compute_ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i < header.len() - 1 {
        if i == 10 {
            i += 2;
            continue;
        }
        let word = ((header[i] as u32) << 8) | (header[i + 1] as u32);
        sum += word;
        i += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
