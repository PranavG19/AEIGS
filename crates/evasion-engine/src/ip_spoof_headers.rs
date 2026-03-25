use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rand::Rng;

/// All known IP-forwarding headers that proxies, CDNs, and load balancers honour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpoofHeader {
    XForwardedFor,
    XRealIp,
    XOriginatingIp,
    XRemoteIp,
    XRemoteAddr,
    TrueClientIp,
    CfConnectingIp,
    FastlyClientIp,
    XClusterClientIp,
    XClientIp,
    Forwarded,
}

impl SpoofHeader {
    pub fn header_name(&self) -> &'static str {
        match self {
            Self::XForwardedFor => "X-Forwarded-For",
            Self::XRealIp => "X-Real-IP",
            Self::XOriginatingIp => "X-Originating-IP",
            Self::XRemoteIp => "X-Remote-IP",
            Self::XRemoteAddr => "X-Remote-Addr",
            Self::TrueClientIp => "True-Client-IP",
            Self::CfConnectingIp => "CF-Connecting-IP",
            Self::FastlyClientIp => "Fastly-Client-IP",
            Self::XClusterClientIp => "X-Cluster-Client-IP",
            Self::XClientIp => "X-Client-IP",
            Self::Forwarded => "Forwarded",
        }
    }

    pub fn all() -> &'static [SpoofHeader] {
        &[
            Self::XForwardedFor,
            Self::XRealIp,
            Self::XOriginatingIp,
            Self::XRemoteIp,
            Self::XRemoteAddr,
            Self::TrueClientIp,
            Self::CfConnectingIp,
            Self::FastlyClientIp,
            Self::XClusterClientIp,
            Self::XClientIp,
            Self::Forwarded,
        ]
    }
}

/// Strategy for generating the spoofed IP value.
#[derive(Debug, Clone)]
pub enum SpoofStrategy {
    /// A single specific IP address.
    SingleIp(IpAddr),
    /// A chain of IPs simulating multi-proxy hops.
    Chain(Vec<IpAddr>),
    /// Random IP from the given CIDR-like range.
    RandomFromRange(IpRange),
    /// Use a well-known internal/private IP.
    InternalIp(InternalIpClass),
}

/// Classification of internal/private IP ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalIpClass {
    /// 127.0.0.0/8 — loopback
    Loopback,
    /// 10.0.0.0/8 — Class A private
    ClassA,
    /// 172.16.0.0/12 — Class B private
    ClassB,
    /// 192.168.0.0/16 — Class C private
    ClassC,
    /// 169.254.0.0/16 — link-local
    LinkLocal,
    /// ::1 — IPv6 loopback
    Ipv6Loopback,
    /// fe80::/10 — IPv6 link-local
    Ipv6LinkLocal,
    /// fc00::/7 — IPv6 unique local
    Ipv6UniqueLocal,
}

impl InternalIpClass {
    pub fn all() -> &'static [InternalIpClass] {
        &[
            Self::Loopback,
            Self::ClassA,
            Self::ClassB,
            Self::ClassC,
            Self::LinkLocal,
            Self::Ipv6Loopback,
            Self::Ipv6LinkLocal,
            Self::Ipv6UniqueLocal,
        ]
    }

    /// Generate a representative IP from this internal class.
    pub fn representative_ip(&self) -> IpAddr {
        match self {
            Self::Loopback => IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            Self::ClassA => IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            Self::ClassB => IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            Self::ClassC => IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            Self::LinkLocal => IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
            Self::Ipv6Loopback => IpAddr::V6(Ipv6Addr::LOCALHOST),
            Self::Ipv6LinkLocal => IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            Self::Ipv6UniqueLocal => IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
        }
    }

    /// Generate a random IP from this internal class.
    pub fn random_ip(&self) -> IpAddr {
        let mut rng = rand::rng();
        match self {
            Self::Loopback => IpAddr::V4(Ipv4Addr::new(
                127,
                rng.random_range(0..=255),
                rng.random_range(0..=255),
                rng.random_range(1..=254),
            )),
            Self::ClassA => IpAddr::V4(Ipv4Addr::new(
                10,
                rng.random_range(0..=255),
                rng.random_range(0..=255),
                rng.random_range(1..=254),
            )),
            Self::ClassB => IpAddr::V4(Ipv4Addr::new(
                172,
                rng.random_range(16..=31),
                rng.random_range(0..=255),
                rng.random_range(1..=254),
            )),
            Self::ClassC => IpAddr::V4(Ipv4Addr::new(
                192,
                168,
                rng.random_range(0..=255),
                rng.random_range(1..=254),
            )),
            Self::LinkLocal => IpAddr::V4(Ipv4Addr::new(
                169,
                254,
                rng.random_range(1..=254),
                rng.random_range(1..=254),
            )),
            Self::Ipv6Loopback => IpAddr::V6(Ipv6Addr::LOCALHOST),
            Self::Ipv6LinkLocal => IpAddr::V6(Ipv6Addr::new(
                0xfe80,
                0,
                0,
                0,
                rng.random(),
                rng.random(),
                rng.random(),
                rng.random_range(1..=0xfffe),
            )),
            Self::Ipv6UniqueLocal => IpAddr::V6(Ipv6Addr::new(
                0xfd00,
                rng.random(),
                rng.random(),
                rng.random(),
                rng.random(),
                rng.random(),
                rng.random(),
                rng.random_range(1..=0xfffe),
            )),
        }
    }
}

/// Simple IP range for random generation.
#[derive(Debug, Clone)]
pub struct IpRange {
    pub base: Ipv4Addr,
    pub prefix_len: u8,
}

impl IpRange {
    pub fn new(base: Ipv4Addr, prefix_len: u8) -> Self {
        assert!(prefix_len <= 32, "prefix_len must be <= 32");
        Self { base, prefix_len }
    }

    pub fn random_ip(&self) -> Ipv4Addr {
        let mut rng = rand::rng();
        let base_u32 = u32::from(self.base);
        let host_bits = 32 - self.prefix_len;
        if host_bits == 0 {
            return self.base;
        }
        let host_mask = (1u32 << host_bits) - 1;
        let network = base_u32 & !host_mask;
        let random_host: u32 = rng.random_range(1..host_mask);
        Ipv4Addr::from(network | random_host)
    }
}

/// A generated spoof header: name + value, ready to inject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpoofedHeader {
    pub name: String,
    pub value: String,
}

/// Primary IP spoofing header generator.
#[derive(Debug)]
pub struct IpSpoofHeaderGenerator;

impl Default for IpSpoofHeaderGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl IpSpoofHeaderGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generate a single spoofed header for the given header type and strategy.
    pub fn generate(&self, header: SpoofHeader, strategy: &SpoofStrategy) -> SpoofedHeader {
        let value = match header {
            SpoofHeader::Forwarded => self.format_forwarded(strategy),
            _ => self.format_standard(strategy),
        };
        SpoofedHeader {
            name: header.header_name().to_string(),
            value,
        }
    }

    /// Generate spoofed headers for ALL known header types with the given strategy.
    pub fn generate_all(&self, strategy: &SpoofStrategy) -> Vec<SpoofedHeader> {
        SpoofHeader::all()
            .iter()
            .map(|h| self.generate(*h, strategy))
            .collect()
    }

    /// Generate headers cycling through all internal IP classes for a single header type.
    pub fn generate_internal_variants(&self, header: SpoofHeader) -> Vec<SpoofedHeader> {
        InternalIpClass::all()
            .iter()
            .map(|class| {
                let strategy = SpoofStrategy::InternalIp(*class);
                self.generate(header, &strategy)
            })
            .collect()
    }

    /// Generate a full matrix: every header × every internal IP class.
    pub fn generate_full_matrix(&self) -> Vec<SpoofedHeader> {
        let mut results = Vec::new();
        for header in SpoofHeader::all() {
            for class in InternalIpClass::all() {
                let strategy = SpoofStrategy::InternalIp(*class);
                results.push(self.generate(*header, &strategy));
            }
        }
        results
    }

    /// Generate a chain of IPs simulating passage through multiple proxies.
    pub fn generate_chain(&self, header: SpoofHeader, hops: usize) -> SpoofedHeader {
        let mut rng = rand::rng();
        let chain: Vec<IpAddr> = (0..hops)
            .map(|_| {
                IpAddr::V4(Ipv4Addr::new(
                    rng.random_range(1..=223),
                    rng.random_range(0..=255),
                    rng.random_range(0..=255),
                    rng.random_range(1..=254),
                ))
            })
            .collect();
        let strategy = SpoofStrategy::Chain(chain);
        self.generate(header, &strategy)
    }

    /// Generate IPv6-specific spoofed headers.
    pub fn generate_ipv6(&self, header: SpoofHeader) -> SpoofedHeader {
        let mut rng = rand::rng();
        let addr = IpAddr::V6(Ipv6Addr::new(
            0x2001,
            0x0db8,
            rng.random(),
            rng.random(),
            rng.random(),
            rng.random(),
            rng.random(),
            rng.random(),
        ));
        let strategy = SpoofStrategy::SingleIp(addr);
        self.generate(header, &strategy)
    }

    fn format_standard(&self, strategy: &SpoofStrategy) -> String {
        match strategy {
            SpoofStrategy::SingleIp(ip) => ip.to_string(),
            SpoofStrategy::Chain(ips) => ips
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            SpoofStrategy::RandomFromRange(range) => IpAddr::V4(range.random_ip()).to_string(),
            SpoofStrategy::InternalIp(class) => class.representative_ip().to_string(),
        }
    }

    fn format_forwarded(&self, strategy: &SpoofStrategy) -> String {
        match strategy {
            SpoofStrategy::SingleIp(ip) => format_forwarded_entry(*ip),
            SpoofStrategy::Chain(ips) => ips
                .iter()
                .map(|ip| format_forwarded_entry(*ip))
                .collect::<Vec<_>>()
                .join(", "),
            SpoofStrategy::RandomFromRange(range) => {
                format_forwarded_entry(IpAddr::V4(range.random_ip()))
            }
            SpoofStrategy::InternalIp(class) => format_forwarded_entry(class.representative_ip()),
        }
    }
}

fn format_forwarded_entry(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => format!("for={v4}"),
        IpAddr::V6(v6) => format!("for=\"[{v6}]\""),
    }
}
