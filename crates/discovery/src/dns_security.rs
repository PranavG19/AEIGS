use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

/// DNS record types relevant to security auditing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Txt,
    Soa,
    Dnskey,
    Rrsig,
    Nsec,
    Nsec3,
    Ptr,
    Srv,
    Axfr,
    Ds,
    Spf,
}

impl fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::Aaaa => write!(f, "AAAA"),
            Self::Cname => write!(f, "CNAME"),
            Self::Mx => write!(f, "MX"),
            Self::Ns => write!(f, "NS"),
            Self::Txt => write!(f, "TXT"),
            Self::Soa => write!(f, "SOA"),
            Self::Dnskey => write!(f, "DNSKEY"),
            Self::Rrsig => write!(f, "RRSIG"),
            Self::Nsec => write!(f, "NSEC"),
            Self::Nsec3 => write!(f, "NSEC3"),
            Self::Ptr => write!(f, "PTR"),
            Self::Srv => write!(f, "SRV"),
            Self::Axfr => write!(f, "AXFR"),
            Self::Ds => write!(f, "DS"),
            Self::Spf => write!(f, "SPF"),
        }
    }
}

/// A single DNS record returned from queries.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: DnsRecordType,
    pub ttl: u32,
    pub value: String,
}

/// Severity grading for DNS security findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DnsSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for DnsSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Categories of DNS security checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsCheckType {
    ZoneTransfer,
    DnssecValidation,
    CachePoisoning,
    DnsRebinding,
    DanglingRecords,
    EmailAuthentication,
    NsecWalking,
    DnsAmplification,
    SubdomainDelegation,
}

impl fmt::Display for DnsCheckType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZoneTransfer => write!(f, "Zone Transfer (AXFR)"),
            Self::DnssecValidation => write!(f, "DNSSEC Validation"),
            Self::CachePoisoning => write!(f, "DNS Cache Poisoning"),
            Self::DnsRebinding => write!(f, "DNS Rebinding Defense"),
            Self::DanglingRecords => write!(f, "Dangling DNS Records"),
            Self::EmailAuthentication => write!(f, "Email Authentication (SPF/DKIM/DMARC)"),
            Self::NsecWalking => write!(f, "NSEC Zone Walking"),
            Self::DnsAmplification => write!(f, "DNS Amplification"),
            Self::SubdomainDelegation => write!(f, "Subdomain Delegation"),
        }
    }
}

/// Individual finding from a DNS security check.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsFinding {
    pub check_type: DnsCheckType,
    pub severity: DnsSeverity,
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub remediation: String,
}

/// Result of an AXFR zone transfer attempt.
#[derive(Debug, Clone, PartialEq)]
pub struct ZoneTransferResult {
    pub domain: String,
    pub nameserver: String,
    pub success: bool,
    pub records: Vec<DnsRecord>,
    pub error: Option<String>,
}

/// DNSSEC validation status for a domain.
#[derive(Debug, Clone, PartialEq)]
pub struct DnssecStatus {
    pub domain: String,
    pub has_dnskey: bool,
    pub has_rrsig: bool,
    pub has_nsec: bool,
    pub has_nsec3: bool,
    pub has_ds: bool,
    pub fully_signed: bool,
}

impl DnssecStatus {
    pub fn grade(&self) -> DnsSeverity {
        if self.fully_signed && self.has_dnskey && self.has_rrsig && self.has_ds {
            DnsSeverity::Info
        } else if self.has_dnskey && self.has_rrsig {
            DnsSeverity::Low
        } else if self.has_dnskey {
            DnsSeverity::Medium
        } else {
            DnsSeverity::High
        }
    }
}

/// Kaminsky-style cache poisoning payload.
#[derive(Debug, Clone, PartialEq)]
pub struct CachePoisoningPayload {
    pub target_domain: String,
    pub spoofed_answer: String,
    pub transaction_id: u16,
    pub source_port: u16,
    pub authority_injection: String,
    pub description: String,
}

/// DNS rebinding test result.
#[derive(Debug, Clone, PartialEq)]
pub struct RebindingTestResult {
    pub domain: String,
    pub initial_ip: String,
    pub rebind_ip: String,
    pub ttl_used: u32,
    pub vulnerable: bool,
    pub description: String,
}

/// Dangling DNS record detection result.
#[derive(Debug, Clone, PartialEq)]
pub struct DanglingRecord {
    pub record: DnsRecord,
    pub reason: DanglingReason,
    pub risk: DnsSeverity,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DanglingReason {
    NxdomainTarget,
    ExpiredService,
    UnclaimedCloud(String),
    OrphanedCname,
}

impl fmt::Display for DanglingReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NxdomainTarget => write!(f, "Target returns NXDOMAIN"),
            Self::ExpiredService => write!(f, "Service appears expired"),
            Self::UnclaimedCloud(provider) => write!(f, "Unclaimed {} resource", provider),
            Self::OrphanedCname => write!(f, "CNAME chain broken"),
        }
    }
}

/// SPF record analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct SpfAnalysis {
    pub raw_record: String,
    pub version: Option<String>,
    pub mechanisms: Vec<SpfMechanism>,
    pub all_qualifier: SpfQualifier,
    pub dns_lookup_count: usize,
    pub issues: Vec<String>,
    pub grade: DnsSeverity,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpfMechanism {
    pub qualifier: SpfQualifier,
    pub mechanism_type: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfQualifier {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
}

impl fmt::Display for SpfQualifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "+"),
            Self::Fail => write!(f, "-"),
            Self::SoftFail => write!(f, "~"),
            Self::Neutral => write!(f, "?"),
            Self::None => write!(f, "none"),
        }
    }
}

/// DKIM record analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct DkimAnalysis {
    pub selector: String,
    pub raw_record: Option<String>,
    pub version: Option<String>,
    pub key_type: Option<String>,
    pub key_size_bits: Option<u32>,
    pub public_key_present: bool,
    pub issues: Vec<String>,
    pub grade: DnsSeverity,
}

/// DMARC record analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct DmarcAnalysis {
    pub raw_record: Option<String>,
    pub version: Option<String>,
    pub policy: DmarcPolicy,
    pub subdomain_policy: Option<DmarcPolicy>,
    pub percentage: u8,
    pub rua: Vec<String>,
    pub ruf: Vec<String>,
    pub issues: Vec<String>,
    pub grade: DnsSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcPolicy {
    None,
    Quarantine,
    Reject,
    Missing,
}

impl fmt::Display for DmarcPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Quarantine => write!(f, "quarantine"),
            Self::Reject => write!(f, "reject"),
            Self::Missing => write!(f, "missing"),
        }
    }
}

/// Combined email authentication audit.
#[derive(Debug, Clone, PartialEq)]
pub struct EmailAuthAudit {
    pub domain: String,
    pub spf: Option<SpfAnalysis>,
    pub dkim: Vec<DkimAnalysis>,
    pub dmarc: Option<DmarcAnalysis>,
    pub overall_grade: DnsSeverity,
}

/// NSEC walking result — zone enumeration via NSEC record traversal.
#[derive(Debug, Clone, PartialEq)]
pub struct NsecWalkResult {
    pub domain: String,
    pub walkable: bool,
    pub discovered_names: Vec<String>,
    pub uses_nsec3: bool,
    pub nsec3_salt: Option<String>,
    pub nsec3_iterations: Option<u32>,
}

/// DNS amplification test result.
#[derive(Debug, Clone, PartialEq)]
pub struct AmplificationResult {
    pub resolver_ip: String,
    pub query_size: usize,
    pub response_size: usize,
    pub amplification_factor: f64,
    pub open_resolver: bool,
    pub recursion_available: bool,
}

/// Subdomain delegation audit result.
#[derive(Debug, Clone, PartialEq)]
pub struct DelegationResult {
    pub subdomain: String,
    pub delegated_ns: Vec<String>,
    pub ns_reachable: Vec<bool>,
    pub lame_delegation: bool,
    pub missing_glue: bool,
}

/// Complete DNS security audit report.
#[derive(Debug, Clone)]
pub struct DnsSecurityAudit {
    pub domain: String,
    pub zone_transfer: Vec<ZoneTransferResult>,
    pub dnssec: Option<DnssecStatus>,
    pub cache_poisoning_payloads: Vec<CachePoisoningPayload>,
    pub rebinding_tests: Vec<RebindingTestResult>,
    pub dangling_records: Vec<DanglingRecord>,
    pub email_auth: Option<EmailAuthAudit>,
    pub nsec_walk: Option<NsecWalkResult>,
    pub amplification: Vec<AmplificationResult>,
    pub delegation: Vec<DelegationResult>,
    pub findings: Vec<DnsFinding>,
}

#[derive(Debug)]
pub enum DnsSecurityError {
    InvalidDomain(String),
    QueryFailed(String),
    ParseError(String),
    Timeout(String),
}

impl fmt::Display for DnsSecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDomain(d) => write!(f, "Invalid domain: {}", d),
            Self::QueryFailed(e) => write!(f, "DNS query failed: {}", e),
            Self::ParseError(e) => write!(f, "Parse error: {}", e),
            Self::Timeout(e) => write!(f, "Timeout: {}", e),
        }
    }
}

impl std::error::Error for DnsSecurityError {}

/// Validates a domain string for basic structural correctness.
pub fn validate_domain(domain: &str) -> Result<String, DnsSecurityError> {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() {
        return Err(DnsSecurityError::InvalidDomain("empty domain".into()));
    }
    if domain.len() > 253 {
        return Err(DnsSecurityError::InvalidDomain(
            "domain exceeds 253 characters".into(),
        ));
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DnsSecurityError::InvalidDomain(format!(
                "invalid label: '{}'",
                label
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(DnsSecurityError::InvalidDomain(format!(
                "label starts or ends with hyphen: '{}'",
                label
            )));
        }
    }
    Ok(domain.to_lowercase())
}

/// Builds an AXFR (zone transfer) request wire format.
///
/// Returns the raw bytes for a DNS AXFR query that can be sent over TCP.
/// The transaction ID is caller-supplied for correlation.
pub fn build_axfr_request(domain: &str, transaction_id: u16) -> Result<Vec<u8>, DnsSecurityError> {
    let domain = validate_domain(domain)?;
    let mut packet = Vec::with_capacity(64);

    // Transaction ID
    packet.extend_from_slice(&transaction_id.to_be_bytes());
    // Flags: standard query, recursion desired
    packet.extend_from_slice(&[0x00, 0x00]);
    // Questions: 1
    packet.extend_from_slice(&[0x00, 0x01]);
    // Answer, Authority, Additional RRs: 0
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // QNAME: encode domain labels
    for label in domain.split('.') {
        let len = label.len() as u8;
        packet.push(len);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00); // root label

    // QTYPE: AXFR = 252
    packet.extend_from_slice(&[0x00, 0xFC]);
    // QCLASS: IN = 1
    packet.extend_from_slice(&[0x00, 0x01]);

    Ok(packet)
}

/// Parses a raw DNS AXFR response into individual records.
///
/// This handles the wire format: header, then repeated resource records.
/// Minimal parser — enough for security auditing, not a full resolver.
pub fn parse_axfr_response(data: &[u8], domain: &str) -> Result<Vec<DnsRecord>, DnsSecurityError> {
    if data.len() < 12 {
        return Err(DnsSecurityError::ParseError(
            "response too short for DNS header".into(),
        ));
    }

    let flags = u16::from_be_bytes([data[2], data[3]]);
    let rcode = flags & 0x000F;

    if rcode == 5 {
        return Err(DnsSecurityError::QueryFailed(
            "zone transfer refused (RCODE=5)".into(),
        ));
    }
    if rcode != 0 {
        return Err(DnsSecurityError::QueryFailed(format!(
            "DNS error RCODE={}",
            rcode
        )));
    }

    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let mut records = Vec::with_capacity(ancount);

    // Skip header (12 bytes) + question section
    let mut offset = 12;
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    for _ in 0..qdcount {
        offset = skip_dns_name(data, offset)?;
        offset += 4; // QTYPE + QCLASS
    }

    for _ in 0..ancount {
        if offset >= data.len() {
            break;
        }
        let (record, new_offset) = parse_resource_record(data, offset, domain)?;
        records.push(record);
        offset = new_offset;
    }

    Ok(records)
}

fn skip_dns_name(data: &[u8], mut offset: usize) -> Result<usize, DnsSecurityError> {
    if offset >= data.len() {
        return Err(DnsSecurityError::ParseError(
            "name offset out of bounds".into(),
        ));
    }
    loop {
        if offset >= data.len() {
            return Err(DnsSecurityError::ParseError("truncated name".into()));
        }
        let len = data[offset] as usize;
        if len == 0 {
            offset += 1;
            break;
        }
        if len >= 0xC0 {
            offset += 2; // pointer
            break;
        }
        offset += 1 + len;
    }
    Ok(offset)
}

fn read_dns_name(data: &[u8], mut offset: usize) -> Result<(String, usize), DnsSecurityError> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut return_offset = 0;
    let mut hops = 0;

    loop {
        if offset >= data.len() {
            return Err(DnsSecurityError::ParseError(
                "name read out of bounds".into(),
            ));
        }
        hops += 1;
        if hops > 128 {
            return Err(DnsSecurityError::ParseError("name compression loop".into()));
        }
        let len = data[offset] as usize;
        if len == 0 {
            if !jumped {
                return_offset = offset + 1;
            }
            break;
        }
        if len >= 0xC0 {
            if offset + 1 >= data.len() {
                return Err(DnsSecurityError::ParseError("truncated pointer".into()));
            }
            if !jumped {
                return_offset = offset + 2;
                jumped = true;
            }
            let pointer = ((len & 0x3F) << 8) | (data[offset + 1] as usize);
            offset = pointer;
            continue;
        }
        offset += 1;
        if offset + len > data.len() {
            return Err(DnsSecurityError::ParseError(
                "label extends past data".into(),
            ));
        }
        let label = String::from_utf8_lossy(&data[offset..offset + len]).to_string();
        labels.push(label);
        offset += len;
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };
    Ok((name, return_offset))
}

fn parse_resource_record(
    data: &[u8],
    offset: usize,
    _domain: &str,
) -> Result<(DnsRecord, usize), DnsSecurityError> {
    let (name, mut offset) = read_dns_name(data, offset)?;

    if offset + 10 > data.len() {
        return Err(DnsSecurityError::ParseError(
            "truncated resource record".into(),
        ));
    }

    let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    // class
    offset += 2;
    let ttl = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    offset += 4;
    let rdlength = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    if offset + rdlength > data.len() {
        return Err(DnsSecurityError::ParseError(
            "RDATA extends past packet".into(),
        ));
    }

    let record_type = rtype_to_enum(rtype);
    let value = parse_rdata(data, offset, rdlength, rtype)?;
    let new_offset = offset + rdlength;

    Ok((
        DnsRecord {
            name,
            record_type,
            ttl,
            value,
        },
        new_offset,
    ))
}

fn rtype_to_enum(rtype: u16) -> DnsRecordType {
    match rtype {
        1 => DnsRecordType::A,
        28 => DnsRecordType::Aaaa,
        5 => DnsRecordType::Cname,
        15 => DnsRecordType::Mx,
        2 => DnsRecordType::Ns,
        16 => DnsRecordType::Txt,
        6 => DnsRecordType::Soa,
        48 => DnsRecordType::Dnskey,
        46 => DnsRecordType::Rrsig,
        47 => DnsRecordType::Nsec,
        50 => DnsRecordType::Nsec3,
        12 => DnsRecordType::Ptr,
        33 => DnsRecordType::Srv,
        252 => DnsRecordType::Axfr,
        43 => DnsRecordType::Ds,
        99 => DnsRecordType::Spf,
        _ => DnsRecordType::Txt, // fallback for unknown types
    }
}

fn parse_rdata(
    data: &[u8],
    offset: usize,
    rdlength: usize,
    rtype: u16,
) -> Result<String, DnsSecurityError> {
    match rtype {
        1 if rdlength == 4 => {
            // A record
            Ok(format!(
                "{}.{}.{}.{}",
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3]
            ))
        }
        28 if rdlength == 16 => {
            // AAAA record
            let mut parts = Vec::with_capacity(8);
            for i in 0..8 {
                let val = u16::from_be_bytes([data[offset + i * 2], data[offset + i * 2 + 1]]);
                parts.push(format!("{:x}", val));
            }
            Ok(parts.join(":"))
        }
        5 | 2 | 12 => {
            // CNAME, NS, PTR — domain name
            let (name, _) = read_dns_name(data, offset)?;
            Ok(name)
        }
        16 | 99 => {
            // TXT, SPF — character strings
            let mut result = String::new();
            let mut pos = offset;
            let end = offset + rdlength;
            while pos < end {
                let str_len = data[pos] as usize;
                pos += 1;
                if pos + str_len > end {
                    break;
                }
                result.push_str(&String::from_utf8_lossy(&data[pos..pos + str_len]));
                pos += str_len;
            }
            Ok(result)
        }
        15 => {
            // MX — preference + domain
            if rdlength < 3 {
                return Ok(String::new());
            }
            let preference = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let (exchange, _) = read_dns_name(data, offset + 2)?;
            Ok(format!("{} {}", preference, exchange))
        }
        _ => {
            // Hex dump for everything else (DNSKEY, RRSIG, NSEC, DS, etc.)
            let rdata = &data[offset..offset + rdlength];
            Ok(rdata
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>())
        }
    }
}

/// Parses an SPF TXT record into structured analysis.
pub fn parse_spf_record(txt: &str) -> Option<SpfAnalysis> {
    let trimmed = txt.trim();
    if !trimmed.starts_with("v=spf1") {
        return None;
    }

    let mut mechanisms = Vec::new();
    let mut all_qualifier = SpfQualifier::None;
    let mut issues = Vec::new();
    let mut dns_lookups = 0u32;

    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    for token in &tokens[1..] {
        let token_lower = token.to_lowercase();

        if token_lower == "all" || token_lower == "+all" {
            all_qualifier = SpfQualifier::Pass;
            issues.push("SPF uses +all — any server can send as this domain".into());
        } else if token_lower == "-all" {
            all_qualifier = SpfQualifier::Fail;
        } else if token_lower == "~all" {
            all_qualifier = SpfQualifier::SoftFail;
            issues.push(
                "SPF uses ~all (softfail) — messages from unauthorized senders are not rejected"
                    .into(),
            );
        } else if token_lower == "?all" {
            all_qualifier = SpfQualifier::Neutral;
            issues.push("SPF uses ?all (neutral) — provides no protection".into());
        } else {
            let (qualifier, mechanism_str) = parse_spf_qualifier(token);
            let (mtype, value) = parse_spf_mechanism_parts(mechanism_str);

            if matches!(
                mtype.as_str(),
                "include" | "a" | "mx" | "ptr" | "exists" | "redirect"
            ) {
                dns_lookups += 1;
            }

            mechanisms.push(SpfMechanism {
                qualifier,
                mechanism_type: mtype,
                value,
            });
        }
    }

    if dns_lookups > 10 {
        issues.push(format!(
            "SPF exceeds 10 DNS lookup limit ({} lookups) — may cause permerror",
            dns_lookups
        ));
    }

    if all_qualifier == SpfQualifier::None {
        issues.push("SPF record has no 'all' mechanism — defaults to neutral".into());
    }

    let grade = if all_qualifier == SpfQualifier::Pass {
        DnsSeverity::Critical
    } else if !issues.is_empty() && all_qualifier != SpfQualifier::Fail {
        DnsSeverity::Medium
    } else if issues.is_empty() && all_qualifier == SpfQualifier::Fail {
        DnsSeverity::Info
    } else {
        DnsSeverity::Low
    };

    Some(SpfAnalysis {
        raw_record: trimmed.to_string(),
        version: Some("spf1".into()),
        mechanisms,
        all_qualifier,
        dns_lookup_count: dns_lookups as usize,
        issues,
        grade,
    })
}

fn parse_spf_qualifier(token: &str) -> (SpfQualifier, &str) {
    match token.as_bytes().first() {
        Some(b'+') => (SpfQualifier::Pass, &token[1..]),
        Some(b'-') => (SpfQualifier::Fail, &token[1..]),
        Some(b'~') => (SpfQualifier::SoftFail, &token[1..]),
        Some(b'?') => (SpfQualifier::Neutral, &token[1..]),
        _ => (SpfQualifier::Pass, token), // default is pass
    }
}

fn parse_spf_mechanism_parts(mechanism: &str) -> (String, String) {
    if let Some(pos) = mechanism.find(':') {
        (
            mechanism[..pos].to_lowercase(),
            mechanism[pos + 1..].to_string(),
        )
    } else if let Some(pos) = mechanism.find('/') {
        (
            mechanism[..pos].to_lowercase(),
            mechanism[pos..].to_string(),
        )
    } else {
        (mechanism.to_lowercase(), String::new())
    }
}

/// Parses a DKIM TXT record for a given selector.
pub fn parse_dkim_record(selector: &str, txt: Option<&str>) -> DkimAnalysis {
    let Some(raw) = txt else {
        return DkimAnalysis {
            selector: selector.to_string(),
            raw_record: None,
            version: None,
            key_type: None,
            key_size_bits: None,
            public_key_present: false,
            issues: vec![format!("No DKIM record found for selector '{}'", selector)],
            grade: DnsSeverity::High,
        };
    };

    let tags = parse_dkim_tags(raw);
    let mut issues = Vec::new();

    let version = tags.get("v").cloned();
    if version.as_deref() != Some("DKIM1") {
        issues.push("Missing or invalid DKIM version tag".into());
    }

    let key_type = tags.get("k").cloned().or_else(|| Some("rsa".into()));
    let public_key_present = tags.get("p").is_some_and(|p| !p.is_empty());

    if !public_key_present {
        issues.push("No public key in DKIM record — key revoked or missing".into());
    }

    let key_size_bits = tags.get("p").and_then(|p| estimate_rsa_key_size(p));

    if let Some(size) = key_size_bits {
        if size < 1024 {
            issues.push(format!(
                "DKIM key too short ({} bits) — minimum 1024 recommended",
                size
            ));
        } else if size < 2048 {
            issues.push(format!(
                "DKIM key is {} bits — 2048+ bits recommended",
                size
            ));
        }
    }

    let grade = if !public_key_present || key_size_bits.is_some_and(|s| s < 1024) {
        DnsSeverity::High
    } else if !issues.is_empty() {
        DnsSeverity::Medium
    } else {
        DnsSeverity::Info
    };

    DkimAnalysis {
        selector: selector.to_string(),
        raw_record: Some(raw.to_string()),
        version,
        key_type,
        key_size_bits,
        public_key_present,
        issues,
        grade,
    }
}

fn parse_dkim_tags(record: &str) -> HashMap<String, String> {
    let mut tags = HashMap::new();
    for part in record.split(';') {
        let part = part.trim();
        if let Some(eq_pos) = part.find('=') {
            let key = part[..eq_pos].trim().to_lowercase();
            let value = part[eq_pos + 1..].trim().to_string();
            tags.insert(key, value);
        }
    }
    tags
}

fn estimate_rsa_key_size(base64_key: &str) -> Option<u32> {
    let cleaned: String = base64_key.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return None;
    }
    // base64 encodes 3 bytes per 4 chars; RSA public key DER includes overhead
    let byte_count = (cleaned.len() * 3) / 4;
    // Rough estimate: subtract ~38 bytes DER overhead, rest is modulus
    let modulus_bytes = byte_count.saturating_sub(38);
    Some((modulus_bytes * 8) as u32)
}

/// Parses a DMARC TXT record.
pub fn parse_dmarc_record(txt: Option<&str>) -> DmarcAnalysis {
    let Some(raw) = txt else {
        return DmarcAnalysis {
            raw_record: None,
            version: None,
            policy: DmarcPolicy::Missing,
            subdomain_policy: None,
            percentage: 100,
            rua: vec![],
            ruf: vec![],
            issues: vec!["No DMARC record found".into()],
            grade: DnsSeverity::High,
        };
    };

    let tags = parse_dkim_tags(raw); // reuse tag parser
    let mut issues = Vec::new();

    let version = tags.get("v").cloned();
    if version.as_deref() != Some("DMARC1") {
        issues.push("Missing or invalid DMARC version tag".into());
    }

    let policy = match tags.get("p").map(|s| s.as_str()) {
        Some("none") => {
            issues.push("DMARC policy is 'none' — no enforcement".into());
            DmarcPolicy::None
        }
        Some("quarantine") => DmarcPolicy::Quarantine,
        Some("reject") => DmarcPolicy::Reject,
        _ => {
            issues.push("Missing DMARC policy tag".into());
            DmarcPolicy::Missing
        }
    };

    let subdomain_policy = tags.get("sp").map(|sp| match sp.as_str() {
        "none" => DmarcPolicy::None,
        "quarantine" => DmarcPolicy::Quarantine,
        "reject" => DmarcPolicy::Reject,
        _ => DmarcPolicy::Missing,
    });

    let percentage = tags
        .get("pct")
        .and_then(|pct| pct.parse::<u8>().ok())
        .unwrap_or(100);

    if percentage < 100 {
        issues.push(format!(
            "DMARC pct={} — only {}% of messages are subject to policy",
            percentage, percentage
        ));
    }

    let rua: Vec<String> = tags
        .get("rua")
        .map(|r| r.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    let ruf: Vec<String> = tags
        .get("ruf")
        .map(|r| r.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    if rua.is_empty() {
        issues.push("No aggregate report URI (rua) — no visibility into failures".into());
    }

    let grade = match policy {
        DmarcPolicy::Missing => DnsSeverity::High,
        DmarcPolicy::None => DnsSeverity::Medium,
        DmarcPolicy::Quarantine if percentage < 100 => DnsSeverity::Low,
        DmarcPolicy::Quarantine => DnsSeverity::Low,
        DmarcPolicy::Reject if percentage == 100 && rua.is_empty() => DnsSeverity::Low,
        DmarcPolicy::Reject => DnsSeverity::Info,
    };

    DmarcAnalysis {
        raw_record: Some(raw.to_string()),
        version,
        policy,
        subdomain_policy,
        percentage,
        rua,
        ruf,
        issues,
        grade,
    }
}

/// Performs combined email authentication audit on SPF, DKIM, and DMARC records.
pub fn audit_email_authentication(
    domain: &str,
    spf_txt: Option<&str>,
    dkim_records: &[(&str, Option<&str>)],
    dmarc_txt: Option<&str>,
) -> Result<EmailAuthAudit, DnsSecurityError> {
    let domain = validate_domain(domain)?;

    let spf = spf_txt.and_then(parse_spf_record);
    let dkim: Vec<DkimAnalysis> = dkim_records
        .iter()
        .map(|(sel, txt)| parse_dkim_record(sel, *txt))
        .collect();
    let dmarc = Some(parse_dmarc_record(dmarc_txt));

    let worst_grade = [
        spf.as_ref().map(|s| s.grade),
        dkim.iter().map(|d| d.grade).max(),
        dmarc.as_ref().map(|d| d.grade),
    ]
    .iter()
    .filter_map(|g| *g)
    .max()
    .unwrap_or(DnsSeverity::High);

    Ok(EmailAuthAudit {
        domain,
        spf,
        dkim,
        dmarc,
        overall_grade: worst_grade,
    })
}

/// Generates Kaminsky-style cache poisoning payloads for testing.
pub fn generate_cache_poisoning_payloads(
    target_domain: &str,
    spoofed_ip: &str,
    count: usize,
) -> Result<Vec<CachePoisoningPayload>, DnsSecurityError> {
    let domain = validate_domain(target_domain)?;
    let mut payloads = Vec::with_capacity(count);

    for i in 0..count {
        let txid = ((i * 7 + 0xABCD) & 0xFFFF) as u16;
        let port = 1024 + ((i * 13 + 53) % 64511) as u16;
        let random_sub = format!("nxd-{:04x}.{}", txid, domain);

        payloads.push(CachePoisoningPayload {
            target_domain: random_sub.clone(),
            spoofed_answer: spoofed_ip.to_string(),
            transaction_id: txid,
            source_port: port,
            authority_injection: format!("{} IN NS attacker-ns.evil.test", domain),
            description: format!(
                "Query for non-existent {}, race response with spoofed NS delegation for {}",
                random_sub, domain
            ),
        });
    }

    Ok(payloads)
}

/// Evaluates DNSSEC status from a set of DNS records.
pub fn evaluate_dnssec(
    domain: &str,
    records: &[DnsRecord],
) -> Result<DnssecStatus, DnsSecurityError> {
    let domain = validate_domain(domain)?;

    let has_dnskey = records
        .iter()
        .any(|r| r.record_type == DnsRecordType::Dnskey);
    let has_rrsig = records
        .iter()
        .any(|r| r.record_type == DnsRecordType::Rrsig);
    let has_nsec = records.iter().any(|r| r.record_type == DnsRecordType::Nsec);
    let has_nsec3 = records
        .iter()
        .any(|r| r.record_type == DnsRecordType::Nsec3);
    let has_ds = records.iter().any(|r| r.record_type == DnsRecordType::Ds);
    let fully_signed = has_dnskey && has_rrsig && (has_nsec || has_nsec3);

    Ok(DnssecStatus {
        domain,
        has_dnskey,
        has_rrsig,
        has_nsec,
        has_nsec3,
        has_ds,
        fully_signed,
    })
}

/// Checks a set of DNS records for dangling references.
///
/// Identifies CNAME and A records that point to cloud services
/// which may be unclaimed, or CNAME chains with broken targets.
pub fn check_dangling_records(records: &[DnsRecord]) -> Vec<DanglingRecord> {
    let cloud_patterns: &[(&str, &str)] = &[
        (".s3.amazonaws.com", "AWS S3"),
        (".cloudfront.net", "AWS CloudFront"),
        (".herokuapp.com", "Heroku"),
        (".azurewebsites.net", "Azure"),
        (".trafficmanager.net", "Azure Traffic Manager"),
        (".cloudapp.azure.com", "Azure Cloud"),
        (".ghost.io", "Ghost"),
        (".github.io", "GitHub Pages"),
        (".gitlab.io", "GitLab Pages"),
        (".netlify.app", "Netlify"),
        (".surge.sh", "Surge"),
        (".firebaseapp.com", "Firebase"),
        (".pantheonsite.io", "Pantheon"),
        (".shopify.com", "Shopify"),
        (".squarespace.com", "Squarespace"),
        (".zendesk.com", "Zendesk"),
        (".freshdesk.com", "Freshdesk"),
        (".wpengine.com", "WP Engine"),
        (".bitbucket.io", "Bitbucket"),
        (".readthedocs.io", "ReadTheDocs"),
    ];

    let mut dangling = Vec::new();
    let known_names: std::collections::HashSet<&str> =
        records.iter().map(|r| r.name.as_str()).collect();

    for record in records {
        match record.record_type {
            DnsRecordType::Cname => {
                // CNAME to known cloud service — possible takeover
                let target_lower = record.value.to_lowercase();
                for (pattern, provider) in cloud_patterns {
                    if target_lower.ends_with(pattern) {
                        dangling.push(DanglingRecord {
                            record: record.clone(),
                            reason: DanglingReason::UnclaimedCloud(provider.to_string()),
                            risk: DnsSeverity::High,
                        });
                        break;
                    }
                }
                // Orphaned CNAME: target not in our record set
                if !known_names.contains(record.value.as_str())
                    && !cloud_patterns
                        .iter()
                        .any(|(p, _)| target_lower.ends_with(p))
                {
                    dangling.push(DanglingRecord {
                        record: record.clone(),
                        reason: DanglingReason::OrphanedCname,
                        risk: DnsSeverity::Medium,
                    });
                }
            }
            DnsRecordType::A => {
                // Reserved/documentation IPs that signal a dead record
                let ip_str = &record.value;
                if ip_str.starts_with("192.0.2.")
                    || ip_str.starts_with("198.51.100.")
                    || ip_str.starts_with("203.0.113.")
                    || ip_str == "0.0.0.0"
                {
                    dangling.push(DanglingRecord {
                        record: record.clone(),
                        reason: DanglingReason::NxdomainTarget,
                        risk: DnsSeverity::Medium,
                    });
                }
            }
            _ => {}
        }
    }

    dangling
}

/// Evaluates an NSEC walk result for zone enumeration vulnerability.
pub fn evaluate_nsec_walk(
    domain: &str,
    nsec_records: &[DnsRecord],
) -> Result<NsecWalkResult, DnsSecurityError> {
    let domain = validate_domain(domain)?;

    let nsec_entries: Vec<&DnsRecord> = nsec_records
        .iter()
        .filter(|r| r.record_type == DnsRecordType::Nsec)
        .collect();
    let nsec3_entries: Vec<&DnsRecord> = nsec_records
        .iter()
        .filter(|r| r.record_type == DnsRecordType::Nsec3)
        .collect();

    let uses_nsec3 = !nsec3_entries.is_empty();
    let walkable = !nsec_entries.is_empty() && !uses_nsec3;

    let discovered_names: Vec<String> = nsec_entries.iter().map(|r| r.name.clone()).collect();

    let (nsec3_salt, nsec3_iterations) = if let Some(first_nsec3) = nsec3_entries.first() {
        parse_nsec3_params(&first_nsec3.value)
    } else {
        (None, None)
    };

    Ok(NsecWalkResult {
        domain,
        walkable,
        discovered_names,
        uses_nsec3,
        nsec3_salt,
        nsec3_iterations,
    })
}

fn parse_nsec3_params(rdata_hex: &str) -> (Option<String>, Option<u32>) {
    // NSEC3 wire format: algorithm(1) flags(1) iterations(2) salt_len(1) salt(N) ...
    let bytes: Vec<u8> = rdata_hex
        .as_bytes()
        .chunks(2)
        .filter_map(|c| {
            let s = std::str::from_utf8(c).ok()?;
            u8::from_str_radix(s, 16).ok()
        })
        .collect();

    if bytes.len() < 5 {
        return (None, None);
    }

    let iterations = u16::from_be_bytes([bytes[2], bytes[3]]) as u32;
    let salt_len = bytes[4] as usize;
    let salt = if salt_len > 0 && bytes.len() >= 5 + salt_len {
        Some(
            bytes[5..5 + salt_len]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect(),
        )
    } else if salt_len == 0 {
        Some("-".to_string())
    } else {
        None
    };

    (salt, Some(iterations))
}

/// Assesses DNS amplification risk for a resolver.
pub fn assess_amplification(
    resolver_ip: &str,
    query_size: usize,
    response_size: usize,
    recursion_available: bool,
) -> AmplificationResult {
    let amplification_factor = if query_size > 0 {
        response_size as f64 / query_size as f64
    } else {
        0.0
    };

    let open_resolver = recursion_available && amplification_factor > 1.0;

    AmplificationResult {
        resolver_ip: resolver_ip.to_string(),
        query_size,
        response_size,
        amplification_factor,
        open_resolver,
        recursion_available,
    }
}

/// Evaluates subdomain delegation health.
pub fn check_delegation(
    subdomain: &str,
    ns_records: &[(&str, bool)],
) -> Result<DelegationResult, DnsSecurityError> {
    let subdomain = validate_domain(subdomain)?;

    let delegated_ns: Vec<String> = ns_records.iter().map(|(ns, _)| ns.to_string()).collect();
    let ns_reachable: Vec<bool> = ns_records.iter().map(|(_, reachable)| *reachable).collect();

    let lame_delegation = ns_reachable.iter().all(|r| !r) && !ns_reachable.is_empty();
    let missing_glue = delegated_ns
        .iter()
        .any(|ns| ns.ends_with(&format!(".{}", subdomain)));

    Ok(DelegationResult {
        subdomain,
        delegated_ns,
        ns_reachable,
        lame_delegation,
        missing_glue,
    })
}

/// Tests DNS rebinding vulnerability for given IP pairs.
pub fn evaluate_rebinding(
    domain: &str,
    initial_ip: &str,
    rebind_ip: &str,
    ttl: u32,
    resolver_blocked: bool,
) -> Result<RebindingTestResult, DnsSecurityError> {
    let domain = validate_domain(domain)?;

    let is_internal = is_internal_ip(rebind_ip);
    let vulnerable = is_internal && !resolver_blocked;

    let description = if vulnerable {
        format!(
            "Resolver allows rebinding from {} to internal address {} with TTL {} — vulnerable to DNS rebinding attacks",
            initial_ip, rebind_ip, ttl
        )
    } else if resolver_blocked {
        format!(
            "Resolver blocked rebinding from {} to {} — rebinding defense active",
            initial_ip, rebind_ip
        )
    } else {
        format!(
            "Rebinding from {} to {} (TTL {}) — target not internal",
            initial_ip, rebind_ip, ttl
        )
    };

    Ok(RebindingTestResult {
        domain,
        initial_ip: initial_ip.to_string(),
        rebind_ip: rebind_ip.to_string(),
        ttl_used: ttl,
        vulnerable,
        description,
    })
}

fn is_internal_ip(ip: &str) -> bool {
    if let Ok(addr) = ip.parse::<IpAddr>() {
        match addr {
            IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.octets()[0] == 169 && v4.octets()[1] == 254
            }
            IpAddr::V6(v6) => v6.is_loopback(),
        }
    } else {
        false
    }
}

/// Generates a comprehensive set of DnsFindings from audit results.
pub fn generate_findings(audit: &DnsSecurityAudit) -> Vec<DnsFinding> {
    let mut findings = Vec::new();

    // Zone transfer findings
    for zt in &audit.zone_transfer {
        if zt.success {
            findings.push(DnsFinding {
                check_type: DnsCheckType::ZoneTransfer,
                severity: DnsSeverity::Critical,
                title: format!("Zone transfer permitted on {}", zt.nameserver),
                description: format!(
                    "Nameserver {} allows AXFR zone transfer for {} — {} records exposed",
                    zt.nameserver,
                    zt.domain,
                    zt.records.len()
                ),
                evidence: format!("AXFR returned {} records", zt.records.len()),
                remediation: "Restrict zone transfers to authorized secondary nameservers only via allow-transfer ACL".into(),
            });
        }
    }

    // DNSSEC findings
    if let Some(ref dnssec) = audit.dnssec {
        let grade = dnssec.grade();
        if grade >= DnsSeverity::Medium {
            findings.push(DnsFinding {
                check_type: DnsCheckType::DnssecValidation,
                severity: grade,
                title: format!("DNSSEC not fully deployed on {}", dnssec.domain),
                description: format!(
                    "DNSKEY={}, RRSIG={}, NSEC={}, NSEC3={}, DS={}, fully_signed={}",
                    dnssec.has_dnskey,
                    dnssec.has_rrsig,
                    dnssec.has_nsec,
                    dnssec.has_nsec3,
                    dnssec.has_ds,
                    dnssec.fully_signed
                ),
                evidence: "DNSSEC record query results".into(),
                remediation: "Deploy DNSSEC with DNSKEY, sign zones with RRSIG, publish DS records at registrar".into(),
            });
        }
    }

    // Cache poisoning — always informational (payloads are for testing)
    if !audit.cache_poisoning_payloads.is_empty() {
        findings.push(DnsFinding {
            check_type: DnsCheckType::CachePoisoning,
            severity: DnsSeverity::Info,
            title: format!(
                "Generated {} cache poisoning test payloads",
                audit.cache_poisoning_payloads.len()
            ),
            description: "Kaminsky-style cache poisoning payloads for testing resolver resilience"
                .into(),
            evidence: format!(
                "{} payloads generated",
                audit.cache_poisoning_payloads.len()
            ),
            remediation: "Ensure resolvers use source port randomization and 0x20 encoding".into(),
        });
    }

    // Rebinding findings
    for rb in &audit.rebinding_tests {
        if rb.vulnerable {
            findings.push(DnsFinding {
                check_type: DnsCheckType::DnsRebinding,
                severity: DnsSeverity::High,
                title: format!(
                    "DNS rebinding vulnerable: {} → {}",
                    rb.initial_ip, rb.rebind_ip
                ),
                description: rb.description.clone(),
                evidence: format!(
                    "Rebind from {} to {} with TTL {} succeeded",
                    rb.initial_ip, rb.rebind_ip, rb.ttl_used
                ),
                remediation:
                    "Configure resolver to block private IP responses for external domains".into(),
            });
        }
    }

    // Dangling records
    for dr in &audit.dangling_records {
        findings.push(DnsFinding {
            check_type: DnsCheckType::DanglingRecords,
            severity: dr.risk,
            title: format!(
                "Dangling {} record: {} → {}",
                dr.record.record_type, dr.record.name, dr.record.value
            ),
            description: format!("Reason: {}", dr.reason),
            evidence: format!(
                "{} record {} points to {}",
                dr.record.record_type, dr.record.name, dr.record.value
            ),
            remediation: "Remove or update the DNS record to point to a valid target".into(),
        });
    }

    // Email authentication
    if let Some(ref email) = audit.email_auth {
        if let Some(ref spf) = email.spf {
            for issue in &spf.issues {
                findings.push(DnsFinding {
                    check_type: DnsCheckType::EmailAuthentication,
                    severity: spf.grade,
                    title: format!("SPF issue on {}", email.domain),
                    description: issue.clone(),
                    evidence: spf.raw_record.clone(),
                    remediation: "Tighten SPF record with -all and limit DNS lookups to 10".into(),
                });
            }
        }
        for dkim in &email.dkim {
            for issue in &dkim.issues {
                findings.push(DnsFinding {
                    check_type: DnsCheckType::EmailAuthentication,
                    severity: dkim.grade,
                    title: format!("DKIM issue (selector: {})", dkim.selector),
                    description: issue.clone(),
                    evidence: dkim
                        .raw_record
                        .clone()
                        .unwrap_or_else(|| "no record".into()),
                    remediation: "Publish DKIM record with 2048-bit RSA key".into(),
                });
            }
        }
        if let Some(ref dmarc) = email.dmarc {
            for issue in &dmarc.issues {
                findings.push(DnsFinding {
                    check_type: DnsCheckType::EmailAuthentication,
                    severity: dmarc.grade,
                    title: format!("DMARC issue on {}", email.domain),
                    description: issue.clone(),
                    evidence: dmarc
                        .raw_record
                        .clone()
                        .unwrap_or_else(|| "no record".into()),
                    remediation: "Set DMARC policy to reject with rua reporting URI".into(),
                });
            }
        }
    }

    // NSEC walking
    if let Some(ref nsec) = audit.nsec_walk
        && nsec.walkable
    {
        findings.push(DnsFinding {
            check_type: DnsCheckType::NsecWalking,
            severity: DnsSeverity::Medium,
            title: format!("NSEC zone walking possible on {}", nsec.domain),
            description: format!(
                "NSEC records allow full zone enumeration — {} names discovered",
                nsec.discovered_names.len()
            ),
            evidence: format!("NSEC walk returned {} names", nsec.discovered_names.len()),
            remediation: "Use NSEC3 with opt-out to prevent zone walking".into(),
        });
    }

    // Amplification
    for amp in &audit.amplification {
        if amp.open_resolver {
            findings.push(DnsFinding {
                check_type: DnsCheckType::DnsAmplification,
                severity: DnsSeverity::High,
                title: format!("Open resolver at {}", amp.resolver_ip),
                description: format!(
                    "Resolver accepts recursive queries with {:.1}x amplification factor",
                    amp.amplification_factor
                ),
                evidence: format!(
                    "Query: {} bytes → Response: {} bytes (factor {:.1}x)",
                    amp.query_size, amp.response_size, amp.amplification_factor
                ),
                remediation:
                    "Disable recursion for external queries or implement response rate limiting"
                        .into(),
            });
        }
    }

    // Delegation issues
    for del in &audit.delegation {
        if del.lame_delegation {
            findings.push(DnsFinding {
                check_type: DnsCheckType::SubdomainDelegation,
                severity: DnsSeverity::High,
                title: format!("Lame delegation for {}", del.subdomain),
                description: format!(
                    "All nameservers ({}) unreachable for {}",
                    del.delegated_ns.join(", "),
                    del.subdomain
                ),
                evidence: "No delegated nameserver responded".into(),
                remediation: "Fix NS records to point to active nameservers or remove delegation"
                    .into(),
            });
        }
        if del.missing_glue {
            findings.push(DnsFinding {
                check_type: DnsCheckType::SubdomainDelegation,
                severity: DnsSeverity::Medium,
                title: format!("Missing glue records for {}", del.subdomain),
                description: "In-bailiwick nameservers without glue records cause resolution failures".into(),
                evidence: format!("NS records: {}", del.delegated_ns.join(", ")),
                remediation: "Add glue A/AAAA records for in-bailiwick nameservers".into(),
            });
        }
    }

    findings
}

/// Returns all supported DNS check types.
pub fn supported_check_types() -> Vec<DnsCheckType> {
    vec![
        DnsCheckType::ZoneTransfer,
        DnsCheckType::DnssecValidation,
        DnsCheckType::CachePoisoning,
        DnsCheckType::DnsRebinding,
        DnsCheckType::DanglingRecords,
        DnsCheckType::EmailAuthentication,
        DnsCheckType::NsecWalking,
        DnsCheckType::DnsAmplification,
        DnsCheckType::SubdomainDelegation,
    ]
}
