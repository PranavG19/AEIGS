<!-- metadata:
  crate: aegis-audit-log
  purpose: Tamper-evident append-only audit log with SHA3-256 hash chain and HMAC integrity
  public_api: AuditWriter (trait), AuditLogWriter, NoOpAuditLogWriter,
              HashChain, HmacSigner, VerificationReport, VerifierError,
              EventQuery, ScanSnapshot, SnapshotDiff, ReplayResult, FindingRecord,
              ConfigChangeRecord, EventStoreError,
              verify_log(), verify_log_bytes(), replay_from_entries(), filter_entries(),
              diff_snapshots(), compute_scan_timeline(), classify_event(), serialize_event()
  modules: hash_chain, hmac_signer, log_writer, log_verifier, event_store
  dependencies: aegis-protocol, serde, serde_json, ciborium, sha3, hmac, uuid, tracing
-->

# aegis-audit-log

## Purpose

`aegis-audit-log` provides a tamper-evident, append-only audit trail for scan operations. Each
event is CBOR-serialized, chained via SHA3-256 hash linking, and signed with HMAC-SHA3-256. The
audit log satisfies two security goals: detecting accidental corruption or deliberate tampering
(reordered, deleted, or modified entries) and providing a verifiable chronological timeline of scan
activities. Audit logging is mandatory by default in AEGIS — the scan fails if the log cannot be
created — and `--no-audit` must be explicitly passed to opt out. The crate also provides event
sourcing via `replay_from_entries()` and `diff_snapshots()` for post-hoc scan state reconstruction.

## Crate Type

Library

## Dependencies on Workspace Crates

- `aegis-protocol` — `AuditEntry`, `AuditEventType`, `ModuleIdentifier`, `VulnerabilityClass`

## External Dependencies

| Dependency | Version | Role |
|---|---|---|
| serde | 1 | Serialization derives |
| serde_json | 1 | JSON in event sourcing types |
| ciborium | 0.2 | CBOR serialization for event payloads (~40% smaller than JSON, self-describing) |
| sha3 | 0.10 | SHA3-256 for hash chain and HMAC key derivation |
| hmac | 0.12 | HMAC-SHA3-256 for per-entry integrity signatures |
| uuid | 1 | Available to callers |
| tracing | 0.1 | Diagnostic spans |

## Module Structure

| Module | Responsibility |
|---|---|
| `hash_chain` | `HashChain` append-only struct; `genesis_hash()`, `compute_next_hash()`, `verify_chain()` |
| `hmac_signer` | `HmacSigner` with key file I/O, passphrase derivation, constant-time verification |
| `log_writer` | `AuditWriter` trait, `AuditLogWriter` (disk), `NoOpAuditLogWriter` (--no-audit), `LogWriterError`, `serialize_event()` |
| `log_verifier` | `verify_log()`, `verify_log_bytes()`, `VerificationReport`, `VerifierError` |
| `event_store` | `replay_from_entries()`, `filter_entries()`, `diff_snapshots()`, `compute_scan_timeline()`, event sourcing types |

## Public API Summary

### Trait: AuditWriter

The primary abstraction used by the pipeline. `Box<dyn AuditWriter>` is passed through `ScanContext`.

```rust
pub trait AuditWriter {
    /// Appends an event and returns the full entry with hash chain and HMAC metadata.
    /// Use when the caller needs the entry (e.g., verification tests).
    fn append_event_full(&mut self, event: AuditEventType) -> Result<AuditEntry, LogWriterError>;

    /// Appends an event, discarding the returned entry. Default implementation delegates to append_event_full.
    fn append_event(&mut self, event: AuditEventType) -> Result<(), LogWriterError> {
        self.append_event_full(event)?;
        Ok(())
    }

    fn sequence_number(&self) -> u64;
}
```

### Struct: AuditLogWriter

Persists events to a CBOR binary file on disk.

```rust
pub struct AuditLogWriter { chain: HashChain, signer: HmacSigner, sequence: u64, file: File }

impl AuditLogWriter {
    pub fn create(path: &Path, hmac_key: &[u8]) -> Result<Self, LogWriterError>;
}
impl AuditWriter for AuditLogWriter { ... }
```

Wire format per entry (binary, no delimiters between entries):
```
[8 bytes: sequence_number LE u64]
[32 bytes: entry_hash SHA3-256(prev_hash || payload_cbor)]
[4 bytes: payload_len LE u32]
[payload_len bytes: CBOR-encoded AuditEventType]
[32 bytes: HMAC-SHA3-256(payload_cbor)]
```

The file is opened with `append` mode and flushed after every entry to ensure durability.

### Struct: NoOpAuditLogWriter

Intentionally discards all events. Used when `--no-audit` is passed. Returns synthetic `AuditEntry`
values with zeroed hashes so callers that call `append_event_full` do not need to handle `None`.

```rust
pub struct NoOpAuditLogWriter { sequence: u64 }
impl NoOpAuditLogWriter {
    pub fn new() -> Self;
}
impl AuditWriter for NoOpAuditLogWriter { ... }
// append_event_full returns AuditEntry with previous_hash=[0u8;32], hmac=[0u8;32]
```

### Struct: HashChain

```rust
pub struct HashChain { current_hash: Hash }
impl HashChain {
    pub fn new() -> Self;
    pub fn append(&mut self, data: &[u8]) -> Hash;
    pub fn current_hash(&self) -> Hash;
}

pub type Hash = [u8; 32];
pub const HASH_SIZE: usize = 32;
pub fn genesis_hash() -> Hash;  // SHA3-256 of empty input
pub fn compute_next_hash(previous_hash: &Hash, data: &[u8]) -> Hash;
pub fn verify_chain(entries: &[(Hash, Vec<u8>)]) -> bool;
```

Chain invariant: `entry_hash[i] = SHA3-256(entry_hash[i-1] || payload_cbor[i])`. The genesis hash
is `SHA3-256("")` (SHA3-256 of empty bytes, deterministic).

### Struct: HmacSigner

```rust
pub struct HmacSigner { key: Vec<u8> }
pub type MacBytes = [u8; 32];
pub const MAC_SIZE: usize = 32;

impl HmacSigner {
    pub fn new(key: &[u8]) -> Self;
    pub fn with_key_file(path: &Path) -> Result<Self, std::io::Error>;
    pub fn save_key_to_file(&self, path: &Path) -> Result<(), std::io::Error>;
    // Sets Unix permissions to 0o600 on save

    pub fn with_derived_key(passphrase: &[u8]) -> Self;
    // Key = SHA3-256("aegis-hmac-key-derivation-v1" || passphrase)

    pub fn sign(&self, data: &[u8]) -> MacBytes;
    pub fn verify(&self, data: &[u8], expected_mac: &MacBytes) -> bool;
    // Uses constant-time comparison (manual XOR accumulator, not subtle::ConstantTimeEq)
}
```

### Verification

```rust
pub struct VerificationReport {
    pub entries_checked: u64,
    pub first_invalid_entry: Option<u64>,  // sequence number of first tampered entry
    pub tamper_detected: bool,
    pub hash_chain_valid: bool,
    pub hmac_valid: bool,
}

pub enum VerifierError {
    IoError(io::Error),
    InvalidFormat(String),  // truncated header, truncated payload/hmac
}

pub fn verify_log(path: &Path, hmac_key: &[u8]) -> Result<VerificationReport, VerifierError>;
pub fn verify_log_bytes(data: &[u8], hmac_key: &[u8]) -> Result<VerificationReport, VerifierError>;
// Reads the binary format, recomputes hash chain and HMAC independently,
// reports the first sequence number where either check fails.
// tamper_detected = !hash_chain_valid || !hmac_valid
```

### Event Sourcing (event_store)

```rust
// Query criteria (all fields optional, combined with AND)
pub struct EventQuery {
    pub event_types: Option<Vec<String>>,      // e.g. ["FindingRecorded", "ScanCompleted"]
    pub after_sequence: Option<u64>,
    pub before_sequence: Option<u64>,
    pub after_timestamp_ms: Option<u64>,
    pub before_timestamp_ms: Option<u64>,
}

// Reconstructed scan state from replay
pub struct ScanSnapshot {
    pub target_description: Option<String>,
    pub active_modules: Vec<String>,
    pub findings: Vec<FindingRecord>,
    pub total_findings: Option<u64>,
    pub config_changes: Vec<ConfigChangeRecord>,
    pub key_events: Vec<String>,
    pub last_sequence: u64,
    pub last_timestamp_ms: u64,
    pub is_complete: bool,
}

pub struct FindingRecord {
    pub finding_id: u64,
    pub vulnerability_class: String,
    pub sequence_number: u64,
    pub timestamp_ms: u64,
}

pub struct ConfigChangeRecord {
    pub key: String,
    pub old_value: String,
    pub new_value: String,
    pub sequence_number: u64,
    pub timestamp_ms: u64,
}

pub struct SnapshotDiff {
    pub new_findings: Vec<FindingRecord>,
    pub new_modules: Vec<String>,
    pub new_config_changes: Vec<ConfigChangeRecord>,
    pub new_key_events: Vec<String>,
}

pub struct ReplayResult {
    pub snapshot: ScanSnapshot,
    pub entries_replayed: u64,
    pub entries_skipped: u64,
}

pub enum EventStoreError {
    VerificationFailed(String),
    DeserializationFailed(String),
    InvalidQuery(String),   // after_sequence >= before_sequence, or same for timestamps
    Io(std::io::Error),
}

// Replay all entries to reconstruct scan state. Does NOT verify hash chain or HMAC.
pub fn replay_from_entries(entries: &[AuditEntry]) -> ScanSnapshot;

// Filter entries by EventQuery. Returns Err(InvalidQuery) on contradictory range constraints.
pub fn filter_entries<'a>(entries: &'a [AuditEntry], query: &EventQuery) -> Result<Vec<&'a AuditEntry>, EventStoreError>;

// Compute delta between two snapshots.
// Findings: diff by finding_id. Modules/config changes/key events: diff by position.
pub fn diff_snapshots(before: &ScanSnapshot, after: &ScanSnapshot) -> SnapshotDiff;

// Build (timestamp_ms, description) pairs for a human-readable timeline.
pub fn compute_scan_timeline(entries: &[AuditEntry]) -> Vec<(u64, String)>;

// Return the event type discriminator string for an AuditEventType.
pub fn classify_event(event: &AuditEventType) -> &'static str;
// Returns: "ScanStarted", "ModuleStarted", "FindingRecorded", "ScanCompleted", "KeyEvent", "ConfigChange"
```

### Other

```rust
// Serialize an AuditEventType to CBOR bytes (used internally and in tests).
pub fn serialize_event(event: &AuditEventType) -> Result<Vec<u8>, LogWriterError>;
```

## Error Types

```rust
pub enum LogWriterError {
    IoError(io::Error),
    SerializationError(String),
    LogCreationFailed(String),
}
impl From<io::Error> for LogWriterError { ... }
```

`VerifierError`, `EventStoreError` implement `std::error::Error` and `From<io::Error>`.

## Key Implementation Notes

**Threat model: tamper evidence, not tamper resistance.** The hash chain detects reordering,
deletion, and modification of entries. It does NOT prevent an attacker who has access to the HMAC
key from rewriting the entire chain. The key is intended to be stored separately from the audit
data (`save_key_to_file` writes with mode `0o600`; alternatively `with_derived_key` derives from a
passphrase). The log is designed for detecting accidental corruption and providing a forensic
timeline; not for resisting a compromised host.

**CBOR is used for event payloads, not JSON.** ciborium CBOR serialization is ~40% smaller than
JSON and self-describing (no schema compilation step). The binary wire format then stores a length
prefix + CBOR payload + HMAC. CBOR is also used for the audit sidecar file in the certificate
serializer.

**`replay_from_entries` does not verify the chain.** It operates on `&[AuditEntry]` slices and
purely reconstructs state by applying events in order. Callers who need integrity verification must
call `verify_log` or `verify_log_bytes` separately before calling replay. This separation avoids
coupling replay semantics with the cryptographic verification path.

**`NoOpAuditLogWriter` has an explicit contract.** It is not a broken implementation — the design
document comments in the source code explicitly state that events are silently dropped. This is the
correct behavior for `--no-audit` mode. Callers that need to distinguish no-op from real writes
should not downcast; instead, use `sequence_number()` — the no-op writer still increments
its sequence counter, which is sometimes useful for test assertions.

**`diff_snapshots` uses different strategies by field type.** Findings are diffed by `finding_id`
(set difference). Module activations, config changes, and key events are diffed positionally (items
in `after` beyond `before`'s length). This means config changes and key events can only grow
forward, not be retroactively inserted.

**`EventQuery` validates range constraints.** `filter_entries` returns `InvalidQuery` if
`after_sequence >= before_sequence` or `after_timestamp_ms >= before_timestamp_ms`. An empty query
(all `None`) is valid and returns all entries.

## Usage Context

The orchestrator constructs either an `AuditLogWriter` (when audit is enabled, which is the default)
or a `NoOpAuditLogWriter` (when `--no-audit` is passed) and boxes it as `Box<dyn AuditWriter>`. The
boxed writer is stored in `ScanContext` and called at the start of each scan phase
(`ScanStarted`, `ModuleStarted`), when each finding is recorded (`FindingRecorded`), and on
completion (`ScanCompleted`). After a scan, the orchestrator can optionally call `verify_log` with
the HMAC key to confirm log integrity, or call `replay_from_entries` to reconstruct scan state for
diff-mode comparison with a previous run.
