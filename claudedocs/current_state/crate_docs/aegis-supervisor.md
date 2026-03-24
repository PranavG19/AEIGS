<!-- metadata: crate=aegis-supervisor, purpose=process lifecycle management and capability-based token authorization for AEGIS component processes, type=library, internal_deps=[aegis-protocol], external_deps=[sha3, subtle, tokio] -->

# aegis-supervisor

## Purpose

Manages AEGIS component process lifecycles (start, stop, restart with exponential backoff) and issues/validates short-lived capability tokens that authorize specific permissions per module, using SHA3-256 HMAC-derived token bytes and constant-time comparison.

## Crate Type

Library

## Dependencies on Workspace Crates

- `aegis-protocol` — `CapabilityToken`, `Permission`, `ModuleIdentifier`

## External Dependencies

- `sha3` — SHA3-256 for token byte computation (`Sha3_256::new()`)
- `subtle` — `ConstantTimeEq` (`ct_eq`) for timing-safe token validation
- `tokio` — async runtime (referenced in broader workspace context; not used directly in these modules but required by dependents)

## Module Structure

| Module | Description |
|---|---|
| `process_manager` | `ProcessManager` — registers, tracks, and transitions component processes through a lifecycle state machine |
| `capability_manager` | `CapabilityManager` — issues and validates time-bounded capability tokens per registered module policy |

## Public API Summary

### `process_manager`

```rust
pub enum ComponentId {
    KnowledgeGraph, PassiveRecon, Enumeration, Fuzzing, TaintAnalysis,
    ChainSynthesis, Reporting, Watchdog, HypothesisEngine,
}
// implements Display: "knowledge-graph", "passive-recon", etc.

pub enum ProcessState { NotStarted, Running, Stopped, Failed, Restarting }

pub struct ProcessConfig {
    pub component: ComponentId,
    pub binary_path: PathBuf,
    pub arguments: Vec<String>,
    pub max_restarts: u32,                   // default: 3
    pub restart_backoff_base: Duration,       // default: 1s
    pub memory_limit_bytes: Option<u64>,
    pub cpu_limit_percent: Option<u32>,
}
impl ProcessConfig {
    pub fn new(component: ComponentId, binary_path: PathBuf) -> Self
    pub fn with_arguments(self, args: Vec<String>) -> Self
    pub fn with_max_restarts(self, max: u32) -> Self
    pub fn with_restart_backoff(self, base: Duration) -> Self
    pub fn with_memory_limit(self, bytes: u64) -> Self
    pub fn with_cpu_limit(self, percent: u32) -> Self
}

pub struct ManagedProcess {
    pub config: ProcessConfig,
    pub state: ProcessState,
    pub pid: Option<u32>,
    pub restart_count: u32,
    pub last_started: Option<Instant>,
    pub last_stopped: Option<Instant>,
    pub exit_code: Option<i32>,
}
impl ManagedProcess {
    pub fn can_restart(&self) -> bool            // restart_count < max_restarts
    /// Returns base * 2^restart_count (saturating multiply).
    pub fn backoff_duration(&self) -> Duration
    pub fn mark_started(&mut self, pid: u32)     // -> Running
    pub fn mark_stopped(&mut self, exit_code: i32) // -> Stopped (0) or Failed (!0)
    pub fn mark_restarting(&mut self)            // -> Restarting, increments restart_count
}

pub enum ProcessManagerError {
    ComponentAlreadyRegistered(ComponentId),
    ComponentNotFound(ComponentId),
    MaxRestartsExceeded(ComponentId),
    SpawnFailed(ComponentId, String),
}

pub struct ProcessManager { /* private */ }

impl ProcessManager {
    pub fn new() -> Self
    pub fn register(&mut self, config: ProcessConfig) -> Result<(), ProcessManagerError>
    pub fn get_process(&self, component: ComponentId) -> Option<&ManagedProcess>
    pub fn get_process_mut(&mut self, component: ComponentId) -> Option<&mut ManagedProcess>
    pub fn spawn_order(&self) -> &[ComponentId]
    pub fn all_processes(&self) -> impl Iterator<Item = (&ComponentId, &ManagedProcess)>
    pub fn running_count(&self) -> usize
    pub fn failed_count(&self) -> usize
    /// Marks component as Restarting and returns the backoff duration to wait.
    pub fn request_restart(&mut self, component: ComponentId)
        -> Result<Duration, ProcessManagerError>
    pub fn mark_started(&mut self, component: ComponentId, pid: u32)
        -> Result<(), ProcessManagerError>
    pub fn mark_stopped(&mut self, component: ComponentId, exit_code: i32)
        -> Result<(), ProcessManagerError>
    pub fn components_in_state(&self, state: ProcessState) -> Vec<ComponentId>
    /// Marks all Running processes as Stopped (reverse spawn order). Returns affected IDs.
    pub fn shutdown_all(&mut self) -> Vec<ComponentId>
}
```

### `capability_manager`

```rust
pub enum CapabilityError {
    TokenExpired,
    InsufficientPermissions(Permission),
    UnknownModule(ModuleIdentifier),
    InvalidToken,
}

pub struct ModulePermissionPolicy {
    pub module: ModuleIdentifier,
    pub allowed_permissions: Vec<Permission>,
    pub token_lifetime: Duration,
}

pub struct CapabilityManager { /* private */ }

impl CapabilityManager {
    pub fn new(master_key: Vec<u8>) -> Self
    pub fn register_policy(&mut self, policy: ModulePermissionPolicy)
    /// Issues a time-bounded token. Requires a registered policy for module.
    /// Token bytes = SHA3-256(master_key || module_debug_name || expires_at_le_bytes).
    pub fn issue_token(&mut self, module: ModuleIdentifier, current_time_ms: u64)
        -> Result<CapabilityToken, CapabilityError>
    /// Validates token using constant-time comparison (subtle::ConstantTimeEq).
    /// Checks: not expired → token bytes match → permission present.
    pub fn validate_token(&self, token: &CapabilityToken, required_permission: Permission,
        current_time_ms: u64) -> Result<(), CapabilityError>
    pub fn issued_count(&self) -> u64
    pub fn has_policy(&self, module: ModuleIdentifier) -> bool
    pub fn policy_for(&self, module: ModuleIdentifier) -> Option<&ModulePermissionPolicy>
}
```

## Key Implementation Notes

- **`ProcessManager` does not spawn actual OS processes**: The struct manages process lifecycle state and computes backoff durations, but does not call `std::process::Command::spawn()`. The actual OS spawn is expected to be performed by the caller, which then calls `mark_started(component, pid)`. This keeps the struct pure (no side effects, fully testable without actual subprocesses) (process_manager.rs:176-298).

- **Exponential backoff uses saturating arithmetic**: `backoff_duration` computes `base * 2^restart_count` via `2u64.saturating_pow(restart_count)` and then `saturating_mul(multiplier as u32)`. This prevents overflow on high restart counts at the cost of capping at `Duration::MAX` (process_manager.rs:122-127).

- **`shutdown_all` reverses spawn order**: Components are shut down in reverse registration order (process_manager.rs:282-291). This mirrors correct teardown ordering (e.g., stop consumers before producers).

- **`mark_stopped` distinguishes clean exit from failure**: Exit code 0 transitions to `ProcessState::Stopped`; any non-zero exit code transitions to `ProcessState::Failed`. The exit code is stored on the `ManagedProcess` for inspection (process_manager.rs:136-145).

- **Token bytes use SHA3-256, not HMAC**: `compute_token_bytes` creates a SHA3-256 hash of `master_key || module_debug_name || expires_at_le_bytes`. This is not a proper HMAC (no separate padding) but provides sufficient binding between the master key and the token parameters for the localhost-only threat model (capability_manager.rs:119-126).

- **Constant-time comparison is critical**: `validate_token` uses `bool::from(token.token_bytes.ct_eq(&expected_bytes))` from the `subtle` crate. A standard `==` comparison would be vulnerable to timing oracle attacks where an attacker could brute-force token bytes by measuring response time differences (capability_manager.rs:93-94).

- **Validation order: expiry before cryptographic check**: The token is checked for expiry before the token bytes are compared. This leaks whether the token has expired (a timing channel on expiry status), but avoids revealing any information about token byte validity in cases where time-bounded replays are attempted.

- **`ModuleIdentifier` uses debug representation for hashing**: `compute_token_bytes` uses `format!("{module:?}").as_bytes()` — the `Debug` output of `ModuleIdentifier`. Adding new `ModuleIdentifier` variants changes the Debug string, which would invalidate any stored tokens — acceptable since tokens are short-lived and not persisted.

## Usage Context

`ProcessManager` is intended for use by the orchestrator when running AEGIS as a multi-process distributed system, where component processes are managed as separate binaries. In the current single-process scan pipeline, its state management is used to track hypothetical component states for metrics. `CapabilityManager` provides the authorization layer that validates module tokens before sensitive graph operations are applied, ensuring only authorized modules can write to specific node/edge/finding types.
