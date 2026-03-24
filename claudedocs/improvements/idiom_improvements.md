# Idiomatic Rust Improvements

Generated: 2026-02-23 | Source depth: 2

---

### IDIOM-001: parse_stealth_level / resolve_persona_id Should Be TryFrom
**Severity:** medium
**Effort:** small
**Affected:** aegis-orchestrator
**Source confirmed:** yes (`scan_config.rs:435-453`)

Multiple standalone conversion functions should implement standard Rust conversion traits:
- `parse_stealth_level(&str) -> Result<StealthLevel, ConfigError>` → `TryFrom<&str> for StealthLevel`
- `resolve_persona_id(&str) -> Result<PersonaId, ConfigError>` → `TryFrom<&str> for PersonaId`
- `parse_report_format(&str) -> Result<ReportFormat, ConfigError>` → `TryFrom<&str> for ReportFormat`

Using `TryFrom` makes conversions discoverable via the trait system and allows `.try_into()` call syntax.

**Recommendation:**
```rust
impl TryFrom<&str> for StealthLevel {
    type Error = ConfigError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "default" => Ok(StealthLevel::Default),
            "aggressive" => Ok(StealthLevel::Aggressive),
            "paranoid" => Ok(StealthLevel::Paranoid),
            _ => Err(ConfigError::InvalidStealthLevel(s.to_string())),
        }
    }
}
```

---

### IDIOM-002: StealthLevel Stored as String in ScanConfig (Should Be Enum)
**Severity:** medium
**Effort:** small
**Affected:** aegis-orchestrator
**Source confirmed:** yes (`StealthOptions::stealth_level: String`)

`StealthLevel` enum exists but `StealthOptions::stealth_level` uses `String`. The conversion happens at `parse_stealth_level()` call time during pipeline execution, not at parse time. This delays error detection and requires extra unwrapping.

**Recommendation:** Use clap's `ValueEnum` derive to parse directly to the enum:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum StealthLevel {
    #[value(name = "default")]
    Default,
    #[value(name = "aggressive")]
    Aggressive,
    #[value(name = "paranoid")]
    Paranoid,
}
// In StealthOptions:
#[arg(long, default_value_t = StealthLevel::Default, value_enum)]
pub stealth_level: StealthLevel,
```
This provides better help text, tab completion, and fails fast on invalid values.

---

### IDIOM-003: Manual match on Option/Result Instead of Combinators
**Severity:** low
**Effort:** medium
**Affected:** multiple crates
**Source confirmed:** partial

Based on the pipeline code read, there are patterns like:
```rust
// Instead of:
match ctx.graph.get_node(id).ok().flatten() {
    Some(n) => n.properties.get("path").cloned(),
    None => None,
}
// Use:
ctx.graph.get_node(id).ok().flatten()
    .and_then(|n| n.properties.get("path").cloned())
```

Audit the codebase for verbose `match Some(x) => ..., None => None` patterns that could use `.map()` or `.and_then()`.

---

### IDIOM-004: Public Struct Fields Should Be Private With Accessors
**Severity:** low
**Effort:** large
**Affected:** aegis-protocol
**Source confirmed:** yes (`finding.rs`, `node.rs`, `edge.rs`)

`FindingData`, `NodeData`, `EdgeData`, `FuzzRequest`, `FuzzResponse`, `OperationLogEntry` all have `pub` fields. For a framework with claimed invariants (FindingData.severity must be [0.0, 10.0], EdgeData.weight must be >= 0.0), public fields allow callers to violate these invariants after construction.

**Recommendation:** The builder pattern (`with_*` methods) already exists for `FindingData` — make fields private and enforce construction through the builder. For `NodeData` and `EdgeData`, add accessor methods. `FuzzRequest`/`FuzzResponse` may be acceptable with pub fields since they're data transfer objects with no invariants.

---

### IDIOM-005: Missing Display Implementation on Key Domain Types
**Severity:** low
**Effort:** small
**Affected:** aegis-protocol, aegis-fuzzing
**Source confirmed:** partial

Some types used in error messages or logging lack `Display`:
- `MutationOrigin` (fuzzing) — appears in log messages but may not implement Display
- `AnomalyType` (fuzzing) — appears in finding descriptions
- `PersonaId` (evasion-engine) — should have human-readable Display (currently just Debug)

**Recommendation:** Add `Display` implementations to all types that appear in user-facing output (log messages, SARIF findings, interactive mode status).

---

### IDIOM-006: Iterator Usage — for Loops That Could Use Adapters
**Severity:** low
**Effort:** small
**Affected:** multiple crates
**Source confirmed:** partial

Based on the code patterns reviewed, there are likely `for` loops that could use iterator adapters:
- `for &id in ids { if let Some(node) = ... { result.push(...) } }` → `.filter_map()`
- `for item in collection { if condition { continue } process(item); }` → `.filter().for_each()`

Run `cargo clippy -- -W clippy::needless_pass_by_value -W clippy::unnecessary_filter_map` to catch these automatically.

---

### IDIOM-007: Missing `#[must_use]` on Builder Methods
**Severity:** low
**Effort:** small
**Affected:** aegis-protocol, aegis-fuzzing, aegis-evasion-engine
**Source confirmed:** partial

Builder methods like `FindingData::with_stable_id()`, `NodeData::with_property()`, `EvasionTransportBuilder::with_persona()` take `self` and return `Self`. Without `#[must_use]`, callers can accidentally write:
```rust
finding.with_stable_id(endpoint, param);  // Bug: result is discarded
```

**Recommendation:** Add `#[must_use = "builder methods return modified value"]` to all builder methods that return `Self`.

---

### IDIOM-008: Use of `format!()` for Error Messages That Are Static
**Severity:** low
**Effort:** small
**Affected:** multiple crates
**Source confirmed:** partial

Patterns like `format!("graph validation failed: {e}")` in `Display` implementations allocate a `String` every time they're called. Static message components can use `write!` macros directly.

**Recommendation:** In `fmt::Display` implementations, avoid intermediate `format!()` calls:
```rust
// Instead of:
write!(f, "{}", format!("graph validation failed: {e}"))
// Use:
write!(f, "graph validation failed: {e}")
```

---

### IDIOM-009: `to_string()` Called Where `String::from()` or `Into::into()` Would Be Clearer
**Severity:** low
**Effort:** small
**Affected:** multiple crates
**Source confirmed:** partial

`.to_string()` is commonly used for type conversions where the intent is clearer with `.into()` or `String::from()`:
```rust
// If value is already a &str:
let s: String = value.to_string();  // unclear
let s: String = value.into();       // clearer intent
let s = String::from(value);        // most explicit
```

---

### IDIOM-010: Missing Default Implementation for Structs with All-Defaultable Fields
**Severity:** low
**Effort:** small
**Affected:** multiple crates
**Source confirmed:** partial

Some configuration structs may be missing `#[derive(Default)]` where all fields have sensible defaults:
- `DefenseProfile` — has an `empty()` constructor but should derive or implement `Default`
- `StealthConfig` — has a `default()` constructor; should derive `Default`
- `LlmMetrics`, `PhaseTimings` — both have `#[derive(Default)]` which is correct

**Recommendation:** Audit structs with custom `new()` constructors that create all-default values. Replace with `#[derive(Default)]` where applicable.

---

### IDIOM-011: No Lint Configuration (clippy.toml or workspace [lints])
**Severity:** low
**Effort:** small
**Affected:** all crates
**Source confirmed:** yes (no clippy.toml found, no [lints] in Cargo.toml)

The workspace has no `clippy.toml` or `[workspace.lints]` section. The CLAUDE.md mentions a "zero warnings policy" for `cargo clippy -- -D warnings` but without explicit lint configuration, some useful lints are not enabled by default.

**Recommendation:** Add a `[workspace.lints.clippy]` section to `Cargo.toml`:
```toml
[workspace.lints.clippy]
pedantic = "warn"
must_use_candidate = "warn"
missing_errors_doc = "warn"
missing_panics_doc = "warn"
```
And a `#![allow(clippy::module_name_repetitions)]` where it's acceptable (type names like `AuditLogWriter` in `audit_log` crate).
