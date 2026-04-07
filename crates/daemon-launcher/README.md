# AEGIS Autonomous Daemon System

Launches multiple specialized autonomous daemons for high-ROI AEGIS modules.

## Daemon Types

### 1. Ghost Protocol Daemon (`aegis-ghost-protocol-daemon`)
**Purpose**: Implements missing evasion modules  
**ROI**: High (missing modules with significant impact)

#### Worktree Structure
```
/tmp/aegis_agents/ghost_protocol_{id}/
├── config.toml          # Daemon configuration
├── workspace/           # Isolated working directory
│   ├── payloads/        # Generated evasion payloads
│   ├── fingerprints/    # Collected fingerprints
│   └── bypasses/        # Successful bypass artifacts
├── logs/                # Daemon-specific logs
└── state/               # Persistent state storage
```

#### Memory/State Isolation
- Separate process with isolated heap
- Dedicated temporary workspace directory
- No shared memory with other daemons
- Cleanup on termination

#### Goals
- Implement 5 missing evasion modules from ROI analysis
- Achieve 85%+ success rate on target fingerprinting
- Generate 1000+ novel bypass payloads daily
- Maintain <5% false positive rate

#### Monitoring
- Heartbeat every 30 seconds
- Progress metrics via Unix socket
- Resource utilization tracking
- Crash detection and restart

#### Log Analysis
- Success/failure ratios per module
- Payload effectiveness statistics
- Bypass pattern clustering
- Performance bottlenecks

### 2. Cache Poisoning Daemon (`aegis-cache-poisoning-daemon`)
**Purpose**: Implements ROI=78.4 cache poisoning module  
**ROI**: 78.4

#### Worktree Structure
```
/tmp/aegis_agents/cache_poisoning_{id}/
├── config.toml          # Daemon configuration
├── workspace/           # Isolated working directory
│   ├── vectors/         # Poisoning vectors
│   ├── responses/       # Captured responses
│   └── proofs/          # Proof of poisoning artifacts
├── logs/                # Daemon-specific logs
└── state/               # Persistent state storage
```

#### Memory/State Isolation
- Separate process with isolated heap
- Dedicated temporary workspace directory
- No shared memory with other daemons
- Cleanup on termination

#### Goals
- Achieve 90%+ success rate on cache poisoning vectors
- Generate 500+ unique poisoning scenarios daily
- Maintain <2% false positive rate
- Target high-impact cache endpoints

#### Monitoring
- Heartbeat every 30 seconds
- Success metrics via Unix socket
- Resource utilization tracking
- Crash detection and restart

#### Log Analysis
- Vector effectiveness statistics
- Cache hit/miss ratios
- Poisoning duration metrics
- Target impact assessment

### 3. Schema-Grammar Pipeline Daemon (`aegis-schema-grammar-daemon`)
**Purpose**: Implements ROI=37.3 cheap compound module  
**ROI**: 37.3

#### Worktree Structure
```
/tmp/aegis_agents/schema_grammar_{id}/
├── config.toml          # Daemon configuration
├── workspace/           # Isolated working directory
│   ├── schemas/         # Inferred API schemas
│   ├── grammars/        # Generated grammar definitions
│   └── fuzz_inputs/     # Generated fuzz inputs
├── logs/                # Daemon-specific logs
└── state/               # Persistent state storage
```

#### Memory/State Isolation
- Separate process with isolated heap
- Dedicated temporary workspace directory
- No shared memory with other daemons
- Cleanup on termination

#### Goals
- Infer 100+ API schemas daily
- Generate 1000+ grammar-based fuzz inputs
- Achieve 80%+ accuracy in schema inference
- Maintain <100ms average processing time per endpoint

#### Monitoring
- Heartbeat every 30 seconds
- Schema inference metrics via Unix socket
- Resource utilization tracking
- Crash detection and restart

#### Log Analysis
- Schema accuracy statistics
- Grammar complexity metrics
- Fuzz input diversity scores
- Processing time distributions

### 4. HTTP/2 CONTINUATION Flood Daemon (`aegis-h2-continuation-daemon`)
**Purpose**: Implements ROI=52.5 HTTP/2 flood module  
**ROI**: 52.5

#### Worktree Structure
```
/tmp/aegis_agents/http2_flood_{id}/
├── config.toml          # Daemon configuration
├── workspace/           # Isolated working directory
│   ├── frames/          # Generated HTTP/2 frames
│   ├── results/         # Attack results and metrics
│   └── captures/        # Network capture artifacts
├── logs/                # Daemon-specific logs
└── state/               # Persistent state storage
```

#### Memory/State Isolation
- Separate process with isolated heap
- Dedicated temporary workspace directory
- No shared memory with other daemons
- Cleanup on termination

#### Goals
- Achieve 95%+ success rate on HTTP/2 flood attacks
- Generate 10,000+ frames per second
- Maintain <1% connection drop rate
- Target high-impact HTTP/2 endpoints

#### Monitoring
- Heartbeat every 30 seconds
- Performance metrics via Unix socket
- Resource utilization tracking
- Crash detection and restart

#### Log Analysis
- Frame generation rates
- Connection success/failure ratios
- Server response analysis
- Resource consumption patterns

## Usage

### Launch All Daemons
```bash
# Launch all four specialized daemons
cargo run -p aegis-daemon-launcher -- launch-all --work-dir /tmp/aegis_daemons --target http://example.com

# Launch with verbose logging
cargo run -p aegis-daemon-launcher -- launch-all --verbose --work-dir /tmp/aegis_daemons --target http://example.com
```

### Launch Specific Daemon
```bash
# Launch Ghost Protocol daemon
cargo run -p aegis-daemon-launcher -- launch ghost-protocol --work-dir /tmp/ghost_daemon --target http://example.com

# Launch Cache Poisoning daemon
cargo run -p aegis-daemon-launcher -- launch cache-poisoning --work-dir /tmp/cache_daemon --target http://example.com

# Launch Schema-Grammar Pipeline daemon
cargo run -p aegis-daemon-launcher -- launch schema-grammar --work-dir /tmp/schema_daemon --target http://example.com

# Launch HTTP/2 CONTINUATION Flood daemon
cargo run -p aegis-daemon-launcher -- launch h2-continuation --work-dir /tmp/http2_daemon --target http://example.com
```

### Stop All Daemons
```bash
# Stop all running daemons
cargo run -p aegis-daemon-launcher -- stop-all --work-dir /tmp/aegis_daemons
```

## Building

```bash
# Build all daemon binaries
cargo build --workspace

# Build specific daemon
cargo build -p aegis-ghost-protocol-daemon
cargo build -p aegis-cache-poisoning-daemon
cargo build -p aegis-schema-grammar-daemon
cargo build -p aegis-h2-continuation-daemon
cargo build -p aegis-daemon-launcher
```

## Testing

```bash
# Run tests for daemon launcher
cargo test -p aegis-daemon-launcher

# Run tests for all daemon crates
cargo test -p aegis-ghost-protocol-daemon
cargo test -p aegis-cache-poisoning-daemon
cargo test -p aegis-schema-grammar-daemon
cargo test -p aegis-h2-continuation-daemon
```

## Architecture

Each daemon runs as a separate process with:

1. **Isolated Workspace**: Dedicated temporary directory for state and artifacts
2. **Process Isolation**: Separate memory space and process ID
3. **Configuration Management**: Individual TOML configuration files
4. **Logging**: Structured logging with tracing
5. **Monitoring**: Health checks and metrics collection
6. **Lifecycle Management**: Proper startup/shutdown procedures

The daemon launcher coordinates the creation, monitoring, and termination of all specialized daemons.