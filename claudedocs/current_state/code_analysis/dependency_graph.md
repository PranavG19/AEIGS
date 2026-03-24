# AEGIS Internal Crate Dependency Graph

<!-- metadata: internal crate dependencies, layered architecture, dependency directions -->

## Directed Dependency Graph

Edges represent `crate_a → crate_b` meaning "crate_a depends on crate_b".

```
aegis-orchestrator (bin: aegis)
    ├──[runtime]──► aegis-protocol
    ├──[runtime]──► aegis-knowledge-graph
    ├──[runtime]──► aegis-audit-log
    ├──[runtime]──► aegis-supervisor
    ├──[runtime]──► aegis-passive-recon
    ├──[runtime]──► aegis-enumeration
    ├──[runtime]──► aegis-fuzzing
    ├──[runtime]──► aegis-chain-synthesis
    ├──[runtime]──► aegis-reporting
    ├──[runtime]──► aegis-evasion-engine
    ├──[runtime]──► aegis-crawler
    ├──[dev-only]──► aegis-compliance
    ├──[dev-only]──► aegis-discovery
    └──[dev-only]──► aegis-exploiter

aegis-knowledge-graph
    └──► aegis-protocol

aegis-audit-log
    └──► aegis-protocol

aegis-supervisor
    ├──► aegis-audit-log
    └──► aegis-protocol

aegis-passive-recon
    ├──► aegis-knowledge-graph
    ├──► aegis-protocol
    └──[dev]──► aegis-test-support

aegis-enumeration
    ├──► aegis-knowledge-graph
    ├──► aegis-protocol
    └──[dev]──► aegis-test-support

aegis-fuzzing
    ├──► aegis-knowledge-graph
    └──► aegis-protocol

aegis-chain-synthesis
    ├──► aegis-knowledge-graph
    └──► aegis-protocol

aegis-reporting
    ├──► aegis-fuzzing
    ├──► aegis-knowledge-graph
    └──► aegis-protocol

aegis-evasion-engine
    └──► aegis-protocol

aegis-crawler
    └──► aegis-protocol

aegis-compliance
    └──► aegis-protocol

aegis-discovery
    └──► aegis-protocol

aegis-exploiter
    └──► aegis-protocol

aegis-proxy
    └──► aegis-protocol

aegis-test-support
    ├──► aegis-audit-log
    └──► aegis-protocol

aegis-protocol
    (no internal dependencies — foundation layer)
```

## Layered Architecture View

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 3: Integration                                           │
│  aegis-orchestrator (binary: aegis)                             │
└─────────────────────────────────────────────────────────────────┘
           │ depends on all runtime crates
┌─────────────────────────────────────────────────────────────────┐
│  Layer 2: Capability Crates                                     │
│  passive-recon  enumeration    fuzzing      chain-synthesis     │
│  reporting      evasion-engine crawler      supervisor          │
│  compliance*    discovery*     exploiter*   proxy               │
│  test-support†                                                  │
└─────────────────────────────────────────────────────────────────┘
           │ all depend on knowledge-graph and/or audit-log
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1: Core Storage                                          │
│  aegis-knowledge-graph         aegis-audit-log                  │
└─────────────────────────────────────────────────────────────────┘
           │ all depend on protocol
┌─────────────────────────────────────────────────────────────────┐
│  Layer 0: Foundation (no internal deps)                         │
│  aegis-protocol                                                 │
└─────────────────────────────────────────────────────────────────┘
```

`*` dev-only in orchestrator (not in production binary)
`†` only used as dev-dependency by passive-recon and enumeration

## Crate Coupling Analysis

| Crate | Depends On (internal) | Depended On By (internal) | Coupling |
|-------|----------------------|--------------------------|---------|
| aegis-protocol | — | 16 crates | **Hub** — must stay stable |
| aegis-knowledge-graph | protocol | passive-recon, enumeration, fuzzing, chain-synthesis, reporting | **Core storage** |
| aegis-audit-log | protocol | supervisor, test-support | Medium |
| aegis-supervisor | protocol, audit-log | orchestrator | Low |
| aegis-fuzzing | protocol, knowledge-graph | reporting, orchestrator | Medium |
| aegis-reporting | protocol, knowledge-graph, fuzzing | orchestrator | Low |
| aegis-evasion-engine | protocol | orchestrator | Low |
| aegis-crawler | protocol | orchestrator | Low |
| aegis-passive-recon | protocol, knowledge-graph | orchestrator | Low |
| aegis-enumeration | protocol, knowledge-graph | orchestrator | Low |
| aegis-chain-synthesis | protocol, knowledge-graph | orchestrator | Low |
| aegis-compliance | protocol | orchestrator (dev) | Low |
| aegis-discovery | protocol | orchestrator (dev) | Low |
| aegis-exploiter | protocol | orchestrator (dev) | Low |
| aegis-proxy | protocol | — (standalone) | Isolated |
| aegis-test-support | protocol, audit-log | passive-recon (dev), enumeration (dev) | Test-only |
| aegis-orchestrator | 14 crates | — | **Integration root** |

## Key Design Observations

1. **No circular dependencies** — the graph is a strict DAG with protocol at the root
2. **protocol is the choke point** — changes to public types in protocol require updates across all 17 crates
3. **fuzzing → reporting dependency** — reporting imports fuzzing types (`DefenseProfile`, `WafFingerprint`) because defense-fingerprinting was merged into fuzzing crate
4. **proxy is isolated** — no crate in the workspace depends on proxy; it's a standalone capability
5. **test-support crosses layer boundaries** — depends on audit-log (Layer 1) but serves Layer 2 crates; purely for testing
6. **compliance/discovery/exploiter are dev-only** — these crates exist but are not compiled into the production `aegis` binary; they only appear in integration tests
