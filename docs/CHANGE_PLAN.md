# AEGIS Change Plan — Addressing Roundtable Feedback

## 10 Workstreams

### WS1: Evaluation Harness & Benchmarking
### WS2: Safety & Dual-Use Hardening
### WS3: LLM Integration & Feedback Loop
### WS4: Formal Correctness & Graph Validation
### WS5: Architecture & Modularity
### WS6: Adaptive Evasion & Game-Theoretic Strategy
### WS7: Human-Centered Design & Interactivity
### WS8: Data Interoperability & Standards
### WS9: Causal Reasoning & Evidence Standards
### WS10: Documentation & Domain Knowledge Preservation

## Dependency Graph

```
WS1 (Eval Harness) ← independent, highest priority
WS2 (Safety) ← independent, high priority
WS4 (Graph Validation) ← independent
WS5 (Architecture) ← independent, enables WS3 and WS6
WS10 (Documentation) ← independent, can be done anytime
WS3 (LLM Integration) ← depends on WS1 for measuring value
WS6 (Adaptive Evasion) ← depends on WS5.1 (type moves)
WS7 (Human-Centered) ← depends on WS5.3 (certificates linked)
WS8 (Interoperability) ← independent
WS9 (Causal Reasoning) ← depends on WS1
```

## Priority Order

1. WS4 (Graph Validation) — correctness foundation
2. WS2 (Safety) — critical for responsible tool
3. WS5 (Architecture) — enables downstream work
4. WS10 (Documentation) — quick wins
5. WS1 (Eval Harness) — measurement infrastructure
6. WS3 (LLM Integration) — major feature
7. WS9 (Causal Reasoning) — quality improvement
8. WS6 (Adaptive Evasion) — advanced feature
9. WS7 (Human-Centered) — UX improvement
10. WS8 (Interoperability) — standards compliance

## Progress (as of session)

- **1,005 Rust tests passing** (was 935, +70 new)
- **125 Python tests passing** (was 115, +10 new)
- **Zero clippy warnings across all 12 crates**
- **25 of 49 subtasks completed**
- **WS10 fully complete**
- All 10 workstreams have at least one completed subtask
