# AEGIS Improvement Analysis — Navigation Index

**Analysis date:** 2026-02-23
**Source documentation:** `claudedocs/current_state/`
**Total findings:** 83 (0 critical, 8 high, 22 medium, 53 low)

---

## How to Use This Index

Add this file to your AI assistant context along with `claudedocs/current_state/index.md` for the full project knowledge base. Then ask:

- *"What are the quick wins I can start with today?"* → See `task_list.md` Quick Wins Sprint
- *"Implement TASK-H01 (blocking I/O fix)"* → See `task_list.md` and `safety_improvements.md`
- *"What safety issues need attention?"* → See `safety_improvements.md`
- *"Show me all the high-severity findings"* → See `improvement_summary.md` Top 10 section
- *"Help me plan the type system improvements"* → See `type_system_improvements.md`
- *"What would improve performance most?"* → See `performance_improvements.md`

---

## File Directory

| File | Purpose | Key Content |
|------|---------|-------------|
| `improvement_summary.md` | **START HERE** — Prioritized overview | Top 10 findings, quick wins, phase plan, impact matrix |
| `task_list.md` | Actionable task list | Quick wins sprint, high-priority tasks, medium/low tasks, dependencies |
| `architecture_improvements.md` | Structural issues | God crate, unintegrated features, dead code, crate boundaries |
| `type_system_improvements.md` | Type system issues | Type safety gaps, error types, API ergonomics, newtypes |
| `performance_improvements.md` | Performance issues | Blocking I/O, allocation patterns, async optimization |
| `safety_improvements.md` | Safety and correctness | Blocking async I/O, mutex poisoning, unwrap audit |
| `simplification_improvements.md` | Over-engineering | Dead code, unnecessary abstractions, pipeline DAG |
| `idiom_improvements.md` | Rust conventions | TryFrom, ValueEnum, builder patterns, lint config |
| `testing_improvements.md` | Test coverage | Doc tests, coverage gaps, missing test categories |
| `dependency_improvements.md` | External dependencies | tokio features, chromiumoxide optional, zeroize |

---

## Top Findings Quick Reference

| ID | Title | Severity | Effort | File |
|----|-------|---------|--------|------|
| ARCH-002 | Three unintegrated feature modules | high | medium | architecture_improvements.md |
| SAFETY-001 | Blocking std::fs on Tokio thread | high | medium | safety_improvements.md |
| ARCH-005 | Crawler not wired | high | large | architecture_improvements.md |
| ARCH-001 | Orchestrator god crate | high | large | architecture_improvements.md |
| TYPE-001 | AddFinding uses f64 not Confidence | high | small | type_system_improvements.md |
| SAFETY-002 | std::sync::Mutex poisoning risk | medium | small | safety_improvements.md |
| TEST-001 | Zero doc tests | high | medium | testing_improvements.md |
| ARCH-009 | compliance_mapper string matching | medium | small | architecture_improvements.md |

---

## Quick Wins (21 tasks, ~4-6 days total)

All tasks in the "Quick Wins Sprint" section of `task_list.md`. Key ones:
- Fix `WORKSPACE_CRATE_COUNT = 11` (5 min)
- Replace `std::sync::Mutex` with `parking_lot::Mutex` (30 min)
- Add `#[must_use]` to builder methods (1 hour)
- Configure workspace clippy lints (30 min)
- Add `TryFrom<&str>` for StealthLevel, PersonaId, ReportFormat (2 hours)
- Fix compliance_mapper enum matching (1 hour)

---

## Phased Plan Summary

| Phase | Focus | Effort | Outcome |
|-------|-------|--------|---------|
| Phase 1 | Safety + Quick Wins | 1-2 weeks | No more poisoning risk, correct async I/O, 21 small fixes |
| Phase 2 | Core Type Safety + Feature Wiring | 2-4 weeks | Crawler wired, IdorAnalyzer active, type safety improved |
| Phase 3 | Architecture + Advanced | Ongoing | Orchestrator decomposed, full test coverage |

---

## Analysis Methodology

- **Source depth 2**: All high and critical findings verified by reading actual Rust source files
- **Key sources read**: `pipeline.rs`, `phase_fuzz.rs`, `process_manager.rs`, `scan_config.rs`, `protocol/src/*.rs`, `knowledge-graph/src/graph.rs`
- **grep-verified**: unwrap count (66), expect count (34), tokio::fs usage (0), spawn_blocking usage (0)
- **Not read** (documentation-only): Python hypothesis-engine internals, Docker Tier 2 test specifics, individual fuzzing specialized tester implementations

---

## Example Queries for AI Assistant

```
"Implement TASK-H04: Change GraphOperation::AddFinding::confidence from f64 to Confidence"

"Fix SAFETY-002: Replace std::sync::Mutex with parking_lot::Mutex for interactive session in pipeline.rs"

"Do all the quick wins in Q-01 through Q-10"

"What changes are needed to fix the compliance_mapper string matching issue (ARCH-009)?"

"Show me all the type system improvements and sort by effort"

"What testing improvements should I do alongside the crawler wiring task?"
```
