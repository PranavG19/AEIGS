# DAEMON STATE

## current
priority: P4 (OPEN_SOURCE_INTEGRATIONS)
task: wire tool wrappers into pipeline phases
status: in-progress

## test-results
- cargo test --workspace: 4485 passed, 0 failed
- cargo clippy --workspace: 0 warnings
- cargo fmt --all --check: 0 diffs
- pytest hypothesis-engine: 511 passed, 0 failed

## active-feature
name: wire-tools-into-pipeline
size: L
status: step 4/7 (IMPLEMENT)
completed: integration_validation_test updated, checker.rs KNOWN_TOOLS updated
next-step: wire httpx into phase_fingerprint.rs as liveness + tech-stack gate
acceptance: all 6 new wrappers callable from their respective pipeline phases

## P4-progress
All wrappers implemented + tested + registered in selector.rs + lib.rs.
Remaining: wire into pipeline phases:
- [ ] httpx → phase_fingerprint.rs (liveness gate + tech stack)
- [ ] gau → phase_recon.rs (passive URL harvest)
- [ ] feroxbuster → phase_fingerprint.rs (dir brute-force)
- [ ] trufflehog → phase_recon.rs (secret scanning)
- [ ] dalfox → phase_fuzz.rs (XSS DOM confirmation)
- [ ] amass → phase_recon.rs (subdomain enum)

## handoff
Wire httpx into run_fingerprint_phase() in pipeline.rs. Pattern: construct
ExploitContext from ScanContext, create ToolRunner with HttpxWrapper registered,
call run_tool("httpx", &ctx) if available, parse results into KG operations.
Gracefully skip when httpx not installed (is_available() check).
