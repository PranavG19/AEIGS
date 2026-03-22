# DAEMON STATE

## current
priority: P4 (OPEN_SOURCE_INTEGRATIONS)
task: wire remaining tool wrappers into pipeline phases
status: in-progress

## test-results
- cargo test --workspace: 4487 passed, 0 failed
- cargo clippy --workspace: 0 warnings
- cargo fmt --all --check: 0 diffs
- pytest hypothesis-engine: 511 passed, 0 failed

## active-feature
name: wire-tools-into-pipeline
size: L
status: step 4/7 (IMPLEMENT)
completed: integration test, checker.rs, httpx→phase_fingerprint
next-step: wire gau into phase_recon.rs as passive URL harvest
acceptance: all 6 new wrappers callable from their respective pipeline phases

## P4-progress
All wrappers implemented + tested + registered in selector.rs + lib.rs.
Phase wiring status:
- [x] httpx → phase_fingerprint.rs (tech stack detection, concurrent with defense probing)
- [ ] gau → phase_recon.rs (passive URL harvest)
- [ ] feroxbuster → phase_fingerprint.rs (dir brute-force)
- [ ] trufflehog → phase_recon.rs (secret scanning)
- [ ] dalfox → phase_fuzz.rs (XSS DOM confirmation)
- [ ] amass → phase_recon.rs (subdomain enum)

## handoff
Wire gau into phase_recon.rs. Pattern same as httpx: use spawn_with_timeout
(now pub in runner.rs), construct ExploitContext from target, parse URLs from
GauWrapper output, add discovered URLs as Endpoint nodes in KG. Run on thread
concurrent with existing passive recon.
