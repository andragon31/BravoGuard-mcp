# Feature: bravoguard-supply-rules

Objective: Own supply-chain Semgrep rule pack as the Windows-viable guarddog alternative (no new binaries, no accounts, cross-platform day one).
Problem: guarddog uninstallable on Windows (Rust/C toolchain); researched malcontent rejected (no Windows binary, heavier toolchain, Defender flags it). Supply-chain heuristics lane missing on Windows.
Why: User chose own rule pack after research verdict.
Scope: `rules/supply-chain/*.yaml` (new), tests proving each rule fires, `src/bravoguard/suggest.py` (1-2 templates for new rule IDs, optional if generic suffices — decide), `CHANGELOG.md`, `rules/README.md` (only if convention needs the new dir documented).
Constraints: portable semgrep/opengrep YAML (same engine abstraction); metadata convention mandatory (cwe/owasp_2025/fix_hint); every CWE must resolve non-unknown in our 249-CWE table (else pick a mapped one with justification); rules target install-time/package-context behavior (setup.py/cmdclass/install hooks, socket exfil in packaging files, base64+exec/marshal obfuscation, hardcoded URLs fetching code at install); avoid false-positive mines (narrow patterns, test both fire + no-fire cases); `semgrep --validate` must pass; picked up automatically via existing `--config rules/` (verify no wiring change needed — if wiring IS needed, do it minimally).
Authorized scope: Write only BravoGuard-mcp on branch `feature/bravoguard-supply-rules`. Work-unit commits authorized. Push/PR deferred. No remote. No installs (semgrep present).
Acceptance criteria:
- [x] >=4 supply-chain rules, each with fire + no-fire tests and valid metadata — 4 rules, 14 tests, metadata + OWASP-resolve checked
- [x] `semgrep --validate --config rules/` exit 0 with increased rule count — 8 rules, 0 errors
- [x] Live proof: seeded malicious setup.py returns new rule findings end-to-end via scan path — 3 findings via scan_diff
- [x] `uv run pytest -q` green + ruff clean (ruff on yaml n/a) — 254 passed, clean
Applicable checks: `uv run pytest -q`, semgrep --validate, live seeded proof.
TDD: off, runner `uv run pytest -q`.
Delivery: `ask-on-risk`. Forecast <250 lines. Work-unit commits; PR deferred.
Review: RDD on but V2 unavailable, functional + spot check only.

## Tasks
- [x] G1 (delegated direct — writer trigger: 2+ files): rule pack + tests (+1 suggest template). DONE ses_f01aecc54ffeAN7XYsV94lXdsM, 254 passed. 4 rules, packaging-scoped paths, live end-to-end 3 findings. Parent spot-check 254 passed ruff clean, validate 0.
- [x] G2 (parent inline — bounded): spot-check, commit, merge, push.

## Progress
- Branch `feature/bravoguard-supply-rules` from master `483bdda`. Base 240 passed (master; release-bins merged+pushed).
- Evidence: malcontent research (no win binary, Go+Rust+YARA toolchain, Defender disclaimer); guarddog nono-py no win wheel.

## Verification evidence
- Per task `<command>: <observed result>`; parent spot-checks one. Live semgrep repo-local only (never %TEMP%).

## Route declaration
- G1 delegated direct (writer + preparation triggers fired).
- No SDD artifacts.
