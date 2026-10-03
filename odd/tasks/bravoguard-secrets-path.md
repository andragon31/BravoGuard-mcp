# Feature: bravoguard-secrets-path

Objective: Zero failing lanes — scan_diff secrets lane must not report failed when gitleaks is the engine.
Problem: gitleaks v8 (our betterleaks fallback) rejects stdin (`--source -` FTL), so every scan_diff reports errors.betterleaks=failed. User requires nothing failing.
Why: Explicit user request for zero failures.
Scope: `src/bravoguard/orchestrator.py` (scan_diff secrets lane: path-mode on materialized workdir instead of stdin), tests, `CHANGELOG.md`.
Constraints: path-mode works for BOTH engines (betterleaks accepts paths too — verify, else branch by resolved binary with stdin kept for betterleaks-only); files already materialized (zero extra IO); exclude filtering already applied at materialization; empty-materialized -> ok/empty without spawning (keep); timeouts unchanged; no secrets in errors/outputs (redaction preserved).
Authorized scope: Write only BravoGuard-mcp on branch `feature/bravoguard-secrets-path`. Work-unit commits authorized. Push/PR deferred (parent delivery: merge+push+MCP test).
Acceptance criteria:
- [x] scan_diff with secret-bearing diff returns secret finding with NO errors map (live proven) — generic-api-key HIGH, errors {}
- [x] betterleaks-primary path unaffected (unit-proven with fakes for both engines) — parity tests both engines path-mode
- [x] `uv run pytest -q` green + ruff clean — 279 passed, clean
Applicable checks: `uv run pytest -q`, `uv run ruff check src/bravoguard/orchestrator.py tests/`.
TDD: off, runner `uv run pytest -q`.
Delivery: `ask-on-risk`. Forecast <120 lines. Work-unit commits; PR N/A.
Review: RDD on but V2 unavailable, functional + spot check only.

## Tasks
- [x] D1 (delegated direct — writer trigger: 2 files): path-mode secrets + tests. DONE ses_f00735045ffey2PHHDCpOLKxPF, 279 passed. Live proof: secret finding, errors {}. Parent spot-check 279 passed ruff clean.
- [x] D2 (parent inline — bounded): spot-check, commit, merge, push, MCP reload + live proof (errors absent).

## Progress
- Branch `feature/bravoguard-secrets-path` from master `5bbb252`. Base 276 passed (master tip).
- Evidence: gitleaks stdin FTL (pre-existing); path-mode proven on repo scans (SEXTUSYT errors None).

## Verification evidence
- Per task `<command>: <observed result>`; parent spot-checks one. Live semgrep repo-local only.

## Route declaration
- D1 delegated direct (writer + preparation triggers fired).
- No SDD artifacts.
