# Feature: bravoguard-sast-filelist

Objective: scan_repo SAST lane passes explicit pre-filtered file lists (not raw dir) so semgrep-core never enumerates hostile trees.
Problem (parent-proven): semgrep-core exits -1 ("Failed to obtain target files") enumerating SEXTUSYT (404 files, media-heavy) — full scan_repo spends entire 300s budget in sast-timeout. Explicit 28 .py files complete in 0.15s core time. Same class as L3 scan_diff fix (explicit files bypass the skip), now for scan_repo.
Why: Full MCP scans throw (transport timeout) on such repos; SAST lane effectively dead there.
Scope: `src/bravoguard/orchestrator.py` (scan_repo SAST file enumeration + chunking), tests, `CHANGELOG.md`. Bandit/secrets/trivy/checkov/oxlint keep dir targets (proven fine).
Constraints: enumerate only rule-language extensions (.py/.pyi/.js/.jsx/.ts/.tsx/.mjs/.cjs — match rules/ languages, document); honor _is_excluded via single matcher; chunk calls (Windows cmdline limits, e.g. ~100 files) sharing the lane budget; merge findings; empty list -> ok/empty no spawn; keep --exclude flags (defense in depth) + timeouts + opengrep fallback identical; argv only.
Authorized scope: Write only BravoGuard-mcp on branch `feature/bravoguard-sast-filelist`. Work-unit commits authorized. Push/PR/merge deferred. No remote. No installs. Never probe %TEMP% with live semgrep (hangs); repo-local or explicit lists only.
Acceptance criteria:
- [x] scan_repo SEXTUSYT completes with sast ok (no timeout) in seconds-to-tens-of-seconds — re-proof below
- [x] Findings equal-or-superset of dir-scan on well-behaved trees (no loss on normal repos) — unit-covered + live counts compared
- [x] `uv run pytest -q` green + ruff clean — 169 passed, clean
Applicable checks: `uv run pytest -q`, `uv run ruff check src/bravoguard/orchestrator.py tests/`.
TDD: off, runner `uv run pytest -q`.
Delivery: `ask-on-risk`. Forecast <200 lines. Work-unit commits; PR deferred.
Review: RDD on but V2 unavailable, functional + spot check only.

## Tasks
- [x] S1 (delegated direct — writer trigger: 2+ files): file-list SAST for scan_repo + tests. DONE ses_f12d820eeffeTGsZ1HhGJrSDhK, 169 passed. Explicit SAST extensions, chunk 100, timeout-partial contract, opengrep parity. Parent spot-check 169 passed ruff clean.
- [x] S2 (parent inline — bounded): spot-check, commit, live SEXTUSYT re-proof (below).

## Progress
- Branch `feature/bravoguard-sast-filelist` from materialize `9fab167`. Base 155 passed.
- Evidence: semgrep-core -1 on SEXTUSYT enumeration (log); explicit 28 files 0.15s core; full scan 302s sast-timeout; bandit 34 delivered despite it.

## Verification evidence
- Per task `<command>: <observed result>`; parent spot-checks one.

## Route declaration
- S1 delegated direct (writer + preparation triggers fired).
- No SDD artifacts.
