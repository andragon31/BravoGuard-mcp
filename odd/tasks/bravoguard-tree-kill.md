# Feature: bravoguard-tree-kill

Objective: Timeout-kills take down the whole scanner process tree (no CPU-burning orphan grandchildren).
Problem (parent-proven): run_scanner_json kills only the direct child; semgrep-core grandchildren survive — 12 orphans found saturating a 16-CPU box, each grinding drive-wide enumeration. Every timeout then cascades into system-wide flakiness. Related env facts (NOT fixing here): accidental empty C:\.git repo (recommend removal to user), suspected Defender behavior-monitor interference with semgrep (unverifiable without admin).
Why: Follow-up of S1 re-proof investigation; user asked to resolve errors to 100%.
Scope: `src/bravoguard/orchestrator.py` (timeout-kill path in run_scanner_json only), tests, `CHANGELOG.md`.
Constraints: Windows: taskkill /F /T /PID (no shell=True — invoke taskkill.exe directly via argv); POSIX: process-group kill (start_new_session + killpg, fallback plain kill); all inside existing INSTALL_TIMEOUT/timeout budgets; never mask the original TimeoutError (still raise ScannerTimeoutError after best-effort tree kill); unit-testable without live scanners (fake Popen objects; DO NOT run live semgrep in tests — flaky env).
Authorized scope: Write only BravoGuard-mcp on branch `feature/bravoguard-tree-kill`. Work-unit commits authorized. Push/PR/merge deferred. No remote. No installs. No live-semgrep verification (env flaky; pytest/ruff only).
Acceptance criteria:
- [x] Timeout path kills process trees (Windows taskkill /T + POSIX killpg with fallbacks), original error preserved — helper + 3 fake-proc tests
- [x] `uv run pytest -q` green + ruff clean — 172 passed, clean
Applicable checks: `uv run pytest -q`, `uv run ruff check src/bravoguard/orchestrator.py tests/`.
TDD: off, runner `uv run pytest -q`.
Delivery: `ask-on-risk`. Forecast <120 lines. Work-unit commits; PR deferred.
Review: RDD on but V2 unavailable, functional + spot check only.

## Tasks
- [x] K1 (delegated direct — writer trigger: 2 files): tree-kill + tests. DONE ses_f129f88e5ffePUvkG4aXzca2BU, 172 passed. taskkill /T win, killpg posix, error preserved. Parent spot-check 172 passed ruff clean.
- [x] K2 (parent inline — bounded): spot-check, commit.

## Progress
- Branch `feature/bravoguard-tree-kill` from sast-filelist `b6da472`. Base 169 passed.
- Evidence: 12 semgrep-core orphans after timeout-kills; direct-child kill verified insufficient.

## Verification evidence
- Per task `<command>: <observed result>`; parent spot-checks one. No live semgrep (flaky env by design).

## Route declaration
- K1 delegated direct (writer + preparation triggers fired).
- No SDD artifacts.
