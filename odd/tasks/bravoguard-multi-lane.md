# Feature: bravoguard-multi-lane

Objective: Wire installed oxlint + trivy + checkov lanes into the orchestrator (they are installed but dead weight).
Problem: Doctor lists them, code ignores them. Env facts (parent-verified): oxlint 1.65.0 (ps1 shim -> cmd /c needed), trivy 0.74.0 exe (direct OK), checkov 3.3.20 works ONLY via `uv tool run --from checkov checkov` (uv .cmd shim broken on Windows, clean reinstall keeps failing). guarddog out of scope (Windows skip stands; Linux real).
Why: User authorized multi-lane after level recommendation.
Scope: `src/bravoguard/orchestrator.py` (3 lanes), `src/bravoguard/normalizer.py` (parsers if needed), `src/bravoguard/server.py`/`cli.py` (probe/wiring only), `tests/test_*.py`, `CHANGELOG.md`.
Constraints: argv only; timeouts enforced; exclude-aware (reuse E1 plumbing); cache via existing post-normalization; errors honest (not-installed preserved); win .ps1/.cmd via cmd /c; checkov via `uv tool run --from`; no secrets logged.
Authorized scope: Write only BravoGuard-mcp on branch `feature/bravoguard-multi-lane` (stacked on self-findings `d9b055c`). Work-unit commits authorized. Push/PR/merge deferred. No remote.
Acceptance criteria:
- [x] scan_repo runs oxlint + trivy + checkov lanes with real binaries (proven live, not fakes) — SEXTUSYT 6 lanes, errors None after M3
- [x] Findings normalized to extended schema with honest severities/CWEs (None where unmappable) — oxlint≤MEDIUM, trivy cap HIGH, CWE only from CweIDs
- [x] `uv run pytest -q` green + ruff clean — 136 passed, clean
Applicable checks: `uv run pytest -q`, `uv run ruff check src/bravoguard tests`.
TDD: off, runner `uv run pytest -q`.
Delivery: `ask-on-risk`. Forecast ~400 lines (advisory). Work-unit commits; PR deferred.
Review: RDD on but V2 unavailable, functional + spot check only.

## Tasks
- [x] M1 (delegated direct — writer trigger: 2+ files): 3 lanes + tests. DONE ses_f15047756ffe5v7hnkFpVtuEj7, 134 passed. Live per-lane proofs + SEXTUSYT 34 findings.
- [x] M2 (parent inline — bounded): spot-check 134 passed ruff clean, commit 1be6abb. Live SEXTUSYT found oxlint false-failure on py-only repos (fixed next).
- [x] M3 (delegated direct — writer trigger: 2 files): oxlint no-files envelope-wins fix + 2 tests. DONE ses_f14faf6adffegSFp4qNs8FY57P, 136 passed. Live SEXTUSYT errors None after fix. Parent spot-check 136 passed ruff clean.

## Progress
- Branch `feature/bravoguard-multi-lane` from self-findings `d9b055c`.
- Env: oxlint 1.65.0, trivy 0.74.0, checkov 3.3.20 (uv-tool-run only). Base 123 passed.

## Verification evidence
- Per task `<command>: <observed result>`; parent spot-checks one.

## Route declaration
- M1 delegated direct (writer + preparation triggers fired).
- No SDD artifacts.
