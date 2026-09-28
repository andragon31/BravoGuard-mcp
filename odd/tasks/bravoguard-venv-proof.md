# Feature: bravoguard-venv-proof

Objective: Prove BravoGuard works correctly in a clean venv with full tests, plus a real read-only scan of SEXTUSYT, refining details until perfectly functional.
Problem: MVP close has 64 unit tests with fakes, but no clean-venv proof and no real-project scan proof.
Why: User asked for venv + tests + real Python project analysis with fix loop.
Scope: `src/bravoguard/*.py`, `tests/test_*.py`, `CHANGELOG.md` fixes only in BravoGuard-mcp. Target `C:\Users\Andragon\Documents\Github\SEXTUSYT` is READ-ONLY (never write, no commits there). Backups: `laya-mcp/py`, `valhalla-ai/skills/code-map/scripts`.
Constraints: local only, no push/PR/merge, no remote exec/SSH, no secrets logged, subprocess argv only, timeouts enforced, target scans exclude media (`frames/`, `projects/`, binaries).
Authorized scope: Write only in `C:\Users\Andragon\Documents\Github\BravoGuard-mcp` on branch `feature/bravoguard-venv-proof`. Read-only scan of SEXTUSYT. Work-unit commits on proof branch authorized. Push/PR/merge deferred.
Acceptance criteria:
- [x] Clean venv `uv sync` + `uv run pytest -q` 64 passed + scoped ruff clean + `cli doctor/tools` ok (V1: 64 passed, doctor core ok, V3 final 83 passed ruff clean)
- [x] Real `scan_repo SEXTUSYT` returns normalized findings (no crash, no hang, timeouts honored) (V2: ok 0 fail-fast + cache hit, excludes gap fixed in V3)
- [x] `scan_diff` on real SEXTUSYT diff + `owasp_explain` + `suggest_fix` + `osv_lookup` verified (V2: CWE-78->A05, suggest gap fixed, osv 19.1s)
- [x] All gaps fixed, full suite still green (V3: 83 passed, ruff clean)
Applicable checks: `uv run pytest -q`, `uv run ruff check src/bravoguard tests`, `uv run bravoguard doctor`, `uv run bravoguard tools`.
TDD: mode off, source default, runner `uv run pytest -q`.
Delivery strategy: `ask-on-risk`. Forecast <400 lines (fixes only, advisory). Work-unit commits on proof branch; PR deferred.
Review: RDD on (global) but V2 transport unavailable, functional checks + parent spot check only.

## Tasks
- [x] V1 (direct inline — bounded venv/test proof, 1-3 files to verify): clean venv proof — DONE parent inline: `uv sync` exit 0 Python 3.11.9, `pytest` 64 passed, ruff only cli.py pre-existing, doctor core ok (missing binaries expected), tools pip-audit+ruff present.
- [x] V2 (delegated direct — mapping + scan needs 4+ files): real-project scan proof on SEXTUSYT read-only — DONE ses_f1971ba77ffe8OAxZ7YJdONJB0: scan_repo ok 0 findings fail-fast + cache hit, scan_diff ok, CWE-78->A05, suggest generic fallback gap, osv httpx 0 vulns 19.1s. 6 gaps ordered for V3.
- [x] V3 (delegated direct — writer trigger if 2+ files): fix loop — DONE ses_f196e77caffeNJRtnyUeG9xLvJ, 19 new tests, 83 passed total, ruff clean. Parent spot-check: 83 passed, ruff clean.

## Progress
- Branch `feature/bravoguard-venv-proof` from `7dc4633`. Target picked: SEXTUSYT (30 py, subprocess dense, low risk).
- V1 pending, V2 pending, V3 pending.

## Verification evidence
- Base: 64 passed on `feature/bravoguard-mvp-close`, ruff only pre-existing cli.py (3 errors).
- Per task: writer reports `<command>: <observed result>`; parent spot-checks one.

## Route declaration
- V1: direct inline (bounded action, tests/builds allowed inline).
- V2: delegated direct (mapping trigger fired).
- V3: delegated direct (writer trigger if fixes touch 2+ files).
- No SDD artifacts.
