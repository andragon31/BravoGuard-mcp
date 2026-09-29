# Feature: bravoguard-exclude-fix

Objective: Enforce `exclude` in scanner engines so excluded paths (default .venv) are never scanned.
Problem: `exclude` only affects fingerprint/materializer/cache-key; bandit/semgrep/betterleaks run on the whole target. Dogfood proof: scan_repo BravoGuard-mcp returned 3242 findings (2505x B101 from .venv deps like adodbapi) despite `exclude: ["*/.venv/*"]`.
Why: User authorized fix after dogfood self-scan.
Scope: `src/bravoguard/orchestrator.py` (engine invocation), `tests/test_exclude.py` (extend), `CHANGELOG.md`. No other behavior changes.
Constraints: argv only (never shell=True); keep `_is_excluded`/`_normalize_excludes` semantics, document pattern syntax (fnmatch on rel posix); semgrep native --exclude where possible; bandit/secrets via safest mechanism (native flag or pre-filtered file list); timeouts unchanged; no secrets logged.
Authorized scope: Write only BravoGuard-mcp on branch `feature/bravoguard-exclude-fix`. Work-unit commits authorized. Push/PR/merge deferred. No remote.
Acceptance criteria:
- [x] scan_repo with default excludes skips .venv (dogfood re-proof: 3296 -> 363 findings, 0 venv leaks, live via fresh interpreter)
- [x] Explicit `exclude` patterns honored by all three engines (unit-proven with fakes: 14 E1 tests + 7 S1 tests)
- [x] `uv run pytest -q` green + ruff clean (172 passed on tip, clean)
Applicable checks: `uv run pytest -q`, `uv run ruff check src/bravoguard/orchestrator.py tests/test_exclude.py`.
TDD: off, runner `uv run pytest -q`.
Delivery: `ask-on-risk`. Forecast <200 lines. Work-unit commits; PR deferred.
Review: RDD on but V2 unavailable, functional + spot check only.

## Tasks
- [x] E1 (delegated direct — writer trigger: 2+ files): enforce excludes in engines + tests. DONE ses_f1558efacffe5KAZo0liDhk4oFM, 14 tests, 121 passed. Mechanisms: semgrep native --exclude, bandit native -x with dialect translation (proven live), secrets pre-filter + staging mirror with remap. Parent spot-check 121 passed ruff clean.
- [x] E2 (parent inline — bounded): spot-check, commit, live dogfood re-proof via MCP (see evidence below).

## Progress
- Branch `feature/bravoguard-exclude-fix` from remaining-100 `54cae8c`.
- Evidence: orchestrator.py:130 bandit `-r target`, :568-570 str(target) direct; :265-414 exclude plumbing fingerprint-only.

## Verification evidence
- Pre-fix dogfood: repo scan 3242 findings via MCP (B101 x2505 from .venv); src scan 8 findings.
- Per task `<command>: <observed result>`; parent spot-checks one.

## Route declaration
- E1 delegated direct (writer + preparation triggers fired).
- No SDD artifacts.
