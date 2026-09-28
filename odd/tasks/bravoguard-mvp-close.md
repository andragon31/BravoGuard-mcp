# Feature: bravoguard-mvp-close

Objective: Close Phase-1 MVP so all five MCP tools return real normalized findings with timeouts, cache, and template fixes.
Problem: 4 of 5 tools return `not-implemented`; no Orchestrator, Normalizer, or SQLite cache exists.
Why: PRD exit criteria requires `scan_diff` on seeded vuln -> 1 CWE-mapped finding; smoke lists five tools; no binary without timeout.
Scope: `src/bravoguard/server.py`, `src/bravoguard/orchestrator.py` (new), `src/bravoguard/normalizer.py` (new), `src/bravoguard/cache.py` (new), `src/bravoguard/suggest.py` (new or templates), `tests/test_*.py`, docs updates alongside behavior. No push/PR/merge overnight.
Constraints: subprocess-first, `create_subprocess_exec` with argv (never `shell=True`), path validation for `scan_repo`, timeouts enforced (`DIFF 60s`, `DEFAULT 120s`), no secrets logged, offline-first with cache-first `osv_lookup`.
Authorized scope: Local repo only `C:\Users\Andragon\Documents\Github\BravoGuard-mcp`, branch `feature/bravoguard-mvp-close`. Work-unit commits on this branch are authorized. Push, PR creation, merge deferred to user morning decision. No remote exec, no SSH, no global config changes.
Acceptance criteria:
- [x] `scan_diff` seeded diff -> >=1 finding with CWE mapped to OWASP A05 (T4 e2e: CWE-95/79 -> A05)
- [x] `tests/test_server_smoke.py` passes without scanner binaries (64 passed total)
- [x] No scanner invoked without timeout (create_subprocess_exec + wait_for DIFF 60/DEFAULT 120)
- [x] `osv_lookup` cache-first, `suggest_fix` template-first
Applicable checks: `uv run pytest -q`, `uv run ruff check src tests`. Parent spot-check re-runs one reported command before delivery.
TDD: mode off, source default (no project TDD config found, user did not enable), runner `uv run pytest -q`. Ordinary functional checks apply.
Delivery strategy: `ask-on-risk` (default). Forecast ~1200 authored lines total, ~200-300 per task (advisory only, not a cap). Work-unit commits on feature branch; PR slicing deferred to morning; slice boundaries recorded below.
Review: RDD on (global on) but OpenCode V2 review transport unavailable, so no reviewer launched overnight. Verification is writer self-verification + parent spot check. Per-task tier/outcome recorded below.

## Tasks
- [x] T1 (delegated direct — writer trigger: 2+ non-trivial files; preparation trigger: reading pyproject + server.py prepares write so belongs to writer): Orchestrator subprocess real — DONE ses_f19952995ffe2X5h1dGzrq4iX1, 10 tests, 16 passed. Parent spot-check: `uv run pytest -q` 16 passed. Commit 8d3996c.
- [x] T2 (delegated direct — writer trigger): Normalizer one schema — DONE ses_f198dc3bbffe4ZNVX3z6XTj7SA, 9 tests, 25 passed total. Parent spot-check: `uv run pytest -q` 25 passed. Commit 7b9a47c.
- [x] T3 (delegated direct — writer trigger): SQLite cache — DONE ses_f198a691effejSHmZvjkoZHJVQ, 14 tests, 39 passed total. Parent spot-check: `uv run pytest -q` 39 passed. Commit d017b42.
- [x] T4 (delegated direct — writer trigger): `osv_lookup` real + e2e `scan_diff` fixture — DONE ses_f1986a3ccffeeFh0RNhHJDcW1h, 13 tests, 52 passed total. Parent spot-check: `uv run pytest -q` 52 passed. Commit cbfb6db.
- [x] T5 (delegated direct — writer trigger): `suggest_fix` templates — DONE ses_f19825af2ffe0EOx45WL9hSou2, 12 tests, 64 passed total. Parent spot-check: `uv run pytest -q` 64 passed, ruff only pre-existing cli.py.

## Progress
- Branch `feature/bravoguard-mvp-close` from `master`. T1 8d3996c, T2 7b9a47c, T3 d017b42, T4 cbfb6db, T5 d459d4e. All 5 tasks implemented sequential foreground, no parallel writers. No push/PR/merge (deferred to morning).

## Verification evidence
- T1 writer: `uv run pytest -q`: 16 passed; ruff scoped clean (base cli.py F401/F541 pre-existing). Parent: 16 passed.
- T2: 25 passed. Parent: 25 passed.
- T3: 39 passed. Parent: 39 passed.
- T4: 52 passed. Parent: 52 passed.
- T5 writer: `uv run pytest -q`: 64 passed; ruff touched files clean. Parent final: 64 passed, full `ruff check src tests` only pre-existing cli.py (3 errors).

## Route declaration
- T1-T5: delegated direct (writer trigger fired; preparation trigger: reading that prepares write belongs to writer).
- No SDD artifacts; file count alone never selects SDD.

## Slice boundaries
- 8d3996c T1 orchestrator (749 ins, 5 files) — slice 1
- 7b9a47c T2 normalizer (424 ins) — slice 1
- d017b42 T3 cache (692 ins) — slice 1
- cbfb6db T4 osv+e2e (675 ins) — slice 1
- d459d4e T5 suggest (225 ins) — slice 1
- PR split deferred to morning; all local on feature/bravoguard-mvp-close, no push.
