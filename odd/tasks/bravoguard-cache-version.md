# Feature: bravoguard-cache-version

Objective: Scan cache invalidates when our own code changes, so updated MCP never serves pre-fix cached results.
Problem: Cache key = diff/content + scanner versions + DB dates. Own code version absent. Parent trap: first MCP re-proof after L3 returned the pre-L3 cached finding set for the identical diff; only a fresh diff proved the fix.
Why: User authorized the improvement after MCP updated-code proof.
Scope: Fingerprint function (wherever scanner_fingerprint/make_scan_key live: `src/bravoguard/cache.py` and/or `orchestrator.py`), tests, `CHANGELOG.md`. No lane behavior changes.
Constraints: version signal must work on Windows + Linux + Docker + installed copies (no git dependency); cheap (<2ms per scan — hash once, lru_cache); never weaken existing invalidation (content/scanner/DB still bust); no secrets in keys (hashes only, never content); same guarantee for scan_diff + scan_repo + osv paths that share the fingerprint.
Authorized scope: Write only BravoGuard-mcp on branch `feature/bravoguard-cache-version`. Work-unit commits authorized. Push/PR/merge deferred. No remote. No installs.
Acceptance criteria:
- [x] Touching orchestrator.py/normalizer.py (or any fingerprinted module) changes the cache key; identical tree keeps the key (unit-proven) — monkeypatched-bytes tests, stability + sentinel + read-once
- [x] Full `uv run pytest -q` green + ruff clean — 162 passed, clean
- [x] Live two-phase proof: scan -> cached hit -> (simulated code change via monkeypatched source read, NOT real file mutation) -> miss — covered by unit tests by design (no live file mutation)
Applicable checks: `uv run pytest -q`, `uv run ruff check src/bravoguard/cache.py src/bravoguard/orchestrator.py tests/`.
TDD: off, runner `uv run pytest -q`.
Delivery: `ask-on-risk`. Forecast <150 lines. Work-unit commits; PR deferred.
Review: RDD on but V2 unavailable, functional + spot check only.

## Tasks
- [x] C1 (delegated direct — writer trigger: 2+ files): source-hash fingerprint + tests. DONE ses_f14ac8230ffeIndEbDrFOvUXHK, 162 passed. `code:<hex12>` over 6 modules, lru_cache, shared by diff+repo+osv with zero per-path edits. Parent spot-check 162 passed ruff clean.
- [x] C2 (parent inline — bounded): spot-check, commit.

## Progress
- Branch `feature/bravoguard-cache-version` from materialize `9fab167`. Base 155 passed.
- Evidence: MCP re-proof trap (stale hit on identical diff post-L3).

## Verification evidence
- Per task `<command>: <observed result>`; parent spot-checks one. No live file mutation (unit-level proof only, by design).

## Route declaration
- C1 delegated direct (writer + preparation triggers fired).
- No SDD artifacts.
