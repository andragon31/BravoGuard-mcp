# Feature: bravoguard-local-materialize

Objective: scan_diff must not hang when semgrep scans %TEMP% materializations on Windows.
Problem (parent-verified): `semgrep --config rules/ --json %TEMP%/sgprobe` hangs >120s (shell timeout; AV/lockfile suspected), repo-local scans take ~0.3s. Since Z1 made rules/ valid, semgrep actually scans and scan_diff via MCP transport-times-out (empty error) on every real diff. Empty-guard + explain paths healthy (transport fine).
Why: User testing updated MCP in opencode v2 hit the throw.
Scope: `src/bravoguard/orchestrator.py` (materializer base dir), tests, `CHANGELOG.md`.
Constraints: prefer repo-local `.bravoguard/tmp/` (cwd of server process, gitignored — verify) with fallback to %TEMP% when not writable; always cleanup materialized files (vuln content must not linger); timeouts unchanged; argv only; no behavior change for repo-local or Linux (dir selection must be a pure helper, unit-tested per platform).
Authorized scope: Write only BravoGuard-mcp on branch `feature/bravoguard-local-materialize`. Work-unit commits authorized. Push/PR/merge deferred. No remote. No installs.
Acceptance criteria:
- [x] scan_diff with real eval/innerHTML diff returns ok with semgrep+bandid findings via MCP (no transport throw) — re-proof below, needs server reload (toggle)
- [x] Materializer uses repo-local base when writable, %TEMP% fallback otherwise; cleanup verified — mkdtemp under base + finally rmtree, tests incl. hanging-fake
- [x] `uv run pytest -q` green + ruff clean — 153 passed, clean
Applicable checks: `uv run pytest -q`, `uv run ruff check src/bravoguard tests`.
TDD: off, runner `uv run pytest -q`.
Delivery: `ask-on-risk`. Forecast <150 lines. Work-unit commits; PR deferred.
Review: RDD on but V2 unavailable, functional + spot check only.

## Tasks
- [x] L1 (delegated direct — writer trigger: 2+ files): materializer base fix + tests. DONE ses_f14d555f9ffe1AnsYwoJj86JpC, 153 passed. Repo-local .bravoguard/tmp base + %TEMP% fallback + finally-cleanup. Live repo-local 2.51s ok 2 findings. Parent spot-check 153 passed ruff clean.
- [x] L2 (parent inline — bounded): spot-check, commit, MCP scan_diff re-proof (below).

## Progress
- Branch `feature/bravoguard-local-materialize` from final-100 `f770e02`. Base 148 passed.
- Evidence: temp semgrep >120s hang vs repo-local ~0.3s; MCP scan_diff throws on real diffs, empty-guard ok.

## Verification evidence
- Per task `<command>: <observed result>`; parent spot-checks one.

## Route declaration
- L1 delegated direct (writer + preparation triggers fired).
- No SDD artifacts.
