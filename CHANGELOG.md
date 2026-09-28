# Changelog

All notable changes to BravoGuard-mcp, following Keep a Changelog + SemVer.
Users: watch GitHub Releases — `bravoguard version --check` and `bravoguard update --check-only` tell you when to upgrade.

## [Unreleased]

### Added
- T1 Orchestrator (`src/bravoguard/orchestrator.py`): real subprocess fan-out for
  `scan_diff`/`scan_repo` — `asyncio.create_subprocess_exec` with argv lists (never
  `shell=True`), `asyncio.wait_for` budgets (DIFF 60s, DEFAULT 120s), semgrep
  `--config rules/ --json` primary with opengrep fallback (same args), bandit JSON,
  betterleaks stdin/path, `scan_repo` path validation (traversal rejected), minimal
  normalization to `FINDING_KEYS`, secrets never propagated into findings or errors.
  `server.py` delegates to it; `_run_with_timeout` placeholder removed.
- T2 Normalizer (`src/bravoguard/normalizer.py`, single source for `FINDING_KEYS`):
  extended schema with `epss, kev, reachability_note` (10 keys),
  one parser per scanner (semgrep/opengrep JSON, bandit JSON, betterleaks JSON
  with Secret/Match redaction and CWE-798 default), dedup on
  `rule_id+path+line+message hash` (first wins), risk sort
  (KEV first, then EPSS desc). `orchestrator.py` re-exports the
  parsers and applies dedup plus sort in `_collect`; `server.py` re-exports
  `FINDING_KEYS` from the normalizer.

## [0.1.0] — skeleton
- FastMCP 4 + MCP SDK 2 stdio server with 5 stub tools.
- Corrected OWASP 2025 mapping (A05 injection) + versioned `owasp_2025.json` / `llm_2026.json`.
- `bravoguard` CLI: `version`, `doctor`, `tools`, `update` (safe: backup cache + `--ff-only` + verify).
- `tools-manifest.json` pins + `scripts/install_external.py` fail-fast verifier.
- Ruff 0.16.7, hatchling wheel includes JSON, pytest `pythonpath=["src"]`.
