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
- T3 Cache (`src/bravoguard/cache.py` + orchestrator/server wiring): SQLite
  finding cache (default `.bravoguard/cache.db`, `BRAVO_CACHE_PATH` override,
  `:memory:` for tests), key `sha256(content-hash + scanner versions from
  tools-manifest.json + orchestrator engines + DB UpdatedAt/Built + image
  digest + rule versions)`, optional TTL (default no expiry, `cache_ttl`
  forwarded from tools). `scan_diff`/`scan_repo` are cache-first with
  write-through (hits return `cached: True`; empty/invalid guards bypass the
  cache; `scan_repo` keys on a directory content digest so edits invalidate).
  `osv_lookup` is cache-first via `make_osv_key` with a `fetcher` hook left
  for the T4 scanner wiring. Payloads are never logged; cache failures never
  fail a scan. T4 wiring (`src/bravoguard/osv.py` + server delegation):
  subprocess-first `fetch_osv` — `osv-scanner --package/--version --format json`
  first, `pip-audit -r <pinned requirements> --format=json` fallback when the
  primary is missing or fails (timeouts propagate), argv lists via
  `run_scanner_json` (never `shell=True`, 60s budget). Both outputs parse to
  `{id, severity, summary, package, version}` (+ `cwe` when present) with
  `normalize_osv_vulns` mapping to `FINDING_KEYS`; `server.osv_lookup`
  delegates with `fetcher=fetch_osv` (hits return `cached: True` without a
  subprocess; no binary -> `unavailable`). Seeded e2e
  (`tests/test_e2e_scan.py`): eval/pickle/innerHTML diff -> >=1 A05 finding.
- T5 Suggest (`src/bravoguard/suggest.py` + server delegation): template-first
  `suggest_fix` - `rule_id -> template` table (eval/exec CWE-95 ->
  `ast.literal_eval`, pickle/B301 CWE-502 -> `json`, innerHTML CWE-79 ->
  `textContent`/sanitizer, generic-api-key CWE-798 -> env var) with CWE
  fallback and a generic template carrying the `owasp_map` reference; output
  `{suggestion, rule_id, cwe, owasp_ref}` (`status: ok`, empty-finding guard
  preserved). No LLM calls.

## [V3] — venv-proof gap fixes

### Added
- `exclude` param on `scan_repo`/`scan_diff` (orchestrator + server
  passthrough): list of dir/file globs, defaults to `DEFAULT_EXCLUDES`
  (`frames/`, `projects/`, `*.wav`, `*.zip`, media/binary extensions).
  `_dir_fingerprint` and `materialize_diff_files` respect it (`.git` always
  excluded); the normalized list joins the cache key so media churn keeps
  cache hits. Tests in `tests/test_exclude.py`.
- Subprocess argv template in `suggest.py`: B603-B607 plus bravoguard
  equivalents map to a `shell=False` + allowlist + `shlex.quote` template,
  with a CWE-78 fallback (OWASP A05). Tests in `tests/test_suggest.py`.

### Fixed
- Fully-degraded scans (every scanner `not-installed`, 0 findings) are no
  longer cached, so the next call re-probes instead of replaying the miss.
- Cache hits now return stored `errors` alongside findings (SQLite payloads
  are `{findings, errors}` envelopes; legacy list payloads still read back).
- `cli.py` ruff clean: dropped unused `sys` import, fixed 2 placeholder-less
  f-strings.

### Verified
- `betterleaks`/`osv-scanner` argv reviewed against `tools-manifest.json`
  pins (gitleaks v8-style `detect --no-git --source`, osv-scanner V2
  `--package/--version/--format json`); missing binaries surface as
  `not-installed` errors (scans) or `unavailable` (osv_lookup), never a
  crash. Units with fakes in `tests/test_orchestrator.py`/`tests/test_osv.py`.

## [0.1.0] — skeleton
- FastMCP 4 + MCP SDK 2 stdio server with 5 stub tools.
- Corrected OWASP 2025 mapping (A05 injection) + versioned `owasp_2025.json` / `llm_2026.json`.
- `bravoguard` CLI: `version`, `doctor`, `tools`, `update` (safe: backup cache + `--ff-only` + verify).
- `tools-manifest.json` pins + `scripts/install_external.py` fail-fast verifier.
- Ruff 0.16.7, hatchling wheel includes JSON, pytest `pythonpath=["src"]`.
