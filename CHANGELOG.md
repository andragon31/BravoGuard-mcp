# Changelog

All notable changes to BravoGuard-mcp, following Keep a Changelog + SemVer.
Users: watch GitHub Releases — `bravoguard version --check` and `bravoguard update --check-only` tell you when to upgrade.

## [Unreleased]

### Added
- H1 supply-plus (`feature/bravoguard-supply-plus`, `src/bravoguard/supply.py` +
  `src/bravoguard/orchestrator.py` + `src/bravoguard/normalizer.py` +
  `src/bravoguard/suggest.py` + `tests/test_supply_plus.py`): Windows
  guarddog alternative, in-scan (no new MCP tool, no binaries). `scan_repo`
  fans out to a pure-Python supply job (bounded walk, never errors, empty
  -> ok/empty): typosquat parses required deps from `requirements*.txt`
  (tolerant lines, comments/flags/URLs skipped) + `pyproject.toml`
  `[project].dependencies` (`optional-dependencies` excluded — extras are
  opt-in; documented) and flags Damerau-distance-1 against a curated
  certain-only top-PyPI list (~150 famous projects, short names omitted —
  `box` vs `tox` collides; transposition included so `reqeusts` fires)
  as `bravoguard-supply-typosquat` (CWE-1357 -> A03, MEDIUM, pin/exact-name
  fix hint); bundled executables (`.exe/.dll/.so/.dylib/.bin`) walked with
  excludes, except bare binary-extension globs (`*.exe` etc.) are lifted
  for this lane only (they keep engines off binaries; listing binaries is
  the lane's purpose — dir/filename excludes like `.venv/` still honored),
  as `bravoguard-supply-bundled-binary` (CWE-506 -> A08, LOW, review-not-
  guilty wording + rebuild/verify-hash hint). Both CWEs verified via
  `explain_cwe`. `scan_diff` untouched (diffs lack dependency context;
  binaries never appear in diffs). Two new suggest templates (pinning for
  typosquat, provenance-review for binaries — both differ materially from
  generic; no new CWE fallbacks). Opengrep installs from the official
  release binary (same asset-matrix pattern as trivy): `RELEASE_REPOS` +
  `RELEASE_ASSETS` entries (bare unversioned binaries —
  `opengrep_manylinux_x86` / `opengrep_windows_x86.exe` /
  `opengrep_osx_arm64`; new bare-binary install branch renames the asset to
  the engine name), release-first chain (go install proven broken upstream:
  malformed `;/hello.yml` path, v1.26.0 + v1.30.1-candidate) with go +
  manual fallback. Manifest stays v1.26.0 — the windows exe ships in the
  v1.26.0 assets (API-verified). Live proof: opengrep 1.26.0 `--version` +
  identical rule fire vs semgrep on a seeded fixture; `scan_repo` flags
  `reqeusts`/`numpi` + bundled `.exe` with the exact refs above.
- G1 supply-chain rule pack (`feature/bravoguard-supply-rules`,
  `rules/supply-chain/*.yaml` + `tests/test_supply_rules.py`): 4 portable
  semgrep/opengrep rules for install-time/package-context malice (Windows
  guarddog alternative, no new binaries). `install-exec` (subprocess/shell
  in setup.py, CWE-506 → A08), `exfil` (socket/requests-post/smtp sends in
  setup.py, CWE-200 → A01, packaging-scoped so apps never flag),
  `obfuscated-payload` (base64/hex/marshal decode-and-execute, CWE-506 →
  A08), `remote-download` (install-time fetch without integrity check,
  CWE-494 → A08). All ERROR, `pattern`/`pattern-either` only, every CWE
  verified against the 249-CWE table. Picked up automatically via the
  existing `--config rules/` dir (no wiring change). One new suggest
  template (`SUPPLY_SUGGESTION`: quarantine/remove/report) keyed to the 4
  rule ids — generic + OWASP ref sufficed otherwise.
- P1 CI (`feature/bravoguard-ci-and-polish`, `.github/workflows/ci.yml`):
  GitHub Actions on push to master + pull_request (ubuntu-latest, per-ref
  cancel-in-progress). Four independent jobs, all hard gates: `test`
  (`uv sync --frozen --all-extras` + `uv run pytest -q`), `lint` (Ruff
  0.16.7 per the README Stack table + `semgrep --validate --config rules/`,
  both isolated via `uv tool`), `install-check` (dogfoods the repo installer
  `--install --yes` for the non-strict core plan, then `--check` must exit 0),
  `docker-proof` (builds `docker/Dockerfile.linux-test` + runs the
  in-container proof, 20min timeout). Ubuntu-only by design; README carries
  the CI badge.
- W1 full OWASP Top 10:2025 table (`feature/bravoguard-owasp-full`,
  `src/bravoguard/owasp_2025.json` + `src/bravoguard/owasp_map.py` +
  `tests/test_owasp_map.py`): `cwe_map` expanded from the 7 seed CWEs to
  the complete official 249 (per-category 40/16/6/32/37/39/36/14/5/24,
  verified 2026-09-30 against https://owasp.org/Top10/2025; see the
  `coverage` provenance field). Seed entries keep exact meaning and the 7
  seed notes are byte-identical; new entries carry no note (loader
  defaults to ""). Loader unknown branch now reports `unknown CWE id`
  (Phase-2 placeholder retired); invalid-format branch unchanged.
  Note: CWE-307 maps to A07 per the official A07 list.
- M1 multi-lane (`feature/bravoguard-multi-lane`, `src/bravoguard/orchestrator.py`
  + `src/bravoguard/normalizer.py` + `tests/test_lanes.py`): `scan_repo` fans
  out to three new lanes alongside SAST/bandit/secrets (post-normalization
  cache reuse unchanged; `scan_diff` stays SAST+secrets — the materializer
  emits Python snippets while these lanes need JS/TS, manifests, or IaC):
  oxlint frontend (`oxlint <target> --format json`, `cmd /c` prefix on win32
  for the `.ps1` shim, native repeatable `--ignore-pattern`, error->MEDIUM /
  warning->LOW, CWE empty), trivy container/IaC (`trivy fs --format json
  --scanners vuln,misconfig` — the `secret` scanner stays off because
  betterleaks owns secrets, native `--skip-dirs`/`--skip-files`, vuln
  severity passthrough capped CRITICAL->HIGH with first `CweIDs` entry,
  misconfig `Resolution` -> fix hint), checkov IaC (`uv tool run --from
  checkov checkov -d <target> -o json --quiet --compact` — the only working
  invocation here since the bare `.cmd` shim throws on import, native
  repeatable `--skip-path` with `fnmatch.translate`d globs, missing
  severity -> MEDIUM, `guideline` URL -> fix hint). Non-applicable targets
  (no JS, no manifests/IaC) return `ok` with empty findings; missing
  binaries degrade to `not-installed` without failing the scan. `cli.py`
  needed no change (`trivy`/`checkov`/`oxlint` already in `CORE_BINARIES`;
  `tools` stays manifest-driven). Notes: trivy downloads its ~118 MB vuln
  DB + checks bundle on first run (slow once, then cached; overruns
  surface honestly as `timeout`); checkov `uv` startup costs seconds
  inside the 120s budget.
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
- P2 suggest templates (`feature/bravoguard-ci-and-polish`,
  `src/bravoguard/suggest.py` + `tests/test_suggest.py`): specific templates
  for the top remaining bandit rules, dual-keyed by `rule_id` + CWE fallback
  (CWEs verified live against bandit 1.9.4 JSON `issue_cwe`; OWASP refs from
  the 249-CWE table): B102 exec CWE-78 -> allowlist dispatch, B104 bind-all
  CWE-605 -> 127.0.0.1 (OWASP unlisted, honestly `unknown`), B105/B106/B107
  CWE-259 -> env var + rotation, B110 CWE-703 -> narrow except + logging,
  B302 marshal + B403 pickle-import CWE-502 -> `json` (distinct import vs
  usage notes), B303/B324 CWE-327 -> SHA-256 + password-hasher note,
  B304/B305/B413 CWE-327 -> AES-GCM/Fernet, B310 CWE-22 -> scheme allow-list
  (same shape as `cli._check_release_url`), B311 CWE-330 -> `secrets`,
  B602 joins the CWE-78 argv family, B607 gets its own CWE-78 partial-path
  template (`shutil.which` + argv), B608 CWE-89 -> parameterized queries.
  B404 (import subprocess) intentionally keeps the generic path — the import
  alone is not a flaw. The generic-fallback test now uses CWE-94 (CWE-89 is
  covered). No LLM calls.
- X1 Installer (`scripts/install.py`, ~200 lines): cross-platform
  Windows + Linux installer driven by `tools-manifest.json` pins.
  `--check` reuses `scripts/install_external.py` check functions (verifier
  unchanged); `--install` dry-runs by default and mutates only with `--yes`;
  `--strict` adds optional tools. Python CLIs install isolated
  (`uv tool install`, fallback `pipx install`), never in the project venv;
  binaries via winget (fallback choco/scoop/npm/go) on Windows and
  apt/brew/npm/go on Linux; every action prints tool + pinned version.
  Guarddog skips on Windows with a warning (known `nono-py` build failure)
  unless `--force-guarddog`. Unit-tested for both platforms with mocks
  (`tests/test_install.py`); README quickstart covers Windows + Linux.
- X2 Docker Linux proof (`docker/Dockerfile.linux-test`, `docker/proof-linux.sh`,
  `docker/run-linux-proof.ps1`/`.sh`): `python:3.11-slim-bookworm` image with
  `uv sync --frozen`, isolated Python CLIs (`semgrep bandit guarddog pip-audit ruff`
  -- guarddog builds on Linux, no Windows skip), Go binaries
  (`osv-scanner`, `betterleaks`/gitleaks fallback, best-effort `opengrep`) and
  `oxlint` via npm, versions from `tools-manifest.json`. In-container proof runs
  `pytest` + `ruff` + `install.py --check` + `bravoguard doctor` + seeded
  `scan_diff` (>=1 real finding) + `osv_lookup`, logging to `/tmp/proof.log`.
  Host runners gate on `docker info` first (exit 2 honest-blocked when the
  daemon is down). Contract-tested without a daemon (`tests/test_docker.py`);
  see `docs/DOCKER_PROOF.md`.
- B1 release binaries (`feature/bravoguard-release-bins`,
  `scripts/install.py` + `tests/test_install.py`): Go-unfriendly tools now
  install from official GitHub release binaries (stdlib
  urllib/tarfile/zipfile only, per-platform asset matrix, single binary
  unpacked into `~/.local/bin` with `chmod +x` on POSIX, `INSTALL_TIMEOUT`
  on downloads). trivy/trufflehog try release first, then the existing go
  candidate, then manual; syft/grype keep their proven go install first
  with the release as fallback (same helper). trufflehog `v3.95.x` resolves
  to the newest exact patch via the GitHub releases API at install time and
  degrades to go/manual offline without crashing. Dry-run prints the new
  chains readably (`release: <tool> <version> from https://...`).

### Fixed
- D1 secrets path-mode (`feature/bravoguard-secrets-path`,
  `src/bravoguard/orchestrator.py` + `tests/test_orchestrator.py`):
  `scan_diff` secrets lane now scans the materialized workdir in path-mode
  instead of stdin — gitleaks v8 rejects `--source -` (its stdin leg is
  `--pipe`), so every `scan_diff` reported `errors.betterleaks=failed`.
  Single path-mode for both engines (files already exist
  post-materialization: zero extra IO; betterleaks accepts dirs too, so no
  per-engine branch). Exclude filtering already applied at materialization;
  empty-materialized returns ok/empty without spawning; timeouts,
  Secret/Match redaction, and the not-installed taxonomy unchanged. Deleted
  `betterleaks_stdin_argv` + `_run_betterleaks_stdin`; `_filter_diff` stays
  (still unit-covered in `tests/test_exclude.py`). Live proof: secret-bearing
  diff returns the finding with no secrets error key.
- C1 own-code cache invalidation (`feature/bravoguard-cache-version`,
  `src/bravoguard/cache.py` + `tests/test_cache.py`): `scanner_fingerprint()`
  now appends a `code:<hex12>` segment — sha256 over the bytes of a fixed
  core-module set (`orchestrator.py`, `normalizer.py`, `server.py`,
  `cache.py`, `osv.py`, `suggest.py`), resolved against the package
  `__file__` (never cwd, no git dependency; missing/unreadable files feed a
  fixed sentinel, never a crash), computed once per process (`lru_cache`).
  `scan_diff`/`scan_repo` (via `make_scan_key`) and `osv_lookup` (via
  `make_osv_key`) all flow through it, so any own-code change busts the
  cache while content/scanner/DB invalidation behaves as before.
- L1 diff-materializer base (`feature/bravoguard-local-materialize`,
  `src/bravoguard/orchestrator.py` + `tests/test_orchestrator.py` +
  `.gitignore`): `scan_diff` materializes under the new `materialize_base()`
  helper — `<cwd>/.bravoguard/tmp/` when writable (server cwd is the repo
  under `uv --directory` spawn; `.bravoguard/` added to `.gitignore`), system
  temp otherwise (same rule on every platform, no branches). Motive
  (parent-verified): semgrep 1.178 on a `%TEMP%` tree hangs >120s while the
  same tree repo-local scans in ~0.3s, so every real `scan_diff`
  transport-timed-out via MCP once Z1 made `rules/` valid. The materialized
  tree is now always removed afterwards, even on scanner error/timeout, so
  finding content never lingers. Exclude filtering, cache keys, timeouts,
  and argv shapes unchanged. Covered by base-selection
  (writable/mkdir-fail/probe-fail), cleanup-on-timeout (hanging fake), and
  repo-local e2e (fakes capture the materialized path) tests.
- Z1 final-100 blockers (`feature/bravoguard-final-100`):
  - `rules/frontend/dangerous-html.yaml`: the bare
    `dangerouslySetInnerHTML={{ __html: ... }}` scalar broke YAML parsing
    (validate exit 5, 0 rules loaded — SAST-semgrep lane blind). The rule
    now quotes a real JSX sink pattern plus the `$EL.innerHTML = $HTML`
    sink under `pattern-either`; still 2 rules, CWE-79 x2, with
    `cwe`/`owasp_2025`/`fix_hint` metadata. Live proof: `el.innerHTML = x`
    and `dangerouslySetInnerHTML={{ __html: ... }}` both fire.
  - `scripts/install_external.py`: `check_binaries` accepts the gitleaks v8
    fallback for `betterleaks` (mirrors the orchestrator R2 fallback), so
    `install.py --check` passes with gitleaks on PATH; strict otherwise.
  - `src/bravoguard/cli.py`: `doctor` demotes a missing `guarddog` to WARN
    on win32 (same wording as the installer: nono-py fails to build on
    Windows; Linux path unaffected) and exits 0 when it is the sole missing
    item; Linux/macOS still FAIL. `tools` shows SKIP for guarddog on win32.
  - `src/bravoguard/orchestrator.py`: the gitleaks fallback leg captures
    findings via an explicit `--report-path` tmpfile (this versionless
    build prints only logs to stdout — verified live; clean scans write
    `[]`). The file is read once then deleted, contents never logged;
    betterleaks primary argv, Secret/Match redaction, and empty-guards
    unchanged. Covered by report-capture, tmpfile-deletion, and
    missing-report-`failed` tests.
- F1 self-findings (`feature/bravoguard-self-findings`,
  `src/bravoguard/cli.py` + `tests/test_docker.py` + `tests/test_cli.py`):
  B108 gone — the docker proof-log gate asserts on the `proof.log` basename
  plus the script's `LOG=` assignment instead of the `/tmp/proof.log`
  literal (container-internal log path, not a secret; contract kept honest).
  B310 gone — `fetch_latest_release` passes its URL through the new
  `_check_release_url` allow-list (`http`/`https` only; `file:`/custom
  schemes raise `ValueError`, no silent fallback) with timeout + error
  handling unchanged; the audited `urlopen` call carries `# nosec: B310`
  (bandit flags the call syntactically and cannot see the prior check).
  Covered by `test_release_url_rejects_non_http_schemes` (file/gopher/ftp
  rejected, http/https pass) and `test_fetch_latest_release_https_proceeds`
  (mocked `urlopen`, https URL + timeout preserved).
- E1 engine-side `exclude` enforcement (`feature/bravoguard-exclude-fix`,
  `src/bravoguard/orchestrator.py` + `tests/test_exclude.py`): `exclude`
  (default `DEFAULT_EXCLUDES`, now including `.venv/`) previously affected
  only the fingerprint/materializer/cache-key while bandit/semgrep/secrets
  scanned the whole target (dogfood: 3242 findings, 2505x B101 from `.venv`
  deps). Now every engine enforces it in both `scan_repo` and `scan_diff`:
  semgrep/opengrep via native repeatable `--exclude=PATTERN` (spelling
  verified against semgrep 1.178 `scan --help`); bandit via native `-x`
  comma list (verified in bandit 1.9.4 `--help`) with pattern translation
  (`frames/` -> `*/frames/*`, bare `skip.py` -> `*/skip.py`, proven live:
  translated `-x` drops `.venv/evil.py` while raw `.venv/` does not);
  secrets (betterleaks/gitleaks have no native path-exclude flag per
  `gitleaks detect --help`) via pre-filter — `scan_diff` filters diff
  chunks by b-side path before stdin, `scan_repo` stages a filtered mirror
  (rel layout preserved, findings paths remapped, lane skipped when empty).
  `_is_excluded` stays the single matcher (fnmatch on rel-posix path, on
  `"/" + rel-posix` so `*/.venv/*` matches top-level `.venv/...`, and on
  basename; trailing `/` = dir prefix) and is now also checked against the
  full `diff --git` b-side path in the materializer. Empty-after-filter
  returns `ok` with empty findings; timeouts, cache keys, and default argv
  shapes are unchanged. Live proof: repo scan of a tmp tree reports B101
  only for `src/ok.py`, zero `.venv` findings.
- R2 secrets-edge fallback (`feature/bravoguard-remaining-100`,
  `src/bravoguard/orchestrator.py` + `src/bravoguard/cli.py` +
  `tests/test_orchestrator.py`): the secrets lane no longer hardcodes the
  `betterleaks` binary — `resolve_secrets_binary()` probes betterleaks-first
  with gitleaks v8 fallback (same try-next-candidate shape as
  semgrep/opengrep; flags identical `detect --no-git --source`). Betterleaks
  stays the primary argv so existing fakes/pins are untouched; gitleaks is
  retried only when it resolves, and a combined `betterleaks/gitleaks`
  not-installed error surfaces only when neither binary runs. The
  `betterleaks` result label and Secret/Match redaction are unchanged.
  `bravoguard doctor`/`tools` accept either name and report the resolved
  engine (`secrets via gitleaks`).
- R1 installer Windows fixes (`feature/bravoguard-remaining-100`,
  `scripts/install.py` + `tests/test_install.py`): osv-scanner go install uses
  `github.com/google/osv-scanner/v2/cmd/osv-scanner@latest` (`@v2` is an
  invalid version query); betterleaks emits a two-step go chain
  (`github.com/gitleaks/betterleaks@latest`, then
  `github.com/zricethezav/gitleaks/v8@latest` fallback); scoop/npm
  candidates are wrapped as `cmd /c ...` on Windows (bare `.cmd` shims fail
  with WinError 2 under CreateProcess; choco/winget stay bare `.exe`);
  `execute_plan` now tries candidates in order until one succeeds
  (RUN/RETRY/OK/FAIL per attempt, FAIL + manual hint only when all fail) so
  fallbacks actually execute. `go_tag("V2")` kept for other tools; osv uses a
  hardcoded `@latest` with an invalid-query comment.
- Linux proof parity (`feature/bravoguard-xplatform-install`): installer dry-run
  test is platform-aware (guarddog `SKIP` asserted on Windows, install plan on
  Linux); `docker/proof-linux.sh` gates `install --check` + `doctor` core-only
  (PASS when semgrep+bandit+guarddog+pip-audit resolve, optionals missing by
  design); ruff clean under both 0.15.14 and 0.16.9 (auto-fixable modernizations
  applied, broad `except` narrowed to realistic failures, intentional
  never-crash guards documented with `noqa`; `EXE002` ignored repo-wide because
  Docker Windows build contexts stamp `+x` on every `COPY`'d file while the git
  index stays `100644`).
- S1 isolated-scanner setup: `tools-manifest.json` note and
  `scripts/install_external.py` fix hint no longer reference the nonexistent
  `uv sync --extra scanners` path — Python CLIs install isolated
  (pipx / `uv tool`), never in the project venv. Verified with semgrep
  1.178.0 + bandit 1.9.4 (`uv tool install`), osv-scanner 2.0.3 + gitleaks
  v8.28.0 fallback (`go install`, GOBIN `~/.local/bin`); guarddog blocked by
  a `nono-py` build failure on Windows (honest partial, evidence in task).
- oxlint no-files false-failure (`feature/bravoguard-multi-lane`, `src/bravoguard/orchestrator.py` + `tests/test_lanes.py`): py-only targets exited 1 with `No files found...` on stdout ahead of a valid empty-diagnostics envelope, which failed JSON parsing and reported `errors={'oxlint': 'failed'}` — the lane now strips a leading non-JSON preamble and lets a parseable envelope win over rc (empty diagnostics -> `ok`/empty; findings unchanged; garbage stdout still `failed`; same output-driven tolerance may later apply to trivy/checkov, out of scope).
- L3 scan_diff SAST gitignore-skip (`feature/bravoguard-local-materialize`, `src/bravoguard/orchestrator.py` + `tests/test_exclude.py`): `scan_diff` passes the explicit materialized file list to semgrep/opengrep instead of the workdir (semgrep skips gitignored `.bravoguard/tmp` trees; explicit files bypass); empty list returns ok/empty without spawning, repo dir-scans unchanged.
- S1 scan_repo SAST file-list (`feature/bravoguard-sast-filelist`, `src/bravoguard/orchestrator.py` + `tests/test_exclude.py`): `scan_repo` passes explicit pre-filtered file lists to semgrep/opengrep instead of the raw dir (semgrep-core exits -1 "Failed to obtain target files" enumerating hostile media-heavy trees; explicit files bypass, same class as the L3 fix). New `_enumerate_sast_files` collects only `SAST_FILE_EXTENSIONS` (`.py/.pyi/.js/.jsx/.ts/.tsx/.mjs/.cjs`, matching `rules/` python + javascript/typescript languages) via the single `_is_excluded` matcher, skipping non-regular entries (`is_file() and not is_symlink()`, `.git` never descended). New `_scan_sast_repo_files` chunks at `SAST_FILES_PER_SCAN` (100) sharing the lane budget evenly, merging chunk `results`/`errors`; empty candidates return ok/empty without spawning. A chunk timeout aborts remaining chunks and keeps findings-so-far with an honest `timeout` error (via `_SastPartialTimeout`, handled in `_collect`). `--exclude` flags stay on every argv (defense in depth), opengrep fallback is per-chunk identical, cache keys unchanged (candidate set is a pure function of target content + excludes, both already digested). `scan_diff` untouched (already explicit files). Two older `scan_repo` assertions updated to expect files instead of the raw dir.
- K1 timeout tree-kill (`feature/bravoguard-tree-kill`, `src/bravoguard/orchestrator.py` + `tests/test_orchestrator.py`): `run_scanner_json` no longer kills only the direct child on timeout (parent-proven: semgrep-core grandchildren survived as CPU-burning orphans). New `_kill_tree` helper runs best-effort before the existing `proc.kill()`/`wait()` fallback: Windows (`os.name == "nt"`) invokes `taskkill.exe /F /T /PID <pid>` via argv (never `shell=True`, all errors suppressed); POSIX kills the process group (`start_new_session=True` at spawn + `os.killpg(pid, SIGKILL)`, suppressed, fallback unchanged). `ScannerTimeoutError` still raised; success/fast-failure paths unchanged. Covered by win32 taskkill-argv, POSIX killpg-shape, and taskkill-missing-fallback fake-proc tests.
- B1 go module roots (`feature/bravoguard-release-bins`, `scripts/install.py`): syft/grype used the repository roots instead of the `/cmd/...` build roots — now `github.com/anchore/syft/cmd/syft` and `github.com/anchore/grype/cmd/grype` (version handling unchanged).

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
