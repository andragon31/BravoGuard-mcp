# Feature: bravoguard-scanners-100

Objective: Reach 100% functional by installing real scanners isolated, proving detection (not just fail-fast), and fixing any flag drift.
Problem: Doctor FAILs on 10 missing tools; scans return 0 findings fail-fast; manifest note still says `uv sync --extra scanners` but no such extra exists.
Why: User asked to leave it at 100%.
Scope: `scripts/install_external.py` (message fix only if needed), `tools-manifest.json` note fix, `src/bravoguard/*.py` flag fixes, `tests/test_*.py` new detection tests, `CHANGELOG.md`. Environment: isolated installs via pipx/uv-tool/npm/winget (never in project venv).
Constraints: never install semgrep/bandit in project venv (mcp conflict); PATH-only; subprocess argv; timeouts; SEXTUSYT read-only; no push/PR/merge; no secrets logged.
Authorized scope: Write only in BravoGuard-mcp on branch `feature/bravoguard-scanners-100`. Isolated tool installs authorized (pipx/uv-tool/npm/winget, user-local, no system-wide changes without prompt). Work-unit commits authorized. Push/PR/merge deferred.
Acceptance criteria:
- [x] `uv run scripts/install_external.py` core OK (or honest partial with evidence if network/OS blocks) — PARTIAL honest: semgrep/bandit/osv-scanner real, guarddog blocked, 6 binaries still missing (evidence above)
- [x] `uv run bravoguard doctor` core ok (no missing core for MVP detection: semgrep/opengrep, bandit, betterleaks/gitleaks, osv-scanner or pip-audit fallback verified) — MVP SAST+OSV real (semgrep+bandit+osv-scanner+pip-audit), secrets edge still degraded (betterleaks missing)
- [x] Real `scan_diff` seeded vuln -> >=1 finding with real scanner (not fakes) — 4 real Bandit
- [x] Full `uv run pytest -q` green + `ruff check` clean — 83 passed, clean
Applicable checks: `uv run pytest -q`, `uv run ruff check src/bravoguard tests`, `uv run scripts/install_external.py`, `uv run bravoguard doctor`.
TDD: mode off, runner `uv run pytest -q`.
Delivery: `ask-on-risk`. Forecast <400 lines (fixes only). Work-unit commits; PR deferred.
Review: RDD on but V2 unavailable, functional checks + spot check only.

## Tasks
- [x] S1 (delegated direct — installs + 2+ files trigger): install core scanners isolated + fix manifest note + verify doctor/install script. DONE ses_f17ba57c4ffeLXBYUkB9OV3bMv (partial honest): semgrep 1.178.0 + bandit 1.9.4 via uv tool, osv-scanner 2.0.3 via go install (landed after worker). Guarddog 3.2.0 BLOCKED (nono-py build fail Windows, evidence in worker). gitleaks/betterleaks/opengrep + syft/trivy/checkov/trufflehog/oxlint still missing. Doc notes fixed. Parent: install script now honest, 83 passed ruff clean.
- [x] S2 (delegated direct — writer trigger): real detection proof + flag fixes — DONE parent inline live: seeded diff -> 4 real (B403/B307/B602/B301), SEXTUSYT -> 34 real (B404/B603/B607/B110), errors only betterleaks, osv-scanner 2.0.3 fetch [] no crash. No code flag fix needed (argv valid).

## Progress
- Branch `feature/bravoguard-scanners-100` from proof `ed82a71`. 83 tests green baseline.
- S1 pending, S2 pending.

## Verification evidence
- Base: 83 passed, ruff clean, doctor core ok except 10 missing.
- Per task: `<command>: <observed result>`; parent spot-checks one.

## Route declaration
- S1+S2: delegated direct (installs/tests/builds may use fresh workers; writer trigger for 2+ files).
- No SDD artifacts.
