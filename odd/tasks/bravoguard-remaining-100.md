# Feature: bravoguard-remaining-100

Objective: Fix installer Windows bugs found by real --yes run, retry remaining tools, re-verify to green.
Problem: install.py --install --yes honest partial — checkov OK (new), but 3 installer bugs: osv-scanner bad go path (@v2 invalid), betterleaks wrong module with no fallback execution, scoop/npm bare names fail (WinError 2, .cmd shims need cmd /c). Plus execute_plan tries only first candidate, so fallbacks never run.
Why: User asked to fix any errors and re-prove resolved.
Scope: `scripts/install.py`, `tests/test_install.py`, `CHANGELOG.md` only. Env retries user-local.
Constraints: never project venv; --yes required (already given for this feature); guarddog Windows skip stays; no push/PR/merge.
Authorized scope: Write only BravoGuard-mcp on branch `feature/bravoguard-remaining-100`. Isolated installs user-local. Work-unit commits authorized. Push/PR/merge deferred.
Acceptance criteria:
- [x] Installer bugs fixed with tests (osv path, betterleaks fallback, cmd /c shims, try-next-candidate) — R1 done, --yes exit 0
- [x] Retry --yes improves installed set (gitleaks via go1.26, scoop/choco/npm via cmd) — syft/trivy/trufflehog/oxlint/gitleaks/checkov all OK
- [x] `uv run pytest -q` green + ruff clean + honest --check evidence — 107 passed, clean, live errors None (guarddog sole known skip)
Applicable checks: `uv run pytest -q`, `uv run ruff check scripts tests`, `uv run scripts/install.py --check`.
TDD: off, runner `uv run pytest -q`.
Delivery: `ask-on-risk`. Forecast <200 lines. Work-unit commits; PR deferred.
Review: RDD on but V2 unavailable, functional + spot check only.

## Tasks
- [x] R1 (delegated direct — writer trigger: 2 files): installer fixes + tests. DONE ses_f16e5bc6fffedZtzLDW51uHPuY, 104 passed. Retry --yes exit 0: osv/syft/trivy/checkov/gitleaks-fallback/trufflehog/oxlint all OK.
- [x] R2 (delegated direct — writer trigger: 2 files): gitleaks-binary fallback in orchestrator. DONE ses_f16e01fa7ffe7lw5qfX8YhJEfx, 107 passed. Live: secrets lane errors None, repo 34 findings errors None. Only guarddog missing (known Windows skip).

## Progress
- Branch `feature/bravoguard-remaining-100` from master `31fd41b`. Evidence: --yes run OK semgrep/bandit/pip-audit/ruff/checkov; FAIL osv-SYNTAX/syft/scoop/trivy/scoop/betterleaks-PATH/trufflehog/scoop/oxlint-npm (all WinError2 or bad path except guarddog-skip).
- Env: uv + npm.cmd + go1.26.1 + scoop.cmd present; no pipx/choco/winget.

## Verification evidence
- Pre-fix --yes log: scripts-install.log (untracked? check). Parent spot-checks one command per task.

## Route declaration
- R1 delegated direct (writer trigger fired).
- No SDD artifacts.
