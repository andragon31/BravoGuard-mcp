# Feature: bravoguard-self-findings

Objective: Fix the two own-code findings from the dogfood self-scan (B108 test password, B310 urlopen scheme).
Problem: Dogfood src+tests scan flagged B108 MEDIUM hardcoded password in tests/test_docker.py:29 and B310 MEDIUM unrestricted urlopen in src/bravoguard/cli.py:96.
Why: User authorized continue after dogfood report.
Scope: `tests/test_docker.py`, `src/bravoguard/cli.py`, related tests, `CHANGELOG.md`. No behavior changes beyond the two fixes.
Constraints: argv only; no secrets in code/tests (use env/fixture/generated); urlopen restricted to http/https with explicit rejection + test; keep 121 green.
Authorized scope: Write only BravoGuard-mcp on branch `feature/bravoguard-self-findings` (stacked on exclude-fix `7e752f9`). Work-unit commits authorized. Push/PR/merge deferred.
Acceptance criteria:
- [x] B108 gone (test intent preserved, no hardcoded secret) — was /tmp literal, now basename gate
- [x] B310 gone (file:/ and custom schemes rejected, http/https work) — allowlist + tests + bandit proof 0 med+
- [x] `uv run pytest -q` green + ruff clean + live self-scan confirms both gone — 123 passed, clean, bandit 18 LOW-only
Applicable checks: `uv run pytest -q`, `uv run ruff check src/bravoguard/cli.py tests/test_docker.py`.
TDD: off, runner `uv run pytest -q`.
Delivery: `ask-on-risk`. Forecast <100 lines. Work-unit commits; PR deferred.
Review: RDD on but V2 unavailable, functional + spot check only.

## Tasks
- [x] F1 (delegated direct — writer trigger: 2 files): B108 + B310 fixes + tests. DONE ses_f151bc19bffekeD1rxx4OXgmDr, 123 passed. B108 was hardcoded /tmp path (not password) -> basename gate; B310 scheme allowlist + audited nosec.
- [x] F2 (parent inline — bounded): spot-check 123 passed ruff clean, bandit 18 findings 0 med+ on both files. Commit below.

## Progress
- Branch `feature/bravoguard-self-findings` from exclude-fix `7e752f9`.
- Pre-fix self-scan: src 8 findings (1 MEDIUM B310), tests 353 (1 MEDIUM B108).

## Verification evidence
- Per task `<command>: <observed result>`; parent spot-checks one.

## Route declaration
- F1 delegated direct (writer + preparation triggers fired).
- No SDD artifacts.
