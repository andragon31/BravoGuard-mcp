# Feature: bravoguard-final-100

Objective: Resolve remaining errors so install --check, doctor, and live detection are fully green (guarddog Windows skip aside, warned not failed).
Problem (parent-verified evidence): `semgrep --validate --config rules/` exits 5 — `rules/frontend/dangerous-html.yaml` invalid YAML line 10 col 47, semgrep loads 0 rules (SAST-semgrep lane blind). install --check still demands binary literally named `betterleaks` though gitleaks v8 fallback is installed and orchestrator accepts it. doctor FAILs on guarddog/Windows instead of WARN (installer already warns). Gitleaks live capture (stdout vs --report-path) unverified.
Why: User asked to resolve errors for 100% functional.
Scope: `rules/frontend/dangerous-html.yaml`, `scripts/install_external.py` (gitleaks satisfies betterleaks), `src/bravoguard/cli.py` (doctor guarddog-win WARN), `src/bravoguard/orchestrator.py` (gitleaks flags only if live probe demands), tests, `CHANGELOG.md`.
Constraints: rule fix must keep rule intent (dangerous-html, CWE-79 x2) + metadata convention (cwe/owasp_2025/fix_hint); checker/doctor stay honest (missing still FAILs on Linux / for other tools); argv only; no secrets.
Authorized scope: Write only BravoGuard-mcp on branch `feature/bravoguard-final-100`. Work-unit commits authorized. Push/PR/merge deferred. No remote. No installs needed (binaries present).
Acceptance criteria:
- [x] `semgrep --validate --config rules/` exit 0 with rules loaded; live seeded scan returns semgrep findings (not just bandit) — 4 rules, innerHTML + JSX fire
- [x] `install.py --check` exit 0 on Windows (guarddog WARN + gitleaks satisfies betterleaks) — install OK
- [x] `doctor` exit 0 on Windows (guarddog WARN only); unchanged strictness on Linux — PASS, linux path mock-tested
- [x] Live secrets proof via gitleaks (finding captured or honest empty with reason) — generic-api-key redacted via report file
- [x] `uv run pytest -q` green + ruff clean — 148 passed, clean
Applicable checks: `uv run pytest -q`, `uv run ruff check rules scripts src tests` (ruff on yaml n/a — validate via semgrep), `semgrep --validate`, install --check, doctor.
TDD: off, runner `uv run pytest -q`.
Delivery: `ask-on-risk`. Forecast <200 lines. Work-unit commits; PR deferred.
Review: RDD on but V2 unavailable, functional + spot check only.

## Tasks
- [x] Z1 (delegated direct — writer trigger: 3+ files): rule YAML fix + checker gitleaks + doctor guarddog-warn + gitleaks live flags + tests. DONE ses_f14f29219ffe9E00aYu55Yz1md, 148 passed. Live: semgrep 4 rules + innerHTML finding, gitleaks generic-api-key redacted.
- [x] Z2 (parent inline — bounded): spot-check validate 0, 148 passed, ruff clean, --check 0 OK, doctor 0 PASS. Commit below.

## Progress
- Branch `feature/bravoguard-final-100` from multi-lane `16c0e8f`. Base 136 passed.
- Evidence: validate exit 5 (yaml line 10:47); --check lists betterleaks; doctor missing guarddog only.

## Verification evidence
- Per task `<command>: <observed result>`; parent spot-checks one.

## Route declaration
- Z1 delegated direct (writer + preparation triggers fired).
- No SDD artifacts.
