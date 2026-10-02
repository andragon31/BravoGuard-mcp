# Feature: bravoguard-owasp-full

Objective: Expand owasp_2025.json from 7 seed CWEs to full official OWASP Top 10:2025 coverage (~249 CWEs) so explain/suggest never return unknown for mapped CWEs.
Problem: Seed map covers 7 CWEs; live dogfood showed CWE-22 -> unknown + generic suggest fallback.
Why: Last functional gap before 100%; parent verified all 10 official mapped-CWE lists today from owasp.org/Top10/2025 (see evidence below).
Scope: `src/bravoguard/owasp_2025.json` (data), `src/bravoguard/owasp_map.py` (unknown message only), tests, `CHANGELOG.md`. No lane changes; suggest templates unchanged (generic fallback stays).
Constraints: exact official ID lists (passed verbatim in delegation prompt); existing 7 entries + notes preserved; notes optional for new entries (loader defaults ""); categories table unchanged; add coverage provenance field; JSON must stay valid + packaged (hatchling includes *.json).
Authorized scope: Write only BravoGuard-mcp on branch `feature/bravoguard-owasp-full`. Work-unit commits authorized. Push/PR deferred (no remote configured).
Acceptance criteria:
- [x] cwe_map covers all official 2025 mapped CWEs with exact per-category counts (40/16/6/32/37/39/36/14/5/24) — 249 total, count-tested
- [x] Every CWE our scanners emit maps non-unknown (bandit set + trivy/osv common + existing 7) — 12-CWE coverage test
- [x] `uv run pytest -q` green + ruff clean + live explain spot checks (CWE-22->A01, CWE-307->A07 corrected, CWE-918->A01) — 180 passed, clean
Applicable checks: `uv run pytest -q`, `uv run ruff check src/bravoguard tests`.
TDD: off, runner `uv run pytest -q`.
Delivery: `ask-on-risk`. Forecast <150 lines data-heavy. Work-unit commits; PR deferred (no remote).
Review: RDD on but V2 unavailable, functional + spot check only.

## Tasks
- [x] W1 (delegated direct — writer trigger: data + code + tests): full table + loader message + tests. DONE ses_f033298e9ffe9RbLSuY77qg4Xt, 180 passed. 249 CWEs exact counts. Correction: CWE-307 is A07 per official (my brief wrongly said A05 — lists rule). Parent spot-check 180 passed ruff clean, live A01/A07/A05/unknown correct.
- [x] W2 (parent inline — bounded): spot-check, commit.

## Progress
- Branch `feature/bravoguard-owasp-full` from master `5d2ddb4`. Base 172 passed.
- Evidence: all 10 lists verified 2026-09-30 from https://owasp.org/Top10/2025/A0X_2025-*/ (official mapped-CWE sections).

## Verification evidence
- Per task `<command>: <observed result>`; parent spot-checks one.

## Route declaration
- W1 delegated direct (writer + preparation triggers fired).
- No SDD artifacts.
