# Feature: bravoguard-ci-and-polish

Objective: CI on GitHub + expanded suggest templates + v0.1.0 release.
Problem: Public repo with no CI safety net; suggest_fix specific for ~7 rules, generic for the rest; no tag/release baseline.
Why: User authorized CI first + improve everything possible.
Scope: `.github/workflows/ci.yml` (new), `src/bravoguard/suggest.py` (template table), `tests/test_suggest.py` (+), `README.md` (badges minimal, only if CI green), `CHANGELOG.md`. Release via tag + gh (parent).
Constraints: CI matrix ubuntu-latest (+ windows? keep ubuntu-only first + document; windows runners slower/costlier — decide in workflow, default ubuntu); CI jobs: pytest, ruff, semgrep --validate, install --check (non-strict, honest), docker proof only if daemon available (skip gracefully); templates genuinely useful + CWE-correct, no LLM calls; keep 180 green.
Authorized scope: Write only BravoGuard-mcp on branch `feature/bravoguard-ci-and-polish`. Tag v0.1.0 + push + gh release authorized by user (public repo goal). No other remotes.
Acceptance criteria:
- [ ] CI workflow runs green (validate YAML locally; first real run observed on push)
- [ ] Top bandit rules have specific templates with tests (no generic fallback for covered rules)
- [ ] v0.1.0 tag pushed + GitHub release published + MCP reloaded and smoke-tested
Applicable checks: `uv run pytest -q`, `uv run ruff check src/bravoguard tests`, YAML parse check.
TDD: off, runner `uv run pytest -q`.
Delivery: `ask-on-risk`. Work-unit commits per task; PR N/A (direct to master flow used so far — merge FF at end).
Review: RDD on but V2 unavailable, functional + spot check only.

## Tasks
- [x] P1 (delegated direct — new files): CI workflow + validation. DONE ses_f01dcd45fffe042vFZ30HeS6pM, 76-line workflow, 4 hard gates, badge. Parent verified YAML parses, 4 jobs.
- [x] P2 (delegated direct — writer trigger): suggest template table + tests. DONE ses_f01daae91ffe3GwRjIV9OF8PAZ, 222 passed. 13 templates/20 rules, B104-unknown honest. Parent spot-check 222 passed ruff clean.
- [x] P3 (parent inline — bounded): verify, merge, push, tag, release, MCP reload + smoke.

## Progress
- Branch `feature/bravoguard-ci-and-polish` from master `946fee8`. Base 180 passed, tree clean.

## Verification evidence
- Per task `<command>: <observed result>`; parent spot-checks one.

## Route declaration
- P1+P2 delegated direct sequential (writer triggers; no parallel writers in one worktree).
- No SDD artifacts.
