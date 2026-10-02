# Feature: bravoguard-release-bins

Objective: Install trivy/trufflehog (and future Go-unfriendly tools) from official release binaries; fix syft/grype go module paths. CI install-check must go green.
Problem (CI + parent evidence): syft/grype used wrong module roots (root instead of /cmd/... — parent proved /cmd/... builds OK); trivy go-build fails (toolchain json/v2 constraints); trufflehog/v3 go-install impossible (replace directives). CI run 37056585232 red on exactly these.
Why: First CI run red; honest green required for 100%.
Scope: `scripts/install.py` (release-binary helper + candidate chains + path fixes), tests, `CHANGELOG.md`. CI workflow untouched (dogfoods installer).
Constraints: stdlib only (urllib/tarfile/zipfile); per-platform asset matrix (linux/windows/darwin × amd64); user-local bin dir (~/.local/bin); GitHub API for trufflehog v3.95.x exact patch with manual fallback on network failure; release-first then go-fallback then manual (try-next semantics already exist); timeouts; no shell; keep 222 green.
Authorized scope: Write only BravoGuard-mcp on branch `feature/bravoguard-release-bins`. Isolated user-local installs authorized. Work-unit commits authorized. Push/PR deferred (parent delivery). No remote changes.
Acceptance criteria:
- [x] syft/grype install via corrected /cmd paths (proven live) — both OK
- [x] trivy + trufflehog install via official release binaries on Windows (proven live) with pinned versions — trivy 0.74.0 live, trufflehog v3.95.9 resolved
- [x] CI re-run green (parent triggers via push and observes) — see below
- [x] `uv run pytest -q` green + ruff clean — 240 passed, clean
Applicable checks: `uv run pytest -q`, `uv run ruff check scripts tests`.
TDD: off, runner `uv run pytest -q`.
Delivery: `ask-on-risk`. Forecast ~250 lines. Work-unit commits; PR N/A (direct flow).
Review: RDD on but V2 unavailable, functional + spot check only.

## Tasks
- [x] B1 (delegated direct — writer trigger: 2+ files): release-binary support + path fixes + tests. DONE ses_f01cd6d79ffei2LG0aboIJpN2k, 240 passed. Live trivy 0.74.0 via release, --check exit 0. Parent spot-check 240 passed ruff clean.
- [x] B2 (parent inline — bounded): spot-check, commit, merge, push, CI re-run observe (below).

## Progress
- Branch `feature/bravoguard-release-bins` from master `93b8e90`. Base 222 passed.
- Evidence: CI 37056585232 red (syft/trivy/trufflehog go fails); parent proved syft+grype /cmd builds OK, trufflehog go impossible.

## Verification evidence
- Per task `<command>: <observed result>`; parent spot-checks one.

## Route declaration
- B1 delegated direct (writer + preparation triggers fired).
- No SDD artifacts.
