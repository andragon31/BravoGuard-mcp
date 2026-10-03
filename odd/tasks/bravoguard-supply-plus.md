# Feature: bravoguard-supply-plus

Objective: Complete the Windows guarddog alternative (typosquat + bundled-binary detection in-scan) and fix opengrep installs via official release binary.
Problem: Supply pack covers install-hooks/exfil/obfuscation but not typosquatting or bundled executables (guarddog's other two pillars). Opengrep go-install is broken upstream (malformed test path in their repo, proven v1.26.0 + v1.30.1-candidate), but v1.30.0 publishes standalone binaries incl. opengrep_windows_x86.exe (parent-verified via API).
Why: User asked to resolve everything except open-design, including the guarddog alternative for Windows.
Scope: `src/bravoguard/supply.py` (new: typosquat + binexe checks) OR orchestrator integration (writer decides minimal shape), `src/bravoguard/orchestrator.py` (supply job in scan_repo fan-out only — scan_diff untouched: diffs lack dependency context), `scripts/install.py` (opengrep release-binary leg), tests, `CHANGELOG.md`, manifest version ONLY if 1.26.0 lacks the windows asset (evidence-required bump).
Constraints: typosquat list curated certain-only (top famous packages, distance-1/separator heuristics, zero invented names — every entry must be a real top PyPI project); findings use mapped CWEs only (1357/A03 typosquat, 506/A08 bundled bin — verify via explain_cwe); binexe walk honors excludes + skips .venv? No — .venv excluded already by default excludes; pure-Python, fast, no subprocess; opengrep asset matrix like trivy pattern (release-first, go-fallback, manual); keep 254 green.
Authorized scope: Write only BravoGuard-mcp on branch `feature/bravoguard-supply-plus`. Isolated installs authorized (opengrep exe download for live proof). Work-unit commits authorized. Push/PR deferred (parent delivery: merge+push+tag v0.2.0+release+MCP test).
Acceptance criteria:
- [x] scan_repo flags typosquat dep (e.g. reqeusts) + bundled .exe with specific findings (live proven) — reqeusts/numpi MEDIUM + helper.exe LOW via real scan_repo
- [x] opengrep installs via release binary on Windows and fallback lane verified (same-rules fire) — 1.26.0 live + parity identical rule set
- [x] `uv run pytest -q` green + ruff clean — 276 passed, clean
Applicable checks: `uv run pytest -q`, `uv run ruff check src/bravoguard tests scripts`.
TDD: off, runner `uv run pytest -q`.
Delivery: `ask-on-risk`. Forecast ~300 lines. Work-unit commits; PR N/A.
Review: RDD on but V2 unavailable, functional + spot check only.

## Tasks
- [x] H1 (delegated direct — writer trigger: 3+ files): typosquat + binexe lane + opengrep release leg + tests. DONE ses_f00c140c6ffeg7oluhatthCJ6Z, 276 passed. Live: opengrep 1.26.0 + parity + supply findings. Parent spot-check 276 passed ruff clean.
- [x] H2 (parent inline — bounded): spot-check, commit, merge, push, tag v0.2.0, gh release, MCP reload + full test.

## Progress
- Branch `feature/bravoguard-supply-plus` from master `1ed0d25`. Base 254 passed.
- Evidence: opengrep go broken upstream (both versions); v1.30.0 assets include windows exe (API-verified); guarddog still Rust-blocked (re-retried).

## Verification evidence
- Per task `<command>: <observed result>`; parent spot-checks one. Live network downloads allowed for opengrep proof.

## Route declaration
- H1 delegated direct (writer + preparation triggers fired).
- No SDD artifacts.
