# Feature: bravoguard-xplatform-install

Objective: Installer works on Windows AND Linux; venv tests both envs; Docker proves Linux from Windows box.
Problem: install_external.py only checks PATH; manifest note fixed but no real installer; guarddog fails Windows build; Docker daemon down (pipe missing); no Linux proof.
Why: User requires Windows + Linux support with venv + Docker proof.
Scope: `scripts/install.py` (new cross-platform installer), `scripts/install_external.py` (keep as verifier), `docker/Dockerfile.linux-test` + `docker/compose` or run script, `tests/test_install.py` (platform logic mocked), docs + CHANGELOG. Env installs user-local only.
Constraints: never in project venv (mcp conflict); argv only; timeouts; SEXTUSYT read-only if reused; no push/PR/merge; no system-wide changes without explicit flag; guarddog Windows known-bad (honest skip with warning + Linux path).
Authorized scope: Write only BravoGuard-mcp on branch `feature/bravoguard-xplatform-install`. Isolated installs (pipx/uv-tool/npm/go, winget/choco/scoop on Win, apt/brew on Linux) authorized user-local. Docker build/run authorized local only. No remote/SSH.
Acceptance criteria:
- [x] `uv run scripts/install.py --check` passes on Windows with semgrep/bandit/osv-scanner real — PARTIAL honest: SAST+OSV real, 6 binaries + guarddog-win-skip missing (exit 1 with pins)
- [x] Same installer logic unit-tested for Linux paths (mocked platform) + Dockerfile builds when daemon up — 15 installer/docker tests mocked green; Dockerfile unexecuted (daemon down)
- [x] `uv run pytest -q` green + ruff clean — 98 passed, clean
- [x] Linux proof via Docker (or honest blocked with exact start command if daemon stays down) — BLOCKED honest: runner exit 2 with Desktop start command, docs/DOCKER_PROOF.md
Applicable checks: `uv run pytest -q`, `uv run ruff check src/bravoguard tests scripts`, `uv run scripts/install_external.py`, `uv run bravoguard doctor`.
TDD: off, runner `uv run pytest -q`.
Delivery: `ask-on-risk`. Forecast <400 lines. Work-unit commits; PR deferred.
Review: RDD on but V2 unavailable, functional + spot check only.

## Tasks
- [x] X1 (delegated direct — 2+ files): cross-platform installer — DONE ses_f179d3c18ffe4ywDXqMdkq7Iei, 10 tests, 93 passed. Parent spot-check 93 passed. --check honest partial (6 missing expected).
- [x] X2 (delegated direct — 2+ files): Docker Linux proof — DONE ses_f1798f778ffe5gBPExqepTpkLK + parent fix loop (uv-tool loop, osv v2 path, secrets best-effort, COPY docker/, --all-extras): image builds, Linux proof exit 0 all 6 gates PASS.
- [x] X3 (parent inline — bounded verify): dual-env matrix — DONE parent: Windows 98 passed ruff clean; Linux container 0 gates failed (pytest, ruff, core check/doctor, seeded real finding, osv). Linux-only fixes: guarddog test platform-aware, EXE002 ignore + ruff hand-fixes, proof core_gate.

## Progress
- Branch `feature/bravoguard-xplatform-install` from scanners-100 `9c551b4`. Docker daemon started by parent, Linux proof GREEN (exit 0).
- X1+X2+X3 done. Windows 98 passed, Linux 0 gates failed.

## Verification evidence
- Base: 83 passed, ruff clean, semgrep/bandit/osv-scanner real Windows.
- Per task `<command>: <observed result>`; parent spot-checks one.

## Route declaration
- X1+X2 delegated direct (writer trigger); X3 direct inline (bounded verify).
- No SDD artifacts.
