# BRAVOGuard

[![ci](https://github.com/andragon31/BravoGuard-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/andragon31/BravoGuard-mcp/actions/workflows/ci.yml)

Security-first MCP server for AI-assisted code review and vulnerability triage.

## Vision

BRAVOGuard wraps proven 2026-era scanners behind a small, stable MCP toolset so coding agents get actionable, deduplicated findings mapped to OWASP Top 10:2025 and LLM Top 10:2026 — without learning every scanner CLI.

Two-layer philosophy: fast offline gates at the edge (`scan_diff`), verified deep sweeps on schedule (`scan_repo`).

## Stack (Sep 2026 — verified via Context7 + releases)

| Layer | Tool | Version / Note |
|---|---|---|
| MCP framework | FastMCP | `>=4` — 4.0.0 GA confirmed via Context7 (`/prefecthq/fastmcp`) |
| MCP protocol | MCP Python SDK | `==2.0.0` — v2 renames to `MCPServer`, drops `mcp.server.fastmcp` |
| Python SAST | Semgrep | 1.176 — primary engine |
| Python SAST fallback | Opengrep | v1.26.0 LGPL-2.1 — drop-in for Semgrep relicense (Dec 2024 rules change) |
| Python SAST | Bandit | 1.8.x — 47 AST checks, zero-config pre-commit |
| Python lint/type | Ruff | 0.16.7 confirmed via Context7 (`/astral-sh/ruff`) |
| Python type | ty | beta / `latest` — fast-path only (Context7 `/astral-sh/docs` shows no stable) |
| Python type (CI) | Pyrefly 1.0 / pyright strict | full spec coverage; Pyrefly stable May 2026 |
| Supply chain | pip-audit | 2.10 — first CI gate on `uv.lock`, OSV DB |
| Supply chain | osv-scanner | V2 — second advisory source, lockfile/SBOM |
| Supply chain | GuardDog | latest — malicious PyPI/npm heuristics |
| Supply chain SBOM | Syft | 1.51.1 — generate CycloneDX/SPDX once, rescan many times |
| Container/IaC | Trivy | 0.74 (pinned by SHA) — all-in-one: vuln + `config` + secrets + licenses |
| Container (optional 2nd opinion) | Grype | 0.118.0 — SBOM-first matcher with EPSS/KEV composite risk |
| IaC depth | Checkov | latest — 1000+ policies for Terraform/K8s/Dockerfile |
| Secrets (edge) | Betterleaks | Gitleaks-compatible successor — Gitleaks v8.28 is feature-complete, security patches only |
| Secrets (verify) | TruffleHog | v3.95.x — 800+ detectors, live verification (`--results=verified`) |
| Frontend (via CLI) | Oxlint | 1.65.0 — 50-100x ESLint, 865+ rules, JS plugins alpha |
| Frontend | Biome | 2.4+ (2.2.x indexed, 2.4/2.5 real) confirmed via Context7 (`/biomejs/biome`, `/biomejs/website`) |
| Frontend specialist | ESLint | 10.4.0 — keep shrunk to Hooks/Next/a11y/security/custom rules |
| JS metrics | Knip 5 / madge 8 / jscpd 4 / dependency-cruiser | `jscpd --min-lines 10 --min-tokens 100 threshold 0` |
| Mapping | OWASP Top 10:2025 + LLM Top 10:2026 | versioned JSON, not hardcoded dict — see `src/bravoguard/owasp_map.py` |

> Injection is A05 in 2025 (not A03). A03:2025 is Software Supply Chain Failures. LLM Top 10:2026 published 4 Aug 2026: LLM01 Prompt Injection, LLM02 Sensitive Disclosure, LLM03 Excessive Agency, LLM04 Supply Chain, LLM05 Data/Model Poisoning, LLM06 Unbounded Consumption, LLM07 Misinformation, LLM08 Hidden Context Exposure, LLM09 Weak Vectors/Embeddings, LLM10 Improper Output Handling.

## Quickstart (uv — full install, no silent stubs)

Windows (PowerShell):

```powershell
cd C:/Users/Andragon/Documents/Github/BravoGuard-mcp
uv sync --all-extras
uv run scripts/install.py --install        # dry-run first: lists actions + pins
uv run scripts/install.py --install --yes  # execute user-local installs
uv run scripts/install.py --check          # verify (guarddog warns + skips on Windows)
uv run src/bravoguard/server.py
```

Linux (bash — same installer, apt/brew path):

```bash
cd ~/BravoGuard-mcp
uv sync --all-extras
uv run scripts/install.py --install        # dry-run first: lists actions + pins
uv run scripts/install.py --install --yes  # execute user-local installs
uv run scripts/install.py --check          # verify
```

- `scripts/install.py` is the cross-platform installer: Python CLIs (`semgrep`,
  `bandit`, `guarddog`, `pip-audit`, `ruff`) go isolated via `uv tool install`
  (fallback `pipx install`), never in the project venv; binaries follow
  `tools-manifest.json` pins via winget (fallback choco/scoop/npm/go) on
  Windows and apt/brew/npm/go on Linux. Mutation requires `--yes`; without it
  every run is a dry-run that lists actions. Guarddog skips on Windows with a
  warning (known `nono-py` build failure) unless `--force-guarddog`.
- `scripts/install_external.py` stays the verifier (fail-fast PATH check).
- Linux proof via Docker: `powershell -File docker/run-linux-proof.ps1`
  (Windows) or `bash docker/run-linux-proof.sh` — see `docs/DOCKER_PROOF.md`.

- `uv sync --all-extras` installs core (fastmcp+mcp) + dev. Scanners instalan aislados a propósito: semgrep 1.176 pinea `mcp==1.29` y rompería el venv con `mcp>=2.0.0`, así que van por `pipx install / uv tool install` + binarios en PATH.
- `scripts/install_external.py` verifies Go/JS + Python CLIs pinned in `tools-manifest.json` (trivy, osv-scanner, syft, betterleaks, trufflehog, oxlint, etc.) and fails fast with the fix if anything is missing.
- `--strict` also requires optional tools (opengrep, grype, biome, eslint, knip/madge/jscpd).

Register in OpenCode with `examples/opencode-mcp.jsonc` as a starting point.
Public repo: `https://github.com/Andragon/BravoGuard-mcp` (override with `BRAVO_GITHUB_REPO` env for forks).

## Versions + safe update (public users)

SemVer + GitHub Releases + `CHANGELOG.md`. The server advertises `bravoguard.__version__`; clients never guess.

```bash
bravoguard version --check      # local vs latest GitHub tag
bravoguard doctor               # health: server, tables, rules, tools, cache
bravoguard tools                # pinned vs installed matrix
bravoguard update --check-only  # is there a new release?
bravoguard update --yes         # safe: backup cache -> git pull --ff-only -> uv sync -> doctor
```

Rules: tags `vX.Y.Z`, release notes = what changed + `bravoguard update --yes` reminder. Never force-update; `update` refuses without `--yes` and refuses dirty trees instead of merging.

## Status

Scaffold Phase 1. The five MCP tools (`scan_diff`, `scan_repo`, `osv_lookup`, `owasp_explain`, `suggest_fix`) are stubs with docstrings and `TODO`s. No scanner binaries are invoked yet. See `docs/PRD.md` and `docs/ARCHITECTURE.md`.

Research baseline Sep 2026 is now pinned in docs. Next: Orchestrator + Normalizer + SQLite cache + e2e `scan_diff` fixture.
