# BRAVOGuard Architecture

## Overview

Single MCP server (`src/bravoguard/server.py`, FastMCP 4.0.0 stdio + MCP SDK 2.0.0) in front of a three-stage pipeline: **Orchestrator → Normalizer → OWASP/CWE Enricher**, backed by a **SQLite cache** and **SBOM store**.

## Components

- **Orchestrator**: validates input, fans out scanner subprocesses with `asyncio.wait_for` timeouts (`DIFF_TIMEOUT_SECONDS=60`, `DEFAULT_TIMEOUT_SECONDS=120`). No scanner runs without a timeout. Engine abstraction: `semgrep --config rules/ --json` with `opengrep` drop-in (same JSON/SARIF).
- **Normalizer**: converts Semgrep/Opengrep/Bandit SARIF-or-JSON, Betterleaks/TruffleHog JSON/SARIF, pip-audit/osv-scanner JSON, Trivy/Grype JSON/SARIF, and frontend CLI JSON (Oxlint/Biome/ESLint, Knip/madge/jscpd) into one finding schema (`rule_id`, `cwe`, `path`, `line`, `severity`, `message`, `fix_hint`, `epss`, `kev`, `reachability_note`). Dedupes by `rule_id + path + line + content hash`.
- **Enricher**: attaches OWASP Top 10:2025 (A05 Injection, A03 Supply Chain — not A03 for injection) and LLM Top 10:2026 (LLM01-LLM10, published 4 Aug 2026) context via versioned JSON (`owasp_2025.json`, `llm_2026.json`) fronted by `owasp_map.py`. Maps to CWE + NIST + MITRE ATLAS refs.
- **Cache (SQLite)**: keys on `content hash + scanner versions + DB UpdatedAt/Built + image digest`. `osv_lookup` and repeat `scan_diff` calls hit cache first. Honors FastMCP 4 `cache_ttl/scope` hints. Syft SBOMs stored once (CycloneDX/SPDX), rescanned by Grype/Trivy as feeds update.
- **Secrets two-layer**: Betterleaks (Gitleaks-compatible, CEL + BPE filtering, offline) at edge for `scan_diff`/pre-commit; TruffleHog (`--results=verified`) scheduled for `scan_repo` history sweeps. Supports `baseline-path`, `redact`, inline allowlists.
- **Rules**: Semgrep/Opengrep seed rules under `rules/` run with `--config rules/`. Portable — same YAML runs on both engines.

## Transport

stdio only in Phase 1. The server starts with `mcp.run()` and speaks MCP over stdin/stdout so OpenCode can spawn it with `uv --directory ... run src/bravoguard/server.py`. FastMCP 4 negotiates best mutual protocol era (modern `2026-07-28` vs legacy `initialize`); Inspector (`mcp[cli]`) for debugging. Production: OpenTelemetry spans (one SERVER span per request), component versioning, granular auth.

## Flow

```text
scan_diff / scan_repo
  -> Orchestrator (validate, fan-out with timeout)
  -> scanners emit SARIF/JSON (semgrep/opengrep, bandit, betterleaks, pip-audit/osv, trivy, oxlint)
  -> Normalizer (one schema, dedupe, EPSS/KEV sort)
  -> Enricher (CWE -> OWASP 2025 + LLM 2026 via versioned JSON)
  -> SQLite cache write (hash + versions + DB dates + digest)
  -> MCP response { findings: [...] }

osv_lookup -> cache? -> osv-scanner/pip-audit JSON -> normalize -> cache -> response
owasp_explain -> owasp_map.explain_cwe (no subprocess, versioned tables)
suggest_fix -> template for finding.rule_id (Phase 2), LLM fallback later
scheduled scan_repo -> + trufflehog --results=verified -> live-credential incidents
```

## Decisions (ADR seed — Sep 2026)

- FastMCP 4.0.0 + MCP Python SDK 2.0.0 (`MCPServer`): stable stdio server with typed tools. Confirmed via Context7 `/prefecthq/fastmcp`.
- Subprocess-first scanners: no native bindings, versions pinned independently (Ruff 0.16.7, Biome 2.4+, Oxlint 1.65, Trivy 0.74, Grype 0.118, Syft 1.51.1).
- Engine abstraction for Semgrep relicense: Opengrep v1.26 fallback.
- Secrets edge + verify: Betterleaks (successor) + TruffleHog (verification).
- Seed OWASP table corrected to 2025 (A05 injection); full 2025 + LLM 2026 in Phase 2 as JSON (YAGNI for code, accuracy for mapping).
- Astral toolchain: `uv + Ruff + ty` fast-path, Pyrefly/pyright in CI for spec completeness.
