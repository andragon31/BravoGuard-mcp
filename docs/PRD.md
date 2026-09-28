# BRAVOGuard PRD

## 1. Problem

AI coding agents ship code fast but miss security issues: injection, hardcoded secrets, vulnerable dependencies, and misconfigurations. Existing scanners each speak a different CLI and output format, so agents either ignore them or paste raw, noisy output. There is no small, stable MCP surface that returns deduplicated, OWASP-mapped, fix-oriented findings.

## 2. Users

- **AI coding agents** (primary): call MCP tools from OpenCode/Claude-style harnesses.
- **Solo developers**: run `scan_diff` before committing, `scan_repo` before release.
- **Reviewers**: use `owasp_explain` and `suggest_fix` to triage faster.

## 3. Scope

### Phase 1 — MVP (1 week)

- stdio MCP server on FastMCP 4.0.0 + MCP SDK 2.0.0 with five tools: `scan_diff`, `scan_repo`, `osv_lookup`, `owasp_explain`, `suggest_fix`.
- Subprocess orchestration with timeouts: Semgrep 1.176 (with Opengrep v1.26 fallback, same JSON/SARIF) + `rules/`, Bandit 1.8.x, Betterleaks (Gitleaks v8.28-compatible) for edge, pip-audit 2.10 / osv-scanner V2.
- Unified finding schema (SARIF/JSON normalized to `rule_id`, `cwe`, `path`, `line`, `severity`, `message` + `fix_hint`) + SQLite cache keyed on `content hash + scanner versions + DB UpdatedAt/Built`.
- Ruff 0.16.7 + ty beta (fast-path) in pre-commit; Pyrefly 1.0 / pyright strict in CI for full coverage.
- Exit criteria: `scan_diff` on a seeded vuln returns one CWE-mapped finding; smoke test lists five tools; no binary invoked without timeout.

### Phase 2 — Differentiation (2 weeks)

- Full CWE → OWASP Top 10:2025 (A05 = Injection, A03 = Supply Chain) + LLM Top 10:2026 (published 4 Aug 2026, LLM01 Prompt Injection → LLM10 Improper Output Handling) mapping as versioned JSON; rule-aware `suggest_fix` templates (LLM fallback second).
- Frontend lane via CLI: Oxlint 1.65 (primary, 50-100x ESLint) + ESLint 10.4 shrunk to Hooks/Next/a11y/security, Biome 2.4+ for new projects (lint+format), Knip 5 / madge 8 / jscpd 4 (`--min-lines 10 --min-tokens 100 threshold 0`) for dead code and duplication.
- GuardDog for supply-chain heuristics + Syft 1.51.1 SBOM (CycloneDX/SPDX, generate once / rescan many); Trivy 0.74 (pinned by SHA) primary + Grype 0.118 optional second opinion with EPSS/KEV composite risk; Checkov for IaC depth.
- Secrets two-layer: Betterleaks at edge (fast offline), TruffleHog v3.95.x scheduled (`--results=verified`) for live-credential confirmation.
- Deduplication, EPSS/KEV + reachability prioritization, false-positive notes.

### Phase 3 — Hardening (2–3 weeks)

- Policy gates (block/advise), baseline diffing (`baseline-path`), `redact` support, cached rescans.
- Evals on seeded repos (one fixture per CWE); docs and OpenCode distribution.
- FastMCP 4 production defaults: `cache_ttl/scope`, OpenTelemetry, component versioning, granular auth.

## 4. The five tools

| Tool | Input | Output |
|---|---|---|
| `scan_diff` | unified diff | normalized findings (fast, offline) |
| `scan_repo` | repo path | normalized findings (deep, may call verify layer) |
| `osv_lookup` | package + version | known vulns (cache-first) |
| `owasp_explain` | CWE id | OWASP 2025 / LLM 2026 context + mitigation |
| `suggest_fix` | one finding | minimal template fix suggestion |

## 5. Exit criteria (MVP)

- All five tools listed over MCP stdio.
- `tests/test_server_smoke.py` passes without scanner binaries installed.
- One end-to-end `scan_diff` fixture maps to the corrected OWASP table (A05 for CWE-79/89/78).

## 6. Risks (Sep 2026)

- **Semgrep relicense (Dec 2024)**: maintained rules moved to Semgrep Rules License. Mitigation: Opengrep v1.26 LGPL-2.1 fallback, engine abstraction.
- **Gitleaks**: feature-complete (security patches only), author shifted to Betterleaks. Mitigation: Betterleaks drop-in (same TOML/CLI/SARIF) + TruffleHog verification.
- **Trivy (Mar 2026)**: release pinned by SHA; digest must be re-verified each upgrade or the container lane silently drifts. Record `trivy-db UpdatedAt` + image digest per run.
- **ty**: still beta (no stable per Context7 `/astral-sh/docs`). Mitigation: fast-path only, keep Pyrefly/pyright in CI.
- **MCP SDK 2.0 (Aug 2026)**: renames to `MCPServer`, drops `mcp.server.fastmcp`. Pin and migrate from `<2`.
- **Local model quality**: small local models produce weak fixes; `suggest_fix` stays template-first with LLM fallback second.
