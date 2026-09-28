"""BRAVOGuard MCP server (Phase 1, T1 orchestrated).

Exposes five tools over stdio (FastMCP 4 + MCP SDK 2.0). `scan_diff` and
`scan_repo` fan out to real scanner subprocesses via `bravoguard.orchestrator`
(argv lists, never shell, every call under a wait_for budget); `osv_lookup`
and `suggest_fix` stay not-implemented until T4/T5.

Engines (all subprocess-first, pinned independently):
- SAST: semgrep 1.176 (+ rules/) with opengrep v1.26 fallback (same JSON/SARIF)
- Python: bandit 1.8.x; lint/type: ruff 0.16.7 + ty beta (pre-commit), pyrefly/pyright in CI
- Supply chain: pip-audit 2.10 / osv-scanner V2, guarddog + syft SBOM
- Secrets edge: betterleaks (gitleaks-compatible); verify: trufflehog --results=verified
- Container/IaC: trivy 0.74 (+ config), optional grype 0.118 + syft, checkov depth
- Frontend: oxlint 1.65 primary, eslint 10.4 specialist, biome 2.4+ for new projects
"""

import asyncio

from fastmcp import FastMCP

from bravoguard import orchestrator
from bravoguard.orchestrator import DEFAULT_TIMEOUT_SECONDS, DIFF_TIMEOUT_SECONDS

# Re-exported for backwards compatibility (single source: orchestrator).
FINDING_KEYS = orchestrator.FINDING_KEYS
SEMGREP_ENGINE = orchestrator.SEMGREP_ENGINE
OPENGREP_FALLBACK = orchestrator.OPENGREP_FALLBACK

mcp = FastMCP("bravoguard")


@mcp.tool()
async def scan_diff(diff: str) -> dict:
    """Scan an inline unified diff for high-signal issues.

    Fans out to `semgrep --config rules/ --json` (or opengrep fallback) +
    bandit + betterleaks stdin via the orchestrator, normalized to FINDING_KEYS.
    """
    if not diff.strip():
        return {"status": "empty-diff", "findings": []}
    return await asyncio.wait_for(
        orchestrator.scan_diff(diff, timeout=DIFF_TIMEOUT_SECONDS),
        timeout=DIFF_TIMEOUT_SECONDS,
    )


@mcp.tool()
async def scan_repo(path: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> dict:
    """Scan a local repository checkout and return unified findings.

    Orchestrates semgrep/opengrep + bandit + betterleaks with path validation
    and per-scanner timeouts, normalized to one schema.
    """
    if not path.strip():
        return {"status": "empty-path", "findings": []}
    budget = timeout if isinstance(timeout, (int, float)) and timeout > 0 else DEFAULT_TIMEOUT_SECONDS
    return await asyncio.wait_for(
        orchestrator.scan_repo(path, timeout=budget),
        timeout=budget,
    )


@mcp.tool()
async def osv_lookup(package: str, version: str) -> dict:
    """Look up known vulnerabilities for a package version via OSV.

    Phase-1 target: call osv-scanner/pip-audit JSON output, cache in SQLite
    keyed on package@version + DB UpdatedAt.
    """
    if not package.strip():
        return {"status": "empty-package", "vulns": []}
    # Real osv-scanner/pip-audit wiring lands in T4; keep the stub explicit.
    return {"status": "not-implemented", "task": f"osv_lookup:{package}@{version}"}


@mcp.tool()
async def owasp_explain(cwe_id: str) -> dict:
    """Explain a CWE in terms of OWASP Top 10:2025 and LLM Top 10:2026."""
    from bravoguard.owasp_map import explain_cwe

    return explain_cwe(cwe_id)


@mcp.tool()
async def suggest_fix(finding: dict) -> dict:
    """Suggest a minimal fix for one normalized finding.

    Phase-1 target: rule-aware templates by finding.rule_id before any LLM fallback.
    """
    if not finding:
        return {"status": "empty-finding", "suggestion": ""}
    # Rule-aware templates land in T5; keep the stub explicit.
    return {"status": "not-implemented", "task": "suggest_fix"}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
