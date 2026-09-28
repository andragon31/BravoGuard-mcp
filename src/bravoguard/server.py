"""BRAVOGuard MCP server (Phase 1 skeleton, refined Sep 2026).

Exposes five tools over stdio (FastMCP 4 + MCP SDK 2.0). Scanner subprocess
wiring lands in Phase 1; each tool already carries its timeout budget so
later work only fills in the command builders.

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

DEFAULT_TIMEOUT_SECONDS = 120
DIFF_TIMEOUT_SECONDS = 60

# Engine abstraction — semgrep relicense Dec 2024 makes opengrep the fallback.
SEMGREP_ENGINE = "semgrep"
OPENGREP_FALLBACK = "opengrep"

mcp = FastMCP("bravoguard")

# Unified finding schema (Phase 1 target):
# {rule_id, cwe, path, line, severity, message, fix_hint, epss, kev}
FINDING_KEYS = ("rule_id", "cwe", "path", "line", "severity", "message", "fix_hint")


async def _run_with_timeout(description: str, timeout: float) -> dict:
    """Placeholder runner replaced by real scanner subprocess calls in Phase 1."""
    await asyncio.sleep(0)  # TODO(phase-1): replace with asyncio.create_subprocess_exec + wait_for.
    return {"status": "not-implemented", "task": description}


@mcp.tool()
async def scan_diff(diff: str) -> dict:
    """Scan an inline unified diff for high-signal issues.

    Phase-1 target: pipe diff to `semgrep --config rules/ --json`
    (or opengrep fallback) + betterleaks stdin, normalize to FINDING_KEYS.
    """
    if not diff.strip():
        return {"status": "empty-diff", "findings": []}
    return await asyncio.wait_for(
        _run_with_timeout("scan_diff", DIFF_TIMEOUT_SECONDS),
        timeout=DIFF_TIMEOUT_SECONDS,
    )


@mcp.tool()
async def scan_repo(path: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> dict:
    """Scan a local repository checkout and return unified findings.

    Phase-1 target: orchestrate semgrep/opengrep + bandit + betterleaks,
    normalize to one schema, enrich via owasp_2025.json.
    """
    if not path.strip():
        return {"status": "empty-path", "findings": []}
    return await asyncio.wait_for(
        _run_with_timeout(f"scan_repo:{path}", timeout),
        timeout=timeout,
    )


@mcp.tool()
async def osv_lookup(package: str, version: str) -> dict:
    """Look up known vulnerabilities for a package version via OSV.

    Phase-1 target: call osv-scanner/pip-audit JSON output, cache in SQLite
    keyed on package@version + DB UpdatedAt.
    """
    if not package.strip():
        return {"status": "empty-package", "vulns": []}
    return await asyncio.wait_for(
        _run_with_timeout(f"osv_lookup:{package}@{version}", DEFAULT_TIMEOUT_SECONDS),
        timeout=DEFAULT_TIMEOUT_SECONDS,
    )


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
    return await asyncio.wait_for(
        _run_with_timeout("suggest_fix", DIFF_TIMEOUT_SECONDS),
        timeout=DIFF_TIMEOUT_SECONDS,
    )


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
