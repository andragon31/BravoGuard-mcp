"""BRAVOGuard MCP server (Phase 1, T1 orchestrated, T4 OSV real).

Exposes five tools over stdio (FastMCP 4 + MCP SDK 2.0). `scan_diff` and
`scan_repo` fan out to real scanner subprocesses via `bravoguard.orchestrator`
(argv lists, never shell, every call under a wait_for budget); `osv_lookup`
runs the real osv-scanner/pip-audit fetcher cache-first; `suggest_fix`
returns rule-aware templates from `bravoguard.suggest` (no LLM calls).

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
from bravoguard.cache import FindingCache, get_default_cache
from bravoguard.normalizer import FINDING_KEYS
from bravoguard.orchestrator import DEFAULT_TIMEOUT_SECONDS, DIFF_TIMEOUT_SECONDS
from bravoguard.osv import fetch_osv
from bravoguard.suggest import suggest_for_finding

# Re-exported for backwards compatibility (single source: normalizer).
assert orchestrator.FINDING_KEYS == FINDING_KEYS
SEMGREP_ENGINE = orchestrator.SEMGREP_ENGINE
OPENGREP_FALLBACK = orchestrator.OPENGREP_FALLBACK

mcp = FastMCP("bravoguard")

# Cache config surface: override with BRAVO_CACHE_PATH; tests pass :memory:.
CACHE_CONFIG = {"env_var": "BRAVO_CACHE_PATH", "default": ".bravoguard/cache.db"}


def _scan_cache() -> FindingCache:
    return get_default_cache()


@mcp.tool()
async def scan_diff(diff: str, cache_ttl: float | None = None) -> dict:
    """Scan an inline unified diff for high-signal issues.

    Fans out to `semgrep --config rules/ --json` (or opengrep fallback) +
    bandit + betterleaks stdin via the orchestrator, normalized to FINDING_KEYS.
    Cache-first (SQLite write-through); empty diffs bypass the cache.
    """
    if not diff.strip():
        return {"status": "empty-diff", "findings": []}
    return await asyncio.wait_for(
        orchestrator.scan_diff(diff, timeout=DIFF_TIMEOUT_SECONDS, cache=_scan_cache(), cache_ttl=cache_ttl),
        timeout=DIFF_TIMEOUT_SECONDS,
    )


@mcp.tool()
async def scan_repo(path: str, timeout: int = DEFAULT_TIMEOUT_SECONDS, cache_ttl: float | None = None) -> dict:
    """Scan a local repository checkout and return unified findings.

    Orchestrates semgrep/opengrep + bandit + betterleaks with path validation
    and per-scanner timeouts, normalized to one schema. Cache-first (SQLite
    write-through keyed on directory content digest); guard statuses bypass it.
    """
    if not path.strip():
        return {"status": "empty-path", "findings": []}
    budget = timeout if isinstance(timeout, (int, float)) and timeout > 0 else DEFAULT_TIMEOUT_SECONDS
    return await asyncio.wait_for(
        orchestrator.scan_repo(path, timeout=budget, cache=_scan_cache(), cache_ttl=cache_ttl),
        timeout=budget,
    )


@mcp.tool()
async def osv_lookup(package: str, version: str, cache_ttl: float | None = None) -> dict:
    """Look up known vulnerabilities for a package version via OSV.

    Cache-first (SQLite write-through keyed on package@version): hits return
    ``cached: True`` without spawning a subprocess. Misses run
    ``bravoguard.osv.fetch_osv`` (osv-scanner JSON first, pip-audit fallback);
    with no scanner binary installed the tool reports ``unavailable``.
    """
    if not package.strip():
        return {"status": "empty-package", "vulns": []}
    try:
        return await orchestrator.osv_lookup(
            package,
            version,
            cache=_scan_cache(),
            cache_ttl=cache_ttl,
            fetcher=fetch_osv,
        )
    except orchestrator.ScannerTimeoutError as exc:
        return {"status": "unavailable", "reason": f"scanner timed out: {exc.binary}", "vulns": []}
    except orchestrator.ScannerMissingError as exc:
        return {
            "status": "unavailable",
            "reason": f"scanner not installed: {exc.binary}",
            "vulns": [],
        }
    except orchestrator.OrchestratorError:
        return {"status": "unavailable", "reason": "scanner failed", "vulns": []}


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
    return {"status": "ok", **suggest_for_finding(finding)}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
