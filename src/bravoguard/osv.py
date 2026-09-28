"""OSV supply-chain lookup for BRAVOGuard (Phase 1, T4).

Subprocess-first fetcher used as the ``fetcher`` hook of
:func:`bravoguard.orchestrator.osv_lookup` (cache-first, write-through).

Strategy: try ``osv-scanner --format json`` first, fall back to
``pip-audit --format=json`` when the primary is missing or fails. Both run
via :func:`bravoguard.orchestrator.run_scanner_json` (argv list, never shell,
bounded by a wait_for budget). Parsed vulns share one shape —
``{id, severity, summary, package, version}`` (plus ``cwe`` when the payload
carries one); :func:`normalize_osv_vulns` maps them to FINDING_KEYS.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from bravoguard.normalizer import make_finding
from bravoguard.orchestrator import (
    OrchestratorError,
    ScannerTimeoutError,
    run_scanner_json,
)

OSV_SCANNER_BIN = "osv-scanner"
PIP_AUDIT_BIN = "pip-audit"
OSV_TIMEOUT_SECONDS = 60

__all__ = [
    "OSV_SCANNER_BIN",
    "OSV_TIMEOUT_SECONDS",
    "PIP_AUDIT_BIN",
    "fetch_osv",
    "normalize_osv_vulns",
    "osv_scanner_argv",
    "parse_osv_scanner",
    "parse_pip_audit",
    "pip_audit_argv",
]


def osv_scanner_argv(package: str, version: str) -> list[str]:
    """Single-package OSV query as JSON."""
    return [OSV_SCANNER_BIN, "--package", package, "--version", version, "--format", "json"]


def pip_audit_argv(requirements_path: str) -> list[str]:
    """Audit a pinned requirements file, JSON output."""
    return [PIP_AUDIT_BIN, "-r", requirements_path, "--format=json"]


def _vuln(
    vuln_id: Any,
    severity: Any,
    summary: Any,
    package: str,
    version: str,
    cwe: str = "",
) -> dict[str, Any]:
    return {
        "id": str(vuln_id or "unknown"),
        "severity": str(severity or "UNKNOWN").upper(),
        "summary": str(summary or ""),
        "package": package,
        "version": version,
        "cwe": cwe,
    }


def _osv_severity(entry: dict[str, Any]) -> str:
    specific = entry.get("database_specific")
    if isinstance(specific, dict) and specific.get("severity"):
        return str(specific["severity"])
    scores = entry.get("severity")
    if isinstance(scores, list) and scores:
        first = scores[0]
        if isinstance(first, dict) and first.get("score"):
            return str(first["score"])
    return "UNKNOWN"


def _osv_cwe(entry: dict[str, Any]) -> str:
    specific = entry.get("database_specific")
    if isinstance(specific, dict):
        cwe_ids = specific.get("cwe_ids") or specific.get("cwe") or []
        if isinstance(cwe_ids, str):
            return cwe_ids
        if isinstance(cwe_ids, list) and cwe_ids:
            return str(cwe_ids[0])
    return ""


def parse_osv_scanner(
    payload: Any, *, fallback_package: str = "", fallback_version: str = ""
) -> list[dict[str, Any]]:
    """Map osv-scanner JSON results to the shared vuln shape."""
    results = payload.get("results", []) if isinstance(payload, dict) else []
    vulns = []
    for result in results:
        if not isinstance(result, dict):
            continue
        for pkg in result.get("packages", []) or []:
            if not isinstance(pkg, dict):
                continue
            info = pkg.get("package", {}) if isinstance(pkg.get("package"), dict) else {}
            name = str(info.get("name") or fallback_package)
            ver = str(info.get("version") or fallback_version)
            for entry in pkg.get("vulnerabilities", []) or []:
                if not isinstance(entry, dict) or not entry.get("id"):
                    continue
                summary = entry.get("summary") or str(entry.get("details", ""))[:200]
                vulns.append(
                    _vuln(entry.get("id"), _osv_severity(entry), summary, name, ver, _osv_cwe(entry))
                )
    return vulns


def parse_pip_audit(
    payload: Any, *, fallback_package: str = "", fallback_version: str = ""
) -> list[dict[str, Any]]:
    """Map pip-audit JSON dependencies to the shared vuln shape."""
    deps = payload.get("dependencies", []) if isinstance(payload, dict) else []
    vulns = []
    for dep in deps:
        if not isinstance(dep, dict):
            continue
        name = str(dep.get("name") or fallback_package)
        ver = str(dep.get("version") or fallback_version)
        for entry in dep.get("vulns", []) or []:
            if not isinstance(entry, dict) or not entry.get("id"):
                continue
            summary = (
                entry.get("summary")
                or entry.get("description")
                or _fix_hint_text(entry)
                or " ".join(str(a) for a in entry.get("aliases", []) or [])
            )
            vulns.append(_vuln(entry.get("id"), entry.get("severity"), summary, name, ver))
    return vulns


def _fix_hint_text(entry: dict[str, Any]) -> str:
    fixed = entry.get("fix_versions", []) or []
    if fixed:
        return f"Fixed in: {', '.join(str(v) for v in fixed)}"
    return ""


async def _run_pip_audit(package: str, version: str, timeout: float) -> list[dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="bravoguard-pipaudit-") as tmp:
        req = Path(tmp) / "requirements.txt"
        req.write_text(f"{package}=={version}\n", encoding="utf-8")
        payload = await run_scanner_json(
            pip_audit_argv(str(req)), input_data=None, timeout=timeout
        )
    return parse_pip_audit(payload, fallback_package=package, fallback_version=version)


async def fetch_osv(
    package: str, version: str, timeout: float = OSV_TIMEOUT_SECONDS
) -> list[dict[str, Any]]:
    """Fetch vulns for one package version: osv-scanner, then pip-audit.

    Falls back to pip-audit when osv-scanner is missing or fails; timeouts
    propagate so callers see an honest error instead of silent ``[]``.
    Empty packages return ``[]`` without spawning a subprocess.
    """
    name = (package or "").strip()
    ver = (version or "").strip()
    if not name:
        return []
    budget = timeout if timeout and timeout > 0 else OSV_TIMEOUT_SECONDS
    try:
        payload = await run_scanner_json(
            osv_scanner_argv(name, ver), input_data=None, timeout=budget
        )
    except ScannerTimeoutError:
        raise
    except OrchestratorError:
        return await _run_pip_audit(name, ver, budget)
    return parse_osv_scanner(payload, fallback_package=name, fallback_version=ver)


def normalize_osv_vulns(
    vulns: list[dict[str, Any]] | None, package: str = "", version: str = ""
) -> list[dict[str, Any]]:
    """Map shared-shape vulns to FINDING_KEYS findings where possible."""
    findings = []
    for vuln in vulns or []:
        if not isinstance(vuln, dict):
            continue
        name = str(vuln.get("package") or package)
        vuln_id = str(vuln.get("id") or "unknown")
        findings.append(
            make_finding(
                vuln_id,
                vuln.get("cwe") or "",
                name,
                0,
                vuln.get("severity"),
                vuln.get("summary") or f"{vuln_id} in {name}@{vuln.get('version') or version}",
                f"Upgrade {name} to a patched release.",
            )
        )
    return findings
