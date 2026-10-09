"""OSV supply-chain lookup for BRAVOGuard (Phase 1, T4; HTTP-first in T9).

HTTP-first fetcher used as the ``fetcher`` hook of
:func:`bravoguard.orchestrator.osv_lookup` (cache-first, write-through).

Strategy: POST ``https://api.osv.dev/v1/query`` via stdlib ``urllib`` first
(free, no auth); on any HTTP failure fall back to ``osv-scanner --format
json``, then to ``pip-audit --format=json`` when the primary is missing or
fails. Binaries run via :func:`bravoguard.orchestrator.run_scanner_json`
(argv list, never shell, bounded by a wait_for budget). Parsed vulns share
one shape — ``{id, severity, summary, package, version}`` (plus ``cwe`` when
the payload carries one); :func:`normalize_osv_vulns` maps them to
FINDING_KEYS.
"""

from __future__ import annotations

import json
import tempfile
import urllib.request
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
OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_HTTP_TIMEOUT_SECONDS = 15

__all__ = [
    "OSV_API_URL",
    "OSV_HTTP_TIMEOUT_SECONDS",
    "OSV_SCANNER_BIN",
    "OSV_TIMEOUT_SECONDS",
    "PIP_AUDIT_BIN",
    "fetch_osv",
    "normalize_osv_vulns",
    "osv_scanner_argv",
    "parse_osv_http",
    "parse_osv_scanner",
    "parse_pip_audit",
    "pip_audit_argv",
]


def osv_scanner_argv(package: str, version: str) -> list[str]:
    """Single-package OSV query as JSON (osv-scanner V2 pin, tools-manifest.json)."""
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


def parse_osv_http(
    payload: Any, *, fallback_package: str = "", fallback_version: str = ""
) -> list[dict[str, Any]]:
    """Map the OSV HTTP ``/v1/query`` response to the shared vuln shape.

    The API answers ``{"vulns": [...]}`` (verified live: entries carry
    ``id`` + ``summary``/``details`` + ``aliases`` + ``severity[]`` +
    ``database_specific{severity, cwe_ids}`` — the same per-entry fields as
    osv-scanner, only without the ``results/packages`` wrapper, and without
    echoing the queried package/version, hence the fallbacks). Severity
    and CWE reuse :func:`_osv_severity` / :func:`_osv_cwe` unchanged.
    """
    entries = payload.get("vulns", []) if isinstance(payload, dict) else []
    vulns = []
    for entry in entries or []:
        if not isinstance(entry, dict) or not entry.get("id"):
            continue
        summary = entry.get("summary") or str(entry.get("details", ""))[:200]
        vulns.append(
            _vuln(
                entry.get("id"),
                _osv_severity(entry),
                summary,
                fallback_package,
                fallback_version,
                _osv_cwe(entry),
            )
        )
    return vulns


def _query_osv_http(package: str, version: str, timeout: float) -> list[dict[str, Any]]:
    """POST one package version to the OSV API; any failure propagates.

    Sends ``ecosystem: PyPI``: this module serves Python packages
    (pip-audit is the fallback), and an ecosystem-less query returns
    version-unfiltered results (verified live: 261 vs 96 vulns for
    django@4.2). Other ecosystems answer ``{}`` (no ``vulns`` key), which
    counts as failure so the caller falls back to the binaries instead of
    trusting a wrong shape.
    """
    body = json.dumps(
        {"package": {"name": package, "ecosystem": "PyPI"}, "version": version}
    ).encode("utf-8")
    request = urllib.request.Request(
        OSV_API_URL,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()
    payload = json.loads(raw.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict) or "vulns" not in payload:
        raise ValueError("unexpected OSV API shape")
    return parse_osv_http(payload, fallback_package=package, fallback_version=version)


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
    """Fetch vulns for one package version: OSV HTTP API, then binaries.

    The free, no-auth ``/v1/query`` endpoint is tried first
    (bounded by ``min(timeout, OSV_HTTP_TIMEOUT_SECONDS)``; success — even
    an empty vuln list — spawns no subprocess). Any HTTP failure
    (offline, timeout, bad shape) falls back to osv-scanner, then
    pip-audit, exactly as before; binary timeouts still propagate so
    callers see an honest error instead of silent ``[]``. Empty packages
    return ``[]`` without any network or subprocess; empty versions skip
    HTTP (the API is version-scoped) and go straight to the binaries.
    """
    name = (package or "").strip()
    ver = (version or "").strip()
    if not name:
        return []
    budget = timeout if timeout and timeout > 0 else OSV_TIMEOUT_SECONDS
    if ver:
        try:
            return _query_osv_http(name, ver, min(budget, OSV_HTTP_TIMEOUT_SECONDS))
        except Exception:  # noqa: BLE001, S110 — HTTP best-effort; binaries are the fallback
            pass
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
