"""Unified finding Normalizer for BRAVOGuard scanners (Phase 1, T2).

Single source for the finding schema and all scanner parsers:

- SAST: semgrep / opengrep JSON (identical shape, same parser).
- Python: bandit JSON.
- Secrets: betterleaks JSON (Secret/Match values are never read).

Schema (``FINDING_KEYS``): ``rule_id, cwe, path, line, severity, message,
fix_hint, epss, kev, reachability_note``. ``epss`` is a float in [0, 1] or
``None`` when unknown; ``kev`` is a bool; ``reachability_note`` is free text
(empty when unknown).

Helpers:

- :func:`dedup_findings` drops repeats keyed on
  ``rule_id + path + line + sha256(message)`` (first occurrence wins).
- :func:`sort_findings` orders KEV-listed findings first, then EPSS
  descending (unknown EPSS sorts last).
"""

from __future__ import annotations

import hashlib
import math
from typing import Any

FINDING_KEYS = (
    "rule_id",
    "cwe",
    "path",
    "line",
    "severity",
    "message",
    "fix_hint",
    "epss",
    "kev",
    "reachability_note",
)

BETTERLEAKS_FIX_HINT = "Remove the secret, rotate it, and load it from env or a secret manager."
SECRETS_DEFAULT_CWE = "CWE-798"


def make_finding(
    rule_id: Any = None,
    cwe: Any = None,
    path: Any = None,
    line: Any = None,
    severity: Any = None,
    message: Any = None,
    fix_hint: Any = None,
    epss: Any = None,
    kev: Any = None,
    reachability_note: Any = None,
) -> dict[str, Any]:
    """Build one schema-conformant finding with coerced types."""
    return {
        "rule_id": str(rule_id or "unknown"),
        "cwe": str(cwe or ""),
        "path": str(path or ""),
        "line": _safe_line(line),
        "severity": str(severity or "MEDIUM").upper(),
        "message": str(message or ""),
        "fix_hint": str(fix_hint or ""),
        "epss": _safe_epss(epss),
        "kev": _safe_kev(kev),
        "reachability_note": str(reachability_note or ""),
    }


def _safe_line(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _safe_epss(value: Any) -> float | None:
    if value is None or value is False or value == "":
        return None
    try:
        score = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if math.isnan(score):
        return None
    return min(1.0, max(0.0, score))


def _safe_kev(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "1", "kev", "known")
    return False


def _cwe_text(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("id", "")
    if isinstance(value, int):
        return f"CWE-{value}"
    if isinstance(value, list):
        return _cwe_text(value[0]) if value else ""
    text = str(value or "").strip()
    if text.isdigit():
        return f"CWE-{text}"
    return text.upper() if text.upper().startswith("CWE-") else text


def _semgrep_cwe(metadata: dict[str, Any]) -> str:
    return _cwe_text(metadata.get("cwe", ""))


def normalize_semgrep(payload: Any) -> list[dict[str, Any]]:
    """Map semgrep/opengrep JSON results to the unified finding shape."""
    results = payload.get("results", []) if isinstance(payload, dict) else []
    findings = []
    for item in results:
        if not isinstance(item, dict):
            continue
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        start = item.get("start") if isinstance(item.get("start"), dict) else {}
        findings.append(
            make_finding(
                item.get("check_id"),
                _semgrep_cwe(metadata),
                item.get("path"),
                start.get("line"),
                extra.get("severity"),
                extra.get("message"),
                metadata.get("fix_hint"),
                metadata.get("epss"),
                metadata.get("kev"),
                metadata.get("reachability_note", metadata.get("reachability", "")),
            )
        )
    return findings


def normalize_bandit(payload: Any) -> list[dict[str, Any]]:
    """Map bandit JSON results to the unified finding shape."""
    results = payload.get("results", []) if isinstance(payload, dict) else []
    findings = []
    for item in results:
        if not isinstance(item, dict):
            continue
        findings.append(
            make_finding(
                item.get("test_id"),
                _cwe_text(item.get("issue_cwe")),
                item.get("filename"),
                item.get("line_number"),
                item.get("issue_severity"),
                item.get("issue_text"),
                "",
            )
        )
    return findings


def normalize_betterleaks(payload: Any) -> list[dict[str, Any]]:
    """Map betterleaks JSON to the unified finding shape.

    Only rule metadata is propagated; Secret/Match values are never read,
    so live credentials cannot flow into findings, logs, or errors.
    """
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        results = payload.get("results", [])
        items = results if isinstance(results, list) else []
    else:
        items = []
    findings = []
    for item in items:
        if not isinstance(item, dict):
            continue
        findings.append(
            make_finding(
                item.get("RuleID"),
                SECRETS_DEFAULT_CWE,
                item.get("File"),
                item.get("StartLine"),
                "HIGH",
                item.get("Description"),
                BETTERLEAKS_FIX_HINT,
            )
        )
    return findings


def _dedup_key(finding: dict[str, Any]) -> tuple[str, str, int, str]:
    content = hashlib.sha256(str(finding.get("message", "")).encode("utf-8")).hexdigest()
    try:
        line = int(finding.get("line", 0))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        line = 0
    return (str(finding.get("rule_id", "")), str(finding.get("path", "")), line, content)


def dedup_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop repeats on rule_id + path + line + message hash; first wins."""
    seen: set[tuple[str, str, int, str]] = set()
    unique = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = _dedup_key(finding)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _rank_epss(value: Any) -> float:
    score = _safe_epss(value)
    return score if score is not None else -1.0


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Order KEV-listed findings first, then EPSS descending (stable)."""
    return sorted(
        findings,
        key=lambda f: (not _safe_kev(f.get("kev")), -_rank_epss(f.get("epss"))),
    )


def normalize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Dedup then risk-sort a mixed-scanner finding list."""
    return sort_findings(dedup_findings(findings))
