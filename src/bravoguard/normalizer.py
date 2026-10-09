"""Unified finding Normalizer for BRAVOGuard scanners (Phase 1, T2).

Single source for the finding schema and all scanner parsers:

- SAST: semgrep / opengrep JSON (identical shape, same parser).
- Python: bandit JSON.
- Secrets: betterleaks JSON (Secret/Match values are never read).
- Secrets verify: trufflehog ``filesystem --json --results=verified`` JSONL
  (Raw/RawV2 values are never read; verified live credentials -> CRITICAL).
- Frontend: oxlint ``--format json`` (``diagnostics`` list).
- Container/IaC/license: trivy ``fs --format json`` (``Results`` list).
- IaC: checkov ``-o json`` (``results.failed_checks``).
- Supply: typosquat + bundled-binary findings pass through
  (:func:`normalize_supply`) — emitted normalized, never an error.
- SBOM: the syft store lane emits no findings (:func:`normalize_syft`
  always returns ``[]``; the stored SBOM feeds grype).
- Supply vulns: grype ``sbom:... -o json`` matches (:func:`normalize_grype`).
  Severities cap CRITICAL -> HIGH via :func:`_capped_severity` (same policy
  as trivy: engine-assigned without exploit context).

Schema (``FINDING_KEYS``): ``rule_id, cwe, path, line, severity, message,
fix_hint, epss, kev, reachability_note``. ``epss`` is a float in [0, 1] or
``None`` when unknown; ``kev`` is a bool; ``reachability_note`` is free text
(empty when unknown).

Severity honesty (M1 multi-lane): engines without exploit context never emit
CRITICAL on their own authority. oxlint maps ``error`` -> MEDIUM and
everything else -> LOW (lint signal, no CVE, never above MEDIUM); trivy
and checkov pass their feed severity through but cap CRITICAL -> HIGH
and default blanks to MEDIUM (checkov omits ``severity`` for many graph
checks). ``cwe`` is ``""`` where the engine carries no mapping (oxlint
diagnostics, checkov checks, trivy entries without ``CweIDs``); trivy
uses the first ``CweIDs`` entry when present.

Helpers:

- :func:`dedup_findings` drops repeats keyed on
  ``rule_id + path + line + sha256(message)`` (first occurrence wins).
- :func:`dedup_cve_findings` is the secondary pass: trivy + grype report
  the same CVE on the same path, so one finding per ``(cve, path)`` is
  kept, preferring the richer fix info (longest non-empty ``fix_hint``;
  first occurrence wins exact ties). Only ``trivy-``/``grype-`` rule ids
  carrying a ``CVE-YYYY-NNNN`` id participate; everything else passes
  through untouched, so the primary dedup is never weakened.
- :func:`sort_findings` orders KEV-listed findings first, then EPSS
  descending (unknown EPSS sorts last).
"""

from __future__ import annotations

import hashlib
import math
import re
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
TRUFFLEHOG_FIX_HINT = (
    "This credential verified live: revoke it immediately, rotate it, "
    "audit recent usage, and load the replacement from env or a secret manager."
)
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


def _trufflehog_location(item: dict[str, Any]) -> tuple[Any, Any]:
    """File + line for one trufflehog entry (filesystem scans).

    Only ``SourceMetadata.Data.Filesystem`` and the ``SourceName`` fallback
    are read; ``Raw``/``RawV2``/``Redacted`` are never touched.
    """
    source = item.get("SourceMetadata")
    data = source.get("Data") if isinstance(source, dict) else None
    fs = data.get("Filesystem") if isinstance(data, dict) else None
    if isinstance(fs, dict):
        return fs.get("file") or item.get("SourceName"), fs.get("line")
    return item.get("SourceName"), 0


def normalize_trufflehog(payload: Any) -> list[dict[str, Any]]:
    """Map trufflehog ``--json`` entries to the unified finding shape.

    Entry shape (trufflehog v3 ``filesystem``): ``DetectorName`` (e.g.
    ``Github``), ``DetectorDescription``, ``Verified`` bool, and
    ``SourceMetadata.Data.Filesystem.{file, line}``. The detector names the
    rule (``trufflehog-<DetectorName>``); a ``Verified: true`` entry is a
    live credential and maps to CRITICAL (active compromise signal),
    anything else to HIGH (same standing as the betterleaks edge). Only
    detector metadata is propagated; ``Raw``/``RawV2``/``Redacted`` values
    are never read, so live credentials cannot flow into findings.
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
        detector = str(item.get("DetectorName") or "unknown")
        verified = item.get("Verified") is True
        path, line = _trufflehog_location(item)
        description = item.get("DetectorDescription") or f"{detector} credential detected"
        findings.append(
            make_finding(
                f"trufflehog-{detector}",
                SECRETS_DEFAULT_CWE,
                path,
                line,
                "CRITICAL" if verified else "HIGH",
                f"{'Verified live' if verified else 'Unverified'} {detector} credential: "
                f"{description}",
                TRUFFLEHOG_FIX_HINT,
            )
        )
    return findings


def _oxlint_severity(value: Any) -> str:
    """oxlint ``error`` -> MEDIUM, anything else (``warning``) -> LOW.

    Lint findings carry no CVE, so they never escalate above MEDIUM.
    """
    return "MEDIUM" if str(value or "").lower() == "error" else "LOW"


def _oxlint_line(item: dict[str, Any]) -> int:
    labels = item.get("labels")
    if isinstance(labels, list) and labels:
        first = labels[0]
        if isinstance(first, dict):
            span = first.get("span")
            if isinstance(span, dict):
                return _safe_line(span.get("line"))
    return 0


def normalize_oxlint(payload: Any) -> list[dict[str, Any]]:
    """Map oxlint ``--format json`` diagnostics to the unified shape.

    Real shape (oxlint 1.65.0, verified live): ``{"diagnostics": [{message,
    code, severity, help, filename, labels: [{span: {line, column}}]}]}``.
    Rules become ``oxlint-<code>``; ``help`` becomes the fix hint; ``cwe``
    stays empty (lint codes do not map to CWEs).
    """
    items = payload.get("diagnostics", []) if isinstance(payload, dict) else []
    findings = []
    for item in items:
        if not isinstance(item, dict):
            continue
        findings.append(
            make_finding(
                f"oxlint-{item.get('code', 'unknown')}",
                "",
                item.get("filename"),
                _oxlint_line(item),
                _oxlint_severity(item.get("severity")),
                item.get("message"),
                item.get("help"),
            )
        )
    return findings


def _capped_severity(value: Any) -> str:
    """Uppercase passthrough capped at HIGH (CRITICAL -> HIGH).

    Trivy/checkov severities are engine-assigned without exploit context,
    so CRITICAL is capped; blanks default to MEDIUM.
    """
    severity = str(value or "MEDIUM").upper()
    return "HIGH" if severity == "CRITICAL" else severity


def normalize_trivy(payload: Any) -> list[dict[str, Any]]:
    """Map trivy ``fs --format json`` Results to the unified shape.

    Real shape (trivy 0.74.0, verified live): ``{"Results": [{Target,
    Vulnerabilities: [{VulnerabilityID, PkgName, InstalledVersion,
    FixedVersion, Severity, Title, CweIDs[], PrimaryURL}],
    Misconfigurations: [{ID, Title, Message, Resolution, Severity,
    CauseMetadata: {StartLine}}],
    Licenses: [{PkgName, PkgVersion/InstalledVersion, Name, Confidence,
    Link, CweIDs[]}]}]}``. Missing ``Results`` (clean target)
    yields no findings. Vuln rules are ``trivy-<VulnerabilityID>`` with the
    first ``CweIDs`` entry (else empty); misconfig rules are
    ``trivy-<ID>`` with ``Resolution`` as the fix hint; license rules are
    ``trivy-license-<PkgName>-<Name>`` at LOW severity (license signal
    never escalates) with ``cwe`` empty unless the entry carries
    ``CweIDs`` and a fix hint naming the package for license review.
    """
    results = payload.get("Results", []) if isinstance(payload, dict) else []
    findings = []
    for result in results:
        if not isinstance(result, dict):
            continue
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            cwe_ids = vuln.get("CweIDs") or []
            package = vuln.get("PkgName", "")
            installed = vuln.get("InstalledVersion", "")
            fixed = vuln.get("FixedVersion", "")
            hint = f"Upgrade {package} {installed} to {fixed}." if fixed else ""
            findings.append(
                make_finding(
                    f"trivy-{vuln.get('VulnerabilityID', 'unknown')}",
                    _cwe_text(cwe_ids[0]) if cwe_ids else "",
                    target,
                    0,
                    _capped_severity(vuln.get("Severity")),
                    vuln.get("Title") or vuln.get("Description"),
                    hint,
                )
            )
        for misconfig in result.get("Misconfigurations") or []:
            if not isinstance(misconfig, dict):
                continue
            cause = misconfig.get("CauseMetadata")
            line = cause.get("StartLine") if isinstance(cause, dict) else 0
            findings.append(
                make_finding(
                    f"trivy-{misconfig.get('ID', 'unknown')}",
                    "",
                    target,
                    line,
                    _capped_severity(misconfig.get("Severity")),
                    misconfig.get("Title") or misconfig.get("Message"),
                    misconfig.get("Resolution"),
                )
            )
        for lic in result.get("Licenses") or []:
            if not isinstance(lic, dict):
                continue
            package = str(lic.get("PkgName", "") or "")
            name = str(
                lic.get("Name", lic.get("License", lic.get("ID", "unknown"))) or "unknown"
            )
            version = str(lic.get("PkgVersion", lic.get("InstalledVersion", "")) or "")
            cwe_ids = lic.get("CweIDs") or []
            at_version = f" {version}" if version else ""
            findings.append(
                make_finding(
                    f"trivy-license-{package or 'unknown'}-{name}",
                    _cwe_text(cwe_ids[0]) if cwe_ids else "",
                    target,
                    0,
                    "LOW",
                    f"Package {package or 'unknown'}{at_version} uses license {name}.",
                    f"Review license {name} for package {package or 'unknown'}{at_version}.",
                )
            )
    return findings


def normalize_checkov(payload: Any) -> list[dict[str, Any]]:
    """Map checkov ``-o json`` failed_checks to the unified shape.

    Real shape (checkov 3.3.20, verified live): ``{"check_type": ...,
    "results": {"failed_checks": [{check_id, check_name, file_abs_path,
    file_line_range: [start, end], severity (often null), guideline}]}}``.
    Non-IaC targets return a summary-only payload without ``results`` (no
    findings, not an error); a list payload (multi-framework runs) is
    accepted too. Rules are ``checkov-<check_id>``; ``guideline`` (docs URL)
    becomes the fix hint; ``cwe`` stays empty (checks do not carry CWEs).
    """
    items = payload if isinstance(payload, list) else [payload]
    findings = []
    for entry in items:
        if not isinstance(entry, dict):
            continue
        results = entry.get("results")
        failed = results.get("failed_checks", []) if isinstance(results, dict) else []
        for check in failed:
            if not isinstance(check, dict):
                continue
            line_range = check.get("file_line_range") or [0]
            findings.append(
                make_finding(
                    f"checkov-{check.get('check_id', 'unknown')}",
                    "",
                    check.get("file_abs_path") or check.get("file_path"),
                    line_range[0] if isinstance(line_range, list) else 0,
                    _capped_severity(check.get("severity")),
                    check.get("check_name"),
                    check.get("guideline"),
                )
            )
    return findings


def normalize_syft(payload: Any) -> list[dict[str, Any]]:
    """SBOM store lane: the SBOM is inventory for grype, never findings."""
    return []


def _grype_location(artifact: dict[str, Any]) -> Any:
    """First artifact location path of a grype match, else empty.

    Grype matches SBOM inventory, so locations mirror the SBOM's recorded
    paths (e.g. ``package-lock.json``); image-derived SBOMs may carry none.
    """
    locations = artifact.get("locations")
    if isinstance(locations, list) and locations:
        first = locations[0]
        if isinstance(first, dict):
            return first.get("path")
    return ""


def _grype_epss(vulnerability: dict[str, Any], match: dict[str, Any]) -> Any:
    """Best-effort EPSS read: vulnerability keys first, then match level."""
    for source in (vulnerability, match):
        for key in ("epss", "epssScore", "epss_score"):
            value = source.get(key)
            if value is not None:
                return value
    return None


def _grype_kev(vulnerability: dict[str, Any], match: dict[str, Any]) -> Any:
    """Best-effort KEV read: vulnerability keys first, then match level."""
    for source in (vulnerability, match):
        for key in ("kev", "knownExploited", "cisaKev", "isKev"):
            if source.get(key) is not None:
                return source.get(key)
    return False


def normalize_grype(payload: Any) -> list[dict[str, Any]]:
    """Map grype ``sbom:... -o json`` matches to the unified shape.

    Recorded shape (grype 0.118.0, documented source — binary absent in
    this env): ``{"matches": [{"vulnerability": {id, severity,
    description, fix: {versions[]}}, "artifact": {name, version,
    locations: [{path}]}}]}``. Rules are ``grype-<vuln-id>``; the fix hint
    mirrors the trivy format (``Upgrade <pkg> <installed> to <fixed>.``)
    from the first fixed version; ``cwe`` stays empty (matches carry no
    CWE); EPSS/KEV pass through when present (grype OSS omits them, so
    blanks degrade to unknown, never fabricated).
    """
    matches = payload.get("matches", []) if isinstance(payload, dict) else []
    findings = []
    for match in matches:
        if not isinstance(match, dict):
            continue
        vulnerability = match.get("vulnerability")
        vulnerability = vulnerability if isinstance(vulnerability, dict) else {}
        artifact = match.get("artifact")
        artifact = artifact if isinstance(artifact, dict) else {}
        fix = vulnerability.get("fix")
        fix = fix if isinstance(fix, dict) else {}
        versions = fix.get("versions") or []
        fixed = versions[0] if isinstance(versions, list) and versions else ""
        package = artifact.get("name", "")
        installed = artifact.get("version", "")
        hint = f"Upgrade {package} {installed} to {fixed}." if fixed else ""
        findings.append(
            make_finding(
                f"grype-{vulnerability.get('id', 'unknown')}",
                "",
                _grype_location(artifact),
                0,
                _capped_severity(vulnerability.get("Severity", vulnerability.get("severity"))),
                vulnerability.get("description") or vulnerability.get("summary"),
                hint,
                _grype_epss(vulnerability, match),
                _grype_kev(vulnerability, match),
            )
        )
    return findings


def normalize_supply(payload: Any) -> list[dict[str, Any]]:
    """Pass through supply-lane findings (already normalized at creation).

    The typosquat/bundled-binary lane emits schema-conformant findings
    directly via :func:`make_finding`, so this only drops non-dict items
    and tolerates non-list payloads (empty, never an error).
    """
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_CVE_LANE_PREFIXES = ("trivy-", "grype-")


def _cve_dedup_key(finding: dict[str, Any]) -> tuple[str, str] | None:
    """``(cve, path)`` for trivy/grype CVE findings, else None (pass-through)."""
    rule_id = str(finding.get("rule_id", ""))
    if not rule_id.startswith(_CVE_LANE_PREFIXES):
        return None
    match = _CVE_RE.search(rule_id)
    if match is None:
        return None
    return (match.group(0).upper(), str(finding.get("path", "")))


def _fix_richness(finding: dict[str, Any]) -> tuple[int, int]:
    """Tie-break rank: a non-empty fix hint beats an empty one, longer wins."""
    hint = str(finding.get("fix_hint", ""))
    return (1 if hint else 0, len(hint))


def dedup_cve_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Secondary pass: keep ONE finding per ``(cve, path)``.

    Trivy and grype match the same inventory, so the same CVE on the same
    path arrives twice with different rule ids (``trivy-CVE-…`` vs
    ``grype-CVE-…``) — the primary ``rule_id``-keyed dedup cannot see the
    pair. The winner is the richer fix info (highest :func:`_fix_richness`);
    exact ties keep the first occurrence (stable, engine-agnostic). Findings
    without a trivy/grype CVE rule id pass through in order.
    """
    winners: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = _cve_dedup_key(finding)
        if key is None:
            continue
        current = winners.get(key)
        if current is None or _fix_richness(finding) > _fix_richness(current):
            winners[key] = finding
    emitted: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = _cve_dedup_key(finding)
        if key is None:
            unique.append(finding)
        elif key not in emitted:
            emitted.add(key)
            unique.append(winners[key])
    return unique


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
    """Dedup (primary, then CVE secondary) then risk-sort a mixed-scanner list."""
    return sort_findings(dedup_cve_findings(dedup_findings(findings)))
