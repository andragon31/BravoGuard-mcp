"""Live CVE enrichment: FIRST EPSS scores + CISA KEV join (Phase 5, T9).

Best-effort post pass over normalized findings, stdlib ``urllib`` only (no
new dependencies). :func:`enrich_findings` extracts CVE IDs from findings,
batch-queries the FIRST.org EPSS API (free, no auth) for ``epss`` floats,
and joins the CISA KEV catalog (free JSON feed, cached under the cache dir
with a 7-day refresh) for ``kev`` bools.

Endpoint/field evidence (verified live 2026-10-09):

- EPSS ``GET https://api.first.org/data/v1/epss?cve=A,B`` answers
  ``{"status": "OK", "data": [{"cve": "CVE-…", "epss": "0.97…",
  "percentile": "…", "date": "…"}]}``. ``epss`` arrives as a numeric
  string; comma-joined batch queries return one entry per known CVE.
- KEV ``GET https://www.cisa.gov/sites/default/files/feeds/
  known_exploited_vulnerabilities.json`` answers ``{"vulnerabilities":
  [{"cveID": "CVE-…", …}]}`` (~1.7 MB, ``cveID`` with a capital D).

Rules: zero CVEs means zero network calls (neither feed is touched); any
feed failure or timeout leaves that feed's fields untouched and never drops
a finding or fails the scan; findings without CVEs are returned untouched.
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
KEV_FILENAME = "kev.json"
KEV_TTL_SECONDS = 7 * 24 * 3600
EPSS_CHUNK_SIZE = 100
ENRICH_TIMEOUT_SECONDS = 5.0
DEFAULT_FEED_DIRNAME = ".bravoguard"

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_CVE_FIELDS: tuple[str, ...] = ("rule_id", "message", "fix_hint")

__all__ = [
    "DEFAULT_FEED_DIRNAME",
    "ENRICH_TIMEOUT_SECONDS",
    "EPSS_API_URL",
    "EPSS_CHUNK_SIZE",
    "KEV_FEED_URL",
    "KEV_FILENAME",
    "KEV_TTL_SECONDS",
    "enrich_findings",
    "extract_cves",
    "fetch_epss_scores",
    "kev_cache_path",
    "load_kev_set",
]


def extract_cves(finding: Any) -> list[str]:
    """CVE IDs carried by one finding, uppercased, first-seen order.

    Scans ``rule_id`` + ``message`` + ``fix_hint`` (trivy/grype CVE rule ids
    as well as CVEs mentioned in prose); findings without CVEs yield ``[]``.
    Non-dict inputs yield ``[]`` (never raises).
    """
    if not isinstance(finding, dict):
        return []
    seen: list[str] = []
    for field in _CVE_FIELDS:
        text = finding.get(field)
        if not isinstance(text, str) or not text:
            continue
        for match in _CVE_RE.finditer(text):
            cve = match.group(0).upper()
            if cve not in seen:
                seen.append(cve)
    return seen


def _download(url: str, timeout: float) -> bytes:
    """GET one URL with a bounded timeout; transport errors propagate."""
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def fetch_epss_scores(cves: list[str], timeout: float = ENRICH_TIMEOUT_SECONDS) -> dict[str, float]:
    """Batch-query EPSS for CVE IDs; transport/parse errors propagate.

    One GET per :data:`EPSS_CHUNK_SIZE` CVEs (comma-joined ``cve`` param);
    returns ``{CVE: score}`` for entries carrying a parseable ``epss``
    value. Unknown CVEs are simply absent (the caller keeps existing
    values). Callers treat any exception as feed failure (passthrough).
    """
    ids = [c.upper() for c in dict.fromkeys(cves) if c]
    if not ids:
        return {}
    budget = timeout if timeout and timeout > 0 else ENRICH_TIMEOUT_SECONDS
    scores: dict[str, float] = {}
    for offset in range(0, len(ids), EPSS_CHUNK_SIZE):
        chunk = ids[offset : offset + EPSS_CHUNK_SIZE]
        query = urllib.parse.urlencode({"cve": ",".join(chunk)})
        raw = _download(f"{EPSS_API_URL}?{query}", budget)
        payload = json.loads(raw.decode("utf-8", errors="replace"))
        entries = payload.get("data", []) if isinstance(payload, dict) else []
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            cve = str(entry.get("cve", "")).upper()
            if not cve:
                continue
            try:
                score = float(entry.get("epss"))
            except (TypeError, ValueError):
                continue
            scores[cve] = min(1.0, max(0.0, score))
    return scores


def kev_cache_path(cache_dir: str | Path | None = None) -> Path:
    """Local KEV catalog file: ``<cache-dir>/kev.json`` (feed-cache place)."""
    base = Path(cache_dir) if cache_dir is not None else Path.cwd() / DEFAULT_FEED_DIRNAME
    return Path(base) / KEV_FILENAME


def _parse_kev(raw: bytes) -> set[str]:
    """Uppercase CVE-ID set from catalog bytes; parse errors propagate."""
    payload = json.loads(raw.decode("utf-8", errors="replace"))
    entries = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    ids = set()
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict) and entry.get("cveID"):
                ids.add(str(entry["cveID"]).upper())
    return ids


def load_kev_set(
    cache_dir: str | Path | None = None, timeout: float = ENRICH_TIMEOUT_SECONDS
) -> set[str]:
    """KEV CVE-ID set with a 7-day file cache; errors propagate to the caller.

    A fresh cache file (mtime within :data:`KEV_TTL_SECONDS`) is read with
    no network. Otherwise the feed is re-downloaded and written through
    (write failures are best-effort and never hide the fresh set); when the
    download fails but a stale file exists, the stale set applies instead
    of failing the scan.
    """
    path = kev_cache_path(cache_dir)
    budget = timeout if timeout and timeout > 0 else ENRICH_TIMEOUT_SECONDS
    if path.is_file():
        try:
            age = time.time() - path.stat().st_mtime
        except OSError:
            age = float("inf")
        if age < KEV_TTL_SECONDS:
            return _parse_kev(path.read_bytes())
    try:
        raw = _download(KEV_FEED_URL, budget)
    except Exception:
        if path.is_file():
            return _parse_kev(path.read_bytes())
        raise
    ids = _parse_kev(raw)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{KEV_FILENAME}.tmp")
        tmp.write_bytes(raw)
        tmp.replace(path)
    except OSError:
        pass
    return ids


def enrich_findings(
    findings: list[dict[str, Any]],
    cache_dir: str | Path | None = None,
    timeout: float = ENRICH_TIMEOUT_SECONDS,
) -> list[dict[str, Any]]:
    """Join live EPSS scores + KEV flags into CVE findings (best-effort).

    Findings with CVEs gain ``epss`` (max score across their CVEs, only
    when the feed answers) and ``kev`` (any CVE catalog-listed, only when
    the catalog loads); findings without CVEs pass through untouched, and
    the input dicts are never mutated. Zero CVEs means zero network calls;
    any feed failure leaves that feed's fields at their existing values and
    the full finding list is always returned (never drops, never raises).
    """
    if not isinstance(findings, list) or not findings:
        return findings
    per_finding = [extract_cves(item) for item in findings]
    universe = sorted({cve for cves in per_finding for cve in cves})
    if not universe:
        return findings
    budget = timeout if timeout and timeout > 0 else ENRICH_TIMEOUT_SECONDS
    try:
        epss_map = fetch_epss_scores(universe, timeout=budget)
    except Exception:  # noqa: BLE001 — enrichment is best-effort; feeds fail open
        epss_map = {}
    try:
        kev_set = load_kev_set(cache_dir, timeout=budget)
    except Exception:  # noqa: BLE001 — same fail-open contract for the catalog
        kev_set = None
    if not epss_map and kev_set is None:
        return findings
    enriched: list[dict[str, Any]] = []
    for finding, cves in zip(findings, per_finding):
        if not isinstance(finding, dict) or not cves:
            enriched.append(finding)
            continue
        updates: dict[str, Any] = {}
        scores = [epss_map[cve] for cve in cves if cve in epss_map]
        if scores:
            updates["epss"] = max(scores)
        if kev_set is not None:
            updates["kev"] = any(cve in kev_set for cve in cves)
        if not updates:
            enriched.append(finding)
            continue
        merged = dict(finding)
        merged.update(updates)
        enriched.append(merged)
    return enriched
