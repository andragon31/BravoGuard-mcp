"""T9 enrich tests: FIRST EPSS batch + CISA KEV join (all network mocked, never live).

Recorded shapes under ``tests/fixtures/enrich/`` mirror the live endpoints
(verified 2026-10-09): ``epss.json`` follows the FIRST.org ``/data/v1/epss``
envelope (``data[]`` of ``{cve, epss, percentile, date}`` with ``epss`` as a
numeric string); ``kev.json`` follows the CISA catalog (``vulnerabilities[]``
of ``{cveID, ...}`` with a capital-D ``cveID``).
"""

import asyncio
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Self

from bravoguard import orchestrator
from bravoguard.cache import FindingCache
from bravoguard.enrich import (
    KEV_FILENAME,
    KEV_TTL_SECONDS,
    enrich_findings,
    extract_cves,
)
from bravoguard.normalizer import make_finding, sort_findings

FIXTURES = Path(__file__).parent / "fixtures" / "enrich"

LOG4SHELL = "CVE-2021-44228"  # in both fixtures: high EPSS + KEV-listed
DJANGO_CVE = "CVE-2019-14234"  # EPSS fixture only: scored, not KEV-listed
UNKNOWN_CVE = "CVE-0000-0000"  # in neither fixture: scores stay untouched


def epss_bytes() -> bytes:
    return (FIXTURES / "epss.json").read_bytes()


def kev_bytes() -> bytes:
    return (FIXTURES / "kev.json").read_bytes()


class FakeResponse:
    """Minimal urllib response: bytes payload, context-manager protocol."""

    def __init__(self, payload: bytes, status: int = 200) -> None:
        self._payload = payload
        self.status = status

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


def install_urlopen(monkeypatch, routes: list, calls: list) -> None:
    """Route urlopen by URL substring; fallthrough raises (unexpected call).

    ``routes`` entries are ``(marker, payload-or-exception)``; every URL is
    recorded in ``calls`` so tests can assert which feeds were hit.
    """

    def fake_open(url: object, *args: object, **kwargs: object) -> FakeResponse:
        if isinstance(url, urllib.request.Request):
            target = url.full_url
        else:
            target = str(url)
        calls.append(target)
        for marker, outcome in routes:
            if marker in target:
                if isinstance(outcome, Exception):
                    raise outcome
                return FakeResponse(outcome)
        raise AssertionError(f"unexpected network call: {target}")

    monkeypatch.setattr(urllib.request, "urlopen", fake_open)


def seed_kev(tmp_path: Path, payload: bytes | None = None) -> Path:
    cache_dir = tmp_path / "feed-cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / KEV_FILENAME).write_bytes(payload if payload is not None else kev_bytes())
    return cache_dir


def stale_catalog_without(cve: str) -> bytes:
    catalog = json.loads(kev_bytes())
    catalog["vulnerabilities"] = [
        v for v in catalog["vulnerabilities"] if v.get("cveID") != cve
    ]
    catalog["count"] = len(catalog["vulnerabilities"])
    return json.dumps(catalog).encode()


def test_extract_cves_from_rule_id_message_and_fix_hint() -> None:
    finding = make_finding(
        "trivy-CVE-2021-44228",
        "",
        "app.lock",
        0,
        "HIGH",
        f"fix {DJANGO_CVE} soon",
        "see cve-2023-31047 advisory",
    )
    assert extract_cves(finding) == ["CVE-2021-44228", "CVE-2019-14234", "CVE-2023-31047"]
    assert extract_cves(make_finding("ruff-F401", "", "a.py", 1, "LOW", "unused")) == []
    assert extract_cves(None) == []  # type: ignore[arg-type]
    assert extract_cves({"rule_id": "grype-cve-2021-44228"}) == ["CVE-2021-44228"]


def test_enrich_populates_epss_and_kev(monkeypatch, tmp_path: Path) -> None:
    calls: list = []
    install_urlopen(
        monkeypatch,
        [("first.org", epss_bytes()), ("cisa.gov", kev_bytes())],
        calls,
    )
    findings = [
        make_finding(f"trivy-{LOG4SHELL}", "", "app.lock", 0, "HIGH", "m1", "h1"),
        make_finding(f"grype-{DJANGO_CVE}", "", "req.txt", 0, "HIGH", "m2", "h2"),
        make_finding(f"trivy-{UNKNOWN_CVE}", "", "req.txt", 0, "HIGH", "m3", "h3"),
        make_finding("ruff-F401", "", "a.py", 1, "LOW", "unused import", ""),
    ]
    enriched = enrich_findings(findings, tmp_path / "feed-cache")
    by_rule = {f["rule_id"]: f for f in enriched}
    assert by_rule[f"trivy-{LOG4SHELL}"]["epss"] == 0.97484
    assert by_rule[f"trivy-{LOG4SHELL}"]["kev"] is True
    assert by_rule[f"grype-{DJANGO_CVE}"]["epss"] == 0.01593
    assert by_rule[f"grype-{DJANGO_CVE}"]["kev"] is False
    assert by_rule[f"trivy-{UNKNOWN_CVE}"]["epss"] is None
    assert by_rule[f"trivy-{UNKNOWN_CVE}"]["kev"] is False
    plain = by_rule["ruff-F401"]
    assert plain["epss"] is None and plain["kev"] is False
    assert any("first.org" in url for url in calls)
    assert any("cisa.gov" in url for url in calls)


def test_zero_cves_makes_no_network_calls(monkeypatch, tmp_path: Path) -> None:
    def _forbidden(url: object, *args: object, **kwargs: object) -> FakeResponse:
        raise AssertionError("zero CVEs must skip all network calls")

    monkeypatch.setattr(urllib.request, "urlopen", _forbidden)
    findings = [make_finding("ruff-F401", "", "a.py", 1, "LOW", "unused", "")]
    assert enrich_findings(findings, tmp_path / "feed-cache") == findings
    assert not (tmp_path / "feed-cache" / KEV_FILENAME).exists()


def test_empty_findings_make_no_network_calls(monkeypatch, tmp_path: Path) -> None:
    def _forbidden(url: object, *args: object, **kwargs: object) -> FakeResponse:
        raise AssertionError("empty findings must skip all network calls")

    monkeypatch.setattr(urllib.request, "urlopen", _forbidden)
    assert enrich_findings([], tmp_path / "feed-cache") == []


def test_offline_passthrough_never_drops_findings(monkeypatch, tmp_path: Path) -> None:
    calls: list = []
    install_urlopen(
        monkeypatch,
        [
            ("first.org", urllib.error.URLError("offline")),
            ("cisa.gov", urllib.error.URLError("offline")),
        ],
        calls,
    )
    findings = [make_finding(f"trivy-{LOG4SHELL}", "", "app.lock", 0, "HIGH", "m", "h")]
    assert enrich_findings(findings, tmp_path / "feed-cache") == findings


def test_timeout_passthrough_never_fails_scan(monkeypatch, tmp_path: Path) -> None:
    calls: list = []
    install_urlopen(
        monkeypatch,
        [
            ("first.org", TimeoutError("slow")),
            ("cisa.gov", TimeoutError("slow")),
        ],
        calls,
    )
    findings = [make_finding(f"grype-{DJANGO_CVE}", "", "r.txt", 0, "HIGH", "m", "h")]
    assert enrich_findings(findings, tmp_path / "feed-cache") == findings


def test_epss_failure_still_applies_kev(monkeypatch, tmp_path: Path) -> None:
    cache_dir = seed_kev(tmp_path)
    calls: list = []
    install_urlopen(
        monkeypatch,
        [("first.org", urllib.error.URLError("epss down"))],
        calls,
    )
    findings = [make_finding(f"trivy-{LOG4SHELL}", "", "app.lock", 0, "HIGH", "m", "h")]
    (enriched,) = enrich_findings(findings, cache_dir)
    assert enriched["epss"] is None  # failed feed leaves its field untouched
    assert enriched["kev"] is True  # healthy feed still enriches
    assert not any("cisa.gov" in url for url in calls)  # fresh seed: no re-download


def test_kev_cache_hit_avoids_redownload(monkeypatch, tmp_path: Path) -> None:
    cache_dir = seed_kev(tmp_path)
    calls: list = []
    install_urlopen(monkeypatch, [("first.org", epss_bytes())], calls)
    findings = [make_finding(f"trivy-{LOG4SHELL}", "", "app.lock", 0, "HIGH", "m", "h")]
    (enriched,) = enrich_findings(findings, cache_dir)
    assert enriched["epss"] == 0.97484
    assert enriched["kev"] is True
    assert not any("cisa.gov" in url for url in calls)


def test_kev_stale_file_triggers_refresh(monkeypatch, tmp_path: Path) -> None:
    cache_dir = seed_kev(tmp_path, stale_catalog_without(LOG4SHELL))
    kev_path = cache_dir / KEV_FILENAME
    old = time.time() - (KEV_TTL_SECONDS + 86400)
    import os

    os.utime(kev_path, (old, old))
    calls: list = []
    install_urlopen(
        monkeypatch,
        [("first.org", epss_bytes()), ("cisa.gov", kev_bytes())],
        calls,
    )
    findings = [make_finding(f"trivy-{LOG4SHELL}", "", "app.lock", 0, "HIGH", "m", "h")]
    (enriched,) = enrich_findings(findings, cache_dir)
    assert any("cisa.gov" in url for url in calls)
    assert enriched["kev"] is True  # refreshed catalog lists it
    assert LOG4SHELL in kev_path.read_text(encoding="utf-8")  # write-through


def test_kev_refresh_boundary(monkeypatch, tmp_path: Path) -> None:
    import os

    # Just inside the TTL: fresh, no download.
    fresh_dir = seed_kev(tmp_path / "fresh")
    fresh_path = fresh_dir / KEV_FILENAME
    now = time.time()
    os.utime(fresh_path, (now - (KEV_TTL_SECONDS - 60), now - (KEV_TTL_SECONDS - 60)))
    calls: list = []
    install_urlopen(monkeypatch, [("first.org", epss_bytes())], calls)
    enrich_findings(
        [make_finding(f"trivy-{LOG4SHELL}", "", "a.lock", 0, "HIGH", "m", "h")],
        fresh_dir,
    )
    assert not any("cisa.gov" in url for url in calls)

    # Just outside the TTL: stale, re-downloads.
    stale_dir = seed_kev(tmp_path / "stale")
    stale_path = stale_dir / KEV_FILENAME
    os.utime(stale_path, (now - (KEV_TTL_SECONDS + 60), now - (KEV_TTL_SECONDS + 60)))
    calls.clear()
    install_urlopen(
        monkeypatch,
        [("first.org", epss_bytes()), ("cisa.gov", kev_bytes())],
        calls,
    )
    enrich_findings(
        [make_finding(f"trivy-{LOG4SHELL}", "", "a.lock", 0, "HIGH", "m", "h")],
        stale_dir,
    )
    assert any("cisa.gov" in url for url in calls)


def test_kev_download_failure_falls_back_to_stale_file(
    monkeypatch, tmp_path: Path
) -> None:
    cache_dir = seed_kev(tmp_path)  # lists LOG4SHELL
    kev_path = cache_dir / KEV_FILENAME
    import os

    old = time.time() - (KEV_TTL_SECONDS + 86400)
    os.utime(kev_path, (old, old))
    calls: list = []
    install_urlopen(
        monkeypatch,
        [
            ("first.org", epss_bytes()),
            ("cisa.gov", urllib.error.URLError("kev down")),
        ],
        calls,
    )
    findings = [make_finding(f"trivy-{LOG4SHELL}", "", "app.lock", 0, "HIGH", "m", "h")]
    (enriched,) = enrich_findings(findings, cache_dir)
    assert enriched["kev"] is True  # stale catalog still applies, scan never fails


def test_findings_without_cves_stay_untouched(monkeypatch, tmp_path: Path) -> None:
    calls: list = []
    install_urlopen(
        monkeypatch,
        [("first.org", epss_bytes()), ("cisa.gov", kev_bytes())],
        calls,
    )
    plain = make_finding("ruff-F401", "", "a.py", 1, "LOW", "unused", "")
    cve_hit = make_finding(f"trivy-{LOG4SHELL}", "", "app.lock", 0, "HIGH", "m", "h")
    enriched = enrich_findings([plain, cve_hit], tmp_path / "feed-cache")
    assert enriched[0] == plain
    assert enriched[1]["epss"] == 0.97484


def test_original_findings_are_not_mutated(monkeypatch, tmp_path: Path) -> None:
    calls: list = []
    install_urlopen(
        monkeypatch,
        [("first.org", epss_bytes()), ("cisa.gov", kev_bytes())],
        calls,
    )
    original = make_finding(f"trivy-{LOG4SHELL}", "", "app.lock", 0, "HIGH", "m", "h")
    (enriched,) = enrich_findings([original], tmp_path / "feed-cache")
    assert original["epss"] is None and original["kev"] is False
    assert enriched["epss"] == 0.97484 and enriched["kev"] is True


def test_enriched_values_feed_existing_risk_sort(monkeypatch, tmp_path: Path) -> None:
    calls: list = []
    install_urlopen(
        monkeypatch,
        [("first.org", epss_bytes()), ("cisa.gov", kev_bytes())],
        calls,
    )
    low_kev = make_finding(f"trivy-{LOG4SHELL}", "", "a.lock", 0, "HIGH", "m", "h")
    scored = make_finding(f"grype-{DJANGO_CVE}", "", "b.lock", 0, "HIGH", "m", "h")
    unscored = make_finding("ruff-F401", "", "c.py", 1, "LOW", "m", "h")
    enriched = enrich_findings([unscored, scored, low_kev], tmp_path / "feed-cache")
    assert [f["rule_id"] for f in sort_findings(enriched)] == [
        f"trivy-{LOG4SHELL}",  # KEV-listed first, whatever its EPSS
        f"grype-{DJANGO_CVE}",  # then EPSS descending
        "ruff-F401",  # unknown risk last
    ]


# --- scan-tail wiring (orchestrator calls enrich after dedup, before sort) ----


class FakeProc:
    def __init__(self, stdout: bytes) -> None:
        self._stdout = stdout
        self.returncode = 0

    async def communicate(self, input_data=None):
        return (self._stdout, b"")

    def kill(self) -> None:
        pass

    async def wait(self) -> int:
        return self.returncode


def install_scan_fake(monkeypatch, semgrep_payload: bytes, trivy_payload: bytes) -> None:
    async def fake_create(*argv: str, **kwargs: object) -> FakeProc:
        first = Path(str(argv[0])).name
        names = {Path(str(a)).name for a in argv}
        if first in ("semgrep", "opengrep"):
            return FakeProc(semgrep_payload)
        if first == "bandit":
            return FakeProc(b'{"results": []}')
        if first in ("betterleaks", "gitleaks"):
            return FakeProc(b"[]")
        if first == "trivy":
            return FakeProc(trivy_payload)
        if first == "uv" and "checkov" in names:
            return FakeProc(b'{"results": {"failed_checks": []}}')
        raise FileNotFoundError(first)  # every other lane reports skipped+reason

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)


def semgrep_cve_payload() -> bytes:
    return json.dumps(
        {
            "results": [
                {
                    "check_id": f"custom-{LOG4SHELL}",
                    "path": "app.py",
                    "start": {"line": 1},
                    "extra": {"severity": "ERROR", "message": "m", "metadata": {}},
                }
            ]
        }
    ).encode()


def trivy_cve_payload() -> bytes:
    return json.dumps(
        {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": LOG4SHELL,
                            "PkgName": "log4j-core",
                            "InstalledVersion": "2.14.0",
                            "Severity": "CRITICAL",
                            "Title": "Log4j RCE",
                        }
                    ],
                }
            ]
        }
    ).encode()


def test_scan_diff_enriches_after_dedup_before_sort(monkeypatch, tmp_path: Path) -> None:
    install_scan_fake(monkeypatch, semgrep_cve_payload(), b"{}")
    calls: list = []
    install_urlopen(
        monkeypatch, [("first.org", epss_bytes()), ("cisa.gov", kev_bytes())], calls
    )
    cache = FindingCache(str(tmp_path / "cache.db"))
    try:
        diff = (
            "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n"
            "@@ -0,0 +1 @@\n+print('hi')\n"
        )
        result = asyncio.run(orchestrator.scan_diff(diff, cache=cache))
    finally:
        cache.close()
    hit = next(f for f in result["findings"] if LOG4SHELL in f["rule_id"])
    assert hit["epss"] == 0.97484
    assert hit["kev"] is True
    assert any("first.org" in url for url in calls)


def test_scan_repo_enriches_and_caches_enriched(monkeypatch, tmp_path: Path) -> None:
    install_scan_fake(monkeypatch, b'{"results": []}', trivy_cve_payload())
    calls: list = []
    install_urlopen(
        monkeypatch, [("first.org", epss_bytes()), ("cisa.gov", kev_bytes())], calls
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    cache = FindingCache(str(tmp_path / "cache.db"))
    try:
        result = asyncio.run(orchestrator.scan_repo(str(repo), cache=cache))
    finally:
        cache.close()
    hit = next(f for f in result["findings"] if LOG4SHELL in f["rule_id"])
    assert hit["epss"] == 0.97484
    assert hit["kev"] is True
    assert (tmp_path / KEV_FILENAME).is_file()  # feed-cache sits beside cache.db

    def _forbidden(url: object, *args: object, **kwargs: object):
        raise AssertionError("cache hit must skip scanners and feeds")

    monkeypatch.setattr(urllib.request, "urlopen", _forbidden)
    cache2 = FindingCache(str(tmp_path / "cache.db"))
    try:
        second = asyncio.run(orchestrator.scan_repo(str(repo), cache=cache2))
    finally:
        cache2.close()
    assert second.get("cached") is True
    assert second["findings"] == result["findings"]
