"""T4 OSV tests: fetcher parsing, cache hit/miss, pip-audit fallback."""

import asyncio
import json
from pathlib import Path

import pytest

from bravoguard import orchestrator
from bravoguard.cache import FindingCache
from bravoguard.normalizer import FINDING_KEYS
from bravoguard.osv import (
    fetch_osv,
    normalize_osv_vulns,
    parse_osv_scanner,
    parse_pip_audit,
)


class FakeProcess:
    def __init__(self, stdout: bytes, returncode: int = 0) -> None:
        self._stdout = stdout
        self.returncode = returncode

    async def communicate(self, input_data=None):
        return (self._stdout, b"")

    def kill(self) -> None:
        pass

    async def wait(self) -> int:
        return self.returncode


def install_fake(monkeypatch: pytest.MonkeyPatch, responses: dict, calls: list) -> None:
    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append(list(argv))
        assert "shell" not in kwargs, "scanners must never run with shell=True"
        name = Path(str(argv[0])).name
        if name not in responses:
            raise FileNotFoundError(name)
        stdout, returncode = responses[name]
        return FakeProcess(stdout, returncode)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)


def osv_scanner_payload() -> bytes:
    return json.dumps(
        {
            "results": [
                {
                    "packages": [
                        {
                            "package": {
                                "name": "django",
                                "version": "4.2",
                                "ecosystem": "PyPI",
                            },
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-2hrw-hx67-34x6",
                                    "summary": "Django SQL injection.",
                                    "severity": [
                                        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}
                                    ],
                                    "database_specific": {
                                        "cwe_ids": ["CWE-89"],
                                        "severity": "HIGH",
                                    },
                                },
                                {"id": "GHSA-minimal", "details": "No summary entry."},
                            ],
                        }
                    ]
                }
            ]
        }
    ).encode()


def pip_audit_payload() -> bytes:
    return json.dumps(
        {
            "dependencies": [
                {
                    "name": "django",
                    "version": "4.2",
                    "vulns": [
                        {
                            "id": "PYSEC-2024-1",
                            "fix_versions": ["4.2.11"],
                            "spec": "<4.2.11",
                            "aliases": ["CVE-2024-1234"],
                        },
                        {
                            "id": "PYSEC-2024-2",
                            "fix_versions": [],
                            "spec": "",
                            "aliases": [],
                            "severity": "medium",
                            "summary": "XSS in admin.",
                        },
                    ],
                }
            ]
        }
    ).encode()


def test_parse_osv_scanner_shape() -> None:
    vulns = parse_osv_scanner(json.loads(osv_scanner_payload()))
    assert len(vulns) == 2
    first, minimal = vulns
    assert {"id", "severity", "summary", "package", "version"} <= set(first)
    assert first["id"] == "GHSA-2hrw-hx67-34x6"
    assert first["severity"] == "HIGH"
    assert first["summary"] == "Django SQL injection."
    assert (first["package"], first["version"]) == ("django", "4.2")
    assert first["cwe"] == "CWE-89"
    assert minimal["severity"] == "UNKNOWN"


def test_parse_pip_audit_shape() -> None:
    vulns = parse_pip_audit(json.loads(pip_audit_payload()))
    assert len(vulns) == 2
    assert {"id", "severity", "summary", "package", "version"} <= set(vulns[0])
    assert "4.2.11" in vulns[0]["summary"]
    assert (vulns[0]["package"], vulns[0]["version"]) == ("django", "4.2")
    assert vulns[1]["severity"] == "MEDIUM"
    assert vulns[1]["summary"] == "XSS in admin."


def test_parse_guards_return_empty() -> None:
    assert parse_osv_scanner({}) == []
    assert parse_osv_scanner([]) == []
    assert parse_osv_scanner(None) == []
    assert parse_pip_audit({}) == []
    assert parse_pip_audit(None) == []


def test_fetch_osv_prefers_osv_scanner(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    install_fake(
        monkeypatch,
        {
            "osv-scanner": (osv_scanner_payload(), 0),
            "pip-audit": (b"{}", AssertionError("fallback must not run")),
        },
        calls,
    )
    vulns = asyncio.run(fetch_osv("django", "4.2"))
    assert [v["id"] for v in vulns] == ["GHSA-2hrw-hx67-34x6", "GHSA-minimal"]
    binaries = {Path(argv[0]).name for argv in calls}
    assert "pip-audit" not in binaries
    osv_argv = next(a for a in calls if Path(a[0]).name == "osv-scanner")
    assert "--format" in osv_argv and "json" in osv_argv


def test_fetch_osv_falls_back_to_pip_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    install_fake(monkeypatch, {"pip-audit": (pip_audit_payload(), 0)}, calls)
    vulns = asyncio.run(fetch_osv("django", "4.2"))
    assert [v["id"] for v in vulns] == ["PYSEC-2024-1", "PYSEC-2024-2"]
    binaries = {Path(argv[0]).name for argv in calls}
    assert {"osv-scanner", "pip-audit"} <= binaries
    audit_argv = next(a for a in calls if Path(a[0]).name == "pip-audit")
    assert "--format=json" in audit_argv


def test_fetch_osv_empty_package_skips_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    def _forbidden(*argv: str, **kwargs: object):
        raise AssertionError("empty package must skip subprocesses")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _forbidden)
    assert asyncio.run(fetch_osv("   ", "1.0")) == []


def test_osv_lookup_write_through_then_hit_avoids_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache = FindingCache(":memory:")
    try:
        calls: list = []
        install_fake(monkeypatch, {"osv-scanner": (osv_scanner_payload(), 0)}, calls)
        first = asyncio.run(
            orchestrator.osv_lookup("django", "4.2", cache=cache, fetcher=fetch_osv)
        )
        assert first["status"] == "ok"
        assert "cached" not in first
        assert len(first["vulns"]) == 2

        def _forbidden(*argv: str, **kwargs: object):
            raise AssertionError("cache hit must skip subprocesses")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", _forbidden)
        second = asyncio.run(
            orchestrator.osv_lookup("django", "4.2", cache=cache, fetcher=fetch_osv)
        )
        assert second == {"status": "ok", "vulns": first["vulns"], "cached": True}
    finally:
        cache.close()


def test_normalize_osv_vulns_shape() -> None:
    vulns = parse_osv_scanner(json.loads(osv_scanner_payload()))
    findings = normalize_osv_vulns(vulns)
    assert len(findings) == 2
    assert set(findings[0]) == set(FINDING_KEYS)
    assert findings[0]["rule_id"] == "GHSA-2hrw-hx67-34x6"
    assert findings[0]["cwe"] == "CWE-89"
    assert normalize_osv_vulns(None) == []
    assert normalize_osv_vulns([None]) == []  # type: ignore[list-item]


def test_osv_lookup_empty_guard_skips_fetcher() -> None:
    async def _fetcher(package: str, version: str):
        raise AssertionError("empty package must skip fetcher")

    assert asyncio.run(orchestrator.osv_lookup("  ", "1.0", fetcher=_fetcher)) == {
        "status": "empty-package",
        "vulns": [],
    }


def test_fetch_osv_both_missing_raises_not_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bravoguard.orchestrator import ScannerMissingError

    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        raise FileNotFoundError(str(argv[0]))

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)
    with pytest.raises(ScannerMissingError):
        asyncio.run(fetch_osv("django", "4.2"))
