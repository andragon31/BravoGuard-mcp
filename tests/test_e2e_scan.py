"""T4 seeded e2e: vuln diff -> >=1 finding mapped to OWASP A05."""

import asyncio
import inspect
import json
from pathlib import Path

import pytest

from bravoguard import orchestrator
from bravoguard.cache import FindingCache
from bravoguard.orchestrator import FINDING_KEYS
from bravoguard.osv import fetch_osv
from bravoguard.owasp_map import explain_cwe

SEED_DIFF = """\
diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -0,0 +1,3 @@
+import pickle
+result = eval(user_input)
+obj = pickle.loads(data)
diff --git a/app.js b/app.js
index 3333333..4444444 100644
--- a/app.js
+++ b/app.js
@@ -0,0 +1,1 @@
+el.innerHTML = userInput;
"""


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


def _semgrep_result(
    check_id: str, path: str, line: int, cwe: str, owasp: str, message: str
) -> dict:
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line, "col": 1},
        "end": {"line": line, "col": 10},
        "extra": {
            "message": message,
            "severity": "ERROR",
            "metadata": {"cwe": cwe, "owasp_2025": owasp},
        },
    }


def install_scan_fake(monkeypatch: pytest.MonkeyPatch, calls: list) -> None:
    payload = json.dumps(
        {
            "results": [
                _semgrep_result(
                    "bravoguard-python-eval",
                    "app.py",
                    2,
                    "CWE-95",
                    "A05",
                    "Avoid eval on untrusted input (CWE-95).",
                ),
                _semgrep_result(
                    "bravoguard-python-pickle-load",
                    "app.py",
                    3,
                    "CWE-502",
                    "A08",
                    "Avoid pickle.loads on untrusted input (CWE-502).",
                ),
                _semgrep_result(
                    "bravoguard-js-innerhtml",
                    "app.js",
                    1,
                    "CWE-79",
                    "A05",
                    "Avoid innerHTML with untrusted data (CWE-79).",
                ),
            ]
        }
    ).encode()

    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append(list(argv))
        assert "shell" not in kwargs, "scanners must never run with shell=True"
        name = Path(str(argv[0])).name
        if name in ("semgrep", "opengrep"):
            return FakeProcess(payload, 1)
        if name in ("bandit", "betterleaks"):
            empty = b'{"results": []}' if name == "bandit" else b"[]"
            return FakeProcess(empty, 0)
        raise FileNotFoundError(name)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)


def test_e2e_seeded_diff_yields_a05_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    install_scan_fake(monkeypatch, calls)
    result = asyncio.run(orchestrator.scan_diff(SEED_DIFF))
    assert result["status"] == "ok"
    assert len(result["findings"]) >= 1
    for finding in result["findings"]:
        assert set(finding) == set(FINDING_KEYS)
    a05 = [
        f for f in result["findings"] if explain_cwe(f["cwe"]).get("owasp_2025") == "A05"
    ]
    assert len(a05) >= 1
    assert {"CWE-95", "CWE-79"} <= {f["cwe"] for f in a05}


def test_osv_lookup_cache_hit_avoids_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    osv_payload = json.dumps(
        {
            "results": [
                {
                    "packages": [
                        {
                            "package": {"name": "django", "version": "4.2"},
                            "vulnerabilities": [
                                {"id": "GHSA-e2e-1", "summary": "Seeded vuln."}
                            ],
                        }
                    ]
                }
            ]
        }
    ).encode()

    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        assert Path(str(argv[0])).name == "osv-scanner"
        return FakeProcess(osv_payload, 0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)
    cache = FindingCache(":memory:")
    try:
        first = asyncio.run(
            orchestrator.osv_lookup("django", "4.2", cache=cache, fetcher=fetch_osv)
        )
        assert first["status"] == "ok"
        assert len(first["vulns"]) == 1

        def _forbidden(*argv: str, **kwargs: object):
            raise AssertionError("cache hit must skip subprocesses")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", _forbidden)
        second = asyncio.run(
            orchestrator.osv_lookup("django", "4.2", cache=cache, fetcher=fetch_osv)
        )
        assert second == {"status": "ok", "vulns": first["vulns"], "cached": True}
    finally:
        cache.close()


def test_empty_guards_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    cache = FindingCache(":memory:")
    try:
        puts: list = []
        real_put = cache.put
        monkeypatch.setattr(
            cache, "put", lambda k, f, ttl_seconds=None: puts.append(k) or real_put(k, f)
        )

        async def _fetcher(package: str, version: str):
            raise AssertionError("empty package must skip fetcher")

        assert asyncio.run(orchestrator.scan_diff("   ", cache=cache)) == {
            "status": "empty-diff",
            "findings": [],
        }
        assert asyncio.run(orchestrator.osv_lookup("  ", "1.0", cache=cache)) == {
            "status": "empty-package",
            "vulns": [],
        }
        assert asyncio.run(
            orchestrator.osv_lookup("  ", "1.0", cache=cache, fetcher=_fetcher)
        ) == {"status": "empty-package", "vulns": []}
        assert puts == []
    finally:
        cache.close()


def test_server_osv_lookup_wired_to_real_fetcher() -> None:
    from bravoguard import server

    source = inspect.getsource(server)
    assert "fetcher=fetch_osv" in source
    assert '"not-implemented", "task": f"osv_lookup' not in source
