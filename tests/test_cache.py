"""T3 cache tests: hit/miss, invalidation, orchestrator write-through."""

import asyncio
import json
import time
from pathlib import Path

import pytest

from bravoguard import orchestrator
from bravoguard.cache import (
    FindingCache,
    content_hash,
    make_key,
    make_osv_key,
    make_scan_key,
    resolve_cache_path,
    scanner_fingerprint,
)

SEED_DIFF = """\
diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -0,0 +1,3 @@
+import pickle
+data = input()
+obj = pickle.load(data)
"""

FINDINGS = [
    {
        "rule_id": "bravoguard-python-pickle-load",
        "cwe": "CWE-502",
        "path": "app.py",
        "line": 3,
        "severity": "ERROR",
        "message": "Avoid pickle.load on untrusted input.",
        "fix_hint": "Use json.load.",
        "epss": None,
        "kev": False,
        "reachability_note": "",
    }
]


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


def install_fake(monkeypatch: pytest.MonkeyPatch, calls: list) -> None:
    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append(list(argv))
        name = Path(str(argv[0])).name
        if name == "semgrep":
            payload = json.dumps({"results": []}).encode()
            return FakeProcess(payload, 0)
        if name == "bandit":
            return FakeProcess(b'{"results": []}', 0)
        if name == "betterleaks":
            return FakeProcess(b"[]", 0)
        raise FileNotFoundError(name)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)


def test_cache_miss_then_hit() -> None:
    cache = FindingCache(":memory:")
    try:
        assert cache.get("missing") is None
        cache.put("k1", FINDINGS)
        assert cache.get("k1") == FINDINGS
    finally:
        cache.close()


def test_key_invalidation_on_content_change() -> None:
    assert make_scan_key("diff-a") != make_scan_key("diff-b")
    assert content_hash("a") != content_hash("b")


def test_key_invalidation_on_scanner_version_change() -> None:
    digest = content_hash(SEED_DIFF)
    assert make_key(digest, "semgrep@1") != make_key(digest, "semgrep@2")
    assert make_scan_key(SEED_DIFF, scanner_versions="v1") != make_scan_key(
        SEED_DIFF, scanner_versions="v2"
    )


def test_key_invalidation_on_db_and_image_fields() -> None:
    base = make_scan_key(SEED_DIFF, scanner_versions="v1")
    assert make_scan_key(SEED_DIFF, scanner_versions="v1", db_updated_at="2026-01-01") != base
    assert make_scan_key(SEED_DIFF, scanner_versions="v1", image_digest="sha256:abc") != base


def test_scanner_fingerprint_reads_manifest() -> None:
    fingerprint = scanner_fingerprint()
    assert "semgrep" in fingerprint
    assert "opengrep" in fingerprint


def test_ttl_expiry() -> None:
    cache = FindingCache(":memory:")
    try:
        cache.put("ttl-key", FINDINGS, ttl_seconds=0.05)
        assert cache.get("ttl-key") == FINDINGS
        time.sleep(0.08)
        assert cache.get("ttl-key") is None
    finally:
        cache.close()


def test_in_memory_isolation() -> None:
    first, second = FindingCache(":memory:"), FindingCache(":memory:")
    try:
        first.put("shared", FINDINGS)
        assert first.get("shared") == FINDINGS
        assert second.get("shared") is None
    finally:
        first.close()
        second.close()


def test_resolve_cache_path_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "custom.db"
    monkeypatch.setenv("BRAVO_CACHE_PATH", str(target))
    assert str(resolve_cache_path()) == str(target)
    monkeypatch.setenv("BRAVO_CACHE_PATH", ":memory:")
    assert resolve_cache_path() == ":memory:"


def test_scan_diff_write_through_then_hit_avoids_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache = FindingCache(":memory:")
    try:
        calls: list = []
        install_fake(monkeypatch, calls)
        first = asyncio.run(orchestrator.scan_diff(SEED_DIFF, cache=cache))
        assert first["status"] == "ok"
        assert "cached" not in first
        assert len(calls) == 3

        def _forbidden(*argv: str, **kwargs: object):
            raise AssertionError("cache hit must skip subprocesses")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", _forbidden)
        second = asyncio.run(orchestrator.scan_diff(SEED_DIFF, cache=cache))
        assert second == {"status": "ok", "findings": first["findings"], "cached": True}
    finally:
        cache.close()


def test_scan_diff_empty_guard_bypasses_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    cache = FindingCache(":memory:")
    try:
        puts: list = []
        real_put = cache.put
        monkeypatch.setattr(cache, "put", lambda k, f, ttl_seconds=None: puts.append(k) or real_put(k, f))
        assert asyncio.run(orchestrator.scan_diff("   ", cache=cache)) == {
            "status": "empty-diff",
            "findings": [],
        }
        assert puts == []
    finally:
        cache.close()


def test_scan_repo_hit_avoids_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    cache = FindingCache(":memory:")
    try:
        calls: list = []
        install_fake(monkeypatch, calls)
        first = asyncio.run(orchestrator.scan_repo(str(tmp_path), cache=cache))
        assert first["status"] == "ok"
        count = len(calls)

        def _forbidden(*argv: str, **kwargs: object):
            raise AssertionError("cache hit must skip subprocesses")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", _forbidden)
        second = asyncio.run(orchestrator.scan_repo(str(tmp_path), cache=cache))
        assert second["cached"] is True
        assert second["findings"] == first["findings"]
        assert len(calls) == count
    finally:
        cache.close()


def test_scan_repo_content_change_invalidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    cache = FindingCache(":memory:")
    try:
        calls: list = []
        install_fake(monkeypatch, calls)
        asyncio.run(orchestrator.scan_repo(str(tmp_path), cache=cache))
        (tmp_path / "app.py").write_text("x = 1\ny = 2\n", encoding="utf-8")
        before = len(calls)
        asyncio.run(orchestrator.scan_repo(str(tmp_path), cache=cache))
        assert len(calls) > before
    finally:
        cache.close()


def test_osv_lookup_cache_first_hook() -> None:
    cache = FindingCache(":memory:")
    try:
        missed = asyncio.run(orchestrator.osv_lookup("django", "4.2", cache=cache))
        assert missed["status"] == "not-implemented"

        vulns = [{"id": "GHSA-1", "severity": "HIGH"}]
        cache.put(make_osv_key("django", "4.2", scanner_versions=scanner_fingerprint()), vulns)

        async def _fetcher(package: str, version: str):
            raise AssertionError("cache hit must skip fetcher")

        hit = asyncio.run(orchestrator.osv_lookup("django", "4.2", cache=cache, fetcher=_fetcher))
        assert hit == {"status": "ok", "vulns": vulns, "cached": True}

        assert asyncio.run(orchestrator.osv_lookup("  ", "1.0", cache=cache)) == {
            "status": "empty-package",
            "vulns": [],
        }
    finally:
        cache.close()


def test_osv_lookup_fetcher_write_through() -> None:
    cache = FindingCache(":memory:")
    try:
        vulns = [{"id": "GHSA-2", "severity": "CRITICAL"}]

        async def _fetcher(package: str, version: str):
            return vulns

        result = asyncio.run(orchestrator.osv_lookup("flask", "3.0", cache=cache, fetcher=_fetcher))
        assert result == {"status": "ok", "vulns": vulns}
        assert cache.get(make_osv_key("flask", "3.0", scanner_versions=scanner_fingerprint())) == vulns
    finally:
        cache.close()
