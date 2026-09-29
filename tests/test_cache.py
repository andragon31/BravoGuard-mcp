"""T3 cache tests: hit/miss, invalidation, orchestrator write-through."""

import asyncio
import json
import time
from pathlib import Path

import pytest

from bravoguard import orchestrator
from bravoguard.cache import (
    FindingCache,
    code_fingerprint,
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


def _missing_everything(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_create(*argv: str, **kwargs: object):
        raise FileNotFoundError(str(argv[0]))

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)


def test_fully_degraded_result_not_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    cache = FindingCache(":memory:")
    try:
        _missing_everything(monkeypatch)
        first = asyncio.run(orchestrator.scan_diff(SEED_DIFF, cache=cache))
        assert first["status"] == "ok"
        assert first["findings"] == []
        assert first["errors"] == {
            "sast": "not-installed",
            "bandit": "not-installed",
            "betterleaks": "not-installed",
        }
        calls: list = []
        install_fake(monkeypatch, calls)
        second = asyncio.run(orchestrator.scan_diff(SEED_DIFF, cache=cache))
        assert "cached" not in second
        assert len(calls) == 3
    finally:
        cache.close()


def test_cache_hit_preserves_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        name = Path(str(argv[0])).name
        if name == "semgrep":
            return FakeProcess(json.dumps({"results": []}).encode(), 0)
        if name == "betterleaks":
            return FakeProcess(b"[]", 0)
        raise FileNotFoundError(name)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)
    cache = FindingCache(":memory:")
    try:
        first = asyncio.run(orchestrator.scan_diff(SEED_DIFF, cache=cache))
        assert first["status"] == "ok"
        assert first["errors"] == {"bandit": "not-installed"}
        assert "cached" not in first

        def _forbidden(*argv: str, **kwargs: object):
            raise AssertionError("cache hit must skip subprocesses")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", _forbidden)
        second = asyncio.run(orchestrator.scan_diff(SEED_DIFF, cache=cache))
        assert second["cached"] is True
        assert second["errors"] == {"bandit": "not-installed"}
        assert second["findings"] == first["findings"]
    finally:
        cache.close()


# --- C1: own-code version signal in the cache fingerprint ---

EXPECTED_CODE_MODULES = {
    "orchestrator.py",
    "normalizer.py",
    "server.py",
    "cache.py",
    "osv.py",
    "suggest.py",
}


@pytest.fixture
def fresh_code_fingerprint():
    code_fingerprint.cache_clear()
    try:
        yield code_fingerprint
    finally:
        code_fingerprint.cache_clear()


def _patch_source_bytes(
    monkeypatch: pytest.MonkeyPatch, name: str, data: bytes | None = None
) -> None:
    """Simulate a source change (or missing file) without touching the tree."""
    real_read_bytes = Path.read_bytes

    def fake_read_bytes(self: Path, *args: object, **kwargs: object) -> bytes:
        if self.name == name and self.parent.name == "bravoguard":
            if data is None:
                raise FileNotFoundError(str(self))
            return data
        return real_read_bytes(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_bytes", fake_read_bytes)


def test_code_segment_embeds_in_fingerprint(fresh_code_fingerprint) -> None:
    fingerprint = scanner_fingerprint()
    assert "code:" in fingerprint
    segment = fingerprint.rsplit("code:", 1)[1]
    assert len(segment) == 12
    int(segment, 16)


def test_key_changes_when_source_changes(
    monkeypatch: pytest.MonkeyPatch, fresh_code_fingerprint
) -> None:
    baseline = make_scan_key(SEED_DIFF)
    _patch_source_bytes(monkeypatch, "orchestrator.py", b"tampered-source")
    fresh_code_fingerprint.cache_clear()
    assert make_scan_key(SEED_DIFF) != baseline


def test_key_stable_on_identical_tree(fresh_code_fingerprint) -> None:
    first = make_scan_key(SEED_DIFF)
    fresh_code_fingerprint.cache_clear()
    assert make_scan_key(SEED_DIFF) == first
    fresh_code_fingerprint.cache_clear()
    assert make_osv_key("django", "4.2") == make_osv_key("django", "4.2")


def test_missing_source_file_never_crashes(
    monkeypatch: pytest.MonkeyPatch, fresh_code_fingerprint
) -> None:
    baseline = make_scan_key(SEED_DIFF)
    _patch_source_bytes(monkeypatch, "suggest.py")
    fresh_code_fingerprint.cache_clear()
    segment = fresh_code_fingerprint()
    assert segment.startswith("code:")
    int(segment.removeprefix("code:"), 16)
    assert make_scan_key(SEED_DIFF) != baseline


def test_code_segment_shared_by_diff_repo_osv_keys(
    monkeypatch: pytest.MonkeyPatch, fresh_code_fingerprint
) -> None:
    from bravoguard import cache as cache_module

    monkeypatch.setattr(cache_module, "code_fingerprint", lambda: "code:aaaaaaaaaaaa")
    scanner_a = scanner_fingerprint()
    scan_a = make_scan_key(SEED_DIFF)
    osv_a = make_osv_key("django", "4.2")
    monkeypatch.setattr(cache_module, "code_fingerprint", lambda: "code:bbbbbbbbbbbb")
    assert "code:bbbbbbbbbbbb" in scanner_fingerprint()
    assert make_scan_key(SEED_DIFF) != scan_a
    assert make_osv_key("django", "4.2") != osv_a
    assert "code:aaaaaaaaaaaa" in scanner_a


def test_code_fingerprint_read_once(
    monkeypatch: pytest.MonkeyPatch, fresh_code_fingerprint
) -> None:
    real_read_bytes = Path.read_bytes
    seen: list[str] = []

    def counting_read_bytes(self: Path, *args: object, **kwargs: object) -> bytes:
        if self.parent.name == "bravoguard" and self.suffix == ".py":
            seen.append(self.name)
        return real_read_bytes(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_bytes", counting_read_bytes)
    first = fresh_code_fingerprint()
    assert sorted(seen) == sorted(EXPECTED_CODE_MODULES)
    assert fresh_code_fingerprint() == first
    assert sorted(seen) == sorted(EXPECTED_CODE_MODULES)


def test_code_fingerprint_amortized_fast(fresh_code_fingerprint) -> None:
    fresh_code_fingerprint()
    start = time.perf_counter()
    for _ in range(50):
        fresh_code_fingerprint()
    assert (time.perf_counter() - start) / 50 * 1000 < 2
