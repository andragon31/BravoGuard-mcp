"""V3 gap 1: media/binary exclusions in fingerprint, materializer, and scans."""

import asyncio
import json
from pathlib import Path

import pytest

from bravoguard import orchestrator
from bravoguard.cache import FindingCache
from bravoguard.orchestrator import (
    _dir_fingerprint,
    _is_excluded,
    materialize_diff_files,
)

SEED_DIFF = """\
diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -0,0 +1 @@
+x = 1
"""


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


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


def install_quiet_fake(monkeypatch: pytest.MonkeyPatch, calls: list) -> None:
    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append(list(argv))
        name = Path(str(argv[0])).name
        if name == "semgrep":
            return FakeProcess(json.dumps({"results": []}).encode(), 0)
        if name == "bandit":
            return FakeProcess(b'{"results": []}', 0)
        if name == "betterleaks":
            return FakeProcess(b"[]", 0)
        raise FileNotFoundError(name)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)


def test_is_excluded_matches_dirs_and_globs() -> None:
    excluded = orchestrator.DEFAULT_EXCLUDES
    assert _is_excluded("frames/clip.mp4", excluded)
    assert _is_excluded("projects/demo/app.py", excluded)
    assert _is_excluded("audio.wav", excluded)
    assert _is_excluded("bundle.zip", excluded)
    assert not _is_excluded("src/app.py", excluded)
    assert not _is_excluded("src/app.py", ())


def test_dir_fingerprint_ignores_excluded_media(tmp_path: Path) -> None:
    _write(tmp_path / "app.py", "x = 1\n")
    _write(tmp_path / "frames" / "clip.mp4", "fake-bytes-1")
    _write(tmp_path / "notes.wav", "more-fake-bytes")
    before = _dir_fingerprint(tmp_path)
    _write(tmp_path / "frames" / "clip.mp4", "fake-bytes-2-changed-much-longer")
    _write(tmp_path / "notes.wav", "changed")
    assert _dir_fingerprint(tmp_path) == before
    _write(tmp_path / "app.py", "x = 1\ny = 2\n")
    assert _dir_fingerprint(tmp_path) != before


def test_dir_fingerprint_custom_exclude(tmp_path: Path) -> None:
    _write(tmp_path / "app.py", "x = 1\n")
    _write(tmp_path / "skipme.py", "a = 1\n")
    excluded_before = _dir_fingerprint(tmp_path, exclude=["skipme.py"])
    full_before = _dir_fingerprint(tmp_path, exclude=[])
    _write(tmp_path / "skipme.py", "a = 1\nb = 2\n")
    assert _dir_fingerprint(tmp_path, exclude=["skipme.py"]) == excluded_before
    assert _dir_fingerprint(tmp_path, exclude=[]) != full_before


def test_materialize_skips_excluded_files(tmp_path: Path) -> None:
    diff = (
        "diff --git a/app.py b/app.py\n"
        "+++ b/app.py\n"
        "@@ -0,0 +1 @@\n"
        "+x = 1\n"
        "diff --git a/sound.wav b/sound.wav\n"
        "+++ b/sound.wav\n"
        "@@ -0,0 +1 @@\n"
        "+noise\n"
    )
    written = materialize_diff_files(diff, tmp_path)
    assert [p.name for p in written] == ["app.py"]


def test_scan_repo_media_churn_keeps_cache_hit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(tmp_path / "app.py", "x = 1\n")
    _write(tmp_path / "frames" / "clip.mp4", "fake-bytes-1")
    cache = FindingCache(":memory:")
    try:
        calls: list = []
        install_quiet_fake(monkeypatch, calls)
        first = asyncio.run(orchestrator.scan_repo(str(tmp_path), cache=cache))
        assert first["status"] == "ok"
        count = len(calls)
        _write(tmp_path / "frames" / "clip.mp4", "fake-bytes-2-changed-much-longer")
        second = asyncio.run(orchestrator.scan_repo(str(tmp_path), cache=cache))
        assert second.get("cached") is True
        assert second["findings"] == first["findings"]
        assert len(calls) == count
    finally:
        cache.close()


def test_scan_diff_forwards_exclude(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict = {}
    real = orchestrator.materialize_diff_files

    def _spy(diff: str, workdir: Path, exclude=None):  # type: ignore[no-untyped-def]
        seen["exclude"] = exclude
        return real(diff, workdir, exclude)

    monkeypatch.setattr(orchestrator, "materialize_diff_files", _spy)
    calls: list = []
    install_quiet_fake(monkeypatch, calls)
    result = asyncio.run(orchestrator.scan_diff(SEED_DIFF, exclude=["skip.py"]))
    assert result["status"] == "ok"
    assert list(seen["exclude"]) == ["skip.py"]
