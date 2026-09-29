"""V3 gap 1: media/binary exclusions in fingerprint, materializer, and scans."""

import asyncio
import json
from pathlib import Path

import pytest

from bravoguard import orchestrator
from bravoguard.cache import FindingCache
from bravoguard.orchestrator import (
    _dir_fingerprint,
    _filter_diff,
    _is_excluded,
    _remap_staged_path,
    _stage_filtered_tree,
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


VENV_DIFF = """\
diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -0,0 +1 @@
+x = 1
diff --git a/.venv/evil.py b/.venv/evil.py
index 3333333..4444444 100644
--- a/.venv/evil.py
+++ b/.venv/evil.py
@@ -0,0 +1 @@
+import pickle
"""

VENV_ONLY_DIFF = """\
diff --git a/.venv/evil.py b/.venv/evil.py
index 3333333..4444444 100644
--- a/.venv/evil.py
+++ b/.venv/evil.py
@@ -0,0 +1 @@
+import pickle
"""


def install_capture_fake(
    monkeypatch: pytest.MonkeyPatch, calls: list, stdins: list | None = None
) -> None:
    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append(list(argv))
        name = Path(str(argv[0])).name
        table = {
            "semgrep": json.dumps({"results": []}).encode(),
            "opengrep": json.dumps({"results": []}).encode(),
            "bandit": b'{"results": []}',
            "betterleaks": b"[]",
            "gitleaks": b"[]",
        }
        if name not in table:
            raise FileNotFoundError(name)
        stdout = table[name]

        async def communicate(input_data=None):  # type: ignore[no-untyped-def]
            if stdins is not None:
                stdins.append(input_data)
            return (stdout, b"")

        proc = FakeProcess(stdout, 0)
        proc.communicate = communicate  # type: ignore[method-assign]
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)


def _argv_for(calls: list, binary: str) -> list[str]:
    return next(argv for argv in calls if Path(argv[0]).name == binary)


def test_is_excluded_star_venv_matches_top_level() -> None:
    patterns = ("*/.venv/*",)
    assert _is_excluded(".venv/evil.py", patterns)
    assert _is_excluded("a/.venv/evil.py", patterns)
    assert not _is_excluded("src/app.py", patterns)


def test_default_excludes_cover_venv() -> None:
    assert ".venv/" in orchestrator.DEFAULT_EXCLUDES
    assert _is_excluded(".venv/lib/site.py", orchestrator.DEFAULT_EXCLUDES)
    assert not _is_excluded("src/app.py", orchestrator.DEFAULT_EXCLUDES)


def test_semgrep_argv_forwards_excludes() -> None:
    argv = orchestrator.semgrep_argv("target", ("*/.venv/*", "*.wav"))
    assert argv[:5] == ["semgrep", "--config", str(orchestrator.RULES_DIR), "--json", "--quiet"]
    assert "--exclude=*/.venv/*" in argv
    assert "--exclude=*.wav" in argv
    assert argv[-1] == "target"
    fallback = orchestrator.opengrep_argv("target", ("*/.venv/*", "*.wav"))
    assert fallback[0] == "opengrep"
    assert fallback[1:] == argv[1:]


def test_argv_builders_default_to_no_exclude_flags() -> None:
    assert orchestrator.semgrep_argv("target") == [
        "semgrep",
        "--config",
        str(orchestrator.RULES_DIR),
        "--json",
        "--quiet",
        "target",
    ]
    assert orchestrator.bandit_argv("target") == ["bandit", "-f", "json", "-q", "-r", "target"]


def test_bandit_argv_native_exclude_translated() -> None:
    argv = orchestrator.bandit_argv("target", (".venv/", "*/.venv/*", "skipme.py", "*.wav"))
    assert argv[:6] == ["bandit", "-f", "json", "-q", "-r", "target"]
    value = argv[argv.index("-x") + 1]
    parts = value.split(",")
    assert "*/.venv/*" in parts
    assert ".venv/" not in parts
    assert "*/skipme.py" in parts
    assert "*.wav" in parts


def test_filter_diff_drops_excluded_chunks() -> None:
    filtered = _filter_diff(VENV_DIFF, ("*/.venv/*",))
    assert ".venv/evil.py" not in filtered
    assert "b/app.py" in filtered
    assert "+x = 1" in filtered
    assert _filter_diff(VENV_DIFF, ()) == VENV_DIFF
    assert _filter_diff(VENV_ONLY_DIFF, ("*/.venv/*",)).strip() == ""


def test_materialize_skips_excluded_b_path(tmp_path: Path) -> None:
    written = materialize_diff_files(VENV_DIFF, tmp_path, ("*/.venv/*",))
    assert [p.name for p in written] == ["app.py"]


def test_scan_diff_excludes_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    stdins: list = []
    install_capture_fake(monkeypatch, calls, stdins)
    result = asyncio.run(orchestrator.scan_diff(VENV_DIFF, exclude=["evil.py"]))
    assert result["status"] == "ok"
    assert "--exclude=evil.py" in _argv_for(calls, "semgrep")
    bandit_argv = _argv_for(calls, "bandit")
    assert "*/evil.py" in bandit_argv[bandit_argv.index("-x") + 1].split(",")
    assert stdins and all(b"pickle" not in (data or b"") for data in stdins)
    assert any(b"x = 1" in (data or b"") for data in stdins)


def test_scan_diff_venv_pattern_reaches_all_engines(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    stdins: list = []
    install_capture_fake(monkeypatch, calls, stdins)
    result = asyncio.run(orchestrator.scan_diff(VENV_DIFF, exclude=["*/.venv/*"]))
    assert result["status"] == "ok"
    assert "--exclude=*/.venv/*" in _argv_for(calls, "semgrep")
    bandit_argv = _argv_for(calls, "bandit")
    assert "*/.venv/*" in bandit_argv[bandit_argv.index("-x") + 1].split(",")
    assert stdins and all(b".venv" not in (data or b"") for data in stdins)


def test_scan_diff_empty_after_filter_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    install_capture_fake(monkeypatch, calls)
    result = asyncio.run(orchestrator.scan_diff(VENV_ONLY_DIFF, exclude=["*/.venv/*"]))
    assert result["status"] == "ok"
    assert result["findings"] == []
    assert {Path(argv[0]).name for argv in calls} == {"bandit"}


def _spy_staging(monkeypatch: pytest.MonkeyPatch, seen: dict) -> None:
    real = orchestrator._stage_filtered_tree

    def _spy(target: Path, excludes: tuple, staging: Path) -> int:  # type: ignore[no-untyped-def]
        staged = real(target, excludes, staging)
        seen["staged"] = sorted(
            p.relative_to(staging).as_posix()
            for p in staging.rglob("*")
            if p.is_file()
        )
        return staged

    monkeypatch.setattr(orchestrator, "_stage_filtered_tree", _spy)


def test_scan_repo_default_excludes_skip_venv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(tmp_path / "src" / "app.py", "x = 1\n")
    _write(tmp_path / ".venv" / "evil.py", "assert True\n")
    seen: dict = {}
    _spy_staging(monkeypatch, seen)
    calls: list = []
    install_capture_fake(monkeypatch, calls)
    result = asyncio.run(orchestrator.scan_repo(str(tmp_path)))
    assert result["status"] == "ok"
    semgrep_argv = _argv_for(calls, "semgrep")
    assert "--exclude=.venv/" in semgrep_argv
    assert semgrep_argv[-1] == str(tmp_path)
    bandit_argv = _argv_for(calls, "bandit")
    assert "*/.venv/*" in bandit_argv[bandit_argv.index("-x") + 1].split(",")
    secrets_argv = _argv_for(calls, "betterleaks")
    assert secrets_argv[secrets_argv.index("--source") + 1] != str(tmp_path)
    assert seen["staged"] == ["src/app.py"]


def test_scan_repo_explicit_venv_pattern_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(tmp_path / "src" / "app.py", "x = 1\n")
    _write(tmp_path / ".venv" / "evil.py", "assert True\n")
    assert _is_excluded(".venv/evil.py", ("*/.venv/*",))
    seen: dict = {}
    _spy_staging(monkeypatch, seen)
    calls: list = []
    install_capture_fake(monkeypatch, calls)
    result = asyncio.run(orchestrator.scan_repo(str(tmp_path), exclude=["*/.venv/*"]))
    assert result["status"] == "ok"
    assert "--exclude=*/.venv/*" in _argv_for(calls, "semgrep")
    assert seen["staged"] == ["src/app.py"]


def test_scan_repo_empty_mirror_skips_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(tmp_path / "app.py", "x = 1\n")
    calls: list = []
    install_capture_fake(monkeypatch, calls)
    result = asyncio.run(orchestrator.scan_repo(str(tmp_path), exclude=["*.py"]))
    assert result["status"] == "ok"
    assert result["findings"] == []
    assert "betterleaks" not in {Path(argv[0]).name for argv in calls}


def test_stage_mirror_preserves_layout_and_remaps(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    _write(target / "src" / "app.py", "x = 1\n")
    _write(target / ".venv" / "evil.py", "assert True\n")
    staging = tmp_path / "staging"
    staging.mkdir()
    assert _stage_filtered_tree(target, ("*/.venv/*",), staging) == 1
    assert (staging / "src" / "app.py").read_text(encoding="utf-8") == "x = 1\n"
    assert _remap_staged_path(str(staging / "src" / "app.py"), staging, target) == str(
        target / "src" / "app.py"
    )
    assert _remap_staged_path(str(target / "src" / "app.py"), staging, target) == str(
        target / "src" / "app.py"
    )


def test_scan_diff_sast_uses_explicit_files(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    install_capture_fake(monkeypatch, calls)
    seen: dict = {}
    real = orchestrator.materialize_diff_files

    def _spy(diff: str, workdir: Path, exclude=None):  # type: ignore[no-untyped-def]
        files = real(diff, workdir, exclude)
        seen["files"] = [str(p) for p in files]
        seen["workdir"] = str(workdir)
        return files

    monkeypatch.setattr(orchestrator, "materialize_diff_files", _spy)
    result = asyncio.run(orchestrator.scan_diff(SEED_DIFF))
    assert result["status"] == "ok"
    assert seen["files"]
    argv = _argv_for(calls, "semgrep")
    assert argv[-len(seen["files"]) :] == seen["files"]
    assert seen["workdir"] not in argv


JS_INNERHTML_DIFF = """\
diff --git a/app.js b/app.js
index 1111111..2222222 100644
--- a/app.js
+++ b/app.js
@@ -0,0 +1 @@
+el.innerHTML = location.hash;
"""


def test_scan_diff_gitignored_tree_passes_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: tmp_path))
    calls: list = []
    install_capture_fake(monkeypatch, calls)
    result = asyncio.run(orchestrator.scan_diff(JS_INNERHTML_DIFF))
    assert result["status"] == "ok"
    argv = _argv_for(calls, "semgrep")
    assert argv[-1].endswith(".js")
    assert any(str(tmp_path / ".bravoguard" / "tmp") in part for part in argv)
    assert list((tmp_path / ".bravoguard" / "tmp").glob("bravoguard-diff-*")) == []
