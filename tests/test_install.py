"""Installer unit tests: platform dispatch mocked, dry-run never mutates."""

import importlib.util
import json
import shutil
import sys
from pathlib import Path


def load_install():
    path = Path(__file__).resolve().parents[1] / "scripts" / "install.py"
    spec = importlib.util.spec_from_file_location("bravoguard_install", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["bravoguard_install"] = mod
    spec.loader.exec_module(mod)
    return mod


install = load_install()
SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def test_detect_platform_win_and_linux(monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    assert install.detect_platform() == "windows"
    monkeypatch.setattr(sys, "platform", "linux")
    assert install.detect_platform() == "linux"
    assert install.detect_platform("darwin") == "macos"


def test_guarddog_skipped_on_windows_unless_forced() -> None:
    skipped = [a for a in install.build_plan("windows", False, False) if a.tool == "guarddog"]
    assert len(skipped) == 1 and skipped[0].skipped and "Windows" in skipped[0].skip_reason
    forced = [a for a in install.build_plan("windows", False, True) if a.tool == "guarddog"]
    assert len(forced) == 1 and not forced[0].skipped and forced[0].candidates
    linux = [a for a in install.build_plan("linux", False, False) if a.tool == "guarddog"]
    assert len(linux) == 1 and not linux[0].skipped


def test_dry_run_never_mutates(monkeypatch) -> None:
    def _boom(*args, **kwargs):
        raise AssertionError("dry-run must not execute subprocesses")

    monkeypatch.setattr(install.subprocess, "run", _boom)
    assert install.main(["--install"]) == 0
    assert install.main([]) == 0


def test_install_without_yes_lists_guarddog_skip(capsys) -> None:
    assert install.main(["--install"]) == 0
    out = capsys.readouterr().out
    assert "SKIP guarddog" in out and "--yes" in out


def test_manifest_pins_respected() -> None:
    manifest = json.loads((install.ROOT / "tools-manifest.json").read_text(encoding="utf-8"))
    expected = {b["name"]: b["version"] for b in manifest["binaries"]}
    plan = install.build_plan("linux", True, False)
    got = {a.tool: a.version for a in plan if a.tool in expected}
    assert got == expected


def test_windows_prefers_winget_linux_prefers_brew() -> None:
    win = {a.tool: a for a in install.build_plan("windows", True, False)}
    assert win["syft"].candidates[0][0] == "winget"
    assert win["oxlint"].candidates[0][:2] == ["npm", "i"]
    lin = {a.tool: a for a in install.build_plan("linux", True, False)}
    assert lin["syft"].candidates[0][0] == "brew"
    assert lin["oxlint"].candidates[0][:2] == ["npm", "i"]
    assert "1.65.0" in " ".join(lin["oxlint"].candidates[0])


def test_python_tools_isolated_never_venv() -> None:
    plan = install.build_plan("linux", False, False)
    for a in plan:
        if a.tool in install.PYTHON_TOOLS and not a.skipped:
            assert a.candidates[0][:3] == ["uv", "tool", "install"]
            assert all(c[0] != "pip" for c in a.candidates)


def test_strict_gates_optionals() -> None:
    slim = {a.tool for a in install.build_plan("linux", False, False)}
    full = {a.tool for a in install.build_plan("linux", True, False)}
    assert "grype" not in slim and "grype" in full
    assert "opengrep" not in slim and "opengrep" in full


def test_check_delegates_to_verifier(monkeypatch) -> None:
    real_which = shutil.which
    monkeypatch.setattr(shutil, "which", lambda name: f"/fake/{name}")
    monkeypatch.setattr(sys, "platform", "linux")
    assert install.run_check(False, install.detect_platform(), False) == 0
    monkeypatch.setattr(shutil, "which", lambda name: None if name == "syft" else real_which(name))
    assert install.run_check(False, install.detect_platform(), False) == 1


def test_check_on_windows_warns_not_fails_for_guarddog(monkeypatch, capsys) -> None:
    real_which = shutil.which
    monkeypatch.setattr(shutil, "which", lambda name: None if name == "guarddog" else real_which(name))
    install.run_check(False, "windows", False)
    out = capsys.readouterr().out
    assert "WARN" in out and "guarddog" in out
    assert "- python:guarddog" not in out
