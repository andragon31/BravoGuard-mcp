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
    assert "--yes" in out
    if install.detect_platform() == "windows":
        assert "SKIP guarddog" in out
    else:
        assert "guarddog==latest" in out


def test_manifest_pins_respected() -> None:
    manifest = json.loads((install.ROOT / "tools-manifest.json").read_text(encoding="utf-8"))
    expected = {b["name"]: b["version"] for b in manifest["binaries"]}
    plan = install.build_plan("linux", True, False)
    got = {a.tool: a.version for a in plan if a.tool in expected}
    assert got == expected


def test_windows_prefers_winget_linux_prefers_brew() -> None:
    win = {a.tool: a for a in install.build_plan("windows", True, False)}
    assert win["syft"].candidates[0][0] == "winget"
    # Windows .cmd shims need cmd /c under subprocess (bare scoop/npm hit WinError 2).
    assert win["oxlint"].candidates[0][:3] == ["cmd", "/c", "npm"]
    scoop_cmds = [c for c in win["syft"].candidates if "scoop" in c]
    assert scoop_cmds and scoop_cmds[0][:2] == ["cmd", "/c"]
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


def test_osv_scanner_uses_v2_module_path() -> None:
    plan = {a.tool: a for a in install.build_plan("windows", False, False)}
    go_cmds = [c for c in plan["osv-scanner"].candidates if c[0] == "go"]
    assert len(go_cmds) == 1
    assert go_cmds[0] == ["go", "install", "github.com/google/osv-scanner/v2/cmd/osv-scanner@latest"]
    lin = {a.tool: a for a in install.build_plan("linux", False, False)}
    lin_go = [c for c in lin["osv-scanner"].candidates if c[0] == "go"]
    assert lin_go[0] == ["go", "install", "github.com/google/osv-scanner/v2/cmd/osv-scanner@latest"]


def test_betterleaks_falls_back_to_gitleaks_v8() -> None:
    for plat in ("windows", "linux"):
        plan = {a.tool: a for a in install.build_plan(plat, False, False)}
        go_cmds = [c for c in plan["betterleaks"].candidates if c[0] == "go"]
        assert go_cmds == [
            ["go", "install", "github.com/gitleaks/betterleaks@latest"],
            ["go", "install", "github.com/zricethezav/gitleaks/v8@latest"],
        ]


def test_windows_wraps_cmd_shims_linux_stays_bare(monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    win = {a.tool: a for a in install.build_plan("windows", True, False)}
    assert install.detect_platform() == "windows"
    assert win["oxlint"].candidates[0][:3] == ["cmd", "/c", "npm"]
    scoop_cmds = [c for c in win["syft"].candidates if "scoop" in c]
    assert scoop_cmds and scoop_cmds[0][:2] == ["cmd", "/c"]
    choco_cmds = [c for c in win["syft"].candidates if c[0] == "choco"]
    assert choco_cmds and choco_cmds[0][0] == "choco"
    winget_cmds = [c for c in win["syft"].candidates if c[0] == "winget"]
    assert winget_cmds and winget_cmds[0][0] == "winget"
    monkeypatch.setattr(sys, "platform", "linux")
    lin = {a.tool: a for a in install.build_plan("linux", True, False)}
    assert lin["oxlint"].candidates[0][0] == "npm"
    assert all(c[0] != "cmd" for c in lin["oxlint"].candidates)


def test_execute_plan_tries_next_candidate(monkeypatch, capsys) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/fake/{name}")
    calls: list[list[str]] = []

    def _run(cmd, **kwargs):
        calls.append(cmd)
        if len(calls) == 1:
            raise install.subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(install.subprocess, "run", _run)
    action = install.Action(
        tool="demo",
        version="1.0",
        candidates=[["fakemgr-a", "install", "demo"], ["fakemgr-b", "install", "demo"]],
    )
    assert install.execute_plan([action]) == 0
    assert calls == [["fakemgr-a", "install", "demo"], ["fakemgr-b", "install", "demo"]]
    out = capsys.readouterr().out
    assert "RUN demo" in out and "RETRY demo" in out and "OK demo" in out


def test_execute_plan_all_fail_counts_once(monkeypatch, capsys) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/fake/{name}")
    calls: list[list[str]] = []

    def _fail(cmd, **kwargs):
        calls.append(cmd)
        raise install.subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(install.subprocess, "run", _fail)
    action = install.Action(
        tool="demo",
        version="1.0",
        candidates=[["fakemgr-a", "install", "demo"], ["fakemgr-b", "install", "demo"]],
        manual="manual: install demo by hand",
    )
    assert install.execute_plan([action]) == 1
    assert len(calls) == 2
    out = capsys.readouterr().out
    assert "FAIL demo" in out and "fallback: manual: install demo by hand" in out


def test_execute_plan_resolves_cmd_shim_target(monkeypatch, capsys) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/fake/{name}" if name == "scoop" else None)
    seen: list[list[str]] = []

    def _run(cmd, **kwargs):
        seen.append(cmd)

    monkeypatch.setattr(install.subprocess, "run", _run)
    action = install.Action(
        tool="syft",
        version="1.0",
        candidates=[["cmd", "/c", "scoop", "install", "syft"]],
    )
    assert install.execute_plan([action]) == 0
    assert seen == [["cmd", "/c", "scoop", "install", "syft"]]
    assert "OK syft" in capsys.readouterr().out
