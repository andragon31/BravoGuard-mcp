"""Installer unit tests: platform dispatch mocked, dry-run never mutates."""

import importlib.util
import io
import json
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path


def load_install():
    path = Path(__file__).resolve().parents[1] / "scripts" / "install.py"
    spec = importlib.util.spec_from_file_location("bravoguard_install", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["bravoguard_install"] = mod
    spec.loader.exec_module(mod)
    return mod


def load_external():
    sys.path.insert(0, str(SCRIPTS))
    import install_external

    importlib.reload(install_external)
    return install_external


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


def test_check_binaries_gitleaks_satisfies_betterleaks(monkeypatch) -> None:
    ext = load_external()
    monkeypatch.setattr(shutil, "which", lambda name: "/fake/gitleaks" if name == "gitleaks" else None)
    assert ext.check_binaries(["betterleaks"]) == []
    assert ext.check_binaries(["betterleaks", "syft"]) == ["bin:syft (see tools-manifest.json)"]


def test_check_binaries_betterleaks_itself_satisfies(monkeypatch) -> None:
    ext = load_external()
    monkeypatch.setattr(shutil, "which", lambda name: "/fake/betterleaks" if name == "betterleaks" else None)
    assert ext.check_binaries(["betterleaks"]) == []


def test_check_binaries_neither_present_still_missing(monkeypatch) -> None:
    ext = load_external()
    monkeypatch.setattr(shutil, "which", lambda name: None)
    missing = ext.check_binaries(["betterleaks"])
    assert len(missing) == 1
    assert "betterleaks" in missing[0] and "gitleaks" in missing[0]


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


def test_go_modules_use_cmd_roots() -> None:
    assert install.GO_MODULES["syft"] == "github.com/anchore/syft/cmd/syft"
    assert install.GO_MODULES["grype"] == "github.com/anchore/grype/cmd/grype"
    plan = {a.tool: a for a in install.build_plan("linux", True, False)}
    syft_go = [c for c in plan["syft"].candidates if c[0] == "go"]
    assert syft_go == [["go", "install", "github.com/anchore/syft/cmd/syft@v1.51.1"]]
    grype_go = [c for c in plan["grype"].candidates if c[0] == "go"]
    assert grype_go == [["go", "install", "github.com/anchore/grype/cmd/grype@v0.118.0"]]


def test_release_asset_names_per_platform() -> None:
    assert install.release_asset("trivy", "linux", "0.74.0") == "trivy_0.74.0_Linux-64bit.tar.gz"
    assert install.release_asset("trivy", "windows", "0.74.0") == "trivy_0.74.0_windows-64bit.zip"
    assert install.release_asset("trivy", "macos", "0.74.0") == "trivy_0.74.0_macOS-64bit.tar.gz"
    assert install.release_asset("trufflehog", "linux", "v3.95.9") == "trufflehog_3.95.9_linux_amd64.tar.gz"
    assert install.release_asset("trufflehog", "windows", "v3.95.9") == "trufflehog_3.95.9_windows_amd64.tar.gz"
    assert install.release_asset("trufflehog", "macos", "v3.95.9") == "trufflehog_3.95.9_darwin_amd64.tar.gz"
    assert install.release_asset("syft", "linux", "1.51.1") == "syft_1.51.1_linux_amd64.tar.gz"
    assert install.release_asset("syft", "windows", "1.51.1") == "syft_1.51.1_windows_amd64.zip"
    assert install.release_asset("syft", "macos", "1.51.1") == "syft_1.51.1_darwin_amd64.tar.gz"
    assert install.release_asset("grype", "linux", "0.118.0") == "grype_0.118.0_linux_amd64.tar.gz"
    assert install.release_asset("grype", "windows", "0.118.0") == "grype_0.118.0_windows_amd64.zip"
    assert install.release_asset("grype", "macos", "0.118.0") == "grype_0.118.0_darwin_amd64.tar.gz"


def test_release_url_uses_v_tag() -> None:
    url = install.release_url("aquasecurity/trivy", "0.74.0", "trivy_0.74.0_windows-64bit.zip")
    assert url == "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_windows-64bit.zip"
    assert install.release_tag("v3.95.9") == "v3.95.9"
    assert install.release_tag("0.74.0") == "v0.74.0"


class _FakeAPI:
    def __init__(self, payload: bytes) -> None:
        self._stream = io.BytesIO(payload)

    def __enter__(self):
        return self._stream

    def __exit__(self, *args) -> bool:
        return False


def test_resolve_trufflehog_picks_newest_patch(monkeypatch) -> None:
    payload = json.dumps([{"tag_name": "v3.95.9"}, {"tag_name": "v3.95.8"}, {"tag_name": "v3.94.0"}]).encode()
    monkeypatch.setattr(install.urllib.request, "urlopen", lambda *a, **k: _FakeAPI(payload))
    assert install.resolve_trufflehog_version("v3.95.x") == "v3.95.9"


def test_resolve_trufflehog_offline_returns_none(monkeypatch) -> None:
    def _down(*args, **kwargs):
        raise OSError("offline")

    monkeypatch.setattr(install.urllib.request, "urlopen", _down)
    assert install.resolve_trufflehog_version("v3.95.x") is None


def test_resolve_trufflehog_exact_needs_no_network(monkeypatch) -> None:
    def _boom(*args, **kwargs):
        raise AssertionError("exact pins must not hit the network")

    monkeypatch.setattr(install.urllib.request, "urlopen", _boom)
    assert install.resolve_trufflehog_version("v3.95.9") == "v3.95.9"


def _make_tar_gz(path: Path, members: dict[str, bytes]) -> None:
    path.write_bytes(_tar_bytes(members))


def _tar_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_extract_release_binary_tar_gz(tmp_path) -> None:
    archive = tmp_path / "trivy.tar.gz"
    _make_tar_gz(archive, {"trivy": b"fake-trivy"})
    dest = tmp_path / "bin"
    assert install.extract_release_binary(archive, dest, "trivy") is True
    expected = "trivy.exe" if install.detect_platform() == "windows" else "trivy"
    assert (dest / expected).read_bytes() == b"fake-trivy"


def test_extract_release_binary_zip(tmp_path) -> None:
    archive = tmp_path / "trivy.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("trivy.exe", b"fake-trivy-exe")
    dest = tmp_path / "bin"
    assert install.extract_release_binary(archive, dest, "trivy") is True
    assert (dest / "trivy.exe").read_bytes() == b"fake-trivy-exe"


def test_extract_ignores_path_traversal(tmp_path) -> None:
    archive = tmp_path / "evil.tar.gz"
    _make_tar_gz(archive, {"../evil": b"nope", "trivy": b"real"})
    dest = tmp_path / "bin"
    assert install.extract_release_binary(archive, dest, "trivy") is True
    assert not (tmp_path / "evil").exists()
    assert dest.is_dir()


def test_download_guards_fail_before_network(monkeypatch) -> None:
    def _boom(*args, **kwargs):
        raise AssertionError("guards must fail before any download")

    monkeypatch.setattr(install.urllib.request, "urlopen", _boom)
    matrix = install.RELEASE_ASSETS["trivy"]
    assert install.download_release_binary("aquasecurity/trivy", "v3.95.x", matrix, Path(".")) is False
    monkeypatch.setattr(install, "detect_platform", lambda *a: "plan9")
    assert install.download_release_binary("aquasecurity/trivy", "0.74.0", matrix, Path(".")) is False


def test_download_release_writes_binary(monkeypatch, tmp_path) -> None:
    buf = _tar_bytes({"trivy": b"fake-trivy"})
    monkeypatch.setattr(install.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(buf))
    plat = install.detect_platform()
    dest = tmp_path / "bin"
    assert install.download_release_binary("aquasecurity/trivy", "0.74.0", {plat: "fake.tar.gz"}, dest) is True
    expected = "trivy.exe" if plat == "windows" else "trivy"
    assert (dest / expected).read_bytes() == b"fake-trivy"
    assert not (dest / "fake.tar.gz").exists()


def test_download_substitutes_version_placeholder(monkeypatch, tmp_path) -> None:
    plat = install.detect_platform()
    if plat == "windows":
        template, payload, binary = "pkg_{ver}.zip", _zip_bytes({"pkg.exe": b"fake"}), "pkg.exe"
    else:
        template, payload, binary = "pkg_{ver}.tar.gz", _tar_bytes({"pkg": b"fake"}), "pkg"
    seen: list[str] = []

    def _fake(req, **kwargs):
        seen.append(req.full_url)
        return io.BytesIO(payload)

    monkeypatch.setattr(install.urllib.request, "urlopen", _fake)
    assert install.download_release_binary("example/pkg", "v9.9.9", {plat: template}, tmp_path) is True
    expected_asset = template.format(ver="9.9.9")
    assert seen == [f"https://github.com/example/pkg/releases/download/v9.9.9/{expected_asset}"]
    assert (tmp_path / binary).read_bytes() == b"fake"


def _candidate_kinds(action) -> list[str]:
    return ["release" if c and c[0] == install.RELEASE_MARKER else c[0] for c in action.candidates]


def test_trivy_trufflehog_release_before_go() -> None:
    for plat in ("windows", "linux", "macos"):
        plan = {a.tool: a for a in install.build_plan(plat, False, False)}
        for tool in ("trivy", "trufflehog"):
            kinds = _candidate_kinds(plan[tool])
            assert kinds[0] == "release"
            assert "go" in kinds and kinds.index("release") < kinds.index("go")
        assert "github.com/trufflesecurity/trufflehog" in plan["trufflehog"].manual


def test_syft_grype_go_before_release() -> None:
    for plat in ("windows", "linux", "macos"):
        plan = {a.tool: a for a in install.build_plan(plat, True, False)}
        for tool in ("syft", "grype"):
            kinds = _candidate_kinds(plan[tool])
            assert "go" in kinds and "release" in kinds
            assert kinds.index("go") < kinds.index("release")


def test_install_release_trufflehog_offline_returns_false(monkeypatch) -> None:
    monkeypatch.setattr(install, "resolve_trufflehog_version", lambda pinned: None)
    assert install.install_release("trufflehog", "v3.95.x") is False


def test_execute_plan_release_needs_no_manager(monkeypatch, capsys) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.setattr(install, "install_release", lambda *a: True)
    action = install.Action(
        tool="trivy",
        version="0.74.0",
        candidates=[install.release_candidate("trivy", "0.74.0", "windows")],
    )
    assert install.execute_plan([action]) == 0
    assert "OK trivy" in capsys.readouterr().out


def test_execute_plan_release_failure_tries_go(monkeypatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/fake/{name}")
    calls: list[list[str]] = []

    def _run(cmd, **kwargs):
        calls.append(cmd)

    monkeypatch.setattr(install, "install_release", lambda *a: False)
    monkeypatch.setattr(install.subprocess, "run", _run)
    action = install.Action(
        tool="trivy",
        version="0.74.0",
        candidates=[install.release_candidate("trivy", "0.74.0", "linux"), ["go", "install", "x"]],
        manual="manual: install trivy by hand",
    )
    assert install.execute_plan([action]) == 0
    assert calls == [["go", "install", "x"]]


def test_dry_run_prints_release_chain(capsys) -> None:
    install.print_plan(install.build_plan("windows", False, False), "windows")
    out = capsys.readouterr().out
    assert "release: trivy 0.74.0 from https://github.com/aquasecurity/trivy/releases/download/" in out
    assert "trivy_0.74.0_windows-64bit.zip" in out
    assert "trufflehog v3.95.x (exact patch resolved at install)" in out
