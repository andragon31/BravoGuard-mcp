"""H1 supply-plus: typosquat + bundled-binary lane, opengrep release leg.

Unit + fixture tests for ``bravoguard.supply`` (pure Python, no subprocess),
the ``scan_repo`` supply job, the two new suggest templates, and the
opengrep release-binary installer chain (mocked network).
"""

import asyncio
import importlib.util
import io
import sys
from pathlib import Path

import pytest

from bravoguard import orchestrator
from bravoguard.owasp_map import explain_cwe
from bravoguard.suggest import suggest_for_finding
from bravoguard.supply import (
    BIN_CWE,
    BIN_RULE_ID,
    TYPO_CWE,
    TYPO_RULE_ID,
    find_typosquat_target,
    is_edit_distance_one,
    normalize_dep_name,
    parse_pyproject_dependencies,
    parse_requirement_name,
    scan_bundled_binaries,
    scan_supply,
    scan_typosquat,
)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# --- edit distance --------------------------------------------------------


def test_normalize_strips_case_and_separators() -> None:
    assert normalize_dep_name("Scikit-Learn") == "scikitlearn"
    assert normalize_dep_name("python_dateutil") == "pythondateutil"
    assert normalize_dep_name("requests") == "requests"


def test_distance_one_covers_insert_delete_substitute_and_swap() -> None:
    assert is_edit_distance_one("request", "requests")  # deletion
    assert is_edit_distance_one("requestss", "requests")  # insertion
    assert is_edit_distance_one("requesfs", "requests")  # substitution
    assert is_edit_distance_one("reqeusts", "requests")  # adjacent transposition
    assert is_edit_distance_one("flaks", "flask")  # adjacent transposition


def test_distance_rejects_equal_and_far() -> None:
    assert not is_edit_distance_one("requests", "requests")  # equal: legit dep
    assert not is_edit_distance_one("reqets", "requests")  # distance 2
    assert not is_edit_distance_one("resquest", "requests")  # swap + substitution
    assert not is_edit_distance_one("django", "flask")  # unrelated


def test_typosquat_hits_and_silences() -> None:
    assert find_typosquat_target(normalize_dep_name("reqeusts")) == "requests"
    assert find_typosquat_target(normalize_dep_name("numpi")) == "numpy"
    assert find_typosquat_target(normalize_dep_name("requests")) is None
    assert find_typosquat_target(normalize_dep_name("numpy")) is None
    assert find_typosquat_target(normalize_dep_name("obscure-unique-name")) is None
    assert find_typosquat_target(normalize_dep_name("box")) is None  # short-name gate


def test_typosquat_cwe_maps_to_a03() -> None:
    assert TYPO_CWE == "CWE-1357"
    assert explain_cwe(TYPO_CWE)["owasp_2025"] == "A03"
    assert BIN_CWE == "CWE-506"
    assert explain_cwe(BIN_CWE)["owasp_2025"] == "A08"


# --- requirement parsing --------------------------------------------------


def test_requirement_name_tolerant_parsing() -> None:
    assert parse_requirement_name("requests==2.32.3") == "requests"
    assert parse_requirement_name("Django>=4.2  # web") == "Django"
    assert parse_requirement_name("uvicorn[standard]>=0.20") == "uvicorn"
    assert parse_requirement_name('pywin32; sys_platform=="win32"') == "pywin32"
    assert parse_requirement_name("# comment") is None
    assert parse_requirement_name("") is None
    assert parse_requirement_name("-r base.txt") is None
    assert parse_requirement_name("--index-url https://x") is None
    assert parse_requirement_name("https://example.com/pkg.tar.gz") is None
    assert parse_requirement_name("git+https://github.com/x/y.git") is None


def test_pyproject_required_only(tmp_path: Path) -> None:
    _write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "demo"\ndependencies = ["reqeusts>=2", "click==8"]\n'
        '[project.optional-dependencies]\ntest = ["numpi"]\n',
    )
    pairs = parse_pyproject_dependencies(tmp_path / "pyproject.toml")
    assert ("reqeusts", 0) in pairs
    assert all(name != "numpi" for name, _ in pairs)  # extras stay out


# --- typosquat lane -------------------------------------------------------


def _fixture_repo(root: Path) -> Path:
    _write(
        root / "requirements.txt",
        "# demo\nrequests==2.32.3\nreqeusts==2.32.3\nnumpy\nnumpi\n"
        "obscure-unique-name==1.0\n-r base.txt\nhttps://example.com/x.tar.gz\n",
    )
    _write(root / "src" / "ok.py", "x = 1\n")
    return root


def test_scan_typosquat_flags_only_distance_one(tmp_path: Path) -> None:
    findings = scan_typosquat(_fixture_repo(tmp_path), ())
    by_dep = {f["message"].split("'")[1]: f for f in findings}
    assert set(by_dep) == {"reqeusts", "numpi"}
    for finding in findings:
        assert finding["rule_id"] == TYPO_RULE_ID
        assert finding["cwe"] == "CWE-1357"
        assert finding["severity"] == "MEDIUM"
        assert finding["path"] == "requirements.txt"
    assert by_dep["reqeusts"]["line"] == 3
    assert "requests" in by_dep["reqeusts"]["message"]


def test_scan_typosquat_respects_excludes(tmp_path: Path) -> None:
    root = _fixture_repo(tmp_path)
    assert scan_typosquat(root, ("requirements.txt",)) == []


# --- bundled-binary lane --------------------------------------------------


def test_scan_bundled_binaries_flags_exe_and_reviews(tmp_path: Path) -> None:
    _write(tmp_path / "tools" / "app.exe", "MZfake")
    _write(tmp_path / "src" / "ok.py", "x = 1\n")
    findings = scan_bundled_binaries(tmp_path, ())
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == BIN_RULE_ID
    assert finding["cwe"] == "CWE-506"
    assert finding["severity"] == "LOW"
    assert finding["path"] == "tools/app.exe"
    assert "review" in finding["message"].lower()
    assert "legitimate" in finding["message"].lower()


def test_scan_bundled_binaries_silent_source_and_venv(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "ok.py", "x = 1\n")
    assert scan_bundled_binaries(tmp_path, ()) == []
    _write(tmp_path / ".venv" / "lib" / "vendored.dll", "fake")
    defaults = orchestrator.DEFAULT_EXCLUDES
    assert scan_bundled_binaries(tmp_path, defaults) == []


def test_scan_bundled_binaries_honors_dir_excludes(tmp_path: Path) -> None:
    _write(tmp_path / "vendored" / "tool.so", "fake")
    assert len(scan_bundled_binaries(tmp_path, ())) == 1
    assert scan_bundled_binaries(tmp_path, ("vendored/",)) == []
    # Named-file excludes silence one binary without lifting the lane.
    assert scan_bundled_binaries(tmp_path, ("tool.so",)) == []


def test_scan_bundled_binaries_extension_globs_do_not_silence(tmp_path: Path) -> None:
    # Bare *.exe-style globs are engine-oriented defaults lifted for this
    # lane (documented in supply.py); the lane still fires.
    _write(tmp_path / "tools" / "app.exe", "MZfake")
    assert len(scan_bundled_binaries(tmp_path, ("*.exe",))) == 1


def test_scan_supply_missing_path_is_empty(tmp_path: Path) -> None:
    assert scan_supply(tmp_path / "nope", ()) == []


# --- scan_repo wiring -----------------------------------------------------


class _FakeProcess:
    def __init__(self, stdout: bytes, returncode: int = 0) -> None:
        self._stdout = stdout
        self.returncode = returncode

    async def communicate(self, input_data=None):
        return (self._stdout, b"")

    def kill(self) -> None:
        pass

    async def wait(self) -> int:
        return self.returncode


def _quiet_subprocesses(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_create(*argv: str, **kwargs: object) -> _FakeProcess:
        names = {Path(str(a)).name for a in argv}
        if "oxlint" in names:
            return _FakeProcess(b'{"diagnostics": []}', 0)
        if "trivy" in names:
            return _FakeProcess(b"{}", 0)
        if "uv" in names:
            return _FakeProcess(b'{"results": {"failed_checks": []}}', 0)
        label = Path(str(argv[0])).name
        quiet = {
            "semgrep": b'{"results": []}',
            "bandit": b'{"results": []}',
            "betterleaks": b"[]",
        }
        if label in quiet:
            return _FakeProcess(quiet[label], 0)
        raise FileNotFoundError(label)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)


def test_scan_repo_supply_job_flags_typosquat_and_binexe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fixture_repo(tmp_path)
    _write(tmp_path / "tools" / "app.exe", "MZfake")
    _quiet_subprocesses(monkeypatch)
    result = asyncio.run(orchestrator.scan_repo(str(tmp_path)))
    assert result["status"] == "ok"
    assert "errors" not in result
    rules = {f["rule_id"] for f in result["findings"]}
    assert TYPO_RULE_ID in rules
    assert BIN_RULE_ID in rules


def test_scan_diff_has_no_supply_lane(monkeypatch: pytest.MonkeyPatch) -> None:
    _quiet_subprocesses(monkeypatch)
    diff = (
        "diff --git a/requirements.txt b/requirements.txt\n"
        "+++ b/requirements.txt\n"
        "+reqeusts==2.0\n"
    )
    result = asyncio.run(orchestrator.scan_diff(diff))
    assert all(
        f["rule_id"] not in (TYPO_RULE_ID, BIN_RULE_ID) for f in result["findings"]
    )


# --- suggest templates ----------------------------------------------------


def test_suggest_typosquat_and_binex_templates() -> None:
    typo = suggest_for_finding(
        {"rule_id": TYPO_RULE_ID, "cwe": "CWE-1357", "fix_hint": ""}
    )
    assert "pin" in typo["suggestion"].lower()
    assert typo["owasp_ref"] == "A03"
    binexe = suggest_for_finding(
        {"rule_id": BIN_RULE_ID, "cwe": "CWE-506", "fix_hint": ""}
    )
    assert "rebuild" in binexe["suggestion"].lower()
    assert binexe["owasp_ref"] == "A08"


# --- opengrep installer leg -----------------------------------------------


def _load_install():
    path = Path(__file__).resolve().parents[1] / "scripts" / "install.py"
    spec = importlib.util.spec_from_file_location("bravoguard_install_h1", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["bravoguard_install_h1"] = mod
    spec.loader.exec_module(mod)
    return mod


install = _load_install()


def test_opengrep_release_assets_per_platform() -> None:
    assert install.release_asset("opengrep", "linux", "v1.26.0") == "opengrep_manylinux_x86"
    assert install.release_asset("opengrep", "windows", "v1.26.0") == "opengrep_windows_x86.exe"
    assert install.release_asset("opengrep", "macos", "v1.26.0") == "opengrep_osx_arm64"


def test_opengrep_release_before_go_and_manual() -> None:
    for plat in ("windows", "linux", "macos"):
        plan = {a.tool: a for a in install.build_plan(plat, True, False)}
        action = plan["opengrep"]
        assert action.version == "v1.26.0"  # manifest unbumped: exe in v1.26.0
        kinds = [
            "release" if c and c[0] == install.RELEASE_MARKER else c[0]
            for c in action.candidates
        ]
        assert kinds[0] == "release"
        assert "go" in kinds and kinds.index("release") < kinds.index("go")
        assert "opengrep/opengrep" in action.manual


def test_opengrep_dry_run_shows_release_chain(capsys) -> None:
    install.print_plan(install.build_plan("windows", True, False), "windows")
    out = capsys.readouterr().out
    assert "release: opengrep v1.26.0 from https://github.com/opengrep/opengrep/releases/download/" in out
    assert "opengrep_windows_x86.exe" in out


def test_download_bare_binary_renames_to_engine(monkeypatch, tmp_path) -> None:
    payload = b"fake-opengrep-binary"

    def _fake(req, **kwargs):
        return io.BytesIO(payload)

    monkeypatch.setattr(install.urllib.request, "urlopen", _fake)
    plat = install.detect_platform()
    matrix = {plat: "binary-no-version"}
    assert install.download_release_binary("example/opengrep", "v1.26.0", matrix, tmp_path) is True
    expected = "opengrep.exe" if plat == "windows" else "opengrep"
    assert (tmp_path / expected).read_bytes() == payload
    assert not (tmp_path / "binary-no-version").exists()


def test_download_bare_binary_guards_before_network(monkeypatch) -> None:
    def _boom(*args, **kwargs):
        raise AssertionError("guards must fail before any download")

    monkeypatch.setattr(install.urllib.request, "urlopen", _boom)
    matrix = install.RELEASE_ASSETS["opengrep"]
    assert install.download_release_binary("opengrep/opengrep", "v3.95.x", matrix, Path(".")) is False
    monkeypatch.setattr(install, "detect_platform", lambda *a: "plan9")
    assert install.download_release_binary("opengrep/opengrep", "v1.26.0", matrix, Path(".")) is False
