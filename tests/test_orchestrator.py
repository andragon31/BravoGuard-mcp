"""T1 orchestrator tests: subprocess fan-out with fake scanner binaries."""

import asyncio
import json
import os
import shutil
import signal
import subprocess
import tempfile
from pathlib import Path
from typing import Self

import pytest

from bravoguard import orchestrator
from bravoguard.orchestrator import FINDING_KEYS

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


class FakeProcess:
    """Minimal stand-in for asyncio.subprocess.Process."""

    def __init__(self, stdout: bytes, returncode: int = 0, hang: bool = False) -> None:
        self._stdout = stdout
        self.returncode = returncode
        self._hang = hang
        self.killed = False

    async def communicate(self, input_data=None):
        if self._hang:
            await asyncio.sleep(30)
        return (self._stdout, b"")

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> int:
        return self.returncode


def install_fake(monkeypatch: pytest.MonkeyPatch, responses: dict, calls: list) -> None:
    """Patch create_subprocess_exec so each binary returns canned stdout."""

    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append((list(argv), dict(kwargs)))
        assert "shell" not in kwargs, "scanners must never run with shell=True"
        name = Path(str(argv[0])).name
        if name not in responses:
            raise FileNotFoundError(name)
        spec = responses[name]
        if isinstance(spec, FakeProcess):
            return spec
        stdout, returncode = spec
        return FakeProcess(stdout, returncode)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)


def semgrep_pickle_payload() -> bytes:
    return json.dumps(
        {
            "version": "1.176.0",
            "results": [
                {
                    "check_id": "bravoguard-python-pickle-load",
                    "path": "app.py",
                    "start": {"line": 3, "col": 5},
                    "end": {"line": 3, "col": 20},
                    "extra": {
                        "message": "Avoid pickle.load on untrusted input (CWE-502).",
                        "severity": "ERROR",
                        "metadata": {
                            "cwe": "CWE-502",
                            "owasp_2025": "A08",
                            "fix_hint": "Replace pickle.load with json.load.",
                        },
                    },
                }
            ],
            "errors": [],
        }
    ).encode()


def quiet_responses(**overrides: object) -> dict:
    responses: dict = {
        "semgrep": (b'{"results": []}', 0),
        "bandit": (b'{"results": []}', 0),
        "betterleaks": (b"[]", 0),
        # M1 lanes: trivy direct, checkov always via `uv tool run`, oxlint
        # bare on POSIX but `cmd /c oxlint` on win32 (argv[0] == "cmd").
        "trivy": (b"{}", 0),
        "uv": (b'{"results": {"failed_checks": []}}', 0),
        "oxlint": (b'{"diagnostics": []}', 0),
        "cmd": (b'{"diagnostics": []}', 0),
    }
    responses.update(overrides)
    return responses


def test_scan_diff_seeded_returns_finding_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list = []
    install_fake(
        monkeypatch,
        quiet_responses(semgrep=(semgrep_pickle_payload(), 1)),
        calls,
    )
    result = asyncio.run(orchestrator.scan_diff(SEED_DIFF))
    assert result["status"] == "ok"
    assert len(result["findings"]) >= 1
    finding = result["findings"][0]
    assert set(finding) == set(FINDING_KEYS)
    assert finding["rule_id"] == "bravoguard-python-pickle-load"
    assert finding["cwe"] == "CWE-502"
    assert finding["line"] == 3
    argv = calls[0][0]
    assert "--config" in argv and "--json" in argv


def test_scan_diff_empty_guard() -> None:
    assert asyncio.run(orchestrator.scan_diff("   ")) == {"status": "empty-diff", "findings": []}


def test_scan_diff_bandit_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    bandit = json.dumps(
        {
            "results": [
                {
                    "filename": "app.py",
                    "line_number": 3,
                    "test_id": "B301",
                    "test_name": "blacklist",
                    "issue_severity": "MEDIUM",
                    "issue_text": "Pickle and modules that wrap it can be unsafe.",
                    "issue_cwe": {"id": 502},
                }
            ],
            "errors": [],
        }
    ).encode()
    install_fake(monkeypatch, quiet_responses(bandit=(bandit, 1)), calls)
    result = asyncio.run(orchestrator.scan_diff(SEED_DIFF))
    bandit_finding = next(f for f in result["findings"] if f["rule_id"] == "B301")
    assert set(bandit_finding) == set(FINDING_KEYS)
    assert bandit_finding["cwe"] == "CWE-502"


def test_betterleaks_secrets_never_propagated(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    leaks = json.dumps(
        [
            {
                "Description": "Generic API Key",
                "RuleID": "generic-api-key",
                "File": "app.py",
                "StartLine": 2,
                "Secret": "sk-live-abcdef123456",
                "Match": "api_key = 'sk-live-abcdef123456'",
            }
        ]
    ).encode()
    install_fake(monkeypatch, quiet_responses(betterleaks=(leaks, 0)), calls)
    result = asyncio.run(orchestrator.scan_diff(SEED_DIFF))
    assert "sk-live-abcdef123456" not in json.dumps(result)
    leak = next(f for f in result["findings"] if f["rule_id"] == "generic-api-key")
    assert set(leak) == set(FINDING_KEYS)
    assert leak["cwe"] == "CWE-798"


def test_opengrep_fallback_when_semgrep_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    responses = quiet_responses(opengrep=(semgrep_pickle_payload(), 0))
    del responses["semgrep"]
    install_fake(monkeypatch, responses, calls)
    result = asyncio.run(orchestrator.scan_diff(SEED_DIFF))
    assert len(result["findings"]) >= 1
    binaries = {Path(argv[0]).name for argv, _ in calls}
    assert {"semgrep", "opengrep", "bandit", "betterleaks"} <= binaries


def test_scanner_timeout_recorded_as_error(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    hanging = FakeProcess(b"", hang=True)
    install_fake(monkeypatch, quiet_responses(semgrep=hanging), calls)
    result = asyncio.run(orchestrator.scan_diff(SEED_DIFF, timeout=0.05))
    assert result["status"] == "ok"
    assert result["errors"]["sast"] == "timeout"
    assert hanging.killed


def test_scan_repo_rejects_traversal(tmp_path: Path) -> None:
    with pytest.raises(orchestrator.ScanPathError):
        orchestrator.resolve_scan_path("../..", tmp_path)
    outside = tmp_path.parent / "outside"
    outside.mkdir(exist_ok=True)
    with pytest.raises(orchestrator.ScanPathError):
        orchestrator.resolve_scan_path(str(outside), tmp_path)
    result = asyncio.run(orchestrator.scan_repo("../..", allowed_root=tmp_path))
    assert result["status"] == "invalid-path"
    assert asyncio.run(orchestrator.scan_repo("   "))["status"] == "empty-path"
    missing = asyncio.run(orchestrator.scan_repo(str(tmp_path / "nope"), allowed_root=tmp_path))
    assert missing == {"status": "invalid-path", "findings": [], "reason": "not-found"}


def test_scan_repo_accepts_valid_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_repo(str(tmp_path)))
    assert result == {"status": "ok", "findings": []}
    bandit_argv = next(argv for argv, _ in calls if Path(argv[0]).name == "bandit")
    assert str(tmp_path) in bandit_argv


def test_diff_without_headers_falls_back_to_snippet(tmp_path: Path) -> None:
    written = orchestrator.materialize_diff_files("+eval(data)\n", tmp_path)
    assert [p.name for p in written] == ["snippet.py"]
    assert "eval(data)" in written[0].read_text(encoding="utf-8")


def test_server_delegates_to_orchestrator() -> None:
    import inspect

    from bravoguard import server

    source = inspect.getsource(server)
    assert "_run_with_timeout" not in source
    assert "orchestrator.scan_diff" in source
    assert "orchestrator.scan_repo" in source


def test_missing_betterleaks_recorded_without_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list = []
    responses = quiet_responses()
    del responses["betterleaks"]
    install_fake(monkeypatch, responses, calls)
    result = asyncio.run(orchestrator.scan_diff(SEED_DIFF))
    assert result["status"] == "ok"
    assert result["errors"]["betterleaks"] == "not-installed"


def test_all_scanners_missing_stays_ok_with_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list = []
    install_fake(monkeypatch, {}, calls)
    result = asyncio.run(orchestrator.scan_diff(SEED_DIFF))
    assert result["status"] == "ok"
    assert result["findings"] == []
    assert set(result["errors"]) == {"sast", "bandit", "betterleaks"}
    assert all(reason == "not-installed" for reason in result["errors"].values())


def test_scanner_argv_match_manifest_pins() -> None:
    from bravoguard.osv import osv_scanner_argv, pip_audit_argv

    assert osv_scanner_argv("pkg", "1.0") == [
        "osv-scanner",
        "--package",
        "pkg",
        "--version",
        "1.0",
        "--format",
        "json",
    ]
    assert pip_audit_argv("req.txt") == ["pip-audit", "-r", "req.txt", "--format=json"]
    assert orchestrator.betterleaks_path_argv("repo") == [
        "betterleaks",
        "detect",
        "--no-git",
        "--source",
        "repo",
    ]


def test_secrets_falls_back_to_gitleaks_when_betterleaks_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        shutil, "which", lambda name: "/usr/local/bin/gitleaks" if name == "gitleaks" else None
    )
    assert orchestrator.resolve_secrets_binary() == "gitleaks"
    calls: list = []
    leaks = json.dumps(
        [
            {
                "Description": "Generic API Key",
                "RuleID": "generic-api-key",
                "File": "app.py",
                "StartLine": 2,
                "Secret": "sk-live-abcdef123456",
                "Match": "api_key = 'sk-live-abcdef123456'",
            }
        ]
    ).encode()

    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append((list(argv), dict(kwargs)))
        assert "shell" not in kwargs, "scanners must never run with shell=True"
        name = Path(str(argv[0])).name
        if name == "betterleaks":
            raise FileNotFoundError(name)
        if name == "gitleaks":
            # This gitleaks build prints only logs to stdout: findings arrive
            # via the --report-path tmpfile, which the fake writes here.
            arglist = list(argv)
            assert "--report-path" in arglist
            report = arglist[arglist.index("--report-path") + 1]
            Path(report).write_bytes(leaks)
            return FakeProcess(b"INF scanned (stdout carries logs only)", 1)
        if name in ("semgrep", "bandit"):
            return FakeProcess(b'{"results": []}', 0)
        raise FileNotFoundError(name)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)
    result = asyncio.run(orchestrator.scan_diff(SEED_DIFF))
    assert "sk-live-abcdef123456" not in json.dumps(result)
    assert any(f["rule_id"] == "generic-api-key" for f in result["findings"])
    gitleaks_argv = next(argv for argv, _ in calls if Path(argv[0]).name == "gitleaks")
    assert "--report-path" in gitleaks_argv
    binaries = {Path(argv[0]).name for argv, _ in calls}
    assert {"betterleaks", "gitleaks"} <= binaries


def test_gitleaks_report_tmpfile_deleted_after_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        shutil, "which", lambda name: "/usr/local/bin/gitleaks" if name == "gitleaks" else None
    )
    report = tmp_path / "gitleaks-report.json"

    class _Tmp:
        name = str(report)

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *args: object) -> bool:
            return False

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", lambda **kwargs: _Tmp())
    leaks = json.dumps(
        [
            {
                "Description": "Generic API Key",
                "RuleID": "generic-api-key",
                "File": "app.py",
                "StartLine": 2,
                "Secret": "sk-live-abcdef123456",
                "Match": "api_key = 'sk-live-abcdef123456'",
            }
        ]
    ).encode()
    calls: list = []

    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append(list(argv))
        if Path(str(argv[0])).name == "gitleaks":
            arglist = list(argv)
            assert arglist[arglist.index("--report-path") + 1] == str(report)
            Path(str(report)).write_bytes(leaks)
            return FakeProcess(b"INF scanned (stdout carries logs only)", 1)
        if Path(str(argv[0])).name == "betterleaks":
            raise FileNotFoundError("betterleaks")
        return FakeProcess(b'{"results": []}', 0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)
    result = asyncio.run(orchestrator.scan_diff(SEED_DIFF))
    assert any(f["rule_id"] == "generic-api-key" for f in result["findings"])
    assert not report.exists()


def test_gitleaks_missing_report_surfaces_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        shutil, "which", lambda name: "/usr/local/bin/gitleaks" if name == "gitleaks" else None
    )
    calls: list = []

    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append(list(argv))
        if Path(str(argv[0])).name == "betterleaks":
            raise FileNotFoundError("betterleaks")
        if Path(str(argv[0])).name == "gitleaks":
            return FakeProcess(b"INF scanned (stdout carries logs only)", 1)
        return FakeProcess(b'{"results": []}', 0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)
    result = asyncio.run(orchestrator.scan_diff(SEED_DIFF))
    assert result["status"] == "ok"
    assert result["errors"]["betterleaks"] == "failed"


def test_secrets_both_absent_records_not_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert orchestrator.resolve_secrets_binary() is None
    calls: list = []
    responses = quiet_responses()
    del responses["betterleaks"]
    install_fake(monkeypatch, responses, calls)
    result = asyncio.run(orchestrator.scan_diff(SEED_DIFF))
    assert result["status"] == "ok"
    assert result["errors"]["betterleaks"] == "not-installed"


def test_secrets_path_argv_flags_identical_for_both_engines() -> None:
    assert orchestrator.betterleaks_path_argv("repo", "gitleaks") == [
        "gitleaks",
        "detect",
        "--no-git",
        "--source",
        "repo",
    ]
    assert (
        orchestrator.betterleaks_path_argv("repo", "gitleaks")[1:]
        == orchestrator.betterleaks_path_argv("repo")[1:]
    )


SECRET_DIFF = """\
diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -0,0 +1 @@
+api_key = "sk-live-abcdef1234567890"
"""


def _leak_payload() -> bytes:
    return json.dumps(
        [
            {
                "Description": "Generic API Key",
                "RuleID": "generic-api-key",
                "File": "app.py",
                "StartLine": 1,
                "Secret": "sk-live-abcdef1234567890",
                "Match": "api_key = 'sk-live-abcdef1234567890'",
            }
        ]
    ).encode()


def test_scan_diff_secrets_path_mode_on_workdir(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list = []
    install_fake(
        monkeypatch,
        quiet_responses(betterleaks=(_leak_payload(), 1)),
        calls,
    )
    result = asyncio.run(orchestrator.scan_diff(SECRET_DIFF))
    assert any(f["rule_id"] == "generic-api-key" for f in result["findings"])
    assert "sk-live-abcdef1234567890" not in json.dumps(result)
    argv, kwargs = next(
        (argv, kwargs) for argv, kwargs in calls if Path(argv[0]).name == "betterleaks"
    )
    source = argv[argv.index("--source") + 1]
    assert source != "-"
    assert "bravoguard-diff-" in source
    assert kwargs.get("stdin") == asyncio.subprocess.DEVNULL


def test_scan_diff_secrets_gitleaks_fallback_path_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        shutil, "which", lambda name: "/usr/local/bin/gitleaks" if name == "gitleaks" else None
    )
    calls: list = []

    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append((list(argv), dict(kwargs)))
        name = Path(str(argv[0])).name
        if name == "betterleaks":
            raise FileNotFoundError(name)
        if name == "gitleaks":
            arglist = list(argv)
            assert "--report-path" in arglist
            report = arglist[arglist.index("--report-path") + 1]
            Path(report).write_bytes(_leak_payload())
            return FakeProcess(b"INF scanned (stdout carries logs only)", 1)
        if name in ("semgrep", "bandit"):
            return FakeProcess(b'{"results": []}', 0)
        raise FileNotFoundError(name)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)
    result = asyncio.run(orchestrator.scan_diff(SECRET_DIFF))
    assert any(f["rule_id"] == "generic-api-key" for f in result["findings"])
    assert "sk-live-abcdef1234567890" not in json.dumps(result)
    assert "betterleaks" not in result.get("errors", {})
    argv, kwargs = next(
        (argv, kwargs) for argv, kwargs in calls if Path(argv[0]).name == "gitleaks"
    )
    source = argv[argv.index("--source") + 1]
    assert source != "-"
    assert "bravoguard-diff-" in source
    assert kwargs.get("stdin") == asyncio.subprocess.DEVNULL


def test_scan_diff_all_excluded_skips_secrets_lane(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    venv_diff = (
        "diff --git a/.venv/evil.py b/.venv/evil.py\n"
        "index 1111111..2222222 100644\n"
        "--- a/.venv/evil.py\n"
        "+++ b/.venv/evil.py\n"
        "@@ -0,0 +1 @@\n"
        "+assert True\n"
    )
    result = asyncio.run(orchestrator.scan_diff(venv_diff))
    assert result["status"] == "ok"
    assert result["findings"] == []
    assert "betterleaks" not in {Path(argv[0]).name for argv, _ in calls}
    assert "betterleaks" not in result.get("errors", {})


def _cwd_to(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: root))


def test_materialize_base_prefers_repo_local_when_writable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _cwd_to(monkeypatch, tmp_path)
    base = orchestrator.materialize_base()
    assert base == tmp_path / ".bravoguard" / "tmp"
    assert base.is_dir()


def test_materialize_base_falls_back_when_mkdir_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _cwd_to(monkeypatch, tmp_path)
    real_mkdir = Path.mkdir

    def fail_mkdir(self: Path, *args: object, **kwargs: object) -> None:
        if self == tmp_path / ".bravoguard" / "tmp":
            raise OSError("read-only mount")
        real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fail_mkdir)
    assert orchestrator.materialize_base() == Path(tempfile.gettempdir())


def test_materialize_base_falls_back_when_probe_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _cwd_to(monkeypatch, tmp_path)

    def fail_probe(**kwargs: object) -> object:
        raise OSError("not writable")

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", fail_probe)
    assert orchestrator.materialize_base() == Path(tempfile.gettempdir())


def test_scan_diff_materializes_under_repo_local_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _cwd_to(monkeypatch, tmp_path)
    calls: list = []
    install_fake(
        monkeypatch,
        quiet_responses(semgrep=(semgrep_pickle_payload(), 1)),
        calls,
    )
    result = asyncio.run(orchestrator.scan_diff(SEED_DIFF))
    assert result["status"] == "ok"
    assert len(result["findings"]) >= 1
    target = Path(calls[0][0][-1])
    assert target.is_relative_to(tmp_path / ".bravoguard" / "tmp")
    assert not target.exists()
    assert list((tmp_path / ".bravoguard" / "tmp").glob("bravoguard-diff-*")) == []


def test_scan_diff_cleans_materialized_tree_on_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _cwd_to(monkeypatch, tmp_path)
    hanging = FakeProcess(b"", hang=True)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(semgrep=hanging), calls)
    result = asyncio.run(orchestrator.scan_diff(SEED_DIFF, timeout=0.05))
    assert result["status"] == "ok"
    assert result["errors"]["sast"] == "timeout"
    assert hanging.killed
    assert list((tmp_path / ".bravoguard" / "tmp").glob("bravoguard-diff-*")) == []


def _patch_hanging_fake(monkeypatch: pytest.MonkeyPatch, binary: str, proc: FakeProcess, calls: list) -> None:
    """Patch spawn to return ``proc`` for ``binary`` without touching Path.

    The shared ``install_fake`` resolves names via ``Path(...).name``, which
    breaks while ``os.name`` is spoofed cross-platform (Path dispatches on
    ``os.name``), so tree-kill tests use this exact-match fake instead.
    """

    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append((list(argv), dict(kwargs)))
        assert "shell" not in kwargs, "scanners must never run with shell=True"
        assert argv[0] == binary
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)


def test_timeout_kills_tree_on_win32(monkeypatch: pytest.MonkeyPatch) -> None:
    taskkill_calls: list = []
    run_kwargs: list = []

    def fake_run(argv: object, **kwargs: object) -> object:
        taskkill_calls.append(list(argv))  # type: ignore[arg-type]
        run_kwargs.append(dict(kwargs))
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(orchestrator.subprocess, "run", fake_run)
    hanging = FakeProcess(b"", hang=True)
    hanging.pid = 4242  # type: ignore[attr-defined]
    calls: list = []
    _patch_hanging_fake(monkeypatch, "fake-scanner", hanging, calls)
    real_name = os.name
    os.name = "nt"  # type: ignore[assignment]
    try:
        with pytest.raises(orchestrator.ScannerTimeoutError):
            asyncio.run(orchestrator.run_scanner_json(["fake-scanner"], input_data=None, timeout=0.05))
    finally:
        os.name = real_name  # type: ignore[assignment]
    assert taskkill_calls == [["taskkill.exe", "/F", "/T", "/PID", "4242"]]
    assert all("shell" not in kwargs for kwargs in run_kwargs)
    assert hanging.killed
    assert calls[0][1].get("start_new_session") is True


def test_timeout_killpg_shape_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    killpg_calls: list = []
    monkeypatch.setattr(os, "killpg", lambda pid, sig: killpg_calls.append((pid, sig)), raising=False)
    sigkill = getattr(signal, "SIGKILL", 9)
    monkeypatch.setattr(signal, "SIGKILL", sigkill, raising=False)
    hanging = FakeProcess(b"", hang=True)
    hanging.pid = 4243  # type: ignore[attr-defined]
    calls: list = []
    _patch_hanging_fake(monkeypatch, "fake-scanner", hanging, calls)
    real_name = os.name
    os.name = "posix"  # type: ignore[assignment]
    try:
        with pytest.raises(orchestrator.ScannerTimeoutError):
            asyncio.run(orchestrator.run_scanner_json(["fake-scanner"], input_data=None, timeout=0.05))
    finally:
        os.name = real_name  # type: ignore[assignment]
    assert killpg_calls == [(4243, sigkill)]
    assert calls[0][1].get("start_new_session") is True
    assert hanging.killed


def test_timeout_fallback_when_taskkill_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing_run(argv: object, **kwargs: object) -> object:
        raise FileNotFoundError("taskkill.exe")

    monkeypatch.setattr(orchestrator.subprocess, "run", missing_run)
    hanging = FakeProcess(b"", hang=True)
    hanging.pid = 4244  # type: ignore[attr-defined]
    calls: list = []
    _patch_hanging_fake(monkeypatch, "fake-scanner", hanging, calls)
    real_name = os.name
    os.name = "nt"  # type: ignore[assignment]
    try:
        with pytest.raises(orchestrator.ScannerTimeoutError):
            asyncio.run(orchestrator.run_scanner_json(["fake-scanner"], input_data=None, timeout=0.05))
    finally:
        os.name = real_name  # type: ignore[assignment]
    assert hanging.killed
