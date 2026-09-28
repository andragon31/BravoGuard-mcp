"""T1 orchestrator tests: subprocess fan-out with fake scanner binaries."""

import asyncio
import json
from pathlib import Path

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
    assert orchestrator.betterleaks_stdin_argv() == [
        "betterleaks",
        "detect",
        "--no-git",
        "--source",
        "-",
    ]
    assert orchestrator.betterleaks_path_argv("repo") == [
        "betterleaks",
        "detect",
        "--no-git",
        "--source",
        "repo",
    ]
