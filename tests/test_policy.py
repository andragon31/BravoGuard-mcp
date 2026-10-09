"""T10 policy gates + baseline/redact tests (all subprocesses mocked).

Policy verdicts ride ``policy_verdict: {decision, denies, warns}`` on both
scan entry points; a missing conftest binary reports skipped+reason and
never fails the scan. Baseline/redact pass through to the secrets lane.
"""

import asyncio
import inspect
import json
import shutil
from pathlib import Path

import pytest

from bravoguard import orchestrator

FIXTURES = Path(__file__).parent / "fixtures" / "policy"
REPO_ROOT = Path(__file__).resolve().parents[1]

CONFTEST_SKIP_REASON = "conftest not installed: policy gates skipped"

SEED_DIFF = """\
diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -0,0 +1,2 @@
+import os
+print(os.environ.get("TOKEN"))
"""

REDACT_SENTINEL = "sk-live-abcdef1234567890"


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


def quiet_responses(**overrides: object) -> dict:
    responses: dict = {
        "semgrep": (b'{"results": []}', 0),
        "opengrep": (b'{"results": []}', 0),
        "bandit": (b'{"results": []}', 0),
        "betterleaks": (b"[]", 0),
        "gitleaks": (b"[]", 0),
        "oxlint": (b'{"diagnostics": []}', 0),
        "cmd": (b'{"diagnostics": []}', 0),
        "trivy": (b"{}", 0),
        "uv": (b'{"results": {"failed_checks": []}}', 0),
        "conftest": (b"[]", 0),
    }
    responses.update(overrides)
    return responses


def install_fake(monkeypatch: pytest.MonkeyPatch, responses: dict, calls: list) -> None:
    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append((list(argv), dict(kwargs)))
        assert "shell" not in kwargs, "scanners must never run with shell=True"
        first = Path(str(argv[0])).name
        names = {Path(str(a)).name for a in argv}
        if first == "uv" and "checkov" in names:
            label = "checkov"
        elif "oxlint" in names:
            label = "oxlint"
        else:
            label = first
        if label not in responses:
            raise FileNotFoundError(label)
        stdout, returncode = responses[label]
        return FakeProcess(stdout, returncode)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)


def test_conftest_argv_shape() -> None:
    argv = orchestrator.conftest_argv("findings.json")
    assert argv[0] == "conftest"
    assert "test" in argv
    assert "--policy" in argv
    assert argv[argv.index("--policy") + 1].endswith("policy")
    assert "--output" in argv
    assert argv[argv.index("--output") + 1] == "json"
    assert argv[-1] == "findings.json"


def test_parse_conftest_fail_fixture() -> None:
    payload = json.loads((FIXTURES / "conftest_fail.json").read_text(encoding="utf-8"))
    verdict = orchestrator.parse_conftest_output(payload)
    assert verdict["decision"] == "block"
    assert len(verdict["denies"]) == 1
    assert len(verdict["warns"]) == 1
    assert "CRITICAL" in verdict["denies"][0]


def test_parse_conftest_pass_fixture() -> None:
    payload = json.loads((FIXTURES / "conftest_pass.json").read_text(encoding="utf-8"))
    verdict = orchestrator.parse_conftest_output(payload)
    assert verdict == {"decision": "allow", "denies": [], "warns": []}


def test_policy_rego_has_deny_and_warn() -> None:
    rego = (REPO_ROOT / "policy" / "bravoguard.rego").read_text(encoding="utf-8")
    assert "deny" in rego
    assert "warn" in rego
    assert "CRITICAL" in rego
    assert "trufflehog" in rego.lower() or "verified" in rego.lower()


def test_scan_signatures_carry_baseline_redact() -> None:
    for fn in (orchestrator.scan_diff, orchestrator.scan_repo):
        params = inspect.signature(fn).parameters
        assert "baseline" in params
        assert "redact" in params
        assert params["baseline"].default is None
        assert params["redact"].default is False


def test_server_forwards_baseline_redact() -> None:
    source = (REPO_ROOT / "src" / "bravoguard" / "server.py").read_text(encoding="utf-8")
    assert "baseline" in source
    assert "redact" in source


def test_missing_conftest_reports_skipped_never_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    real_which = shutil.which
    monkeypatch.setattr(
        shutil, "which", lambda name: None if name == "conftest" else real_which(name)
    )
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_repo(str(tmp_path)))
    assert result["status"] == "ok"
    assert result["skipped"]["conftest"] == CONFTEST_SKIP_REASON
    assert result["policy_verdict"] == {"decision": "allow", "denies": [], "warns": []}


def test_missing_conftest_diff_reports_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    real_which = shutil.which
    monkeypatch.setattr(
        shutil, "which", lambda name: None if name == "conftest" else real_which(name)
    )
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_diff(SEED_DIFF))
    assert result["status"] == "ok"
    assert result["skipped"]["conftest"] == CONFTEST_SKIP_REASON
    assert result["policy_verdict"]["decision"] == "allow"


def test_policy_blocks_on_mocked_deny(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/fake/{name}")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    calls: list = []
    fail_stdout = (FIXTURES / "conftest_fail.json").read_text(encoding="utf-8").encode()
    install_fake(monkeypatch, quiet_responses(conftest=(fail_stdout, 1)), calls)
    result = asyncio.run(orchestrator.scan_repo(str(tmp_path)))
    assert "conftest" in {Path(str(argv[0])).name for argv, _ in calls}
    assert result["policy_verdict"]["decision"] == "block"
    assert len(result["policy_verdict"]["denies"]) == 1
    assert result["status"] == "ok"


def test_baseline_flag_reaches_secrets_lane() -> None:
    argv = orchestrator.betterleaks_path_argv("repo", baseline="base.json")
    assert "--baseline-path" in argv
    assert argv[argv.index("--baseline-path") + 1] == "base.json"
    plain = orchestrator.betterleaks_path_argv("repo")
    assert "--baseline-path" not in plain


def test_redact_flag_reaches_secrets_lane() -> None:
    argv = orchestrator.betterleaks_path_argv("repo", redact=True)
    assert "--redact" in argv
    assert "--redact" not in orchestrator.betterleaks_path_argv("repo")


def test_baseline_suppresses_known_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/fake/{name}")
    leak = json.dumps(
        [
            {
                "Description": "Generic API Key",
                "RuleID": "generic-api-key",
                "File": "app.py",
                "StartLine": 1,
            }
        ]
    ).encode()

    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        arglist = [str(a) for a in argv]
        name = Path(arglist[0]).name
        if name == "betterleaks":
            # Engine-side suppression: with a baseline the known leak is gone.
            if "--baseline-path" in arglist:
                return FakeProcess(b"[]", 0)
            return FakeProcess(leak, 1)
        if name == "conftest":
            return FakeProcess(b"[]", 0)
        if name in ("semgrep", "bandit"):
            return FakeProcess(b'{"results": []}', 0)
        raise FileNotFoundError(name)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)
    without = asyncio.run(orchestrator.scan_diff(SEED_DIFF))
    assert any(f["rule_id"] == "generic-api-key" for f in without["findings"])
    suppressed = asyncio.run(
        orchestrator.scan_diff(SEED_DIFF, baseline=str(FIXTURES / "baseline.json"))
    )
    assert not any(f["rule_id"] == "generic-api-key" for f in suppressed["findings"])


def test_redact_strips_sensitive_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/fake/{name}")
    payload = {
        "results": [
            {
                "check_id": "bravoguard-python-ssrf-requests",
                "path": "app.py",
                "start": {"line": 1},
                "extra": {
                    "message": f"Review {REDACT_SENTINEL} before merge.",
                    "severity": "ERROR",
                    "metadata": {"cwe": "CWE-918"},
                },
            }
        ]
    }

    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        arglist = [str(a) for a in argv]
        name = Path(arglist[0]).name
        if name in ("semgrep", "opengrep"):
            return FakeProcess(json.dumps(payload).encode(), 1)
        if name == "conftest":
            return FakeProcess(b"[]", 0)
        if name == "bandit":
            return FakeProcess(b'{"results": []}', 0)
        if name == "betterleaks":
            return FakeProcess(b"[]", 0)
        raise FileNotFoundError(name)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)
    plain = asyncio.run(orchestrator.scan_diff(SEED_DIFF))
    assert REDACT_SENTINEL in json.dumps(plain["findings"])
    redacted = asyncio.run(orchestrator.scan_diff(SEED_DIFF, redact=True))
    assert REDACT_SENTINEL not in json.dumps(redacted["findings"])
    assert "[REDACTED]" in json.dumps(redacted["findings"])


def test_diff_routing_unaffected_by_new_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    """T2 split still holds with the grown pack: python groups never see the
    frontend config and vice versa (mocked subprocess, no binaries)."""
    calls: list = []

    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append(list(argv))
        name = Path(str(argv[0])).name
        if name in ("semgrep", "opengrep"):
            return FakeProcess(b'{"results": []}', 0)
        if name == "conftest":
            return FakeProcess(b"[]", 0)
        if name in ("bandit", "betterleaks"):
            empty = b'{"results": []}' if name == "bandit" else b"[]"
            return FakeProcess(empty, 0)
        raise FileNotFoundError(name)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)
    py_diff = (
        "diff --git a/app.py b/app.py\nindex 1111111..2222222 100644\n"
        "--- a/app.py\n+++ b/app.py\n@@ -0,0 +1 @@\n+import os\n"
    )
    asyncio.run(orchestrator.scan_diff(py_diff))
    semgrep_calls = [a for a in calls if Path(str(a[0])).name == "semgrep"]
    assert len(semgrep_calls) == 1
    assert any("rules/python" in str(a) for a in semgrep_calls[0])
    assert not any("rules/frontend" in str(a) for a in semgrep_calls[0])
    calls.clear()
    js_diff = (
        "diff --git a/app.js b/app.js\nindex 1111111..2222222 100644\n"
        "--- a/app.js\n+++ b/app.js\n@@ -0,0 +1 @@\n+console.log(1)\n"
    )
    asyncio.run(orchestrator.scan_diff(js_diff))
    semgrep_calls = [a for a in calls if Path(str(a[0])).name == "semgrep"]
    assert len(semgrep_calls) == 1
    assert any("rules/frontend" in str(a) for a in semgrep_calls[0])
    assert not any("rules/python" in str(a) for a in semgrep_calls[0])
