"""T3 TruffleHog verify-lane tests: normalize + opt-in wiring.

All subprocesses are mocked; no real binary or network is ever invoked.
The recorded fixture under ``tests/fixtures/secrets/`` carries one verified
and one unverified entry with sentinel secrets in ``Raw``/``RawV2``.
"""

import asyncio
import inspect
import json
from pathlib import Path

import pytest

from bravoguard import orchestrator
from bravoguard.normalizer import FINDING_KEYS, normalize_trufflehog

FIXTURE = Path(__file__).parent / "fixtures" / "secrets" / "trufflehog_verified.json"
SENTINELS = ("SENTINEL_GH_LIVE_9f8e7d6c5b4a", "SENTINEL_STRIPE_51H7xYz")
OPT_IN_REASON = "trufflehog verify is opt-in: pass verify_secrets=True"

SEED_DIFF = """\
diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -0,0 +1,2 @@
+import os
+print(os.environ.get("TOKEN"))
"""


class FakeProcess:
    """Minimal stand-in for asyncio.subprocess.Process."""

    def __init__(self, stdout: bytes, returncode: int = 0) -> None:
        self._stdout = stdout
        self.returncode = returncode

    async def communicate(self, input_data=None):
        return (self._stdout, b"")

    def kill(self) -> None:
        pass

    async def wait(self) -> int:
        return self.returncode


def install_fake(monkeypatch: pytest.MonkeyPatch, responses: dict, calls: list) -> None:
    """Patch create_subprocess_exec so each binary returns canned stdout."""

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
        "trufflehog": (b"", 0),
    }
    responses.update(overrides)
    return responses


def fixture_payload() -> list:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def fixture_jsonl() -> bytes:
    return "\n".join(json.dumps(item) for item in fixture_payload()).encode()


def spawned_binaries(calls: list) -> set[str]:
    return {Path(str(argv[0])).name for argv, _ in calls}


def test_normalize_trufflehog_mapping() -> None:
    findings = normalize_trufflehog(fixture_payload())
    assert len(findings) == 2
    for finding in findings:
        assert set(finding) == set(FINDING_KEYS)
    verified, unverified = findings
    assert "Github" in verified["rule_id"]
    assert verified["path"] == "config/settings.py"
    assert verified["line"] == 12
    assert verified["cwe"] == "CWE-798"
    assert "Stripe" in unverified["rule_id"]
    assert unverified["path"] == "billing/keys.py"


def test_verified_live_credential_is_critical() -> None:
    (verified, _) = normalize_trufflehog(fixture_payload())
    assert verified["severity"] == "CRITICAL"


def test_unverified_stays_high_never_dropped() -> None:
    (_, unverified) = normalize_trufflehog(fixture_payload())
    assert unverified["severity"] == "HIGH"


def test_secret_values_never_reach_findings() -> None:
    findings = normalize_trufflehog(fixture_payload())
    blob = json.dumps(findings)
    for sentinel in SENTINELS:
        assert sentinel not in blob


def test_message_and_fix_hint_guide_rotation() -> None:
    (verified, _) = normalize_trufflehog(fixture_payload())
    assert "rotat" in verified["fix_hint"].lower()
    assert "revok" in verified["fix_hint"].lower()
    assert all(sentinel not in verified["message"] for sentinel in SENTINELS)


def test_trufflehog_argv_is_verified_only_json_filesystem() -> None:
    argv = orchestrator.trufflehog_argv("/repo")
    assert argv[0] == "trufflehog"
    assert "filesystem" in argv
    assert "--json" in argv
    assert "--results=verified" in argv
    assert "/repo" in argv


def test_opt_out_reports_skipped_with_reason(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_repo(str(tmp_path)))
    assert result["skipped"]["trufflehog"] == OPT_IN_REASON
    assert "trufflehog" not in spawned_binaries(calls)
    assert "trufflehog" not in result.get("errors", {})


def test_opt_in_runs_verify_lane(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    calls: list = []
    install_fake(monkeypatch, quiet_responses(trufflehog=(fixture_jsonl(), 0)), calls)
    result = asyncio.run(orchestrator.scan_repo(str(tmp_path), verify_secrets=True))
    assert "trufflehog" in spawned_binaries(calls)
    assert "trufflehog" not in result.get("skipped", {})
    critical = [f for f in result["findings"] if f["rule_id"].startswith("trufflehog-")]
    assert critical and all(f["severity"] == "CRITICAL" for f in critical if "Github" in f["rule_id"])
    blob = json.dumps(result["findings"])
    for sentinel in SENTINELS:
        assert sentinel not in blob


def test_missing_binary_degrades_to_not_installed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    calls: list = []
    responses = quiet_responses()
    del responses["trufflehog"]
    install_fake(monkeypatch, responses, calls)
    result = asyncio.run(orchestrator.scan_repo(str(tmp_path), verify_secrets=True))
    assert result["errors"]["trufflehog"] == "not-installed"
    assert result["status"] == "ok"


def test_scan_diff_behavior_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    assert "verify_secrets" not in inspect.signature(orchestrator.scan_diff).parameters
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_diff(SEED_DIFF))
    assert "trufflehog" not in spawned_binaries(calls)
    assert "trufflehog" not in result.get("skipped", {})
    assert "trufflehog" not in result.get("errors", {})
    assert not any(str(f.get("rule_id", "")).startswith("trufflehog-") for f in result["findings"])
