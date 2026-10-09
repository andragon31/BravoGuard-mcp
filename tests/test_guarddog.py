"""T5 GuardDog heuristics-lane tests: normalize, gating, skips, coexistence.

All subprocesses are mocked; no real guarddog binary or network is invoked.
Fixtures under ``tests/fixtures/guarddog/`` carry recorded-shape payloads:
a ``pypi scan`` per-dependency dict and an ``npm scan`` results envelope
(documented-source shapes — the binary is absent in this env, so the argv
builders record that provenance and flag live re-verification as owed).

The lane complements the own typosquat lane (heuristics vs name-distance):
both may flag the same dependency with different rule ids.
"""

import asyncio
import json
import shutil
import sys
from pathlib import Path

from bravoguard import orchestrator
from bravoguard.languages import LANE_GATES, SKIP_REASONS, detect_languages, lanes_for
from bravoguard.normalizer import FINDING_KEYS, GUARDDOG_CWE_BY_DETECTOR, normalize_guarddog
from bravoguard.owasp_map import explain_cwe

PYPI_FIXTURE = Path(__file__).parent / "fixtures" / "guarddog" / "pypi_scan.json"
NPM_FIXTURE = Path(__file__).parent / "fixtures" / "guarddog" / "npm_scan.json"

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


def install_fake(monkeypatch, responses: dict, calls: list) -> None:
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
    }
    responses.update(overrides)
    return responses


def patch_binaries(monkeypatch, *, guarddog=True) -> None:
    """Control shutil.which for the guarddog presence matrix."""
    real_which = shutil.which

    def fake_which(name: str):
        if name == "guarddog":
            return "/usr/bin/guarddog" if guarddog else None
        return real_which(name)

    monkeypatch.setattr(shutil, "which", fake_which)


def spawned_binaries(calls: list) -> set[str]:
    return {Path(str(argv[0])).name for argv, _ in calls}


def guarddog_argvs(calls: list) -> list:
    return [argv for argv, _ in calls if Path(str(argv[0])).name == "guarddog"]


def pypi_payload() -> dict:
    return json.loads(PYPI_FIXTURE.read_text(encoding="utf-8"))


def npm_payload() -> dict:
    return json.loads(NPM_FIXTURE.read_text(encoding="utf-8"))


# --- argv shape ------------------------------------------------------------


def test_pypi_argv_scans_manifest_as_json() -> None:
    argv = orchestrator.guarddog_pypi_argv("/repo/requirements.txt")
    assert argv[0] == "guarddog"
    assert argv[1:3] == ["pypi", "scan"]
    assert "/repo/requirements.txt" in argv
    assert "--output-format" in argv
    assert "json" in argv


def test_npm_argv_scans_manifest_as_json() -> None:
    argv = orchestrator.guarddog_npm_argv("/repo/package.json")
    assert argv[0] == "guarddog"
    assert argv[1:3] == ["npm", "scan"]
    assert "/repo/package.json" in argv
    assert "--output-format" in argv
    assert "json" in argv


# --- normalize -------------------------------------------------------------


def test_normalize_guarddog_pypi_mapping() -> None:
    findings = normalize_guarddog(pypi_payload())
    assert len(findings) == 3
    for finding in findings:
        assert set(finding) == set(FINDING_KEYS)
    typosquat, exfil, code_exec = findings
    assert typosquat["rule_id"] == "guarddog-typosquatting"
    assert typosquat["cwe"] == "CWE-1357"
    assert typosquat["severity"] == "HIGH"
    assert "reqeusts" in typosquat["message"]
    assert exfil["rule_id"] == "guarddog-exfiltrate-sensitive-data"
    assert exfil["cwe"] == "CWE-200"
    assert exfil["severity"] == "MEDIUM"
    # code-execution has no confident CWE analog: empty, never fabricated.
    assert code_exec["rule_id"] == "guarddog-code-execution"
    assert code_exec["cwe"] == ""
    assert code_exec["severity"] == "MEDIUM"


def test_normalize_guarddog_npm_envelope_mapping() -> None:
    findings = normalize_guarddog(npm_payload())
    assert len(findings) == 3
    for finding in findings:
        assert set(finding) == set(FINDING_KEYS)
    exfil, bundled, empty = findings
    assert exfil["rule_id"] == "guarddog-npm-exfiltrate-sensitive-data"
    assert exfil["cwe"] == "CWE-200"
    assert exfil["severity"] == "HIGH"
    assert bundled["rule_id"] == "guarddog-npm-bundled-binary"
    assert bundled["cwe"] == "CWE-506"
    assert bundled["severity"] == "MEDIUM"
    assert empty["rule_id"] == "guarddog-npm-empty-information"
    assert empty["cwe"] == ""


def test_guarddog_cwes_verified_via_owasp_map() -> None:
    assert set(GUARDDOG_CWE_BY_DETECTOR.values()) == {"CWE-1357", "CWE-506", "CWE-200"}
    assert explain_cwe("CWE-1357")["owasp_2025"] == "A03"
    assert explain_cwe("CWE-506")["owasp_2025"] == "A08"
    for cwe in GUARDDOG_CWE_BY_DETECTOR.values():
        assert explain_cwe(cwe)["owasp_2025"] != "unknown"


def test_guarddog_severity_policy_medium_default_high_capped() -> None:
    findings = normalize_guarddog(pypi_payload()) + normalize_guarddog(npm_payload())
    assert {f["severity"] for f in findings} <= {"MEDIUM", "HIGH"}
    assert normalize_guarddog({"pkg": {"issues": [{"detector": "x-typo"}]}})[
        0
    ]["severity"] == "MEDIUM"


def test_guarddog_fix_hint_guides_review_remove_pin() -> None:
    findings = normalize_guarddog(pypi_payload())
    for finding in findings:
        hint = finding["fix_hint"].lower()
        assert "review" in hint
        assert "remove" in hint
        assert "pin" in hint


def test_normalize_guarddog_tolerates_empty_payload() -> None:
    assert normalize_guarddog({}) == []
    assert normalize_guarddog({"results": []}) == []
    assert normalize_guarddog([]) == []


# --- lane registration -----------------------------------------------------


def test_lane_gates_register_guarddog_manifest_gated() -> None:
    assert LANE_GATES["guarddog"]["kind"] == "manifest"
    assert set(LANE_GATES["guarddog"]["manifests"]) == {"python", "javascript"}
    assert "guarddog" in SKIP_REASONS


def test_manifest_gating_no_manifests_skips_without_spawn(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert result["status"] == "ok"
    assert "guarddog" in result.get("skipped", {})
    assert guarddog_argvs(calls) == []
    assert "guarddog" not in result.get("errors", {})


# --- skip matrix -----------------------------------------------------------


def test_win32_skips_guarddog_without_spawn(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (repo / "package.json").write_text('{"name": "x"}\n', encoding="utf-8")
    # No real shutil.which under the fake platform (its win32 branch needs
    # _winapi, absent on Linux): guarddog present, everything else missing.
    monkeypatch.setattr(
        shutil, "which", lambda name: "/usr/bin/guarddog" if name == "guarddog" else None
    )
    monkeypatch.setattr(sys, "platform", "win32")
    calls: list = []
    install_fake(
        monkeypatch,
        quiet_responses(guarddog=(json.dumps(pypi_payload()).encode(), 0)),
        calls,
    )
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert result["status"] == "ok"
    reason = result["skipped"]["guarddog"]
    assert "indows" in reason and "nono-py" in reason
    assert guarddog_argvs(calls) == []
    assert "guarddog" not in result.get("errors", {})


def test_missing_binary_skips_guarddog_without_spawn(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    patch_binaries(monkeypatch, guarddog=False)
    calls: list = []
    install_fake(
        monkeypatch,
        quiet_responses(guarddog=(json.dumps(pypi_payload()).encode(), 0)),
        calls,
    )
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert result["status"] == "ok"
    assert "not installed" in result["skipped"]["guarddog"].lower()
    assert guarddog_argvs(calls) == []
    assert "guarddog" not in result.get("errors", {})


# --- wiring ----------------------------------------------------------------


def test_pypi_only_runs_pypi_side(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("reqeusts==2.31.0\n", encoding="utf-8")
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(
        monkeypatch,
        quiet_responses(guarddog=(json.dumps(pypi_payload()).encode(), 0)),
        calls,
    )
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert "guarddog" not in result.get("skipped", {})
    argv = guarddog_argvs(calls)
    assert len(argv) == 1
    assert argv[0][1:3] == ["pypi", "scan"]
    assert "requirements.txt" in argv[0][3]
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert "guarddog-typosquatting" in rule_ids


def test_npm_only_runs_npm_side(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text('{"name": "x"}\n', encoding="utf-8")
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(
        monkeypatch, quiet_responses(guarddog=(json.dumps(npm_payload()).encode(), 0)), calls
    )
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert "guarddog" not in result.get("skipped", {})
    argv = guarddog_argvs(calls)
    assert len(argv) == 1
    assert argv[0][1:3] == ["npm", "scan"]
    assert "package.json" in argv[0][3]
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert "guarddog-npm-exfiltrate-sensitive-data" in rule_ids


def test_coexists_with_typosquat_lane(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("reqeusts==2.31.0\n", encoding="utf-8")
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(
        monkeypatch,
        quiet_responses(guarddog=(json.dumps(pypi_payload()).encode(), 0)),
        calls,
    )
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    rule_ids = [f["rule_id"] for f in result["findings"]]
    # Heuristics axis (guarddog) complements the name-distance axis (own lane).
    assert "bravoguard-supply-typosquat" in rule_ids
    assert "guarddog-typosquatting" in rule_ids


def test_scan_diff_never_spawns_guarddog(monkeypatch) -> None:
    calls: list = []
    install_fake(
        monkeypatch,
        quiet_responses(guarddog=(json.dumps(pypi_payload()).encode(), 0)),
        calls,
    )
    result = asyncio.run(orchestrator.scan_diff(SEED_DIFF))
    assert "guarddog" not in spawned_binaries(calls)
    assert "guarddog" not in result.get("skipped", {})
    assert "guarddog" not in result.get("errors", {})
    assert not any(
        str(f.get("rule_id", "")).startswith("guarddog-") for f in result["findings"]
    )


def test_run_guarddog_without_manifests_spawns_nothing(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    engine, payload = asyncio.run(orchestrator._run_guarddog(str(repo), 30))
    assert engine == "guarddog"
    assert normalize_guarddog(payload) == []
    assert guarddog_argvs(calls) == []


def test_lanes_for_empty_detection_skips_guarddog(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("hello\n", encoding="utf-8")
    skips = lanes_for(detect_languages(tmp_path))
    assert "guarddog" in skips


# --- installer verification --------------------------------------------------


def test_installer_covers_guarddog() -> None:
    from bravoguard import cli
    from scripts import install, install_external

    assert "guarddog" in install.PYTHON_TOOLS
    assert "guarddog" in install_external.PYTHON_TOOLS
    assert "guarddog" in cli.PYTHON_TOOLS
    assert install.should_skip_guarddog("windows", False) is True
    assert install.should_skip_guarddog("windows", True) is False
    assert install.should_skip_guarddog("linux", False) is False
    # Python CLIs install isolated (pipx/uv-tool), so tools-manifest.json
    # pins only external binaries by design — no installer change needed.
    manifest = json.loads(
        (Path(__file__).parent.parent / "tools-manifest.json").read_text(encoding="utf-8")
    )
    assert "guarddog" not in {b["name"] for b in manifest.get("binaries", [])}
