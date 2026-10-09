"""T6 Python depth-lane tests: ruff (no-S), vulture, deptry (manifest-gated).

All subprocesses are mocked; no real ruff/vulture/deptry binary is invoked.
Fixtures under ``tests/fixtures/python-lanes/`` carry recorded-shape
payloads: ruff ``check --output-format json`` (ruff 0.16.5 shape, verified
live), vulture ``<file> --min-confidence 60`` text lines (vulture 2.16,
verified live via ``uvx vulture``), and deptry ``--json-output`` JSON
(deptry 0.25.1, verified live via ``uvx deptry``).

Ruff runs WITHOUT S rules (bandit owns security: S is flake8-bandit per
``ruff linter``); vulture flags dead code as attack surface; deptry checks
dependency hygiene on project manifests only.
"""

import asyncio
import json
import shutil
from pathlib import Path

from bravoguard import orchestrator
from bravoguard.languages import LANE_GATES, SKIP_REASONS, detect_languages, lanes_for
from bravoguard.normalizer import (
    FINDING_KEYS,
    normalize_bandit,
    normalize_deptry,
    normalize_findings,
    normalize_ruff,
    normalize_vulture,
    parse_vulture_output,
)

RUFF_FIXTURE = Path(__file__).parent / "fixtures" / "python-lanes" / "ruff.json"
VULTURE_FIXTURE = Path(__file__).parent / "fixtures" / "python-lanes" / "vulture.txt"
DEPTRY_FIXTURE = Path(__file__).parent / "fixtures" / "python-lanes" / "deptry.json"

PY_DIFF = """\
diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -0,0 +1,3 @@
+import os
+import pickle
+obj = pickle.load(open("d.pkl", "rb").read())
"""

JS_DIFF = """\
diff --git a/app.js b/app.js
index 1111111..2222222 100644
--- a/app.js
+++ b/app.js
@@ -0,0 +1,2 @@
+const x = eval(userInput);
+debugger;
"""

# Bandit payload flagging line 1 (same line as the ruff F401 finding):
# different engines, different rule namespaces, no dedup collapse.
BANDIT_OVERLAP = {
    "results": [
        {
            "test_id": "B301",
            "issue_cwe": {"id": 20},
            "filename": "app.py",
            "line_number": 1,
            "issue_severity": "MEDIUM",
            "issue_text": "Pickle and modules that wrap it can be unsafe.",
        }
    ]
}


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
    """Patch create_subprocess_exec so each binary returns canned stdout.

    The deptry leg writes the fixture JSON to its ``--json-output`` path
    (the real binary writes the report file, stdout carries text only).
    """

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
        if label == "deptry":
            args = [str(a) for a in argv]
            report = args[args.index("--json-output") + 1]
            Path(report).write_text(DEPTRY_FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
            stdout, returncode = responses.get(label, (b"deptry summary text", 1))
            return FakeProcess(stdout, returncode)
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
        "ruff": (RUFF_FIXTURE.read_bytes(), 1),
        "vulture": (VULTURE_FIXTURE.read_bytes(), 1),
    }
    responses.update(overrides)
    return responses


def patch_binaries(monkeypatch, *, ruff=True, vulture=True, deptry=True) -> None:
    """Control shutil.which for the T6 presence matrix (rest pass through)."""
    wanted = {"ruff": ruff, "vulture": vulture, "deptry": deptry}
    real_which = shutil.which

    def fake_which(name: str):
        if name in wanted:
            return f"/usr/bin/{name}" if wanted[name] else None
        if name in ("syft", "grype", "guarddog"):
            return None
        return real_which(name)

    monkeypatch.setattr(shutil, "which", fake_which)


def spawned_binaries(calls: list) -> set[str]:
    return {Path(str(argv[0])).name for argv, _ in calls}


def spawn_count(calls: list, binary: str) -> int:
    return sum(1 for argv, _ in calls if Path(str(argv[0])).name == binary)


def ruff_payload() -> list:
    return json.loads(RUFF_FIXTURE.read_text(encoding="utf-8"))


def vulture_text() -> str:
    return VULTURE_FIXTURE.read_text(encoding="utf-8")


def deptry_payload() -> list:
    return json.loads(DEPTRY_FIXTURE.read_text(encoding="utf-8"))


# --- argv shapes -----------------------------------------------------------


def test_ruff_argv_select_excludes_s_rules() -> None:
    argv = orchestrator.ruff_argv(["/repo/app.py"])
    assert argv[:2] == ["ruff", "check"]
    assert "--output-format" in argv and "json" in argv
    select = argv[argv.index("--select") + 1]
    prefixes = select.split(",")
    assert "S" not in prefixes
    assert not any(p == "S" or p.startswith("S1") for p in prefixes)
    assert "/repo/app.py" in argv


def test_ruff_argv_pins_line_length_100() -> None:
    argv = orchestrator.ruff_argv(["/repo/app.py"])
    assert argv[argv.index("--line-length") + 1] == "100"


def test_vulture_argv_documents_min_confidence() -> None:
    argv = orchestrator.vulture_argv(["/repo/app.py"])
    assert argv[0] == "vulture"
    assert argv[argv.index("--min-confidence") + 1] == str(
        orchestrator.VULTURE_MIN_CONFIDENCE
    )
    assert "/repo/app.py" in argv


def test_deptry_argv_writes_json_report() -> None:
    argv = orchestrator.deptry_argv("/repo", "/tmp/deptry.json")
    assert argv[0] == "deptry"
    assert "/repo" in argv
    assert argv[argv.index("--json-output") + 1] == "/tmp/deptry.json"


# --- ruff normalize --------------------------------------------------------


def test_normalize_ruff_mapping() -> None:
    findings = normalize_ruff(ruff_payload())
    assert len(findings) == 4
    for finding in findings:
        assert set(finding) == set(FINDING_KEYS)
    first = findings[0]
    assert first["rule_id"] == "ruff-F401"
    assert first["path"] == "pkg/sample.py"
    assert first["line"] == 1
    assert "`os` imported but unused" in first["message"]


def test_normalize_ruff_severity_never_above_medium() -> None:
    findings = normalize_ruff(ruff_payload())
    assert {f["severity"] for f in findings} == {"LOW"}
    assert all(f["severity"] in ("LOW", "MEDIUM") for f in findings)


def test_normalize_ruff_cwe_always_empty() -> None:
    assert all(f["cwe"] == "" for f in normalize_ruff(ruff_payload()))


def test_normalize_ruff_fix_hint_carries_url_and_fix() -> None:
    first, long_line = normalize_ruff(ruff_payload())[:2]
    assert "https://docs.astral.sh/ruff/rules/unused-import" in first["fix_hint"]
    assert "fix" in first["fix_hint"].lower()
    assert "line-too-long" in long_line["fix_hint"]


def test_normalize_ruff_tolerates_empty_payload() -> None:
    assert normalize_ruff([]) == []
    assert normalize_ruff({}) == []
    assert normalize_ruff([{"nope": True}, "garbage", None]) == []


# --- vulture parser + normalize --------------------------------------------


def test_vulture_parser_keeps_threshold_and_drops_below() -> None:
    entries = parse_vulture_output(vulture_text())
    confidences = {(e["path"], e["line"]): e["confidence"] for e in entries}
    assert confidences[("pkg/sample.py", 1)] == 90
    assert confidences[("pkg/sample.py", 4)] == 60
    assert ("pkg/sample.py", 9) not in confidences


def test_vulture_parser_tolerates_malformed_lines() -> None:
    entries = parse_vulture_output(vulture_text())
    assert len(entries) == 4
    entries = parse_vulture_output("garbage\n\n  \nno-colons-here\n")
    assert entries == []
    entries = parse_vulture_output("a.py:xx: unused import 'x' (90% confidence)\n")
    assert entries == []


def test_normalize_vulture_mapping() -> None:
    findings = normalize_vulture(parse_vulture_output(vulture_text()))
    assert len(findings) == 4
    for finding in findings:
        assert set(finding) == set(FINDING_KEYS)
        assert finding["severity"] == "LOW"
        assert finding["cwe"] == ""
    assert findings[0]["rule_id"] == "vulture-unused-import"
    assert findings[0]["line"] == 1
    assert findings[2]["rule_id"] == "vulture-unused-function"
    assert findings[3]["rule_id"] == "vulture-unused-class"


def test_normalize_vulture_fix_hint_remove_or_whitelist() -> None:
    hint = normalize_vulture(parse_vulture_output(vulture_text()))[0]["fix_hint"].lower()
    assert "remove" in hint
    assert "whitelist" in hint


def test_normalize_vulture_tolerates_empty_payload() -> None:
    assert normalize_vulture([]) == []
    assert normalize_vulture({}) == []


# --- deptry gating + normalize ---------------------------------------------


def test_deptry_manifests_requirements_and_pyproject_with_deps(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (tmp_path / "requirements-dev.txt").write_text("pytest==8.0.0\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["requests"]\n', encoding="utf-8"
    )
    manifests = orchestrator._deptry_manifests(tmp_path)
    names = sorted(Path(str(m)).name for m in manifests)
    assert names == ["pyproject.toml", "requirements-dev.txt", "requirements.txt"]


def test_deptry_manifests_skip_pyproject_without_dependencies(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n', encoding="utf-8")
    (tmp_path / "setup.py").write_text("from setuptools import setup\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    assert orchestrator._deptry_manifests(tmp_path) == []


def test_normalize_deptry_mapping() -> None:
    findings = normalize_deptry(deptry_payload())
    assert len(findings) == 2
    for finding in findings:
        assert set(finding) == set(FINDING_KEYS)
        assert finding["severity"] == "LOW"
        assert finding["cwe"] == ""
    unused, missing = findings
    assert unused["rule_id"] == "deptry-DEP002"
    assert unused["path"] == "pyproject.toml"
    assert unused["line"] == 0
    assert missing["rule_id"] == "deptry-DEP001"
    assert missing["path"] == "src/app.py"
    assert missing["line"] == 2


def test_normalize_deptry_fix_hint_pin_remove_declare() -> None:
    unused, missing = normalize_deptry(deptry_payload())
    assert "remove" in unused["fix_hint"].lower()
    assert "declare" in missing["fix_hint"].lower() or "add" in missing["fix_hint"].lower()


def test_normalize_deptry_tolerates_empty_payload() -> None:
    assert normalize_deptry([]) == []
    assert normalize_deptry({}) == []


# --- lane registration -----------------------------------------------------


def test_lane_gates_suffix_vs_manifest_distinction() -> None:
    assert LANE_GATES["ruff"]["kind"] == "suffix"
    assert LANE_GATES["ruff"]["languages"] == ("python",)
    assert LANE_GATES["vulture"]["kind"] == "suffix"
    assert LANE_GATES["vulture"]["languages"] == ("python",)
    assert LANE_GATES["deptry"]["kind"] == "manifest"
    assert LANE_GATES["deptry"]["manifests"] == ("python",)
    assert {"ruff", "vulture", "deptry"} <= set(SKIP_REASONS)


def test_lanes_for_empty_detection_skips_all_three(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("hello\n", encoding="utf-8")
    skips = lanes_for(detect_languages(tmp_path))
    assert {"ruff", "vulture", "deptry"} <= set(skips)


# --- missing-binary skips --------------------------------------------------


def test_missing_binaries_skip_all_three_in_repo(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import os\nprint(os.name)\n", encoding="utf-8")
    (repo / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    patch_binaries(monkeypatch, ruff=False, vulture=False, deptry=False)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert result["status"] == "ok"
    for lane in ("ruff", "vulture", "deptry"):
        assert "not installed" in result["skipped"][lane].lower()
        assert lane not in result.get("errors", {})
    assert {"ruff", "vulture", "deptry"} & spawned_binaries(calls) == set()


def test_missing_binaries_skip_all_three_in_diff(monkeypatch) -> None:
    patch_binaries(monkeypatch, ruff=False, vulture=False, deptry=False)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_diff(PY_DIFF))
    assert result["status"] == "ok"
    for lane in ("ruff", "vulture", "deptry"):
        assert lane in result["skipped"]
        assert lane not in result.get("errors", {})
    assert {"ruff", "vulture", "deptry"} & spawned_binaries(calls) == set()


# --- diff + repo routing ---------------------------------------------------


def test_diff_js_only_skips_all_three_with_reason(monkeypatch) -> None:
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_diff(JS_DIFF))
    assert result["status"] == "ok"
    assert {"ruff", "vulture", "deptry"} <= set(result.get("skipped", {}))
    assert not any(
        str(f.get("rule_id", "")).startswith(("ruff-", "vulture-", "deptry-"))
        for f in result["findings"]
    )


def test_diff_py_runs_ruff_and_vulture_but_not_deptry(monkeypatch) -> None:
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_diff(PY_DIFF))
    assert result["status"] == "ok"
    assert "ruff" not in result.get("skipped", {})
    assert "vulture" not in result.get("skipped", {})
    assert "deptry" in result.get("skipped", {})
    assert spawn_count(calls, "ruff") == 1
    assert spawn_count(calls, "vulture") == 1
    assert "deptry" not in spawned_binaries(calls)
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert any(r.startswith("ruff-") for r in rule_ids)
    assert any(r.startswith("vulture-") for r in rule_ids)


def test_repo_js_only_skips_all_three_with_reason(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text("const x = 1;\n", encoding="utf-8")
    (repo / "package.json").write_text('{"name": "x"}\n', encoding="utf-8")
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert result["status"] == "ok"
    assert {"ruff", "vulture", "deptry"} <= set(result.get("skipped", {}))
    assert {"ruff", "vulture", "deptry"} & spawned_binaries(calls) == set()


def test_repo_py_runs_all_three(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import os\nprint(os.name)\n", encoding="utf-8")
    (repo / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert result["status"] == "ok"
    assert "ruff" not in result.get("skipped", {})
    assert "vulture" not in result.get("skipped", {})
    assert "deptry" not in result.get("skipped", {})
    assert {"ruff", "vulture", "deptry"} <= spawned_binaries(calls)
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert any(r.startswith("ruff-") for r in rule_ids)
    assert any(r.startswith("vulture-") for r in rule_ids)
    assert any(r.startswith("deptry-") for r in rule_ids)


def test_repo_py_without_manifests_skips_deptry_but_runs_ruff(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import os\nprint(os.name)\n", encoding="utf-8")
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert result["status"] == "ok"
    assert "deptry" in result.get("skipped", {})
    assert "manifest" in result["skipped"]["deptry"].lower()
    assert "ruff" not in result.get("skipped", {})
    assert "vulture" not in result.get("skipped", {})
    assert "deptry" not in spawned_binaries(calls)


def test_ruff_vulture_empty_file_list_spawns_nothing(monkeypatch) -> None:
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    assert asyncio.run(orchestrator._run_ruff([], 30))[1] == []
    assert asyncio.run(orchestrator._run_vulture([], 30))[1] == []
    assert calls == []


# --- coexistence -----------------------------------------------------------


def test_coexists_with_bandit_no_duplicate_rule_ids(monkeypatch) -> None:
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(
        monkeypatch,
        quiet_responses(bandit=(json.dumps(BANDIT_OVERLAP).encode(), 1)),
        calls,
    )
    result = asyncio.run(orchestrator.scan_diff(PY_DIFF))
    line1 = [f for f in result["findings"] if f["line"] == 1]
    rule_ids = [f["rule_id"] for f in line1]
    assert "B301" in rule_ids
    assert "ruff-F401" in rule_ids
    # Different engines, different rule namespaces by construction.
    assert len(rule_ids) == len(set(rule_ids))
    assert len(result["findings"]) == len(
        normalize_findings(
            normalize_bandit(BANDIT_OVERLAP)
            + normalize_ruff(ruff_payload())
            + normalize_vulture(parse_vulture_output(vulture_text()))
        )
    )


# --- installer -------------------------------------------------------------


def test_installer_covers_deptry_and_vulture() -> None:
    from bravoguard import cli
    from scripts import install, install_external

    for tool in ("deptry", "vulture"):
        assert tool in install.PYTHON_TOOLS
        assert tool in install_external.PYTHON_TOOLS
        assert tool in cli.PYTHON_TOOLS
    # Ruff was already covered: confirm, do not duplicate.
    assert install.PYTHON_TOOLS.count("ruff") == 1
    assert install_external.PYTHON_TOOLS.count("ruff") == 1
    assert cli.PYTHON_TOOLS.count("ruff") == 1
    # PyPI CLIs install isolated (pipx/uv-tool), so tools-manifest.json
    # pins only external binaries by design — same convention as ruff/bandit.
    manifest = json.loads(
        (Path(__file__).parent.parent / "tools-manifest.json").read_text(encoding="utf-8")
    )
    names = {b["name"] for b in manifest.get("binaries", [])}
    assert {"deptry", "vulture"} & names == set()
    assert {"ruff", "bandit"} & names == set()
