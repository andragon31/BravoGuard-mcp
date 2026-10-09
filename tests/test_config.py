"""T2 config tests: oxlint suspicious, trivy +license, semgrep python/frontend split.

TDD applies to argv/normalizer/routing (behavior changes). The
.oxlintrc.json file itself is pure-config (declarative categories): it is
verified live via ``oxlint --print-config`` (see task evidence), not via a
RED/GREEN unit test — the unit tests below pin the wired behavior (argv
carries --config, suspicious diagnostics stay LOW/MEDIUM).
"""

import asyncio
import json
import sys
from pathlib import Path

from bravoguard import orchestrator
from bravoguard.normalizer import normalize_trivy

FIXTURES = Path(__file__).parent / "fixtures" / "config"
REPO_ROOT = Path(__file__).resolve().parents[1]

# Suspicious-category shape (oxlint 1.65.0, verified live): ``no-new`` is a
# suspicious rule, off by default, emitted as ``warning`` once
# ``categories.suspicious=warn`` is enabled via --config.
SUSPICIOUS_PAYLOAD = {
    "diagnostics": [
        {
            "message": "Do not use 'new' for side effects.",
            "code": "eslint(no-new)",
            "severity": "warning",
            "causes": [],
            "url": "https://oxc.rs/docs/guide/usage/linter/rules/eslint/no-new.html",
            "help": "Assign the result of 'new' to a variable.",
            "filename": "app.js",
            "labels": [{"span": {"offset": 14, "length": 7, "line": 1, "column": 15}}],
            "related": [],
        }
    ],
    "number_of_files": 1,
    "number_of_rules": 122,
}


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


def test_oxlintrc_enables_suspicious_warn_only() -> None:
    """Pure-config pin: correctness=error + suspicious=warn, pedantic off."""
    config = json.loads((REPO_ROOT / ".oxlintrc.json").read_text(encoding="utf-8"))
    categories = config.get("categories", {})
    assert categories.get("correctness") in ("error", "deny")
    assert categories.get("suspicious") in ("warn", "warning")
    assert "pedantic" not in categories


def test_oxlint_argv_carries_config(monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    argv = orchestrator.oxlint_argv("target")
    assert "--config" in argv
    config_index = argv.index("--config")
    assert argv[config_index + 1].endswith(".oxlintrc.json")
    assert argv[-1] == "target"
    assert "--format" in argv and "json" in argv


def test_oxlint_argv_config_before_target_and_forwards_excludes(monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    argv = orchestrator.oxlint_argv("target", ("*.min.js", "vendor/"))
    assert argv.index("--config") < argv.index("target")
    assert "--ignore-pattern=*.min.js" in argv
    assert "--ignore-pattern=vendor/" in argv


def test_oxlint_argv_win32_keeps_config(monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    argv = orchestrator.oxlint_argv("target")
    assert argv[:2] == ["cmd", "/c"]
    assert "--config" in argv
    assert argv[-1] == "target"


def test_oxlint_suspicious_diagnostic_stays_low() -> None:
    from bravoguard.normalizer import normalize_oxlint

    findings = normalize_oxlint(SUSPICIOUS_PAYLOAD)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == "oxlint-eslint(no-new)"
    assert finding["severity"] == "LOW"
    assert finding["severity"] in ("LOW", "MEDIUM")


def test_trivy_argv_includes_license_not_secret() -> None:
    argv = orchestrator.trivy_argv("target")
    scanners = argv[argv.index("--scanners") + 1].split(",")
    assert scanners == ["vuln", "misconfig", "license"]
    assert "secret" not in scanners


def test_normalize_trivy_license_fixture() -> None:
    payload = json.loads((FIXTURES / "trivy-license.json").read_text(encoding="utf-8"))
    findings = normalize_trivy(payload)
    assert len(findings) == 3
    for finding in findings:
        assert finding["severity"] == "LOW"
        assert finding["cwe"] == ""
        assert finding["rule_id"].startswith("trivy-license-")
    lodash = next(f for f in findings if "lodash" in f["rule_id"])
    assert "lodash" in lodash["fix_hint"]
    assert lodash["path"] == "package-lock.json"
    assert "MIT" in lodash["message"]


def test_normalize_trivy_license_cwe_when_present() -> None:
    payload = {
        "Results": [
            {
                "Target": "package-lock.json",
                "Licenses": [
                    {"PkgName": "pkg", "Name": "MIT", "CweIDs": ["CWE-79"]},
                    {"PkgName": "other", "Name": "Apache-2.0"},
                ],
            }
        ]
    }
    findings = normalize_trivy(payload)
    assert next(f for f in findings if "pkg" in f["rule_id"])["cwe"] == "CWE-79"
    assert next(f for f in findings if "other" in f["rule_id"])["cwe"] == ""


def test_normalize_trivy_license_empty() -> None:
    assert normalize_trivy({}) == []
    assert normalize_trivy({"Results": []}) == []
    assert normalize_trivy({"Results": [{"Target": "x"}]}) == []


def test_semgrep_python_group_argv() -> None:
    argv = orchestrator.semgrep_argv(
        ["a.py"], None, orchestrator._sast_rule_dirs("python")
    )
    configs = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "--config"]
    assert any(p.endswith("rules/python") for p in configs)
    assert any(p.endswith("rules/supply-chain") for p in configs)
    assert not any(p.endswith("rules/frontend") for p in configs)
    assert "--json" in argv
    assert "a.py" in argv


def test_semgrep_javascript_group_argv() -> None:
    argv = orchestrator.semgrep_argv(
        ["b.js"], None, orchestrator._sast_rule_dirs("javascript")
    )
    configs = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "--config"]
    assert any(p.endswith("rules/frontend") for p in configs)
    assert not any(p.endswith("rules/python") for p in configs)
    assert "b.js" in argv


def test_opengrep_fallback_argv_matches_semgrep_groups() -> None:
    for group in ("python", "javascript"):
        semgrep = orchestrator.semgrep_argv(
            ["f"], None, orchestrator._sast_rule_dirs(group)
        )
        opengrep = orchestrator.opengrep_argv(
            ["f"], None, orchestrator._sast_rule_dirs(group)
        )
        assert opengrep[0] == "opengrep"
        assert semgrep[1:] == opengrep[1:]


def test_sast_rule_dirs_single_branch() -> None:
    assert str(orchestrator._sast_rule_dirs("python")[0]).endswith("rules/python")
    assert str(orchestrator._sast_rule_dirs("python")[1]).endswith("rules/supply-chain")
    assert str(orchestrator._sast_rule_dirs("javascript")[0]).endswith("rules/frontend")
    assert str(orchestrator._sast_rule_dirs("other")[0]).endswith("rules")


def _install_group_aware_fake(monkeypatch, calls: list) -> None:
    """Semgrep fake routing on --config: python group returns pickle, js returns frontend."""

    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append(list(argv))
        name = Path(str(argv[0])).name
        arglist = [str(a) for a in argv]
        if name in ("semgrep", "opengrep"):
            if any("rules/frontend" in a for a in arglist):
                payload = {
                    "results": [
                        {
                            "check_id": "bravoguard-frontend-dangerous-html",
                            "path": "app.js",
                            "start": {"line": 1, "col": 1},
                            "extra": {
                                "message": "Avoid innerHTML.",
                                "severity": "WARNING",
                                "metadata": {"cwe": "CWE-79"},
                            },
                        }
                    ]
                }
            else:
                payload = {
                    "results": [
                        {
                            "check_id": "bravoguard-python-pickle-load",
                            "path": "app.py",
                            "start": {"line": 3, "col": 5},
                            "extra": {
                                "message": "Avoid pickle.",
                                "severity": "ERROR",
                                "metadata": {"cwe": "CWE-502"},
                            },
                        }
                    ]
                }
            return FakeProcess(json.dumps(payload).encode(), 1)
        if name == "bandit":
            return FakeProcess(b'{"results": []}', 0)
        if name == "betterleaks":
            return FakeProcess(b"[]", 0)
        raise FileNotFoundError(name)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)


def test_scan_diff_py_only_never_passes_frontend(monkeypatch) -> None:
    calls: list = []
    _install_group_aware_fake(monkeypatch, calls)
    py_diff = (
        "diff --git a/app.py b/app.py\n"
        "index 1111111..2222222 100644\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -0,0 +1 @@\n"
        "+import pickle\n"
    )
    result = asyncio.run(orchestrator.scan_diff(py_diff))
    assert result["status"] == "ok"
    semgrep_calls = [a for a in calls if Path(str(a[0])).name == "semgrep"]
    assert len(semgrep_calls) == 1
    assert not any("rules/frontend" in str(a) for a in semgrep_calls[0])
    assert any("rules/python" in str(a) for a in semgrep_calls[0])
    assert {f["rule_id"] for f in result["findings"]} == {"bravoguard-python-pickle-load"}


def test_scan_diff_js_only_never_passes_python(monkeypatch) -> None:
    calls: list = []
    _install_group_aware_fake(monkeypatch, calls)
    js_diff = (
        "diff --git a/app.js b/app.js\n"
        "index 1111111..2222222 100644\n"
        "--- a/app.js\n"
        "+++ b/app.js\n"
        "@@ -0,0 +1 @@\n"
        "+el.innerHTML = x;\n"
    )
    result = asyncio.run(orchestrator.scan_diff(js_diff))
    assert result["status"] == "ok"
    semgrep_calls = [a for a in calls if Path(str(a[0])).name == "semgrep"]
    assert len(semgrep_calls) == 1
    assert not any("rules/python" in str(a) for a in semgrep_calls[0])
    assert any("rules/frontend" in str(a) for a in semgrep_calls[0])
    assert {f["rule_id"] for f in result["findings"]} == {
        "bravoguard-frontend-dangerous-html"
    }


def test_scan_diff_mixed_split_findings_identical(monkeypatch) -> None:
    """Mixed diff runs one invocation per language group; findings merge losslessly."""
    calls: list = []
    _install_group_aware_fake(monkeypatch, calls)
    mixed = (
        "diff --git a/app.py b/app.py\n"
        "index 1111111..2222222 100644\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -0,0 +1 @@\n"
        "+import pickle\n"
        "diff --git a/app.js b/app.js\n"
        "index 1111111..2222222 100644\n"
        "--- a/app.js\n"
        "+++ b/app.js\n"
        "@@ -0,0 +1 @@\n"
        "+el.innerHTML = x;\n"
    )
    result = asyncio.run(orchestrator.scan_diff(mixed))
    semgrep_calls = [a for a in calls if Path(str(a[0])).name == "semgrep"]
    assert len(semgrep_calls) == 2
    assert {f["rule_id"] for f in result["findings"]} == {
        "bravoguard-python-pickle-load",
        "bravoguard-frontend-dangerous-html",
    }
