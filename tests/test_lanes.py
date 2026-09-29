"""M1 multi-lane tests: oxlint + trivy + checkov argv, parsing, normalization.

Fixtures mirror REAL captured outputs (oxlint 1.65.0 ``--format json``,
trivy 0.74.0 ``fs --format json``, checkov 3.3.20 ``-o json``); only the
second oxlint diagnostic (error severity) is a synthetic variation of the
same real shape to pin the error->MEDIUM mapping.
"""

import asyncio
import json
import sys
from pathlib import Path

import pytest

from bravoguard import orchestrator
from bravoguard.orchestrator import FINDING_KEYS, OrchestratorError

OXLINT_PAYLOAD = {
    "diagnostics": [
        {
            "message": "`debugger` statement is not allowed",
            "code": "eslint(no-debugger)",
            "severity": "warning",
            "causes": [],
            "url": "https://oxc.rs/docs/guide/usage/linter/rules/eslint/no-debugger.html",
            "help": "Remove the debugger statement",
            "filename": "C:/tmp/bg-ox/bad.js",
            "labels": [{"span": {"offset": 11, "length": 9, "line": 2, "column": 1}}],
            "related": [],
        },
        {
            "message": "`eval` is dangerous",
            "code": "eslint(no-eval)",
            "severity": "error",
            "causes": [],
            "url": "",
            "help": "Avoid eval",
            "filename": "C:/tmp/bg-ox/bad.js",
            "labels": [{"span": {"offset": 0, "length": 4, "line": 5, "column": 1}}],
            "related": [],
        },
    ],
    "number_of_files": 1,
    "number_of_rules": 95,
}

TRIVY_PAYLOAD = {
    "SchemaVersion": 2,
    "ArtifactName": "bg-tr2",
    "ArtifactType": "filesystem",
    "Results": [
        {
            "Target": "requirements.txt",
            "Class": "lang-pkgs",
            "Type": "pip",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2019-14234",
                    "PkgName": "django",
                    "InstalledVersion": "2.2",
                    "FixedVersion": "1.11.23, 2.1.11, 2.2.4",
                    "Severity": "CRITICAL",
                    "Title": "Django: SQL injection possibility in key lookups",
                    "CweIDs": ["CWE-89"],
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-14234",
                },
                {
                    "VulnerabilityID": "CVE-0000-0000",
                    "PkgName": "django",
                    "InstalledVersion": "2.2",
                    "FixedVersion": "",
                    "Severity": "",
                    "Title": "No CWE, no severity",
                    "CweIDs": [],
                    "PrimaryURL": "",
                },
            ],
        },
        {
            "Target": "Dockerfile",
            "Class": "config",
            "Type": "dockerfile",
            "Misconfigurations": [
                {
                    "ID": "DS-0001",
                    "Title": "':latest' tag used",
                    "Description": "Use a specific tag.",
                    "Severity": "MEDIUM",
                    "Message": "Specify a tag in the 'FROM' statement for image 'ubuntu'",
                    "Resolution": "Add a tag to the image in the 'FROM' statement",
                    "PrimaryURL": "https://avd.aquasec.com/misconfig/ds-0001",
                    "CauseMetadata": {"Provider": "Dockerfile", "StartLine": 1, "EndLine": 1},
                }
            ],
        },
    ],
}

CHECKOV_PAYLOAD = {
    "check_type": "terraform",
    "results": {
        "failed_checks": [
            {
                "check_id": "CKV2_AWS_62",
                "bc_check_id": "BC_AWS_LOGGING_36",
                "check_name": "Ensure S3 buckets should have event notifications enabled",
                "file_path": "/main.tf",
                "file_abs_path": "C:/tmp/bg-ck/main.tf",
                "repo_file_path": "/tmp/bg-ck/main.tf",
                "file_line_range": [1, 3],
                "resource": "aws_s3_bucket.b",
                "severity": None,
                "guideline": "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-logging-policies/bc-aws-2-62",
            }
        ]
    },
    "summary": {"passed": 0, "failed": 1, "skipped": 0, "parsing_errors": 0},
}

CHECKOV_SUMMARY_ONLY = {
    "passed": 0,
    "failed": 0,
    "skipped": 0,
    "parsing_errors": 0,
    "resource_count": 0,
    "checkov_version": "3.3.20",
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


def install_lane_fake(monkeypatch: pytest.MonkeyPatch, calls: list, missing: set = frozenset()) -> None:
    """Fake dispatcher: quiet legacy lanes + real-shape M1 payloads.

    Routes on argv content (win32 oxlint arrives as ``cmd /c oxlint``,
    checkov always as ``uv tool run ...``); names in ``missing`` raise
    FileNotFoundError to emulate absent binaries.
    """

    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append(list(argv))
        assert "shell" not in kwargs, "scanners must never run with shell=True"
        table = {
            "semgrep": (b'{"results": []}', 0),
            "bandit": (b'{"results": []}', 0),
            "betterleaks": (b"[]", 0),
            "oxlint": (json.dumps(OXLINT_PAYLOAD).encode(), 0),
            "trivy": (json.dumps(TRIVY_PAYLOAD).encode(), 0),
            "uv": (json.dumps(CHECKOV_PAYLOAD).encode(), 0),
        }
        names = {Path(str(a)).name for a in argv}
        if "oxlint" in names:
            label = "oxlint"
        elif "trivy" in names:
            label = "trivy"
        elif "uv" in names and "checkov" in names:
            label = "uv"
        else:
            label = Path(str(argv[0])).name
        lane = {"uv": "checkov"}.get(label, label)
        if lane in missing or label in missing:
            raise FileNotFoundError(label)
        if label not in table:
            raise FileNotFoundError(label)
        stdout, returncode = table[label]
        return FakeProcess(stdout, returncode)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)


def test_oxlint_argv_uses_json_format_and_win32_cmd_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    posix = orchestrator.oxlint_argv("target")
    assert posix == ["oxlint", "--format", "json", "target"]
    monkeypatch.setattr(sys, "platform", "win32")
    win = orchestrator.oxlint_argv("target")
    assert win[:3] == ["cmd", "/c", "oxlint"]
    assert "--format" in win and "json" in win and win[-1] == "target"


def test_oxlint_argv_forwards_excludes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    argv = orchestrator.oxlint_argv("target", ("*.min.js", "vendor/"))
    assert "--ignore-pattern=*.min.js" in argv
    assert "--ignore-pattern=vendor/" in argv
    assert argv[-1] == "target"


def test_trivy_argv_excludes_secret_scanner_and_translates_excludes() -> None:
    argv = orchestrator.trivy_argv("target", ("frames/", "*.wav", "skip.py"))
    assert argv[:6] == ["trivy", "fs", "--format", "json", "--scanners", "vuln,misconfig"]
    scanners = argv[argv.index("--scanners") + 1]
    assert "secret" not in scanners.split(",")
    assert argv[-1] == "target"
    assert "--skip-dirs" in argv
    assert argv[argv.index("--skip-dirs") + 1] == "frames"
    skips = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "--skip-files"]
    assert "*.wav" in skips
    assert "**/skip.py" in skips


def test_trivy_argv_default_has_no_skip_flags() -> None:
    assert orchestrator.trivy_argv("target") == [
        "trivy",
        "fs",
        "--format",
        "json",
        "--scanners",
        "vuln,misconfig",
        "target",
    ]


def test_checkov_argv_uses_uv_tool_run_and_skip_path() -> None:
    argv = orchestrator.checkov_argv("target")
    assert argv[:6] == ["uv", "tool", "run", "--from", "checkov", "checkov"]
    assert "-d" in argv and "-o" in argv
    assert argv[argv.index("-o") + 1] == "json"
    assert "--quiet" in argv and "--compact" in argv
    assert argv[argv.index("-d") + 1] == "target"
    assert "--skip-path" not in argv
    with_excludes = orchestrator.checkov_argv("target", ("*.wav",))
    assert "--skip-path" in with_excludes


def test_normalize_oxlint_severity_map_and_no_cwe() -> None:
    from bravoguard.normalizer import normalize_oxlint

    findings = normalize_oxlint(OXLINT_PAYLOAD)
    assert len(findings) == 2
    warn = next(f for f in findings if f["rule_id"] == "oxlint-eslint(no-debugger)")
    assert set(warn) == set(FINDING_KEYS)
    assert warn["severity"] == "LOW"
    assert warn["cwe"] == ""
    assert warn["line"] == 2
    assert warn["fix_hint"] == "Remove the debugger statement"
    err = next(f for f in findings if f["rule_id"] == "oxlint-eslint(no-eval)")
    assert err["severity"] == "MEDIUM"
    assert err["cwe"] == ""
    assert normalize_oxlint({}) == []
    assert normalize_oxlint({"diagnostics": []}) == []


def test_normalize_trivy_vuln_capped_and_misconfig_hint() -> None:
    from bravoguard.normalizer import normalize_trivy

    findings = normalize_trivy(TRIVY_PAYLOAD)
    assert len(findings) == 3
    vuln = next(f for f in findings if f["rule_id"] == "trivy-CVE-2019-14234")
    assert set(vuln) == set(FINDING_KEYS)
    assert vuln["cwe"] == "CWE-89"
    assert vuln["severity"] == "HIGH"
    assert "1.11.23" in vuln["fix_hint"]
    assert vuln["path"] == "requirements.txt"
    bare = next(f for f in findings if f["rule_id"] == "trivy-CVE-0000-0000")
    assert bare["cwe"] == ""
    assert bare["severity"] == "MEDIUM"
    mis = next(f for f in findings if f["rule_id"] == "trivy-DS-0001")
    assert mis["cwe"] == ""
    assert mis["line"] == 1
    assert mis["fix_hint"] == "Add a tag to the image in the 'FROM' statement"
    assert mis["path"] == "Dockerfile"
    assert normalize_trivy({}) == []
    assert normalize_trivy({"SchemaVersion": 2}) == []


def test_normalize_checkov_failed_checks_and_summary_only() -> None:
    from bravoguard.normalizer import normalize_checkov

    findings = normalize_checkov(CHECKOV_PAYLOAD)
    assert len(findings) == 1
    check = findings[0]
    assert set(check) == set(FINDING_KEYS)
    assert check["rule_id"] == "checkov-CKV2_AWS_62"
    assert check["cwe"] == ""
    assert check["severity"] == "MEDIUM"
    assert check["line"] == 1
    assert check["fix_hint"].startswith("https://docs.prismacloud.io")
    assert check["path"] == "C:/tmp/bg-ck/main.tf"
    assert normalize_checkov(CHECKOV_SUMMARY_ONLY) == []
    assert normalize_checkov([CHECKOV_PAYLOAD, CHECKOV_SUMMARY_ONLY]) == findings


def test_scan_repo_runs_three_new_lanes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    calls: list = []
    install_lane_fake(monkeypatch, calls)
    result = asyncio.run(orchestrator.scan_repo(str(tmp_path)))
    assert result["status"] == "ok"
    assert "errors" not in result
    rules = {f["rule_id"] for f in result["findings"]}
    assert "oxlint-eslint(no-debugger)" in rules
    assert "trivy-CVE-2019-14234" in rules
    assert "checkov-CKV2_AWS_62" in rules
    for finding in result["findings"]:
        assert set(finding) == set(FINDING_KEYS)
    oxlint_argv = next(a for a in calls if "oxlint" in a)
    assert "--format" in oxlint_argv and "json" in oxlint_argv
    if sys.platform == "win32":
        assert oxlint_argv[:2] == ["cmd", "/c"]
    trivy_argv = next(a for a in calls if "trivy" in a)
    assert trivy_argv[:2] == ["trivy", "fs"]
    checkov_argv = next(a for a in calls if "checkov" in a)
    assert checkov_argv[:6] == ["uv", "tool", "run", "--from", "checkov", "checkov"]


def test_scan_repo_new_lanes_empty_when_not_applicable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        names = {Path(str(a)).name for a in argv} | set(argv)
        if "oxlint" in names:
            return FakeProcess(b'{"diagnostics": []}', 0)
        if "trivy" in names:
            return FakeProcess(b"{}", 0)
        if "checkov" in names:
            return FakeProcess(json.dumps(CHECKOV_SUMMARY_ONLY).encode(), 0)
        name = Path(str(argv[0])).name
        quiet = {"semgrep": b'{"results": []}', "bandit": b'{"results": []}', "betterleaks": b"[]"}
        if name in quiet:
            return FakeProcess(quiet[name], 0)
        raise FileNotFoundError(name)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)
    result = asyncio.run(orchestrator.scan_repo(str(tmp_path)))
    assert result == {"status": "ok", "findings": []}


def test_scan_repo_new_lanes_missing_degrades_to_not_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    calls: list = []
    install_lane_fake(monkeypatch, calls, missing={"oxlint", "trivy", "checkov"})
    result = asyncio.run(orchestrator.scan_repo(str(tmp_path)))
    assert result["status"] == "ok"
    assert result["findings"] == []
    assert result["errors"] == {
        "oxlint": "not-installed",
        "trivy": "not-installed",
        "checkov": "not-installed",
    }


OXLINT_NO_FILES_STDOUT = (
    b"No files found to lint. Please check your paths and ignore patterns.\n"
    + json.dumps({"diagnostics": [], "number_of_files": 0, "number_of_rules": 95}).encode()
)


def test_scan_repo_oxlint_no_files_returns_ok_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """oxlint rc=1 with preamble + empty envelope is ok/empty, not failed."""
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        names = {Path(str(a)).name for a in argv} | set(argv)
        if "oxlint" in names:
            return FakeProcess(OXLINT_NO_FILES_STDOUT, 1)
        if "trivy" in names:
            return FakeProcess(b"{}", 0)
        if "checkov" in names:
            return FakeProcess(json.dumps(CHECKOV_SUMMARY_ONLY).encode(), 0)
        name = Path(str(argv[0])).name
        quiet = {"semgrep": b'{"results": []}', "bandit": b'{"results": []}', "betterleaks": b"[]"}
        if name in quiet:
            return FakeProcess(quiet[name], 0)
        raise FileNotFoundError(name)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)
    result = asyncio.run(orchestrator.scan_repo(str(tmp_path)))
    assert result == {"status": "ok", "findings": []}


def test_oxlint_garbage_stdout_still_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """oxlint rc=1 with unparsable stdout keeps the failed lane error."""

    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        return FakeProcess(b"oxlint crashed: boom { not json", 1)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)
    with pytest.raises(OrchestratorError):
        asyncio.run(orchestrator._run_oxlint("target", 10))
