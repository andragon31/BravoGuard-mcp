"""T1 language detection + lane routing tests (Fase 0.1).

Markers unit tests on tmp dirs, suffix census counts, scan_diff/scan_repo
routing with mocked scanner subprocesses (dispatcher pattern follows
tests/test_lanes.py), ``languages`` presence in both entry points, and a
findings-identical regression on the mixed fixture. Never invokes real
binaries (the supply lane is in-process pure Python, same as existing
suites that let it run for real).
"""

import asyncio
import json
from pathlib import Path

import pytest

from bravoguard import languages, orchestrator
from bravoguard.languages import (
    CONTAINER_MARKERS,
    JS_MARKERS,
    LANE_GATES,
    PYTHON_MARKERS,
    UNSUPPORTED_MARKERS,
    detect_languages,
    lanes_for,
)
from bravoguard.normalizer import (
    normalize_bandit,
    normalize_checkov,
    normalize_findings,
    normalize_oxlint,
    normalize_semgrep,
    normalize_trivy,
)
from bravoguard.supply import scan_supply

FIXTURES = Path(__file__).parent / "fixtures" / "languages"

PY_DIFF = """\
diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -0,0 +1,3 @@
+import pickle
+data = input()
+obj = pickle.load(data)
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

MIXED_DIFF = PY_DIFF + JS_DIFF


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


def install_t1_fake(
    monkeypatch: pytest.MonkeyPatch,
    calls: list,
    payloads: dict | None = None,
    missing: set = frozenset(),
) -> None:
    """Fake dispatcher: canned payloads per lane, FileNotFoundError when missing.

    Routes on argv content (win32 oxlint arrives as ``cmd /c oxlint``,
    checkov always as ``uv tool run ...``); mirrors test_lanes.py.
    """

    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append(list(argv))
        assert "shell" not in kwargs, "scanners must never run with shell=True"
        first = Path(str(argv[0])).name
        names = {Path(str(a)).name for a in argv}
        if "oxlint" in names:
            label = "oxlint"
        elif "trivy" in names:
            label = "trivy"
        elif first == "uv" and "checkov" in names:
            label = "checkov"
        else:
            label = first
        if label in missing:
            raise FileNotFoundError(label)
        defaults = {
            "semgrep": (b'{"results": []}', 0),
            "opengrep": (b'{"results": []}', 0),
            "bandit": (b'{"results": []}', 0),
            "betterleaks": (b"[]", 0),
            "oxlint": (b'{"diagnostics": []}', 0),
            "trivy": (b"{}", 0),
            "checkov": (b'{"results": {"failed_checks": []}}', 0),
        }
        if label not in (payloads or {}) and label not in defaults:
            raise FileNotFoundError(label)
        stdout, returncode = (payloads or {}).get(label, defaults[label])
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


def bandit_pickle_payload() -> bytes:
    return json.dumps(
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


def oxlint_debugger_payload() -> bytes:
    return json.dumps(
        {
            "diagnostics": [
                {
                    "message": "`debugger` statement is not allowed",
                    "code": "eslint(no-debugger)",
                    "severity": "warning",
                    "causes": [],
                    "url": "",
                    "help": "Remove the debugger statement",
                    "filename": "app.js",
                    "labels": [{"span": {"offset": 11, "length": 9, "line": 2, "column": 1}}],
                    "related": [],
                }
            ],
            "number_of_files": 1,
            "number_of_rules": 95,
        }
    ).encode()


def trivy_django_payload() -> bytes:
    return json.dumps(
        {
            "SchemaVersion": 2,
            "ArtifactName": "bg-mixed",
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
                            "FixedVersion": "2.2.4",
                            "Severity": "CRITICAL",
                            "Title": "Django: SQL injection possibility in key lookups",
                            "CweIDs": ["CWE-89"],
                            "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-14234",
                        }
                    ],
                }
            ],
        }
    ).encode()


def checkov_fail_payload() -> bytes:
    return json.dumps(
        {
            "check_type": "terraform",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV2_AWS_62",
                        "bc_check_id": "BC_AWS_LOGGING_36",
                        "check_name": "S3 buckets should have event notifications enabled",
                        "file_path": "/main.tf",
                        "file_abs_path": "/tmp/bg-ck/main.tf",
                        "repo_file_path": "/tmp/bg-ck/main.tf",
                        "file_line_range": [1, 3],
                        "resource": "aws_s3_bucket.b",
                        "severity": None,
                        "guideline": "https://example.invalid/policy",
                    }
                ]
            },
            "summary": {"passed": 0, "failed": 1, "skipped": 0, "parsing_errors": 0},
        }
    ).encode()


def spawned_binaries(calls: list) -> set[str]:
    names: set[str] = set()
    for argv in calls:
        first = Path(str(argv[0])).name
        hit = {Path(str(a)).name for a in argv} | {first}
        if "oxlint" in hit:
            names.add("oxlint")
        elif "trivy" in hit:
            names.add("trivy")
        elif first == "uv" and "checkov" in hit:
            names.add("checkov")
        else:
            names.add(first)
    return names


# --- marker + census unit tests --------------------------------------------


def test_marker_constants_pin_spec_lists() -> None:
    assert "pyproject.toml" in PYTHON_MARKERS
    assert "setup.py" in PYTHON_MARKERS
    assert "setup.cfg" in PYTHON_MARKERS
    assert "Pipfile" in PYTHON_MARKERS
    assert "poetry.lock" in PYTHON_MARKERS
    assert "package.json" in JS_MARKERS
    assert "package-lock.json" in JS_MARKERS
    assert "yarn.lock" in JS_MARKERS
    assert "pnpm-lock.yaml" in JS_MARKERS
    assert "tsconfig.json" in JS_MARKERS
    assert "Dockerfile" in CONTAINER_MARKERS
    assert "Containerfile" in CONTAINER_MARKERS
    assert "docker-compose.yml" in CONTAINER_MARKERS
    assert "docker-compose.yaml" in CONTAINER_MARKERS
    assert "compose.yml" in CONTAINER_MARKERS
    assert UNSUPPORTED_MARKERS == {
        "go.mod": "go",
        "Cargo.toml": "rust",
        "Gemfile": "ruby",
        "composer.json": "php",
        "pom.xml": "java",
    }


def test_lane_gates_classify_existing_lanes() -> None:
    assert LANE_GATES["bandit"]["kind"] == "suffix"
    assert LANE_GATES["bandit"]["languages"] == ("python",)
    assert LANE_GATES["oxlint"]["kind"] == "suffix"
    assert LANE_GATES["oxlint"]["languages"] == ("javascript",)
    assert set(LANE_GATES["sast"]["languages"]) == {"python", "javascript"}
    assert LANE_GATES["supply"]["kind"] == "manifest"


def test_py_only_dir(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n', encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    detection = detect_languages(tmp_path)
    assert detection["languages"] == ["python"]
    assert "pyproject.toml" in detection["markers"]["python"]
    assert detection["markers"]["javascript"] == []
    assert detection["census"] == {"python": 1, "javascript": 0}
    assert detection["typescript"] is False
    assert detection["containers"] is False
    assert detection["unsupported"] == []


def test_js_only_dir(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "x"}\n', encoding="utf-8")
    (tmp_path / "app.js").write_text("console.log(1);\n", encoding="utf-8")
    detection = detect_languages(tmp_path)
    assert detection["languages"] == ["javascript"]
    assert "package.json" in detection["markers"]["javascript"]
    assert detection["census"] == {"python": 0, "javascript": 1}
    assert detection["typescript"] is False


def test_typescript_flag_from_ts_suffix_and_tsconfig(tmp_path: Path) -> None:
    (tmp_path / "app.ts").write_text("const x: number = 1;\n", encoding="utf-8")
    assert detect_languages(tmp_path)["typescript"] is True
    assert detect_languages(tmp_path)["languages"] == ["javascript"]
    tsconfig_only = tmp_path / "cfg"
    tsconfig_only.mkdir()
    (tsconfig_only / "tsconfig.json").write_text("{}\n", encoding="utf-8")
    detection = detect_languages(tsconfig_only)
    assert detection["typescript"] is True
    assert detection["languages"] == ["javascript"]


def test_mixed_dir_and_census_counts(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n', encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name": "x"}\n', encoding="utf-8")
    for name in ("a.py", "b.py", "c.pyi"):
        (tmp_path / name).write_text("x = 1\n", encoding="utf-8")
    for name in ("a.js", "b.tsx"):
        (tmp_path / name).write_text("let x = 1;\n", encoding="utf-8")
    detection = detect_languages(tmp_path)
    assert detection["languages"] == ["python", "javascript"]
    assert detection["census"] == {"python": 3, "javascript": 2}
    assert detection["typescript"] is True


def test_containers_only_dir(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM ubuntu:22.04\n", encoding="utf-8")
    (tmp_path / "compose.yml").write_text("services: {}\n", encoding="utf-8")
    detection = detect_languages(tmp_path)
    assert detection["languages"] == ["containers"]
    assert detection["containers"] is True
    assert detection["census"] == {"python": 0, "javascript": 0}
    assert "Dockerfile" in detection["markers"]["containers"]


def test_dockerfile_variant_and_requirements_glob(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile.prod").write_text("FROM ubuntu:22.04\n", encoding="utf-8")
    (tmp_path / "requirements-dev.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    detection = detect_languages(tmp_path)
    assert detection["containers"] is True
    assert "Dockerfile.prod" in detection["markers"]["containers"]
    assert "requirements-dev.txt" in detection["markers"]["python"]
    assert detection["languages"] == ["python", "containers"]


def test_unsupported_markers_reported_never_faked(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module example\n", encoding="utf-8")
    detection = detect_languages(tmp_path)
    assert detection["unsupported"] == ["go"]
    assert detection["languages"] == []


def test_empty_dir(tmp_path: Path) -> None:
    detection = detect_languages(tmp_path)
    assert detection["languages"] == []
    assert detection["census"] == {"python": 0, "javascript": 0}
    assert detection["markers"] == {"python": [], "javascript": [], "containers": []}
    assert detection["typescript"] is False
    assert detection["containers"] is False
    assert detection["unsupported"] == []


def test_git_tree_and_symlinks_never_counted(tmp_path: Path) -> None:
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "evil.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "app.js").write_text("let x = 1;\n", encoding="utf-8")
    outside = tmp_path / "outside.py"
    outside.write_text("y = 2\n", encoding="utf-8")
    link = tmp_path / "link.py"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    detection = detect_languages(tmp_path)
    # .git/evil.py ignored, link.py symlink ignored: only outside.py counts.
    assert detection["census"] == {"python": 1, "javascript": 1}


def test_nested_markers_found(tmp_path: Path) -> None:
    nested = tmp_path / "backend"
    nested.mkdir()
    (nested / "pyproject.toml").write_text('[project]\nname = "x"\n', encoding="utf-8")
    detection = detect_languages(tmp_path)
    assert detection["languages"] == ["python"]


def test_single_file_target() -> None:
    target = FIXTURES / "py-only" / "app.py"
    detection = detect_languages(target)
    assert detection["languages"] == ["python"]
    assert detection["census"] == {"python": 1, "javascript": 0}


def test_bounded_census_caps_files_examined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for i in range(5):
        (tmp_path / f"mod{i}.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(languages, "MAX_CENSUS_FILES", 3)
    assert detect_languages(tmp_path)["census"] == {"python": 3, "javascript": 0}


# --- lanes_for routing unit tests -------------------------------------------


def test_lanes_for_py_only_skips_js_lanes(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n', encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    skips = lanes_for(detect_languages(tmp_path))
    assert skips == {"oxlint": "no javascript files or markers detected"}


def test_lanes_for_js_only_skips_python_lanes(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "x"}\n', encoding="utf-8")
    (tmp_path / "app.js").write_text("let x = 1;\n", encoding="utf-8")
    skips = lanes_for(detect_languages(tmp_path))
    # sast covers both languages so it still runs on JS; supply needs py manifests.
    assert skips == {
        "bandit": "no python files or markers detected",
        "supply": "no python manifests detected",
    }


def test_lanes_for_empty_dir_skips_all_gated(tmp_path: Path) -> None:
    skips = lanes_for(detect_languages(tmp_path))
    # T4: syft/grype gated on any-stack signals; empty dir skips them too.
    # T5: guarddog manifest-gated; empty dir skips it too.
    assert set(skips) == {"sast", "bandit", "oxlint", "supply", "syft", "grype", "guarddog"}
    assert skips["sast"] == "no python or javascript files detected"
    assert skips["supply"] == "no python manifests detected"


def test_lanes_for_mixed_runs_everything() -> None:
    assert lanes_for(detect_languages(FIXTURES / "mixed")) == {}


def test_sast_targets_partition_hook() -> None:
    grouped = orchestrator._sast_targets_by_language(
        [Path("a.py"), Path("b.js"), Path("c.ts"), Path("notes.md")]
    )
    assert [p.name for p in grouped["python"]] == ["a.py"]
    assert [p.name for p in grouped["javascript"]] == ["b.js", "c.ts"]
    assert [p.name for p in grouped["other"]] == ["notes.md"]


# --- scan_diff routing --------------------------------------------------------


def test_scan_diff_py_only_runs_bandit(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    install_t1_fake(
        monkeypatch,
        calls,
        {"semgrep": (semgrep_pickle_payload(), 1), "bandit": (bandit_pickle_payload(), 1)},
    )
    result = asyncio.run(orchestrator.scan_diff(PY_DIFF))
    assert result["status"] == "ok"
    assert "skipped" not in result
    assert result["languages"]["languages"] == ["python"]
    assert "bandit" in spawned_binaries(calls)
    rule_ids = {f["rule_id"] for f in result["findings"]}
    assert "bravoguard-python-pickle-load" in rule_ids
    assert "B301" in rule_ids


def test_scan_diff_js_only_skips_bandit(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    install_t1_fake(monkeypatch, calls)
    result = asyncio.run(orchestrator.scan_diff(JS_DIFF))
    assert result["status"] == "ok"
    assert result["languages"]["languages"] == ["javascript"]
    assert result["skipped"] == {"bandit": "no python files in diff"}
    assert "bandit" not in spawned_binaries(calls)
    assert "semgrep" in spawned_binaries(calls)


def test_scan_diff_mixed_bandit_runs_semgrep_covers_both(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list = []
    install_t1_fake(
        monkeypatch,
        calls,
        {"semgrep": (semgrep_pickle_payload(), 1), "bandit": (bandit_pickle_payload(), 1)},
    )
    result = asyncio.run(orchestrator.scan_diff(MIXED_DIFF))
    assert result["status"] == "ok"
    assert result["languages"]["languages"] == ["python", "javascript"]
    assert "skipped" not in result
    assert "bandit" in spawned_binaries(calls)
    semgrep_argvs = [a for a in calls if Path(str(a[0])).name == "semgrep"]
    # T2 split: one invocation per language group (python: rules/python, js: rules/frontend).
    scanned = sorted(
        Path(str(a)).name
        for argv in semgrep_argvs
        for a in argv
        if str(a).endswith((".py", ".js"))
    )
    assert scanned == ["app.js", "app.py"]
    py_argv = next(a for a in semgrep_argvs if any(str(x).endswith("rules/python") for x in a))
    assert any(Path(str(x)).name == "app.py" for x in py_argv)
    js_argv = next(a for a in semgrep_argvs if any(str(x).endswith("rules/frontend") for x in a))
    assert any(Path(str(x)).name == "app.js" for x in js_argv)
    rule_ids = {f["rule_id"] for f in result["findings"]}
    assert {"bravoguard-python-pickle-load", "B301"} <= rule_ids


def test_scan_diff_mixed_findings_identical_to_ungated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mixed diff: every diff lane runs, so findings equal the normalizer baseline."""
    calls: list = []
    semgrep_raw = json.loads(semgrep_pickle_payload().decode())
    bandit_raw = json.loads(bandit_pickle_payload().decode())
    install_t1_fake(
        monkeypatch,
        calls,
        {"semgrep": (semgrep_pickle_payload(), 1), "bandit": (bandit_pickle_payload(), 1)},
    )
    result = asyncio.run(orchestrator.scan_diff(MIXED_DIFF))
    expected = normalize_findings(normalize_semgrep(semgrep_raw) + normalize_bandit(bandit_raw))
    assert result["findings"] == expected
    assert "skipped" not in result


# --- scan_repo routing ---------------------------------------------------------


def test_scan_repo_py_only_skips_oxlint(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list = []
    install_t1_fake(monkeypatch, calls)
    result = asyncio.run(orchestrator.scan_repo(str(FIXTURES / "py-only")))
    assert result["status"] == "ok"
    assert result["languages"]["languages"] == ["python"]
    # T3: trufflehog verify is opt-in, always reported skipped by default.
    # T4: syft/grype binaries absent here -> missing-binary skips.
    # T5: guarddog binary absent here -> missing-binary skip.
    assert result["skipped"] == {
        "oxlint": "no javascript files or markers detected",
        "trufflehog": "trufflehog verify is opt-in: pass verify_secrets=True",
        "syft": "syft not installed: SBOM store skipped",
        "grype": "syft SBOM unavailable: no SBOM to match",
        "guarddog": "guarddog not installed: heuristics lane skipped",
    }
    binaries = spawned_binaries(calls)
    assert "bandit" in binaries
    assert "oxlint" not in binaries


def test_scan_repo_js_only_skips_bandit_and_supply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list = []
    install_t1_fake(monkeypatch, calls)
    result = asyncio.run(orchestrator.scan_repo(str(FIXTURES / "js-only")))
    assert result["status"] == "ok"
    assert result["languages"]["languages"] == ["javascript"]
    assert result["skipped"] == {
        "bandit": "no python files or markers detected",
        "supply": "no python manifests detected",
        "trufflehog": "trufflehog verify is opt-in: pass verify_secrets=True",
        "syft": "syft not installed: SBOM store skipped",
        "grype": "syft SBOM unavailable: no SBOM to match",
        "guarddog": "guarddog not installed: heuristics lane skipped",
    }
    binaries = spawned_binaries(calls)
    assert "oxlint" in binaries
    assert "bandit" not in binaries


def test_scan_repo_container_only_skips_code_lanes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list = []
    install_t1_fake(monkeypatch, calls)
    result = asyncio.run(orchestrator.scan_repo(str(FIXTURES / "container-only")))
    assert result["status"] == "ok"
    assert result["languages"]["languages"] == ["containers"]
    assert result["languages"]["containers"] is True
    # T5: container-only has no manifests -> guarddog gate skip.
    assert set(result["skipped"]) == {
        "sast", "bandit", "oxlint", "supply", "trufflehog", "syft", "grype", "guarddog",
    }
    binaries = spawned_binaries(calls)
    assert {"trivy", "checkov"} <= binaries
    assert not ({"semgrep", "bandit", "oxlint"} & binaries)


def test_scan_repo_mixed_findings_identical_to_ungated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mixed fixture: only the opt-in lane is skipped, findings equal the baseline."""
    assert scan_supply(FIXTURES / "mixed", orchestrator.DEFAULT_EXCLUDES) == []
    semgrep_raw = json.loads(semgrep_pickle_payload().decode())
    bandit_raw = json.loads(bandit_pickle_payload().decode())
    oxlint_raw = json.loads(oxlint_debugger_payload().decode())
    trivy_raw = json.loads(trivy_django_payload().decode())
    checkov_raw = json.loads(checkov_fail_payload().decode())
    calls: list = []
    install_t1_fake(
        monkeypatch,
        calls,
        {
            "semgrep": (semgrep_pickle_payload(), 1),
            "bandit": (bandit_pickle_payload(), 1),
            "oxlint": (oxlint_debugger_payload(), 0),
            "trivy": (trivy_django_payload(), 0),
            "checkov": (checkov_fail_payload(), 0),
        },
    )
    result = asyncio.run(orchestrator.scan_repo(str(FIXTURES / "mixed")))
    expected = normalize_findings(
        normalize_semgrep(semgrep_raw)
        + normalize_bandit(bandit_raw)
        + normalize_oxlint(oxlint_raw)
        + normalize_trivy(trivy_raw)
        + normalize_checkov(checkov_raw)
    )
    assert result["findings"] == expected
    # T3: trufflehog verify is opt-in, reported skipped even on mixed fixtures.
    # T4: syft/grype binaries absent here -> missing-binary skips.
    # T5: guarddog binary absent here -> missing-binary skip.
    assert result["skipped"] == {
        "trufflehog": "trufflehog verify is opt-in: pass verify_secrets=True",
        "syft": "syft not installed: SBOM store skipped",
        "grype": "syft SBOM unavailable: no SBOM to match",
        "guarddog": "guarddog not installed: heuristics lane skipped",
    }
    assert result["languages"]["languages"] == ["python", "javascript"]
    assert result["languages"]["typescript"] is True
    assert result["languages"]["census"] == {"python": 1, "javascript": 2}
    binaries = spawned_binaries(calls)
    assert {"semgrep", "bandit", "betterleaks", "oxlint", "trivy", "checkov"} <= binaries
