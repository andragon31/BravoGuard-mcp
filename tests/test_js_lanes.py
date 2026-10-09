"""T7 JS depth-lane tests: oxlint in diff, eslint, knip, lockfile-lint, npm audit.

All subprocesses are mocked; no real eslint/knip/lockfile-lint/npm binary is
invoked and no network is touched (the npm audit fixture is recorded JSON).
Fixtures under ``tests/fixtures/js-lanes/`` carry recorded-shape payloads:

- eslint ``--format json`` (documented source: eslint docs flag + flat-config
  shape; binary absent in this env, so live ``--help`` re-verification owed).
- knip ``--reporter json`` (documented source: knip.dev reporters page +
  ``cli-arguments.ts`` ``--reporter``/``--directory`` flags; binary absent).
- lockfile-lint plain text (documented source: lirantal/lockfile-lint README
  ``--path/--type/--validate-https/--allowed-hosts`` + ``bin/lockfile-lint.js``
  stderr reporting; binary absent). The fake emits the fixture on stderr to
  prove the runner merges streams (the real binary ``console.error``\\ s each
  validator failure).
- npm audit ``--json`` modern ``vulnerabilities`` shape (documented source:
  npm docs; ``npm`` itself ships with node so no installer entry is needed).

Design decisions (documented cuts, per spec):

- ``eslint-plugin-security`` 4.2.0 exists on the registry (verified via
  ``npm view``) but is CUT: it needs an extra npm dep plus installer support
  for a second package, and the hermetic lane must run with zero extra deps.
  The repo-root ``eslint.config.mjs`` enables only core security-adjacent
  rules (``no-eval``, ``no-implied-eval``, ``no-new-func``, ``no-script-url``).
- Hooks/Next/a11y scope CUT: each needs a heavy plugin dep
  (``eslint-plugin-react-hooks``, ``@next/eslint-plugin-next``,
  ``eslint-plugin-jsx-a11y``) with no installer support; pulling them would
  trade a hermetic lane for a dependency fan-out. Documented here, not wired.
"""

import asyncio
import json
import shutil
from pathlib import Path

from bravoguard import orchestrator
from bravoguard.languages import LANE_GATES, SKIP_REASONS, detect_languages, lanes_for
from bravoguard.normalizer import (
    FINDING_KEYS,
    normalize_eslint,
    normalize_knip,
    normalize_lockfile_lint,
    normalize_npm_audit,
)

FIXTURES = Path(__file__).parent / "fixtures" / "js-lanes"
ESLINT_FIXTURE = FIXTURES / "eslint.json"
KNIP_FIXTURE = FIXTURES / "knip.json"
LOCKFILE_FIXTURE = FIXTURES / "lockfile-lint.txt"
NPM_AUDIT_FIXTURE = FIXTURES / "npm-audit.json"

PY_DIFF = """\
diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -0,0 +1,2 @@
+import os
+print(os.name)
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

OXLINT_DIFF_PAYLOAD = {
    "diagnostics": [
        {
            "message": "`debugger` statement is not allowed",
            "code": "eslint(no-debugger)",
            "severity": "warning",
            "causes": [],
            "url": "https://oxc.rs/docs/guide/usage/linter/rules/eslint/no-debugger.html",
            "help": "Remove the debugger statement",
            "filename": "app.js",
            "labels": [{"span": {"offset": 11, "length": 9, "line": 2, "column": 1}}],
            "related": [],
        }
    ],
    "number_of_files": 1,
    "number_of_rules": 122,
}


class FakeProcess:
    """Minimal stand-in for asyncio.subprocess.Process."""

    def __init__(self, stdout: bytes, stderr: bytes = b"", returncode: int = 0) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode

    async def communicate(self, input_data=None):
        return (self._stdout, self._stderr)

    def kill(self) -> None:
        pass

    async def wait(self) -> int:
        return self.returncode


def install_fake(monkeypatch, responses: dict, calls: list) -> None:
    """Patch create_subprocess_exec so each binary returns canned output.

    ``responses`` maps lane label -> ``(stdout, returncode)`` or
    ``(stdout, stderr, returncode)`` (lockfile-lint uses the 3-tuple to prove
    stderr merging). Unknown binaries raise FileNotFoundError (absent).
    """

    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append((list(argv), dict(kwargs)))
        assert "shell" not in kwargs, "scanners must never run with shell=True"
        first = Path(str(argv[0])).name
        names = {Path(str(a)).name for a in argv}
        arglist = [str(a) for a in argv]
        if first == "uv" and "checkov" in names:
            label = "checkov"
        elif "oxlint" in names:
            label = "oxlint"
        elif first == "eslint" or "eslint" in names:
            label = "eslint"
        elif first == "knip" or "knip" in names:
            label = "knip"
        elif first == "lockfile-lint" or "lockfile-lint" in names:
            label = "lockfile-lint"
        elif first == "npm" and "audit" in arglist:
            label = "npm-audit"
        else:
            label = first
        if label not in responses:
            raise FileNotFoundError(label)
        entry = responses[label]
        if len(entry) == 3:
            stdout, stderr, returncode = entry
        else:
            stdout, returncode = entry
            stderr = b""
        return FakeProcess(stdout, stderr, returncode)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)


def quiet_responses(**overrides: object) -> dict:
    responses: dict = {
        "semgrep": (b'{"results": []}', 0),
        "opengrep": (b'{"results": []}', 0),
        "bandit": (b'{"results": []}', 0),
        "betterleaks": (b"[]", 0),
        "gitleaks": (b"[]", 0),
        "oxlint": (json.dumps(OXLINT_DIFF_PAYLOAD).encode(), 0),
        "cmd": (json.dumps(OXLINT_DIFF_PAYLOAD).encode(), 0),
        "trivy": (b"{}", 0),
        "uv": (b'{"results": {"failed_checks": []}}', 0),
        "eslint": (ESLINT_FIXTURE.read_bytes(), 1),
        "knip": (KNIP_FIXTURE.read_bytes(), 1),
        # Real lockfile-lint writes validator failures to stderr
        # (console.error); the fake proves the runner merges streams.
        "lockfile-lint": (b"", LOCKFILE_FIXTURE.read_bytes(), 1),
        "npm-audit": (NPM_AUDIT_FIXTURE.read_bytes(), 1),
        "ruff": (b"[]", 0),
        "vulture": (b"", 0),
    }
    responses.update(overrides)
    return responses


def patch_binaries(
    monkeypatch,
    *,
    oxlint=True,
    eslint=True,
    knip=True,
    lockfile_lint=True,
    npm=True,
) -> None:
    """Control shutil.which for the T7 presence matrix (rest pass through)."""
    wanted = {
        "oxlint": oxlint,
        "eslint": eslint,
        "knip": knip,
        "lockfile-lint": lockfile_lint,
        "npm": npm,
    }
    real_which = shutil.which

    def fake_which(name: str):
        if name in wanted:
            return f"/usr/bin/{name}" if wanted[name] else None
        if name in ("syft", "grype", "guarddog", "ruff", "vulture", "deptry"):
            return None
        return real_which(name)

    monkeypatch.setattr(shutil, "which", fake_which)


def spawned_binaries(calls: list) -> set[str]:
    labels = set()
    for argv, _ in calls:
        names = {Path(str(a)).name for a in argv}
        arglist = [str(a) for a in argv]
        if "oxlint" in names:
            labels.add("oxlint")
        elif Path(str(argv[0])).name == "eslint" or "eslint" in names:
            labels.add("eslint")
        elif Path(str(argv[0])).name == "knip":
            labels.add("knip")
        elif Path(str(argv[0])).name == "lockfile-lint":
            labels.add("lockfile-lint")
        elif Path(str(argv[0])).name == "npm" and "audit" in arglist:
            labels.add("npm-audit")
        else:
            labels.add(Path(str(argv[0])).name)
    return labels


def spawn_count(calls: list, binary: str) -> int:
    if binary == "npm-audit":
        return sum(
            1
            for argv, _ in calls
            if Path(str(argv[0])).name == "npm" and "audit" in [str(a) for a in argv]
        )
    return sum(
        1
        for argv, _ in calls
        if Path(str(argv[0])).name == binary or binary in {Path(str(a)).name for a in argv}
    )


def eslint_payload() -> list:
    return json.loads(ESLINT_FIXTURE.read_text(encoding="utf-8"))


def knip_payload() -> dict:
    return json.loads(KNIP_FIXTURE.read_text(encoding="utf-8"))


def lockfile_text() -> str:
    return LOCKFILE_FIXTURE.read_text(encoding="utf-8")


def npm_audit_payload() -> dict:
    return json.loads(NPM_AUDIT_FIXTURE.read_text(encoding="utf-8"))


# --- argv shapes -----------------------------------------------------------


def test_oxlint_diff_argv_targets_js_files() -> None:
    argv = orchestrator.oxlint_argv("/tmp/bg-diff/app.js")
    assert argv[0] in ("oxlint", "cmd")
    assert "--format" in argv and "json" in argv
    assert "--config" in argv
    assert "/tmp/bg-diff/app.js" in argv


def test_eslint_argv_format_json_and_config() -> None:
    argv = orchestrator.eslint_argv(["/repo/app.js"])
    assert argv[0] == "eslint"
    assert argv[argv.index("--format") + 1] == "json"
    assert "--config" in argv
    config = argv[argv.index("--config") + 1]
    assert config.endswith("eslint.config.mjs")
    assert "/repo/app.js" in argv


def test_eslint_config_enables_only_core_security_rules() -> None:
    from pathlib import Path as _Path

    config_path = _Path(__file__).resolve().parents[1] / "eslint.config.mjs"
    assert config_path.is_file(), "repo-root eslint.config.mjs must exist"
    text = config_path.read_text(encoding="utf-8")
    for rule in ("no-eval", "no-implied-eval", "no-new-func", "no-script-url"):
        assert rule in text, f"core security rule {rule} must be enabled"
    # Heavy plugin scope stays cut: no plugins array, no plugin rule prefixes
    # enabled (the config COMMENTS document the cuts by name, so raw-substring
    # matching would false-positive on documentation — check wiring instead).
    assert "plugins:" not in text
    assert "security/detect-" not in text
    assert "jsx-a11y/" not in text


def test_knip_argv_reporter_json_and_directory() -> None:
    argv = orchestrator.knip_argv("/repo")
    assert argv[0] == "knip"
    assert argv[argv.index("--reporter") + 1] == "json"
    assert "/repo" in argv


def test_lockfile_lint_argv_checks_https_hosts_scheme() -> None:
    argv = orchestrator.lockfile_lint_argv("/repo/package-lock.json", "npm")
    assert argv[0] == "lockfile-lint"
    assert argv[argv.index("--path") + 1] == "/repo/package-lock.json"
    assert argv[argv.index("--type") + 1] == "npm"
    # https-only + allowed-hosts (valid scheme enforced via https-only;
    # --allowed-schemes is mutually exclusive with --validate-https per the
    # lockfile-lint README, so the runner documents that trade-off).
    assert "--validate-https" in argv
    assert "--allowed-hosts" in argv
    hosts = argv[argv.index("--allowed-hosts") + 1 :]
    assert any("npm" in h for h in hosts)


def test_npm_audit_argv_json_no_new_binary() -> None:
    argv = orchestrator.npm_audit_argv("/repo")
    assert argv[:2] == ["npm", "audit"]
    assert "--json" in argv
    assert "/repo" in argv
    # npm ships with node: no installer entry needed (documented choice).


# --- eslint normalize ------------------------------------------------------


def test_normalize_eslint_mapping() -> None:
    findings = normalize_eslint(eslint_payload())
    assert len(findings) == 4
    for finding in findings:
        assert set(finding) == set(FINDING_KEYS)
    first = findings[0]
    assert first["rule_id"] == "eslint-no-eval"
    assert first["path"] == "app.js"
    assert first["line"] == 1
    assert "eval" in first["message"].lower()


def test_normalize_eslint_severity_capped_at_medium() -> None:
    findings = normalize_eslint(eslint_payload())
    by_rule = {f["rule_id"]: f for f in findings}
    # error (2) -> MEDIUM (lint policy cap), warning (1) -> LOW.
    assert by_rule["eslint-no-eval"]["severity"] == "MEDIUM"
    assert by_rule["eslint-no-new-func"]["severity"] == "MEDIUM"
    assert by_rule["eslint-no-script-url"]["severity"] == "LOW"
    assert all(f["severity"] in ("LOW", "MEDIUM") for f in findings)


def test_normalize_eslint_cwe_empty_without_documented_mapping() -> None:
    assert all(f["cwe"] == "" for f in normalize_eslint(eslint_payload()))


def test_normalize_eslint_tolerates_empty_and_fatal() -> None:
    assert normalize_eslint([]) == []
    assert normalize_eslint({}) == []
    # Null ruleId (fatal parse error) still yields an eslint-unknown finding.
    findings = normalize_eslint(eslint_payload())
    assert any(f["rule_id"] == "eslint-unknown" for f in findings)
    assert normalize_eslint([{"nope": True}, "garbage", None]) == []


# --- knip gating + normalize -----------------------------------------------


def test_knip_manifests_require_package_json(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "x"}\n', encoding="utf-8")
    assert orchestrator._knip_manifests(tmp_path) != []
    bare = tmp_path / "bare"
    bare.mkdir()
    (bare / "app.js").write_text("const x = 1;\n", encoding="utf-8")
    assert orchestrator._knip_manifests(bare) == []


def test_normalize_knip_mapping() -> None:
    findings = normalize_knip(knip_payload())
    for finding in findings:
        assert set(finding) == set(FINDING_KEYS)
        assert finding["severity"] == "LOW"
        assert finding["cwe"] == ""
        assert finding["rule_id"].startswith("knip-")
    by_rule = {f["rule_id"] for f in findings}
    assert "knip-files" in by_rule
    assert "knip-dependencies" in by_rule
    assert "knip-exports" in by_rule
    assert len(findings) == 5


def test_normalize_knip_fix_hint_remove() -> None:
    for finding in normalize_knip(knip_payload()):
        assert "remove" in finding["fix_hint"].lower()


def test_normalize_knip_tolerates_empty_payload() -> None:
    assert normalize_knip({}) == []
    assert normalize_knip({"issues": []}) == []
    assert normalize_knip([]) == []


# --- lockfile-lint detection + normalize -----------------------------------


def test_lockfile_detection_picks_type(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text("{}\n", encoding="utf-8")
    locks = orchestrator._js_lockfiles(tmp_path)
    assert ("npm", str(tmp_path / "package-lock.json")) in [
        (t, p) for p, t in [(str(p), t) for p, t in locks]
    ] or any(t == "npm" for _, t in locks)
    yarn_dir = tmp_path / "yarnproj"
    yarn_dir.mkdir()
    (yarn_dir / "yarn.lock").write_text("# yarn\n", encoding="utf-8")
    assert any(t == "yarn" for _, t in orchestrator._js_lockfiles(yarn_dir))
    pnpm_dir = tmp_path / "pnpmproj"
    pnpm_dir.mkdir()
    (pnpm_dir / "pnpm-lock.yaml").write_text("lockfileVersion: 9\n", encoding="utf-8")
    assert any(t == "pnpm" for _, t in orchestrator._js_lockfiles(pnpm_dir))


def test_normalize_lockfile_lint_mapping() -> None:
    payload = {"lockfile": "package-lock.json", "output": lockfile_text()}
    findings = normalize_lockfile_lint(payload)
    assert len(findings) == 3
    for finding in findings:
        assert set(finding) == set(FINDING_KEYS)
        assert finding["severity"] == "LOW"
        assert finding["rule_id"].startswith("lockfile-")
    by_rule = {f["rule_id"] for f in findings}
    assert "lockfile-https" in by_rule
    assert "lockfile-hosts" in by_rule
    assert "lockfile-scheme" in by_rule


def test_normalize_lockfile_lint_fix_hint_regenerate() -> None:
    payload = {"lockfile": "package-lock.json", "output": lockfile_text()}
    for finding in normalize_lockfile_lint(payload):
        hint = finding["fix_hint"].lower()
        assert "regenerate" in hint or "registry" in hint or "pin" in hint


def test_normalize_lockfile_lint_empty_output_is_clean() -> None:
    assert normalize_lockfile_lint({"lockfile": "x", "output": ""}) == []
    assert normalize_lockfile_lint({}) == []


# --- npm audit normalize ---------------------------------------------------


def test_normalize_npm_audit_mapping() -> None:
    findings = normalize_npm_audit(npm_audit_payload())
    assert len(findings) == 3
    for finding in findings:
        assert set(finding) == set(FINDING_KEYS)
        assert finding["rule_id"].startswith("npm-audit-")
    by_rule = {f["rule_id"]: f for f in findings}
    assert "npm-audit-lodash" in by_rule
    assert by_rule["npm-audit-lodash"]["severity"] == "HIGH"
    assert "4.17.21" in by_rule["npm-audit-lodash"]["fix_hint"]


def test_normalize_npm_audit_severity_capped_at_high() -> None:
    findings = normalize_npm_audit(npm_audit_payload())
    by_rule = {f["rule_id"]: f for f in findings}
    # critical caps to HIGH (mirror trivy policy: engine-assigned, no exploit ctx).
    assert by_rule["npm-audit-minimist"]["severity"] == "HIGH"
    assert all(f["severity"] != "CRITICAL" for f in findings)


def test_normalize_npm_audit_fix_hint_carries_versions() -> None:
    findings = normalize_npm_audit(npm_audit_payload())
    by_rule = {f["rule_id"]: f for f in findings}
    assert "4.17.21" in by_rule["npm-audit-lodash"]["fix_hint"]
    assert by_rule["npm-audit-debug"]["fix_hint"] != ""


def test_normalize_npm_audit_tolerates_empty_payload() -> None:
    assert normalize_npm_audit({}) == []
    assert normalize_npm_audit({"vulnerabilities": {}}) == []


# --- lane registration -----------------------------------------------------


def test_lane_gates_suffix_vs_manifest_distinction() -> None:
    assert LANE_GATES["eslint"]["kind"] == "suffix"
    assert LANE_GATES["eslint"]["languages"] == ("javascript",)
    assert LANE_GATES["knip"]["kind"] == "manifest"
    assert LANE_GATES["knip"]["manifests"] == ("javascript",)
    assert LANE_GATES["lockfile-lint"]["kind"] == "manifest"
    assert LANE_GATES["npm-audit"]["kind"] == "manifest"
    assert {"eslint", "knip", "lockfile-lint", "npm-audit"} <= set(SKIP_REASONS)


def test_lanes_for_empty_detection_skips_all_five(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("hello\n", encoding="utf-8")
    skips = lanes_for(detect_languages(tmp_path))
    assert {"oxlint", "eslint", "knip", "lockfile-lint", "npm-audit"} <= set(skips)


# --- missing-binary skips --------------------------------------------------


def test_missing_binaries_skip_runnable_lanes_in_repo(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text("const x = eval(y);\n", encoding="utf-8")
    (repo / "package.json").write_text('{"name": "x"}\n', encoding="utf-8")
    (repo / "package-lock.json").write_text("{}\n", encoding="utf-8")
    patch_binaries(
        monkeypatch, oxlint=True, eslint=False, knip=False, lockfile_lint=False, npm=False
    )
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert result["status"] == "ok"
    for lane in ("eslint", "knip", "lockfile-lint", "npm-audit"):
        assert lane in result["skipped"]
        assert "not installed" in result["skipped"][lane].lower() or "missing" in result["skipped"][lane].lower()
        assert lane not in result.get("errors", {})
    assert "eslint" not in spawned_binaries(calls)
    assert "knip" not in spawned_binaries(calls)
    assert "lockfile-lint" not in spawned_binaries(calls)
    assert "npm-audit" not in spawned_binaries(calls)


def test_missing_oxlint_eslint_skip_in_diff(monkeypatch) -> None:
    patch_binaries(monkeypatch, oxlint=False, eslint=False)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_diff(JS_DIFF))
    assert result["status"] == "ok"
    assert "oxlint" in result["skipped"]
    assert "eslint" in result["skipped"]
    assert "oxlint" not in spawned_binaries(calls)
    assert "eslint" not in spawned_binaries(calls)


# --- diff + repo routing ---------------------------------------------------


def test_diff_py_only_skips_all_five_with_reason(monkeypatch) -> None:
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_diff(PY_DIFF))
    assert result["status"] == "ok"
    assert {"oxlint", "eslint", "knip", "lockfile-lint", "npm-audit"} <= set(
        result.get("skipped", {})
    )
    assert not any(
        str(f.get("rule_id", "")).startswith(
            ("oxlint-", "eslint-", "knip-", "lockfile-", "npm-audit-")
        )
        for f in result["findings"]
    )


def test_diff_js_runs_oxlint_and_eslint_but_manifest_lanes_skip(monkeypatch) -> None:
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_diff(JS_DIFF))
    assert result["status"] == "ok"
    assert "oxlint" not in result.get("skipped", {})
    assert "eslint" not in result.get("skipped", {})
    for lane in ("knip", "lockfile-lint", "npm-audit"):
        assert lane in result.get("skipped", {})
    assert spawn_count(calls, "oxlint") == 1
    assert spawn_count(calls, "eslint") == 1
    assert "knip" not in spawned_binaries(calls)
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert any(r.startswith("oxlint-") for r in rule_ids)
    assert any(r.startswith("eslint-") for r in rule_ids)


def test_repo_py_only_skips_all_five_with_reason(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert result["status"] == "ok"
    assert {"oxlint", "eslint", "knip", "lockfile-lint", "npm-audit"} <= set(
        result.get("skipped", {})
    )
    assert {"eslint", "knip", "lockfile-lint", "npm-audit"} & spawned_binaries(calls) == set()


def test_repo_js_runs_all_five(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text("const x = eval(y);\n", encoding="utf-8")
    (repo / "package.json").write_text('{"name": "x"}\n', encoding="utf-8")
    (repo / "package-lock.json").write_text("{}\n", encoding="utf-8")
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert result["status"] == "ok"
    for lane in ("eslint", "knip", "lockfile-lint", "npm-audit"):
        assert lane not in result.get("skipped", {})
    assert "oxlint" not in result.get("skipped", {})
    assert "eslint" in spawned_binaries(calls)
    assert "knip" in spawned_binaries(calls)
    assert "lockfile-lint" in spawned_binaries(calls)
    assert "npm-audit" in spawned_binaries(calls)
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert any(r.startswith("eslint-") for r in rule_ids)
    assert any(r.startswith("knip-") for r in rule_ids)
    assert any(r.startswith("lockfile-") for r in rule_ids)
    assert any(r.startswith("npm-audit-") for r in rule_ids)


def test_repo_js_without_manifests_skips_manifest_lanes_but_runs_lint(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text("const x = 1;\n", encoding="utf-8")
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert result["status"] == "ok"
    for lane in ("knip", "lockfile-lint", "npm-audit"):
        assert lane in result.get("skipped", {})
        assert "manifest" in result["skipped"][lane].lower() or "package.json" in result["skipped"][lane].lower() or "lockfile" in result["skipped"][lane].lower()
    assert "eslint" not in result.get("skipped", {})
    assert "knip" not in spawned_binaries(calls)


# --- coexistence -----------------------------------------------------------


def test_coexists_with_oxlint_different_namespaces(monkeypatch) -> None:
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_diff(JS_DIFF))
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert any(r.startswith("oxlint-") for r in rule_ids)
    assert any(r.startswith("eslint-") for r in rule_ids)
    # Different engines, different rule namespaces by construction.
    assert len(rule_ids) == len(set(rule_ids))
    assert not any(r.startswith("oxlint-") and r.startswith("eslint-") for r in rule_ids)


# --- installer -------------------------------------------------------------


def test_installer_covers_eslint_knip_lockfile_lint() -> None:
    from scripts import install, install_external

    manifest = json.loads(
        (Path(__file__).parent.parent / "tools-manifest.json").read_text(encoding="utf-8")
    )
    names = {b["name"] for b in manifest.get("binaries", [])}
    # eslint + knip were already pinned (npm-distributed, pre-existing entries).
    assert "eslint" in names
    assert "knip" in names
    # lockfile-lint is npm-distributed (npm:lockfile-lint 5.0.1, verified via
    # npm view) so it joins the npm path + manifest like its siblings.
    assert "lockfile-lint" in names
    assert "lockfile-lint" in install.NPM_PKGS
    assert "lockfile-lint" in install.OPTIONAL_BINARIES
    assert "lockfile-lint" in install_external.OPTIONAL_BINARIES
    # npm audit is `npm audit --json` (npm ships with node): no new binary,
    # so no installer or manifest entry by design — same convention as the
    # uv-based checkov lane needing only its host binary.
    assert "npm-audit" not in names
    assert "npm-audit" not in install.NPM_PKGS
